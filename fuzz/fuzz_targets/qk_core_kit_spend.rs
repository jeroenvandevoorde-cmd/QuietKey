#![no_main]

use libfuzzer_sys::fuzz_target;
use qk_core::fuzz::{fuzz_start_session, reset_wiped_bytes, wiped_bytes};
use qk_core::{
    CardPresence, CoordinatorCompletenessStatementV2, CoreDeviceGrants, CoreMode, CoreReceiveEvent,
    CoreSession, CoreState, Interruption, KeypadKey, KitArtifactErrorV2, KitDeliverySessionV2,
    KitDoorV2, KitExportActionV2, KitExportRouteV2, KitInputModeV2, KitIntakeOutcomeV2,
    KitIntakeSessionV2, KitSpendAssertionDigitV2, KitSpendErrorV2, KitSpendForeignOperationV2,
    KitSpendOutcomeV2, KitSpendScreenV2, KitSpendSessionV2, KitSpendStageV2, MockCardSlot,
    MockDisplay, MockKeypad, Source,
};
use qk_ipc::{Direction, HEADER_BYTES, MessageKind, encode_frame, parse_frame};
use qk_psbt::ReplacementReceiveIndexV2;

const MAX_PRESENTED_BYTES: usize = 512;
const NAMESPACE: [u8; 12] = *b"QKS7SPEND001";
const SHARES: &str = include_str!("../../host/qk-kit/tests/fixtures/kit_share_v2.txt");
const SPEND: &str = include_str!("../../host/qk-host-sim/tests/fixtures/kit_spend_v2.txt");
const PROVISIONING: &str =
    include_str!("../../host/qk-provisioning/tests/fixtures/provisioning_v2.txt");
const BASE32: &[u8; 32] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
const INTERRUPTIONS: [Interruption; 10] = [
    Interruption::Cancelled,
    Interruption::OperationFailed,
    Interruption::MediaRemoved,
    Interruption::CardRemoved,
    Interruption::SessionTimeout,
    Interruption::Shutdown,
    Interruption::Restart,
    Interruption::PowerLoss,
    Interruption::PeerLost,
    Interruption::CapabilityFailed,
];

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct Fact {
    error: Option<&'static str>,
    success: bool,
    wiped: usize,
}

fn field<'a>(fixture: &'a str, name: &str) -> &'a str {
    fixture
        .lines()
        .find_map(|line| line.strip_prefix(name)?.strip_prefix(": "))
        .expect("registered fixture field")
}

fn nibble(value: u8) -> u8 {
    match value {
        b'0'..=b'9' => value - b'0',
        b'a'..=b'f' => value - b'a' + 10,
        _ => panic!("hex"),
    }
}
fn hex_vec(value: &str) -> Vec<u8> {
    value
        .as_bytes()
        .chunks_exact(2)
        .map(|p| (nibble(p[0]) << 4) | nibble(p[1]))
        .collect()
}
fn hex_array<const N: usize>(value: &str) -> [u8; N] {
    hex_vec(value).try_into().expect("registered width")
}
fn compact(output: &mut Vec<u8>, value: usize) {
    assert!(value <= 0xfc);
    output.push(value as u8)
}
fn record(output: &mut Vec<u8>, key: &[u8], value: &[u8]) {
    compact(output, key.len());
    output.extend_from_slice(key);
    compact(output, value.len());
    output.extend_from_slice(value)
}
fn input_map(foreign: bool) -> Vec<u8> {
    let previous = hex_vec(field(SPEND, "previous_transaction_hex"));
    let script = hex_vec(field(SPEND, "old_script_pubkey_hex"));
    let pub_a = hex_array::<33>(field(SPEND, "old_role_a_route_public_key_hex"));
    let pub_b = hex_array::<33>(field(SPEND, "old_role_b_route_public_key_hex"));
    let mut fp_a = hex_array::<4>(field(SPEND, "old_role_a_fingerprint_hex"));
    if foreign {
        fp_a[0] ^= 0x80
    }
    let fp_b = hex_array::<4>(field(SPEND, "old_role_b_fingerprint_hex"));
    let path = [0x8000_0030u32, 0x8000_0000, 0x8000_0000, 0x8000_0002, 0, 0]
        .into_iter()
        .flat_map(u32::to_le_bytes)
        .collect::<Vec<_>>();
    let mut witness = 1_000_000u64.to_le_bytes().to_vec();
    compact(&mut witness, script.len());
    witness.extend_from_slice(&script);
    let mut out = Vec::new();
    record(&mut out, &[0], &previous);
    record(&mut out, &[1], &witness);
    record(&mut out, &[3], &1u32.to_le_bytes());
    for (pubkey, fp) in [(pub_a, fp_a), (pub_b, fp_b)] {
        let mut key = vec![6];
        key.extend_from_slice(&pubkey);
        let mut value = fp.to_vec();
        value.extend_from_slice(&path);
        record(&mut out, &key, &value)
    }
    out.push(0);
    out
}
fn unsigned_transaction(outputs: &[(u64, Vec<u8>)]) -> Vec<u8> {
    let mut tx = 2u32.to_le_bytes().to_vec();
    tx.push(1);
    tx.extend_from_slice(&hex_array::<32>(field(SPEND, "previous_txid_wire_hex")));
    tx.extend_from_slice(&0u32.to_le_bytes());
    tx.push(0);
    tx.extend_from_slice(&0xffff_fffdu32.to_le_bytes());
    compact(&mut tx, outputs.len());
    for (amount, script) in outputs {
        tx.extend_from_slice(&amount.to_le_bytes());
        compact(&mut tx, script.len());
        tx.extend_from_slice(script)
    }
    tx.extend_from_slice(&500_000u32.to_le_bytes());
    tx
}
fn constructed_s0(outputs: &[(u64, Vec<u8>)], foreign: bool) -> Vec<u8> {
    let tx = unsigned_transaction(outputs);
    let mut psbt = b"psbt\xff".to_vec();
    record(&mut psbt, &[0], &tx);
    psbt.push(0);
    psbt.extend_from_slice(&input_map(foreign));
    psbt.extend(std::iter::repeat_n(0, outputs.len()));
    psbt
}
fn destination_script() -> Vec<u8> {
    hex_vec(field(SPEND, "destination_script_pubkey_hex"))
}
fn old_change_s0() -> Vec<u8> {
    let script = hex_vec(field(PROVISIONING, "change_0_script_pubkey"));
    let tx = unsigned_transaction(&[(900_000, script)]);
    let mut psbt = b"psbt\xff".to_vec();
    record(&mut psbt, &[0], &tx);
    psbt.push(0);
    psbt.extend_from_slice(&input_map(false));
    let path = [0x8000_0030u32, 0x8000_0000, 0x8000_0000, 0x8000_0002, 1, 0]
        .into_iter()
        .flat_map(u32::to_le_bytes)
        .collect::<Vec<_>>();
    for (pubkey_field, fingerprint_field) in [
        ("change_0_role_a_pubkey", "old_role_a_fingerprint_hex"),
        ("change_0_role_b_pubkey", "old_role_b_fingerprint_hex"),
    ] {
        let mut key = vec![2];
        key.extend_from_slice(&hex_array::<33>(field(PROVISIONING, pubkey_field)));
        let mut value = hex_array::<4>(field(SPEND, fingerprint_field)).to_vec();
        value.extend_from_slice(&path);
        record(&mut psbt, &key, &value)
    }
    psbt.push(0);
    psbt
}
fn descriptors(prefix: &str) -> [[u8; 306]; 2] {
    [
        field(SPEND, &format!("{prefix}_receive_descriptor"))
            .as_bytes()
            .try_into()
            .expect("receive"),
        field(SPEND, &format!("{prefix}_change_descriptor"))
            .as_bytes()
            .try_into()
            .expect("change"),
    ]
}
fn ready(door: KitDoorV2) -> qk_core::KitIntakeReadyV2 {
    let mut one = hex_array::<142>(field(SHARES, "frame_1_hex"));
    let mut two = hex_array::<142>(field(SHARES, "frame_2_hex"));
    let mut intake = KitIntakeSessionV2::begin(door, KitInputModeV2::Scanner);
    assert!(matches!(
        intake.submit_scanner_frame(&mut one),
        Ok(KitIntakeOutcomeV2::FirstShareAccepted(_))
    ));
    let KitIntakeOutcomeV2::Ready(ready) = intake.submit_scanner_frame(&mut two).expect("second")
    else {
        panic!("ready")
    };
    ready
}
fn key(d: u8) -> KeypadKey {
    match d {
        0 => KeypadKey::Zero,
        1 => KeypadKey::One,
        2 => KeypadKey::TwoDown,
        3 => KeypadKey::Three,
        4 => KeypadKey::FourLeft,
        5 => KeypadKey::Five,
        6 => KeypadKey::SixRight,
        7 => KeypadKey::Seven,
        8 => KeypadKey::EightUp,
        9 => KeypadKey::Nine,
        _ => panic!("digit"),
    }
}
fn outer_response(request: &qk_core::CoreOutbound, kind: MessageKind, payload: &[u8]) -> Vec<u8> {
    let parsed = parse_frame(request.frame_bytes()).expect("canonical request");
    let mut output = vec![0; HEADER_BYTES + payload.len()];
    let written = encode_frame(
        Direction::IoToCore,
        kind,
        *parsed.header().session_id(),
        parsed.header().exchange_id(),
        payload,
        &mut output,
    )
    .expect("response");
    assert_eq!(written, output.len());
    output
}
fn opened_core(counter: u32) -> CoreSession {
    let grants = CoreDeviceGrants::validate(
        Some(MockDisplay::new()),
        Some(MockKeypad::new()),
        Some(MockCardSlot::new(CardPresence::Present)),
        false,
    )
    .expect("kit grants");
    let (mut core, opening) =
        fuzz_start_session(NAMESPACE, counter, CoreMode::Kit, grants).expect("kit core");
    let ready = outer_response(&opening, MessageKind::SessionReady, &[]);
    let outcome = core.receive(&ready, false).expect("ready");
    assert_eq!(outcome.event(), CoreReceiveEvent::SessionReady);
    assert_eq!(core.state(), CoreState::Ready);
    core
}
fn inner_success(opcode: u8, body: &[u8]) -> Vec<u8> {
    let mut p = vec![1, opcode, 0, 0];
    p.extend_from_slice(&(body.len() as u32).to_le_bytes());
    p.extend_from_slice(body);
    p
}
fn operation_response(request: &qk_core::CoreOutbound, opcode: u8, body: &[u8]) -> Vec<u8> {
    outer_response(
        request,
        MessageKind::OperationResponse,
        &inner_success(opcode, body),
    )
}
fn base36(v: u16) -> u8 {
    if v < 10 {
        b'0' + v as u8
    } else {
        b'A' + (v as u8 - 10)
    }
}
fn base32(input: &[u8]) -> Vec<u8> {
    let mut out = Vec::new();
    let (mut acc, mut bits) = (0u16, 0usize);
    for b in input {
        acc = (acc << 8) | u16::from(*b);
        bits += 8;
        while bits >= 5 {
            bits -= 5;
            out.push(BASE32[usize::from((acc >> bits) & 31)]);
            acc &= (1u16 << bits).wrapping_sub(1)
        }
    }
    if bits != 0 {
        out.push(BASE32[usize::from((acc << (5 - bits)) & 31)])
    }
    out
}
fn bbqr_frames(raw: &[u8], part: usize) -> Vec<Vec<u8>> {
    let count = raw.len().div_ceil(part);
    (0..count)
        .map(|i| {
            let body = base32(&raw[i * part..raw.len().min((i + 1) * part)]);
            let mut f = b"B$2T".to_vec();
            f.extend_from_slice(&[
                base36((count as u16) / 36),
                base36((count as u16) % 36),
                base36((i as u16) / 36),
                base36((i as u16) % 36),
            ]);
            f.extend_from_slice(&body);
            f
        })
        .collect()
}
fn artifact_error_name(error: KitArtifactErrorV2) -> &'static str {
    let name = match error {
        KitArtifactErrorV2::InvalidTransition => "InvalidTransition",
        KitArtifactErrorV2::ExportRouteUnavailable => "ExportRouteUnavailable",
        KitArtifactErrorV2::ExportArtifactInvariant => "ExportArtifactInvariant",
        KitArtifactErrorV2::ExportReceiptMismatch => "ExportReceiptMismatch",
        KitArtifactErrorV2::BbqrVerificationMismatch => "BbqrVerificationMismatch",
        KitArtifactErrorV2::Finished => "Finished",
        KitArtifactErrorV2::Core(_) => "Core",
    };
    assert_eq!(error.name(), name);
    name
}
fn error_name(error: KitSpendErrorV2) -> &'static str {
    let name = match error {
        KitSpendErrorV2::ProfileMissing => "ProfileMissing",
        KitSpendErrorV2::ProfileUnknown => "ProfileUnknown",
        KitSpendErrorV2::ProfileMalformed => "ProfileMalformed",
        KitSpendErrorV2::InvalidHumanAssertionDigit => "InvalidHumanAssertionDigit",
        KitSpendErrorV2::WrongDoor => "WrongDoor",
        KitSpendErrorV2::InvalidStart => "InvalidStart",
        KitSpendErrorV2::InvalidTransition => "InvalidTransition",
        KitSpendErrorV2::WrongIngressSource => "WrongIngressSource",
        KitSpendErrorV2::RecoveredWalletMismatch => "RecoveredWalletMismatch",
        KitSpendErrorV2::ReplacementDescriptorInvalid => "ReplacementDescriptorInvalid",
        KitSpendErrorV2::ReplacementWalletUnchanged => "ReplacementWalletUnchanged",
        KitSpendErrorV2::Intake(_) => error.name(),
        KitSpendErrorV2::Sweep(_) => error.name(),
        KitSpendErrorV2::ReviewIncomplete => "ReviewIncomplete",
        KitSpendErrorV2::ReviewIdentityMismatch => "ReviewIdentityMismatch",
        KitSpendErrorV2::CompletenessStatementMissing => "CompletenessStatementMissing",
        KitSpendErrorV2::HumanAssertionMismatch => "HumanAssertionMismatch",
        KitSpendErrorV2::PostApprovalYield => "PostApprovalYield",
        KitSpendErrorV2::SigningOutsideSweep => "SigningOutsideSweep",
        KitSpendErrorV2::TransactionOutsideSweep => "TransactionOutsideSweep",
        KitSpendErrorV2::ReviewOutsideSweep => "ReviewOutsideSweep",
        KitSpendErrorV2::ApprovalProhibited => "ApprovalProhibited",
        KitSpendErrorV2::ExportProhibited => "ExportProhibited",
        KitSpendErrorV2::ForeignInputProhibited => "ForeignInputProhibited",
        KitSpendErrorV2::NormalWalletOperationProhibited => "NormalWalletOperationProhibited",
        KitSpendErrorV2::RestoreProhibited => "RestoreProhibited",
        KitSpendErrorV2::KitGenerationProhibited => "KitGenerationProhibited",
        KitSpendErrorV2::KitRegenerationProhibited => "KitRegenerationProhibited",
        KitSpendErrorV2::DoorSwitchAttempt => "DoorSwitchAttempt",
        KitSpendErrorV2::SigningRejected(_) => error.name(),
        KitSpendErrorV2::FinalizationRejected(_) => error.name(),
        KitSpendErrorV2::Interrupted(reason) => reason.name(),
        KitSpendErrorV2::Finished => "Finished",
    };
    assert_eq!(error.name(), name);
    assert_eq!(error.to_string(), name);
    name
}
fn fail(error: KitSpendErrorV2) -> Fact {
    Fact {
        error: Some(error_name(error)),
        success: false,
        wiped: wiped_bytes(),
    }
}
fn begin(profile: &[u8], door: KitDoorV2, digit: u8) -> Result<KitSpendSessionV2, KitSpendErrorV2> {
    KitSpendSessionV2::fuzz_begin(
        profile,
        ready(door),
        &descriptors("old"),
        KitSpendAssertionDigitV2::new(digit)?,
        [0x51; 16],
    )
}
fn load_ingress(core: &mut CoreSession, source: Source, bytes: &[u8]) {
    let begin = core.begin_ingress(source).expect("one ingress");
    let parsed = parse_frame(begin.frame_bytes()).expect("canonical begin");
    assert_eq!(
        parsed.payload(),
        [1, 1, 0, 0, 3, 0, 0, 0, source.wire_value(), 0, 0]
    );
    let mut began = vec![source.wire_value()];
    began.extend_from_slice(&(bytes.len() as u32).to_le_bytes());
    let response = operation_response(&begin, 1, &began);
    core.receive(&response, false).expect("begin response");
    let read = core.request_next_chunk().expect("read request");
    assert_eq!(
        parse_frame(read.frame_bytes()).expect("read").payload(),
        [1, 2, 0, 0, 4, 0, 0, 0, 0, 0, 0, 0]
    );
    let mut chunk = Vec::new();
    chunk.extend_from_slice(&0u32.to_le_bytes());
    chunk.extend_from_slice(&(bytes.len() as u32).to_le_bytes());
    chunk.push(1);
    chunk.extend_from_slice(bytes);
    let response = operation_response(&read, 2, &chunk);
    core.receive(&response, false).expect("chunk response");
    assert_eq!(core.state(), CoreState::IngressComplete);
}

fn ready_in_core(core: &mut CoreSession) -> qk_core::KitIntakeReadyV2 {
    let mut intake =
        KitIntakeSessionV2::begin_in_core(core, KitDoorV2::KitSpend, KitInputModeV2::Scanner)
            .expect("typed Kit-Spend intake");
    for (position, field_name) in [(0, "frame_1_hex"), (1, "frame_2_hex")] {
        let share = hex_array::<142>(field(SHARES, field_name));
        load_ingress(core, Source::CameraKitCandidate, &share);
        let outcome = intake
            .submit_scanner_from_core(core)
            .expect("registered scanner share");
        if position == 0 {
            assert!(matches!(outcome, KitIntakeOutcomeV2::FirstShareAccepted(_)));
        } else {
            let KitIntakeOutcomeV2::Ready(ready) = outcome else {
                panic!("second share must release readiness");
            };
            return ready;
        }
    }
    unreachable!("two registered shares")
}

fn product_begin(profile: u8, digit: u8, counter: u32) -> (CoreSession, KitSpendSessionV2) {
    let mut core = opened_core(counter);
    let ready = ready_in_core(&mut core);
    let session = KitSpendSessionV2::begin(
        &mut core,
        &[profile],
        ready,
        &descriptors("old"),
        KitSpendAssertionDigitV2::new(digit).expect("digit"),
    )
    .expect("product begin");
    (core, session)
}
fn drive_sweep_ingress(
    core: &mut CoreSession,
    session: &mut KitSpendSessionV2,
    bytes: &[u8],
    index: u32,
) {
    load_ingress(core, Source::MediaPsbt, bytes);
    session
        .submit_sweep_from_core(
            core,
            &descriptors("replacement"),
            ReplacementReceiveIndexV2::from_untrusted(index),
        )
        .expect("core-owned sweep");
}
fn deliver(
    outcome: KitSpendOutcomeV2,
    core: CoreSession,
    sd: bool,
    nonce: [u8; 16],
    part: u16,
) -> KitExportRouteV2 {
    let action = if sd {
        KitExportActionV2::Sd {
            caller_nonce: nonce,
        }
    } else {
        KitExportActionV2::Bbqr {
            non_final_part_len: part,
        }
    };
    let (mut delivery, mut outbound) =
        KitDeliverySessionV2::begin(outcome, core, action).expect("delivery");
    let raw = hex_vec(field(SPEND, "raw_transaction_hex"));
    let mut accumulated = Vec::new();
    let result = loop {
        let frame = parse_frame(outbound.frame_bytes()).expect("exact QKIP");
        assert_eq!(frame.header().direction(), Direction::CoreToIo);
        assert_eq!(frame.header().kind(), MessageKind::OperationRequest);
        let p = frame.payload();
        assert!(p.len() >= 8);
        assert_eq!(&p[..4], &[1, p[1], 0, 0]);
        assert_eq!(
            u32::from_le_bytes(p[4..8].try_into().expect("len")) as usize,
            p.len() - 8
        );
        let opcode = p[1];
        let body = match opcode {
            3 => {
                assert_eq!(p[8], if sd { 1 } else { 2 });
                assert_eq!(p[9], 2);
                assert_eq!(
                    u32::from_le_bytes(p[10..14].try_into().expect("total")) as usize,
                    raw.len()
                );
                if sd {
                    assert_eq!(p[16] as usize, p.len() - 17);
                    assert!(p[17..].starts_with(b"qk-") && p[17..].ends_with(b"-final.tx"));
                } else {
                    assert_eq!(&p[16..18], &part.to_le_bytes());
                }
                Vec::new()
            }
            4 => {
                let offset = u32::from_le_bytes(p[8..12].try_into().expect("offset")) as usize;
                let len = u32::from_le_bytes(p[12..16].try_into().expect("chunk")) as usize;
                assert_eq!(offset, accumulated.len());
                assert_eq!(p.len(), 16 + len);
                accumulated.extend_from_slice(&p[16..]);
                (accumulated.len() as u32).to_le_bytes().to_vec()
            }
            5 => {
                assert_eq!(p, &[1, 5, 0, 0, 0, 0, 0, 0]);
                assert_eq!(accumulated, raw);
                if sd {
                    let mut b = vec![1, 2];
                    b.extend_from_slice(&(raw.len() as u32).to_le_bytes());
                    b
                } else {
                    let frames = bbqr_frames(&raw, usize::from(part));
                    let mut b = vec![2, 2];
                    b.extend_from_slice(&(raw.len() as u32).to_le_bytes());
                    b.extend_from_slice(&(frames.len() as u16).to_le_bytes());
                    for f in frames {
                        b.extend_from_slice(&(f.len() as u16).to_le_bytes());
                        b.extend_from_slice(&f)
                    }
                    b
                }
            }
            _ => panic!("closed egress opcode"),
        };
        let response = operation_response(&outbound, opcode, &body);
        let progress = delivery
            .receive(&response, false)
            .expect("verified response");
        if let Some(done) = progress.result() {
            break done;
        }
        outbound = progress.into_outbound().expect("next request")
    };
    assert_eq!(
        result.raw_transaction().sha256(),
        hex_array(field(SPEND, "raw_transaction_sha256"))
    );
    assert_eq!(result.txid(), hex_array(field(SPEND, "txid_raw_hex")));
    assert_eq!(result.wtxid(), hex_array(field(SPEND, "wtxid_raw_hex")));
    assert_eq!(
        artifact_error_name(delivery.receive(&[], false).err().expect("one use")),
        "Finished"
    );
    result.route()
}
fn foreign(v: u8) -> KitSpendForeignOperationV2 {
    match v % 13 {
        0 => KitSpendForeignOperationV2::Signing,
        1 => KitSpendForeignOperationV2::Transaction,
        2 => KitSpendForeignOperationV2::Review,
        3 => KitSpendForeignOperationV2::Approval,
        4 => KitSpendForeignOperationV2::Export,
        5 => KitSpendForeignOperationV2::Intake,
        6 => KitSpendForeignOperationV2::NormalWallet,
        7 => KitSpendForeignOperationV2::Restore,
        8 => KitSpendForeignOperationV2::KitGeneration,
        9 => KitSpendForeignOperationV2::KitRegeneration,
        10 => KitSpendForeignOperationV2::DoorSwitch,
        11 => KitSpendForeignOperationV2::Transport,
        _ => KitSpendForeignOperationV2::Capability,
    }
}

fn drive(data: &[u8]) -> Fact {
    reset_wiped_bytes();
    let s = data.first().copied().unwrap_or(0);
    let digit = data.get(1).copied().unwrap_or(0) % 10;
    if s % 12 == 0 {
        return fail(
            begin(&[], KitDoorV2::KitSpend, digit)
                .err()
                .expect("missing profile"),
        );
    }
    if s % 12 == 1 {
        return fail(
            begin(&[9], KitDoorV2::KitSpend, digit)
                .err()
                .expect("unknown profile"),
        );
    }
    if s % 12 == 2 {
        return fail(
            begin(&[1, 2], KitDoorV2::KitSpend, digit)
                .err()
                .expect("malformed profile"),
        );
    }
    if s % 12 == 3 {
        return fail(
            begin(&[1], KitDoorV2::KitRestore, digit)
                .err()
                .expect("wrong door"),
        );
    }
    if s % 12 == 11 {
        let profile = data.get(6).copied().unwrap_or(0) % 3 + 1;
        let (mut core, mut session) = product_begin(profile, digit, u32::from(s));
        let psbt = hex_vec(field(SPEND, "s0_hex"));
        drive_sweep_ingress(&mut core, &mut session, &psbt, 0);
        while session.stage() == KitSpendStageV2::Review {
            session
                .advance_review_in_core(&mut core)
                .expect("complete review");
        }
        let KitSpendScreenV2::HumanAssertion { approval: _ } = session
            .confirm_all_funds_in_core(
                &mut core,
                CoordinatorCompletenessStatementV2::AllFundsIncluded,
            )
            .expect("statement")
        else {
            panic!("assertion")
        };
        if data.get(5).copied().unwrap_or(0) & 1 == 0 {
            assert!(core.begin_ingress(Source::MediaPsbt).is_err());
            let error = session
                .execute_in_core(&mut core, key(digit))
                .err()
                .expect("approval lock rejects yielded core");
            assert_eq!(error_name(error), "PostApprovalYield");
            assert!(core.begin_ingress(Source::MediaPsbt).is_err());
            return Fact {
                error: Some("PostApprovalYield"),
                success: false,
                wiped: wiped_bytes(),
            };
        }
        let outcome = session
            .execute_in_core(&mut core, key(digit))
            .expect("locked immediate signing");
        let sd = data.get(2).copied().unwrap_or(0) & 1 == 0;
        let route = deliver(
            outcome,
            core,
            sd,
            [data.get(3).copied().unwrap_or(0); 16],
            10 + u16::from(data.get(4).copied().unwrap_or(0) % 9) * 5,
        );
        assert_eq!(
            route,
            if sd {
                KitExportRouteV2::Sd
            } else {
                KitExportRouteV2::Bbqr
            }
        );
        return Fact {
            error: None,
            success: true,
            wiped: wiped_bytes(),
        };
    }
    let mut session = begin(&[s % 3 + 1], KitDoorV2::KitSpend, digit).expect("registered start");
    if s % 12 == 4 {
        return fail(
            session
                .reject_foreign_operation(foreign(data.get(2).copied().unwrap_or(0)))
                .err()
                .expect("foreign"),
        );
    }
    if s % 12 == 5 {
        return fail(
            session
                .interrupt(INTERRUPTIONS[usize::from(data.get(2).copied().unwrap_or(0) % 10)])
                .expect_err("interrupt"),
        );
    }
    let mut psbt = hex_vec(field(SPEND, "s0_hex"));
    if s % 12 == 6 {
        let mut replacement = if data.get(2).copied().unwrap_or(0) & 1 == 0 {
            descriptors("old")
        } else {
            descriptors("replacement")
        };
        if replacement != descriptors("old") {
            replacement[0][0] ^= 1;
        }
        return fail(
            session
                .submit_sweep(
                    Source::MediaPsbt,
                    &mut psbt,
                    &replacement,
                    ReplacementReceiveIndexV2::from_untrusted(0),
                )
                .err()
                .expect("descriptor rejection"),
        );
    }
    if s % 12 == 7 {
        let variant = data.get(2).copied().unwrap_or(0) % 9;
        let (mut hostile, source, index, expected) = match variant {
            0 => (
                constructed_s0(&[], false),
                Source::MediaPsbt,
                0,
                "OutputCountNotOne",
            ),
            1 => (
                constructed_s0(
                    &[
                        (450_000, destination_script()),
                        (450_000, destination_script()),
                    ],
                    false,
                ),
                Source::MediaPsbt,
                0,
                "OutputCountNotOne",
            ),
            2 => (
                constructed_s0(
                    &[(900_000, hex_vec(field(SPEND, "old_script_pubkey_hex")))],
                    false,
                ),
                Source::MediaPsbt,
                0,
                "OldWalletDestination",
            ),
            3 => (
                old_change_s0(),
                Source::MediaPsbt,
                0,
                "ChangeOutputProhibited",
            ),
            4 => (
                constructed_s0(&[(0, hex_vec("6a03aabbcc"))], false),
                Source::MediaPsbt,
                0,
                "DestinationTypeMismatch",
            ),
            5 => {
                let mut wrong = destination_script();
                wrong[2 + usize::from(data.get(3).copied().unwrap_or(0)) % 32] ^= 1;
                (
                    constructed_s0(&[(900_000, wrong)], false),
                    Source::MediaPsbt,
                    0,
                    "DestinationMismatch",
                )
            }
            6 => (
                constructed_s0(&[(900_000, destination_script())], true),
                Source::MediaPsbt,
                0,
                "TransactionReviewRejected",
            ),
            7 => (psbt, Source::CameraKitCandidate, 0, "WrongIngressSource"),
            _ => (
                psbt,
                Source::MediaPsbt,
                65_536,
                "DestinationIndexOutOfRange",
            ),
        };
        let error = session
            .submit_sweep(
                source,
                &mut hostile,
                &descriptors("replacement"),
                ReplacementReceiveIndexV2::from_untrusted(index),
            )
            .err()
            .expect("structured sweep rejection");
        assert_eq!(error_name(error), expected);
        assert!(hostile.iter().all(|byte| *byte == 0));
        return fail(error);
    }
    session
        .submit_sweep(
            Source::MediaPsbt,
            &mut psbt,
            &descriptors("replacement"),
            ReplacementReceiveIndexV2::from_untrusted(0),
        )
        .expect("registered sweep");
    if s % 12 == 8 {
        return fail(
            session
                .confirm_all_funds(CoordinatorCompletenessStatementV2::AllFundsIncluded)
                .err()
                .expect("review incomplete"),
        );
    }
    while session.stage() == KitSpendStageV2::Review {
        session.advance_review().expect("advance");
    }
    let KitSpendScreenV2::HumanAssertion { approval } = session
        .confirm_all_funds(CoordinatorCompletenessStatementV2::AllFundsIncluded)
        .expect("statement")
    else {
        panic!("assertion")
    };
    if s % 12 == 9 {
        return fail(
            session
                .reject_foreign_operation(KitSpendForeignOperationV2::Transport)
                .err()
                .expect("no yield"),
        );
    }
    let entered = if s % 12 == 10 {
        (digit + 1) % 10
    } else {
        digit
    };
    match session.execute(approval, key(entered)) {
        Ok(outcome) => {
            let _ = outcome.facts();
            Fact {
                error: None,
                success: true,
                wiped: wiped_bytes(),
            }
        }
        Err(error) => fail(error),
    }
}

fuzz_target!(|data: &[u8]| {
    if data.len() > MAX_PRESENTED_BYTES {
        return;
    }
    let a = drive(data);
    let b = drive(data);
    assert_eq!(a, b);
});
