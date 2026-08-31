#![no_main]

use libfuzzer_sys::fuzz_target;
use qk_core::fuzz::{reset_wiped_bytes, wiped_bytes};
use qk_core::{
    CardInstanceV2, CardPresence, CoreDeviceGrants, CoreError, CoreOutbound, Interruption,
    KeypadKey, MockCardSlot, MockDisplay, MockKeypad, SetupErrorV2, SetupOutcomeV2, SetupSessionV2,
    SetupStageV2, SpareBChoiceV2,
};
use qk_ipc::{encode_frame, parse_frame, Direction, MessageKind, HEADER_BYTES};

#[allow(dead_code, clippy::chunks_exact_to_as_chunks)]
#[path = "../../host/qk-psbt/src/sha256.rs"]
mod reference_sha256;

const A1_BYTES: usize = 67;
const KIT_PAGE_BYTES: usize = 829;
const EMPTY_HASH: [u8; 32] = [0; 32];

#[derive(Clone, Debug, Eq, PartialEq)]
struct RunFact {
    scenario: u8,
    status: &'static str,
    wallet_id: [u8; 32],
    a1_hash: [u8; 32],
    page_hashes: [[u8; 32]; 4],
    pages_seen: usize,
    wiped: usize,
}

struct Cursor<'a> {
    bytes: &'a [u8],
    offset: usize,
}

impl<'a> Cursor<'a> {
    const fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, offset: 0 }
    }

    fn byte(&mut self) -> u8 {
        let value = self.bytes.get(self.offset).copied().unwrap_or(0);
        self.offset = self.offset.saturating_add(1);
        value
    }

    fn array<const N: usize>(&mut self) -> [u8; N] {
        core::array::from_fn(|_| self.byte())
    }
}

fn grants() -> CoreDeviceGrants {
    CoreDeviceGrants::validate(
        Some(MockDisplay::new()),
        Some(MockKeypad::new()),
        Some(MockCardSlot::new(CardPresence::Present)),
        false,
    )
    .expect("fixed setup grants")
}

fn setup_error_name(error: SetupErrorV2) -> &'static str {
    let name = match error {
        SetupErrorV2::InvalidTransition => "InvalidTransition",
        SetupErrorV2::DiceGridUnavailable => "DiceGridUnavailable",
        SetupErrorV2::InvalidFaceKey => "InvalidFaceKey",
        SetupErrorV2::TranscriptFull => "TranscriptFull",
        SetupErrorV2::EmptyDelete => "EmptyDelete",
        SetupErrorV2::TranscriptCountIncomplete => "TranscriptCountIncomplete",
        SetupErrorV2::TranscriptReuse => "TranscriptReuse",
        SetupErrorV2::ProvisioningRejected => "ProvisioningRejected",
        SetupErrorV2::CommitmentInvariant => "CommitmentInvariant",
        SetupErrorV2::CardAbsent => "CardAbsent",
        SetupErrorV2::CardInstanceAlreadyProvisioned => "CardInstanceAlreadyProvisioned",
        SetupErrorV2::CardBindingMismatch => "CardBindingMismatch",
        SetupErrorV2::SpareChoiceAlreadyMade => "SpareChoiceAlreadyMade",
        SetupErrorV2::ArtifactInvariant => "ArtifactInvariant",
        SetupErrorV2::A1ScanbackMismatch => "A1ScanbackMismatch",
        SetupErrorV2::PrintReceiptMismatch => "PrintReceiptMismatch",
        SetupErrorV2::SetupFinished => "SetupFinished",
        SetupErrorV2::Interrupted(reason) => interruption_name(reason),
        SetupErrorV2::Core(_) => "Core",
    };
    assert_eq!(error.name(), name);
    assert_eq!(error.to_string(), name);
    name
}

fn interruption_name(reason: Interruption) -> &'static str {
    let name = match reason {
        Interruption::Cancelled => "Cancelled",
        Interruption::OperationFailed => "OperationFailed",
        Interruption::MediaRemoved => "MediaRemoved",
        Interruption::CardRemoved => "CardRemoved",
        Interruption::SessionTimeout => "SessionTimeout",
        Interruption::Shutdown => "Shutdown",
        Interruption::Restart => "Restart",
        Interruption::PowerLoss => "PowerLoss",
        Interruption::PeerLost => "PeerLost",
        Interruption::CapabilityFailed => "CapabilityFailed",
    };
    assert_eq!(reason.name(), name);
    name
}

fn response(request: &CoreOutbound, kind: MessageKind, payload: &[u8]) -> Vec<u8> {
    let request = parse_frame(request.frame_bytes()).expect("canonical qk-core QKIP frame");
    let mut output = vec![0u8; HEADER_BYTES + payload.len()];
    let written = encode_frame(
        Direction::IoToCore,
        kind,
        *request.header().session_id(),
        request.header().exchange_id(),
        payload,
        &mut output,
    )
    .expect("bounded canonical peer response");
    assert_eq!(written, output.len());
    output
}

fn inner_success(opcode: u8, body: &[u8]) -> Vec<u8> {
    let mut payload = Vec::with_capacity(8 + body.len());
    payload.extend_from_slice(&[1, opcode, 0, 0]);
    payload.extend_from_slice(&(body.len() as u32).to_le_bytes());
    payload.extend_from_slice(body);
    payload
}

fn operation_response(request: &CoreOutbound, opcode: u8, body: &[u8]) -> Vec<u8> {
    response(
        request,
        MessageKind::OperationResponse,
        &inner_success(opcode, body),
    )
}

fn start_ready(namespace: [u8; 12], nonce: [u8; 12]) -> SetupSessionV2 {
    let mut caller_nonce = nonce;
    let (mut session, opening) =
        SetupSessionV2::fuzz_start(namespace, 0, grants(), &mut caller_nonce)
            .expect("bounded deterministic setup start");
    assert_eq!(caller_nonce, [0; 12]);
    let ready = response(&opening, MessageKind::SessionReady, &[]);
    let outcome = session.receive(&ready, false).expect("ready response");
    assert_eq!(outcome.consumed(), ready.len());
    assert_eq!(
        outcome.outcome(),
        SetupOutcomeV2::Continue(SetupStageV2::SetupStart)
    );
    session
}

fn expect_stage(session: &mut SetupSessionV2, key: KeypadKey, stage: SetupStageV2) {
    let transition = session.apply_key(key).expect("valid setup key");
    assert_eq!(transition.outcome(), SetupOutcomeV2::Continue(stage));
    assert!(transition.outbound().is_none());
    assert_eq!(session.stage(), Some(stage));
}

fn face_key(face: u8) -> KeypadKey {
    match face {
        b'1' => KeypadKey::One,
        b'2' => KeypadKey::TwoDown,
        b'3' => KeypadKey::Three,
        b'4' => KeypadKey::FourLeft,
        b'5' => KeypadKey::Five,
        b'6' => KeypadKey::SixRight,
        _ => unreachable!("generated face is canonical"),
    }
}

fn generated_transcripts(seed: &[u8]) -> [[u8; 100]; 4] {
    core::array::from_fn(|purpose| {
        core::array::from_fn(|position| {
            if position == 0 {
                b'1' + purpose as u8
            } else {
                b'1' + seed.get(position - 1).copied().unwrap_or(0) % 6
            }
        })
    })
}

fn drive_to_provision_b(session: &mut SetupSessionV2, transcripts: &[[u8; 100]; 4]) -> [u8; 32] {
    expect_stage(
        session,
        KeypadKey::EqualsConfirmEnter,
        SetupStageV2::TierSelection,
    );
    expect_stage(
        session,
        KeypadKey::EqualsConfirmEnter,
        SetupStageV2::EntropyModeSelection,
    );
    expect_stage(
        session,
        KeypadKey::SixRight,
        SetupStageV2::EntropyModeSelection,
    );
    expect_stage(
        session,
        KeypadKey::EqualsConfirmEnter,
        SetupStageV2::CeremonyInput,
    );

    for (index, transcript) in transcripts.iter().enumerate() {
        for face in transcript {
            expect_stage(session, face_key(*face), SetupStageV2::CeremonyInput);
        }
        for stage in [
            SetupStageV2::CeremonyEcho,
            SetupStageV2::CeremonyConfirm,
            SetupStageV2::CeremonyCommitment,
        ] {
            expect_stage(session, KeypadKey::EqualsConfirmEnter, stage);
        }
        let expected = if index == 3 {
            SetupStageV2::DerivationExplanation
        } else {
            SetupStageV2::CeremonyInput
        };
        expect_stage(session, KeypadKey::EqualsConfirmEnter, expected);
    }
    assert_eq!(session.retained_counts(), [0; 4]);
    expect_stage(
        session,
        KeypadKey::EqualsConfirmEnter,
        SetupStageV2::ProvisioningResult,
    );
    let wallet_id = session
        .public_facts()
        .expect("derivation exposes public facts")
        .wallet_id();
    expect_stage(
        session,
        KeypadKey::EqualsConfirmEnter,
        SetupStageV2::ProvisionB,
    );
    wallet_id
}

fn sha256(bytes: &[u8]) -> [u8; 32] {
    let mut hasher = reference_sha256::Sha256::new();
    hasher.update(bytes).expect("bounded artifact bytes");
    hasher.finalize().expect("bounded artifact digest")
}

fn assert_terminal_absorption(session: &mut SetupSessionV2) {
    assert!(session.is_terminal());
    assert_eq!(session.retained_counts(), [0; 4]);
    assert!(session.public_facts().is_none());
    assert_eq!(
        session
            .apply_key(KeypadKey::One)
            .err()
            .map(setup_error_name),
        Some("SetupFinished")
    );
    assert_eq!(
        session.begin_a1_print().err().map(setup_error_name),
        Some("SetupFinished")
    );
    assert_eq!(
        session.begin_kit_print().err().map(setup_error_name),
        Some("SetupFinished")
    );
}

fn finish(
    session: SetupSessionV2,
    scenario: u8,
    status: &'static str,
    wallet_id: [u8; 32],
    a1_hash: [u8; 32],
    page_hashes: [[u8; 32]; 4],
    pages_seen: usize,
) -> RunFact {
    drop(session);
    let wiped = wiped_bytes();
    assert!(wiped > 400);
    RunFact {
        scenario,
        status,
        wallet_id,
        a1_hash,
        page_hashes,
        pages_seen,
        wiped,
    }
}

fn terminate_with(
    mut session: SetupSessionV2,
    scenario: u8,
    expected: SetupErrorV2,
    wallet_id: [u8; 32],
    a1_hash: [u8; 32],
    page_hashes: [[u8; 32]; 4],
    pages_seen: usize,
) -> RunFact {
    assert_eq!(session.terminal_error(), Some(expected));
    let status = setup_error_name(expected);
    assert_terminal_absorption(&mut session);
    finish(
        session,
        scenario,
        status,
        wallet_id,
        a1_hash,
        page_hashes,
        pages_seen,
    )
}

fn run(data: &[u8]) -> RunFact {
    reset_wiped_bytes();
    let mut cursor = Cursor::new(data);
    let namespace = cursor.array::<12>();
    let nonce = cursor.array::<12>();
    let scenario = cursor.byte() % 10;
    let selector = cursor.byte();
    let transcripts = generated_transcripts(data.get(26..).unwrap_or_default());
    let mut page_hashes = [EMPTY_HASH; 4];
    let mut pages = [[0u8; KIT_PAGE_BYTES]; 4];

    let mut session = start_ready(namespace, nonce);
    let wallet_id = drive_to_provision_b(&mut session, &transcripts);

    if scenario == 8 {
        let error = match session.verify_card(CardInstanceV2::Required) {
            Ok(_) => panic!("wrong card action must reject"),
            Err(error) => error,
        };
        assert_eq!(error, SetupErrorV2::InvalidTransition);
        return terminate_with(
            session,
            scenario,
            error,
            wallet_id,
            EMPTY_HASH,
            page_hashes,
            0,
        );
    }
    if scenario == 9 {
        let error = session
            .observe_card(CardPresence::Absent)
            .expect_err("card removal terminates setup");
        assert_eq!(error, SetupErrorV2::Interrupted(Interruption::CardRemoved));
        return terminate_with(
            session,
            scenario,
            error,
            wallet_id,
            EMPTY_HASH,
            page_hashes,
            0,
        );
    }
    if scenario == 7 {
        let reasons = [
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
        let reason = reasons[usize::from(selector) % reasons.len()];
        assert_eq!(session.interrupt(reason), Ok(reason));
        return terminate_with(
            session,
            scenario,
            SetupErrorV2::Interrupted(reason),
            wallet_id,
            EMPTY_HASH,
            page_hashes,
            0,
        );
    }

    assert_eq!(
        session
            .provision_card(CardInstanceV2::Required)
            .expect("required card provisioning")
            .outcome(),
        SetupOutcomeV2::Continue(SetupStageV2::VerifyB)
    );
    assert_eq!(
        session
            .verify_card(CardInstanceV2::Required)
            .expect("required card verification")
            .outcome(),
        SetupOutcomeV2::Continue(SetupStageV2::SpareBSelection)
    );
    let spare = scenario == 1 || selector & 1 == 1;
    let choice = if spare {
        SpareBChoiceV2::ProvisionSpare
    } else {
        SpareBChoiceV2::NoSpare
    };
    let selected = session.select_spare(choice).expect("one spare choice");
    if spare {
        assert_eq!(
            selected.outcome(),
            SetupOutcomeV2::Continue(SetupStageV2::ProvisionSpareB)
        );
        assert_eq!(
            session
                .provision_card(CardInstanceV2::Spare)
                .expect("spare provisioning")
                .outcome(),
            SetupOutcomeV2::Continue(SetupStageV2::VerifySpareB)
        );
        assert_eq!(
            session
                .verify_card(CardInstanceV2::Spare)
                .expect("spare verification")
                .outcome(),
            SetupOutcomeV2::Continue(SetupStageV2::CreateA1)
        );
    } else {
        assert_eq!(
            selected.outcome(),
            SetupOutcomeV2::Continue(SetupStageV2::CreateA1)
        );
    }

    let begin = session
        .begin_a1_print()
        .expect("A1 print begin")
        .into_outbound()
        .expect("A1 begin frame");
    assert_eq!(
        parse_frame(begin.frame_bytes())
            .expect("A1 begin frame")
            .payload(),
        &[1, 3, 0, 0, 8, 0, 0, 0, 3, 4, 67, 0, 0, 0, 0, 0]
    );
    let begin_opcode = if scenario == 3 { 4 } else { 3 };
    let begin_reply = operation_response(&begin, begin_opcode, &[]);
    let begin_received = session.receive(&begin_reply, false);
    if scenario == 3 {
        let error = match begin_received {
            Ok(_) => panic!("wrong A1 receipt opcode must reject"),
            Err(error) => error,
        };
        assert_eq!(error, SetupErrorV2::Core(CoreError::ResponseOpcodeMismatch));
        return terminate_with(
            session,
            scenario,
            error,
            wallet_id,
            EMPTY_HASH,
            page_hashes,
            0,
        );
    }
    let write = begin_received
        .expect("A1 begin receipt")
        .into_outbound()
        .expect("A1 write frame");
    let write_frame = parse_frame(write.frame_bytes()).expect("A1 write frame");
    assert_eq!(
        write_frame.payload().get(..16),
        Some(&[1, 4, 0, 0, 75, 0, 0, 0, 0, 0, 0, 0, 67, 0, 0, 0][..])
    );
    let a1: [u8; A1_BYTES] = write_frame
        .payload()
        .get(16..)
        .expect("A1 write body")
        .try_into()
        .expect("exact A1 artifact length");
    let a1_hash = sha256(&a1);
    let accepted = if scenario == 4 { 66u32 } else { 67u32 };
    let write_reply = operation_response(&write, 4, &accepted.to_le_bytes());
    let write_received = session.receive(&write_reply, false);
    if scenario == 4 {
        let error = match write_received {
            Ok(_) => panic!("wrong accepted byte count must reject"),
            Err(error) => error,
        };
        assert_eq!(
            error,
            SetupErrorV2::Core(CoreError::ResponseTotalLengthMismatch)
        );
        return terminate_with(session, scenario, error, wallet_id, a1_hash, page_hashes, 0);
    }
    let finish_request = write_received
        .expect("A1 write receipt")
        .into_outbound()
        .expect("A1 finish frame");
    assert_eq!(
        parse_frame(finish_request.frame_bytes())
            .expect("A1 finish frame")
            .payload(),
        &[1, 5, 0, 0, 0, 0, 0, 0]
    );
    let finish_artifact = if scenario == 5 { 5 } else { 4 };
    let finish_reply = operation_response(&finish_request, 5, &[3, finish_artifact, 67, 0, 0, 0]);
    let finish_received = session.receive(&finish_reply, false);
    if scenario == 5 {
        let error = match finish_received {
            Ok(_) => panic!("wrong A1 artifact receipt must reject"),
            Err(error) => error,
        };
        assert_eq!(error, SetupErrorV2::Core(CoreError::ResponseSourceMismatch));
        return terminate_with(session, scenario, error, wallet_id, a1_hash, page_hashes, 0);
    }

    let scan_begin = finish_received
        .expect("A1 finish receipt")
        .into_outbound()
        .expect("A1 scan begin frame");
    assert_eq!(session.stage(), Some(SetupStageV2::ScanBackA1));
    assert_eq!(
        parse_frame(scan_begin.frame_bytes())
            .expect("scan begin frame")
            .payload(),
        &[1, 1, 0, 0, 3, 0, 0, 0, 1, 0, 0]
    );
    let mut begin_body = vec![1];
    begin_body.extend_from_slice(&(A1_BYTES as u32).to_le_bytes());
    let scan_begin_reply = operation_response(&scan_begin, 1, &begin_body);
    let scan_read = session
        .receive(&scan_begin_reply, false)
        .expect("scan begin receipt")
        .into_outbound()
        .expect("scan read frame");
    assert_eq!(
        parse_frame(scan_read.frame_bytes())
            .expect("scan read frame")
            .payload(),
        &[1, 2, 0, 0, 4, 0, 0, 0, 0, 0, 0, 0]
    );
    let mut scanned = a1;
    if scenario == 2 {
        scanned[usize::from(selector) % A1_BYTES] ^= 1;
    }
    let mut scan_body = Vec::with_capacity(9 + A1_BYTES);
    scan_body.extend_from_slice(&0u32.to_le_bytes());
    scan_body.extend_from_slice(&(A1_BYTES as u32).to_le_bytes());
    scan_body.push(1);
    scan_body.extend_from_slice(&scanned);
    let scan_reply = operation_response(&scan_read, 2, &scan_body);
    let scan_received = session.receive(&scan_reply, false);
    if scenario == 2 {
        let error = match scan_received {
            Ok(_) => panic!("altered scan-back must reject"),
            Err(error) => error,
        };
        assert_eq!(error, SetupErrorV2::A1ScanbackMismatch);
        return terminate_with(session, scenario, error, wallet_id, a1_hash, page_hashes, 0);
    }
    let scan_complete = scan_received.expect("exact scan-back");
    assert_eq!(
        scan_complete.outcome(),
        SetupOutcomeV2::Continue(SetupStageV2::CoordinatorMaterial)
    );
    assert!(scan_complete.outbound().is_none());
    assert_eq!(
        session
            .apply_key(KeypadKey::EqualsConfirmEnter)
            .expect("coordinator confirmation")
            .outcome(),
        SetupOutcomeV2::Continue(SetupStageV2::CreateTwoKits)
    );

    let mut outbound = session
        .begin_kit_print()
        .expect("Kit print begin")
        .into_outbound()
        .expect("first Kit begin frame");
    let expected_positions = [(1u8, 1u8), (1, 2), (2, 1), (2, 2)];
    for index in 0..4 {
        assert_eq!(
            parse_frame(outbound.frame_bytes())
                .expect("Kit begin frame")
                .payload(),
            &[1, 3, 0, 0, 8, 0, 0, 0, 3, 5, 61, 3, 0, 0, 0, 0]
        );
        let begin_reply = operation_response(&outbound, 3, &[]);
        let write = session
            .receive(&begin_reply, false)
            .expect("Kit begin receipt")
            .into_outbound()
            .expect("Kit write frame");
        let parsed = parse_frame(write.frame_bytes()).expect("Kit write frame");
        assert_eq!(
            parsed.payload().get(..16),
            Some(&[1, 4, 0, 0, 69, 3, 0, 0, 0, 0, 0, 0, 61, 3, 0, 0][..])
        );
        pages[index].copy_from_slice(parsed.payload().get(16..).expect("complete Kit page"));
        assert_eq!(&pages[index][0..4], b"QKKP");
        assert_eq!(pages[index][4], 1);
        assert_eq!(
            (pages[index][5], pages[index][6]),
            expected_positions[index]
        );
        assert_eq!(&pages[index][7..39], wallet_id.as_slice());
        assert!(pages[index][72..300].iter().any(|byte| *byte != 0));
        assert!(pages[index][300..].iter().any(|byte| *byte != 0));
        page_hashes[index] = sha256(&pages[index]);

        let write_reply = operation_response(&write, 4, &(KIT_PAGE_BYTES as u32).to_le_bytes());
        let finish_request = session
            .receive(&write_reply, false)
            .expect("Kit write receipt")
            .into_outbound()
            .expect("Kit finish frame");
        assert_eq!(
            parse_frame(finish_request.frame_bytes())
                .expect("Kit finish frame")
                .payload(),
            &[1, 5, 0, 0, 0, 0, 0, 0]
        );
        let total = if scenario == 6 && index == usize::from(selector % 4) {
            828u32
        } else {
            KIT_PAGE_BYTES as u32
        };
        let mut finish_body = vec![3, 5];
        finish_body.extend_from_slice(&total.to_le_bytes());
        let finish_reply = operation_response(&finish_request, 5, &finish_body);
        let received = session.receive(&finish_reply, false);
        if total != KIT_PAGE_BYTES as u32 {
            let error = match received {
                Ok(_) => panic!("wrong Kit total must reject"),
                Err(error) => error,
            };
            assert_eq!(
                error,
                SetupErrorV2::Core(CoreError::ResponseTotalLengthMismatch)
            );
            return terminate_with(
                session,
                scenario,
                error,
                wallet_id,
                a1_hash,
                page_hashes,
                index + 1,
            );
        }
        let received = received.expect("Kit finish receipt");
        if index == 3 {
            assert_eq!(
                received.outcome(),
                SetupOutcomeV2::Continue(SetupStageV2::VerifyTwoKits)
            );
            assert!(received.outbound().is_none());
        } else {
            outbound = received.into_outbound().expect("next Kit page begin");
        }
    }
    assert_eq!(&pages[0][40..], &pages[2][40..]);
    assert_eq!(&pages[1][40..], &pages[3][40..]);

    expect_stage(
        &mut session,
        KeypadKey::EqualsConfirmEnter,
        SetupStageV2::Rehearsal,
    );
    expect_stage(
        &mut session,
        KeypadKey::EqualsConfirmEnter,
        SetupStageV2::SetupReady,
    );
    let close = session
        .apply_key(KeypadKey::EqualsConfirmEnter)
        .expect("setup close request");
    assert_eq!(close.outcome(), SetupOutcomeV2::TransportPending);
    let close = close.into_outbound().expect("session close frame");
    let parsed_close = parse_frame(close.frame_bytes()).expect("canonical close frame");
    assert_eq!(parsed_close.header().kind(), MessageKind::SessionClose);
    assert!(parsed_close.payload().is_empty());
    let closed = response(&close, MessageKind::SessionClosed, &[]);
    let completed = session.receive(&closed, false).expect("session closed");
    assert_eq!(completed.outcome(), SetupOutcomeV2::CompletedWiped);
    assert!(completed.outbound().is_none());
    assert_eq!(session.stage(), Some(SetupStageV2::CompletedWiped));
    assert_terminal_absorption(&mut session);
    finish(
        session,
        scenario,
        "CompletedWiped",
        wallet_id,
        a1_hash,
        page_hashes,
        4,
    )
}

fn admitted(data: &[u8]) -> bool {
    data.iter()
        .fold(0x6du8, |state, byte| state.wrapping_mul(33) ^ byte)
        == 0
}

fn cheap_run(data: &[u8]) -> RunFact {
    reset_wiped_bytes();
    let mut cursor = Cursor::new(data);
    let namespace = cursor.array::<12>();
    let nonce = cursor.array::<12>();
    let mut session = start_ready(namespace, nonce);
    let error = match session.verify_card(CardInstanceV2::Required) {
        Ok(_) => panic!("pre-provisioning card verification must reject"),
        Err(error) => error,
    };
    assert_eq!(error, SetupErrorV2::InvalidTransition);
    terminate_with(
        session,
        u8::MAX,
        error,
        EMPTY_HASH,
        EMPTY_HASH,
        [EMPTY_HASH; 4],
        0,
    )
}

fuzz_target!(|data: &[u8]| {
    let first = if admitted(data) {
        run(data)
    } else {
        cheap_run(data)
    };
    let second = if admitted(data) {
        run(data)
    } else {
        cheap_run(data)
    };
    assert_eq!(first, second);
});
