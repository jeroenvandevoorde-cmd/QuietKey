#![no_main]

use libfuzzer_sys::fuzz_target;
use qk_core::fuzz::{reset_wiped_bytes, wiped_bytes};
use qk_core::{
    CardPresence, CoreDeviceGrants, Interruption, MockCardSlot, MockDisplay, MockKeypad,
    NormalArtifactFactsV2, NormalArtifactKindV2, NormalCardBDataV2, NormalCardBSignatureV2,
    NormalErrorV2, NormalExportActionV2, NormalExportRouteV2, NormalProfileV2,
    NormalReviewPositionV2, NormalSdReceiptV2, NormalSessionV2, NormalStageV2, Source,
};
use qk_ipc::{Direction, HEADER_BYTES, MessageKind, encode_frame, parse_frame};

const SIGNING: &str = include_str!("../../host/qk-psbt/tests/fixtures/signing_finalization_v2.txt");
const PROVISIONING: &str =
    include_str!("../../host/qk-provisioning/tests/fixtures/provisioning_v2.txt");
const BASE32: &[u8; 32] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
const LOWER_HEX: &[u8; 16] = b"0123456789abcdef";

const REVIEW_ORDER: [NormalReviewPositionV2; 13] = [
    NormalReviewPositionV2::Overview,
    NormalReviewPositionV2::Arithmetic,
    NormalReviewPositionV2::Recipient(1),
    NormalReviewPositionV2::Recipient(2),
    NormalReviewPositionV2::Change(0),
    NormalReviewPositionV2::OpReturn(3),
    NormalReviewPositionV2::Locktime,
    NormalReviewPositionV2::Sequence(0),
    NormalReviewPositionV2::FeePolicy,
    NormalReviewPositionV2::FeeFacts,
    NormalReviewPositionV2::Warning(0),
    NormalReviewPositionV2::Warning(1),
    NormalReviewPositionV2::FinalApproval,
];

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum CardMutation {
    None,
    Absent,
    Descriptor,
    WalletId,
    A2,
    InvalidSignature,
    WrongSignatureInput,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum ExportFault {
    None,
    PartialSecondSd,
    WrongSdReceipt,
    MalformedBbqr,
    NineByteBbqr,
    DifferentBbqrGeometry,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct ValidRunFact {
    profile: NormalProfileV2,
    source: Source,
    route: NormalExportRouteV2,
    review_hash: [u8; 32],
    finalized_psbt: Option<NormalArtifactFactsV2>,
    raw_transaction: Option<NormalArtifactFactsV2>,
    psbt_sd_receipt: Option<NormalSdReceiptV2>,
    raw_sd_receipt: Option<NormalSdReceiptV2>,
    txid: [u8; 32],
    wtxid: [u8; 32],
    delivered: Vec<(u8, Vec<u8>)>,
    wiped: usize,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct FailureRunFact {
    case: u8,
    error: &'static str,
    stage: NormalStageV2,
    terminal: bool,
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

fn field<'a>(source: &'a str, name: &str) -> &'a str {
    source
        .lines()
        .find_map(|line| line.strip_prefix(name)?.strip_prefix(": "))
        .expect("registered public fixture field")
}

#[allow(clippy::chunks_exact_to_as_chunks)]
fn hex_vec(text: &str) -> Vec<u8> {
    assert!(text.len().is_multiple_of(2));
    text.as_bytes()
        .chunks_exact(2)
        .map(|pair| {
            u8::from_str_radix(core::str::from_utf8(pair).expect("ASCII hex"), 16)
                .expect("fixture hex")
        })
        .collect()
}

fn hex_array<const N: usize>(text: &str) -> [u8; N] {
    hex_vec(text).try_into().expect("exact fixture width")
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
    assert_eq!(reason.to_string(), name);
    name
}

fn normal_error_name(error: NormalErrorV2) -> &'static str {
    let name = match error {
        NormalErrorV2::ProfileMissing => "ProfileMissing",
        NormalErrorV2::ProfileUnknown => "ProfileUnknown",
        NormalErrorV2::ProfileMalformed => "ProfileMalformed",
        NormalErrorV2::InvalidTransition => "InvalidTransition",
        NormalErrorV2::WrongIngressSource => "WrongIngressSource",
        NormalErrorV2::CardAbsent => "CardAbsent",
        NormalErrorV2::CardBindingMismatch => "CardBindingMismatch",
        NormalErrorV2::CardDataRejected => "CardDataRejected",
        NormalErrorV2::A1Rejected => "A1Rejected",
        NormalErrorV2::RecoveredWalletMismatch => "RecoveredWalletMismatch",
        NormalErrorV2::ReviewRejected => "ReviewRejected",
        NormalErrorV2::ReviewIncomplete => "ReviewIncomplete",
        NormalErrorV2::ReviewIdentityMismatch => "ReviewIdentityMismatch",
        NormalErrorV2::ApprovalUnavailable => "ApprovalUnavailable",
        NormalErrorV2::PostApprovalYield => "PostApprovalYield",
        NormalErrorV2::RevalidationMismatch => "RevalidationMismatch",
        NormalErrorV2::SigningRejected => "SigningRejected",
        NormalErrorV2::InvalidMockSignature => "InvalidMockSignature",
        NormalErrorV2::FinalizationRejected => "FinalizationRejected",
        NormalErrorV2::ExportRouteUnavailable => "ExportRouteUnavailable",
        NormalErrorV2::ExportArtifactInvariant => "ExportArtifactInvariant",
        NormalErrorV2::ExportReceiptMismatch => "ExportReceiptMismatch",
        NormalErrorV2::BbqrVerificationMismatch => "BbqrVerificationMismatch",
        NormalErrorV2::PartialSdCompletion => "PartialSdCompletion",
        NormalErrorV2::Finished => "Finished",
        NormalErrorV2::Interrupted(reason) => interruption_name(reason),
        NormalErrorV2::Core(_) => "Core",
    };
    assert_eq!(error.name(), name);
    assert_eq!(error.to_string(), name);
    name
}

fn card(mutation: CardMutation) -> NormalCardBDataV2 {
    let mut descriptors: [[u8; 306]; 2] = [
        field(PROVISIONING, "receive_descriptor")
            .as_bytes()
            .try_into()
            .expect("receive descriptor width"),
        field(PROVISIONING, "change_descriptor")
            .as_bytes()
            .try_into()
            .expect("change descriptor width"),
    ];
    if mutation == CardMutation::Descriptor {
        descriptors[0][305] ^= 1;
    }
    let mut role_b_der = hex_vec(field(SIGNING, "role_b_der_hex"));
    if mutation == CardMutation::InvalidSignature {
        let last = role_b_der.last_mut().expect("nonempty DER");
        *last ^= 1;
    }
    let signature_input = if mutation == CardMutation::WrongSignatureInput {
        1
    } else {
        0
    };
    let signature = NormalCardBSignatureV2::try_new(signature_input, &mut role_b_der)
        .expect("bounded public mock signature");
    assert!(role_b_der.iter().all(|byte| *byte == 0));
    let mut wallet_id = hex_array(field(PROVISIONING, "wallet_id"));
    if mutation == CardMutation::WalletId {
        wallet_id[0] ^= 1;
    }
    let mut a2 = hex_array::<32>(field(PROVISIONING, "a2_transcript_sha256"));
    if mutation == CardMutation::A2 {
        a2[0] ^= 1;
    }
    let card = NormalCardBDataV2::try_new(
        descriptors,
        wallet_id,
        field(PROVISIONING, "role_b_account_xpub")
            .as_bytes()
            .try_into()
            .expect("role-B xpub width"),
        &mut a2,
        vec![signature],
    )
    .expect("one authenticated public mock factor");
    assert_eq!(a2, [0; 32]);
    card
}

fn grants(mutation: CardMutation) -> CoreDeviceGrants {
    let card_slot = if mutation == CardMutation::Absent {
        MockCardSlot::new(CardPresence::Absent)
    } else {
        MockCardSlot::with_normal_data(CardPresence::Present, card(mutation))
    };
    CoreDeviceGrants::validate(
        Some(MockDisplay::new()),
        Some(MockKeypad::new()),
        Some(card_slot),
        false,
    )
    .expect("fixed complete normal grants")
}

fn outer_payload(outbound: &qk_core::CoreOutbound) -> &[u8] {
    parse_frame(outbound.frame_bytes())
        .expect("qk-core emitted canonical QKIP")
        .payload()
}

fn outer_response(request: &qk_core::CoreOutbound, kind: MessageKind, payload: &[u8]) -> Vec<u8> {
    let request = parse_frame(request.frame_bytes()).expect("qk-core emitted canonical QKIP");
    let mut output = vec![0u8; HEADER_BYTES + payload.len()];
    let written = encode_frame(
        Direction::IoToCore,
        kind,
        *request.header().session_id(),
        request.header().exchange_id(),
        payload,
        &mut output,
    )
    .expect("bounded canonical response");
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

fn operation_response(request: &qk_core::CoreOutbound, opcode: u8, body: &[u8]) -> Vec<u8> {
    outer_response(
        request,
        MessageKind::OperationResponse,
        &inner_success(opcode, body),
    )
}

fn drive_ingress(
    session: &mut NormalSessionV2,
    begin: qk_core::NormalProgressV2,
    source: Source,
    bytes: &[u8],
) -> Result<NormalStageV2, NormalErrorV2> {
    let outbound = begin.into_outbound().expect("ingress begin request");
    let payload = outer_payload(&outbound);
    assert_eq!(payload, [1, 1, 0, 0, 3, 0, 0, 0, source.wire_value(), 0, 0]);
    let mut began_body = Vec::with_capacity(5);
    began_body.push(source.wire_value());
    began_body.extend_from_slice(&(bytes.len() as u32).to_le_bytes());
    let began = operation_response(&outbound, 1, &began_body);
    let read = session
        .receive(&began, false)
        .expect("canonical ingress begin")
        .into_outbound()
        .expect("one ingress read");
    assert_eq!(outer_payload(&read), [1, 2, 0, 0, 4, 0, 0, 0, 0, 0, 0, 0]);
    let mut chunk_body = Vec::with_capacity(9 + bytes.len());
    chunk_body.extend_from_slice(&0u32.to_le_bytes());
    chunk_body.extend_from_slice(&(bytes.len() as u32).to_le_bytes());
    chunk_body.push(1);
    chunk_body.extend_from_slice(bytes);
    let chunk = operation_response(&read, 2, &chunk_body);
    let consumed = session.receive(&chunk, false)?;
    assert_eq!(consumed.consumed(), chunk.len());
    assert!(consumed.outbound().is_none());
    Ok(consumed.stage())
}

fn base36(value: u16) -> u8 {
    match value {
        0..=9 => b'0' + value as u8,
        10..=35 => b'A' + (value as u8 - 10),
        _ => unreachable!("bounded base36 digit"),
    }
}

fn base32(input: &[u8]) -> Vec<u8> {
    let mut output = Vec::with_capacity((input.len() * 8).div_ceil(5));
    let mut accumulator = 0u16;
    let mut bits = 0usize;
    for byte in input {
        accumulator = (accumulator << 8) | u16::from(*byte);
        bits += 8;
        while bits >= 5 {
            bits -= 5;
            output.push(BASE32[usize::from((accumulator >> bits) & 0x1f)]);
            accumulator &= (1u16 << bits).wrapping_sub(1);
        }
    }
    if bits != 0 {
        output.push(BASE32[usize::from((accumulator << (5 - bits)) & 0x1f)]);
    }
    output
}

fn bbqr_frames(file_type: u8, payload: &[u8], part_len: usize) -> Vec<Vec<u8>> {
    assert!(matches!(file_type, b'P' | b'T'));
    assert!(part_len >= 5 && part_len.is_multiple_of(5));
    let count = payload.len().div_ceil(part_len);
    assert!((1..=256).contains(&count));
    (0..count)
        .map(|index| {
            let start = index * part_len;
            let end = payload.len().min(start + part_len);
            let body = base32(&payload[start..end]);
            let mut frame = Vec::with_capacity(8 + body.len());
            frame.extend_from_slice(b"B$2");
            frame.push(file_type);
            frame.push(base36((count as u16) / 36));
            frame.push(base36((count as u16) % 36));
            frame.push(base36((index as u16) / 36));
            frame.push(base36((index as u16) % 36));
            frame.extend_from_slice(&body);
            frame
        })
        .collect()
}

fn sd_filename(caller_nonce: &[u8; 16], artifact: u8) -> Vec<u8> {
    let suffix: &[u8] = match artifact {
        1 => b"-final.psbt",
        2 => b"-final.tx",
        _ => panic!("closed artifact byte"),
    };
    let mut filename = Vec::with_capacity(35 + suffix.len());
    filename.extend_from_slice(b"qk-");
    for byte in caller_nonce {
        filename.push(LOWER_HEX[usize::from(byte >> 4)]);
        filename.push(LOWER_HEX[usize::from(byte & 0x0f)]);
    }
    filename.extend_from_slice(suffix);
    assert_eq!(filename.len(), if artifact == 1 { 46 } else { 44 });
    filename
}

fn expected_sd_begin(artifact: u8, total: u32, caller_nonce: &[u8; 16]) -> Vec<u8> {
    let filename = sd_filename(caller_nonce, artifact);
    let aux_len = 1 + filename.len();
    let body_len = 9 + filename.len();
    let mut expected = Vec::with_capacity(8 + body_len);
    expected.extend_from_slice(&[1, 3, 0, 0]);
    expected.extend_from_slice(&(body_len as u32).to_le_bytes());
    expected.extend_from_slice(&[1, artifact]);
    expected.extend_from_slice(&total.to_le_bytes());
    expected.extend_from_slice(&(aux_len as u16).to_le_bytes());
    expected.push(filename.len() as u8);
    expected.extend_from_slice(&filename);
    assert_eq!(expected.len(), if artifact == 1 { 63 } else { 61 });
    expected
}

fn expected_bbqr_begin(artifact: u8, total: u32, part_len: u16) -> Vec<u8> {
    let mut expected = vec![1, 3, 0, 0, 10, 0, 0, 0, 2, artifact];
    expected.extend_from_slice(&total.to_le_bytes());
    expected.extend_from_slice(&2u16.to_le_bytes());
    expected.extend_from_slice(&part_len.to_le_bytes());
    assert_eq!(expected.len(), 18);
    expected
}

fn drive_export(
    session: &mut NormalSessionV2,
    begin: qk_core::NormalProgressV2,
    expected_sink: u8,
    caller_nonce: Option<[u8; 16]>,
    expected_part_len: Option<u16>,
    fault: ExportFault,
) -> Result<Vec<(u8, Vec<u8>)>, NormalErrorV2> {
    let mut outbound = begin.into_outbound().expect("first egress request");
    let mut current: Option<(u8, u32, usize, Vec<u8>)> = None;
    let mut delivered = Vec::new();
    loop {
        let payload = outer_payload(&outbound);
        assert!(payload.len() >= 8);
        assert_eq!(payload[0], 1);
        let opcode = payload[1];
        let response_body = match opcode {
            3 => {
                let sink = payload[8];
                let artifact = payload[9];
                assert_eq!(sink, expected_sink);
                let total = u32::from_le_bytes(payload[10..14].try_into().expect("total"));
                let part_len = if sink == 2 {
                    let selected = expected_part_len.expect("BBQr geometry");
                    assert!(caller_nonce.is_none());
                    assert_eq!(payload, expected_bbqr_begin(artifact, total, selected));
                    usize::from(selected)
                } else {
                    let nonce = caller_nonce.expect("SD caller nonce");
                    assert!(expected_part_len.is_none());
                    assert_eq!(payload, expected_sd_begin(artifact, total, &nonce));
                    0
                };
                assert!(
                    current
                        .replace((artifact, total, part_len, Vec::new()))
                        .is_none()
                );
                if fault == ExportFault::PartialSecondSd && !delivered.is_empty() {
                    vec![0]
                } else {
                    Vec::new()
                }
            }
            4 => {
                let (artifact, total, part_len, bytes) =
                    current.as_mut().expect("begin precedes write");
                let offset = u32::from_le_bytes(payload[8..12].try_into().expect("offset"));
                let chunk_len = usize::try_from(u32::from_le_bytes(
                    payload[12..16].try_into().expect("chunk length"),
                ))
                .expect("HOST usize");
                assert_eq!(usize::try_from(offset).expect("HOST usize"), bytes.len());
                assert_eq!(payload.len(), 16 + chunk_len);
                bytes.extend_from_slice(&payload[16..]);
                assert!(bytes.len() <= usize::try_from(*total).expect("HOST usize"));
                let _ = (*artifact, *part_len);
                (bytes.len() as u32).to_le_bytes().to_vec()
            }
            5 => {
                assert_eq!(payload, [1, 5, 0, 0, 0, 0, 0, 0]);
                let (artifact, total, part_len, bytes) =
                    current.take().expect("begin and write precede finish");
                assert_eq!(bytes.len(), usize::try_from(total).expect("HOST usize"));
                let expected = match artifact {
                    1 => hex_vec(field(SIGNING, "finalized_psbt_hex")),
                    2 => hex_vec(field(SIGNING, "raw_transaction_hex")),
                    _ => panic!("closed artifact byte"),
                };
                assert_eq!(bytes, expected);
                delivered.push((artifact, bytes.clone()));
                if expected_sink == 1 {
                    let mut body = Vec::with_capacity(6);
                    body.extend_from_slice(&[1, artifact]);
                    let receipt_total = if fault == ExportFault::WrongSdReceipt {
                        total.checked_add(1).expect("bounded fixture length")
                    } else {
                        total
                    };
                    body.extend_from_slice(&receipt_total.to_le_bytes());
                    body
                } else {
                    let file_type = if artifact == 1 { b'P' } else { b'T' };
                    let frames = match fault {
                        ExportFault::NineByteBbqr => {
                            let mut frame = b"B$2P0100A".to_vec();
                            frame[3] = file_type;
                            vec![frame]
                        }
                        ExportFault::DifferentBbqrGeometry => {
                            let alternate = if part_len == 10 { 15 } else { 10 };
                            bbqr_frames(file_type, &bytes, alternate)
                        }
                        _ => bbqr_frames(file_type, &bytes, part_len),
                    };
                    let mut body = Vec::new();
                    body.extend_from_slice(&[2, artifact]);
                    body.extend_from_slice(&total.to_le_bytes());
                    body.extend_from_slice(&(frames.len() as u16).to_le_bytes());
                    for frame in frames {
                        body.extend_from_slice(&(frame.len() as u16).to_le_bytes());
                        body.extend_from_slice(&frame);
                    }
                    if fault == ExportFault::MalformedBbqr {
                        let first_frame = body
                            .get_mut(10)
                            .expect("one encoded frame after the eight-byte receipt prefix");
                        *first_frame = b'C';
                    }
                    body
                }
            }
            _ => panic!("closed normal egress opcode"),
        };
        let response = operation_response(&outbound, opcode, &response_body);
        let outcome = session.receive(&response, false)?;
        if outcome.stage() == NormalStageV2::TransactionResult {
            break;
        }
        outbound = outcome.into_outbound().expect("next egress request");
    }
    Ok(delivered)
}

fn run_valid(data: &[u8], scenario: u8, source: Source) -> ValidRunFact {
    let mut cursor = Cursor::new(data);
    let (profile, profile_byte, sd) = match scenario {
        0 => (NormalProfileV2::SimpleRecovery, 1, true),
        1 => (NormalProfileV2::SimpleRecovery, 1, false),
        2 => (NormalProfileV2::Inheritance, 2, true),
        3 => (NormalProfileV2::Inheritance, 2, false),
        4 => (NormalProfileV2::QuantumShelter, 3, true),
        5 => (NormalProfileV2::QuantumShelter, 3, false),
        _ => unreachable!("modulo six is exhaustive"),
    };
    let namespace = cursor.array::<12>();
    let last_counter = u32::from_le_bytes(cursor.array::<4>()).min(u32::MAX - 1);
    let caller_nonce = cursor.array::<16>();
    let part_len = 10u16 + u16::from(cursor.byte() % 9) * 5;
    let (mut session, opening) = NormalSessionV2::fuzz_start(
        namespace,
        last_counter,
        &[profile_byte],
        grants(CardMutation::None),
    )
    .expect("registered normal start");
    let ready = outer_response(&opening, MessageKind::SessionReady, &[]);
    assert_eq!(
        session
            .receive(&ready, false)
            .expect("session ready")
            .stage(),
        NormalStageV2::ProfileBinding
    );
    assert_eq!(session.profile(), profile);
    assert_eq!(
        session
            .confirm_profile()
            .expect("profile confirmation")
            .stage(),
        NormalStageV2::Transport
    );

    let psbt = hex_vec(field(SIGNING, "s0_hex"));
    let begin = session
        .begin_psbt_intake(source)
        .expect("purpose-bound PSBT intake");
    assert_eq!(
        drive_ingress(&mut session, begin, source, &psbt),
        Ok(NormalStageV2::FactorB)
    );
    assert_eq!(session.stage(), NormalStageV2::FactorB);
    assert_eq!(
        session
            .accept_card_b()
            .expect("authenticated factor B")
            .stage(),
        NormalStageV2::A1Intake
    );
    let a1 = hex_vec(field(PROVISIONING, "a1_capsule_hex"));
    let begin = session.begin_a1_intake().expect("purpose-bound A1 intake");
    assert_eq!(
        drive_ingress(&mut session, begin, Source::CameraA1Candidate, &a1),
        Ok(NormalStageV2::FactorA1)
    );
    assert_eq!(session.stage(), NormalStageV2::FactorA1);
    assert_eq!(
        session
            .validate()
            .expect("binding and semantic proof")
            .stage(),
        NormalStageV2::Review
    );

    for expected in REVIEW_ORDER {
        assert_eq!(session.review_position(), Some(expected));
        if expected != NormalReviewPositionV2::FinalApproval {
            session.advance_review().expect("fixed-order review");
        }
    }
    assert_eq!(session.stage(), NormalStageV2::FinalApproval);
    let token = session.begin_approval_hold().expect("current review hold");
    assert_eq!(token.cycle(), 1);
    assert_eq!(
        session
            .complete_approval_hold(token)
            .expect("revalidate, sign, verify and finalize")
            .stage(),
        NormalStageV2::AwaitingExportAction
    );
    let identity = session
        .approval_identity()
        .expect("bound approval identity");
    assert_eq!(identity.profile(), profile);
    assert_eq!(identity.cycle(), 1);
    let registered_media_review_hash = hex_array(field(SIGNING, "review_hash_hex"));
    if source == Source::MediaPsbt {
        assert_eq!(identity.review_hash(), registered_media_review_hash);
    } else {
        assert_ne!(identity.review_hash(), registered_media_review_hash);
    }

    let action = if sd {
        NormalExportActionV2::Sd { caller_nonce }
    } else {
        NormalExportActionV2::Bbqr {
            non_final_part_len: part_len,
        }
    };
    let begin = session.choose_export(action).expect("one profile route");
    let delivered = drive_export(
        &mut session,
        begin,
        if sd { 1 } else { 2 },
        sd.then_some(caller_nonce),
        (!sd).then_some(part_len),
        ExportFault::None,
    )
    .expect("canonical delivery");
    let result = session.result().expect("immutable result facts");
    assert_eq!(result.profile(), profile);
    assert_eq!(
        result.route(),
        if sd {
            NormalExportRouteV2::Sd
        } else {
            NormalExportRouteV2::Bbqr
        }
    );
    assert_eq!(result.txid(), hex_array(field(SIGNING, "txid_raw_hex")));
    assert_eq!(result.wtxid(), hex_array(field(SIGNING, "wtxid_raw_hex")));

    let psbt_fact = result.finalized_psbt();
    let raw_fact = result.raw_transaction();
    let delivered_kinds: Vec<u8> = delivered.iter().map(|item| item.0).collect();
    let expected_delivered: &[u8] = match (profile, sd) {
        (NormalProfileV2::SimpleRecovery | NormalProfileV2::Inheritance, true) => &[1, 2],
        (NormalProfileV2::SimpleRecovery | NormalProfileV2::Inheritance, false) => &[1],
        (NormalProfileV2::QuantumShelter, _) => &[2],
    };
    assert_eq!(delivered_kinds, expected_delivered);
    if profile == NormalProfileV2::QuantumShelter {
        assert!(psbt_fact.is_none());
    } else {
        let fact = psbt_fact.expect("Simple and Inheritance bind finalized PSBT");
        assert_eq!(fact.kind(), NormalArtifactKindV2::FinalizedPsbt);
        assert_eq!(fact.serialized_len(), 818);
        assert_eq!(
            fact.sha256(),
            hex_array(field(SIGNING, "finalized_psbt_sha256"))
        );
    }
    let raw_expected = sd || profile == NormalProfileV2::QuantumShelter;
    assert_eq!(raw_fact.is_some(), raw_expected);
    if let Some(fact) = raw_fact {
        assert_eq!(fact.kind(), NormalArtifactKindV2::RawTransaction);
        assert_eq!(fact.serialized_len(), 404);
        assert_eq!(
            fact.sha256(),
            hex_array(field(SIGNING, "raw_transaction_sha256"))
        );
    }
    let psbt_sd_receipt = result.finalized_psbt_sd_receipt();
    let raw_sd_receipt = result.raw_transaction_sd_receipt();
    assert_eq!(
        psbt_sd_receipt.is_some(),
        sd && profile != NormalProfileV2::QuantumShelter
    );
    assert_eq!(raw_sd_receipt.is_some(), sd);
    if let Some(receipt) = psbt_sd_receipt {
        assert_eq!(receipt.artifact(), NormalArtifactKindV2::FinalizedPsbt);
        assert_eq!(receipt.total_len(), 818);
    }
    if let Some(receipt) = raw_sd_receipt {
        assert_eq!(receipt.artifact(), NormalArtifactKindV2::RawTransaction);
        assert_eq!(receipt.total_len(), 404);
    }

    let fact = ValidRunFact {
        profile,
        source,
        route: result.route(),
        review_hash: identity.review_hash(),
        finalized_psbt: result.finalized_psbt(),
        raw_transaction: result.raw_transaction(),
        psbt_sd_receipt,
        raw_sd_receipt,
        txid: result.txid(),
        wtxid: result.wtxid(),
        delivered,
        wiped: 0,
    };

    reset_wiped_bytes();
    let close = session
        .complete_result()
        .expect("acknowledge result")
        .into_outbound()
        .expect("sole close request");
    let closed = outer_response(&close, MessageKind::SessionClosed, &[]);
    assert_eq!(
        session
            .receive(&closed, false)
            .expect("graceful close")
            .stage(),
        NormalStageV2::CompletedWiped
    );
    assert!(session.is_terminal());
    let wiped = wiped_bytes();
    assert!(wiped > 0, "graceful completion must clear owned buffers");
    ValidRunFact { wiped, ..fact }
}

fn reach_factor_b_with(
    data: &[u8],
    mutation: CardMutation,
    source: Source,
    profile_byte: u8,
    psbt: &[u8],
) -> NormalSessionV2 {
    let mut cursor = Cursor::new(data);
    let namespace = cursor.array::<12>();
    let last_counter = u32::from_le_bytes(cursor.array::<4>()).min(u32::MAX - 1);
    let (mut session, opening) =
        NormalSessionV2::fuzz_start(namespace, last_counter, &[profile_byte], grants(mutation))
            .expect("registered normal start");
    let ready = outer_response(&opening, MessageKind::SessionReady, &[]);
    assert_eq!(
        session
            .receive(&ready, false)
            .expect("session ready")
            .stage(),
        NormalStageV2::ProfileBinding
    );
    assert_eq!(
        session
            .confirm_profile()
            .expect("profile confirmation")
            .stage(),
        NormalStageV2::Transport
    );
    let begin = session
        .begin_psbt_intake(source)
        .expect("purpose-bound PSBT intake");
    assert_eq!(
        drive_ingress(&mut session, begin, source, psbt),
        Ok(NormalStageV2::FactorB)
    );
    session
}

fn reach_factor_b(data: &[u8], mutation: CardMutation, source: Source) -> NormalSessionV2 {
    let psbt = hex_vec(field(SIGNING, "s0_hex"));
    reach_factor_b_with(data, mutation, source, 1, &psbt)
}

fn reach_review_profile(
    data: &[u8],
    mutation: CardMutation,
    profile_byte: u8,
    corrupt_a1: bool,
) -> NormalSessionV2 {
    let psbt = hex_vec(field(SIGNING, "s0_hex"));
    let mut session = reach_factor_b_with(data, mutation, Source::MediaPsbt, profile_byte, &psbt);
    assert_eq!(
        session
            .accept_card_b()
            .expect("authenticated card data")
            .stage(),
        NormalStageV2::A1Intake
    );
    let begin = session.begin_a1_intake().expect("A1 intake");
    let mut a1 = hex_vec(field(PROVISIONING, "a1_capsule_hex"));
    if corrupt_a1 {
        a1[0] ^= 1;
    }
    assert_eq!(
        drive_ingress(&mut session, begin, Source::CameraA1Candidate, &a1),
        Ok(NormalStageV2::FactorA1)
    );
    assert_eq!(
        session
            .validate()
            .expect("binding and semantic proof")
            .stage(),
        NormalStageV2::Review
    );
    session
}

fn reach_review(data: &[u8], mutation: CardMutation, corrupt_a1: bool) -> NormalSessionV2 {
    reach_review_profile(data, mutation, 1, corrupt_a1)
}

fn finish_review(session: &mut NormalSessionV2) {
    for expected in REVIEW_ORDER {
        assert_eq!(session.review_position(), Some(expected));
        if expected != NormalReviewPositionV2::FinalApproval {
            session.advance_review().expect("fixed-order review");
        }
    }
    assert_eq!(session.stage(), NormalStageV2::FinalApproval);
}

fn finish_approval(session: &mut NormalSessionV2) {
    finish_review(session);
    let token = session.begin_approval_hold().expect("current review hold");
    assert_eq!(
        session
            .complete_approval_hold(token)
            .expect("verified finalization")
            .stage(),
        NormalStageV2::AwaitingExportAction
    );
}

fn failure_fact(
    case: u8,
    session: &mut NormalSessionV2,
    error: NormalErrorV2,
    expected: NormalErrorV2,
) -> FailureRunFact {
    assert_eq!(error, expected);
    assert_eq!(session.terminal_error(), Some(expected));
    assert!(session.is_terminal());
    let stage = session.stage();
    let latched_error = session.terminal_error();
    let wiped = wiped_bytes();
    assert!(wiped > 0, "terminating rejection must clear owned buffers");
    assert_eq!(
        session
            .interrupt(Interruption::OperationFailed)
            .expect_err("a terminal session absorbs every later operation"),
        NormalErrorV2::Finished
    );
    assert_eq!(session.stage(), stage);
    assert_eq!(session.terminal_error(), latched_error);
    assert_eq!(wiped_bytes(), wiped);
    FailureRunFact {
        case,
        error: normal_error_name(error),
        stage,
        terminal: true,
        wiped,
    }
}

fn run_failure(data: &[u8], case: u8) -> FailureRunFact {
    match case {
        6 => {
            let mut session = reach_factor_b(data, CardMutation::Descriptor, Source::MediaPsbt);
            reset_wiped_bytes();
            let error = match session.accept_card_b() {
                Ok(_) => panic!("corrupt descriptor binding must reject"),
                Err(error) => error,
            };
            failure_fact(case, &mut session, error, NormalErrorV2::CardDataRejected)
        }
        7 => {
            let mut session = reach_factor_b(data, CardMutation::A2, Source::MediaPsbt);
            session
                .accept_card_b()
                .expect("card binding remains public-valid");
            let begin = session.begin_a1_intake().expect("A1 intake");
            let a1 = hex_vec(field(PROVISIONING, "a1_capsule_hex"));
            reset_wiped_bytes();
            let error = drive_ingress(&mut session, begin, Source::CameraA1Candidate, &a1)
                .expect_err("wrong A2 must reject A1 authentication");
            failure_fact(case, &mut session, error, NormalErrorV2::A1Rejected)
        }
        8 => {
            let mut session = reach_factor_b(data, CardMutation::None, Source::MediaPsbt);
            session.accept_card_b().expect("card binding");
            let begin = session.begin_a1_intake().expect("A1 intake");
            let mut a1 = hex_vec(field(PROVISIONING, "a1_capsule_hex"));
            a1[0] ^= 1;
            reset_wiped_bytes();
            let error = drive_ingress(&mut session, begin, Source::CameraA1Candidate, &a1)
                .expect_err("corrupt A1 must reject");
            failure_fact(case, &mut session, error, NormalErrorV2::A1Rejected)
        }
        9 => {
            let mut session = reach_review(data, CardMutation::InvalidSignature, false);
            finish_review(&mut session);
            let token = session.begin_approval_hold().expect("current hold");
            reset_wiped_bytes();
            let error = match session.complete_approval_hold(token) {
                Ok(_) => panic!("invalid B signature must never reach export"),
                Err(error) => error,
            };
            failure_fact(
                case,
                &mut session,
                error,
                NormalErrorV2::InvalidMockSignature,
            )
        }
        10 => {
            let mut session = reach_review(data, CardMutation::WrongSignatureInput, false);
            finish_review(&mut session);
            let token = session.begin_approval_hold().expect("current hold");
            reset_wiped_bytes();
            let error = match session.complete_approval_hold(token) {
                Ok(_) => panic!("wrong-input B signature must never be rebound"),
                Err(error) => error,
            };
            failure_fact(
                case,
                &mut session,
                error,
                NormalErrorV2::FinalizationRejected,
            )
        }
        11 => {
            let mut first = reach_review(data, CardMutation::None, false);
            let mut second = reach_review(&[0x55; 32], CardMutation::None, false);
            finish_review(&mut first);
            finish_review(&mut second);
            let first_token = first.begin_approval_hold().expect("first current hold");
            let wrong_token = second.begin_approval_hold().expect("second-session hold");
            assert!(first_token != wrong_token);
            reset_wiped_bytes();
            let error = match first.complete_approval_hold(wrong_token) {
                Ok(_) => panic!("a token from another session must reject"),
                Err(error) => error,
            };
            failure_fact(
                case,
                &mut first,
                error,
                NormalErrorV2::ReviewIdentityMismatch,
            )
        }
        12 => {
            let mut session = reach_review(data, CardMutation::None, false);
            finish_approval(&mut session);
            reset_wiped_bytes();
            let error = match session.begin_psbt_intake(Source::MediaPsbt) {
                Ok(_) => panic!("no intake may yield after completed approval"),
                Err(error) => error,
            };
            failure_fact(case, &mut session, error, NormalErrorV2::PostApprovalYield)
        }
        13 => {
            let mut session = reach_review(data, CardMutation::None, false);
            finish_approval(&mut session);
            let begin = session
                .choose_export(NormalExportActionV2::Sd {
                    caller_nonce: [0x13; 16],
                })
                .expect("Simple SD route");
            reset_wiped_bytes();
            let error = drive_export(
                &mut session,
                begin,
                1,
                Some([0x13; 16]),
                None,
                ExportFault::PartialSecondSd,
            )
            .expect_err("second-artifact failure is partial completion");
            failure_fact(
                case,
                &mut session,
                error,
                NormalErrorV2::PartialSdCompletion,
            )
        }
        14 => {
            let mut session = reach_review(data, CardMutation::None, false);
            finish_approval(&mut session);
            let begin = session
                .choose_export(NormalExportActionV2::Bbqr {
                    non_final_part_len: 10,
                })
                .expect("Simple BBQr route");
            reset_wiped_bytes();
            let error = drive_export(
                &mut session,
                begin,
                2,
                None,
                Some(10),
                ExportFault::MalformedBbqr,
            )
            .expect_err("malformed broker BBQr must reject");
            failure_fact(
                case,
                &mut session,
                error,
                NormalErrorV2::BbqrVerificationMismatch,
            )
        }
        15 => {
            let mut session = reach_review(data, CardMutation::None, false);
            finish_approval(&mut session);
            reset_wiped_bytes();
            let error = session
                .interrupt(Interruption::CardRemoved)
                .expect_err("approved-session interruption terminates");
            failure_fact(
                case,
                &mut session,
                error,
                NormalErrorV2::Interrupted(Interruption::CardRemoved),
            )
        }
        16 => {
            let mut session = reach_factor_b(data, CardMutation::Absent, Source::MediaPsbt);
            reset_wiped_bytes();
            let error = match session.accept_card_b() {
                Ok(_) => panic!("an absent card must reject"),
                Err(error) => error,
            };
            failure_fact(case, &mut session, error, NormalErrorV2::CardAbsent)
        }
        17 => {
            let mut session = reach_factor_b(data, CardMutation::WalletId, Source::MediaPsbt);
            reset_wiped_bytes();
            let error = match session.accept_card_b() {
                Ok(_) => panic!("a valid descriptor pair with another wallet id must reject"),
                Err(error) => error,
            };
            failure_fact(
                case,
                &mut session,
                error,
                NormalErrorV2::CardBindingMismatch,
            )
        }
        18 => {
            let mut session =
                reach_factor_b_with(data, CardMutation::None, Source::MediaPsbt, 1, &[0]);
            session.accept_card_b().expect("public card binding");
            let begin = session.begin_a1_intake().expect("A1 intake");
            let a1 = hex_vec(field(PROVISIONING, "a1_capsule_hex"));
            assert_eq!(
                drive_ingress(&mut session, begin, Source::CameraA1Candidate, &a1),
                Ok(NormalStageV2::FactorA1)
            );
            reset_wiped_bytes();
            let error = match session.validate() {
                Ok(_) => panic!("a structurally invalid PSBT must not produce review facts"),
                Err(error) => error,
            };
            failure_fact(case, &mut session, error, NormalErrorV2::ReviewRejected)
        }
        19 => {
            let mut session = reach_review(data, CardMutation::None, false);
            reset_wiped_bytes();
            let error = match session.begin_approval_hold() {
                Ok(_) => panic!("approval is unavailable before the full review"),
                Err(error) => error,
            };
            failure_fact(
                case,
                &mut session,
                error,
                NormalErrorV2::ApprovalUnavailable,
            )
        }
        20 => {
            let mut session = reach_review(data, CardMutation::None, false);
            finish_review(&mut session);
            reset_wiped_bytes();
            let error = match session.advance_review() {
                Ok(_) => panic!("review cannot advance beyond the final position"),
                Err(error) => error,
            };
            failure_fact(case, &mut session, error, NormalErrorV2::ReviewIncomplete)
        }
        21 => {
            let mut session = reach_review(data, CardMutation::None, false);
            finish_approval(&mut session);
            reset_wiped_bytes();
            let error = match session.choose_export(NormalExportActionV2::Bbqr {
                non_final_part_len: 9,
            }) {
                Ok(_) => panic!("invalid BBQr geometry must not open an export route"),
                Err(error) => error,
            };
            failure_fact(
                case,
                &mut session,
                error,
                NormalErrorV2::ExportRouteUnavailable,
            )
        }
        22 => {
            let mut session = reach_review_profile(data, CardMutation::None, 3, false);
            finish_approval(&mut session);
            let begin = session
                .choose_export(NormalExportActionV2::Sd {
                    caller_nonce: [0x22; 16],
                })
                .expect("Quantum Shelter SD route");
            reset_wiped_bytes();
            let error = drive_export(
                &mut session,
                begin,
                1,
                Some([0x22; 16]),
                None,
                ExportFault::WrongSdReceipt,
            )
            .expect_err("wrong Quantum Shelter SD receipt must reject");
            failure_fact(
                case,
                &mut session,
                error,
                NormalErrorV2::ExportReceiptMismatch,
            )
        }
        23 => {
            let mut session = reach_review_profile(data, CardMutation::None, 3, false);
            finish_approval(&mut session);
            let begin = session
                .choose_export(NormalExportActionV2::Bbqr {
                    non_final_part_len: 10,
                })
                .expect("Quantum Shelter BBQr route");
            reset_wiped_bytes();
            let error = drive_export(
                &mut session,
                begin,
                2,
                None,
                Some(10),
                ExportFault::NineByteBbqr,
            )
            .expect_err("structural nine-byte BBQr must reject");
            failure_fact(
                case,
                &mut session,
                error,
                NormalErrorV2::BbqrVerificationMismatch,
            )
        }
        24 => {
            let mut session = reach_review_profile(data, CardMutation::None, 3, false);
            finish_approval(&mut session);
            let begin = session
                .choose_export(NormalExportActionV2::Bbqr {
                    non_final_part_len: 10,
                })
                .expect("Quantum Shelter BBQr route");
            reset_wiped_bytes();
            let error = drive_export(
                &mut session,
                begin,
                2,
                None,
                Some(10),
                ExportFault::DifferentBbqrGeometry,
            )
            .expect_err("same payload under unselected valid geometry must reject");
            failure_fact(
                case,
                &mut session,
                error,
                NormalErrorV2::BbqrVerificationMismatch,
            )
        }
        _ => unreachable!("closed failure scenario"),
    }
}

fuzz_target!(|data: &[u8]| {
    let selector = data.first().copied().unwrap_or(0) % 25;
    let source = if data.get(1).copied().unwrap_or(0) & 1 == 0 {
        Source::MediaPsbt
    } else {
        Source::CameraBbqrPsbt
    };
    let repeat = data.get(2).copied().unwrap_or(0) & 1 != 0;
    if selector < 6 {
        let first = run_valid(data, selector, source);
        if repeat || source == Source::CameraBbqrPsbt {
            assert_eq!(first, run_valid(data, selector, source));
        }
    } else {
        let first = run_failure(data, selector);
        if repeat {
            assert_eq!(first, run_failure(data, selector));
        }
    }
});
