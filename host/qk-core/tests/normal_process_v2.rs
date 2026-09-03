//! QK-DEC-156 pure Normal process controller and staging locks.

#![cfg(all(feature = "normal-process", feature = "fuzzing"))]

use qk_core::fuzz::{reset_wiped_bytes, wiped_bytes};
use qk_core::{
    KeypadKey, NormalErrorV2, NormalProcessControllerV2, NormalProcessErrorV2,
    NormalProcessEventV2, NormalProcessStageV2, NormalStageV2, Source,
};
use qk_io::{
    parse_request, BrokerReply, BrokerSession, MockInput, MockOutputWriter, Request,
    Sink as IoSink, Source as IoSource,
};
use qk_ipc::{ReceivedFrame, StreamDecoder};
use std::collections::BTreeMap;

const SIGNING: &str = include_str!("../../qk-psbt/tests/fixtures/signing_finalization_v2.txt");
const PROVISIONING: &str = include_str!("../../qk-provisioning/tests/fixtures/provisioning_v2.txt");
const NAMESPACE: [u8; 12] = [0x56; 12];

#[derive(Clone, Copy)]
enum SignatureCase {
    Valid,
    WrongReviewHash,
    WrongInputIndex,
    WrongKey,
    HighS,
    MalformedDer,
    Invalid,
}

fn fields(source: &'static str) -> BTreeMap<&'static str, &'static str> {
    source
        .lines()
        .filter(|line| !line.starts_with('#'))
        .filter_map(|line| line.split_once(": "))
        .collect()
}

fn hex_vec(text: &str) -> Vec<u8> {
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

fn media_record(payload: &[u8]) -> Vec<u8> {
    let name = b"normal-v2.psbt";
    let mut record = Vec::with_capacity(1 + name.len() + 4 + payload.len());
    record.push(name.len() as u8);
    record.extend_from_slice(name);
    record.extend_from_slice(&(payload.len() as u32).to_le_bytes());
    record.extend_from_slice(payload);
    record
}

fn signature_der(case: SignatureCase, valid: &[u8]) -> Vec<u8> {
    match case {
        SignatureCase::Valid
        | SignatureCase::WrongReviewHash
        | SignatureCase::WrongInputIndex
        | SignatureCase::WrongKey => valid.to_vec(),
        SignatureCase::HighS => hex_vec("3046022100ccbfad55e5be35282e8927ef2694257e694a7738513c3fc3e396495227809769022100bf61fc4abd1a78f9fa367c00a6442598aebf994ca058bf34e8a747b94a49ad0a"),
        SignatureCase::MalformedDer => vec![0u8; 8],
        SignatureCase::Invalid => {
            let mut invalid = valid.to_vec();
            if let Some(byte) = invalid.last_mut() {
                *byte ^= 1;
            }
            invalid
        }
    }
}

fn submit_card_signature(
    controller: &mut NormalProcessControllerV2,
    case: SignatureCase,
) -> Result<Option<qk_core::CoreOutbound>, NormalProcessErrorV2> {
    let signing = fields(SIGNING);
    let request = controller
        .card_b_signing_request()
        .expect("post-revalidation request");
    let mut review_hash = *request.review_hash();
    if matches!(case, SignatureCase::WrongReviewHash) {
        review_hash[0] ^= 1;
    }
    let input_index = if matches!(case, SignatureCase::WrongInputIndex) {
        request.input_index().saturating_add(1)
    } else {
        request.input_index()
    };
    let mut role_b_pubkey = *request.role_b_pubkey();
    if matches!(case, SignatureCase::WrongKey) {
        role_b_pubkey[1] ^= 1;
    }
    let mut der = signature_der(case, &hex_vec(signing["role_b_der_hex"]));
    drop(request);
    let result =
        controller.accept_card_b_signature(review_hash, input_index, role_b_pubkey, &mut der);
    assert!(der.iter().all(|byte| *byte == 0));
    result
}

fn factor_body(case: SignatureCase) -> Vec<u8> {
    let provision = fields(PROVISIONING);
    let signing = fields(SIGNING);
    let mut key = hex_vec(provision["receive_0_role_b_pubkey"]);
    if matches!(case, SignatureCase::WrongKey) {
        key[1] ^= 1;
    }
    let der = signature_der(case, &hex_vec(signing["role_b_der_hex"]));
    let mut body = Vec::new();
    body.extend_from_slice(provision["receive_descriptor"].as_bytes());
    body.extend_from_slice(provision["change_descriptor"].as_bytes());
    body.extend_from_slice(&hex_vec(provision["wallet_id"]));
    body.extend_from_slice(provision["role_b_account_xpub"].as_bytes());
    body.extend_from_slice(&hex_vec(provision["a2_transcript_sha256"]));
    body.extend_from_slice(&1u16.to_le_bytes());
    body.extend_from_slice(&0u32.to_le_bytes());
    body.extend_from_slice(&key);
    body.push(der.len() as u8);
    body.extend_from_slice(&der);
    body
}

fn decode_one(bytes: &[u8]) -> ReceivedFrame {
    let mut decoder = StreamDecoder::new();
    let outcome = decoder.ingest(bytes, false).expect("complete QKIP frame");
    assert_eq!(outcome.consumed(), bytes.len());
    assert!(outcome.frame_ready());
    decoder.take_frame().expect("owned QKIP frame")
}

fn reply(
    broker: &mut BrokerSession,
    outbound: &qk_core::CoreOutbound,
    input: Option<&mut MockInput>,
    writer: Option<&mut MockOutputWriter>,
) -> BrokerReply {
    broker
        .accept(&decode_one(outbound.frame_bytes()), input, writer)
        .expect("purpose-bound broker reply")
}

fn receive_reply(
    controller: &mut NormalProcessControllerV2,
    reply: &BrokerReply,
) -> Option<qk_core::CoreOutbound> {
    controller
        .receive_qkip(reply.frame_bytes(), false)
        .expect("hostile response reparsed")
}

fn drive_ingress(
    controller: &mut NormalProcessControllerV2,
    broker: &mut BrokerSession,
    begin: qk_core::CoreOutbound,
    source: IoSource,
    bytes: &[u8],
) {
    let mut input = MockInput::try_new(source, bytes).expect("bounded fixture input");
    let began = reply(broker, &begin, Some(&mut input), None);
    assert!(input.is_used());
    let read = receive_reply(controller, &began).expect("read request");
    let chunk = reply(broker, &read, None, None);
    assert!(receive_reply(controller, &chunk).is_none());
}

fn reach_final_approval(case: SignatureCase) -> (NormalProcessControllerV2, BrokerSession) {
    let signing = fields(SIGNING);
    let provision = fields(PROVISIONING);
    let mut controller =
        NormalProcessControllerV2::fuzz_start(b"01", NAMESPACE, 0).expect("profile");
    controller.accept_profile(0x01).expect("card profile");
    let opening = controller
        .accept_normal_factor(&factor_body(case))
        .expect("factor retained without signature inspection");
    let mut broker = BrokerSession::new();
    let ready = reply(&mut broker, &opening, None, None);
    assert!(receive_reply(&mut controller, &ready).is_none());
    assert_eq!(
        controller.stage(),
        NormalProcessStageV2::Normal(NormalStageV2::ProfileBinding)
    );

    assert!(controller
        .handle_event(NormalProcessEventV2::LogicalKey(
            KeypadKey::EqualsConfirmEnter,
        ))
        .expect("profile confirmation")
        .is_none());
    let begin = controller
        .handle_event(NormalProcessEventV2::SelectPsbtSource(Source::MediaPsbt))
        .expect("source")
        .expect("PSBT begin");
    drive_ingress(
        &mut controller,
        &mut broker,
        begin,
        IoSource::MediaPsbt,
        &media_record(&hex_vec(signing["s0_hex"])),
    );
    assert_eq!(
        controller.stage(),
        NormalProcessStageV2::Normal(NormalStageV2::FactorB)
    );

    let a1_begin = controller
        .advance_automatic()
        .expect("factor B accepted without reading signatures")
        .expect("A1 begin");
    drive_ingress(
        &mut controller,
        &mut broker,
        a1_begin,
        IoSource::CameraA1Candidate,
        &hex_vec(provision["a1_capsule_hex"]),
    );
    assert!(controller
        .advance_automatic()
        .expect("validation does not inspect signature records")
        .is_none());
    while controller.stage() == NormalProcessStageV2::Normal(NormalStageV2::Review) {
        assert!(controller
            .handle_event(NormalProcessEventV2::LogicalKey(
                KeypadKey::EqualsConfirmEnter,
            ))
            .expect("fixed review order")
            .is_none());
    }
    assert_eq!(
        controller.stage(),
        NormalProcessStageV2::Normal(NormalStageV2::FinalApproval)
    );
    (controller, broker)
}

fn finish_sd_export(controller: &mut NormalProcessControllerV2, broker: &mut BrokerSession) {
    let mut psbt_writer = MockOutputWriter::new(IoSink::Sd);
    let mut tx_writer = MockOutputWriter::new(IoSink::Sd);
    let mut outbound = controller
        .handle_event(NormalProcessEventV2::SelectSd {
            caller_nonce: [0x51; 16],
        })
        .expect("SD route")
        .expect("first write");
    let mut finish_count = 0usize;
    loop {
        let frame = decode_one(outbound.frame_bytes());
        let request = parse_request(frame.payload()).expect("exact request");
        let response = match request {
            Request::EgressFinish if finish_count == 0 => {
                finish_count += 1;
                broker
                    .accept(&frame, None, Some(&mut psbt_writer))
                    .expect("PSBT finish")
            }
            Request::EgressFinish if finish_count == 1 => {
                finish_count += 1;
                broker
                    .accept(&frame, None, Some(&mut tx_writer))
                    .expect("transaction finish")
            }
            Request::EgressBegin { .. } | Request::EgressWrite { .. } => {
                broker.accept(&frame, None, None).expect("bounded write")
            }
            _ => panic!("unexpected export request"),
        };
        match receive_reply(controller, &response) {
            Some(next) => outbound = next,
            None => break,
        }
    }
    assert_eq!(finish_count, 2);
    assert!(psbt_writer.final_bytes().is_some());
    assert!(tx_writer.final_bytes().is_some());
}

fn drain_stages(controller: &mut NormalProcessControllerV2) -> Vec<NormalStageV2> {
    let mut stages = Vec::new();
    while let Some(stage) = controller.fuzz_take_display_stage() {
        stages.push(stage);
    }
    stages
}

#[test]
fn complete_controller_emits_only_the_exact_stage_frame_sequence() {
    let (mut controller, mut broker) = reach_final_approval(SignatureCase::Valid);
    assert!(controller
        .handle_event(NormalProcessEventV2::HoldCompleted)
        .expect("revalidate and request card signature")
        .is_none());
    assert_eq!(
        controller.stage(),
        NormalProcessStageV2::Normal(NormalStageV2::CardBSigning)
    );
    assert!(submit_card_signature(&mut controller, SignatureCase::Valid)
        .expect("verified card signature finalizes")
        .is_none());
    finish_sd_export(&mut controller, &mut broker);
    let close = controller
        .handle_event(NormalProcessEventV2::LogicalKey(
            KeypadKey::EqualsConfirmEnter,
        ))
        .expect("result acknowledged")
        .expect("close request");
    let closed = reply(&mut broker, &close, None, None);
    assert!(receive_reply(&mut controller, &closed).is_none());
    assert_eq!(
        drain_stages(&mut controller),
        [
            NormalStageV2::NormalStart,
            NormalStageV2::Transport,
            NormalStageV2::PsbtIntake,
            NormalStageV2::FactorB,
            NormalStageV2::A1Intake,
            NormalStageV2::FactorA1,
            NormalStageV2::Validation,
            NormalStageV2::ApprovalHeld,
            NormalStageV2::Revalidation,
            NormalStageV2::TerminalASigning,
            NormalStageV2::CardBSigning,
            NormalStageV2::Finalization,
            NormalStageV2::AwaitingExportAction,
            NormalStageV2::CompletedWiped,
        ]
    );
}

#[test]
fn post_revalidation_request_is_exact_move_only_and_wiped_on_drop() {
    const REQUEST_BYTES: usize = 32 + 32 + 4 + 4 + 4 + 32 + 33;

    let signing = fields(SIGNING);
    let provision = fields(PROVISIONING);
    let (mut controller, _) = reach_final_approval(SignatureCase::Valid);
    assert!(controller.card_b_signing_request().is_none());
    controller
        .handle_event(NormalProcessEventV2::HoldCompleted)
        .expect("hold reaches card signing");

    reset_wiped_bytes();
    let request = controller
        .card_b_signing_request()
        .expect("one post-revalidation role-B request");
    assert_eq!(
        request.wallet_id(),
        &hex_array::<32>(provision["wallet_id"])
    );
    assert_eq!(
        request.review_hash(),
        &hex_array::<32>(signing["review_hash_hex"])
    );
    assert_eq!(request.input_index(), 0);
    assert_eq!(request.branch(), 0);
    assert_eq!(request.child_index(), 0);
    assert_eq!(
        request.digest(),
        &hex_array::<32>(signing["bip143_digest_hex"])
    );
    assert_eq!(
        request.role_b_pubkey(),
        &hex_array::<33>(signing["role_b_route_public_key_hex"])
    );
    assert_eq!(wiped_bytes(), 0);
    drop(request);
    assert_eq!(wiped_bytes(), REQUEST_BYTES);
}

#[test]
fn card_signatures_are_accepted_only_after_revalidation_and_verified_before_finalization() {
    for (case, expected) in [
        (
            SignatureCase::WrongReviewHash,
            NormalProcessErrorV2::CardSignatureBindingMismatch,
        ),
        (
            SignatureCase::WrongInputIndex,
            NormalProcessErrorV2::CardSignatureBindingMismatch,
        ),
        (
            SignatureCase::WrongKey,
            NormalProcessErrorV2::CardSignatureKeyMismatch,
        ),
        (
            SignatureCase::MalformedDer,
            NormalProcessErrorV2::CardSignatureMalformed,
        ),
        (
            SignatureCase::Invalid,
            NormalProcessErrorV2::CardSignatureInvalid,
        ),
    ] {
        let (mut controller, _) = reach_final_approval(case);
        assert!(controller.card_b_signing_request().is_none());
        assert!(controller
            .handle_event(NormalProcessEventV2::HoldCompleted)
            .expect("hold reaches card signing")
            .is_none());
        assert!(matches!(
            submit_card_signature(&mut controller, case),
            Err(actual) if actual == expected
        ));
        assert_eq!(controller.terminal_error(), Some(expected));
        assert_eq!(
            controller.terminal_error().map(|error| error.name()),
            Some(expected.name())
        );
        assert_eq!(
            controller.fuzz_last_normal_stage(),
            Some(NormalStageV2::CardBSigning)
        );
        assert!(drain_stages(&mut controller)
            .ends_with(&[NormalStageV2::TerminalASigning, NormalStageV2::CardBSigning,]));
    }

    let (mut high_s, _) = reach_final_approval(SignatureCase::HighS);
    high_s
        .handle_event(NormalProcessEventV2::HoldCompleted)
        .expect("hold reaches card signing");
    assert!(submit_card_signature(&mut high_s, SignatureCase::HighS)
        .expect("valid high-S card response is normalized and verified")
        .is_none());
    assert_eq!(
        high_s.stage(),
        NormalProcessStageV2::Normal(NormalStageV2::AwaitingExportAction)
    );
    assert!(high_s.card_b_signing_request().is_none());
}

#[test]
fn signature_reply_buffer_is_wiped_before_request_and_after_termination() {
    let (mut controller, _) = reach_final_approval(SignatureCase::Valid);
    let mut early = [0xa5; 72];
    assert!(matches!(
        controller.accept_card_b_signature([0; 32], 0, [0; 33], &mut early),
        Err(NormalProcessErrorV2::Normal(
            NormalErrorV2::InvalidTransition
        ))
    ));
    assert_eq!(early, [0; 72]);
    assert_eq!(controller.stage(), NormalProcessStageV2::Terminated);

    let mut after_termination = [0x5a; 8];
    assert!(matches!(
        controller.accept_card_b_signature([0; 32], 0, [0; 33], &mut after_termination,),
        Err(NormalProcessErrorV2::Normal(
            NormalErrorV2::InvalidTransition
        ))
    ));
    assert_eq!(after_termination, [0; 8]);
}

#[test]
fn profile_mismatch_and_early_hold_are_named_and_absorbing() {
    let mut profile = NormalProcessControllerV2::start(b"03").expect("profile");
    assert_eq!(
        profile.accept_profile(0x01),
        Err(NormalProcessErrorV2::CardProfileMismatch)
    );
    assert_eq!(profile.stage(), NormalProcessStageV2::Terminated);

    let (mut controller, _) = reach_final_approval(SignatureCase::Valid);
    // A second controller stops before completing its review.
    let mut early =
        NormalProcessControllerV2::fuzz_start(b"01", [0x57; 12], 0).expect("profile selection");
    early.accept_profile(0x01).expect("card profile");
    let _opening = early
        .accept_normal_factor(&factor_body(SignatureCase::Valid))
        .expect("factor");
    assert!(matches!(
        early.handle_event(NormalProcessEventV2::HoldCompleted),
        Err(NormalProcessErrorV2::Normal(
            NormalErrorV2::ApprovalUnavailable
        ))
    ));
    assert_eq!(early.stage(), NormalProcessStageV2::Terminated);

    assert!(controller
        .handle_event(NormalProcessEventV2::HoldCompleted)
        .expect("valid hold")
        .is_none());
    assert!(submit_card_signature(&mut controller, SignatureCase::Valid)
        .expect("valid signature")
        .is_none());
}
