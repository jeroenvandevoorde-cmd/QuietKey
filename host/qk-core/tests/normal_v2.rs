//! QK-DEC-149/150 end-to-end normal A1+B product-session tests.

use qk_core::{
    CardPresence, CoreDeviceGrants, Interruption, MockCardSlot, MockDisplay, MockKeypad,
    NormalCardBDataV2, NormalCardBSignatureV2, NormalErrorV2, NormalExportActionV2,
    NormalProfileV2, NormalRecipientFactV2, NormalReviewPositionV2, NormalScreenV2,
    NormalSessionV2, NormalStageV2, Source,
};
use qk_io::{
    parse_request, BrokerReply, BrokerSession, MockInput, MockOutputWriter, Request,
    Sink as IoSink, Source as IoSource,
};
use qk_ipc::{encode_frame, Direction, MessageKind, ReceivedFrame, StreamDecoder, HEADER_BYTES};
use qk_psbt::{DirectRbf, FeeWarning, RecipientType, ReviewNetwork};
use std::collections::BTreeMap;

const SIGNING: &str = include_str!("../../qk-psbt/tests/fixtures/signing_finalization_v2.txt");
const PROVISIONING: &str = include_str!("../../qk-provisioning/tests/fixtures/provisioning_v2.txt");

fn fields(source: &'static str) -> BTreeMap<&'static str, &'static str> {
    let mut values = BTreeMap::new();
    for line in source.lines().filter(|line| !line.starts_with('#')) {
        if let Some((name, value)) = line.split_once(": ") {
            assert!(values.insert(name, value).is_none(), "unique {name}");
        }
    }
    values
}

fn hex_vec(text: &str) -> Vec<u8> {
    assert_eq!(text.len() % 2, 0);
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

fn card_variant(
    invalid_signature: bool,
    malformed_descriptor: bool,
    wrong_wallet_id: bool,
    wrong_role_b_xpub: bool,
) -> NormalCardBDataV2 {
    let provision = fields(PROVISIONING);
    let signing = fields(SIGNING);
    let mut descriptors: [[u8; 306]; 2] = [
        provision["receive_descriptor"]
            .as_bytes()
            .try_into()
            .expect("receive descriptor width"),
        provision["change_descriptor"]
            .as_bytes()
            .try_into()
            .expect("change descriptor width"),
    ];
    if malformed_descriptor {
        descriptors[0][0] = b'x';
    }
    let mut wallet_id = hex_array(provision["wallet_id"]);
    if wrong_wallet_id {
        wallet_id[0] ^= 1;
    }
    let mut role_b_xpub: [u8; 111] = provision["role_b_account_xpub"]
        .as_bytes()
        .try_into()
        .expect("role-B xpub width");
    if wrong_role_b_xpub {
        role_b_xpub[0] ^= 1;
    }
    let mut role_b_der = hex_vec(signing["role_b_der_hex"]);
    if invalid_signature {
        let last = role_b_der.last_mut().expect("nonempty DER");
        *last ^= 1;
    }
    let signature =
        NormalCardBSignatureV2::try_new(0, &mut role_b_der).expect("bounded mock signature");
    assert!(role_b_der.iter().all(|byte| *byte == 0));
    let mut a2 = hex_array::<32>(provision["a2_transcript_sha256"]);
    let card = NormalCardBDataV2::try_new(
        descriptors,
        wallet_id,
        role_b_xpub,
        &mut a2,
        vec![signature],
    )
    .expect("one authenticated mock factor");
    assert_eq!(a2, [0; 32]);
    card
}

fn card(invalid_signature: bool) -> NormalCardBDataV2 {
    card_variant(invalid_signature, false, false, false)
}

fn grants(card: NormalCardBDataV2) -> CoreDeviceGrants {
    CoreDeviceGrants::validate(
        Some(MockDisplay::new()),
        Some(MockKeypad::new()),
        Some(MockCardSlot::with_normal_data(CardPresence::Present, card)),
        false,
    )
    .expect("exact normal grants")
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
    let frame = decode_one(outbound.frame_bytes());
    broker
        .accept(&frame, input, writer)
        .expect("broker accepts purpose-bound request")
}

fn manual_operation_reply(request: &qk_core::CoreOutbound, inner_payload: &[u8]) -> Vec<u8> {
    let request = decode_one(request.frame_bytes());
    let mut output = vec![0; HEADER_BYTES + inner_payload.len()];
    let written = encode_frame(
        Direction::IoToCore,
        MessageKind::OperationResponse,
        *request.header().session_id(),
        request.header().exchange_id(),
        inner_payload,
        &mut output,
    )
    .expect("manual hostile peer response");
    assert_eq!(written, output.len());
    output
}

fn ingress_begin_success(source: Source, total_len: u32) -> Vec<u8> {
    let mut inner = vec![1, 1, 0, 0, 5, 0, 0, 0, source.wire_value()];
    inner.extend_from_slice(&total_len.to_le_bytes());
    inner
}

fn open_with_card(card: NormalCardBDataV2) -> (NormalSessionV2, BrokerSession) {
    let (mut session, opening) =
        NormalSessionV2::start(&[0x01], grants(card)).expect("normal start");
    let mut broker = BrokerSession::new();
    let ready = reply(&mut broker, &opening, None, None);
    let progress = session
        .receive(ready.frame_bytes(), false)
        .expect("session ready");
    assert_eq!(progress.stage(), NormalStageV2::ProfileBinding);
    assert_eq!(session.profile(), NormalProfileV2::SimpleRecovery);
    (session, broker)
}

fn open(invalid_signature: bool) -> (NormalSessionV2, BrokerSession) {
    open_with_card(card(invalid_signature))
}

fn drive_ingress(
    session: &mut NormalSessionV2,
    broker: &mut BrokerSession,
    begin: qk_core::NormalProgressV2,
    source: IoSource,
    bytes: &[u8],
) {
    let outbound = begin.into_outbound().expect("ingress begin request");
    let mut input = MockInput::try_new(source, bytes).expect("bounded fixture input");
    let began = reply(broker, &outbound, Some(&mut input), None);
    assert!(input.is_used());
    let read = session
        .receive(began.frame_bytes(), false)
        .expect("ingress-begin response")
        .into_outbound()
        .expect("ingress read request");
    let chunk = reply(broker, &read, None, None);
    assert!(session
        .receive(chunk.frame_bytes(), false)
        .expect("final ingress chunk")
        .outbound()
        .is_none());
}

fn reach_factor_b(card: NormalCardBDataV2) -> (NormalSessionV2, BrokerSession) {
    let signing = fields(SIGNING);
    let (mut session, mut broker) = open_with_card(card);
    assert_eq!(
        session
            .confirm_profile()
            .expect("profile confirmation")
            .stage(),
        NormalStageV2::Transport
    );
    let begin = session
        .begin_psbt_intake(Source::MediaPsbt)
        .expect("PSBT intake request");
    drive_ingress(
        &mut session,
        &mut broker,
        begin,
        IoSource::MediaPsbt,
        &media_record(&hex_vec(signing["s0_hex"])),
    );
    assert_eq!(session.stage(), NormalStageV2::FactorB);
    (session, broker)
}

fn reach_review(invalid_signature: bool) -> (NormalSessionV2, BrokerSession) {
    let provision = fields(PROVISIONING);
    let (mut session, mut broker) = reach_factor_b(card(invalid_signature));
    assert_eq!(
        session.accept_card_b().expect("factor B").stage(),
        NormalStageV2::A1Intake
    );
    let begin = session.begin_a1_intake().expect("A1 intake request");
    drive_ingress(
        &mut session,
        &mut broker,
        begin,
        IoSource::CameraA1Candidate,
        &hex_vec(provision["a1_capsule_hex"]),
    );
    assert_eq!(session.stage(), NormalStageV2::FactorA1);
    assert_eq!(
        session.validate().expect("A binding and review").stage(),
        NormalStageV2::Review
    );
    (session, broker)
}

fn finish_review(session: &mut NormalSessionV2) -> Vec<NormalReviewPositionV2> {
    let first = session.review_position().expect("first review item");
    assert_narrow_screen(session, first);
    let mut visited = vec![first];
    while session.stage() == NormalStageV2::Review {
        session.advance_review().expect("fixed forward review");
        let next = session.review_position().expect("next review item");
        assert_narrow_screen(session, next);
        visited.push(next);
    }
    assert_eq!(session.stage(), NormalStageV2::FinalApproval);
    visited
}

fn assert_narrow_screen(session: &NormalSessionV2, position: NormalReviewPositionV2) {
    let signing = fields(SIGNING);
    let provision = fields(PROVISIONING);
    match (position, session.screen().expect("typed screen")) {
        (NormalReviewPositionV2::Overview, NormalScreenV2::ReviewOverview(view)) => {
            assert_eq!(view.profile(), NormalProfileV2::SimpleRecovery);
            assert_eq!(view.network(), ReviewNetwork::BitcoinMainnet);
            assert_eq!(view.wallet_id(), hex_array(provision["wallet_id"]));
            assert_eq!(view.input_count(), 1);
            assert_eq!(view.total_input_amount(), 1_000_000);
        }
        (NormalReviewPositionV2::Arithmetic, NormalScreenV2::ReviewArithmetic(view)) => {
            assert_eq!(view.total_input_amount(), 1_000_000);
            assert_eq!(view.total_output_amount(), 900_000);
            assert_eq!(view.fee(), 100_000);
        }
        (NormalReviewPositionV2::Recipient(index), NormalScreenV2::ReviewRecipient(view)) => {
            assert_eq!(view.index(), u32::try_from(index).expect("fixture index"));
            match (index, view.recipient()) {
                (
                    1,
                    NormalRecipientFactV2::SelfTransfer {
                        child_index,
                        witness_program,
                    },
                ) => {
                    assert_eq!(view.amount(), 300_000);
                    assert_eq!(child_index, 1);
                    assert_eq!(
                        witness_program,
                        hex_vec("2fe9bb02255457981f0613c8f7b5cc2f354fade42a4b4b19f22b3566e1c6bae0")
                    );
                }
                (
                    2,
                    NormalRecipientFactV2::External {
                        recipient_type: RecipientType::P2wpkh,
                        data,
                    },
                ) => {
                    assert_eq!(view.amount(), 200_000);
                    assert_eq!(data, [0x11; 20]);
                }
                _ => panic!("unexpected recipient screen"),
            }
            assert!(!view.script_pubkey().is_empty());
        }
        (NormalReviewPositionV2::Change(0), NormalScreenV2::ReviewChange(view)) => {
            assert_eq!(view.index(), 0);
            assert_eq!(view.amount(), 400_000);
            assert_eq!(view.child_index(), 0);
            assert_eq!(
                view.script_pubkey(),
                hex_vec(provision["change_0_script_pubkey"])
            );
        }
        (NormalReviewPositionV2::OpReturn(3), NormalScreenV2::ReviewOpReturn(view)) => {
            assert_eq!(view.index(), 3);
            assert_eq!(view.amount(), 0);
            assert_eq!(view.script_pubkey(), [0x6a, 0x03, 0xaa, 0xbb, 0xcc]);
            assert_eq!(view.payload(), [0xaa, 0xbb, 0xcc]);
        }
        (NormalReviewPositionV2::Locktime, NormalScreenV2::ReviewLocktime(view)) => {
            assert_eq!(view.locktime(), 500_000);
        }
        (NormalReviewPositionV2::Sequence(0), NormalScreenV2::ReviewSequence(view)) => {
            assert_eq!(view.input_index(), 0);
            assert_eq!(view.sequence(), 0xffff_fffd);
            assert_eq!(view.direct_rbf(), DirectRbf::Signaled);
        }
        (NormalReviewPositionV2::FeePolicy, NormalScreenV2::ReviewFeePolicy(view)) => {
            assert_eq!(view.identifier(), b"QK-FEE-POLICY-V2");
        }
        (NormalReviewPositionV2::FeeFacts, NormalScreenV2::ReviewFeeFacts(view)) => {
            assert_eq!(view.fee(), 100_000);
            assert_eq!(view.estimated_vsize(), 238);
            assert_eq!(view.fee_rate_msat_per_vbyte(), 420_168);
        }
        (NormalReviewPositionV2::Warning(0), NormalScreenV2::ReviewWarning(view)) => {
            assert_eq!(view.warning(), FeeWarning::RateHigh);
        }
        (NormalReviewPositionV2::Warning(1), NormalScreenV2::ReviewWarning(view)) => {
            assert_eq!(view.warning(), FeeWarning::ShareHigh);
        }
        (NormalReviewPositionV2::FinalApproval, NormalScreenV2::FinalApproval(view)) => {
            assert_eq!(view.profile(), NormalProfileV2::SimpleRecovery);
            assert_eq!(view.review_hash(), hex_array(signing["review_hash_hex"]));
        }
        _ => panic!("screen exposed facts outside its selected review position"),
    }
}

fn finish_sd_export(
    session: &mut NormalSessionV2,
    broker: &mut BrokerSession,
) -> (MockOutputWriter, MockOutputWriter) {
    let mut psbt_writer = MockOutputWriter::new(IoSink::Sd);
    let mut tx_writer = MockOutputWriter::new(IoSink::Sd);
    let progress = session
        .choose_export(NormalExportActionV2::Sd {
            caller_nonce: [0x42; 16],
        })
        .expect("one selected route");
    let mut outbound = progress.into_outbound().expect("first egress request");
    let mut finish_count = 0usize;
    loop {
        let frame = decode_one(outbound.frame_bytes());
        let request = parse_request(frame.payload()).expect("exact qk-io request");
        let response = match request {
            Request::EgressFinish if finish_count == 0 => {
                finish_count += 1;
                broker
                    .accept(&frame, None, Some(&mut psbt_writer))
                    .expect("finalized PSBT finish")
            }
            Request::EgressFinish if finish_count == 1 => {
                finish_count += 1;
                broker
                    .accept(&frame, None, Some(&mut tx_writer))
                    .expect("raw transaction finish")
            }
            Request::EgressBegin { .. } | Request::EgressWrite { .. } => broker
                .accept(&frame, None, None)
                .expect("bounded egress step"),
            _ => panic!("unexpected export request"),
        };
        let outcome = session
            .receive(response.frame_bytes(), false)
            .expect("hostile reply reparsed");
        if outcome.stage() == NormalStageV2::TransactionResult {
            break;
        }
        outbound = outcome.into_outbound().expect("next exact egress step");
    }
    assert_eq!(finish_count, 2);
    (psbt_writer, tx_writer)
}

fn reach_second_sd_request() -> (NormalSessionV2, qk_core::CoreOutbound) {
    let (mut session, mut broker) = reach_review(false);
    finish_review(&mut session);
    let token = session.begin_approval_hold().expect("approval hold");
    session
        .complete_approval_hold(token)
        .expect("finalized artifacts");
    let mut psbt_writer = MockOutputWriter::new(IoSink::Sd);
    let mut outbound = session
        .choose_export(NormalExportActionV2::Sd {
            caller_nonce: [0x61; 16],
        })
        .expect("SD route")
        .into_outbound()
        .expect("first request");
    loop {
        let frame = decode_one(outbound.frame_bytes());
        let request = parse_request(frame.payload()).expect("exact request");
        let first_finished = matches!(request, Request::EgressFinish);
        let response = match request {
            Request::EgressFinish => broker
                .accept(&frame, None, Some(&mut psbt_writer))
                .expect("first artifact finalized"),
            Request::EgressBegin { .. } | Request::EgressWrite { .. } => broker
                .accept(&frame, None, None)
                .expect("first artifact step"),
            _ => panic!("unexpected first-artifact request"),
        };
        let progress = session
            .receive(response.frame_bytes(), false)
            .expect("first artifact reply");
        outbound = progress.into_outbound().expect("next request");
        if first_finished {
            break;
        }
    }
    assert!(psbt_writer.final_bytes().is_some());
    (session, outbound)
}

#[test]
fn registered_normal_flow_visits_every_fact_then_exports_exact_final_artifacts() {
    let signing = fields(SIGNING);
    let (mut session, mut broker) = reach_review(false);
    assert_eq!(
        finish_review(&mut session),
        [
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
        ]
    );
    let token = session.begin_approval_hold().expect("current hold token");
    assert_eq!(token.cycle(), 1);
    assert_eq!(
        session
            .complete_approval_hold(token)
            .expect("revalidate, sign and finalize")
            .stage(),
        NormalStageV2::AwaitingExportAction
    );
    let identity = session.approval_identity().expect("bound approval");
    assert_eq!(identity.profile(), NormalProfileV2::SimpleRecovery);
    assert_eq!(identity.cycle(), token.cycle());
    assert_eq!(
        identity.review_hash(),
        hex_array(signing["review_hash_hex"])
    );

    let (psbt_writer, tx_writer) = finish_sd_export(&mut session, &mut broker);
    assert_eq!(
        psbt_writer.final_bytes(),
        Some(hex_vec(signing["finalized_psbt_hex"]).as_slice())
    );
    assert_eq!(
        tx_writer.final_bytes(),
        Some(hex_vec(signing["raw_transaction_hex"]).as_slice())
    );
    let result = session.result().expect("bound result facts");
    assert_eq!(result.txid(), hex_array(signing["txid_raw_hex"]));
    assert_eq!(result.wtxid(), hex_array(signing["wtxid_raw_hex"]));
    assert_eq!(
        result.finalized_psbt().expect("PSBT fact").sha256(),
        hex_array(signing["finalized_psbt_sha256"])
    );
    assert_eq!(
        result.raw_transaction().expect("transaction fact").sha256(),
        hex_array(signing["raw_transaction_sha256"])
    );
    match session.screen().expect("typed result screen") {
        NormalScreenV2::TransactionResult(view) => {
            assert_eq!(view.result().txid(), result.txid());
            assert_eq!(view.result().wtxid(), result.wtxid());
        }
        _ => panic!("result stage exposes only bound result facts"),
    }

    let close = session
        .complete_result()
        .expect("result acknowledgment")
        .into_outbound()
        .expect("sole close request");
    let closed = reply(&mut broker, &close, None, None);
    assert_eq!(
        session
            .receive(closed.frame_bytes(), false)
            .expect("graceful close")
            .stage(),
        NormalStageV2::CompletedWiped
    );
    assert!(session.is_terminal());
}

#[test]
fn invalid_mock_signature_is_named_and_never_reaches_an_export_route() {
    let (mut session, _) = reach_review(true);
    finish_review(&mut session);
    let token = session.begin_approval_hold().expect("current hold");
    assert!(matches!(
        session.complete_approval_hold(token),
        Err(NormalErrorV2::InvalidMockSignature)
    ));
    assert_eq!(
        session.terminal_error(),
        Some(NormalErrorV2::InvalidMockSignature)
    );
    assert!(session.result().is_none());
    assert!(matches!(
        session.choose_export(NormalExportActionV2::Bbqr {
            non_final_part_len: 10
        }),
        Err(NormalErrorV2::Finished)
    ));
}

#[test]
fn malformed_card_data_and_valid_but_mismatched_bindings_are_distinct() {
    let cases = [
        (
            card_variant(false, true, false, false),
            NormalErrorV2::CardDataRejected,
        ),
        (
            card_variant(false, false, true, false),
            NormalErrorV2::CardBindingMismatch,
        ),
        (
            card_variant(false, false, false, true),
            NormalErrorV2::CardBindingMismatch,
        ),
    ];
    for (card, expected) in cases {
        let (mut session, _) = reach_factor_b(card);
        assert!(matches!(session.accept_card_b(), Err(actual) if actual == expected));
        assert_eq!(session.terminal_error(), Some(expected));
    }
}

#[test]
fn exact_camera_source_with_wrong_a1_length_is_a1_rejected() {
    let (mut session, _broker) = reach_factor_b(card(false));
    session.accept_card_b().expect("factor B");
    let outbound = session
        .begin_a1_intake()
        .expect("A1 begin")
        .into_outbound()
        .expect("A1 request");
    let began = manual_operation_reply(
        &outbound,
        &ingress_begin_success(Source::CameraA1Candidate, 66),
    );
    assert!(matches!(
        session.receive(&began, false),
        Err(NormalErrorV2::A1Rejected)
    ));
    assert_eq!(session.terminal_error(), Some(NormalErrorV2::A1Rejected));

    let (mut session, _broker) = reach_factor_b(card(false));
    session.accept_card_b().expect("factor B");
    let outbound = session
        .begin_a1_intake()
        .expect("A1 begin")
        .into_outbound()
        .expect("A1 request");
    let rejected = manual_operation_reply(&outbound, &ingress_begin_success(Source::MediaPsbt, 67));
    assert!(matches!(
        session.receive(&rejected, false),
        Err(NormalErrorV2::WrongIngressSource)
    ));
    assert_eq!(
        session.terminal_error(),
        Some(NormalErrorV2::WrongIngressSource)
    );
}

#[test]
fn outer_failure_after_first_sd_artifact_is_partial_completion() {
    let (mut session, outbound) = reach_second_sd_request();
    assert!(matches!(
        session.receive(outbound.frame_bytes(), true),
        Err(NormalErrorV2::PartialSdCompletion)
    ));
    assert_eq!(
        session.terminal_error(),
        Some(NormalErrorV2::PartialSdCompletion)
    );
}

#[test]
fn interruption_after_first_sd_artifact_has_partial_completion_precedence() {
    for reason in [Interruption::MediaRemoved, Interruption::PeerLost] {
        let (mut session, _outbound) = reach_second_sd_request();
        assert_eq!(
            session.interrupt(reason),
            Err(NormalErrorV2::PartialSdCompletion)
        );
        assert_eq!(
            session.terminal_error(),
            Some(NormalErrorV2::PartialSdCompletion)
        );
    }
}

#[test]
fn unrelated_mutators_after_first_sd_artifact_all_have_partial_precedence() {
    let (mut session, _outbound) = reach_second_sd_request();
    assert!(matches!(
        session.confirm_profile(),
        Err(NormalErrorV2::PartialSdCompletion)
    ));

    let (mut session, _outbound) = reach_second_sd_request();
    assert!(matches!(
        session.begin_psbt_intake(Source::MediaPsbt),
        Err(NormalErrorV2::PartialSdCompletion)
    ));

    let (mut session, _outbound) = reach_second_sd_request();
    assert!(matches!(
        session.begin_approval_hold(),
        Err(NormalErrorV2::PartialSdCompletion)
    ));

    let (mut session, _outbound) = reach_second_sd_request();
    assert!(matches!(
        session.choose_export(NormalExportActionV2::Bbqr {
            non_final_part_len: 10,
        }),
        Err(NormalErrorV2::PartialSdCompletion)
    ));
}

#[test]
fn interruptions_keep_their_names_and_no_yield_has_exact_precedence() {
    let (mut preapproval, _) = open(false);
    assert!(matches!(
        preapproval.choose_export(NormalExportActionV2::Bbqr {
            non_final_part_len: 10
        }),
        Err(NormalErrorV2::InvalidTransition)
    ));

    let (mut preapproval, _) = open(false);
    assert_eq!(
        preapproval.interrupt(Interruption::SessionTimeout),
        Err(NormalErrorV2::Interrupted(Interruption::SessionTimeout))
    );

    let (mut approved, _) = reach_review(false);
    finish_review(&mut approved);
    let token = approved.begin_approval_hold().expect("hold");
    approved
        .complete_approval_hold(token)
        .expect("approved and finalized");
    assert_eq!(
        approved.interrupt(Interruption::CardRemoved),
        Err(NormalErrorV2::Interrupted(Interruption::CardRemoved))
    );

    let (mut approved, _) = reach_review(false);
    finish_review(&mut approved);
    let token = approved.begin_approval_hold().expect("hold");
    approved
        .complete_approval_hold(token)
        .expect("approved and finalized");
    assert!(matches!(
        approved.confirm_profile(),
        Err(NormalErrorV2::PostApprovalYield)
    ));

    let (mut approved, _) = reach_review(false);
    finish_review(&mut approved);
    let token = approved.begin_approval_hold().expect("hold");
    approved
        .complete_approval_hold(token)
        .expect("approved and finalized");
    assert!(matches!(
        approved.receive(&[0], false),
        Err(NormalErrorV2::PostApprovalYield)
    ));

    let (mut approved, _) = reach_review(false);
    finish_review(&mut approved);
    let token = approved.begin_approval_hold().expect("hold");
    approved
        .complete_approval_hold(token)
        .expect("approved and finalized");
    assert!(matches!(
        approved.complete_result(),
        Err(NormalErrorV2::PostApprovalYield)
    ));

    let (mut exporting, _) = reach_review(false);
    finish_review(&mut exporting);
    let token = exporting.begin_approval_hold().expect("hold");
    exporting
        .complete_approval_hold(token)
        .expect("approved and finalized");
    exporting
        .choose_export(NormalExportActionV2::Sd {
            caller_nonce: [0x72; 16],
        })
        .expect("first SD request");
    assert!(matches!(
        exporting.complete_result(),
        Err(NormalErrorV2::PostApprovalYield)
    ));

    let (mut partially_complete, _outbound) = reach_second_sd_request();
    assert!(matches!(
        partially_complete.complete_result(),
        Err(NormalErrorV2::PartialSdCompletion)
    ));
}

#[test]
fn approval_token_from_another_session_is_rejected_at_the_same_cycle() {
    let (mut first, _) = reach_review(false);
    let (mut second, _) = reach_review(false);
    finish_review(&mut first);
    finish_review(&mut second);
    let first_token = first.begin_approval_hold().expect("first session hold");
    let second_token = second.begin_approval_hold().expect("second session hold");
    assert_eq!(first_token.cycle(), second_token.cycle());

    let (mut before_review, _) = open(false);
    assert!(matches!(
        before_review.complete_approval_hold(second_token),
        Err(NormalErrorV2::ApprovalUnavailable)
    ));

    let (mut no_pending_hold, _) = reach_review(false);
    finish_review(&mut no_pending_hold);
    assert!(matches!(
        no_pending_hold.complete_approval_hold(second_token),
        Err(NormalErrorV2::ApprovalUnavailable)
    ));

    let (mut pending_hold, _) = reach_review(false);
    finish_review(&mut pending_hold);
    let _pending_token = pending_hold.begin_approval_hold().expect("pending hold");
    assert!(matches!(
        pending_hold.begin_approval_hold(),
        Err(NormalErrorV2::ApprovalUnavailable)
    ));

    assert!(matches!(
        first.complete_approval_hold(second_token),
        Err(NormalErrorV2::ReviewIdentityMismatch)
    ));
    assert_eq!(
        first.terminal_error(),
        Some(NormalErrorV2::ReviewIdentityMismatch)
    );
}
