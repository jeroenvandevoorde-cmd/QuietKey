//! Product-process normal flow compared with the byte-frozen HOST simulator.

use qk_core::{
    CardPresence, CoreDeviceGrants, MockCardSlot, MockDisplay, MockKeypad, NormalCardBDataV2,
    NormalCardBSignatureV2, NormalExportActionV2, NormalSessionV2, NormalStageV2, Source,
};
use qk_descriptor::{parse_descriptor_pair, parse_descriptor_pair_v2};
use qk_host_sim::{
    ExportArtifacts, FlowApplyOutcomeV2, FlowEventV2, FlowKindV2, KeypadKey, KitTier,
    MockCardBSignature, ReviewReadyV3Workflow, ReviewReadyWorkflow, ScreenFlowV2,
    TerminalInputKeyV2, TierArtifacts, WipingReasonV2,
};
use qk_io::{
    parse_request, BrokerSession, MockInput, MockOutputWriter, Request, Sink as IoSink,
    Source as IoSource,
};
use qk_ipc::{ReceivedFrame, StreamDecoder};
use qk_psbt::InputSource;
use qk_secp::secret_key_import;

const SIGNING: &str = include_str!("../../qk-psbt/tests/fixtures/signing_finalization_v2.txt");
const PROVISIONING: &str = include_str!("../../qk-provisioning/tests/fixtures/provisioning_v2.txt");
const M25_EXPORT: &str = include_str!("../../qk-host-sim/tests/fixtures/m25_export.txt");

fn field(source: &'static str, name: &str) -> &'static str {
    source
        .lines()
        .find_map(|line| line.strip_prefix(&format!("{name}: ")))
        .expect("registered fixture field")
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
    let name = b"differential.psbt";
    let mut record = Vec::with_capacity(1 + name.len() + 4 + payload.len());
    record.push(name.len() as u8);
    record.extend_from_slice(name);
    record.extend_from_slice(&(payload.len() as u32).to_le_bytes());
    record.extend_from_slice(payload);
    record
}

fn decode_one(bytes: &[u8]) -> ReceivedFrame {
    let mut decoder = StreamDecoder::new();
    let outcome = decoder.ingest(bytes, false).expect("complete QKIP frame");
    assert_eq!(outcome.consumed(), bytes.len());
    assert!(outcome.frame_ready());
    decoder.take_frame().expect("owned QKIP frame")
}

fn normal_card() -> NormalCardBDataV2 {
    let descriptors = [
        field(PROVISIONING, "receive_descriptor")
            .as_bytes()
            .try_into()
            .expect("receive descriptor"),
        field(PROVISIONING, "change_descriptor")
            .as_bytes()
            .try_into()
            .expect("change descriptor"),
    ];
    let mut role_b = hex_vec(field(SIGNING, "role_b_der_hex"));
    let signature =
        NormalCardBSignatureV2::try_new(0, &mut role_b).expect("mock B signature owner");
    assert!(role_b.iter().all(|byte| *byte == 0));
    let mut a2 = hex_array(field(PROVISIONING, "a2_transcript_sha256"));
    let card = NormalCardBDataV2::try_new(
        descriptors,
        hex_array(field(PROVISIONING, "wallet_id")),
        field(PROVISIONING, "role_b_account_xpub")
            .as_bytes()
            .try_into()
            .expect("role-B xpub"),
        &mut a2,
        vec![signature],
    )
    .expect("authenticated mock card");
    assert_eq!(a2, [0; 32]);
    card
}

type ComparisonFacts = (Vec<u8>, Vec<u8>, [u8; 32], [u8; 32], [u8; 32], [bool; 4]);

fn product_artifacts() -> ComparisonFacts {
    let grants = CoreDeviceGrants::validate(
        Some(MockDisplay::new()),
        Some(MockKeypad::new()),
        Some(MockCardSlot::with_normal_data(
            CardPresence::Present,
            normal_card(),
        )),
        false,
    )
    .expect("normal grants");
    let (mut session, open) = NormalSessionV2::start(&[1], grants).expect("normal session");
    let mut broker = BrokerSession::new();

    let open_frame = decode_one(open.frame_bytes());
    let ready = broker
        .accept(&open_frame, None, None)
        .expect("broker session ready");
    session
        .receive(ready.frame_bytes(), false)
        .expect("core session ready");
    session.confirm_profile().expect("profile binding");

    let s0 = hex_vec(field(SIGNING, "s0_hex"));
    let mut media =
        MockInput::try_new(IoSource::MediaPsbt, &media_record(&s0)).expect("media fixture record");
    let begin = session
        .begin_psbt_intake(Source::MediaPsbt)
        .expect("PSBT begin")
        .into_outbound()
        .expect("PSBT request");
    let frame = decode_one(begin.frame_bytes());
    let began = broker
        .accept(&frame, Some(&mut media), None)
        .expect("PSBT begin reply");
    let read = session
        .receive(began.frame_bytes(), false)
        .expect("PSBT begin consumed")
        .into_outbound()
        .expect("PSBT read");
    let frame = decode_one(read.frame_bytes());
    let chunk = broker.accept(&frame, None, None).expect("PSBT chunk reply");
    session
        .receive(chunk.frame_bytes(), false)
        .expect("PSBT consumed");

    session.accept_card_b().expect("card B");
    let capsule = hex_vec(field(PROVISIONING, "a1_capsule_hex"));
    let mut camera =
        MockInput::try_new(IoSource::CameraA1Candidate, &capsule).expect("A1 camera candidate");
    let begin = session
        .begin_a1_intake()
        .expect("A1 begin")
        .into_outbound()
        .expect("A1 request");
    let frame = decode_one(begin.frame_bytes());
    let began = broker
        .accept(&frame, Some(&mut camera), None)
        .expect("A1 begin reply");
    let read = session
        .receive(began.frame_bytes(), false)
        .expect("A1 begin consumed")
        .into_outbound()
        .expect("A1 read");
    let frame = decode_one(read.frame_bytes());
    let chunk = broker.accept(&frame, None, None).expect("A1 chunk reply");
    session
        .receive(chunk.frame_bytes(), false)
        .expect("A1 consumed");
    session.validate().expect("immutable review");
    while session.stage() == NormalStageV2::Review {
        session.advance_review().expect("next bound review fact");
    }
    let token = session.begin_approval_hold().expect("approval hold");
    session
        .complete_approval_hold(token)
        .expect("sign and finalize");
    let review_hash = session
        .approval_identity()
        .expect("product approval identity")
        .review_hash();
    let exposure = session.profile().route_exposure();

    let mut psbt_writer = MockOutputWriter::new(IoSink::Sd);
    let mut tx_writer = MockOutputWriter::new(IoSink::Sd);
    let mut outbound = session
        .choose_export(NormalExportActionV2::Sd {
            caller_nonce: [0x51; 16],
        })
        .expect("one SD route")
        .into_outbound()
        .expect("first egress request");
    let mut finish_count = 0usize;
    loop {
        let frame = decode_one(outbound.frame_bytes());
        let request = parse_request(frame.payload()).expect("exact inner request");
        let response = match request {
            Request::EgressFinish if finish_count == 0 => {
                finish_count += 1;
                broker
                    .accept(&frame, None, Some(&mut psbt_writer))
                    .expect("PSBT output")
            }
            Request::EgressFinish if finish_count == 1 => {
                finish_count += 1;
                broker
                    .accept(&frame, None, Some(&mut tx_writer))
                    .expect("transaction output")
            }
            Request::EgressBegin { .. } | Request::EgressWrite { .. } => {
                broker.accept(&frame, None, None).expect("egress exchange")
            }
            _ => panic!("unexpected egress request"),
        };
        let outcome = session
            .receive(response.frame_bytes(), false)
            .expect("hostile egress response");
        if outcome.stage() == NormalStageV2::TransactionResult {
            break;
        }
        outbound = outcome.into_outbound().expect("next egress request");
    }
    let result = session.result().expect("immutable result facts");
    (
        psbt_writer
            .final_bytes()
            .expect("finalized PSBT output")
            .to_vec(),
        tx_writer
            .final_bytes()
            .expect("raw transaction output")
            .to_vec(),
        result.txid(),
        result.wtxid(),
        review_hash,
        [
            exposure.sd_finalized_psbt(),
            exposure.sd_raw_transaction(),
            exposure.bbqr_finalized_psbt(),
            exposure.bbqr_raw_transaction(),
        ],
    )
}

fn simulator_artifacts() -> ComparisonFacts {
    let descriptor = parse_descriptor_pair_v2(
        field(PROVISIONING, "receive_descriptor").as_bytes(),
        field(PROVISIONING, "change_descriptor").as_bytes(),
    )
    .expect("registered D");
    let mut workflow = ReviewReadyV3Workflow::new(descriptor).expect("sim workflow");
    workflow
        .intake(&hex_vec(field(SIGNING, "s0_hex")), InputSource::MicroSd)
        .expect("sim immutable intake");
    workflow.wake().expect("sim wake");
    workflow.begin_validation().expect("sim validation start");
    workflow.validate().expect("sim validation");
    workflow.construct_review().expect("sim review");
    let review_hash = workflow
        .review_ready()
        .expect("sim review-ready")
        .review_hash();
    let mut scalar = hex_array(field(SIGNING, "role_a_route_private_scalar_hex"));
    let terminal = TerminalInputKeyV2::new(
        0,
        secret_key_import(&mut scalar).expect("public fixture scalar"),
    );
    assert_eq!(scalar, [0; 32]);
    let role_b = hex_vec(field(SIGNING, "role_b_der_hex"));
    let finalized = workflow
        .sign_and_finalize_v2(
            vec![terminal],
            &[MockCardBSignature {
                input_index: 0,
                der_signature: &role_b,
            }],
        )
        .expect("frozen sim finalization");
    let finalized_psbt = finalized.finalized_psbt().to_vec();
    let raw_transaction = finalized.raw_transaction().to_vec();
    let txid = finalized.txid();
    let wtxid = finalized.wtxid();
    drop(finalized);
    let route_exposure = simulator_simple_recovery_exposure();
    (
        finalized_psbt,
        raw_transaction,
        txid,
        wtxid,
        review_hash,
        route_exposure,
    )
}

fn simulator_simple_recovery_exposure() -> [bool; 4] {
    let descriptor = parse_descriptor_pair(
        field(M25_EXPORT, "receive_descriptor").as_bytes(),
        field(M25_EXPORT, "change_descriptor").as_bytes(),
    )
    .expect("registered M25 descriptor pair");
    let mut workflow = ReviewReadyWorkflow::new(descriptor).expect("M25 simulator workflow");
    workflow
        .intake(
            &hex_vec(field(M25_EXPORT, "initial_psbt_hex")),
            InputSource::MicroSd,
        )
        .expect("M25 simulator intake");
    workflow.wake().expect("M25 simulator wake");
    workflow
        .begin_validation()
        .expect("M25 simulator validation start");
    workflow.validate().expect("M25 simulator validation");
    workflow.construct_review().expect("M25 simulator review");
    let finalized = workflow
        .sign_and_finalize_m24(Vec::new(), &[])
        .expect("registered threshold-complete M25 fixture");
    let export = ExportArtifacts::from_finalized(finalized, KitTier::SimpleRecovery)
        .expect("M25 simulator export binding");
    match export.artifacts() {
        TierArtifacts::SimpleRecovery {
            finalized_psbt,
            raw_transaction: _,
        } => {
            assert!(finalized_psbt.bbqr(10).is_ok());
            [true, true, true, false]
        }
        _ => panic!("sim SimpleRecovery exposure"),
    }
}

#[test]
fn product_process_and_frozen_simulator_emit_identical_normal_artifacts_and_ids() {
    let product = product_artifacts();
    let simulator = simulator_artifacts();
    assert_eq!(product, simulator);
    assert_eq!(product.0, hex_vec(field(SIGNING, "finalized_psbt_hex")));
    assert_eq!(product.1, hex_vec(field(SIGNING, "raw_transaction_hex")));
    assert_eq!(product.2, hex_array(field(SIGNING, "txid_raw_hex")));
    assert_eq!(product.3, hex_array(field(SIGNING, "wtxid_raw_hex")));
    assert_eq!(product.4, hex_array(field(SIGNING, "review_hash_hex")));
    assert_eq!(product.5, [true, true, true, false]);
}

#[derive(Clone, Copy)]
enum SharedTermination {
    Cancelled,
    OperationFailed,
    MediaRemoved,
    CardRemoved,
    SessionTimeout,
    Shutdown,
    Restart,
    PowerLoss,
}

const SHARED_TERMINATIONS: [SharedTermination; 8] = [
    SharedTermination::Cancelled,
    SharedTermination::OperationFailed,
    SharedTermination::MediaRemoved,
    SharedTermination::CardRemoved,
    SharedTermination::SessionTimeout,
    SharedTermination::Shutdown,
    SharedTermination::Restart,
    SharedTermination::PowerLoss,
];

const fn product_reason(case: SharedTermination) -> qk_core::Interruption {
    match case {
        SharedTermination::Cancelled => qk_core::Interruption::Cancelled,
        SharedTermination::OperationFailed => qk_core::Interruption::OperationFailed,
        SharedTermination::MediaRemoved => qk_core::Interruption::MediaRemoved,
        SharedTermination::CardRemoved => qk_core::Interruption::CardRemoved,
        SharedTermination::SessionTimeout => qk_core::Interruption::SessionTimeout,
        SharedTermination::Shutdown => qk_core::Interruption::Shutdown,
        SharedTermination::Restart => qk_core::Interruption::Restart,
        SharedTermination::PowerLoss => qk_core::Interruption::PowerLoss,
    }
}

const fn sim_event(case: SharedTermination) -> FlowEventV2<'static> {
    match case {
        SharedTermination::Cancelled => FlowEventV2::Key(KeypadKey::CancelBack),
        SharedTermination::OperationFailed => FlowEventV2::OperationFailed,
        SharedTermination::MediaRemoved => FlowEventV2::MediaRemoved,
        SharedTermination::CardRemoved => FlowEventV2::CardRemoved,
        SharedTermination::SessionTimeout => FlowEventV2::SessionTimeout,
        SharedTermination::Shutdown => FlowEventV2::Shutdown,
        SharedTermination::Restart => FlowEventV2::Restart,
        SharedTermination::PowerLoss => FlowEventV2::PowerLoss,
    }
}

const fn sim_reason(case: SharedTermination) -> WipingReasonV2 {
    match case {
        SharedTermination::Cancelled => WipingReasonV2::Cancelled,
        SharedTermination::OperationFailed => WipingReasonV2::OperationFailed,
        SharedTermination::MediaRemoved => WipingReasonV2::MediaRemoved,
        SharedTermination::CardRemoved => WipingReasonV2::CardRemoved,
        SharedTermination::SessionTimeout => WipingReasonV2::SessionTimeout,
        SharedTermination::Shutdown => WipingReasonV2::Shutdown,
        SharedTermination::Restart => WipingReasonV2::Restart,
        SharedTermination::PowerLoss => WipingReasonV2::PowerLoss,
    }
}

#[test]
fn product_normal_owner_matches_all_shared_frozen_simulator_terminations() {
    for case in SHARED_TERMINATIONS {
        let grants = CoreDeviceGrants::validate(
            Some(MockDisplay::new()),
            Some(MockKeypad::new()),
            Some(MockCardSlot::with_normal_data(
                CardPresence::Present,
                normal_card(),
            )),
            false,
        )
        .expect("normal grants");
        let (mut product, _) = NormalSessionV2::start(&[1], grants).expect("product normal");
        let mut simulator = ScreenFlowV2::new(FlowKindV2::A1B);
        let reason = product_reason(case);
        assert_eq!(
            product.interrupt(reason),
            Err(qk_core::NormalErrorV2::Interrupted(reason))
        );
        assert_eq!(
            product.terminal_error(),
            Some(qk_core::NormalErrorV2::Interrupted(reason))
        );
        assert!(matches!(
            simulator.apply(sim_event(case)),
            Ok(FlowApplyOutcomeV2::FailedWiped(actual)) if actual == sim_reason(case)
        ));
        assert!(simulator.is_finished());
    }
}
