//! QK-DEC-151 raw-only Kit-Spend delivery through the qk-io mock peer.

use qk_bbqr::{encode_typed_frame, encoded_part_count, BbqrFileType, MAX_FRAME_TEXT_BYTES};
use qk_core::{
    CardPresence, CoordinatorCompletenessStatementV2, CoreDeviceGrants, CoreMode, CoreReceiveEvent,
    CoreSession, KeypadKey, KitDeliverySessionV2, KitDoorV2, KitExportActionV2, KitExportRouteV2,
    KitInputModeV2, KitIntakeOutcomeV2, KitIntakeSessionV2, KitSpendAssertionDigitV2,
    KitSpendOutcomeV2, KitSpendScreenV2, KitSpendSessionV2, KitSpendStageV2, MockCardSlot,
    MockDisplay, MockKeypad, NormalProfileV2, Source,
};
use qk_io::{parse_request, Artifact, BrokerSession, MockOutputWriter, Request, Sink as IoSink};
use qk_ipc::{ReceivedFrame, StreamDecoder};
use qk_psbt::ReplacementReceiveIndexV2;
use std::collections::BTreeMap;

const SHARES: &str = include_str!("../../qk-kit/tests/fixtures/kit_share_v2.txt");
const SPEND: &str = include_str!("../../qk-host-sim/tests/fixtures/kit_spend_v2.txt");
const ARTIFACT_SOURCE: &str = include_str!("../src/kit_artifact_v2.rs");

fn fields(source: &'static str) -> BTreeMap<&'static str, &'static str> {
    source
        .lines()
        .filter(|line| !line.starts_with('#'))
        .filter_map(|line| line.split_once(": "))
        .collect()
}

fn hex_vec(value: &str) -> Vec<u8> {
    value
        .as_bytes()
        .chunks_exact(2)
        .map(|pair| {
            u8::from_str_radix(core::str::from_utf8(pair).expect("ASCII hex"), 16)
                .expect("registered hex")
        })
        .collect()
}

fn hex_array<const N: usize>(value: &str) -> [u8; N] {
    hex_vec(value).try_into().expect("registered width")
}

fn descriptors(prefix: &str) -> [[u8; 306]; 2] {
    let fixture = fields(SPEND);
    [
        fixture[&*format!("{prefix}_receive_descriptor")]
            .as_bytes()
            .try_into()
            .expect("receive descriptor width"),
        fixture[&*format!("{prefix}_change_descriptor")]
            .as_bytes()
            .try_into()
            .expect("change descriptor width"),
    ]
}

fn finalized_outcome(profile: u8) -> KitSpendOutcomeV2 {
    let shares = fields(SHARES);
    let spend = fields(SPEND);
    let mut first = hex_array::<142>(shares["frame_1_hex"]);
    let mut second = hex_array::<142>(shares["frame_2_hex"]);
    let mut intake = KitIntakeSessionV2::begin(KitDoorV2::KitSpend, KitInputModeV2::Scanner);
    assert!(matches!(
        intake.submit_scanner_frame(&mut first),
        Ok(KitIntakeOutcomeV2::FirstShareAccepted(_))
    ));
    let ready = match intake
        .submit_scanner_frame(&mut second)
        .expect("registered Kit pair")
    {
        KitIntakeOutcomeV2::Ready(ready) => ready,
        KitIntakeOutcomeV2::Continue(_) | KitIntakeOutcomeV2::FirstShareAccepted(_) => {
            panic!("second share must complete intake")
        }
    };
    let (mut core, _broker) = opened_kit_core();
    let mut session = KitSpendSessionV2::begin(
        &mut core,
        &[profile],
        ready,
        &descriptors("old"),
        KitSpendAssertionDigitV2::new(7).expect("digit"),
    )
    .expect("registered spend start");
    let mut psbt = hex_vec(spend["s0_hex"]);
    session
        .submit_sweep(
            Source::MediaPsbt,
            &mut psbt,
            &descriptors("replacement"),
            ReplacementReceiveIndexV2::from_untrusted(0),
        )
        .expect("registered sweep");
    while session.stage() == KitSpendStageV2::Review {
        session.advance_review().expect("complete review");
    }
    let approval = match session
        .confirm_all_funds(CoordinatorCompletenessStatementV2::AllFundsIncluded)
        .expect("completeness statement")
    {
        KitSpendScreenV2::HumanAssertion { approval } => approval,
        _ => panic!("assertion screen"),
    };
    session
        .execute(approval, KeypadKey::Seven)
        .expect("one finalized sweep")
}

fn grants() -> CoreDeviceGrants {
    CoreDeviceGrants::validate(
        Some(MockDisplay::new()),
        Some(MockKeypad::new()),
        Some(MockCardSlot::new(CardPresence::Present)),
        false,
    )
    .expect("Kit capability set")
}

fn decode_one(bytes: &[u8]) -> ReceivedFrame {
    let mut decoder = StreamDecoder::new();
    let outcome = decoder.ingest(bytes, false).expect("complete QKIP frame");
    assert_eq!(outcome.consumed(), bytes.len());
    assert!(outcome.frame_ready());
    decoder.take_frame().expect("owned QKIP frame")
}

fn opened_kit_core() -> (CoreSession, BrokerSession) {
    let (mut core, opening) = CoreSession::start(CoreMode::Kit, grants()).expect("Kit core");
    let mut broker = BrokerSession::new();
    let opening = decode_one(opening.frame_bytes());
    let ready = broker
        .accept(&opening, None, None)
        .expect("broker accepts Kit open");
    let accepted = core
        .receive(ready.frame_bytes(), false)
        .expect("core accepts ready");
    assert_eq!(accepted.event(), CoreReceiveEvent::SessionReady);
    (core, broker)
}

fn expected_filename(nonce: [u8; 16]) -> Vec<u8> {
    let mut name = b"qk-".to_vec();
    for byte in nonce {
        name.extend_from_slice(format!("{byte:02x}").as_bytes());
    }
    name.extend_from_slice(b"-final.tx");
    name
}

#[test]
fn all_profiles_deliver_only_the_exact_raw_transaction_to_sd() {
    let fixture = fields(SPEND);
    let raw = hex_vec(fixture["raw_transaction_hex"]);
    let nonce = [0x42; 16];
    let filename = expected_filename(nonce);
    for (profile_byte, profile) in [
        (1, NormalProfileV2::SimpleRecovery),
        (2, NormalProfileV2::Inheritance),
        (3, NormalProfileV2::QuantumShelter),
    ] {
        let outcome = finalized_outcome(profile_byte);
        let (core, mut broker) = opened_kit_core();
        let (mut delivery, mut outbound) = KitDeliverySessionV2::begin(
            outcome,
            core,
            KitExportActionV2::Sd {
                caller_nonce: nonce,
            },
        )
        .expect("one SD route");
        let mut writer = MockOutputWriter::new(IoSink::Sd);
        let mut written = Vec::new();
        let result = loop {
            let frame = decode_one(outbound.frame_bytes());
            let request = parse_request(frame.payload()).expect("exact inner request");
            let finish = match request {
                Request::EgressBegin {
                    sink,
                    artifact,
                    total_len,
                    aux,
                } => {
                    assert_eq!(sink, IoSink::Sd);
                    assert_eq!(artifact, Artifact::RawTransaction);
                    assert_eq!(usize::try_from(total_len).expect("length"), raw.len());
                    assert_eq!(aux.first().copied(), Some(filename.len() as u8));
                    assert_eq!(aux.get(1..), Some(filename.as_slice()));
                    false
                }
                Request::EgressWrite { offset, chunk } => {
                    assert_eq!(usize::try_from(offset).expect("offset"), written.len());
                    written.extend_from_slice(chunk);
                    false
                }
                Request::EgressFinish => true,
                Request::IngressBegin { .. } | Request::IngressRead { .. } => {
                    panic!("Kit delivery opened an ingress route")
                }
            };
            let reply = if finish {
                broker
                    .accept(&frame, None, Some(&mut writer))
                    .expect("SD finish")
            } else {
                broker.accept(&frame, None, None).expect("SD step")
            };
            if finish {
                assert_exact_sd_reply(reply.frame_bytes(), raw.len());
            }
            let progress = delivery
                .receive(reply.frame_bytes(), false)
                .expect("hostile reply reparsed");
            if let Some(result) = progress.result() {
                break result;
            }
            outbound = progress.into_outbound().expect("next exact QKIP request");
        };
        assert_eq!(written, raw);
        assert_eq!(writer.final_name(), Some(filename.as_slice()));
        assert_eq!(writer.final_bytes(), Some(raw.as_slice()));
        assert_eq!(result.profile(), profile);
        assert_eq!(result.route(), KitExportRouteV2::Sd);
        assert_eq!(
            result.sd_receipt().expect("six-byte receipt").total_len(),
            raw.len() as u32
        );
        assert_eq!(
            result.raw_transaction().sha256(),
            hex_array(fixture["raw_transaction_sha256"])
        );
        assert_eq!(result.txid(), hex_array(fixture["txid_raw_hex"]));
        assert_eq!(result.wtxid(), hex_array(fixture["wtxid_raw_hex"]));
        assert_eq!(
            delivery.receive(&[], false).err().map(|error| error.name()),
            Some("Finished")
        );
    }
}

fn assert_exact_sd_reply(bytes: &[u8], raw_len: usize) {
    let frame = decode_one(bytes);
    let payload = frame.payload();
    assert_eq!(payload.get(0..4), Some([1, 5, 0, 0].as_slice()));
    assert_eq!(payload.get(4..8), Some(6u32.to_le_bytes().as_slice()));
    let mut receipt = [0u8; 6];
    receipt[0] = IoSink::Sd.wire_value();
    receipt[1] = Artifact::RawTransaction.wire_value();
    receipt[2..].copy_from_slice(&(raw_len as u32).to_le_bytes());
    assert_eq!(payload.get(8..), Some(receipt.as_slice()));
}

#[test]
fn bbqr_finish_is_exact_type_t_and_never_opens_sd() {
    let fixture = fields(SPEND);
    let raw = hex_vec(fixture["raw_transaction_hex"]);
    let part_len = 100u16;
    let outcome = finalized_outcome(3);
    let (core, mut broker) = opened_kit_core();
    let (mut delivery, mut outbound) = KitDeliverySessionV2::begin(
        outcome,
        core,
        KitExportActionV2::Bbqr {
            non_final_part_len: part_len,
        },
    )
    .expect("one BBQr route");
    let mut written = Vec::new();
    let result = loop {
        let frame = decode_one(outbound.frame_bytes());
        let request = parse_request(frame.payload()).expect("exact inner request");
        let finish = match request {
            Request::EgressBegin {
                sink,
                artifact,
                total_len,
                aux,
            } => {
                assert_eq!(sink, IoSink::Bbqr);
                assert_eq!(artifact, Artifact::RawTransaction);
                assert_eq!(usize::try_from(total_len).expect("length"), raw.len());
                assert_eq!(aux, part_len.to_le_bytes());
                false
            }
            Request::EgressWrite { offset, chunk } => {
                assert_eq!(usize::try_from(offset).expect("offset"), written.len());
                written.extend_from_slice(chunk);
                false
            }
            Request::EgressFinish => true,
            Request::IngressBegin { .. } | Request::IngressRead { .. } => {
                panic!("Kit delivery opened an ingress route")
            }
        };
        let reply = broker.accept(&frame, None, None).expect("BBQr broker step");
        if finish {
            assert_exact_type_t_reply(reply.frame_bytes(), &raw, part_len);
        }
        let progress = delivery
            .receive(reply.frame_bytes(), false)
            .expect("BBQr reply verified");
        if let Some(result) = progress.result() {
            break result;
        }
        outbound = progress.into_outbound().expect("next exact QKIP request");
    };
    assert_eq!(written, raw);
    assert_eq!(result.profile(), NormalProfileV2::QuantumShelter);
    assert_eq!(result.route(), KitExportRouteV2::Bbqr);
    assert!(result.sd_receipt().is_none());
}

fn assert_exact_type_t_reply(bytes: &[u8], raw: &[u8], part_len: u16) {
    let frame = decode_one(bytes);
    let payload = frame.payload();
    assert_eq!(payload.get(0..4), Some([1, 5, 0, 0].as_slice()));
    let body_len = u32::from_le_bytes(
        payload
            .get(4..8)
            .expect("response length")
            .try_into()
            .expect("u32"),
    ) as usize;
    let body = payload.get(8..).expect("response body");
    assert_eq!(body_len, body.len());
    assert_eq!(body.first().copied(), Some(IoSink::Bbqr.wire_value()));
    assert_eq!(
        body.get(1).copied(),
        Some(Artifact::RawTransaction.wire_value())
    );
    assert_eq!(
        u32::from_le_bytes(body.get(2..6).expect("total").try_into().expect("u32")),
        raw.len() as u32
    );
    let count = u16::from_le_bytes(body.get(6..8).expect("count").try_into().expect("u16"));
    assert_eq!(
        count,
        encoded_part_count(raw.len(), usize::from(part_len)).expect("part count")
    );
    let mut cursor = 8usize;
    for index in 0..count {
        let length_end = cursor + 2;
        let length = usize::from(u16::from_le_bytes(
            body.get(cursor..length_end)
                .expect("frame length")
                .try_into()
                .expect("u16"),
        ));
        let frame_end = length_end + length;
        let actual = body.get(length_end..frame_end).expect("encoded frame");
        let mut expected = [0u8; MAX_FRAME_TEXT_BYTES];
        let expected_len = encode_typed_frame(
            BbqrFileType::Transaction,
            raw,
            usize::from(part_len),
            index,
            &mut expected,
        )
        .expect("type-T frame");
        assert_eq!(actual, &expected[..expected_len]);
        assert!(actual.starts_with(b"B$2T"));
        cursor = frame_end;
    }
    assert_eq!(cursor, body.len());
}

#[test]
fn public_delivery_surface_has_no_inner_request_or_finalized_psbt_constructor() {
    for required in [
        "pub struct KitDeliverySessionV2",
        "outcome: crate::kit_spend_v2::KitSpendOutcomeV2",
        "pub fn receive(",
        "self.core.begin_kit_egress(request.bytes())",
        "NormalEgressArtifactV2::RawTransaction",
    ] {
        assert!(
            ARTIFACT_SOURCE.contains(required),
            "missing surface lock {required}"
        );
    }
    for forbidden in [
        "pub struct KitExportRequestV2",
        "NormalEgressArtifactV2::FinalizedPsbt",
        "pub fn retry",
        "pub fn fallback",
        "pub fn from_bytes",
        "pub fn finalized_psbt",
    ] {
        assert!(
            !ARTIFACT_SOURCE.contains(forbidden),
            "forbidden Kit delivery surface escaped: {forbidden}"
        );
    }
}
