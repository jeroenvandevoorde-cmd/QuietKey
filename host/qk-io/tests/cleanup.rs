#![cfg(feature = "fuzzing")]

use qk_io::{
    reset_wiped_bytes, wiped_bytes, Artifact, BrokerError, BrokerSession, BrokerState, MockInput,
    MockOutputWriter, Operation, Sink, Source, A1_CANDIDATE_BYTES, INNER_HEADER_BYTES,
    INNER_VERSION, MAX_FILENAME_BYTES,
};
use qk_ipc::{
    CoreEvent, CoreProtocol, IpcError, OutboundFrame, ReceivedFrame, StreamDecoder, HEADER_BYTES,
};
use std::panic::{catch_unwind, AssertUnwindSafe};

const SESSION_ID: [u8; 16] = *b"qk-io-cleanup-v1";

struct Harness {
    core: CoreProtocol,
    broker: BrokerSession,
}

impl Harness {
    fn open() -> Self {
        let mut core = CoreProtocol::new(SESSION_ID);
        let mut broker = BrokerSession::new();
        let request = received(core.begin().expect("open"), &[]);
        let reply = broker.accept(&request, None, None).expect("ready reply");
        let response = decode(reply.frame_bytes());
        assert_eq!(core.accept(&response), Ok(CoreEvent::SessionReady));
        drop(reply);
        Self { core, broker }
    }

    fn request(
        &mut self,
        payload: &[u8],
        input: Option<&mut MockInput>,
        writer: Option<&mut MockOutputWriter>,
    ) -> qk_io::BrokerReply {
        let request = received(self.core.request().expect("request"), payload);
        let reply = self
            .broker
            .accept(&request, input, writer)
            .expect("broker reply");
        let response = decode(reply.frame_bytes());
        assert_eq!(
            self.core.accept(&response),
            Ok(CoreEvent::OperationResponse)
        );
        reply
    }
}

fn received(outbound: OutboundFrame, payload: &[u8]) -> ReceivedFrame {
    let mut bytes = vec![0u8; HEADER_BYTES + payload.len()];
    let length = outbound.encode(payload, &mut bytes).expect("encode frame");
    assert_eq!(length, bytes.len());
    decode(&bytes)
}

fn decode(bytes: &[u8]) -> ReceivedFrame {
    let mut decoder = StreamDecoder::new();
    let outcome = decoder.ingest(bytes, false).expect("decode frame");
    assert_eq!(outcome.consumed(), bytes.len());
    assert!(outcome.frame_ready());
    decoder.take_frame().expect("take frame")
}

fn request(operation: Operation, body: &[u8]) -> Vec<u8> {
    let mut payload = Vec::with_capacity(INNER_HEADER_BYTES + body.len());
    payload.extend_from_slice(&[INNER_VERSION, operation.wire_value(), 0, 0]);
    payload.extend_from_slice(&(body.len() as u32).to_le_bytes());
    payload.extend_from_slice(body);
    payload
}

fn ingress_begin(source: Source) -> Vec<u8> {
    request(Operation::IngressBegin, &[source.wire_value(), 0, 0])
}

fn egress_begin(sink: Sink, artifact: Artifact, length: usize, aux: &[u8]) -> Vec<u8> {
    let mut body = vec![sink.wire_value(), artifact.wire_value()];
    body.extend_from_slice(&(length as u32).to_le_bytes());
    body.extend_from_slice(&(aux.len() as u16).to_le_bytes());
    body.extend_from_slice(aux);
    request(Operation::EgressBegin, &body)
}

fn egress_write(offset: usize, bytes: &[u8]) -> Vec<u8> {
    let mut body = Vec::with_capacity(8 + bytes.len());
    body.extend_from_slice(&(offset as u32).to_le_bytes());
    body.extend_from_slice(&(bytes.len() as u32).to_le_bytes());
    body.extend_from_slice(bytes);
    request(Operation::EgressWrite, &body)
}

#[test]
fn peer_loss_wipes_the_exact_active_ingress_allocation() {
    let mut harness = Harness::open();
    let candidate = [0x71; A1_CANDIDATE_BYTES];
    let mut input = MockInput::try_new(Source::CameraA1Candidate, &candidate).expect("input");
    drop(harness.request(
        &ingress_begin(Source::CameraA1Candidate),
        Some(&mut input),
        None,
    ));

    reset_wiped_bytes();
    assert_eq!(harness.broker.peer_lost().to_string(), "PeerLost");
    assert_eq!(harness.broker.state(), BrokerState::Terminated);
    assert_eq!(wiped_bytes(), A1_CANDIDATE_BYTES);
}

#[test]
fn peer_loss_wipes_the_exact_active_egress_owner_and_filename_scratch() {
    const PAYLOAD_BYTES: usize = 41;
    let mut harness = Harness::open();
    drop(harness.request(
        &egress_begin(Sink::Print, Artifact::A1PrintArtifact, PAYLOAD_BYTES, &[]),
        None,
        None,
    ));

    reset_wiped_bytes();
    assert_eq!(harness.broker.peer_lost().to_string(), "PeerLost");
    assert_eq!(harness.broker.state(), BrokerState::Terminated);
    assert_eq!(wiped_bytes(), PAYLOAD_BYTES + MAX_FILENAME_BYTES);
}

#[test]
fn decoder_failure_wipes_the_exact_active_ingress_allocation() {
    let mut harness = Harness::open();
    let candidate = [0x72; A1_CANDIDATE_BYTES];
    let mut input = MockInput::try_new(Source::CameraA1Candidate, &candidate).expect("input");
    drop(harness.request(
        &ingress_begin(Source::CameraA1Candidate),
        Some(&mut input),
        None,
    ));

    reset_wiped_bytes();
    assert_eq!(
        harness.broker.receive_failed(IpcError::AncillaryData),
        BrokerError::Ipc(IpcError::AncillaryData)
    );
    assert_eq!(harness.broker.state(), BrokerState::Terminated);
    assert_eq!(wiped_bytes(), A1_CANDIDATE_BYTES);
}

#[test]
fn decoder_failure_wipes_the_exact_active_egress_owner_and_filename_scratch() {
    const PAYLOAD_BYTES: usize = 43;
    let mut harness = Harness::open();
    drop(harness.request(
        &egress_begin(Sink::Print, Artifact::KitPrintArtifact, PAYLOAD_BYTES, &[]),
        None,
        None,
    ));

    reset_wiped_bytes();
    assert_eq!(
        harness
            .broker
            .receive_failed(IpcError::ConnectionClosedMidFrame),
        BrokerError::Ipc(IpcError::ConnectionClosedMidFrame)
    );
    assert_eq!(harness.broker.state(), BrokerState::Terminated);
    assert_eq!(wiped_bytes(), PAYLOAD_BYTES + MAX_FILENAME_BYTES);
}

#[test]
fn already_formed_reply_wipes_its_complete_frame_allocation_on_drop() {
    let mut harness = Harness::open();
    let reply = harness.request(
        &egress_begin(Sink::Print, Artifact::A1PrintArtifact, 1, &[]),
        None,
        None,
    );
    let complete_frame_bytes = reply.len();

    reset_wiped_bytes();
    drop(reply);
    assert_eq!(wiped_bytes(), complete_frame_bytes);
}

#[test]
fn caught_unwind_wipes_the_exact_active_ingress_allocation() {
    let mut harness = Harness::open();
    let candidate = [0x3c; A1_CANDIDATE_BYTES];
    let mut input = MockInput::try_new(Source::CameraA1Candidate, &candidate).expect("input");
    drop(harness.request(
        &ingress_begin(Source::CameraA1Candidate),
        Some(&mut input),
        None,
    ));

    reset_wiped_bytes();
    let result = catch_unwind(AssertUnwindSafe(move || {
        let _active_session = harness;
        panic!("test-only caught unwind");
    }));
    assert!(result.is_err());
    assert_eq!(wiped_bytes(), A1_CANDIDATE_BYTES);
}

#[test]
fn successful_one_use_writer_wipes_exact_external_mock_bytes_on_drop() {
    let payload = b"public opaque print bytes";
    let mut harness = Harness::open();
    drop(harness.request(
        &egress_begin(Sink::Print, Artifact::A1PrintArtifact, payload.len(), &[]),
        None,
        None,
    ));
    drop(harness.request(&egress_write(0, payload), None, None));
    let mut writer = MockOutputWriter::new(Sink::Print);
    drop(harness.request(
        &request(Operation::EgressFinish, &[]),
        None,
        Some(&mut writer),
    ));

    reset_wiped_bytes();
    drop(writer);
    assert_eq!(wiped_bytes(), payload.len() + MAX_FILENAME_BYTES);
}
