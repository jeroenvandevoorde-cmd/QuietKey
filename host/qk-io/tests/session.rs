//! Exact broker-session states, replies, and terminal transitions.

use qk_io::{
    Artifact, BrokerError, BrokerReply, BrokerSession, BrokerState, InnerError, MockInput,
    MockOutputWriter, Operation, ReplyStatus, Sink, Source, INNER_HEADER_BYTES, INNER_VERSION,
};
use qk_ipc::{
    CoreEvent, CoreProtocol, IpcError, OutboundFrame, ReceivedFrame, StreamDecoder, HEADER_BYTES,
};

const SESSION: [u8; 16] = [0x43; 16];

fn inner_request(operation: Operation, body: &[u8]) -> Vec<u8> {
    let mut request = Vec::with_capacity(INNER_HEADER_BYTES + body.len());
    request.extend_from_slice(&[INNER_VERSION, operation.wire_value(), 0, 0]);
    request.extend_from_slice(&(body.len() as u32).to_le_bytes());
    request.extend_from_slice(body);
    request
}

fn from_outbound(outbound: OutboundFrame, payload: &[u8]) -> ReceivedFrame {
    let mut bytes = vec![0; HEADER_BYTES + payload.len()];
    let length = outbound
        .encode(payload, &mut bytes)
        .expect("valid outbound frame");
    bytes.truncate(length);
    decode(&bytes)
}

fn decode(bytes: &[u8]) -> ReceivedFrame {
    let mut decoder = StreamDecoder::new();
    let outcome = decoder.ingest(bytes, false).expect("complete frame");
    assert_eq!(outcome.consumed(), bytes.len());
    assert!(outcome.frame_ready());
    decoder.take_frame().expect("owned frame")
}

fn decode_reply(reply: &BrokerReply) -> ReceivedFrame {
    assert!(!reply.is_empty());
    assert_eq!(reply.len(), reply.frame_bytes().len());
    decode(reply.frame_bytes())
}

fn open(core: &mut CoreProtocol, broker: &mut BrokerSession) {
    let opening = core.begin().expect("opening frame");
    let opening = from_outbound(opening, &[]);
    let reply = broker
        .accept(&opening, None, None)
        .expect("session ready reply");
    assert_eq!(reply.status(), ReplyStatus::Control);
    let reply = decode_reply(&reply);
    assert_eq!(reply.payload(), &[]);
    assert_eq!(core.accept(&reply), Ok(CoreEvent::SessionReady));
    assert_eq!(broker.state(), BrokerState::Idle);
}

fn exchange(
    core: &mut CoreProtocol,
    broker: &mut BrokerSession,
    payload: &[u8],
    input: Option<&mut MockInput>,
    writer: Option<&mut MockOutputWriter>,
) -> (ReplyStatus, Vec<u8>) {
    let request = core.request().expect("operation frame");
    let request = from_outbound(request, payload);
    let reply = broker
        .accept(&request, input, writer)
        .expect("operation reply");
    let status = reply.status();
    let reply = decode_reply(&reply);
    assert_eq!(core.accept(&reply), Ok(CoreEvent::OperationResponse));
    (status, reply.payload().to_vec())
}

fn ingress_begin() -> Vec<u8> {
    inner_request(
        Operation::IngressBegin,
        &[Source::CameraKitCandidate.wire_value(), 0, 0],
    )
}

fn egress_begin() -> Vec<u8> {
    let mut body = vec![
        Sink::Print.wire_value(),
        Artifact::A1PrintArtifact.wire_value(),
    ];
    body.extend_from_slice(&3u32.to_le_bytes());
    body.extend_from_slice(&0u16.to_le_bytes());
    inner_request(Operation::EgressBegin, &body)
}

#[test]
fn success_path_visits_idle_ingress_and_egress_states_byte_exactly() {
    let mut core = CoreProtocol::new(SESSION);
    let mut broker = BrokerSession::new();
    assert_eq!(broker.state(), BrokerState::Idle);
    open(&mut core, &mut broker);

    let kit = [0x4b; 142];
    let mut input = MockInput::try_new(Source::CameraKitCandidate, &kit).expect("mock input");
    let (status, payload) = exchange(
        &mut core,
        &mut broker,
        &ingress_begin(),
        Some(&mut input),
        None,
    );
    assert_eq!(status, ReplyStatus::Success(Operation::IngressBegin));
    assert_eq!(
        payload,
        [
            INNER_VERSION,
            Operation::IngressBegin.wire_value(),
            0,
            0,
            5,
            0,
            0,
            0,
            Source::CameraKitCandidate.wire_value(),
            142,
            0,
            0,
            0,
        ]
    );
    assert!(input.is_used());
    assert_eq!(broker.state(), BrokerState::IngressReady);

    let (status, payload) = exchange(
        &mut core,
        &mut broker,
        &inner_request(Operation::IngressRead, &0u32.to_le_bytes()),
        None,
        None,
    );
    assert_eq!(status, ReplyStatus::Success(Operation::IngressRead));
    assert_eq!(&payload[..8], &[INNER_VERSION, 2, 0, 0, 151, 0, 0, 0]);
    assert_eq!(&payload[8..17], &[0, 0, 0, 0, 142, 0, 0, 0, 1]);
    assert_eq!(&payload[17..], &kit);
    assert_eq!(broker.state(), BrokerState::Idle);

    let (status, payload) = exchange(&mut core, &mut broker, &egress_begin(), None, None);
    assert_eq!(status, ReplyStatus::Success(Operation::EgressBegin));
    assert_eq!(payload, [INNER_VERSION, 3, 0, 0, 0, 0, 0, 0]);
    assert_eq!(broker.state(), BrokerState::EgressReceiving);

    let mut write_body = Vec::new();
    write_body.extend_from_slice(&0u32.to_le_bytes());
    write_body.extend_from_slice(&3u32.to_le_bytes());
    write_body.extend_from_slice(b"abc");
    let (status, payload) = exchange(
        &mut core,
        &mut broker,
        &inner_request(Operation::EgressWrite, &write_body),
        None,
        None,
    );
    assert_eq!(status, ReplyStatus::Success(Operation::EgressWrite));
    assert_eq!(payload, [INNER_VERSION, 4, 0, 0, 4, 0, 0, 0, 3, 0, 0, 0]);
    assert_eq!(broker.state(), BrokerState::EgressReceiving);

    let mut writer = MockOutputWriter::new(Sink::Print);
    let (status, payload) = exchange(
        &mut core,
        &mut broker,
        &inner_request(Operation::EgressFinish, &[]),
        None,
        Some(&mut writer),
    );
    assert_eq!(status, ReplyStatus::Success(Operation::EgressFinish));
    assert_eq!(
        payload,
        [
            INNER_VERSION,
            5,
            0,
            0,
            6,
            0,
            0,
            0,
            Sink::Print.wire_value(),
            Artifact::A1PrintArtifact.wire_value(),
            3,
            0,
            0,
            0,
        ]
    );
    assert_eq!(writer.final_bytes(), Some(b"abc".as_slice()));
    assert_eq!(broker.state(), BrokerState::Idle);
}

#[test]
fn rejection_reply_has_exact_status_bytes_then_absorbs_all_work() {
    let mut core = CoreProtocol::new(SESSION);
    let mut broker = BrokerSession::new();
    open(&mut core, &mut broker);

    let request = core.request().expect("malformed request frame");
    let request = from_outbound(request, &[0xff]);
    let reply = broker
        .accept(&request, None, None)
        .expect("one rejection reply");
    assert_eq!(
        reply.status(),
        ReplyStatus::Rejected {
            opcode: 0,
            error: InnerError::InnerHeaderTruncated,
        }
    );
    let reply = decode_reply(&reply);
    assert_eq!(reply.payload(), &[INNER_VERSION, 0, 1, 0, 0, 0, 0, 0]);
    assert_eq!(core.accept(&reply), Ok(CoreEvent::OperationResponse));
    assert_eq!(broker.state(), BrokerState::ErrorReplyPending);

    let request = core.request().expect("post-error request frame");
    let request = from_outbound(request, &ingress_begin());
    let mut input =
        MockInput::try_new(Source::CameraKitCandidate, &[0x55; 142]).expect("discarded input");
    assert!(matches!(
        broker.accept(&request, Some(&mut input), None),
        Err(BrokerError::BrokerTerminated)
    ));
    assert!(input.is_used());
    assert_eq!(broker.state(), BrokerState::ErrorReplyPending);
    assert_eq!(broker.peer_lost(), BrokerError::BrokerTerminated);
}

#[test]
fn clean_close_completes_only_from_idle() {
    let mut core = CoreProtocol::new(SESSION);
    let mut broker = BrokerSession::new();
    open(&mut core, &mut broker);

    let close = core.close().expect("close frame");
    let close = from_outbound(close, &[]);
    let reply = broker
        .accept(&close, None, None)
        .expect("session closed reply");
    assert_eq!(reply.status(), ReplyStatus::Control);
    let reply = decode_reply(&reply);
    assert_eq!(reply.payload(), &[]);
    assert_eq!(core.accept(&reply), Ok(CoreEvent::SessionClosed));
    assert_eq!(broker.state(), BrokerState::Closed);
    assert_eq!(broker.peer_lost(), BrokerError::BrokerTerminated);
    assert!(matches!(
        broker.accept(&close, None, None),
        Err(BrokerError::BrokerTerminated)
    ));
}

#[test]
fn peer_loss_and_active_close_are_replyless_terminal_paths() {
    let mut idle_core = CoreProtocol::new(SESSION);
    let mut idle = BrokerSession::new();
    open(&mut idle_core, &mut idle);
    assert_eq!(idle.peer_lost(), BrokerError::Ipc(IpcError::PeerLost));
    assert_eq!(idle.state(), BrokerState::Terminated);
    assert_eq!(idle.peer_lost(), BrokerError::BrokerTerminated);

    let mut ingress_core = CoreProtocol::new([0x51; 16]);
    let mut ingress = BrokerSession::new();
    open(&mut ingress_core, &mut ingress);
    let mut input =
        MockInput::try_new(Source::CameraKitCandidate, &[0x52; 142]).expect("mock input");
    exchange(
        &mut ingress_core,
        &mut ingress,
        &ingress_begin(),
        Some(&mut input),
        None,
    );
    let close = ingress_core.close().expect("active close frame");
    let close = from_outbound(close, &[]);
    assert!(matches!(
        ingress.accept(&close, None, None),
        Err(BrokerError::CloseWithActiveTransfer)
    ));
    assert_eq!(ingress.state(), BrokerState::Terminated);

    let mut egress_core = CoreProtocol::new([0x61; 16]);
    let mut egress = BrokerSession::new();
    open(&mut egress_core, &mut egress);
    exchange(&mut egress_core, &mut egress, &egress_begin(), None, None);
    assert_eq!(egress.peer_lost(), BrokerError::Ipc(IpcError::PeerLost));
    assert_eq!(egress.state(), BrokerState::Terminated);
}

#[test]
fn receive_decoder_failure_is_a_replyless_terminal_path() {
    let mut core = CoreProtocol::new([0x71; 16]);
    let mut broker = BrokerSession::new();
    open(&mut core, &mut broker);

    assert_eq!(
        broker.receive_failed(IpcError::AncillaryData),
        BrokerError::Ipc(IpcError::AncillaryData)
    );
    assert_eq!(broker.state(), BrokerState::Terminated);
    assert_eq!(
        broker.receive_failed(IpcError::ConnectionClosedMidFrame),
        BrokerError::BrokerTerminated
    );
}
