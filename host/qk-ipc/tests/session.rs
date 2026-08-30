//! Exact one-outstanding core/I/O endpoint state transitions.

use qk_ipc::{
    encode_frame, CoreEvent, CoreProtocol, Direction, IoEvent, IoProtocol, IpcError, MessageKind,
    OutboundFrame, ReceivedFrame, StreamDecoder, HEADER_BYTES,
};

const SESSION: [u8; 16] = [0x63; 16];

fn received(
    direction: Direction,
    kind: MessageKind,
    session_id: [u8; 16],
    exchange_id: u32,
    payload: &[u8],
) -> ReceivedFrame {
    let mut encoded = vec![0u8; HEADER_BYTES + payload.len()];
    encode_frame(
        direction,
        kind,
        session_id,
        exchange_id,
        payload,
        &mut encoded,
    )
    .expect("valid wire frame");
    let mut decoder = StreamDecoder::new();
    assert!(decoder
        .ingest(&encoded, false)
        .expect("complete frame")
        .frame_ready());
    decoder.take_frame().expect("owned frame")
}

fn from_outbound(outbound: OutboundFrame, payload: &[u8]) -> ReceivedFrame {
    let mut encoded = vec![0u8; HEADER_BYTES + payload.len()];
    let length = outbound
        .encode(payload, &mut encoded)
        .expect("valid outbound frame");
    encoded.truncate(length);
    let mut decoder = StreamDecoder::new();
    assert!(decoder
        .ingest(&encoded, false)
        .expect("complete frame")
        .frame_ready());
    decoder.take_frame().expect("owned frame")
}

fn open(core: &mut CoreProtocol, io: &mut IoProtocol) {
    let open = core.begin().expect("open initiation");
    assert_eq!(open.direction(), Direction::CoreToIo);
    assert_eq!(open.kind(), MessageKind::SessionOpen);
    assert_eq!(open.session_id(), &SESSION);
    assert_eq!(open.exchange_id(), 1);
    let open = from_outbound(open, &[]);
    assert_eq!(io.accept(&open), Ok(IoEvent::SessionOpen));
    let ready = io.reply().expect("ready reply");
    assert_eq!(ready.direction(), Direction::IoToCore);
    assert_eq!(ready.kind(), MessageKind::SessionReady);
    assert_eq!(ready.exchange_id(), 1);
    let ready = from_outbound(ready, &[]);
    assert_eq!(core.accept(&ready), Ok(CoreEvent::SessionReady));
}

fn operation(core: &mut CoreProtocol, io: &mut IoProtocol, request: &[u8], response: &[u8]) {
    let request_frame = core.request().expect("request initiation");
    let exchange = request_frame.exchange_id();
    let request_frame = from_outbound(request_frame, request);
    assert_eq!(io.accept(&request_frame), Ok(IoEvent::OperationRequest));
    assert_eq!(request_frame.payload(), request);
    let response_frame = io.reply().expect("response");
    assert_eq!(response_frame.exchange_id(), exchange);
    let response_frame = from_outbound(response_frame, response);
    assert_eq!(
        core.accept(&response_frame),
        Ok(CoreEvent::OperationResponse)
    );
    assert_eq!(response_frame.payload(), response);
}

fn ready_io_after_two_exchanges() -> IoProtocol {
    let mut core = CoreProtocol::new(SESSION);
    let mut io = IoProtocol::new();
    open(&mut core, &mut io);
    operation(&mut core, &mut io, &[1], &[2]);
    io
}

#[test]
fn canonical_open_operations_and_close_use_exact_ids() {
    let mut core = CoreProtocol::new(SESSION);
    let mut io = IoProtocol::new();
    open(&mut core, &mut io);
    operation(&mut core, &mut io, b"first", b"one");
    operation(&mut core, &mut io, b"second", b"two");

    let close = core.close().expect("close initiation");
    assert_eq!(close.kind(), MessageKind::SessionClose);
    assert_eq!(close.exchange_id(), 4);
    let close = from_outbound(close, &[]);
    assert_eq!(io.accept(&close), Ok(IoEvent::SessionClose));
    let closed = io.reply().expect("closed reply");
    assert_eq!(closed.kind(), MessageKind::SessionClosed);
    assert_eq!(closed.exchange_id(), 4);
    let closed = from_outbound(closed, &[]);
    assert_eq!(core.accept(&closed), Ok(CoreEvent::SessionClosed));
    assert!(core.is_closed());
    assert!(io.is_closed());
    assert_eq!(core.request(), Err(IpcError::SessionClosed));
    assert_eq!(io.reply(), Err(IpcError::SessionClosed));
    assert_eq!(core.peer_lost(), IpcError::SessionClosed);
    assert_eq!(io.peer_lost(), IpcError::SessionClosed);
}

#[test]
fn local_precondition_rejections_preserve_the_valid_pending_path() {
    let mut core = CoreProtocol::new(SESSION);
    let mut io = IoProtocol::new();
    assert_eq!(core.request(), Err(IpcError::SessionNotReady));
    assert_eq!(core.close(), Err(IpcError::SessionNotReady));
    assert_eq!(io.reply(), Err(IpcError::NoOutstandingExchange));

    let opening = core.begin().expect("opening");
    assert_eq!(core.begin(), Err(IpcError::OutstandingExchange));
    assert_eq!(core.request(), Err(IpcError::OutstandingExchange));
    assert_eq!(core.close(), Err(IpcError::OutstandingExchange));
    let opening = from_outbound(opening, &[]);
    assert_eq!(io.accept(&opening), Ok(IoEvent::SessionOpen));
    let ready = io.reply().expect("ready");
    let ready = from_outbound(ready, &[]);
    assert_eq!(core.accept(&ready), Ok(CoreEvent::SessionReady));

    let request = core.request().expect("request");
    assert_eq!(core.request(), Err(IpcError::OutstandingExchange));
    let request = from_outbound(request, &[1]);
    assert_eq!(io.accept(&request), Ok(IoEvent::OperationRequest));
    assert_eq!(io.reply().expect("response").exchange_id(), 2);
}

#[test]
fn io_rejects_reuse_regression_and_skip_by_distinct_names() {
    let mut reuse = ready_io_after_two_exchanges();
    let frame = received(
        Direction::CoreToIo,
        MessageKind::OperationRequest,
        SESSION,
        2,
        &[1],
    );
    assert_eq!(reuse.accept(&frame), Err(IpcError::ExchangeIdReuse));
    assert!(reuse.is_terminated());

    let mut regression = ready_io_after_two_exchanges();
    let frame = received(
        Direction::CoreToIo,
        MessageKind::OperationRequest,
        SESSION,
        1,
        &[1],
    );
    assert_eq!(
        regression.accept(&frame),
        Err(IpcError::ExchangeIdRegression)
    );
    assert!(regression.is_terminated());

    let mut skipped = ready_io_after_two_exchanges();
    let frame = received(
        Direction::CoreToIo,
        MessageKind::OperationRequest,
        SESSION,
        4,
        &[1],
    );
    assert_eq!(skipped.accept(&frame), Err(IpcError::ExchangeIdSkipped));
    assert!(skipped.is_terminated());
}

#[test]
fn open_must_be_kind_open_and_exchange_one() {
    let mut wrong_kind = IoProtocol::new();
    let frame = received(
        Direction::CoreToIo,
        MessageKind::OperationRequest,
        SESSION,
        1,
        &[1],
    );
    assert_eq!(
        wrong_kind.accept(&frame),
        Err(IpcError::UnexpectedMessageKind)
    );

    let mut wrong_exchange = IoProtocol::new();
    let frame = received(
        Direction::CoreToIo,
        MessageKind::SessionOpen,
        SESSION,
        2,
        &[],
    );
    assert_eq!(
        wrong_exchange.accept(&frame),
        Err(IpcError::ExchangeIdSkipped)
    );
}

#[test]
fn wrong_direction_session_kind_and_response_id_each_terminate_core() {
    let mut wrong_direction = CoreProtocol::new(SESSION);
    wrong_direction.begin().expect("pending open");
    let frame = received(
        Direction::CoreToIo,
        MessageKind::SessionOpen,
        SESSION,
        1,
        &[],
    );
    assert_eq!(
        wrong_direction.accept(&frame),
        Err(IpcError::UnexpectedDirection)
    );
    assert_eq!(wrong_direction.request(), Err(IpcError::SessionTerminated));

    let mut wrong_session = CoreProtocol::new(SESSION);
    wrong_session.begin().expect("pending open");
    let frame = received(
        Direction::IoToCore,
        MessageKind::SessionReady,
        [0x99; 16],
        1,
        &[],
    );
    assert_eq!(
        wrong_session.accept(&frame),
        Err(IpcError::SessionIdMismatch)
    );

    let mut wrong_kind = CoreProtocol::new(SESSION);
    wrong_kind.begin().expect("pending open");
    let frame = received(
        Direction::IoToCore,
        MessageKind::SessionClosed,
        SESSION,
        1,
        &[],
    );
    assert_eq!(
        wrong_kind.accept(&frame),
        Err(IpcError::UnexpectedMessageKind)
    );

    let mut wrong_id = CoreProtocol::new(SESSION);
    wrong_id.begin().expect("pending open");
    let frame = received(
        Direction::IoToCore,
        MessageKind::SessionReady,
        SESSION,
        2,
        &[],
    );
    assert_eq!(wrong_id.accept(&frame), Err(IpcError::ResponseIdMismatch));
}

#[test]
fn second_initiation_while_io_reply_is_pending_terminates() {
    let mut io = IoProtocol::new();
    let first = received(
        Direction::CoreToIo,
        MessageKind::SessionOpen,
        SESSION,
        1,
        &[],
    );
    assert_eq!(io.accept(&first), Ok(IoEvent::SessionOpen));
    let second = received(
        Direction::CoreToIo,
        MessageKind::OperationRequest,
        SESSION,
        2,
        &[1],
    );
    assert_eq!(io.accept(&second), Err(IpcError::OutstandingExchange));
    assert_eq!(io.reply(), Err(IpcError::SessionTerminated));
}

#[test]
fn response_without_an_outstanding_core_exchange_terminates() {
    let mut core = CoreProtocol::new(SESSION);
    let mut io = IoProtocol::new();
    open(&mut core, &mut io);
    let unsolicited = received(
        Direction::IoToCore,
        MessageKind::SessionReady,
        SESSION,
        1,
        &[],
    );
    assert_eq!(
        core.accept(&unsolicited),
        Err(IpcError::NoOutstandingExchange)
    );
    assert!(core.is_terminated());
}

#[test]
fn peer_loss_is_closed_terminal_from_every_live_phase() {
    let mut new_core = CoreProtocol::new(SESSION);
    assert_eq!(new_core.peer_lost(), IpcError::PeerLost);
    assert_eq!(new_core.peer_lost(), IpcError::SessionTerminated);

    let mut opening_core = CoreProtocol::new(SESSION);
    opening_core.begin().expect("opening");
    assert_eq!(opening_core.peer_lost(), IpcError::PeerLost);
    assert_eq!(opening_core.request(), Err(IpcError::SessionTerminated));

    let mut awaiting_io = IoProtocol::new();
    assert_eq!(awaiting_io.peer_lost(), IpcError::PeerLost);
    assert_eq!(awaiting_io.reply(), Err(IpcError::SessionTerminated));

    let mut pending_io = IoProtocol::new();
    let open = received(
        Direction::CoreToIo,
        MessageKind::SessionOpen,
        SESSION,
        1,
        &[],
    );
    pending_io.accept(&open).expect("pending reply");
    assert_eq!(pending_io.peer_lost(), IpcError::PeerLost);
    assert_eq!(pending_io.reply(), Err(IpcError::SessionTerminated));
}

#[test]
fn all_zero_session_bytes_bind_and_round_trip_exactly() {
    let mut core = CoreProtocol::new([0; 16]);
    let mut io = IoProtocol::new();
    let open = core.begin().expect("open");
    assert_eq!(open.session_id(), &[0; 16]);
    let open = from_outbound(open, &[]);
    assert_eq!(io.accept(&open), Ok(IoEvent::SessionOpen));
    let ready = from_outbound(io.reply().expect("ready"), &[]);
    assert_eq!(core.accept(&ready), Ok(CoreEvent::SessionReady));
}

#[test]
fn receive_boundary_rejections_terminate_the_paired_session() {
    for error in [IpcError::MagicMismatch, IpcError::AncillaryData] {
        let mut core = CoreProtocol::new(SESSION);
        core.begin().expect("opening exchange");
        assert_eq!(core.receive_failed(error), error);
        assert!(core.is_terminated());
        assert_eq!(core.begin(), Err(IpcError::SessionTerminated));
        assert_eq!(core.receive_failed(error), IpcError::SessionTerminated);

        let mut io = IoProtocol::new();
        assert_eq!(io.receive_failed(error), error);
        assert!(io.is_terminated());
        assert_eq!(io.reply(), Err(IpcError::SessionTerminated));
        assert_eq!(io.receive_failed(error), IpcError::SessionTerminated);
    }
}
