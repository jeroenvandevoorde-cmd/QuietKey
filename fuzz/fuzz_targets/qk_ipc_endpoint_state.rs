#![no_main]

use libfuzzer_sys::fuzz_target;
use qk_ipc::{
    encode_frame, CoreEvent, CoreProtocol, Direction, IoEvent, IoProtocol, IpcError, MessageKind,
    OutboundFrame, ReceivedFrame, StreamDecoder, HEADER_BYTES,
};

const MAX_PRESENTED_BYTES: usize = 4_096;

fn error_name(error: IpcError) -> &'static str {
    match error {
        IpcError::DecoderTerminated => "DecoderTerminated",
        IpcError::SessionTerminated => "SessionTerminated",
        IpcError::AncillaryData => "AncillaryData",
        IpcError::HeaderTruncated => "HeaderTruncated",
        IpcError::MagicMismatch => "MagicMismatch",
        IpcError::VersionMismatch => "VersionMismatch",
        IpcError::DirectionOutOfRange => "DirectionOutOfRange",
        IpcError::KindOutOfRange => "KindOutOfRange",
        IpcError::DirectionKindMismatch => "DirectionKindMismatch",
        IpcError::ExchangeIdZero => "ExchangeIdZero",
        IpcError::PayloadLengthExceeded => "PayloadLengthExceeded",
        IpcError::PayloadTruncated => "PayloadTruncated",
        IpcError::TrailingByte => "TrailingByte",
        IpcError::ControlPayloadNotEmpty => "ControlPayloadNotEmpty",
        IpcError::OperationPayloadEmpty => "OperationPayloadEmpty",
        IpcError::OutputBufferTooSmall => "OutputBufferTooSmall",
        IpcError::PayloadAllocationFailed => "PayloadAllocationFailed",
        IpcError::UnexpectedDirection => "UnexpectedDirection",
        IpcError::SessionIdMismatch => "SessionIdMismatch",
        IpcError::UnexpectedMessageKind => "UnexpectedMessageKind",
        IpcError::ExchangeIdReuse => "ExchangeIdReuse",
        IpcError::ExchangeIdRegression => "ExchangeIdRegression",
        IpcError::ExchangeIdSkipped => "ExchangeIdSkipped",
        IpcError::ExchangeIdExhausted => "ExchangeIdExhausted",
        IpcError::ResponseIdMismatch => "ResponseIdMismatch",
        IpcError::OutstandingExchange => "OutstandingExchange",
        IpcError::NoOutstandingExchange => "NoOutstandingExchange",
        IpcError::SessionNotReady => "SessionNotReady",
        IpcError::SessionClosed => "SessionClosed",
        IpcError::InvalidTransition => "InvalidTransition",
        IpcError::PeerLost => "PeerLost",
        IpcError::ConnectionClosedMidFrame => "ConnectionClosedMidFrame",
    }
}

fn assert_named(error: IpcError) -> u8 {
    assert_eq!(error.to_string(), error_name(error));
    error as u8
}

fn payload_for(kind: MessageKind, byte: u8) -> Vec<u8> {
    if kind.requires_payload() {
        vec![byte]
    } else {
        Vec::new()
    }
}

fn receive(outbound: OutboundFrame, payload_byte: u8) -> ReceivedFrame {
    let payload = payload_for(outbound.kind(), payload_byte);
    let mut encoded = vec![0u8; HEADER_BYTES + payload.len()];
    let written = outbound
        .encode(&payload, &mut encoded)
        .expect("protocol outbound must encode");
    let mut decoder = StreamDecoder::new();
    let outcome = decoder
        .ingest(&encoded[..written], false)
        .expect("protocol outbound must decode");
    assert_eq!(outcome.consumed(), written);
    assert!(outcome.frame_ready());
    decoder.take_frame().expect("complete protocol frame")
}

fn injected(
    direction: Direction,
    kind: MessageKind,
    session_id: [u8; 16],
    exchange_id: u32,
    payload_byte: u8,
) -> Option<ReceivedFrame> {
    let payload = payload_for(kind, payload_byte);
    let mut encoded = vec![0u8; HEADER_BYTES + payload.len()];
    let written = match encode_frame(
        direction,
        kind,
        session_id,
        exchange_id,
        &payload,
        &mut encoded,
    ) {
        Ok(written) => written,
        Err(error) => {
            assert_named(error);
            return None;
        }
    };
    let mut decoder = StreamDecoder::new();
    let outcome = decoder.ingest(&encoded[..written], false).ok()?;
    assert!(outcome.frame_ready());
    decoder.take_frame().ok()
}

fn happy_path(session_id: [u8; 16]) {
    let mut core = CoreProtocol::new(session_id);
    let mut io = IoProtocol::new();

    let open = core.begin().expect("open");
    assert_eq!(io.accept(&receive(open, 0)), Ok(IoEvent::SessionOpen));
    let ready = io.reply().expect("ready");
    assert_eq!(core.accept(&receive(ready, 0)), Ok(CoreEvent::SessionReady));

    let request = core.request().expect("request");
    assert_eq!(
        io.accept(&receive(request, 0x51)),
        Ok(IoEvent::OperationRequest)
    );
    let response = io.reply().expect("response");
    assert_eq!(
        core.accept(&receive(response, 0x52)),
        Ok(CoreEvent::OperationResponse)
    );

    let close = core.close().expect("close");
    assert_eq!(io.accept(&receive(close, 0)), Ok(IoEvent::SessionClose));
    let closed = io.reply().expect("closed");
    assert_eq!(
        core.accept(&receive(closed, 0)),
        Ok(CoreEvent::SessionClosed)
    );
    assert!(core.is_closed());
    assert!(io.is_closed());
    assert_eq!(core.request(), Err(IpcError::SessionClosed));
    assert_eq!(io.reply(), Err(IpcError::SessionClosed));
}

fn record_outbound(
    result: Result<OutboundFrame, IpcError>,
    slot: &mut Option<OutboundFrame>,
) -> u8 {
    match result {
        Ok(frame) => {
            *slot = Some(frame);
            0x80 | frame.kind().wire_value() as u8
        }
        Err(error) => assert_named(error),
    }
}

fn drive(data: &[u8], session_id: [u8; 16]) -> Vec<u8> {
    let mut core = CoreProtocol::new(session_id);
    let mut io = IoProtocol::new();
    let mut core_outbound = None;
    let mut io_outbound = None;
    let mut summary = Vec::with_capacity(data.len() / 2 + 4);

    for command in data.chunks(4).take(1_024) {
        let action = command[0] % 14;
        let selector = command.get(1).copied().unwrap_or(0);
        let value = command.get(2).copied().unwrap_or(0);
        let id_delta = command.get(3).copied().unwrap_or(0);
        let outcome = match action {
            0 => record_outbound(core.begin(), &mut core_outbound),
            1 => record_outbound(core.request(), &mut core_outbound),
            2 => record_outbound(core.close(), &mut core_outbound),
            3 => match core_outbound {
                Some(frame) => match io.accept(&receive(frame, value)) {
                    Ok(event) => 0xa0 | event as u8,
                    Err(error) => assert_named(error),
                },
                None => 0x7d,
            },
            4 => record_outbound(io.reply(), &mut io_outbound),
            5 => match io_outbound {
                Some(frame) => match core.accept(&receive(frame, value)) {
                    Ok(event) => 0xb0 | event as u8,
                    Err(error) => assert_named(error),
                },
                None => 0x7e,
            },
            6 => assert_named(core.peer_lost()),
            7 => assert_named(io.peer_lost()),
            8 => {
                let selected_kind = match selector % 3 {
                    0 => MessageKind::SessionOpen,
                    1 => MessageKind::OperationRequest,
                    _ => MessageKind::SessionClose,
                };
                let selected_session = if selector & 0x80 == 0 {
                    session_id
                } else {
                    [value; 16]
                };
                let exchange_id = u32::from(id_delta).saturating_add(1);
                match injected(
                    Direction::CoreToIo,
                    selected_kind,
                    selected_session,
                    exchange_id,
                    value,
                ) {
                    Some(frame) => match io.accept(&frame) {
                        Ok(event) => 0xc0 | event as u8,
                        Err(error) => assert_named(error),
                    },
                    None => 0x7b,
                }
            }
            9 => {
                let selected_kind = match selector % 3 {
                    0 => MessageKind::SessionReady,
                    1 => MessageKind::OperationResponse,
                    _ => MessageKind::SessionClosed,
                };
                let selected_session = if selector & 0x80 == 0 {
                    session_id
                } else {
                    [value; 16]
                };
                let exchange_id = u32::from(id_delta).saturating_add(1);
                match injected(
                    Direction::IoToCore,
                    selected_kind,
                    selected_session,
                    exchange_id,
                    value,
                ) {
                    Some(frame) => match core.accept(&frame) {
                        Ok(event) => 0xd0 | event as u8,
                        Err(error) => assert_named(error),
                    },
                    None => 0x7c,
                }
            }
            10 => assert_named(core.receive_failed(if selector & 1 == 0 {
                IpcError::MagicMismatch
            } else {
                IpcError::AncillaryData
            })),
            11 => assert_named(io.receive_failed(if selector & 1 == 0 {
                IpcError::MagicMismatch
            } else {
                IpcError::AncillaryData
            })),
            12 => u8::from(core.is_closed()) | (u8::from(core.is_terminated()) << 1),
            _ => u8::from(io.is_closed()) | (u8::from(io.is_terminated()) << 1),
        };
        summary.push(outcome);
    }
    summary.push(u8::from(core.is_closed()) | (u8::from(core.is_terminated()) << 1));
    summary.push(u8::from(io.is_closed()) | (u8::from(io.is_terminated()) << 1));
    summary
}

fuzz_target!(|data: &[u8]| {
    if data.len() > MAX_PRESENTED_BYTES {
        return;
    }
    let mut session_id = [0u8; 16];
    for (destination, source) in session_id.iter_mut().zip(data.iter().copied()) {
        *destination = source;
    }
    happy_path(session_id);
    assert_eq!(drive(data, session_id), drive(data, session_id));
});
