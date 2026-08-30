#![no_main]

use libfuzzer_sys::fuzz_target;
use qk_ipc::{
    encode_frame, parse_frame, reset_wiped_bytes, wiped_bytes, Direction, IpcError, MessageKind,
    StreamDecoder, HEADER_BYTES, MAX_PAYLOAD_BYTES,
};

const MAX_PRESENTED_BYTES: usize = 4_096;
const SENTINEL: u8 = 0xa5;

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

fn assert_named(error: IpcError) {
    assert_eq!(error.to_string(), error_name(error));
}

fn kind(selector: u8) -> MessageKind {
    match selector % 6 {
        0 => MessageKind::SessionOpen,
        1 => MessageKind::OperationRequest,
        2 => MessageKind::SessionClose,
        3 => MessageKind::SessionReady,
        4 => MessageKind::OperationResponse,
        _ => MessageKind::SessionClosed,
    }
}

fn session(data: &[u8]) -> [u8; 16] {
    let mut value = [0u8; 16];
    for (destination, source) in value.iter_mut().zip(data.iter().copied()) {
        *destination = source;
    }
    value
}

fn exercise_raw(bytes: &[u8]) {
    let first = parse_frame(bytes);
    let second = parse_frame(bytes);
    match (first, second) {
        (Err(left), Err(right)) => {
            assert_eq!(left, right);
            assert_named(left);
        }
        (Ok(left), Ok(right)) => {
            assert_eq!(left, right);
            let mut encoded = vec![SENTINEL; bytes.len() + 1];
            let written = encode_frame(
                left.header().direction(),
                left.header().kind(),
                *left.header().session_id(),
                left.header().exchange_id(),
                left.payload(),
                &mut encoded,
            )
            .expect("accepted frame must re-encode");
            assert_eq!(written, bytes.len());
            assert_eq!(&encoded[..written], bytes);
            assert_eq!(encoded[written], SENTINEL);
        }
        _ => panic!("repeat parse was inconsistent"),
    }
}

fn exercise_structured(data: &[u8]) {
    let selected_kind = kind(data.first().copied().unwrap_or(0));
    let canonical_direction = selected_kind.direction();
    let selected_direction = if data.get(1).copied().unwrap_or(0) & 1 == 0 {
        canonical_direction
    } else {
        match canonical_direction {
            Direction::CoreToIo => Direction::IoToCore,
            Direction::IoToCore => Direction::CoreToIo,
        }
    };
    let exchange_id = u32::from_le_bytes([
        data.get(2).copied().unwrap_or(0),
        data.get(3).copied().unwrap_or(0),
        data.get(4).copied().unwrap_or(0),
        data.get(5).copied().unwrap_or(0),
    ]);
    let payload = data.get(22..).unwrap_or_default();
    let mut output = vec![SENTINEL; HEADER_BYTES + payload.len() + 1];
    let before = output.clone();
    let first = encode_frame(
        selected_direction,
        selected_kind,
        session(data.get(6..22).unwrap_or_default()),
        exchange_id,
        payload,
        &mut output,
    );
    let mut repeated = before.clone();
    let second = encode_frame(
        selected_direction,
        selected_kind,
        session(data.get(6..22).unwrap_or_default()),
        exchange_id,
        payload,
        &mut repeated,
    );
    assert_eq!(first, second);
    assert_eq!(output, repeated);
    match first {
        Err(error) => {
            assert_named(error);
            assert_eq!(output, before);
        }
        Ok(written) => {
            assert_eq!(output[written], SENTINEL);
            let parsed = parse_frame(&output[..written]).expect("encoded frame must parse");
            assert_eq!(parsed.header().direction(), selected_direction);
            assert_eq!(parsed.header().kind(), selected_kind);
            assert_eq!(parsed.header().exchange_id(), exchange_id);
            assert_eq!(parsed.payload(), payload);
        }
    }
}

#[derive(Debug, Eq, PartialEq)]
struct StreamSummary {
    frames: Vec<(Direction, MessageKind, [u8; 16], u32, Vec<u8>)>,
    consumed: usize,
    terminal: IpcError,
}

fn drive_stream(bytes: &[u8], controls: &[u8], ancillary_at: Option<usize>) -> StreamSummary {
    let mut decoder = StreamDecoder::new();
    let mut frames = Vec::new();
    let mut offset = 0usize;
    let mut step = 0usize;
    let terminal = loop {
        if offset == bytes.len() {
            break decoder.finish();
        }
        let remaining = bytes.len() - offset;
        let width = 1 + usize::from(controls.get(step).copied().unwrap_or(0)) % remaining;
        let ancillary = ancillary_at == Some(step);
        match decoder.ingest(&bytes[offset..offset + width], ancillary) {
            Err(error) => break error,
            Ok(outcome) => {
                assert!(outcome.consumed() <= width);
                offset += outcome.consumed();
                if outcome.frame_ready() {
                    let frame = decoder.take_frame().expect("ready frame must be takeable");
                    frames.push((
                        frame.header().direction(),
                        frame.header().kind(),
                        *frame.header().session_id(),
                        frame.header().exchange_id(),
                        frame.payload().to_vec(),
                    ));
                }
                if outcome.consumed() == 0 && !outcome.frame_ready() {
                    break IpcError::InvalidTransition;
                }
            }
        }
        step += 1;
    };
    assert_named(terminal);
    StreamSummary {
        frames,
        consumed: offset,
        terminal,
    }
}

fn canonical_operation(payload: &[u8], exchange_id: u32) -> Vec<u8> {
    let payload = if payload.is_empty() {
        &[0u8][..]
    } else {
        payload
    };
    let mut output = vec![0u8; HEADER_BYTES + payload.len()];
    let written = encode_frame(
        Direction::CoreToIo,
        MessageKind::OperationRequest,
        [0x42; 16],
        exchange_id,
        payload,
        &mut output,
    )
    .expect("canonical operation");
    output.truncate(written);
    output
}

fn exercise_stream(data: &[u8]) {
    let split = data.len().min(16);
    let controls = &data[..split];
    let candidate = data.get(split..).unwrap_or_default();
    let first = drive_stream(candidate, controls, None);
    let second = drive_stream(candidate, controls, None);
    assert_eq!(first, second);

    let one = canonical_operation(candidate, 1);
    let mut coalesced = one.clone();
    coalesced.extend_from_slice(&canonical_operation(b"second", 2));
    let summary = drive_stream(&coalesced, controls, None);
    assert_eq!(summary.frames.len(), 2);
    assert_eq!(summary.consumed, coalesced.len());
    assert_eq!(summary.terminal, IpcError::PeerLost);

    let ancillary = drive_stream(&one, controls, Some(0));
    assert!(ancillary.frames.is_empty());
    assert_eq!(ancillary.consumed, 0);
    assert_eq!(ancillary.terminal, IpcError::AncillaryData);
}

fn exercise_oversized_header() {
    let mut header = [0u8; HEADER_BYTES];
    header[..4].copy_from_slice(b"QKIP");
    header[4] = 1;
    header[5] = 1;
    header[6..8].copy_from_slice(&MessageKind::OperationRequest.wire_value().to_le_bytes());
    header[24..28].copy_from_slice(&1u32.to_le_bytes());
    header[28..32].copy_from_slice(&((MAX_PAYLOAD_BYTES as u32) + 1).to_le_bytes());
    assert_eq!(parse_frame(&header), Err(IpcError::PayloadLengthExceeded));
    let mut decoder = StreamDecoder::new();
    assert_eq!(
        decoder.ingest(&header, false),
        Err(IpcError::PayloadLengthExceeded)
    );
    assert_eq!(decoder.ingest(&[], false), Err(IpcError::DecoderTerminated));
}

fn exercise_cleanup(data: &[u8]) {
    let payload = if data.is_empty() { &[0u8][..] } else { data };
    let encoded = canonical_operation(payload, 1);
    reset_wiped_bytes();
    {
        let mut decoder = StreamDecoder::new();
        let outcome = decoder
            .ingest(&encoded, false)
            .expect("canonical cleanup frame");
        assert!(outcome.frame_ready());
        let frame = decoder.take_frame().expect("cleanup frame");
        assert_eq!(frame.payload(), payload);
    }
    assert!(wiped_bytes() >= HEADER_BYTES + 16 + payload.len());

    reset_wiped_bytes();
    {
        let mut decoder = StreamDecoder::new();
        let outcome = decoder
            .ingest(&encoded[..HEADER_BYTES], false)
            .expect("cleanup header");
        assert!(!outcome.frame_ready());
        assert_eq!(decoder.ingest(&[], true), Err(IpcError::AncillaryData));
    }
    assert!(wiped_bytes() >= HEADER_BYTES + 16 + payload.len());
}

fuzz_target!(|data: &[u8]| {
    if data.len() > MAX_PRESENTED_BYTES {
        return;
    }
    exercise_raw(data);
    exercise_structured(data);
    exercise_stream(data);
    exercise_oversized_header();
    exercise_cleanup(data);
});
