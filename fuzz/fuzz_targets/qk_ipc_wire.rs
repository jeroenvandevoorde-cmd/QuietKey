#![no_main]

use libfuzzer_sys::fuzz_target;
use qk_ipc::{
    encode_frame, parse_frame, reset_wiped_bytes, wiped_bytes, Direction, IpcError, MessageKind,
    StreamDecoder, HEADER_BYTES, MAX_PAYLOAD_BYTES,
};

const MAX_PRESENTED_BYTES: usize = 4_096;
const REF_HEADER_BYTES: usize = 32;
const REF_MAX_PAYLOAD_BYTES: usize = 2_097_152;
const REF_MAX_FRAME_BYTES: usize = REF_HEADER_BYTES + REF_MAX_PAYLOAD_BYTES;
const SENTINEL: u8 = 0xa5;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum RefDirection {
    CoreToIo,
    IoToCore,
}

impl RefDirection {
    const fn wire_value(self) -> u8 {
        match self {
            Self::CoreToIo => 0x01,
            Self::IoToCore => 0x02,
        }
    }

    const fn opposite(self) -> Self {
        match self {
            Self::CoreToIo => Self::IoToCore,
            Self::IoToCore => Self::CoreToIo,
        }
    }

    const fn production(self) -> Direction {
        match self {
            Self::CoreToIo => Direction::CoreToIo,
            Self::IoToCore => Direction::IoToCore,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum RefKind {
    SessionOpen,
    OperationRequest,
    SessionClose,
    SessionReady,
    OperationResponse,
    SessionClosed,
}

impl RefKind {
    const fn wire_value(self) -> u16 {
        match self {
            Self::SessionOpen => 0x0001,
            Self::OperationRequest => 0x0002,
            Self::SessionClose => 0x0003,
            Self::SessionReady => 0x0101,
            Self::OperationResponse => 0x0102,
            Self::SessionClosed => 0x0103,
        }
    }

    const fn direction(self) -> RefDirection {
        match self {
            Self::SessionOpen | Self::OperationRequest | Self::SessionClose => {
                RefDirection::CoreToIo
            }
            Self::SessionReady | Self::OperationResponse | Self::SessionClosed => {
                RefDirection::IoToCore
            }
        }
    }

    const fn requires_payload(self) -> bool {
        matches!(self, Self::OperationRequest | Self::OperationResponse)
    }

    const fn production(self) -> MessageKind {
        match self {
            Self::SessionOpen => MessageKind::SessionOpen,
            Self::OperationRequest => MessageKind::OperationRequest,
            Self::SessionClose => MessageKind::SessionClose,
            Self::SessionReady => MessageKind::SessionReady,
            Self::OperationResponse => MessageKind::OperationResponse,
            Self::SessionClosed => MessageKind::SessionClosed,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct RefHeader {
    direction: RefDirection,
    kind: RefKind,
    session_id: [u8; 16],
    exchange_id: u32,
    payload_len: usize,
}

#[derive(Debug, Eq, PartialEq)]
struct RefFrame<'a> {
    header: RefHeader,
    payload: &'a [u8],
}

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

fn reference_direction(value: u8) -> Result<RefDirection, IpcError> {
    match value {
        0x01 => Ok(RefDirection::CoreToIo),
        0x02 => Ok(RefDirection::IoToCore),
        _ => Err(IpcError::DirectionOutOfRange),
    }
}

fn reference_kind(value: u16) -> Result<RefKind, IpcError> {
    match value {
        0x0001 => Ok(RefKind::SessionOpen),
        0x0002 => Ok(RefKind::OperationRequest),
        0x0003 => Ok(RefKind::SessionClose),
        0x0101 => Ok(RefKind::SessionReady),
        0x0102 => Ok(RefKind::OperationResponse),
        0x0103 => Ok(RefKind::SessionClosed),
        _ => Err(IpcError::KindOutOfRange),
    }
}

fn reference_payload_shape(kind: RefKind, payload_len: usize) -> Result<(), IpcError> {
    if kind.requires_payload() {
        if payload_len == 0 {
            return Err(IpcError::OperationPayloadEmpty);
        }
    } else if payload_len != 0 {
        return Err(IpcError::ControlPayloadNotEmpty);
    }
    Ok(())
}

fn reference_header(bytes: &[u8; REF_HEADER_BYTES]) -> Result<RefHeader, IpcError> {
    if bytes[0..4] != *b"QKIP" {
        return Err(IpcError::MagicMismatch);
    }
    if bytes[4] != 0x01 {
        return Err(IpcError::VersionMismatch);
    }
    let direction = reference_direction(bytes[5])?;
    let kind = reference_kind(u16::from_le_bytes([bytes[6], bytes[7]]))?;
    if kind.direction() != direction {
        return Err(IpcError::DirectionKindMismatch);
    }
    let exchange_id = u32::from_le_bytes([bytes[24], bytes[25], bytes[26], bytes[27]]);
    if exchange_id == 0 {
        return Err(IpcError::ExchangeIdZero);
    }
    let payload_len = u32::from_le_bytes([bytes[28], bytes[29], bytes[30], bytes[31]]) as usize;
    if payload_len > REF_MAX_PAYLOAD_BYTES {
        return Err(IpcError::PayloadLengthExceeded);
    }

    let mut session_id = [0u8; 16];
    session_id.copy_from_slice(&bytes[8..24]);
    Ok(RefHeader {
        direction,
        kind,
        session_id,
        exchange_id,
        payload_len,
    })
}

fn reference_parse(bytes: &[u8]) -> Result<RefFrame<'_>, IpcError> {
    let header: &[u8; REF_HEADER_BYTES] = bytes
        .get(..REF_HEADER_BYTES)
        .ok_or(IpcError::HeaderTruncated)?
        .try_into()
        .map_err(|_| IpcError::HeaderTruncated)?;
    let header = reference_header(header)?;
    let frame_len = REF_HEADER_BYTES
        .checked_add(header.payload_len)
        .ok_or(IpcError::PayloadLengthExceeded)?;
    if bytes.len() < frame_len {
        return Err(IpcError::PayloadTruncated);
    }
    if bytes.len() > frame_len {
        return Err(IpcError::TrailingByte);
    }
    reference_payload_shape(header.kind, header.payload_len)?;
    Ok(RefFrame {
        header,
        payload: &bytes[REF_HEADER_BYTES..frame_len],
    })
}

fn reference_encode(
    direction: RefDirection,
    kind: RefKind,
    session_id: [u8; 16],
    exchange_id: u32,
    payload: &[u8],
    output: &mut [u8],
) -> Result<usize, IpcError> {
    if kind.direction() != direction {
        return Err(IpcError::DirectionKindMismatch);
    }
    if exchange_id == 0 {
        return Err(IpcError::ExchangeIdZero);
    }
    if payload.len() > REF_MAX_PAYLOAD_BYTES {
        return Err(IpcError::PayloadLengthExceeded);
    }
    reference_payload_shape(kind, payload.len())?;
    let frame_len = REF_HEADER_BYTES
        .checked_add(payload.len())
        .ok_or(IpcError::PayloadLengthExceeded)?;
    if frame_len > REF_MAX_FRAME_BYTES || output.len() < frame_len {
        return Err(IpcError::OutputBufferTooSmall);
    }

    output[0..4].copy_from_slice(b"QKIP");
    output[4] = 0x01;
    output[5] = direction.wire_value();
    output[6..8].copy_from_slice(&kind.wire_value().to_le_bytes());
    output[8..24].copy_from_slice(&session_id);
    output[24..28].copy_from_slice(&exchange_id.to_le_bytes());
    output[28..32].copy_from_slice(
        &u32::try_from(payload.len())
            .expect("reference payload cap fits u32")
            .to_le_bytes(),
    );
    output[REF_HEADER_BYTES..frame_len].copy_from_slice(payload);
    Ok(frame_len)
}

fn selected_kind(selector: u8) -> RefKind {
    match selector % 6 {
        0 => RefKind::SessionOpen,
        1 => RefKind::OperationRequest,
        2 => RefKind::SessionClose,
        3 => RefKind::SessionReady,
        4 => RefKind::OperationResponse,
        _ => RefKind::SessionClosed,
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
    let expected = reference_parse(bytes);
    let first = parse_frame(bytes);
    let second = parse_frame(bytes);
    assert_eq!(first, second);
    match (expected, first) {
        (Err(expected_error), Err(actual_error)) => {
            assert_eq!(actual_error, expected_error);
            assert_named(actual_error);
        }
        (Ok(expected_frame), Ok(actual_frame)) => {
            assert_eq!(
                actual_frame.header().direction().wire_value(),
                expected_frame.header.direction.wire_value()
            );
            assert_eq!(
                actual_frame.header().kind().wire_value(),
                expected_frame.header.kind.wire_value()
            );
            assert_eq!(
                actual_frame.header().session_id(),
                &expected_frame.header.session_id
            );
            assert_eq!(
                actual_frame.header().exchange_id(),
                expected_frame.header.exchange_id
            );
            assert_eq!(
                actual_frame.header().payload_len() as usize,
                expected_frame.payload.len()
            );
            assert_eq!(actual_frame.payload(), expected_frame.payload);

            let mut encoded = vec![SENTINEL; bytes.len() + 1];
            let written = encode_frame(
                actual_frame.header().direction(),
                actual_frame.header().kind(),
                *actual_frame.header().session_id(),
                actual_frame.header().exchange_id(),
                actual_frame.payload(),
                &mut encoded,
            )
            .expect("accepted production frame must re-encode");
            assert_eq!(written, bytes.len());
            assert_eq!(&encoded[..written], bytes);
            assert_eq!(encoded[written], SENTINEL);
        }
        (expected, actual) => panic!("reference parser disagreement: {expected:?} != {actual:?}"),
    }
}

fn exercise_structured(data: &[u8]) {
    let kind = selected_kind(data.first().copied().unwrap_or(0));
    let direction = if data.get(1).copied().unwrap_or(0) & 1 == 0 {
        kind.direction()
    } else {
        kind.direction().opposite()
    };
    let exchange_id = u32::from_le_bytes([
        data.get(2).copied().unwrap_or(0),
        data.get(3).copied().unwrap_or(0),
        data.get(4).copied().unwrap_or(0),
        data.get(5).copied().unwrap_or(0),
    ]);
    let session_id = session(data.get(6..22).unwrap_or_default());
    let output_selector = data.get(22).copied().unwrap_or(0);
    let payload = data.get(23..).unwrap_or_default();
    let frame_len = REF_HEADER_BYTES + payload.len();
    let output_len = match output_selector & 3 {
        0 => frame_len + 1,
        1 => frame_len,
        2 => frame_len.saturating_sub(1),
        _ => usize::from(output_selector >> 2) % (frame_len + 2),
    };

    let mut expected_output = vec![SENTINEL; output_len];
    let expected = reference_encode(
        direction,
        kind,
        session_id,
        exchange_id,
        payload,
        &mut expected_output,
    );
    let initial_output = vec![SENTINEL; output_len];
    let mut actual_output = initial_output.clone();
    let actual = encode_frame(
        direction.production(),
        kind.production(),
        session_id,
        exchange_id,
        payload,
        &mut actual_output,
    );
    let mut repeated_output = initial_output;
    let repeated = encode_frame(
        direction.production(),
        kind.production(),
        session_id,
        exchange_id,
        payload,
        &mut repeated_output,
    );
    assert_eq!(actual, expected);
    assert_eq!(repeated, expected);
    assert_eq!(actual_output, expected_output);
    assert_eq!(repeated_output, expected_output);
    if let Err(error) = actual {
        assert_named(error);
    } else {
        let written = actual.expect("checked successful encode");
        let parsed = parse_frame(&actual_output[..written])
            .expect("successful production encode must production-parse");
        assert_eq!(parsed.header().direction(), direction.production());
        assert_eq!(parsed.header().kind(), kind.production());
        assert_eq!(parsed.header().session_id(), &session_id);
        assert_eq!(parsed.header().exchange_id(), exchange_id);
        assert_eq!(parsed.header().payload_len() as usize, payload.len());
        assert_eq!(parsed.payload(), payload);
    }
}

#[derive(Debug, Eq, PartialEq)]
struct ActualOwnedFrame {
    direction: Direction,
    kind: MessageKind,
    session_id: [u8; 16],
    exchange_id: u32,
    payload: Vec<u8>,
}

#[derive(Debug, Eq, PartialEq)]
enum StreamIngestResult {
    Accepted { consumed: usize, frame_ready: bool },
    Rejected(IpcError),
}

#[derive(Debug, Eq, PartialEq)]
struct StreamStep {
    presented: usize,
    result: StreamIngestResult,
}

#[derive(Debug, Eq, PartialEq)]
struct StreamSummary {
    frames: Vec<ActualOwnedFrame>,
    steps: Vec<StreamStep>,
    consumed: usize,
    terminal: IpcError,
}

#[derive(Debug, Eq, PartialEq)]
struct RefOwnedFrame {
    header: RefHeader,
    payload: Vec<u8>,
}

#[derive(Debug, Eq, PartialEq)]
struct RefStreamSummary {
    frames: Vec<RefOwnedFrame>,
    steps: Vec<StreamStep>,
    consumed: usize,
    terminal: IpcError,
}

fn drive_reference_stream(
    bytes: &[u8],
    controls: &[u8],
    ancillary_at: Option<usize>,
) -> RefStreamSummary {
    let mut frames = Vec::new();
    let mut steps = Vec::new();
    let mut offset = 0usize;
    let mut step = 0usize;
    let mut header_bytes = [0u8; REF_HEADER_BYTES];
    let mut header_len = 0usize;
    let mut parsed_header: Option<RefHeader> = None;
    let mut payload = Vec::new();

    let terminal = loop {
        if offset == bytes.len() {
            if header_len != 0 || parsed_header.is_some() {
                break IpcError::ConnectionClosedMidFrame;
            }
            break IpcError::PeerLost;
        }

        let remaining_input = bytes.len() - offset;
        let width = 1 + usize::from(controls.get(step).copied().unwrap_or(0)) % remaining_input;
        if ancillary_at == Some(step) {
            steps.push(StreamStep {
                presented: width,
                result: StreamIngestResult::Rejected(IpcError::AncillaryData),
            });
            break IpcError::AncillaryData;
        }
        let chunk = &bytes[offset..offset + width];
        let mut consumed = 0usize;

        if parsed_header.is_none() {
            let required = REF_HEADER_BYTES - header_len;
            let copied = required.min(chunk.len());
            header_bytes[header_len..header_len + copied].copy_from_slice(&chunk[..copied]);
            header_len += copied;
            consumed += copied;
            if header_len < REF_HEADER_BYTES {
                steps.push(StreamStep {
                    presented: width,
                    result: StreamIngestResult::Accepted {
                        consumed,
                        frame_ready: false,
                    },
                });
                offset += consumed;
                step += 1;
                continue;
            }

            let header = match reference_header(&header_bytes) {
                Ok(header) => header,
                Err(error) => {
                    steps.push(StreamStep {
                        presented: width,
                        result: StreamIngestResult::Rejected(error),
                    });
                    break error;
                }
            };
            parsed_header = Some(header);
            header_len = 0;
            if header.payload_len == 0 {
                if let Err(error) = reference_payload_shape(header.kind, 0) {
                    steps.push(StreamStep {
                        presented: width,
                        result: StreamIngestResult::Rejected(error),
                    });
                    break error;
                }
                frames.push(RefOwnedFrame {
                    header,
                    payload: Vec::new(),
                });
                parsed_header = None;
                steps.push(StreamStep {
                    presented: width,
                    result: StreamIngestResult::Accepted {
                        consumed,
                        frame_ready: true,
                    },
                });
                offset += consumed;
                step += 1;
                continue;
            }
        }

        let header = parsed_header.expect("reference stream has parsed header");
        let remaining_payload = header
            .payload_len
            .checked_sub(payload.len())
            .expect("reference payload length invariant");
        let available = chunk.len() - consumed;
        let copied = remaining_payload.min(available);
        payload.extend_from_slice(&chunk[consumed..consumed + copied]);
        consumed += copied;
        if payload.len() == header.payload_len {
            if let Err(error) = reference_payload_shape(header.kind, payload.len()) {
                steps.push(StreamStep {
                    presented: width,
                    result: StreamIngestResult::Rejected(error),
                });
                break error;
            }
            frames.push(RefOwnedFrame {
                header,
                payload: core::mem::take(&mut payload),
            });
            parsed_header = None;
        }
        steps.push(StreamStep {
            presented: width,
            result: StreamIngestResult::Accepted {
                consumed,
                frame_ready: parsed_header.is_none(),
            },
        });
        offset += consumed;
        step += 1;
    };

    RefStreamSummary {
        frames,
        steps,
        consumed: offset,
        terminal,
    }
}

fn assert_stream_matches(expected: &RefStreamSummary, actual: &StreamSummary) {
    assert_eq!(actual.steps, expected.steps);
    assert_eq!(actual.consumed, expected.consumed);
    assert_eq!(actual.terminal, expected.terminal);
    assert_eq!(actual.frames.len(), expected.frames.len());
    for (actual_frame, expected_frame) in actual.frames.iter().zip(&expected.frames) {
        assert_eq!(
            actual_frame.direction.wire_value(),
            expected_frame.header.direction.wire_value()
        );
        assert_eq!(
            actual_frame.kind.wire_value(),
            expected_frame.header.kind.wire_value()
        );
        assert_eq!(actual_frame.session_id, expected_frame.header.session_id);
        assert_eq!(actual_frame.exchange_id, expected_frame.header.exchange_id);
        assert_eq!(actual_frame.payload, expected_frame.payload);
    }
}

fn drive_stream(bytes: &[u8], controls: &[u8], ancillary_at: Option<usize>) -> StreamSummary {
    let mut decoder = StreamDecoder::new();
    let mut frames = Vec::new();
    let mut steps = Vec::new();
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
            Err(error) => {
                steps.push(StreamStep {
                    presented: width,
                    result: StreamIngestResult::Rejected(error),
                });
                break error;
            }
            Ok(outcome) => {
                assert!(outcome.consumed() <= width);
                steps.push(StreamStep {
                    presented: width,
                    result: StreamIngestResult::Accepted {
                        consumed: outcome.consumed(),
                        frame_ready: outcome.frame_ready(),
                    },
                });
                offset += outcome.consumed();
                if outcome.frame_ready() {
                    let frame = decoder.take_frame().expect("ready frame must be takeable");
                    frames.push(ActualOwnedFrame {
                        direction: frame.header().direction(),
                        kind: frame.header().kind(),
                        session_id: *frame.header().session_id(),
                        exchange_id: frame.header().exchange_id(),
                        payload: frame.payload().to_vec(),
                    });
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
        steps,
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
    let mut output = vec![0u8; REF_HEADER_BYTES + payload.len()];
    let written = reference_encode(
        RefDirection::CoreToIo,
        RefKind::OperationRequest,
        [0x42; 16],
        exchange_id,
        payload,
        &mut output,
    )
    .expect("reference canonical operation");
    output.truncate(written);
    output
}

fn exercise_stream(data: &[u8]) {
    let split = data.len().min(16);
    let controls = &data[..split];
    let candidate = data.get(split..).unwrap_or_default();
    let expected = drive_reference_stream(candidate, controls, None);
    let first = drive_stream(candidate, controls, None);
    let second = drive_stream(candidate, controls, None);
    assert_stream_matches(&expected, &first);
    assert_eq!(first, second);

    let one = canonical_operation(candidate, 1);
    let mut coalesced = one.clone();
    coalesced.extend_from_slice(&canonical_operation(b"second", 2));
    let expected = drive_reference_stream(&coalesced, controls, None);
    let summary = drive_stream(&coalesced, controls, None);
    assert_stream_matches(&expected, &summary);
    assert_eq!(summary.frames.len(), 2);
    assert_eq!(summary.consumed, coalesced.len());
    assert_eq!(summary.terminal, IpcError::PeerLost);
    assert_eq!(summary.frames[0].direction, Direction::CoreToIo);
    assert_eq!(summary.frames[0].kind, MessageKind::OperationRequest);
    assert_eq!(summary.frames[0].session_id, [0x42; 16]);
    assert_eq!(summary.frames[0].exchange_id, 1);
    assert_eq!(summary.frames[0].payload, one[REF_HEADER_BYTES..]);
    assert_eq!(summary.frames[1].direction, Direction::CoreToIo);
    assert_eq!(summary.frames[1].kind, MessageKind::OperationRequest);
    assert_eq!(summary.frames[1].session_id, [0x42; 16]);
    assert_eq!(summary.frames[1].exchange_id, 2);
    assert_eq!(summary.frames[1].payload, b"second");

    let expected = drive_reference_stream(&one, controls, Some(0));
    let ancillary = drive_stream(&one, controls, Some(0));
    assert_stream_matches(&expected, &ancillary);
    assert!(ancillary.frames.is_empty());
    assert_eq!(ancillary.consumed, 0);
    assert_eq!(ancillary.terminal, IpcError::AncillaryData);
}

fn exercise_oversized_header() {
    assert_eq!(HEADER_BYTES, REF_HEADER_BYTES);
    assert_eq!(MAX_PAYLOAD_BYTES, REF_MAX_PAYLOAD_BYTES);
    let mut header = [0u8; REF_HEADER_BYTES];
    header[..4].copy_from_slice(b"QKIP");
    header[4] = 1;
    header[5] = 1;
    header[6..8].copy_from_slice(&0x0002u16.to_le_bytes());
    header[24..28].copy_from_slice(&1u32.to_le_bytes());
    header[28..32].copy_from_slice(&((REF_MAX_PAYLOAD_BYTES as u32) + 1).to_le_bytes());
    assert_eq!(
        reference_parse(&header),
        Err(IpcError::PayloadLengthExceeded)
    );
    assert_eq!(parse_frame(&header), Err(IpcError::PayloadLengthExceeded));
    let mut decoder = StreamDecoder::new();
    assert_eq!(
        decoder.ingest(&header, false),
        Err(IpcError::PayloadLengthExceeded)
    );
    assert_eq!(decoder.ingest(&[], false), Err(IpcError::DecoderTerminated));
}

fn exercise_premature_take() {
    let payload = [0x6du8; 37];
    let encoded = canonical_operation(&payload, 1);
    reset_wiped_bytes();
    {
        let mut decoder = StreamDecoder::new();
        let outcome = decoder
            .ingest(&encoded[..REF_HEADER_BYTES + 5], false)
            .expect("fixed partial payload");
        assert_eq!(outcome.consumed(), REF_HEADER_BYTES + 5);
        assert!(!outcome.frame_ready());
        assert_eq!(
            decoder.take_frame().err(),
            Some(IpcError::InvalidTransition)
        );
        assert_eq!(decoder.ingest(&[], false), Err(IpcError::DecoderTerminated));
        assert_eq!(
            decoder.take_frame().err(),
            Some(IpcError::DecoderTerminated)
        );
        assert_eq!(decoder.finish(), IpcError::DecoderTerminated);
    }
    assert!(wiped_bytes() >= REF_HEADER_BYTES + 16 + payload.len());
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
    assert!(wiped_bytes() >= REF_HEADER_BYTES + 16 + payload.len());

    reset_wiped_bytes();
    {
        let mut decoder = StreamDecoder::new();
        let outcome = decoder
            .ingest(&encoded[..REF_HEADER_BYTES], false)
            .expect("cleanup header");
        assert!(!outcome.frame_ready());
        assert_eq!(decoder.ingest(&[], true), Err(IpcError::AncillaryData));
    }
    assert!(wiped_bytes() >= REF_HEADER_BYTES + 16 + payload.len());
}

fuzz_target!(|data: &[u8]| {
    if data.len() > MAX_PRESENTED_BYTES {
        return;
    }
    exercise_raw(data);
    exercise_structured(data);
    exercise_stream(data);
    exercise_oversized_header();
    exercise_premature_take();
    exercise_cleanup(data);
});
