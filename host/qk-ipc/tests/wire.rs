//! Exact QKIP wire constants, round trips, and rejection precedence.

use qk_ipc::{
    encode_frame, parse_frame, Direction, IpcError, MessageKind, HEADER_BYTES, MAGIC,
    MAX_FRAME_BYTES, MAX_PAYLOAD_BYTES, VERSION,
};

const SESSION: [u8; 16] = [0x42; 16];

fn raw_header(direction: u8, kind: u16, exchange: u32, payload_len: u32) -> [u8; 32] {
    let mut header = [0u8; 32];
    header[0..4].copy_from_slice(b"QKIP");
    header[4] = 1;
    header[5] = direction;
    header[6..8].copy_from_slice(&kind.to_le_bytes());
    header[8..24].copy_from_slice(&SESSION);
    header[24..28].copy_from_slice(&exchange.to_le_bytes());
    header[28..32].copy_from_slice(&payload_len.to_le_bytes());
    header
}

#[test]
fn constants_and_offsets_are_exact() {
    assert_eq!(MAGIC, [0x51, 0x4b, 0x49, 0x50]);
    assert_eq!(VERSION, 0x01);
    assert_eq!(HEADER_BYTES, 32);
    assert_eq!(MAX_PAYLOAD_BYTES, 2_097_152);
    assert_eq!(MAX_FRAME_BYTES, 2_097_184);

    assert_eq!(Direction::CoreToIo.wire_value(), 0x01);
    assert_eq!(Direction::IoToCore.wire_value(), 0x02);
    assert_eq!(MessageKind::SessionOpen.wire_value(), 0x0001);
    assert_eq!(MessageKind::OperationRequest.wire_value(), 0x0002);
    assert_eq!(MessageKind::SessionClose.wire_value(), 0x0003);
    assert_eq!(MessageKind::SessionReady.wire_value(), 0x0101);
    assert_eq!(MessageKind::OperationResponse.wire_value(), 0x0102);
    assert_eq!(MessageKind::SessionClosed.wire_value(), 0x0103);
}

#[test]
fn all_six_kinds_round_trip_with_exact_little_endian_bytes() {
    let cases = [
        (Direction::CoreToIo, MessageKind::SessionOpen, &[][..]),
        (
            Direction::CoreToIo,
            MessageKind::OperationRequest,
            &[0x11][..],
        ),
        (Direction::CoreToIo, MessageKind::SessionClose, &[][..]),
        (Direction::IoToCore, MessageKind::SessionReady, &[][..]),
        (
            Direction::IoToCore,
            MessageKind::OperationResponse,
            &[0x22, 0x33][..],
        ),
        (Direction::IoToCore, MessageKind::SessionClosed, &[][..]),
    ];

    for (index, (direction, kind, payload)) in cases.into_iter().enumerate() {
        let exchange = u32::try_from(index + 1).expect("small exchange");
        let mut output = [0xa5; 96];
        let length = encode_frame(direction, kind, SESSION, exchange, payload, &mut output)
            .expect("canonical frame");
        assert_eq!(length, HEADER_BYTES + payload.len());
        assert_eq!(&output[0..4], b"QKIP");
        assert_eq!(output[4], 1);
        assert_eq!(output[5], direction.wire_value());
        assert_eq!(&output[6..8], &kind.wire_value().to_le_bytes());
        assert_eq!(&output[8..24], &SESSION);
        assert_eq!(&output[24..28], &exchange.to_le_bytes());
        assert_eq!(
            &output[28..32],
            &u32::try_from(payload.len())
                .expect("small payload")
                .to_le_bytes()
        );
        assert_eq!(&output[32..length], payload);
        assert!(output[length..].iter().all(|byte| *byte == 0xa5));

        let parsed = parse_frame(&output[..length]).expect("round trip");
        assert_eq!(parsed.header().direction(), direction);
        assert_eq!(parsed.header().kind(), kind);
        assert_eq!(parsed.header().session_id(), &SESSION);
        assert_eq!(parsed.header().exchange_id(), exchange);
        assert_eq!(parsed.header().payload_len() as usize, payload.len());
        assert_eq!(parsed.payload(), payload);
    }
}

#[test]
fn all_zero_session_identity_is_opaque_and_accepted() {
    let mut output = [0u8; 32];
    let length = encode_frame(
        Direction::CoreToIo,
        MessageKind::SessionOpen,
        [0; 16],
        1,
        &[],
        &mut output,
    )
    .expect("session identity has no slice-one entropy rule");
    let parsed = parse_frame(&output[..length]).expect("opaque identity");
    assert_eq!(parsed.header().session_id(), &[0; 16]);
}

#[test]
fn parser_rejection_precedence_is_fixed() {
    assert_eq!(parse_frame(&[0; 31]), Err(IpcError::HeaderTruncated));

    let mut bytes = raw_header(1, 0x0001, 1, 0).to_vec();
    bytes[0] ^= 1;
    bytes[4] = 2;
    bytes[5] = 9;
    assert_eq!(parse_frame(&bytes), Err(IpcError::MagicMismatch));

    let mut bytes = raw_header(1, 0x0001, 1, 0).to_vec();
    bytes[4] = 2;
    bytes[5] = 9;
    assert_eq!(parse_frame(&bytes), Err(IpcError::VersionMismatch));

    let bytes = raw_header(9, 0xffff, 0, u32::MAX);
    assert_eq!(parse_frame(&bytes), Err(IpcError::DirectionOutOfRange));

    let bytes = raw_header(1, 0xffff, 0, u32::MAX);
    assert_eq!(parse_frame(&bytes), Err(IpcError::KindOutOfRange));

    let bytes = raw_header(2, 0x0001, 0, u32::MAX);
    assert_eq!(parse_frame(&bytes), Err(IpcError::DirectionKindMismatch));

    let bytes = raw_header(1, 0x0001, 0, u32::MAX);
    assert_eq!(parse_frame(&bytes), Err(IpcError::ExchangeIdZero));

    let bytes = raw_header(1, 0x0001, 1, 2_097_153);
    assert_eq!(parse_frame(&bytes), Err(IpcError::PayloadLengthExceeded));

    let bytes = raw_header(1, 0x0002, 1, 1);
    assert_eq!(parse_frame(&bytes), Err(IpcError::PayloadTruncated));

    let mut bytes = raw_header(1, 0x0001, 1, 0).to_vec();
    bytes.push(0);
    assert_eq!(parse_frame(&bytes), Err(IpcError::TrailingByte));

    let mut bytes = raw_header(1, 0x0001, 1, 1).to_vec();
    bytes.push(0);
    assert_eq!(parse_frame(&bytes), Err(IpcError::ControlPayloadNotEmpty));

    let bytes = raw_header(1, 0x0002, 1, 0);
    assert_eq!(parse_frame(&bytes), Err(IpcError::OperationPayloadEmpty));
}

#[test]
fn encoder_rejections_leave_the_complete_output_unchanged() {
    type RejectionCase<'a> = (Direction, MessageKind, u32, &'a [u8], usize, IpcError);
    let oversized = vec![0x55; MAX_PAYLOAD_BYTES + 1];
    let cases: [RejectionCase<'_>; 6] = [
        (
            Direction::IoToCore,
            MessageKind::SessionOpen,
            1,
            &[],
            64,
            IpcError::DirectionKindMismatch,
        ),
        (
            Direction::CoreToIo,
            MessageKind::SessionOpen,
            0,
            &[],
            64,
            IpcError::ExchangeIdZero,
        ),
        (
            Direction::CoreToIo,
            MessageKind::OperationRequest,
            1,
            &oversized,
            64,
            IpcError::PayloadLengthExceeded,
        ),
        (
            Direction::CoreToIo,
            MessageKind::SessionOpen,
            1,
            &[1],
            64,
            IpcError::ControlPayloadNotEmpty,
        ),
        (
            Direction::CoreToIo,
            MessageKind::OperationRequest,
            1,
            &[],
            64,
            IpcError::OperationPayloadEmpty,
        ),
        (
            Direction::CoreToIo,
            MessageKind::SessionOpen,
            1,
            &[],
            31,
            IpcError::OutputBufferTooSmall,
        ),
    ];

    for (direction, kind, exchange, payload, output_len, expected) in cases {
        let mut output = vec![0xa5; output_len];
        let before = output.clone();
        assert_eq!(
            encode_frame(direction, kind, SESSION, exchange, payload, &mut output),
            Err(expected)
        );
        assert_eq!(output, before);
    }
}

#[test]
fn exact_payload_ceiling_round_trips() {
    let payload = vec![0x5a; MAX_PAYLOAD_BYTES];
    let mut output = vec![0xa5; MAX_FRAME_BYTES];
    let length = encode_frame(
        Direction::CoreToIo,
        MessageKind::OperationRequest,
        SESSION,
        7,
        &payload,
        &mut output,
    )
    .expect("ceiling frame");
    assert_eq!(length, MAX_FRAME_BYTES);
    let parsed = parse_frame(&output).expect("ceiling parse");
    assert_eq!(parsed.payload(), payload);
}

#[test]
fn every_error_has_only_its_fixed_registered_name() {
    let errors = [
        IpcError::DecoderTerminated,
        IpcError::SessionTerminated,
        IpcError::AncillaryData,
        IpcError::HeaderTruncated,
        IpcError::MagicMismatch,
        IpcError::VersionMismatch,
        IpcError::DirectionOutOfRange,
        IpcError::KindOutOfRange,
        IpcError::DirectionKindMismatch,
        IpcError::ExchangeIdZero,
        IpcError::PayloadLengthExceeded,
        IpcError::PayloadTruncated,
        IpcError::TrailingByte,
        IpcError::ControlPayloadNotEmpty,
        IpcError::OperationPayloadEmpty,
        IpcError::OutputBufferTooSmall,
        IpcError::PayloadAllocationFailed,
        IpcError::UnexpectedDirection,
        IpcError::SessionIdMismatch,
        IpcError::UnexpectedMessageKind,
        IpcError::ExchangeIdReuse,
        IpcError::ExchangeIdRegression,
        IpcError::ExchangeIdSkipped,
        IpcError::ExchangeIdExhausted,
        IpcError::ResponseIdMismatch,
        IpcError::OutstandingExchange,
        IpcError::NoOutstandingExchange,
        IpcError::SessionNotReady,
        IpcError::SessionClosed,
        IpcError::InvalidTransition,
        IpcError::PeerLost,
        IpcError::ConnectionClosedMidFrame,
    ];
    for error in errors {
        let name = format!("{error:?}");
        assert_eq!(error.to_string(), name);
        assert!(name.bytes().all(|byte| byte.is_ascii_alphanumeric()));
    }
}
