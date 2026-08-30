//! Fragmentation, coalescing, EOF, and terminal-state behavior.

use qk_ipc::{
    encode_frame, IpcError, MessageKind, StreamDecoder, HEADER_BYTES, MAX_FRAME_BYTES,
    MAX_PAYLOAD_BYTES,
};

const SESSION: [u8; 16] = [0x24; 16];

fn frame(kind: MessageKind, exchange: u32, payload: &[u8]) -> Vec<u8> {
    let mut output = vec![0u8; HEADER_BYTES + payload.len()];
    let length = encode_frame(
        kind.direction(),
        kind,
        SESSION,
        exchange,
        payload,
        &mut output,
    )
    .expect("canonical frame");
    output.truncate(length);
    output
}

#[test]
fn every_two_chunk_split_decodes_identically() {
    let encoded = frame(MessageKind::OperationRequest, 7, &[0x3c; 257]);
    for split in 0..=encoded.len() {
        let mut decoder = StreamDecoder::new();
        let first = decoder
            .ingest(&encoded[..split], false)
            .expect("first chunk");
        assert_eq!(first.consumed(), split);
        if first.frame_ready() {
            assert_eq!(split, encoded.len());
        } else {
            let second = decoder
                .ingest(&encoded[split..], false)
                .expect("second chunk");
            assert_eq!(second.consumed(), encoded.len() - split);
            assert!(second.frame_ready());
        }
        let received = decoder.take_frame().expect("complete frame");
        assert_eq!(received.header().kind(), MessageKind::OperationRequest);
        assert_eq!(received.header().exchange_id(), 7);
        assert_eq!(received.payload(), &[0x3c; 257]);
    }
}

#[test]
fn one_byte_fragmentation_decodes_without_chunk_semantics() {
    let encoded = frame(MessageKind::OperationResponse, 11, &[0x55; 97]);
    let mut decoder = StreamDecoder::new();
    for (index, byte) in encoded.iter().enumerate() {
        let outcome = decoder
            .ingest(core::slice::from_ref(byte), false)
            .expect("one byte");
        assert_eq!(outcome.consumed(), 1);
        assert_eq!(outcome.frame_ready(), index + 1 == encoded.len());
    }
    let received = decoder.take_frame().expect("complete frame");
    assert_eq!(received.payload(), &[0x55; 97]);
}

#[test]
fn coalesced_delivery_exposes_one_frame_and_exact_consumed_prefix() {
    let first = frame(MessageKind::SessionOpen, 1, &[]);
    let second = frame(MessageKind::OperationRequest, 2, &[0x77; 3]);
    let mut coalesced = first.clone();
    coalesced.extend_from_slice(&second);

    let mut decoder = StreamDecoder::new();
    let outcome = decoder.ingest(&coalesced, false).expect("first frame");
    assert_eq!(outcome.consumed(), first.len());
    assert!(outcome.frame_ready());
    let received = decoder.take_frame().expect("take first");
    assert_eq!(received.header().kind(), MessageKind::SessionOpen);
    drop(received);

    let outcome = decoder
        .ingest(&coalesced[first.len()..], false)
        .expect("second frame");
    assert_eq!(outcome.consumed(), second.len());
    let received = decoder.take_frame().expect("take second");
    assert_eq!(received.header().kind(), MessageKind::OperationRequest);
    assert_eq!(received.payload(), &[0x77; 3]);
}

#[test]
fn offering_bytes_before_taking_a_ready_frame_terminates() {
    let encoded = frame(MessageKind::SessionOpen, 1, &[]);
    let mut decoder = StreamDecoder::new();
    assert!(decoder
        .ingest(&encoded, false)
        .expect("complete frame")
        .frame_ready());
    assert_eq!(
        decoder.ingest(&[0x51], false),
        Err(IpcError::OutstandingExchange)
    );
    assert_eq!(
        decoder.take_frame().err(),
        Some(IpcError::DecoderTerminated)
    );
    assert_eq!(decoder.ingest(&[], false), Err(IpcError::DecoderTerminated));
}

#[test]
fn stream_payload_shape_waits_for_declared_bytes() {
    let mut invalid = frame(MessageKind::OperationRequest, 1, &[0x55]);
    invalid[6..8].copy_from_slice(&MessageKind::SessionOpen.wire_value().to_le_bytes());
    let mut decoder = StreamDecoder::new();
    let header = decoder
        .ingest(&invalid[..HEADER_BYTES], false)
        .expect("complete valid header with pending payload");
    assert_eq!(header.consumed(), HEADER_BYTES);
    assert!(!header.frame_ready());
    assert_eq!(decoder.finish(), IpcError::ConnectionClosedMidFrame);

    let mut complete = StreamDecoder::new();
    assert_eq!(
        complete.ingest(&invalid, false),
        Err(IpcError::ControlPayloadNotEmpty)
    );
    assert_eq!(
        complete.ingest(&[], false),
        Err(IpcError::DecoderTerminated)
    );
}

#[test]
fn ancillary_presence_precedes_bytes_and_latches_terminal() {
    let encoded = frame(MessageKind::OperationRequest, 1, &[1, 2, 3]);
    for prefix in [0, 1, 17, 31, 32, encoded.len() - 1] {
        let mut decoder = StreamDecoder::new();
        decoder
            .ingest(&encoded[..prefix], false)
            .expect("accepted prefix");
        assert_eq!(
            decoder.ingest(&encoded[prefix..], true),
            Err(IpcError::AncillaryData)
        );
        assert_eq!(
            decoder.ingest(&encoded, false),
            Err(IpcError::DecoderTerminated)
        );
        assert_eq!(
            decoder.take_frame().err(),
            Some(IpcError::DecoderTerminated)
        );
        assert_eq!(decoder.finish(), IpcError::DecoderTerminated);
    }
}

#[test]
fn malformed_complete_header_terminates_at_header_completion() {
    let mut malformed = frame(MessageKind::SessionOpen, 1, &[]);
    malformed[0] ^= 1;
    let mut decoder = StreamDecoder::new();
    assert_eq!(
        decoder.ingest(&malformed, false),
        Err(IpcError::MagicMismatch)
    );
    assert_eq!(decoder.ingest(&[], false), Err(IpcError::DecoderTerminated));
}

#[test]
fn eof_distinguishes_partial_frame_from_clean_peer_loss() {
    let encoded = frame(MessageKind::OperationRequest, 1, &[0x11; 4]);
    for prefix in [1, 31, 32, encoded.len() - 1] {
        let mut decoder = StreamDecoder::new();
        decoder
            .ingest(&encoded[..prefix], false)
            .expect("accepted prefix");
        assert_eq!(decoder.finish(), IpcError::ConnectionClosedMidFrame);
        assert_eq!(decoder.finish(), IpcError::DecoderTerminated);
    }

    let mut clean = StreamDecoder::new();
    assert_eq!(clean.finish(), IpcError::PeerLost);

    let mut complete = StreamDecoder::new();
    assert!(complete
        .ingest(&encoded, false)
        .expect("frame")
        .frame_ready());
    assert_eq!(complete.finish(), IpcError::PeerLost);
}

#[test]
fn exact_ceiling_streams_and_stops_before_following_byte() {
    let encoded = frame(
        MessageKind::OperationRequest,
        u32::MAX,
        &vec![0x66; MAX_PAYLOAD_BYTES],
    );
    assert_eq!(encoded.len(), MAX_FRAME_BYTES);
    let mut coalesced = encoded;
    coalesced.push(0xff);
    let mut decoder = StreamDecoder::new();
    let outcome = decoder.ingest(&coalesced, false).expect("ceiling frame");
    assert_eq!(outcome.consumed(), MAX_FRAME_BYTES);
    assert!(outcome.frame_ready());
    let received = decoder.take_frame().expect("ceiling frame");
    assert_eq!(received.payload().len(), MAX_PAYLOAD_BYTES);
}
