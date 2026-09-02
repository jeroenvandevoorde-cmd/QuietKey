#![allow(clippy::unwrap_used)]

use qk_device_wire::{
    encode_frame, Capability, DeviceError, MessageKind, NormalStage, StreamDecoder, HEADER_BYTES,
    MAGIC, VERSION,
};

fn stage(sequence: u32, value: u8) -> Vec<u8> {
    let mut output = vec![0; HEADER_BYTES + 1];
    encode_frame(
        Capability::Display,
        MessageKind::DisplayStage,
        sequence,
        &[value],
        &mut output,
    )
    .unwrap();
    output
}

fn raw_stage(sequence: u32, body: &[u8]) -> Vec<u8> {
    let mut frame = vec![0; HEADER_BYTES + body.len()];
    frame[..4].copy_from_slice(&MAGIC);
    frame[4] = VERSION;
    frame[5] = Capability::Display.wire_value();
    frame[6] = MessageKind::DisplayStage.wire_value();
    frame[8..12].copy_from_slice(&sequence.to_le_bytes());
    frame[12..16].copy_from_slice(&(body.len() as u32).to_le_bytes());
    frame[16..].copy_from_slice(body);
    frame
}

#[test]
fn every_two_chunk_fragmentation_split_reassembles() {
    let frame = stage(1, NormalStage::NormalStart.wire_value());
    for split in 0..=frame.len() {
        let mut decoder = StreamDecoder::new(Capability::Display);
        let first = decoder.ingest(&frame[..split]).unwrap();
        assert_eq!(first.consumed(), split);
        assert_eq!(first.frame_ready(), split == frame.len());
        if split != frame.len() {
            let second = decoder.ingest(&frame[split..]).unwrap();
            assert_eq!(second.consumed(), frame.len() - split);
            assert!(second.frame_ready());
        }
        let received = decoder.take_frame().unwrap();
        assert_eq!(received.header().sequence(), 1);
        assert_eq!(received.body(), &[1]);
    }
}

#[test]
fn coalescing_consumes_one_frame_at_a_time() {
    let first = stage(1, 1);
    let second = stage(2, 3);
    let joined = [first.as_slice(), second.as_slice()].concat();
    let mut decoder = StreamDecoder::new(Capability::Display);
    let outcome = decoder.ingest(&joined).unwrap();
    assert_eq!(outcome.consumed(), first.len());
    assert!(outcome.frame_ready());
    assert_eq!(decoder.take_frame().unwrap().header().sequence(), 1);
    let outcome = decoder.ingest(&joined[first.len()..]).unwrap();
    assert_eq!(outcome.consumed(), second.len());
    assert!(outcome.frame_ready());
    assert_eq!(decoder.take_frame().unwrap().header().sequence(), 2);
}

#[test]
fn second_frame_before_take_terminates_as_outstanding() {
    let first = stage(1, 1);
    let mut decoder = StreamDecoder::new(Capability::Display);
    assert!(decoder.ingest(&first).unwrap().frame_ready());
    assert_eq!(
        decoder.ingest(&stage(2, 3)),
        Err(DeviceError::OutstandingExchange)
    );
    assert_eq!(
        decoder.take_frame().err(),
        Some(DeviceError::DecoderTerminated)
    );
}

#[test]
fn replay_regression_and_skip_are_distinct_and_terminal() {
    let mut replay = StreamDecoder::new(Capability::Display);
    replay.ingest(&stage(1, 1)).unwrap();
    drop(replay.take_frame().unwrap());
    assert_eq!(
        replay.ingest(&stage(1, 1)),
        Err(DeviceError::SequenceReplay)
    );

    let mut regression = StreamDecoder::new(Capability::Display);
    for sequence in [1, 2] {
        regression.ingest(&stage(sequence, 1)).unwrap();
        drop(regression.take_frame().unwrap());
    }
    assert_eq!(
        regression.ingest(&stage(1, 1)),
        Err(DeviceError::SequenceRegression)
    );

    let mut skipped = StreamDecoder::new(Capability::Display);
    assert_eq!(
        skipped.ingest(&stage(2, 1)),
        Err(DeviceError::SequenceSkipped)
    );
}

#[test]
fn sequence_precedes_body_grammar_after_complete_availability() {
    let invalid_body = raw_stage(2, &[0xff]);
    let mut decoder = StreamDecoder::new(Capability::Display);
    assert_eq!(
        decoder.ingest(&invalid_body),
        Err(DeviceError::SequenceSkipped)
    );

    let invalid_body = raw_stage(1, &[0xff]);
    let mut decoder = StreamDecoder::new(Capability::Display);
    assert_eq!(
        decoder.ingest(&invalid_body),
        Err(DeviceError::ValueOutOfRange)
    );
}

#[test]
fn eof_distinguishes_partial_frame_from_clean_peer_loss() {
    let frame = stage(1, 1);
    let mut partial_header = StreamDecoder::new(Capability::Display);
    partial_header.ingest(&frame[..5]).unwrap();
    assert_eq!(
        partial_header.finish(),
        DeviceError::ConnectionClosedMidFrame
    );

    let mut partial_body = StreamDecoder::new(Capability::Display);
    partial_body.ingest(&frame[..HEADER_BYTES]).unwrap();
    assert_eq!(partial_body.finish(), DeviceError::ConnectionClosedMidFrame);

    let mut clean = StreamDecoder::new(Capability::Display);
    assert_eq!(clean.finish(), DeviceError::PeerLost);
    assert_eq!(clean.finish(), DeviceError::DecoderTerminated);
}

#[test]
fn descriptor_capability_is_bound_before_allocation() {
    let frame = stage(1, 1);
    let mut decoder = StreamDecoder::new(Capability::Keypad);
    assert_eq!(decoder.ingest(&frame), Err(DeviceError::CapabilityMismatch));
}

#[cfg(feature = "fuzzing")]
#[test]
fn exhaustion_probe_is_exact() {
    assert_eq!(
        StreamDecoder::fuzz_sequence_exhaustion_probe(Capability::Display),
        DeviceError::SequenceExhausted
    );
}
