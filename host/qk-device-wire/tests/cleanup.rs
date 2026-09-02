#![cfg(feature = "fuzzing")]
#![allow(clippy::panic, clippy::unwrap_used)]

use qk_device_wire::{
    encode_frame, reset_wiped_bytes, wiped_bytes, Capability, DeviceError, MessageKind,
    StreamDecoder, HEADER_BYTES,
};
use std::panic::{catch_unwind, AssertUnwindSafe};

fn chunk(sequence: u32, length: usize) -> Vec<u8> {
    let mut body = Vec::with_capacity(9 + length);
    body.extend_from_slice(&0u32.to_le_bytes());
    body.extend_from_slice(&(length as u32).to_le_bytes());
    body.push(1);
    body.extend(std::iter::repeat_n(0xa5, length));
    let mut frame = vec![0; HEADER_BYTES + body.len()];
    encode_frame(
        Capability::CameraInput,
        MessageKind::CameraChunk,
        sequence,
        &body,
        &mut frame,
    )
    .unwrap();
    frame
}

#[test]
fn delivered_owner_drop_wipes_exact_allocation_capacity() {
    let bytes = chunk(1, 137);
    let mut decoder = StreamDecoder::new(Capability::CameraInput);
    decoder.ingest(&bytes).unwrap();
    let frame = decoder.take_frame().unwrap();
    let capacity = frame.allocation_capacity();
    reset_wiped_bytes();
    drop(frame);
    assert_eq!(wiped_bytes(), capacity);
}

#[test]
fn decoder_drop_wipes_partial_body_capacity_and_header_storage() {
    let bytes = chunk(1, 257);
    let mut decoder = StreamDecoder::new(Capability::CameraInput);
    decoder.ingest(&bytes[..HEADER_BYTES + 7]).unwrap();
    reset_wiped_bytes();
    drop(decoder);
    assert!(wiped_bytes() >= HEADER_BYTES + 266);
}

#[test]
fn body_rejection_wipes_allocation_before_return() {
    let mut bytes = chunk(1, 41);
    bytes[HEADER_BYTES + 8] = 2;
    let mut decoder = StreamDecoder::new(Capability::CameraInput);
    reset_wiped_bytes();
    assert_eq!(
        decoder.ingest(&bytes),
        Err(DeviceError::FinalFlagOutOfRange)
    );
    assert!(wiped_bytes() >= HEADER_BYTES * 2 + 50);
}

#[test]
fn caught_unwind_drops_and_wipes_complete_body_capacity() {
    let bytes = chunk(1, 193);
    let mut decoder = StreamDecoder::new(Capability::CameraInput);
    decoder.ingest(&bytes).unwrap();
    let frame = decoder.take_frame().unwrap();
    let capacity = frame.allocation_capacity();
    reset_wiped_bytes();
    let result = catch_unwind(AssertUnwindSafe(move || {
        let _kept_alive = frame;
        panic!("test-only caught unwind");
    }));
    assert!(result.is_err());
    assert_eq!(wiped_bytes(), capacity);
}
