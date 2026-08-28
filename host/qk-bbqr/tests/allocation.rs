//! M22 public operations are fixed-memory and leave caller outputs stable on rejection.

use qk_bbqr::{
    decode_frame, decode_typed_frame, encode_frame, encode_typed_frame, encoded_part_count,
    BbqrError, BbqrFileType, Reassembler, MAX_FRAME_TEXT_BYTES, MAX_PART_DECODED_BYTES,
    MAX_TOTAL_DECODED_BYTES,
};
use std::alloc::{GlobalAlloc, Layout, System};
use std::cell::Cell;

struct CountingAllocator;

thread_local! {
    static COUNTING: Cell<bool> = const { Cell::new(false) };
    static ALLOCATIONS: Cell<usize> = const { Cell::new(0) };
}

fn record_allocation() {
    if COUNTING.try_with(Cell::get).unwrap_or(false) {
        let _ = ALLOCATIONS.try_with(|count| count.set(count.get() + 1));
    }
}

unsafe impl GlobalAlloc for CountingAllocator {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        record_allocation();
        unsafe { System.alloc(layout) }
    }

    unsafe fn alloc_zeroed(&self, layout: Layout) -> *mut u8 {
        record_allocation();
        unsafe { System.alloc_zeroed(layout) }
    }

    unsafe fn realloc(&self, pointer: *mut u8, layout: Layout, new_size: usize) -> *mut u8 {
        record_allocation();
        unsafe { System.realloc(pointer, layout, new_size) }
    }

    unsafe fn dealloc(&self, pointer: *mut u8, layout: Layout) {
        unsafe { System.dealloc(pointer, layout) }
    }
}

#[global_allocator]
static GLOBAL: CountingAllocator = CountingAllocator;

fn measured<T>(operation: impl FnOnce() -> T) -> (T, usize) {
    ALLOCATIONS.with(|count| count.set(0));
    COUNTING.with(|counting| counting.set(true));
    let result = operation();
    COUNTING.with(|counting| counting.set(false));
    let allocations = ALLOCATIONS.with(Cell::get);
    (result, allocations)
}

fn storage() -> Box<[u8]> {
    vec![0u8; MAX_TOTAL_DECODED_BYTES].into_boxed_slice()
}

fn encoded_frame(
    payload: &[u8],
    non_final_part_len: usize,
    part_index: u16,
) -> ([u8; MAX_FRAME_TEXT_BYTES], usize) {
    let mut frame = [0xa5; MAX_FRAME_TEXT_BYTES];
    let len = encode_frame(payload, non_final_part_len, part_index, &mut frame).unwrap();
    assert!(frame[len..].iter().all(|byte| *byte == 0xa5));
    (frame, len)
}

#[test]
fn codec_success_and_rejections_allocate_zero_and_preserve_unused_outputs() {
    let payload = [0u8, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10];
    let mut frame = [0xa5; MAX_FRAME_TEXT_BYTES];

    let (part_count, allocations) = measured(|| encoded_part_count(payload.len(), 5));
    assert_eq!(part_count, Ok(3));
    assert_eq!(allocations, 0);

    let (encoded_len, allocations) = measured(|| encode_frame(&payload, 5, 0, &mut frame));
    assert_eq!(encoded_len, Ok(16));
    assert_eq!(allocations, 0);
    assert_eq!(&frame[..16], b"B$2P0300AAAQEAYE");
    assert!(frame[16..].iter().all(|byte| *byte == 0xa5));

    let mut decoded = [0x5a; MAX_PART_DECODED_BYTES];
    let (decoded_frame, allocations) = measured(|| decode_frame(&frame[..16], &mut decoded));
    let decoded_frame = decoded_frame.unwrap();
    assert_eq!(allocations, 0);
    assert_eq!(decoded_frame.declared_parts, 3);
    assert_eq!(decoded_frame.part_index, 0);
    assert_eq!(decoded_frame.decoded_len, 5);
    assert_eq!(&decoded[..5], &payload[..5]);
    assert!(decoded[5..].iter().all(|byte| *byte == 0x5a));

    let before = frame;
    let (error, allocations) = measured(|| encode_frame(&payload, 4, 0, &mut frame));
    assert_eq!(error, Err(BbqrError::InvalidNonFinalPartLength));
    assert_eq!(allocations, 0);
    assert_eq!(frame, before, "encode rejection leaves output unchanged");

    let mut malformed = before;
    malformed[15] = b'!';
    let before_decoded = decoded;
    let (error, allocations) = measured(|| decode_frame(&malformed[..16], &mut decoded));
    assert_eq!(error, Err(BbqrError::MalformedBase32Symbol));
    assert_eq!(allocations, 0);
    assert_eq!(
        decoded, before_decoded,
        "decode rejection leaves output unchanged"
    );
}

#[test]
fn final_first_and_out_of_order_reassembly_allocate_zero() {
    let payload = [0u8, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10];
    let (frame_0, len_0) = encoded_frame(&payload, 5, 0);
    let (frame_1, len_1) = encoded_frame(&payload, 5, 1);
    let (frame_2, len_2) = encoded_frame(&payload, 5, 2);

    for order in [[2usize, 0, 1], [1usize, 0, 2]] {
        let mut backing = storage();
        let backing: &mut [u8; MAX_TOTAL_DECODED_BYTES] = backing.as_mut().try_into().unwrap();
        let (mut reassembler, allocations) = measured(|| Reassembler::new(backing));
        assert_eq!(allocations, 0);

        for part_index in order {
            let (frame, len) = match part_index {
                0 => (&frame_0, len_0),
                1 => (&frame_1, len_1),
                2 => (&frame_2, len_2),
                _ => unreachable!(),
            };
            let (progress, allocations) = measured(|| reassembler.submit(&frame[..len]));
            assert!(progress.is_ok());
            assert_eq!(allocations, 0);
        }

        let (result, allocations) = measured(|| reassembler.payload());
        assert_eq!(allocations, 0);
        assert_eq!(result.unwrap(), payload);
    }
}

#[test]
fn duplicate_and_error_paths_allocate_zero_without_corrupting_the_stream() {
    let payload = [0u8, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10];
    let conflicting_payload = [99u8, 98, 97, 96, 95, 5, 6, 7, 8, 9, 10];
    let (frame_0, len_0) = encoded_frame(&payload, 5, 0);
    let (frame_1, len_1) = encoded_frame(&payload, 5, 1);
    let (frame_2, len_2) = encoded_frame(&payload, 5, 2);
    let (conflict_0, conflict_len_0) = encoded_frame(&conflicting_payload, 5, 0);
    let mut wrong_encoding = frame_1;
    wrong_encoding[2] = b'H';

    let mut backing = storage();
    let backing: &mut [u8; MAX_TOTAL_DECODED_BYTES] = backing.as_mut().try_into().unwrap();
    let mut reassembler = Reassembler::new(backing);

    let (first, allocations) = measured(|| reassembler.submit(&frame_0[..len_0]));
    assert!(!first.unwrap().was_duplicate);
    assert_eq!(allocations, 0);

    let (duplicate, allocations) = measured(|| reassembler.submit(&frame_0[..len_0]));
    let duplicate = duplicate.unwrap();
    assert_eq!(allocations, 0);
    assert!(duplicate.was_duplicate);
    assert_eq!(duplicate.received_parts, 1);
    assert_eq!(duplicate.identical_duplicates, 1);

    let (error, allocations) = measured(|| reassembler.submit(&wrong_encoding[..len_1]));
    assert_eq!(error, Err(BbqrError::StreamEncodingMismatch));
    assert_eq!(allocations, 0);

    let (error, allocations) = measured(|| reassembler.submit(&conflict_0[..conflict_len_0]));
    assert_eq!(error, Err(BbqrError::ConflictingDuplicate));
    assert_eq!(allocations, 0);

    for (frame, len) in [(&frame_2, len_2), (&frame_1, len_1)] {
        let (progress, allocations) = measured(|| reassembler.submit(&frame[..len]));
        assert!(progress.is_ok());
        assert_eq!(allocations, 0);
    }
    let (result, allocations) = measured(|| reassembler.payload());
    assert_eq!(allocations, 0);
    assert_eq!(result.unwrap(), payload);
}

#[test]
fn maximum_total_payload_path_allocates_zero_and_round_trips_exactly() {
    const PART_LEN: usize = 1_025;

    let mut payload = vec![0u8; MAX_TOTAL_DECODED_BYTES];
    for (index, byte) in payload.iter_mut().enumerate() {
        *byte = (index as u8).wrapping_mul(29).wrapping_add(7);
    }
    let mut backing = storage();
    let backing: &mut [u8; MAX_TOTAL_DECODED_BYTES] = backing.as_mut().try_into().unwrap();
    let (mut reassembler, allocations) = measured(|| Reassembler::new(backing));
    assert_eq!(allocations, 0);

    let (result, allocations) = measured(|| {
        let declared_parts = encoded_part_count(payload.len(), PART_LEN)?;
        let mut frame = [0u8; MAX_FRAME_TEXT_BYTES];
        let mut final_progress = None;
        for part_index in 0..declared_parts {
            let frame_len = encode_frame(&payload, PART_LEN, part_index, &mut frame)?;
            final_progress = Some(reassembler.submit(&frame[..frame_len])?);
        }
        Ok::<_, BbqrError>(final_progress.unwrap())
    });
    let progress = result.unwrap();
    assert_eq!(allocations, 0);
    assert_eq!(progress.declared_parts, 256);
    assert_eq!(progress.received_parts, 256);
    assert_eq!(progress.decoded_bytes, MAX_TOTAL_DECODED_BYTES);
    assert!(progress.complete);

    let (result, allocations) = measured(|| reassembler.payload());
    assert_eq!(allocations, 0);
    assert_eq!(result.unwrap(), payload);

    let oversized = vec![0u8; MAX_TOTAL_DECODED_BYTES + 1];
    let mut frame = [0x3c; MAX_FRAME_TEXT_BYTES];
    let before = frame;
    let (error, allocations) = measured(|| encode_frame(&oversized, PART_LEN, 0, &mut frame));
    assert_eq!(error, Err(BbqrError::PayloadTooLarge));
    assert_eq!(allocations, 0);
    assert_eq!(frame, before);
}

#[test]
fn typed_transaction_operations_allocate_zero() {
    let payload = *b"0123456789";
    let mut frame = [0xa5; MAX_FRAME_TEXT_BYTES];
    let (frame_len, allocations) =
        measured(|| encode_typed_frame(BbqrFileType::Transaction, &payload, 5, 0, &mut frame));
    let frame_len = frame_len.unwrap();
    assert_eq!(allocations, 0);

    let mut decoded = [0x5a; MAX_PART_DECODED_BYTES];
    let (metadata, allocations) = measured(|| {
        decode_typed_frame(BbqrFileType::Transaction, &frame[..frame_len], &mut decoded)
    });
    assert_eq!(metadata.unwrap().decoded_len, 5);
    assert_eq!(allocations, 0);

    let mut backing = storage();
    let backing: &mut [u8; MAX_TOTAL_DECODED_BYTES] = backing.as_mut().try_into().unwrap();
    let (mut reassembler, allocations) =
        measured(|| Reassembler::new_typed(BbqrFileType::Transaction, backing));
    assert_eq!(allocations, 0);
    let (progress, allocations) = measured(|| reassembler.submit(&frame[..frame_len]));
    assert!(progress.is_ok());
    assert_eq!(allocations, 0);
}
