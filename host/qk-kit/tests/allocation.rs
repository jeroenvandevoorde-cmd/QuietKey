//! Every public Kit codec operation is fixed-memory on success and rejection.

use qk_kit::{
    combine_frames, decode_fallback, encode_fallback, encode_frame, encode_qr, frame_metadata,
    KitError, ShareIndex, FALLBACK_SYMBOLS, FRAME_LEN, QR_PACKED_BYTES,
};
use std::alloc::{GlobalAlloc, Layout, System};
use std::cell::Cell;

struct CountingAllocator;

thread_local! {
    static COUNTING: Cell<bool> = const { Cell::new(false) };
    static ALLOCATIONS: Cell<usize> = const { Cell::new(0) };
}

unsafe impl GlobalAlloc for CountingAllocator {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        let counting = COUNTING.try_with(Cell::get).unwrap_or(false);
        if counting {
            let _ = ALLOCATIONS.try_with(|count| count.set(count.get() + 1));
        }
        unsafe { System.alloc(layout) }
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

fn facts() -> ([u8; 32], [u8; 96], [u8; 96]) {
    let mut wallet_id = [0u8; 32];
    let mut share_one = [0u8; 96];
    let mut share_two = [0u8; 96];
    for (index, byte) in wallet_id.iter_mut().enumerate() {
        *byte = (index as u8).wrapping_mul(17).wrapping_add(3);
    }
    for (index, byte) in share_one.iter_mut().enumerate() {
        *byte = (index as u8).wrapping_mul(29).wrapping_add(5);
    }
    for (index, byte) in share_two.iter_mut().enumerate() {
        *byte = (index as u8).wrapping_mul(43).wrapping_add(7);
    }
    (wallet_id, share_one, share_two)
}

#[test]
fn every_public_success_path_allocates_zero() {
    let (wallet_id, share_one, share_two) = facts();

    let (frame_one, allocations) =
        measured(|| encode_frame(ShareIndex::One, &wallet_id, &share_one));
    assert_eq!(allocations, 0);
    let (frame_two, allocations) =
        measured(|| encode_frame(ShareIndex::Two, &wallet_id, &share_two));
    assert_eq!(allocations, 0);

    let (metadata, allocations) = measured(|| frame_metadata(&frame_one));
    let metadata = metadata.unwrap();
    assert_eq!(allocations, 0);
    assert_eq!(metadata.share_index, ShareIndex::One);
    assert_eq!(metadata.wallet_id, wallet_id);

    let mut fallback = [0xa5; FALLBACK_SYMBOLS];
    let (result, allocations) = measured(|| encode_fallback(&frame_one, &mut fallback));
    assert_eq!(result, Ok(()));
    assert_eq!(allocations, 0);

    let mut decoded = [0x5a; FRAME_LEN];
    let (metadata, allocations) = measured(|| decode_fallback(&fallback, &mut decoded));
    let metadata = metadata.unwrap();
    assert_eq!(allocations, 0);
    assert_eq!(metadata.share_index, ShareIndex::One);
    assert_eq!(metadata.wallet_id, wallet_id);
    assert_eq!(decoded, frame_one);

    let mut qr = [0x3c; QR_PACKED_BYTES];
    let (metadata, allocations) = measured(|| encode_qr(&frame_one, &mut qr));
    let metadata = metadata.unwrap();
    assert_eq!(allocations, 0);
    assert!(metadata.mask < 8);
    assert_eq!(metadata.penalties.len(), 8);
    assert_eq!(qr[QR_PACKED_BYTES - 1] & 0x7f, 0);

    let (owner, allocations) = measured(|| combine_frames(&frame_one, &frame_two));
    assert_eq!(allocations, 0);
    let owner = owner.unwrap();
    let ((), allocations) = measured(|| drop(owner));
    assert_eq!(allocations, 0);

    let (owner, allocations) = measured(|| combine_frames(&frame_two, &frame_one));
    assert_eq!(allocations, 0);
    let owner = owner.unwrap();
    let ((), allocations) = measured(|| drop(owner));
    assert_eq!(allocations, 0);

    let (one, allocations) = measured(|| ShareIndex::One.as_u8());
    assert_eq!(one, 1);
    assert_eq!(allocations, 0);
}

#[test]
fn every_public_rejection_path_allocates_zero_and_preserves_outputs() {
    let (wallet_id, share_one, share_two) = facts();
    let frame_one = encode_frame(ShareIndex::One, &wallet_id, &share_one);
    let frame_two = encode_frame(ShareIndex::Two, &wallet_id, &share_two);
    let same_index = encode_frame(ShareIndex::One, &wallet_id, &share_two);
    let mut other_wallet = wallet_id;
    other_wallet[0] ^= 0x80;
    let other_wallet_frame = encode_frame(ShareIndex::Two, &other_wallet, &share_two);

    let (result, allocations) = measured(|| frame_metadata(&frame_one[..FRAME_LEN - 1]));
    assert_eq!(result, Err(KitError::FrameLength));
    assert_eq!(allocations, 0);

    let mut bad_checksum = frame_one;
    bad_checksum[FRAME_LEN - 1] ^= 1;
    let (result, allocations) = measured(|| frame_metadata(&bad_checksum));
    assert_eq!(result, Err(KitError::FrameChecksum));
    assert_eq!(allocations, 0);

    let mut fallback_output = [0xa5; FALLBACK_SYMBOLS];
    let fallback_before = fallback_output;
    let (result, allocations) =
        measured(|| encode_fallback(&frame_one[..FRAME_LEN - 1], &mut fallback_output));
    assert_eq!(result, Err(KitError::FrameLength));
    assert_eq!(allocations, 0);
    assert_eq!(fallback_output, fallback_before);

    let (result, allocations) = measured(|| encode_fallback(&bad_checksum, &mut fallback_output));
    assert_eq!(result, Err(KitError::FrameChecksum));
    assert_eq!(allocations, 0);
    assert_eq!(fallback_output, fallback_before);

    let mut valid_fallback = [0u8; FALLBACK_SYMBOLS];
    encode_fallback(&frame_one, &mut valid_fallback).unwrap();
    let mut decoded_output = [0x5a; FRAME_LEN];
    let decoded_before = decoded_output;

    let (result, allocations) =
        measured(|| decode_fallback(&valid_fallback[..FALLBACK_SYMBOLS - 1], &mut decoded_output));
    assert_eq!(result, Err(KitError::FallbackLength));
    assert_eq!(allocations, 0);
    assert_eq!(decoded_output, decoded_before);

    let mut malformed = valid_fallback;
    malformed[0] = b'0';
    let (result, allocations) = measured(|| decode_fallback(&malformed, &mut decoded_output));
    assert_eq!(result, Err(KitError::MalformedSymbol));
    assert_eq!(allocations, 0);
    assert_eq!(decoded_output, decoded_before);

    let mut noncanonical_padding = valid_fallback;
    noncanonical_padding[FALLBACK_SYMBOLS - 1] = b'3';
    let (result, allocations) =
        measured(|| decode_fallback(&noncanonical_padding, &mut decoded_output));
    assert_eq!(result, Err(KitError::NonCanonicalPadding));
    assert_eq!(allocations, 0);
    assert_eq!(decoded_output, decoded_before);

    let mut fallback_bad_frame = valid_fallback;
    fallback_bad_frame[10] = if fallback_bad_frame[10] == b'2' {
        b'3'
    } else {
        b'2'
    };
    let (result, allocations) =
        measured(|| decode_fallback(&fallback_bad_frame, &mut decoded_output));
    assert_eq!(result, Err(KitError::FrameChecksum));
    assert_eq!(allocations, 0);
    assert_eq!(decoded_output, decoded_before);

    let mut qr_output = [0x3c; QR_PACKED_BYTES];
    let qr_before = qr_output;
    let (result, allocations) = measured(|| encode_qr(&frame_one[..FRAME_LEN - 1], &mut qr_output));
    assert_eq!(result, Err(KitError::FrameLength));
    assert_eq!(allocations, 0);
    assert_eq!(qr_output, qr_before);

    let (result, allocations) = measured(|| encode_qr(&bad_checksum, &mut qr_output));
    assert_eq!(result, Err(KitError::FrameChecksum));
    assert_eq!(allocations, 0);
    assert_eq!(qr_output, qr_before);

    let (result, allocations) = measured(|| combine_frames(&[], &frame_two));
    assert!(matches!(result, Err(KitError::FrameLength)));
    assert_eq!(allocations, 0);

    let (result, allocations) = measured(|| combine_frames(&frame_one, &[]));
    assert!(matches!(result, Err(KitError::FrameLength)));
    assert_eq!(allocations, 0);

    let (result, allocations) = measured(|| combine_frames(&frame_one, &frame_one));
    assert!(matches!(result, Err(KitError::DuplicateShare)));
    assert_eq!(allocations, 0);

    let (result, allocations) = measured(|| combine_frames(&frame_one, &same_index));
    assert!(matches!(result, Err(KitError::SameShareIndex)));
    assert_eq!(allocations, 0);

    let (result, allocations) = measured(|| combine_frames(&frame_one, &other_wallet_frame));
    assert!(matches!(result, Err(KitError::WalletMismatch)));
    assert_eq!(allocations, 0);
}
