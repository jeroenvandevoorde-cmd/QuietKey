//! M22 bounded stream-state and hostile-ordering tests.

use qk_bbqr::{
    encode_frame, encoded_part_count, BbqrError, Reassembler, ReassemblyProgress,
    MAX_FRAME_TEXT_BYTES, MAX_PART_DECODED_BYTES, MAX_SUBMISSIONS, MAX_TOTAL_DECODED_BYTES,
};

fn storage(fill: u8) -> Box<[u8; MAX_TOTAL_DECODED_BYTES]> {
    vec![fill; MAX_TOTAL_DECODED_BYTES]
        .into_boxed_slice()
        .try_into()
        .expect("exact fixed storage length")
}

fn patterned(length: usize, seed: u8) -> Vec<u8> {
    (0..length)
        .map(|index| {
            seed.wrapping_add((index as u8).wrapping_mul(29))
                .wrapping_add(7)
        })
        .collect()
}

fn encoded_frame(payload: &[u8], part_len: usize, part_index: u16) -> Vec<u8> {
    let mut output = [0xa5; MAX_FRAME_TEXT_BYTES];
    let length = encode_frame(payload, part_len, part_index, &mut output).unwrap();
    assert!(output[length..].iter().all(|byte| *byte == 0xa5));
    output[..length].to_vec()
}

fn base36_pair(value: u16) -> [u8; 2] {
    fn digit(value: u8) -> u8 {
        match value {
            0..=9 => b'0' + value,
            10..=35 => b'A' + value - 10,
            _ => unreachable!(),
        }
    }
    [digit((value / 36) as u8), digit((value % 36) as u8)]
}

fn rewrite_header(frame: &mut [u8], count: u16, index: u16) {
    frame[4..6].copy_from_slice(&base36_pair(count));
    frame[6..8].copy_from_slice(&base36_pair(index));
}

#[allow(clippy::too_many_arguments)]
fn assert_progress(
    actual: ReassemblyProgress,
    declared: u16,
    received: u16,
    duplicates: u16,
    submissions: u16,
    decoded_bytes: usize,
    duplicate: bool,
    complete: bool,
) {
    assert_eq!(actual.declared_parts, declared);
    assert_eq!(actual.received_parts, received);
    assert_eq!(actual.identical_duplicates, duplicates);
    assert_eq!(actual.submissions, submissions);
    assert_eq!(actual.decoded_bytes, decoded_bytes);
    assert_eq!(actual.was_duplicate, duplicate);
    assert_eq!(actual.complete, complete);
}

#[test]
fn out_of_order_and_identical_duplicate_progress_is_exact() {
    let payload = patterned(37, 0x31);
    let frames: Vec<_> = (0..4)
        .map(|index| encoded_frame(&payload, 10, index))
        .collect();
    let mut backing = storage(0xcc);
    let mut reassembler = Reassembler::new(&mut backing);

    assert_eq!(reassembler.payload(), Err(BbqrError::Incomplete));
    assert_progress(
        reassembler.submit(&frames[2]).unwrap(),
        4,
        1,
        0,
        1,
        10,
        false,
        false,
    );
    assert_progress(
        reassembler.submit(&frames[0]).unwrap(),
        4,
        2,
        0,
        2,
        20,
        false,
        false,
    );
    assert_progress(
        reassembler.submit(&frames[0]).unwrap(),
        4,
        2,
        1,
        3,
        20,
        true,
        false,
    );
    assert_progress(
        reassembler.submit(&frames[3]).unwrap(),
        4,
        3,
        1,
        4,
        27,
        false,
        false,
    );
    assert_eq!(reassembler.payload(), Err(BbqrError::Incomplete));
    assert_progress(
        reassembler.submit(&frames[1]).unwrap(),
        4,
        4,
        1,
        5,
        37,
        false,
        true,
    );
    assert_eq!(reassembler.payload().unwrap(), payload);

    // Completion is terminal and wins before frame parsing or work charging.
    for _ in 0..8 {
        assert_eq!(
            reassembler.submit(b"not a frame"),
            Err(BbqrError::AlreadyComplete)
        );
    }
    assert_eq!(reassembler.payload().unwrap(), payload);
}

#[test]
fn established_header_mismatches_precede_body_and_preserve_the_candidate() {
    let payload = patterned(31, 0x42);
    let frames: Vec<_> = (0..4)
        .map(|index| encoded_frame(&payload, 10, index))
        .collect();
    let mut backing = storage(0xcc);
    let mut reassembler = Reassembler::new(&mut backing);
    assert_progress(
        reassembler.submit(&frames[0]).unwrap(),
        4,
        1,
        0,
        1,
        10,
        false,
        false,
    );

    let mut wrong_encoding = frames[1].clone();
    wrong_encoding[2] = b'H';
    *wrong_encoding.last_mut().unwrap() = b'!';
    assert_eq!(
        reassembler.submit(&wrong_encoding),
        Err(BbqrError::StreamEncodingMismatch)
    );

    let mut wrong_type = frames[1].clone();
    wrong_type[3] = b'U';
    *wrong_type.last_mut().unwrap() = b'!';
    assert_eq!(
        reassembler.submit(&wrong_type),
        Err(BbqrError::StreamFileTypeMismatch)
    );

    let mut wrong_count = frames[1].clone();
    rewrite_header(&mut wrong_count, 5, 1);
    *wrong_count.last_mut().unwrap() = b'!';
    assert_eq!(
        reassembler.submit(&wrong_count),
        Err(BbqrError::StreamPartCountMismatch)
    );

    // The three rejected attempts charged work but did not replace or mutate A.
    assert_progress(
        reassembler.submit(&frames[1]).unwrap(),
        4,
        2,
        0,
        5,
        20,
        false,
        false,
    );
    assert_progress(
        reassembler.submit(&frames[3]).unwrap(),
        4,
        3,
        0,
        6,
        21,
        false,
        false,
    );
    assert_progress(
        reassembler.submit(&frames[2]).unwrap(),
        4,
        4,
        0,
        7,
        31,
        false,
        true,
    );
    assert_eq!(reassembler.payload().unwrap(), payload);
}

#[test]
fn conflicting_duplicate_is_distinct_and_does_not_change_bytes() {
    let payload = patterned(11, 0x11);
    let mut alternate = payload.clone();
    alternate[..5].copy_from_slice(&[99, 98, 97, 96, 95]);
    let frames: Vec<_> = (0..3)
        .map(|index| encoded_frame(&payload, 5, index))
        .collect();
    let conflict = encoded_frame(&alternate, 5, 0);

    let mut backing = storage(0xcc);
    let mut reassembler = Reassembler::new(&mut backing);
    assert_progress(
        reassembler.submit(&frames[0]).unwrap(),
        3,
        1,
        0,
        1,
        5,
        false,
        false,
    );
    assert_eq!(
        reassembler.submit(&conflict),
        Err(BbqrError::ConflictingDuplicate)
    );
    assert_progress(
        reassembler.submit(&frames[2]).unwrap(),
        3,
        2,
        0,
        3,
        6,
        false,
        false,
    );
    assert_progress(
        reassembler.submit(&frames[1]).unwrap(),
        3,
        3,
        0,
        4,
        11,
        false,
        true,
    );
    assert_eq!(reassembler.payload().unwrap(), payload);
}

#[test]
fn duplicate_and_submission_work_caps_have_distinct_precedence() {
    let payload = patterned(11, 0x21);
    let frames: Vec<_> = (0..3)
        .map(|index| encoded_frame(&payload, 5, index))
        .collect();
    let mut backing = storage(0xcc);
    let mut reassembler = Reassembler::new(&mut backing);
    assert_progress(
        reassembler.submit(&frames[0]).unwrap(),
        3,
        1,
        0,
        1,
        5,
        false,
        false,
    );

    for duplicate_number in 1..=3 {
        assert_progress(
            reassembler.submit(&frames[0]).unwrap(),
            3,
            1,
            duplicate_number,
            duplicate_number + 1,
            5,
            true,
            false,
        );
    }
    assert_eq!(
        reassembler.submit(&frames[0]),
        Err(BbqrError::DuplicateWorkExceeded)
    );

    // The duplicate-cap rejection charged submission five without changing
    // duplicate or receipt state. The sixth submission remains available.
    assert_progress(
        reassembler.submit(&frames[1]).unwrap(),
        3,
        2,
        3,
        6,
        10,
        false,
        false,
    );
    assert_eq!(
        reassembler.submit(&frames[2]),
        Err(BbqrError::SubmissionWorkExceeded)
    );
    assert_eq!(reassembler.payload(), Err(BbqrError::Incomplete));
}

#[test]
fn malformed_prestream_work_is_bounded_and_cannot_evade_declared_cap() {
    let mut backing = storage(0xcc);
    let mut reassembler = Reassembler::new(&mut backing);
    for _ in 0..MAX_SUBMISSIONS {
        assert_eq!(reassembler.submit(b""), Err(BbqrError::FrameTooShort));
    }
    assert_eq!(
        reassembler.submit(b""),
        Err(BbqrError::SubmissionWorkExceeded)
    );

    let frame = encoded_frame(b"x", 5, 0);
    assert_eq!(
        reassembler.submit(&frame),
        Err(BbqrError::SubmissionWorkExceeded)
    );

    // A later one-part declaration retroactively narrows its first stream's
    // accepted attempt budget to two, including pre-establishment failures.
    let mut second_backing = storage(0xcc);
    let mut second = Reassembler::new(&mut second_backing);
    assert_eq!(second.submit(b""), Err(BbqrError::FrameTooShort));
    assert_eq!(second.submit(b""), Err(BbqrError::FrameTooShort));
    assert_eq!(
        second.submit(&frame),
        Err(BbqrError::SubmissionWorkExceeded)
    );
    assert_eq!(second.payload(), Err(BbqrError::Incomplete));
}

#[test]
fn nonuniform_geometry_rejects_without_consuming_the_index() {
    let payload = patterned(11, 0x31);
    let frames: Vec<_> = (0..3)
        .map(|index| encoded_frame(&payload, 5, index))
        .collect();
    let ten_byte_geometry = patterned(21, 0x81);
    let wrong_index_one = encoded_frame(&ten_byte_geometry, 10, 1);

    let mut backing = storage(0xcc);
    let mut reassembler = Reassembler::new(&mut backing);
    reassembler.submit(&frames[0]).unwrap();
    assert_eq!(
        reassembler.submit(&wrong_index_one),
        Err(BbqrError::NonUniformPartLength)
    );
    reassembler.submit(&frames[1]).unwrap();
    let progress = reassembler.submit(&frames[2]).unwrap();
    assert_progress(progress, 3, 3, 0, 4, 11, false, true);
    assert_eq!(reassembler.payload().unwrap(), payload);
}

#[test]
fn final_size_checks_work_in_both_arrival_orders() {
    let small = patterned(6, 0x41);
    let small_first = encoded_frame(&small, 5, 0);
    let small_final = encoded_frame(&small, 5, 1);
    let large = patterned(20, 0x71);
    let large_first = encoded_frame(&large, 10, 0);
    let large_final = encoded_frame(&large, 10, 1);

    let mut forward_backing = storage(0xcc);
    let mut forward = Reassembler::new(&mut forward_backing);
    forward.submit(&small_first).unwrap();
    assert_eq!(
        forward.submit(&large_final),
        Err(BbqrError::FinalPartTooLarge)
    );
    assert!(forward.submit(&small_final).unwrap().complete);
    assert_eq!(forward.payload().unwrap(), small);

    let mut reverse_backing = storage(0xcc);
    let mut reverse = Reassembler::new(&mut reverse_backing);
    reverse.submit(&large_final).unwrap();
    assert_eq!(
        reverse.submit(&small_first),
        Err(BbqrError::FinalPartTooLarge)
    );
    assert!(reverse.submit(&large_first).unwrap().complete);
    assert_eq!(reverse.payload().unwrap(), large);

    // The final part may be exactly the common non-final length.
    let equal = patterned(10, 0x91);
    let equal_first = encoded_frame(&equal, 5, 0);
    let equal_final = encoded_frame(&equal, 5, 1);
    let mut equal_backing = storage(0xcc);
    let mut equal_reassembler = Reassembler::new(&mut equal_backing);
    equal_reassembler.submit(&equal_final).unwrap();
    assert!(equal_reassembler.submit(&equal_first).unwrap().complete);
    assert_eq!(equal_reassembler.payload().unwrap(), equal);
}

#[test]
fn impossible_minimum_total_rejects_before_establishment_or_write() {
    // 99 parts with a 2,680-byte non-final imply at least
    // 98 * 2,680 + 1 = 262,641 bytes, beyond the total cap.
    let source = patterned(MAX_PART_DECODED_BYTES + 1, 0x52);
    let mut impossible = encoded_frame(&source, MAX_PART_DECODED_BYTES, 0);
    rewrite_header(&mut impossible, 99, 0);

    let mut backing = storage(0xcc);
    {
        let mut reassembler = Reassembler::new(&mut backing);
        assert_eq!(
            reassembler.submit(&impossible),
            Err(BbqrError::TotalDecodedSizeExceeded)
        );
        assert_eq!(reassembler.payload(), Err(BbqrError::Incomplete));
    }
    assert!(backing.iter().all(|byte| *byte == 0xcc));

    // The rejected first candidate did not silently establish its header.
    // Its charged submission still fits the one-part stream's two-call cap.
    let valid = encoded_frame(b"x", 5, 0);
    let mut recovery_backing = storage(0xcc);
    let mut recovery = Reassembler::new(&mut recovery_backing);
    assert_eq!(
        recovery.submit(&impossible),
        Err(BbqrError::TotalDecodedSizeExceeded)
    );
    assert!(recovery.submit(&valid).unwrap().complete);
    assert_eq!(recovery.payload().unwrap(), b"x");
}

#[test]
fn final_first_minimum_geometry_can_recover_after_oversized_candidate() {
    let source = patterned(MAX_PART_DECODED_BYTES + 1, 0x62);
    let mut final_first = encoded_frame(&source, MAX_PART_DECODED_BYTES, 1);
    rewrite_header(&mut final_first, 99, 98);

    let mut oversized_nonfinal = encoded_frame(&source, MAX_PART_DECODED_BYTES, 0);
    rewrite_header(&mut oversized_nonfinal, 99, 0);

    let five_byte_source = patterned(496, 0x72);
    let mut valid_nonfinal = encoded_frame(&five_byte_source, 5, 0);
    rewrite_header(&mut valid_nonfinal, 99, 0);

    let mut backing = storage(0xcc);
    let mut reassembler = Reassembler::new(&mut backing);
    assert_progress(
        reassembler.submit(&final_first).unwrap(),
        99,
        1,
        0,
        1,
        1,
        false,
        false,
    );
    assert_eq!(
        reassembler.submit(&oversized_nonfinal),
        Err(BbqrError::TotalDecodedSizeExceeded)
    );
    let progress = reassembler.submit(&valid_nonfinal).unwrap();
    assert_progress(progress, 99, 2, 0, 3, 6, false, false);
    assert_eq!(reassembler.payload(), Err(BbqrError::Incomplete));
}

#[test]
fn maximum_payload_and_all_256_receipt_bits_round_trip_in_reverse() {
    const PART_LEN: usize = 1_025;

    let payload = patterned(MAX_TOTAL_DECODED_BYTES, 0xa1);
    assert_eq!(encoded_part_count(payload.len(), PART_LEN), Ok(256));
    let mut backing = storage(0xcc);
    let mut reassembler = Reassembler::new(&mut backing);
    let mut last_progress = None;
    for index in (0u16..256).rev() {
        let frame = encoded_frame(&payload, PART_LEN, index);
        last_progress = Some(reassembler.submit(&frame).unwrap());
    }
    let progress = last_progress.unwrap();
    assert_progress(
        progress,
        256,
        256,
        0,
        256,
        MAX_TOTAL_DECODED_BYTES,
        false,
        true,
    );
    assert_eq!(reassembler.payload().unwrap(), payload);
}
