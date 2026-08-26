#![no_main]

use libfuzzer_sys::fuzz_target;
use qk_bbqr::{
    encode_frame, encoded_part_count, BbqrError, Reassembler, ReassemblyProgress,
    MAX_DECLARED_PARTS, MAX_FRAME_TEXT_BYTES, MAX_PART_DECODED_BYTES, MAX_SUBMISSIONS,
    MAX_TOTAL_DECODED_BYTES,
};

const BACKING_SENTINEL: u8 = 0xa5;
const MAX_SEQUENCE_FRAMES: usize = 64;
const MAX_STRUCTURED_PAYLOAD: usize = 4_096;
const VALID_PART_LENGTHS: [usize; 10] = [
    5,
    10,
    20,
    40,
    80,
    160,
    320,
    640,
    1_025,
    MAX_PART_DECODED_BYTES,
];

fn assert_named_error(error: BbqrError) {
    match error {
        BbqrError::EmptyPayload
        | BbqrError::PayloadTooLarge
        | BbqrError::InvalidNonFinalPartLength
        | BbqrError::TooManyParts
        | BbqrError::PartIndexOutOfRange
        | BbqrError::FrameTooShort
        | BbqrError::FrameTooLarge
        | BbqrError::InvalidMagic
        | BbqrError::UnsupportedEncoding
        | BbqrError::UnsupportedFileType
        | BbqrError::InvalidDeclaredPartCount
        | BbqrError::DeclaredPartCountExceeded
        | BbqrError::InvalidPartIndex
        | BbqrError::EmptyPart
        | BbqrError::Base32PaddingForbidden
        | BbqrError::MalformedBase32Symbol
        | BbqrError::NonCanonicalBase32Length
        | BbqrError::NonCanonicalBase32Padding
        | BbqrError::NonFinalPartLengthNotMultipleOfFive
        | BbqrError::StreamEncodingMismatch
        | BbqrError::StreamFileTypeMismatch
        | BbqrError::StreamPartCountMismatch
        | BbqrError::NonUniformPartLength
        | BbqrError::FinalPartTooLarge
        | BbqrError::TotalDecodedSizeExceeded
        | BbqrError::ConflictingDuplicate
        | BbqrError::DuplicateWorkExceeded
        | BbqrError::SubmissionWorkExceeded
        | BbqrError::Incomplete
        | BbqrError::AlreadyComplete => {}
    }
}

fn frame(payload: &[u8], part_len: usize, index: u16) -> Vec<u8> {
    let mut output = [0xa5; MAX_FRAME_TEXT_BYTES];
    let length = encode_frame(payload, part_len, index, &mut output)
        .expect("structured target input must encode");
    assert!(output[length..].iter().all(|byte| *byte == 0xa5));
    output[..length].to_vec()
}

fn base36_pair(value: u16) -> [u8; 2] {
    fn symbol(value: u8) -> u8 {
        match value {
            0..=9 => b'0' + value,
            10..=35 => b'A' + value - 10,
            _ => unreachable!("base36 value is bounded"),
        }
    }
    [symbol((value / 36) as u8), symbol((value % 36) as u8)]
}

fn rewrite_header(frame: &mut [u8], declared_parts: u16, part_index: u16) {
    frame[4..6].copy_from_slice(&base36_pair(declared_parts));
    frame[6..8].copy_from_slice(&base36_pair(part_index));
}

fn assert_progress(progress: ReassemblyProgress) {
    assert!((1..=MAX_DECLARED_PARTS as u16).contains(&progress.declared_parts));
    assert!(progress.received_parts <= progress.declared_parts);
    assert!(progress.identical_duplicates <= progress.declared_parts);
    assert!(usize::from(progress.submissions) <= usize::from(progress.declared_parts) * 2);
    assert!(progress.decoded_bytes <= MAX_TOTAL_DECODED_BYTES);
    assert_eq!(
        progress.complete,
        progress.received_parts == progress.declared_parts
    );
    if progress.was_duplicate {
        assert!(progress.identical_duplicates > 0);
    }
}

fn raw_once(
    frame_bytes: &[u8],
    backing: &mut [u8; MAX_TOTAL_DECODED_BYTES],
) -> (
    Result<ReassemblyProgress, BbqrError>,
    Result<Vec<u8>, BbqrError>,
) {
    backing.fill(BACKING_SENTINEL);
    let (result, payload) = {
        let mut reassembler = Reassembler::new(backing);
        let result = reassembler.submit(frame_bytes);
        let payload = reassembler.payload().map(<[u8]>::to_vec);
        (result, payload)
    };
    if result.is_err() {
        assert!(backing.iter().all(|byte| *byte == BACKING_SENTINEL));
    }
    (result, payload)
}

fn exercise_raw(frame_bytes: &[u8], backing: &mut [u8; MAX_TOTAL_DECODED_BYTES]) {
    let first = raw_once(frame_bytes, backing);
    let repeated = raw_once(frame_bytes, backing);
    assert_eq!(first, repeated);
    match first.0 {
        Ok(progress) => {
            assert_progress(progress);
            assert_eq!(first.1.is_ok(), progress.complete);
        }
        Err(error) => assert_named_error(error),
    }
}

fn sequence_once(
    data: &[u8],
    backing: &mut [u8; MAX_TOTAL_DECODED_BYTES],
) -> (
    Vec<Result<ReassemblyProgress, BbqrError>>,
    Result<Vec<u8>, BbqrError>,
) {
    backing.fill(BACKING_SENTINEL);
    let mut reassembler = Reassembler::new(backing);
    let mut outcomes = Vec::new();
    let mut cursor = 0usize;

    while cursor + 2 <= data.len() && outcomes.len() < MAX_SEQUENCE_FRAMES {
        let requested = usize::from(u16::from_be_bytes([data[cursor], data[cursor + 1]]));
        cursor += 2;
        let frame_len = requested.min(data.len() - cursor);
        let outcome = reassembler.submit(&data[cursor..cursor + frame_len]);
        cursor += frame_len;

        match outcome {
            Ok(progress) => {
                assert_progress(progress);
                if progress.complete {
                    assert_eq!(
                        reassembler.payload().map(<[u8]>::len),
                        Ok(progress.decoded_bytes)
                    );
                } else {
                    assert_eq!(reassembler.payload(), Err(BbqrError::Incomplete));
                }
            }
            Err(BbqrError::AlreadyComplete) => {
                assert!(reassembler.payload().is_ok());
            }
            Err(error) => {
                assert_named_error(error);
                assert_eq!(reassembler.payload(), Err(BbqrError::Incomplete));
            }
        }
        outcomes.push(outcome);

        if requested > frame_len {
            break;
        }
    }

    let payload = reassembler.payload().map(<[u8]>::to_vec);
    (outcomes, payload)
}

fn exercise_sequence(data: &[u8], backing: &mut [u8; MAX_TOTAL_DECODED_BYTES]) {
    let first = sequence_once(data, backing);
    let repeated = sequence_once(data, backing);
    assert_eq!(first, repeated);
}

fn run_generated(
    payload: &[u8],
    requested_part_len: usize,
    selector: u8,
    backing: &mut [u8; MAX_TOTAL_DECODED_BYTES],
) -> Vec<u8> {
    let minimum = payload.len().div_ceil(MAX_DECLARED_PARTS).max(1);
    let minimum_multiple_of_five = minimum.div_ceil(5) * 5;
    let part_len = requested_part_len.max(minimum_multiple_of_five);
    assert!(part_len <= MAX_PART_DECODED_BYTES);
    let count = encoded_part_count(payload.len(), part_len)
        .expect("structured payload geometry must stay within all caps");
    let frames: Vec<Vec<u8>> = (0..count)
        .map(|index| frame(payload, part_len, index))
        .collect();

    let mut order: Vec<usize> = (0..usize::from(count)).collect();
    match selector % 3 {
        0 => order.reverse(),
        1 if order.len() > 1 => {
            let amount = usize::from(selector) % order.len();
            order.rotate_left(amount);
        }
        _ => {}
    }

    let mut reassembler = Reassembler::new(backing);

    for (position, index) in order.iter().copied().enumerate() {
        let progress = reassembler
            .submit(&frames[index])
            .expect("canonical generated frames must be accepted");
        assert_progress(progress);

        if position == 0 && count > 1 {
            let duplicate = reassembler
                .submit(&frames[index])
                .expect("one identical duplicate is within work caps");
            assert_progress(duplicate);
            assert!(duplicate.was_duplicate);
        }
    }

    let assembled = reassembler
        .payload()
        .expect("all indices were submitted")
        .to_vec();
    assert_eq!(assembled, payload);
    assert_eq!(
        reassembler.submit(b"not a frame"),
        Err(BbqrError::AlreadyComplete)
    );
    assembled
}

fn exercise_generated(
    payload: &[u8],
    requested_part_len: usize,
    selector: u8,
    backing: &mut [u8; MAX_TOTAL_DECODED_BYTES],
) {
    let first = run_generated(payload, requested_part_len, selector, backing);
    let repeated = run_generated(payload, requested_part_len, selector, backing);
    assert_eq!(first, repeated);
}

fn exercise_established_rejections(backing: &mut [u8; MAX_TOTAL_DECODED_BYTES]) {
    let payload: Vec<u8> = (0..31)
        .map(|index| (index as u8).wrapping_mul(29).wrapping_add(7))
        .collect();
    let frames: Vec<Vec<u8>> = (0..4).map(|index| frame(&payload, 10, index)).collect();
    let mut alternate = payload.clone();
    alternate[0] ^= 0x5a;
    let conflict = frame(&alternate, 10, 0);

    let mut reassembler = Reassembler::new(backing);
    assert_progress(reassembler.submit(&frames[0]).expect("first frame"));

    let mut wrong_encoding = frames[1].clone();
    wrong_encoding[2] = b'H';
    assert_eq!(
        reassembler.submit(&wrong_encoding),
        Err(BbqrError::StreamEncodingMismatch)
    );

    let mut wrong_type = frames[1].clone();
    wrong_type[3] = b'U';
    assert_eq!(
        reassembler.submit(&wrong_type),
        Err(BbqrError::StreamFileTypeMismatch)
    );

    let mut wrong_count = frames[1].clone();
    wrong_count[4..6].copy_from_slice(b"05");
    assert_eq!(
        reassembler.submit(&wrong_count),
        Err(BbqrError::StreamPartCountMismatch)
    );
    assert_eq!(
        reassembler.submit(&conflict),
        Err(BbqrError::ConflictingDuplicate)
    );

    for candidate in &frames[1..] {
        assert_progress(
            reassembler
                .submit(candidate)
                .expect("rejections must not corrupt assembled content"),
        );
    }
    assert_eq!(reassembler.payload().unwrap(), payload);
}

fn exercise_geometry_rejections(backing: &mut [u8; MAX_TOTAL_DECODED_BYTES]) {
    let ten_byte_payload: Vec<u8> = (0..31)
        .map(|index| (index as u8).wrapping_mul(17).wrapping_add(3))
        .collect();
    let canonical: Vec<Vec<u8>> = (0..4)
        .map(|index| frame(&ten_byte_payload, 10, index))
        .collect();
    let five_byte_payload: Vec<u8> = (0..16)
        .map(|index| (index as u8).wrapping_mul(23).wrapping_add(5))
        .collect();
    let nonuniform = frame(&five_byte_payload, 5, 1);

    let mut reassembler = Reassembler::new(backing);
    assert_progress(reassembler.submit(&canonical[0]).unwrap());
    assert_eq!(
        reassembler.submit(&nonuniform),
        Err(BbqrError::NonUniformPartLength)
    );
    assert_eq!(reassembler.payload(), Err(BbqrError::Incomplete));
    for candidate in &canonical[1..] {
        assert_progress(reassembler.submit(candidate).unwrap());
    }
    assert_eq!(reassembler.payload().unwrap(), ten_byte_payload);

    let long_final_payload: Vec<u8> = (0..39)
        .map(|index| (index as u8).wrapping_mul(31).wrapping_add(7))
        .collect();
    let oversized_final = frame(&long_final_payload, 10, 3);
    let short_geometry: Vec<Vec<u8>> = (0..4)
        .map(|index| frame(&five_byte_payload, 5, index))
        .collect();
    let mut reassembler = Reassembler::new(backing);
    assert_progress(reassembler.submit(&short_geometry[0]).unwrap());
    assert_eq!(
        reassembler.submit(&oversized_final),
        Err(BbqrError::FinalPartTooLarge)
    );
    assert_eq!(reassembler.payload(), Err(BbqrError::Incomplete));

    let over_total_payload = [0x3cu8; 1_030];
    let mut over_total = frame(&over_total_payload, 1_030, 0);
    rewrite_header(&mut over_total, MAX_DECLARED_PARTS as u16, 0);
    let mut reassembler = Reassembler::new(backing);
    assert_eq!(
        reassembler.submit(&over_total),
        Err(BbqrError::TotalDecodedSizeExceeded)
    );
    assert_eq!(reassembler.payload(), Err(BbqrError::Incomplete));
}

fn exercise_selected_transition(data: &[u8], backing: &mut [u8; MAX_TOTAL_DECODED_BYTES]) {
    let mut payload = [0u8; 31];
    for (index, byte) in payload.iter_mut().enumerate() {
        *byte = data
            .get(index + 1)
            .copied()
            .unwrap_or((index as u8).wrapping_mul(37).wrapping_add(13));
    }
    let canonical: Vec<Vec<u8>> = (0..4).map(|index| frame(&payload, 10, index)).collect();
    let operation = data.first().copied().unwrap_or(0) % 10;

    let mut reassembler = Reassembler::new(backing);
    assert_progress(reassembler.submit(&canonical[0]).unwrap());
    match operation {
        0 => assert_progress(reassembler.submit(&canonical[1]).unwrap()),
        1 => {
            let duplicate = reassembler.submit(&canonical[0]).unwrap();
            assert_progress(duplicate);
            assert!(duplicate.was_duplicate);
        }
        2 => {
            let mut alternate = payload;
            alternate[0] ^= 0x80;
            assert_eq!(
                reassembler.submit(&frame(&alternate, 10, 0)),
                Err(BbqrError::ConflictingDuplicate)
            );
        }
        3 => {
            let mut candidate = canonical[1].clone();
            candidate[2] = b'H';
            assert_eq!(
                reassembler.submit(&candidate),
                Err(BbqrError::StreamEncodingMismatch)
            );
        }
        4 => {
            let mut candidate = canonical[1].clone();
            candidate[3] = b'U';
            assert_eq!(
                reassembler.submit(&candidate),
                Err(BbqrError::StreamFileTypeMismatch)
            );
        }
        5 => {
            let mut candidate = canonical[1].clone();
            rewrite_header(&mut candidate, 5, 1);
            assert_eq!(
                reassembler.submit(&candidate),
                Err(BbqrError::StreamPartCountMismatch)
            );
        }
        6 => {
            let alternate = [0x6du8; 16];
            assert_eq!(
                reassembler.submit(&frame(&alternate, 5, 1)),
                Err(BbqrError::NonUniformPartLength)
            );
        }
        7 => {
            let alternate = [0x93u8; 56];
            assert_eq!(
                reassembler.submit(&frame(&alternate, 15, 3)),
                Err(BbqrError::FinalPartTooLarge)
            );
        }
        8 => {
            let mut candidate = canonical[1].clone();
            *candidate.last_mut().expect("body is nonempty") = b'!';
            assert_eq!(
                reassembler.submit(&candidate),
                Err(BbqrError::MalformedBase32Symbol)
            );
        }
        9 => {
            let mut candidate = frame(b"x", 5, 0);
            rewrite_header(&mut candidate, 4, 1);
            assert_eq!(
                reassembler.submit(&candidate),
                Err(BbqrError::NonFinalPartLengthNotMultipleOfFive)
            );
        }
        _ => unreachable!(),
    }
    assert_eq!(reassembler.payload(), Err(BbqrError::Incomplete));

    for candidate in &canonical[1..] {
        assert_progress(
            reassembler
                .submit(candidate)
                .expect("selected transition must not corrupt the candidate stream"),
        );
    }
    assert_eq!(reassembler.payload().unwrap(), payload);
}

fn exercise_exact_total_cap(run: bool, backing: &mut [u8; MAX_TOTAL_DECODED_BYTES]) {
    if !run {
        return;
    }
    let mut payload = [0u8; MAX_TOTAL_DECODED_BYTES];
    for (index, byte) in payload.iter_mut().enumerate() {
        *byte = (index as u8).wrapping_mul(19).wrapping_add(11);
    }
    assert_eq!(
        encoded_part_count(payload.len(), 1_025),
        Ok(MAX_DECLARED_PARTS as u16)
    );
    let mut reassembler = Reassembler::new(backing);
    for index in 0..MAX_DECLARED_PARTS as u16 {
        let mut encoded = [BACKING_SENTINEL; MAX_FRAME_TEXT_BYTES];
        let encoded_len = encode_frame(&payload, 1_025, index, &mut encoded)
            .expect("exact-cap frame must encode");
        let progress = reassembler
            .submit(&encoded[..encoded_len])
            .expect("exact-cap canonical frame must be accepted");
        assert_progress(progress);
    }
    assert_eq!(reassembler.payload().unwrap(), payload);
}

fn exercise_work_caps(run_absolute_cap: bool, backing: &mut [u8; MAX_TOTAL_DECODED_BYTES]) {
    let payload = [0u8, 1, 2, 3, 4, 5];
    let first = frame(&payload, 5, 0);
    {
        let mut reassembler = Reassembler::new(backing);
        assert_progress(reassembler.submit(&first).unwrap());
        for _ in 0..3 {
            assert_eq!(reassembler.submit(b"x"), Err(BbqrError::FrameTooShort));
        }
        assert_eq!(
            reassembler.submit(&first),
            Err(BbqrError::SubmissionWorkExceeded)
        );
    }

    let payload = [0u8; 11];
    let first = frame(&payload, 5, 0);
    {
        let mut reassembler = Reassembler::new(backing);
        assert_progress(reassembler.submit(&first).unwrap());
        for expected_duplicates in 1..=3 {
            let progress = reassembler.submit(&first).unwrap();
            assert_progress(progress);
            assert_eq!(progress.identical_duplicates, expected_duplicates);
        }
        assert_eq!(
            reassembler.submit(&first),
            Err(BbqrError::DuplicateWorkExceeded)
        );
    }

    if run_absolute_cap {
        let mut reassembler = Reassembler::new(backing);
        for _ in 0..MAX_SUBMISSIONS {
            assert_eq!(reassembler.submit(b"x"), Err(BbqrError::FrameTooShort));
        }
        assert_eq!(
            reassembler.submit(b"B$2P0100AA"),
            Err(BbqrError::SubmissionWorkExceeded)
        );
    }
}

fuzz_target!(|data: &[u8]| {
    let mut backing = [BACKING_SENTINEL; MAX_TOTAL_DECODED_BYTES];
    let raw_len = data.len().min(MAX_FRAME_TEXT_BYTES + 1);
    exercise_raw(&data[..raw_len], &mut backing);
    exercise_sequence(data, &mut backing);

    let payload = if data.is_empty() {
        b"\x70\x73\x62\x74\xff\x00\x01\x02\x03\x04\x05".as_slice()
    } else {
        &data[..data.len().min(MAX_STRUCTURED_PAYLOAD)]
    };
    let selector = data.first().copied().unwrap_or(0);
    let requested_part_len = VALID_PART_LENGTHS
        [usize::from(data.get(1).copied().unwrap_or(0)) % VALID_PART_LENGTHS.len()];
    exercise_generated(payload, requested_part_len, selector, &mut backing);
    exercise_established_rejections(&mut backing);
    exercise_geometry_rejections(&mut backing);
    exercise_selected_transition(data, &mut backing);
    let run_cap_edges = data == b"QK-M22-EXACT-TOTAL-CAP\n";
    exercise_work_caps(run_cap_edges, &mut backing);
    exercise_exact_total_cap(run_cap_edges, &mut backing);
});
