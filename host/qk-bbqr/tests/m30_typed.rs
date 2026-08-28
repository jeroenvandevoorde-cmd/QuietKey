//! M30 typed P/T framing and stream-separation behavior.

use qk_bbqr::{
    decode_frame, decode_typed_frame, encode_frame, encode_typed_frame, BbqrError, BbqrFileType,
    Reassembler, MAX_DECLARED_PARTS, MAX_FRAME_TEXT_BYTES, MAX_PART_DECODED_BYTES, MAX_SUBMISSIONS,
    MAX_TOTAL_DECODED_BYTES,
};

const FILE_TYPES: [BbqrFileType; 2] = [BbqrFileType::Psbt, BbqrFileType::Transaction];

fn encode_typed(file_type: BbqrFileType, payload: &[u8], index: u16) -> Vec<u8> {
    encode_typed_with_part_len(file_type, payload, 5, index)
}

fn encode_typed_with_part_len(
    file_type: BbqrFileType,
    payload: &[u8],
    part_len: usize,
    index: u16,
) -> Vec<u8> {
    let mut frame = [0xa5; MAX_FRAME_TEXT_BYTES];
    let length = encode_typed_frame(file_type, payload, part_len, index, &mut frame).unwrap();
    assert!(frame[length..].iter().all(|byte| *byte == 0xa5));
    frame[..length].to_vec()
}

fn typed_literal(file_type: BbqrFileType, p_frame: &[u8]) -> Vec<u8> {
    let mut frame = p_frame.to_vec();
    if frame.len() >= 4 {
        frame[3] = match file_type {
            BbqrFileType::Psbt => b'P',
            BbqrFileType::Transaction => b'T',
        };
    }
    frame
}

fn assert_typed_decode_rejection(file_type: BbqrFileType, p_frame: &[u8], expected: BbqrError) {
    let frame = typed_literal(file_type, p_frame);
    let mut output = [0x5a; MAX_PART_DECODED_BYTES];
    let before = output;
    assert_eq!(
        decode_typed_frame(file_type, &frame, &mut output),
        Err(expected),
        "file type {file_type:?}"
    );
    assert_eq!(output, before, "rejection changed output for {file_type:?}");
}

fn base36_pair(value: u16) -> [u8; 2] {
    fn symbol(value: u8) -> u8 {
        match value {
            0..=9 => b'0' + value,
            10..=35 => b'A' + value - 10,
            _ => unreachable!(),
        }
    }
    [symbol((value / 36) as u8), symbol((value % 36) as u8)]
}

fn rewrite_header(frame: &mut [u8], count: u16, index: u16) {
    frame[4..6].copy_from_slice(&base36_pair(count));
    frame[6..8].copy_from_slice(&base36_pair(index));
}

fn patterned(length: usize, seed: u8) -> Vec<u8> {
    (0..length)
        .map(|index| seed.wrapping_add((index as u8).wrapping_mul(29)))
        .collect()
}

fn storage() -> Box<[u8; MAX_TOTAL_DECODED_BYTES]> {
    vec![0xcc; MAX_TOTAL_DECODED_BYTES]
        .into_boxed_slice()
        .try_into()
        .expect("exact fixed storage length")
}

#[test]
fn typed_encoding_differs_only_at_the_ratified_file_type_byte() {
    let payload = [0u8, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10];
    let expected_p: [&[u8]; 3] = [b"B$2P0300AAAQEAYE", b"B$2P0301AUDAOCAJ", b"B$2P0302BI"];
    let expected_t: [&[u8]; 3] = [b"B$2T0300AAAQEAYE", b"B$2T0301AUDAOCAJ", b"B$2T0302BI"];

    for index in 0..3 {
        let p = encode_typed(BbqrFileType::Psbt, &payload, index);
        let t = encode_typed(BbqrFileType::Transaction, &payload, index);
        assert_eq!(p, expected_p[usize::from(index)]);
        assert_eq!(t, expected_t[usize::from(index)]);
        assert_eq!(&p[..3], &t[..3]);
        assert_ne!(p[3], t[3]);
        assert_eq!(&p[4..], &t[4..]);
    }
}

#[test]
fn original_operations_remain_exact_type_p_wrappers() {
    let payload = b"public psbt-like bytes";
    let mut legacy = [0xa5; MAX_FRAME_TEXT_BYTES];
    let mut typed = [0xa5; MAX_FRAME_TEXT_BYTES];
    let legacy_len = encode_frame(payload, 10, 1, &mut legacy).unwrap();
    let typed_len = encode_typed_frame(BbqrFileType::Psbt, payload, 10, 1, &mut typed).unwrap();
    assert_eq!(legacy_len, typed_len);
    assert_eq!(legacy, typed);

    let mut legacy_part = [0x5a; MAX_PART_DECODED_BYTES];
    let mut typed_part = [0x5a; MAX_PART_DECODED_BYTES];
    let legacy_metadata = decode_frame(&legacy[..legacy_len], &mut legacy_part).unwrap();
    let typed_metadata =
        decode_typed_frame(BbqrFileType::Psbt, &legacy[..legacy_len], &mut typed_part).unwrap();
    assert_eq!(legacy_metadata, typed_metadata);
    assert_eq!(legacy_part, typed_part);
}

#[test]
fn standalone_decode_requires_the_caller_selected_type_without_output_mutation() {
    let payload = b"ready-to-send transaction bytes";
    let p = encode_typed(BbqrFileType::Psbt, payload, 0);
    let t = encode_typed(BbqrFileType::Transaction, payload, 0);

    let mut output = [0x5a; MAX_PART_DECODED_BYTES];
    let before = output;
    assert_eq!(
        decode_typed_frame(BbqrFileType::Transaction, &p, &mut output),
        Err(BbqrError::UnsupportedFileType)
    );
    assert_eq!(output, before);
    assert_eq!(
        decode_typed_frame(BbqrFileType::Psbt, &t, &mut output),
        Err(BbqrError::UnsupportedFileType)
    );
    assert_eq!(output, before);

    let metadata = decode_typed_frame(BbqrFileType::Transaction, &t, &mut output).unwrap();
    assert_eq!(&output[..metadata.decoded_len], &payload[..5]);
}

#[test]
fn transaction_stream_round_trips_out_of_order_under_unchanged_geometry() {
    let payload = b"0123456789ready-to-send-transaction";
    let frames: Vec<_> = (0..7)
        .map(|index| encode_typed(BbqrFileType::Transaction, payload, index))
        .collect();
    let mut backing = storage();
    let mut reassembler = Reassembler::new_typed(BbqrFileType::Transaction, &mut backing);

    for index in [6usize, 2, 0, 4, 1, 5, 3] {
        reassembler.submit(&frames[index]).unwrap();
    }
    assert_eq!(reassembler.payload().unwrap(), payload);
}

#[test]
fn fresh_and_established_cross_type_rejections_keep_distinct_precedence() {
    let payload = b"0123456789";
    let p0 = encode_typed(BbqrFileType::Psbt, payload, 0);
    let t0 = encode_typed(BbqrFileType::Transaction, payload, 0);
    let t1 = encode_typed(BbqrFileType::Transaction, payload, 1);

    let mut fresh_backing = storage();
    let mut fresh = Reassembler::new_typed(BbqrFileType::Transaction, &mut fresh_backing);
    assert_eq!(fresh.submit(&p0), Err(BbqrError::UnsupportedFileType));
    assert_eq!(fresh.submit(&t0).unwrap().submissions, 2);

    let mut wrong_type_and_body = p0.clone();
    *wrong_type_and_body.last_mut().unwrap() = b'!';
    assert_eq!(
        fresh.submit(&wrong_type_and_body),
        Err(BbqrError::StreamFileTypeMismatch)
    );
    assert!(fresh.submit(&t1).unwrap().complete);
    assert_eq!(fresh.payload().unwrap(), payload);
}

#[test]
fn typed_encode_rejection_preserves_the_entire_output() {
    let payload = b"transaction";
    let mut output = [0xa5; MAX_FRAME_TEXT_BYTES];
    let before = output;
    assert_eq!(
        encode_typed_frame(BbqrFileType::Transaction, payload, 4, 0, &mut output),
        Err(BbqrError::InvalidNonFinalPartLength)
    );
    assert_eq!(output, before);
}

#[test]
fn every_encoder_and_standalone_rejection_is_file_type_symmetric() {
    for file_type in FILE_TYPES {
        let encode_rejection =
            |payload: &[u8], part_len: usize, index: u16, expected: BbqrError| {
                let mut output = [0xa5; MAX_FRAME_TEXT_BYTES];
                let before = output;
                assert_eq!(
                    encode_typed_frame(file_type, payload, part_len, index, &mut output),
                    Err(expected),
                    "file type {file_type:?}"
                );
                assert_eq!(output, before);
            };

        encode_rejection(&[], 0, u16::MAX, BbqrError::EmptyPayload);
        encode_rejection(
            &vec![0; MAX_TOTAL_DECODED_BYTES + 1],
            0,
            u16::MAX,
            BbqrError::PayloadTooLarge,
        );
        encode_rejection(b"x", 4, u16::MAX, BbqrError::InvalidNonFinalPartLength);
        encode_rejection(&vec![0; 1_281], 5, u16::MAX, BbqrError::TooManyParts);
        encode_rejection(b"foobar", 5, 2, BbqrError::PartIndexOutOfRange);

        assert_typed_decode_rejection(file_type, b"", BbqrError::FrameTooShort);
        assert_typed_decode_rejection(file_type, b"B$2P010", BbqrError::FrameTooShort);
        assert_typed_decode_rejection(
            file_type,
            &vec![b'!'; MAX_FRAME_TEXT_BYTES + 1],
            BbqrError::FrameTooLarge,
        );
        assert_typed_decode_rejection(file_type, b"A$HP0000=", BbqrError::InvalidMagic);
        assert_typed_decode_rejection(file_type, b"B$HP0000=", BbqrError::UnsupportedEncoding);
        let other_type = match file_type {
            BbqrFileType::Psbt => BbqrFileType::Transaction,
            BbqrFileType::Transaction => BbqrFileType::Psbt,
        };
        let unsupported = typed_literal(other_type, b"B$2P0000=");
        let mut unsupported_output = [0x5a; MAX_PART_DECODED_BYTES];
        assert_eq!(
            decode_typed_frame(file_type, &unsupported, &mut unsupported_output),
            Err(BbqrError::UnsupportedFileType)
        );
        assert_typed_decode_rejection(file_type, b"B$2P!100=", BbqrError::InvalidDeclaredPartCount);
        assert_typed_decode_rejection(file_type, b"B$2P0000=", BbqrError::InvalidDeclaredPartCount);
        assert_typed_decode_rejection(
            file_type,
            b"B$2P7500=",
            BbqrError::DeclaredPartCountExceeded,
        );
        assert_typed_decode_rejection(file_type, b"B$2P01!0=", BbqrError::InvalidPartIndex);
        assert_typed_decode_rejection(file_type, b"B$2P0101=", BbqrError::InvalidPartIndex);
        assert_typed_decode_rejection(file_type, b"B$2P0100", BbqrError::EmptyPart);
        assert_typed_decode_rejection(
            file_type,
            b"B$2P0100MY======",
            BbqrError::Base32PaddingForbidden,
        );
        assert_typed_decode_rejection(file_type, b"B$2P0100m", BbqrError::MalformedBase32Symbol);
        assert_typed_decode_rejection(file_type, b"B$2P0100A", BbqrError::NonCanonicalBase32Length);
        assert_typed_decode_rejection(
            file_type,
            b"B$2P0100AB",
            BbqrError::NonCanonicalBase32Padding,
        );
        assert_typed_decode_rejection(
            file_type,
            b"B$2P0200AA",
            BbqrError::NonFinalPartLengthNotMultipleOfFive,
        );
    }
}

#[test]
fn every_stream_rejection_and_work_boundary_is_file_type_symmetric() {
    for file_type in FILE_TYPES {
        let payload = patterned(11, 0x21);
        let frames: Vec<_> = (0..3)
            .map(|index| encode_typed(file_type, &payload, index))
            .collect();
        let mut backing = storage();
        let mut stream = Reassembler::new_typed(file_type, &mut backing);
        assert_eq!(stream.payload(), Err(BbqrError::Incomplete));
        stream.submit(&frames[0]).unwrap();

        let mut wrong_encoding = frames[1].clone();
        wrong_encoding[2] = b'H';
        *wrong_encoding.last_mut().unwrap() = b'!';
        assert_eq!(
            stream.submit(&wrong_encoding),
            Err(BbqrError::StreamEncodingMismatch)
        );

        let mut wrong_type = frames[1].clone();
        wrong_type[3] = match file_type {
            BbqrFileType::Psbt => b'T',
            BbqrFileType::Transaction => b'P',
        };
        *wrong_type.last_mut().unwrap() = b'!';
        assert_eq!(
            stream.submit(&wrong_type),
            Err(BbqrError::StreamFileTypeMismatch)
        );

        let mut wrong_count = frames[1].clone();
        rewrite_header(&mut wrong_count, 4, 1);
        *wrong_count.last_mut().unwrap() = b'!';
        assert_eq!(
            stream.submit(&wrong_count),
            Err(BbqrError::StreamPartCountMismatch)
        );

        let alternate = patterned(11, 0x91);
        let conflict = encode_typed(file_type, &alternate, 0);
        assert_eq!(
            stream.submit(&conflict),
            Err(BbqrError::ConflictingDuplicate)
        );
        stream.submit(&frames[1]).unwrap();
        assert_eq!(
            stream.submit(&frames[2]),
            Err(BbqrError::SubmissionWorkExceeded)
        );

        let mut duplicate_backing = storage();
        let mut duplicates = Reassembler::new_typed(file_type, &mut duplicate_backing);
        duplicates.submit(&frames[0]).unwrap();
        for _ in 0..3 {
            duplicates.submit(&frames[0]).unwrap();
        }
        assert_eq!(
            duplicates.submit(&frames[0]),
            Err(BbqrError::DuplicateWorkExceeded)
        );

        let different_geometry = patterned(21, 0x41);
        let wrong_non_final = encode_typed_with_part_len(file_type, &different_geometry, 10, 1);
        let mut geometry_backing = storage();
        let mut geometry = Reassembler::new_typed(file_type, &mut geometry_backing);
        geometry.submit(&frames[0]).unwrap();
        assert_eq!(
            geometry.submit(&wrong_non_final),
            Err(BbqrError::NonUniformPartLength)
        );

        let short = patterned(6, 0x51);
        let short_first = encode_typed(file_type, &short, 0);
        let long = patterned(20, 0x61);
        let long_final = encode_typed_with_part_len(file_type, &long, 10, 1);
        let mut final_backing = storage();
        let mut final_size = Reassembler::new_typed(file_type, &mut final_backing);
        final_size.submit(&short_first).unwrap();
        assert_eq!(
            final_size.submit(&long_final),
            Err(BbqrError::FinalPartTooLarge)
        );

        let impossible_source = patterned(MAX_PART_DECODED_BYTES + 1, 0x71);
        let mut impossible =
            encode_typed_with_part_len(file_type, &impossible_source, MAX_PART_DECODED_BYTES, 0);
        rewrite_header(&mut impossible, 99, 0);
        let mut total_backing = storage();
        let mut total = Reassembler::new_typed(file_type, &mut total_backing);
        assert_eq!(
            total.submit(&impossible),
            Err(BbqrError::TotalDecodedSizeExceeded)
        );

        let one = encode_typed(file_type, b"x", 0);
        let mut complete_backing = storage();
        let mut complete = Reassembler::new_typed(file_type, &mut complete_backing);
        assert!(complete.submit(&one).unwrap().complete);
        assert_eq!(
            complete.submit(b"not a frame"),
            Err(BbqrError::AlreadyComplete)
        );

        let mut prestream_backing = storage();
        let mut prestream = Reassembler::new_typed(file_type, &mut prestream_backing);
        for _ in 0..MAX_SUBMISSIONS {
            assert_eq!(prestream.submit(b""), Err(BbqrError::FrameTooShort));
        }
        assert_eq!(
            prestream.submit(b""),
            Err(BbqrError::SubmissionWorkExceeded)
        );
    }
}

#[test]
fn all_ratified_cap_acceptance_edges_are_file_type_symmetric() {
    assert_eq!(MAX_DECLARED_PARTS, 256);
    assert_eq!(MAX_PART_DECODED_BYTES, 2_680);
    assert_eq!(MAX_TOTAL_DECODED_BYTES, 262_144);
    assert_eq!(MAX_SUBMISSIONS, 512);

    for file_type in FILE_TYPES {
        let max_part = patterned(MAX_PART_DECODED_BYTES, 0x81);
        let max_frame = encode_typed_with_part_len(file_type, &max_part, MAX_PART_DECODED_BYTES, 0);
        assert_eq!(max_frame.len(), MAX_FRAME_TEXT_BYTES);
        let mut decoded = [0x5a; MAX_PART_DECODED_BYTES];
        let metadata = decode_typed_frame(file_type, &max_frame, &mut decoded).unwrap();
        assert_eq!(metadata.decoded_len, MAX_PART_DECODED_BYTES);
        assert_eq!(decoded, max_part.as_slice());

        let max_count_payload = patterned(1_280, 0x91);
        let max_index = encode_typed(file_type, &max_count_payload, 255);
        let metadata = decode_typed_frame(file_type, &max_index, &mut decoded).unwrap();
        assert_eq!(usize::from(metadata.declared_parts), MAX_DECLARED_PARTS);
        assert_eq!(metadata.part_index, 255);

        const PART_LEN: usize = 1_025;
        let max_payload = patterned(MAX_TOTAL_DECODED_BYTES, 0xa1);
        let mut backing = storage();
        let mut stream = Reassembler::new_typed(file_type, &mut backing);
        for index in (0u16..256).rev() {
            let frame = encode_typed_with_part_len(file_type, &max_payload, PART_LEN, index);
            stream.submit(&frame).unwrap();
        }
        assert_eq!(stream.payload().unwrap(), max_payload);
    }
}
