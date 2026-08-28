#![no_main]

use libfuzzer_sys::fuzz_target;
use qk_bbqr::{
    decode_frame, decode_typed_frame, encode_typed_frame, encoded_part_count, BbqrError,
    BbqrFileType, DecodedFrame, Reassembler, ReassemblyProgress, MAX_DECLARED_PARTS,
    MAX_FRAME_TEXT_BYTES, MAX_PART_DECODED_BYTES, MAX_TOTAL_DECODED_BYTES,
};

const FRAME_SENTINEL: u8 = 0xa5;
const PART_SENTINEL: u8 = 0x5a;
const BACKING_SENTINEL: u8 = 0xc3;
const MAX_PRESENTED_FRAME_BYTES: usize = MAX_FRAME_TEXT_BYTES + 1;
const MAX_STRUCTURED_PAYLOAD: usize = 4_096;
const VALID_PART_LENGTHS: [usize; 10] = [5, 10, 20, 40, 80, 160, 320, 640, 1_025, 2_680];

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
    assert!(!error.to_string().is_empty());
}

fn presented_frame(data: &[u8]) -> &[u8] {
    let candidate = if data.first() == Some(&b'!') {
        let body = &data[1..];
        let end = body
            .iter()
            .position(|byte| *byte == b'\n')
            .unwrap_or(body.len());
        &body[..end]
    } else {
        data
    };
    &candidate[..candidate.len().min(MAX_PRESENTED_FRAME_BYTES)]
}

fn assert_metadata(metadata: DecodedFrame) {
    assert!((1..=MAX_DECLARED_PARTS as u16).contains(&metadata.declared_parts));
    assert!(metadata.part_index < metadata.declared_parts);
    assert!((1..=MAX_PART_DECODED_BYTES).contains(&metadata.decoded_len));
}

fn exercise_presented(frame: &[u8]) {
    let mut first = [PART_SENTINEL; MAX_PART_DECODED_BYTES];
    let first_result = decode_typed_frame(BbqrFileType::Transaction, frame, &mut first);
    let mut repeated = [PART_SENTINEL; MAX_PART_DECODED_BYTES];
    let repeated_result = decode_typed_frame(BbqrFileType::Transaction, frame, &mut repeated);
    assert_eq!(first_result, repeated_result);
    assert_eq!(first, repeated);

    match first_result {
        Ok(metadata) => {
            assert_metadata(metadata);
            assert!(first[metadata.decoded_len..]
                .iter()
                .all(|byte| *byte == PART_SENTINEL));
            assert_eq!(frame[3], b'T');

            let mut wrong_type = [PART_SENTINEL; MAX_PART_DECODED_BYTES];
            assert_eq!(
                decode_frame(frame, &mut wrong_type),
                Err(BbqrError::UnsupportedFileType)
            );
            assert_eq!(wrong_type, [PART_SENTINEL; MAX_PART_DECODED_BYTES]);
        }
        Err(error) => {
            assert_named_error(error);
            assert_eq!(first, [PART_SENTINEL; MAX_PART_DECODED_BYTES]);
        }
    }
}

fn assert_progress(progress: ReassemblyProgress) {
    assert!((1..=MAX_DECLARED_PARTS as u16).contains(&progress.declared_parts));
    assert!(progress.received_parts <= progress.declared_parts);
    assert!(progress.identical_duplicates <= progress.declared_parts);
    assert!(progress.submissions <= progress.declared_parts * 2);
    assert!(progress.decoded_bytes <= MAX_TOTAL_DECODED_BYTES);
    assert_eq!(
        progress.complete,
        progress.received_parts == progress.declared_parts
    );
    if progress.was_duplicate {
        assert!(progress.identical_duplicates > 0);
    }
}

fn encoded_frame(
    file_type: BbqrFileType,
    payload: &[u8],
    part_len: usize,
    part_index: u16,
) -> ([u8; MAX_FRAME_TEXT_BYTES], usize) {
    let mut frame = [FRAME_SENTINEL; MAX_FRAME_TEXT_BYTES];
    let frame_len = encode_typed_frame(file_type, payload, part_len, part_index, &mut frame)
        .expect("bounded structured geometry must encode");
    assert!((9..=MAX_FRAME_TEXT_BYTES).contains(&frame_len));
    assert!(frame[frame_len..]
        .iter()
        .all(|byte| *byte == FRAME_SENTINEL));
    (frame, frame_len)
}

fn exercise_generated(payload: &[u8], requested_part_len: usize, selector: u8) {
    let minimum = payload.len().div_ceil(MAX_DECLARED_PARTS).max(1);
    let part_len = requested_part_len.max(minimum.div_ceil(5) * 5);
    assert!(part_len <= MAX_PART_DECODED_BYTES);
    let part_count = encoded_part_count(payload.len(), part_len)
        .expect("structured payload geometry must remain within all caps");
    let count = usize::from(part_count);
    let rotation = usize::from(selector) % count;
    let reverse = selector & 1 != 0;

    let mut backing = [BACKING_SENTINEL; MAX_TOTAL_DECODED_BYTES];
    let mut reassembler = Reassembler::new_typed(BbqrFileType::Transaction, &mut backing);

    for position in 0..count {
        let ordered = (position + rotation) % count;
        let index = if reverse {
            count - 1 - ordered
        } else {
            ordered
        } as u16;
        let (transaction, transaction_len) =
            encoded_frame(BbqrFileType::Transaction, payload, part_len, index);
        let (psbt, psbt_len) = encoded_frame(BbqrFileType::Psbt, payload, part_len, index);
        assert_eq!(transaction_len, psbt_len);
        assert_eq!(&transaction[..3], b"B$2");
        assert_eq!(transaction[3], b'T');
        assert_eq!(psbt[3], b'P');
        assert_eq!(transaction[4..transaction_len], psbt[4..psbt_len]);

        let mut decoded = [PART_SENTINEL; MAX_PART_DECODED_BYTES];
        let metadata = decode_typed_frame(
            BbqrFileType::Transaction,
            &transaction[..transaction_len],
            &mut decoded,
        )
        .expect("an emitted transaction frame must decode");
        assert_metadata(metadata);
        assert_eq!(metadata.declared_parts, part_count);
        assert_eq!(metadata.part_index, index);
        let start = usize::from(index) * part_len;
        let end = payload.len().min(start + part_len);
        assert_eq!(metadata.decoded_len, end - start);
        assert_eq!(&decoded[..metadata.decoded_len], &payload[start..end]);

        let mut wrong_type = [PART_SENTINEL; MAX_PART_DECODED_BYTES];
        assert_eq!(
            decode_typed_frame(
                BbqrFileType::Transaction,
                &psbt[..psbt_len],
                &mut wrong_type,
            ),
            Err(BbqrError::UnsupportedFileType)
        );
        assert_eq!(wrong_type, [PART_SENTINEL; MAX_PART_DECODED_BYTES]);

        let progress = reassembler
            .submit(&transaction[..transaction_len])
            .expect("every generated transaction frame must be accepted");
        assert_progress(progress);

        if position == 0 && count > 1 {
            assert_eq!(
                reassembler.submit(&psbt[..psbt_len]),
                Err(BbqrError::StreamFileTypeMismatch)
            );
            let duplicate = reassembler
                .submit(&transaction[..transaction_len])
                .expect("one identical duplicate remains inside the work cap");
            assert_progress(duplicate);
            assert!(duplicate.was_duplicate);
        }
    }

    assert_eq!(
        reassembler
            .payload()
            .expect("all generated indices were submitted"),
        payload
    );
    assert_eq!(
        reassembler.submit(b"B$2T0100AA"),
        Err(BbqrError::AlreadyComplete)
    );
}

fn exercise_fixed_rejections() {
    let mut frame = [FRAME_SENTINEL; MAX_FRAME_TEXT_BYTES];
    assert_eq!(
        encode_typed_frame(BbqrFileType::Transaction, &[], 5, 0, &mut frame),
        Err(BbqrError::EmptyPayload)
    );
    assert_eq!(frame, [FRAME_SENTINEL; MAX_FRAME_TEXT_BYTES]);

    let payload = [0u8; 6];
    for invalid_part_len in [0, 1, 4, 6, MAX_PART_DECODED_BYTES + 1] {
        assert_eq!(
            encode_typed_frame(
                BbqrFileType::Transaction,
                &payload,
                invalid_part_len,
                0,
                &mut frame,
            ),
            Err(BbqrError::InvalidNonFinalPartLength)
        );
        assert_eq!(frame, [FRAME_SENTINEL; MAX_FRAME_TEXT_BYTES]);
    }
    assert_eq!(
        encode_typed_frame(BbqrFileType::Transaction, &payload, 5, 2, &mut frame),
        Err(BbqrError::PartIndexOutOfRange)
    );
    assert_eq!(frame, [FRAME_SENTINEL; MAX_FRAME_TEXT_BYTES]);
}

fuzz_target!(|data: &[u8]| {
    exercise_presented(presented_frame(data));

    let selector = data.first().copied().unwrap_or(0);
    let requested_part_len = VALID_PART_LENGTHS[usize::from(selector) % VALID_PART_LENGTHS.len()];
    let candidate = if data.is_empty() {
        b"ready-to-send Bitcoin transaction".as_slice()
    } else {
        data
    };
    let payload = &candidate[..candidate.len().min(MAX_STRUCTURED_PAYLOAD)];
    exercise_generated(payload, requested_part_len, selector);
    exercise_fixed_rejections();
});
