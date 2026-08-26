#![no_main]

use libfuzzer_sys::fuzz_target;
use qk_bbqr::{
    decode_frame, encode_frame, encoded_part_count, BbqrError, DecodedFrame, MAX_DECLARED_PARTS,
    MAX_FRAME_TEXT_BYTES, MAX_PART_DECODED_BYTES, MAX_TOTAL_DECODED_BYTES,
};

const FRAME_SENTINEL: u8 = 0xa5;
const PART_SENTINEL: u8 = 0x5a;
const MAX_PRESENTED_FRAME_BYTES: usize = MAX_FRAME_TEXT_BYTES + 1;
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
}

fn reference_base36(symbol: u8) -> Option<u16> {
    match symbol {
        b'0'..=b'9' => Some(u16::from(symbol - b'0')),
        b'A'..=b'Z' => Some(u16::from(symbol - b'A' + 10)),
        _ => None,
    }
}

fn reference_symbol(symbol: u8) -> Option<u8> {
    match symbol {
        b'A'..=b'Z' => Some(symbol - b'A'),
        b'2'..=b'7' => Some(symbol - b'2' + 26),
        _ => None,
    }
}

fn reference_decode(
    frame: &[u8],
    output: &mut [u8; MAX_PART_DECODED_BYTES],
) -> Result<DecodedFrame, BbqrError> {
    if frame.len() > MAX_FRAME_TEXT_BYTES {
        return Err(BbqrError::FrameTooLarge);
    }
    if frame.len() < 8 {
        return Err(BbqrError::FrameTooShort);
    }
    if frame[..2] != *b"B$" {
        return Err(BbqrError::InvalidMagic);
    }
    if frame[2] != b'2' {
        return Err(BbqrError::UnsupportedEncoding);
    }
    if frame[3] != b'P' {
        return Err(BbqrError::UnsupportedFileType);
    }

    let declared_parts = reference_base36(frame[4])
        .zip(reference_base36(frame[5]))
        .map(|(high, low)| high * 36 + low)
        .ok_or(BbqrError::InvalidDeclaredPartCount)?;
    if declared_parts == 0 {
        return Err(BbqrError::InvalidDeclaredPartCount);
    }
    if usize::from(declared_parts) > MAX_DECLARED_PARTS {
        return Err(BbqrError::DeclaredPartCountExceeded);
    }
    let part_index = reference_base36(frame[6])
        .zip(reference_base36(frame[7]))
        .map(|(high, low)| high * 36 + low)
        .ok_or(BbqrError::InvalidPartIndex)?;
    if part_index >= declared_parts {
        return Err(BbqrError::InvalidPartIndex);
    }

    let body = &frame[8..];
    if body.is_empty() {
        return Err(BbqrError::EmptyPart);
    }
    if body.contains(&b'=') {
        return Err(BbqrError::Base32PaddingForbidden);
    }
    if body
        .iter()
        .any(|symbol| reference_symbol(*symbol).is_none())
    {
        return Err(BbqrError::MalformedBase32Symbol);
    }
    if !matches!(body.len() % 8, 0 | 2 | 4 | 5 | 7) {
        return Err(BbqrError::NonCanonicalBase32Length);
    }

    let decoded_len = body.len() * 5 / 8;
    let mut candidate = [0u8; MAX_PART_DECODED_BYTES];
    let mut accumulator = 0u16;
    let mut bits = 0usize;
    let mut written = 0usize;
    for symbol in body {
        accumulator = (accumulator << 5)
            | u16::from(reference_symbol(*symbol).expect("symbols were checked"));
        bits += 5;
        if bits >= 8 {
            bits -= 8;
            candidate[written] = (accumulator >> bits) as u8;
            written += 1;
            accumulator &= (1u16 << bits).wrapping_sub(1);
        }
    }
    if accumulator != 0 {
        return Err(BbqrError::NonCanonicalBase32Padding);
    }
    assert_eq!(written, decoded_len);
    if part_index + 1 < declared_parts && !decoded_len.is_multiple_of(5) {
        return Err(BbqrError::NonFinalPartLengthNotMultipleOfFive);
    }
    output[..decoded_len].copy_from_slice(&candidate[..decoded_len]);
    Ok(DecodedFrame {
        declared_parts,
        part_index,
        decoded_len,
    })
}

fn exercise_decode(frame: &[u8]) -> Option<(DecodedFrame, [u8; MAX_PART_DECODED_BYTES])> {
    let mut reference = [PART_SENTINEL; MAX_PART_DECODED_BYTES];
    let expected = reference_decode(frame, &mut reference);
    let mut decoded = [PART_SENTINEL; MAX_PART_DECODED_BYTES];
    let result = decode_frame(frame, &mut decoded);
    assert_eq!(result, expected);
    match result {
        Err(error) => {
            assert_named_error(error);
            assert_eq!(decoded, [PART_SENTINEL; MAX_PART_DECODED_BYTES]);
            assert_eq!(reference, decoded);

            let mut repeated = [PART_SENTINEL; MAX_PART_DECODED_BYTES];
            assert_eq!(decode_frame(frame, &mut repeated), Err(error));
            assert_eq!(repeated, decoded);
            None
        }
        Ok(metadata) => {
            assert!((1..=MAX_DECLARED_PARTS as u16).contains(&metadata.declared_parts));
            assert!(metadata.part_index < metadata.declared_parts);
            assert!((1..=MAX_PART_DECODED_BYTES).contains(&metadata.decoded_len));
            assert!(decoded[metadata.decoded_len..]
                .iter()
                .all(|byte| *byte == PART_SENTINEL));
            assert_eq!(decoded, reference);

            let mut repeated = [PART_SENTINEL; MAX_PART_DECODED_BYTES];
            assert_eq!(decode_frame(frame, &mut repeated), Ok(metadata));
            assert_eq!(repeated, decoded);
            Some((metadata, decoded))
        }
    }
}

fn exercise_generated(payload: &[u8], non_final_part_len: usize, selector: u16) {
    let count = encoded_part_count(payload.len(), non_final_part_len);
    let mut frame = [FRAME_SENTINEL; MAX_FRAME_TEXT_BYTES];

    let Ok(count) = count else {
        let error = count.unwrap_err();
        assert_named_error(error);
        assert_eq!(
            encode_frame(payload, non_final_part_len, selector, &mut frame),
            Err(error)
        );
        assert_eq!(frame, [FRAME_SENTINEL; MAX_FRAME_TEXT_BYTES]);
        return;
    };

    let index = selector % count;
    let frame_len = encode_frame(payload, non_final_part_len, index, &mut frame)
        .expect("a validated payload and in-range index must encode");
    assert!((9..=MAX_FRAME_TEXT_BYTES).contains(&frame_len));
    assert!(frame[frame_len..]
        .iter()
        .all(|byte| *byte == FRAME_SENTINEL));

    let mut repeated_frame = [FRAME_SENTINEL; MAX_FRAME_TEXT_BYTES];
    assert_eq!(
        encode_frame(payload, non_final_part_len, index, &mut repeated_frame),
        Ok(frame_len)
    );
    assert_eq!(repeated_frame, frame);

    let (metadata, decoded) =
        exercise_decode(&frame[..frame_len]).expect("a frame emitted by the encoder must decode");
    let start = usize::from(index) * non_final_part_len;
    let end = payload.len().min(start + non_final_part_len);
    assert_eq!(metadata.declared_parts, count);
    assert_eq!(metadata.part_index, index);
    assert_eq!(metadata.decoded_len, end - start);
    assert_eq!(&decoded[..metadata.decoded_len], &payload[start..end]);
}

fn exercise_fixed_caps() {
    assert_eq!(encoded_part_count(0, 5), Err(BbqrError::EmptyPayload));
    assert_eq!(
        encoded_part_count(MAX_TOTAL_DECODED_BYTES + 1, 5),
        Err(BbqrError::PayloadTooLarge)
    );
    for invalid in [0, 1, 4, 6, MAX_PART_DECODED_BYTES + 1] {
        assert_eq!(
            encoded_part_count(1, invalid),
            Err(BbqrError::InvalidNonFinalPartLength)
        );
    }
    assert_eq!(
        encoded_part_count(MAX_DECLARED_PARTS * 5 + 1, 5),
        Err(BbqrError::TooManyParts)
    );

    let payload = [0u8; 6];
    let mut frame = [FRAME_SENTINEL; MAX_FRAME_TEXT_BYTES];
    assert_eq!(
        encode_frame(&payload, 5, 2, &mut frame),
        Err(BbqrError::PartIndexOutOfRange)
    );
    assert_eq!(frame, [FRAME_SENTINEL; MAX_FRAME_TEXT_BYTES]);
}

fuzz_target!(|data: &[u8]| {
    let presented_len = data.len().min(MAX_PRESENTED_FRAME_BYTES);
    let _ = exercise_decode(&data[..presented_len]);

    let selector = u16::from_be_bytes([
        data.first().copied().unwrap_or(0),
        data.get(1).copied().unwrap_or(0),
    ]);
    let requested_part_len = VALID_PART_LENGTHS
        [usize::from(data.get(2).copied().unwrap_or(0)) % VALID_PART_LENGTHS.len()];
    let payload = if data.is_empty() {
        b"\x70\x73\x62\x74\xff".as_slice()
    } else {
        data
    };
    exercise_generated(payload, requested_part_len, selector);
    exercise_fixed_caps();
});
