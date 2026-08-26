//! M22 standalone frame encoding and decoding boundaries.

use qk_bbqr::{
    decode_frame, encode_frame, encoded_part_count, BbqrError, DecodedFrame, MAX_BODY_SYMBOLS,
    MAX_DECLARED_PARTS, MAX_FRAME_TEXT_BYTES, MAX_PART_DECODED_BYTES, MAX_SUBMISSIONS,
    MAX_TOTAL_DECODED_BYTES,
};

const FRAME_SENTINEL: u8 = 0xa5;
const PART_SENTINEL: u8 = 0x5a;

fn encoded_frame(payload: &[u8], part_len: usize, part_index: u16) -> Vec<u8> {
    let mut output = [FRAME_SENTINEL; MAX_FRAME_TEXT_BYTES];
    let length = encode_frame(payload, part_len, part_index, &mut output).unwrap();
    assert!(output[length..].iter().all(|byte| *byte == FRAME_SENTINEL));
    output[..length].to_vec()
}

fn assert_decode_rejection(frame: &[u8], expected: BbqrError) {
    let mut output = [PART_SENTINEL; MAX_PART_DECODED_BYTES];
    assert_eq!(decode_frame(frame, &mut output), Err(expected));
    assert!(
        output.iter().all(|byte| *byte == PART_SENTINEL),
        "decode rejection changed its caller output"
    );
}

fn patterned(length: usize) -> Vec<u8> {
    (0..length)
        .map(|index| (index as u8).wrapping_mul(29).wrapping_add(7))
        .collect()
}

#[test]
fn public_caps_and_part_count_edges_are_exact() {
    assert_eq!(MAX_DECLARED_PARTS, 256);
    assert_eq!(MAX_FRAME_TEXT_BYTES, 4_296);
    assert_eq!(MAX_BODY_SYMBOLS, 4_288);
    assert_eq!(MAX_PART_DECODED_BYTES, 2_680);
    assert_eq!(MAX_TOTAL_DECODED_BYTES, 262_144);
    assert_eq!(MAX_SUBMISSIONS, 512);
    assert_eq!(MAX_FRAME_TEXT_BYTES - 8, MAX_BODY_SYMBOLS);
    assert_eq!(MAX_BODY_SYMBOLS * 5 / 8, MAX_PART_DECODED_BYTES);
    assert_eq!(MAX_DECLARED_PARTS * 2, MAX_SUBMISSIONS);

    assert_eq!(encoded_part_count(0, 0), Err(BbqrError::EmptyPayload));
    assert_eq!(
        encoded_part_count(MAX_TOTAL_DECODED_BYTES + 1, 0),
        Err(BbqrError::PayloadTooLarge)
    );
    for invalid in [0, 1, 4, 6, MAX_PART_DECODED_BYTES + 1] {
        assert_eq!(
            encoded_part_count(1, invalid),
            Err(BbqrError::InvalidNonFinalPartLength),
            "part length {invalid}"
        );
    }

    assert_eq!(encoded_part_count(1, 5), Ok(1));
    assert_eq!(encoded_part_count(5, 5), Ok(1));
    assert_eq!(encoded_part_count(6, 5), Ok(2));
    assert_eq!(encoded_part_count(1_280, 5), Ok(256));
    assert_eq!(encoded_part_count(1_281, 5), Err(BbqrError::TooManyParts));
    assert_eq!(encoded_part_count(MAX_TOTAL_DECODED_BYTES, 1_025), Ok(256));
    assert_eq!(
        encoded_part_count(MAX_TOTAL_DECODED_BYTES, MAX_PART_DECODED_BYTES),
        Ok(98)
    );
}

#[test]
fn rfc_4648_frames_are_byte_exact_and_zero_based() {
    let payload = b"foobar";
    let first = encoded_frame(payload, 5, 0);
    let final_part = encoded_frame(payload, 5, 1);
    assert_eq!(first, b"B$2P0200MZXW6YTB");
    assert_eq!(final_part, b"B$2P0201OI");

    for (frame, expected) in [
        (first.as_slice(), b"fooba".as_slice()),
        (final_part.as_slice(), b"r".as_slice()),
    ] {
        let mut output = [PART_SENTINEL; MAX_PART_DECODED_BYTES];
        let decoded = decode_frame(frame, &mut output).unwrap();
        assert_eq!(decoded.declared_parts, 2);
        assert_eq!(decoded.part_index, u16::from(frame[7] - b'0'));
        assert_eq!(decoded.decoded_len, expected.len());
        assert_eq!(&output[..decoded.decoded_len], expected);
        assert!(output[decoded.decoded_len..]
            .iter()
            .all(|byte| *byte == PART_SENTINEL));
    }
}

#[test]
fn encoder_rejections_are_ordered_and_leave_output_unchanged() {
    fn rejects(payload: &[u8], part_len: usize, index: u16, expected: BbqrError) {
        let mut output = [FRAME_SENTINEL; MAX_FRAME_TEXT_BYTES];
        assert_eq!(
            encode_frame(payload, part_len, index, &mut output),
            Err(expected)
        );
        assert!(output.iter().all(|byte| *byte == FRAME_SENTINEL));
    }

    rejects(&[], 0, u16::MAX, BbqrError::EmptyPayload);
    let oversized = vec![0u8; MAX_TOTAL_DECODED_BYTES + 1];
    rejects(&oversized, 0, u16::MAX, BbqrError::PayloadTooLarge);
    rejects(b"x", 4, u16::MAX, BbqrError::InvalidNonFinalPartLength);
    let too_many = vec![0u8; 1_281];
    rejects(&too_many, 5, u16::MAX, BbqrError::TooManyParts);
    rejects(b"foobar", 5, 2, BbqrError::PartIndexOutOfRange);
}

#[test]
fn header_rejection_precedence_is_stable() {
    assert_decode_rejection(b"", BbqrError::FrameTooShort);
    assert_decode_rejection(b"B$2P010", BbqrError::FrameTooShort);

    let oversized = vec![b'!'; MAX_FRAME_TEXT_BYTES + 1];
    assert_decode_rejection(&oversized, BbqrError::FrameTooLarge);

    assert_decode_rejection(b"A$HP0000=", BbqrError::InvalidMagic);
    assert_decode_rejection(b"B$HP0000=", BbqrError::UnsupportedEncoding);
    assert_decode_rejection(b"B$2U0000=", BbqrError::UnsupportedFileType);
    assert_decode_rejection(b"B$2P!100=", BbqrError::InvalidDeclaredPartCount);
    assert_decode_rejection(b"B$2P0100=", BbqrError::Base32PaddingForbidden);
    assert_decode_rejection(b"B$2P0000=", BbqrError::InvalidDeclaredPartCount);
    assert_decode_rejection(b"B$2P7500=", BbqrError::DeclaredPartCountExceeded);
    assert_decode_rejection(b"B$2P01!0=", BbqrError::InvalidPartIndex);
    assert_decode_rejection(b"B$2P0101=", BbqrError::InvalidPartIndex);
    assert_decode_rejection(b"B$2P0100", BbqrError::EmptyPart);
}

#[test]
fn canonical_base32_failures_are_distinct_and_precedence_locked() {
    assert_decode_rejection(b"B$2P0100MY======", BbqrError::Base32PaddingForbidden);
    assert_decode_rejection(b"B$2P0100m", BbqrError::MalformedBase32Symbol);
    assert_decode_rejection(b"B$2P01000", BbqrError::MalformedBase32Symbol);
    assert_decode_rejection(b"B$2P0100A", BbqrError::NonCanonicalBase32Length);
    assert_decode_rejection(b"B$2P0100AAA", BbqrError::NonCanonicalBase32Length);
    assert_decode_rejection(b"B$2P0100AAAAAA", BbqrError::NonCanonicalBase32Length);

    // Valid symbol counts with non-zero unused low bits are noncanonical.
    for body in [b"AB".as_slice(), b"AAAB", b"AAAAB", b"AAAAAAB"] {
        let mut frame = b"B$2P0100".to_vec();
        frame.extend_from_slice(body);
        assert_decode_rejection(&frame, BbqrError::NonCanonicalBase32Padding);
    }

    // Standalone decoding knows the index is non-final and enforces 5-byte geometry.
    assert_decode_rejection(
        b"B$2P0200AA",
        BbqrError::NonFinalPartLengthNotMultipleOfFive,
    );
}

#[test]
fn canonical_tail_lengths_and_multiframe_boundaries_round_trip() {
    for payload_len in 1..=64 {
        let payload = patterned(payload_len);
        let frame = encoded_frame(&payload, MAX_PART_DECODED_BYTES, 0);
        let mut output = [PART_SENTINEL; MAX_PART_DECODED_BYTES];
        let decoded = decode_frame(&frame, &mut output).unwrap();
        assert_eq!(
            decoded,
            DecodedFrame {
                declared_parts: 1,
                part_index: 0,
                decoded_len: payload_len,
            }
        );
        assert_eq!(&output[..payload_len], payload);
    }

    for part_len in [5usize, 10, 25, 1_025, MAX_PART_DECODED_BYTES] {
        for payload_len in [part_len, part_len + 1, part_len * 2, part_len * 2 + 1] {
            let payload = patterned(payload_len);
            let count = encoded_part_count(payload.len(), part_len).unwrap();
            for index in 0..count {
                let frame = encoded_frame(&payload, part_len, index);
                let mut output = [PART_SENTINEL; MAX_PART_DECODED_BYTES];
                let decoded = decode_frame(&frame, &mut output).unwrap();
                let start = usize::from(index) * part_len;
                let end = payload.len().min(start + part_len);
                assert_eq!(decoded.declared_parts, count);
                assert_eq!(decoded.part_index, index);
                assert_eq!(decoded.decoded_len, end - start);
                assert_eq!(&output[..decoded.decoded_len], &payload[start..end]);
            }
        }
    }
}

#[test]
fn maximum_frame_is_exact_and_one_more_byte_rejects_first() {
    let payload = patterned(MAX_PART_DECODED_BYTES);
    let frame = encoded_frame(&payload, MAX_PART_DECODED_BYTES, 0);
    assert_eq!(frame.len(), MAX_FRAME_TEXT_BYTES);
    assert_eq!(frame.len() - 8, MAX_BODY_SYMBOLS);

    let mut output = [PART_SENTINEL; MAX_PART_DECODED_BYTES];
    let decoded = decode_frame(&frame, &mut output).unwrap();
    assert_eq!(decoded.decoded_len, MAX_PART_DECODED_BYTES);
    assert_eq!(output, payload.as_slice());

    let mut oversized = frame;
    oversized.push(b'A');
    assert_decode_rejection(&oversized, BbqrError::FrameTooLarge);
}
