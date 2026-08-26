//! Private canonical unpadded RFC 4648 Base32 primitive for BBQr frames.

use crate::BbqrError;

const ALPHABET: &[u8; 32] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";

pub(crate) fn encoded_len(byte_len: usize) -> usize {
    (byte_len * 8).div_ceil(5)
}

pub(crate) fn decoded_len(symbol_len: usize) -> Result<usize, BbqrError> {
    if !matches!(symbol_len % 8, 0 | 2 | 4 | 5 | 7) {
        return Err(BbqrError::NonCanonicalBase32Length);
    }
    Ok(symbol_len * 5 / 8)
}

pub(crate) fn encode(input: &[u8], output: &mut [u8]) {
    debug_assert_eq!(output.len(), encoded_len(input.len()));

    let mut accumulator = 0u16;
    let mut bits = 0usize;
    let mut written = 0usize;
    for byte in input {
        accumulator = (accumulator << 8) | u16::from(*byte);
        bits += 8;
        while bits >= 5 {
            bits -= 5;
            output[written] = ALPHABET[usize::from((accumulator >> bits) & 0x1f)];
            written += 1;
            accumulator &= (1u16 << bits).wrapping_sub(1);
        }
    }
    if bits != 0 {
        output[written] = ALPHABET[usize::from((accumulator << (5 - bits)) & 0x1f)];
        written += 1;
    }
    debug_assert_eq!(written, output.len());
}

pub(crate) fn decode(input: &[u8], output: &mut [u8]) -> Result<(), BbqrError> {
    if input.contains(&b'=') {
        return Err(BbqrError::Base32PaddingForbidden);
    }
    let expected_len = decoded_len(input.len())?;
    debug_assert_eq!(output.len(), expected_len);

    let mut accumulator = 0u16;
    let mut bits = 0usize;
    let mut written = 0usize;
    for symbol in input {
        let value = match *symbol {
            b'A'..=b'Z' => symbol - b'A',
            b'2'..=b'7' => symbol - b'2' + 26,
            _ => return Err(BbqrError::MalformedBase32Symbol),
        };
        accumulator = (accumulator << 5) | u16::from(value);
        bits += 5;
        if bits >= 8 {
            bits -= 8;
            output[written] = (accumulator >> bits) as u8;
            written += 1;
            accumulator &= (1u16 << bits).wrapping_sub(1);
        }
    }
    if accumulator != 0 {
        return Err(BbqrError::NonCanonicalBase32Padding);
    }
    debug_assert_eq!(written, output.len());
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::{decode, encode, encoded_len};
    use crate::BbqrError;

    #[test]
    fn rfc_4648_unpadded_examples_round_trip() {
        let cases: &[(&[u8], &[u8])] = &[
            (b"", b""),
            (b"f", b"MY"),
            (b"fo", b"MZXQ"),
            (b"foo", b"MZXW6"),
            (b"foob", b"MZXW6YQ"),
            (b"fooba", b"MZXW6YTB"),
            (b"foobar", b"MZXW6YTBOI"),
        ];
        for (plain, encoded) in cases {
            let mut symbols = [0u8; 16];
            let symbol_len = encoded_len(plain.len());
            encode(plain, &mut symbols[..symbol_len]);
            assert_eq!(&symbols[..symbol_len], *encoded);

            let mut decoded = [0u8; 8];
            decode(encoded, &mut decoded[..plain.len()]).unwrap();
            assert_eq!(&decoded[..plain.len()], *plain);
        }
    }

    #[test]
    fn canonical_rejections_are_distinct() {
        let mut output = [0u8; 8];
        assert_eq!(
            decode(b"MY======", &mut output[..1]),
            Err(BbqrError::Base32PaddingForbidden)
        );
        assert_eq!(
            decode(b"my", &mut output[..1]),
            Err(BbqrError::MalformedBase32Symbol)
        );
        assert_eq!(
            decode(b"A", &mut output[..0]),
            Err(BbqrError::NonCanonicalBase32Length)
        );
        assert_eq!(
            decode(b"MZ", &mut output[..1]),
            Err(BbqrError::NonCanonicalBase32Padding)
        );
    }
}
