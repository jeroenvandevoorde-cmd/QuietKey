//! Strict lowercase hexadecimal used by the trace envelope.

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum HexError {
    Empty,
    OddLength,
    InvalidDigit,
    WrongLength,
}

fn nibble(byte: u8) -> Result<u8, HexError> {
    match byte {
        b'0'..=b'9' => Ok(byte - b'0'),
        b'a'..=b'f' => Ok(byte - b'a' + 10),
        _ => Err(HexError::InvalidDigit),
    }
}

pub(crate) fn decode(value: &str, max_bytes: usize) -> Result<Vec<u8>, HexError> {
    if value.is_empty() {
        return Err(HexError::Empty);
    }
    if !value.len().is_multiple_of(2) {
        return Err(HexError::OddLength);
    }
    if value.len() / 2 > max_bytes {
        return Err(HexError::WrongLength);
    }
    let mut decoded = Vec::with_capacity(value.len() / 2);
    let (pairs, remainder) = value.as_bytes().as_chunks::<2>();
    debug_assert!(remainder.is_empty());
    for pair in pairs {
        decoded.push((nibble(pair[0])? << 4) | nibble(pair[1])?);
    }
    Ok(decoded)
}

pub(crate) fn decode_sha256(value: &str) -> Result<[u8; 32], HexError> {
    if value.len() != 64 {
        return Err(HexError::WrongLength);
    }
    let decoded = decode(value, 32)?;
    let mut digest = [0u8; 32];
    digest.copy_from_slice(&decoded);
    Ok(digest)
}

#[cfg(test)]
mod tests {
    use super::{decode, decode_sha256, HexError};

    #[test]
    fn lowercase_hex_is_canonical() {
        assert_eq!(decode("00a5ff", 3), Ok(vec![0x00, 0xa5, 0xff]));
        assert_eq!(decode("00A5ff", 3), Err(HexError::InvalidDigit));
        assert_eq!(decode("0g", 1), Err(HexError::InvalidDigit));
    }

    #[test]
    fn lengths_fail_closed() {
        assert_eq!(decode("", 1), Err(HexError::Empty));
        assert_eq!(decode("0", 1), Err(HexError::OddLength));
        assert_eq!(decode("0000", 1), Err(HexError::WrongLength));
        assert_eq!(decode_sha256(&"00".repeat(31)), Err(HexError::WrongLength));
    }
}
