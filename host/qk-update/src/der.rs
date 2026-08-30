//! Strict canonical DER checks for QK-DEC-136 firmware signatures.

use crate::{UpdateError, MAX_LOW_S_DER_BYTES, MIN_DER_BYTES, SECP256K1_HALF_ORDER};

/// Borrowed signature bytes after strict canonical-DER and low-S validation.
///
/// Construction is confined to [`parse_strict_low_s`], so callers may pass
/// this view directly to the public-only `qk-secp` DER parser without
/// repeating format policy.
#[derive(Clone, Copy)]
pub(crate) struct ParsedDer<'a> {
    bytes: &'a [u8],
}

impl<'a> ParsedDer<'a> {
    pub(crate) const fn as_bytes(self) -> &'a [u8] {
        self.bytes
    }
}

/// Parse exactly one canonical ASN.1 sequence containing positive R and S
/// integers, then enforce the QK-DEC-136 low-S ceiling.
pub(crate) fn parse_strict_low_s(bytes: &[u8]) -> Result<ParsedDer<'_>, UpdateError> {
    if !(MIN_DER_BYTES..=MAX_LOW_S_DER_BYTES).contains(&bytes.len()) {
        return Err(UpdateError::SignatureLengthOutOfBounds);
    }

    let sequence_tag = bytes.first().copied();
    let sequence_len = bytes.get(1).copied().map(usize::from);
    if sequence_tag != Some(0x30)
        || sequence_len != bytes.len().checked_sub(2)
        || bytes.get(2).copied() != Some(0x02)
    {
        return Err(UpdateError::MalformedDerSignature);
    }

    let r_len = bytes
        .get(3)
        .copied()
        .map(usize::from)
        .ok_or(UpdateError::MalformedDerSignature)?;
    let r_start = 4usize;
    let r_end = r_start
        .checked_add(r_len)
        .ok_or(UpdateError::MalformedDerSignature)?;
    let s_tag = bytes
        .get(r_end)
        .copied()
        .ok_or(UpdateError::MalformedDerSignature)?;
    let s_len_at = r_end
        .checked_add(1)
        .ok_or(UpdateError::MalformedDerSignature)?;
    let s_len = bytes
        .get(s_len_at)
        .copied()
        .map(usize::from)
        .ok_or(UpdateError::MalformedDerSignature)?;
    let s_start = r_end
        .checked_add(2)
        .ok_or(UpdateError::MalformedDerSignature)?;
    let s_end = s_start
        .checked_add(s_len)
        .ok_or(UpdateError::MalformedDerSignature)?;

    if s_tag != 0x02 || s_end != bytes.len() {
        return Err(UpdateError::MalformedDerSignature);
    }

    let r = bytes
        .get(r_start..r_end)
        .ok_or(UpdateError::MalformedDerSignature)?;
    let s = bytes
        .get(s_start..s_end)
        .ok_or(UpdateError::MalformedDerSignature)?;
    validate_positive_integer(r)?;
    validate_positive_integer(s)?;

    if integer_exceeds_half_order(s) {
        return Err(UpdateError::HighSSignature);
    }

    Ok(ParsedDer { bytes })
}

fn validate_positive_integer(integer: &[u8]) -> Result<(), UpdateError> {
    let Some(first) = integer.first().copied() else {
        return Err(UpdateError::MalformedDerSignature);
    };
    if first & 0x80 != 0 {
        return Err(UpdateError::MalformedDerSignature);
    }
    if first == 0 {
        let Some(second) = integer.get(1).copied() else {
            return Err(UpdateError::MalformedDerSignature);
        };
        if second & 0x80 == 0 {
            return Err(UpdateError::MalformedDerSignature);
        }
    }
    Ok(())
}

fn integer_exceeds_half_order(integer: &[u8]) -> bool {
    let magnitude = match integer {
        [0, rest @ ..] => rest,
        _ => integer,
    };
    match magnitude.len().cmp(&SECP256K1_HALF_ORDER.len()) {
        core::cmp::Ordering::Greater => true,
        core::cmp::Ordering::Less => false,
        core::cmp::Ordering::Equal => magnitude > SECP256K1_HALF_ORDER.as_slice(),
    }
}

#[cfg(test)]
#[allow(clippy::indexing_slicing)]
mod tests {
    use super::parse_strict_low_s;
    use crate::UpdateError;

    #[test]
    fn accepts_canonical_low_s_boundaries() {
        let minimum = [0x30, 0x06, 0x02, 0x01, 0x01, 0x02, 0x01, 0x01];
        assert_eq!(
            parse_strict_low_s(&minimum).map(|view| view.as_bytes()),
            Ok(minimum.as_slice())
        );

        let mut maximum_s = [0u8; 39];
        maximum_s[..7].copy_from_slice(&[0x30, 0x25, 0x02, 0x01, 0x01, 0x02, 0x20]);
        maximum_s[7..].copy_from_slice(&crate::SECP256K1_HALF_ORDER);
        assert!(parse_strict_low_s(&maximum_s).is_ok());
    }

    #[test]
    fn separates_malformed_from_high_s() {
        let malformed = [0x30, 0x06, 0x02, 0x01, 0x00, 0x02, 0x01, 0x01];
        assert!(matches!(
            parse_strict_low_s(&malformed),
            Err(UpdateError::MalformedDerSignature)
        ));

        let mut high_s = [0u8; 40];
        high_s[..8].copy_from_slice(&[0x30, 0x26, 0x02, 0x01, 0x01, 0x02, 0x21, 0x00]);
        high_s[8..].fill(0xff);
        assert!(matches!(
            parse_strict_low_s(&high_s),
            Err(UpdateError::HighSSignature)
        ));
    }
}
