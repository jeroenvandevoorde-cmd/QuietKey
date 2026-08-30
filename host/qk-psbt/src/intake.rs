//! Owned immutable S0 intake for D-09 review construction.

use crate::error::ParseError;
use crate::parse::{parse, InputSource, PsbtView};
use crate::sha256::sha256;
use crate::wipe;
use core::fmt;

/// One bounded, immutable copy of the exact caller-supplied S0 bytes.
///
/// Construction checks the selected source cap before attempting an
/// allocation. The retained bytes have no mutable accessor; every parse and
/// reparse therefore borrows the same owned artifact.
pub struct OwnedS0 {
    bytes: Vec<u8>,
    source: InputSource,
    sha256: [u8; 32],
}

impl Drop for OwnedS0 {
    fn drop(&mut self) {
        wipe::byte_vec(&mut self.bytes);
        wipe::bytes(&mut self.sha256);
    }
}

impl OwnedS0 {
    /// Copy one caller artifact into bounded immutable ownership.
    ///
    /// # Errors
    ///
    /// Returns a stable [`IntakeError`] if the selected source cap is
    /// exceeded, the exact-size allocation fails, or SHA-256 cannot account
    /// for the retained bytes.
    pub fn new(bytes: &[u8], source: InputSource) -> Result<Self, IntakeError> {
        if bytes.len() > source.max_bytes() {
            return Err(IntakeError::TooLarge);
        }

        let mut owned = Vec::new();
        owned
            .try_reserve_exact(bytes.len())
            .map_err(|_| IntakeError::AllocationFailed)?;
        owned.extend_from_slice(bytes);
        let digest = sha256(&[owned.as_slice()]).map_err(|_| IntakeError::HashFailure)?;

        Ok(Self {
            bytes: owned,
            source,
            sha256: digest,
        })
    }

    /// Exact retained S0 bytes.
    #[must_use]
    pub fn bytes(&self) -> &[u8] {
        &self.bytes
    }

    /// Intake source and corresponding cap used at construction.
    #[must_use]
    pub const fn source(&self) -> InputSource {
        self.source
    }

    /// SHA-256 of the exact retained S0 bytes.
    #[must_use]
    pub const fn sha256(&self) -> [u8; 32] {
        self.sha256
    }

    /// Parse or reparse only the retained immutable S0 artifact.
    ///
    /// # Errors
    ///
    /// Returns the existing stable structural [`ParseError`] for these exact
    /// retained bytes.
    pub fn parse(&self) -> Result<PsbtView<'_>, ParseError> {
        parse(&self.bytes, self.source)
    }
}

impl fmt::Debug for OwnedS0 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("OwnedS0")
            .field("byte_len", &self.bytes.len())
            .field("source", &self.source)
            .finish_non_exhaustive()
    }
}

/// Stable owned-intake failure category.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IntakeError {
    /// Caller bytes exceed the cap for the declared [`InputSource`].
    TooLarge,
    /// The single exact-size retained-byte allocation failed.
    AllocationFailed,
    /// SHA-256 length accounting or an internal hash invariant failed.
    HashFailure,
}

impl fmt::Display for IntakeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::TooLarge => f.write_str("S0 exceeds source byte cap"),
            Self::AllocationFailed => f.write_str("S0 allocation failed"),
            Self::HashFailure => f.write_str("S0 hash failed"),
        }
    }
}

impl std::error::Error for IntakeError {}

#[cfg(test)]
#[allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects
)]
mod tests {
    use super::{IntakeError, OwnedS0};
    use crate::limits;
    use crate::parse::InputSource;
    use crate::sha256::sha256;
    use crate::wipe::{reset_wiped_bytes, wiped_bytes};

    fn minimal_psbt() -> Vec<u8> {
        let mut tx = vec![2, 0, 0, 0, 1];
        tx.extend_from_slice(&[0; 32]);
        tx.extend_from_slice(&[0; 4]);
        tx.push(0);
        tx.extend_from_slice(&[0xff; 4]);
        tx.push(1);
        tx.extend_from_slice(&[0; 8]);
        tx.extend_from_slice(&[1, 0x51]);
        tx.extend_from_slice(&[0; 4]);

        let mut psbt = b"psbt\xff\x01\x00".to_vec();
        psbt.push(u8::try_from(tx.len()).expect("minimal tx length fits one byte"));
        psbt.extend_from_slice(&tx);
        psbt.extend_from_slice(&[0, 0, 0]);
        psbt
    }

    #[test]
    fn micro_sd_cap_is_checked_at_the_exact_boundary() {
        let exact = vec![0; limits::MAX_SD_INPUT_BYTES];
        let owned = OwnedS0::new(&exact, InputSource::MicroSd).unwrap();
        assert_eq!(owned.bytes().len(), limits::MAX_SD_INPUT_BYTES);

        let over = vec![0; limits::MAX_SD_INPUT_BYTES + 1];
        assert_eq!(
            OwnedS0::new(&over, InputSource::MicroSd).unwrap_err(),
            IntakeError::TooLarge
        );
    }

    #[test]
    fn assembled_qr_cap_is_checked_at_the_exact_boundary() {
        let exact = vec![0; limits::MAX_QR_INPUT_BYTES];
        let owned = OwnedS0::new(&exact, InputSource::Qr).unwrap();
        assert_eq!(owned.bytes().len(), limits::MAX_QR_INPUT_BYTES);

        let over = vec![0; limits::MAX_QR_INPUT_BYTES + 1];
        assert_eq!(
            OwnedS0::new(&over, InputSource::Qr).unwrap_err(),
            IntakeError::TooLarge
        );
    }

    #[test]
    fn retained_copy_and_hash_do_not_follow_caller_mutation() {
        let mut caller = minimal_psbt();
        let expected = caller.clone();
        let expected_hash = sha256(&[&expected]).unwrap();
        let owned = OwnedS0::new(&caller, InputSource::MicroSd).unwrap();

        caller.fill(0xa5);

        assert_eq!(owned.bytes(), expected);
        assert_eq!(owned.sha256(), expected_hash);
        assert_ne!(owned.bytes(), caller);
    }

    #[test]
    fn every_parse_borrows_the_exact_retained_artifact() {
        let expected = minimal_psbt();
        let owned = OwnedS0::new(&expected, InputSource::Qr).unwrap();

        let first = owned.parse().unwrap();
        let second = owned.parse().unwrap();

        assert_eq!(first.buffer(), expected);
        assert_eq!(second.buffer(), expected);
        assert!(core::ptr::eq(
            first.buffer().as_ptr(),
            owned.bytes().as_ptr()
        ));
        assert!(core::ptr::eq(
            second.buffer().as_ptr(),
            owned.bytes().as_ptr()
        ));
        assert_eq!(first.source(), InputSource::Qr);
        assert_eq!(second.source(), InputSource::Qr);
        assert_eq!(owned.sha256(), sha256(&[owned.bytes()]).unwrap());
    }

    #[test]
    fn retained_s0_allocation_and_identity_are_wiped_on_drop() {
        let owned = OwnedS0::new(&minimal_psbt(), InputSource::MicroSd).unwrap();
        let expected = owned.bytes.capacity() + 32;
        reset_wiped_bytes();
        drop(owned);
        assert_eq!(wiped_bytes(), expected);
    }
}
