//! Verification-only libsecp256k1 FFI boundary (QK-DEC-040..043).
//!
//! HOST SCAFFOLD ONLY — NOT PRODUCT CODE — NOT A WALLET — NO TARGET CLAIM.
//!
//! This crate links the vendored pinned libsecp256k1 v0.8.0 product
//! closure (QK-DEC-041) and exposes exactly five public functions over
//! one private FFI module (QK-DEC-042): compressed public-key parse,
//! compressed serialize, public-key tweak-add, DER signature parse,
//! and ECDSA verify. All representations are fixed-size and owned:
//! compressed keys are `[u8; 33]` with an 02/03 prefix, digests and
//! tweaks are `[u8; 32]`, DER input is copied into a bounded
//! `[u8; 72]` container with length 8..=72 before any FFI call, and
//! the opaque 64-byte C objects never escape. High-S signatures are
//! not normalized and verification rejects them. Every upstream 0/1
//! return code is mapped explicitly and any other code fails closed.
//! Error values carry fixed text only, never attacker bytes.
//!
//! This Rust wrapper declares and calls no signing or secret-key
//! function and accepts no secret-key input; it creates, randomizes,
//! or destroys no context, normalizes no signature, and integrates
//! with no PSBT flow; it decides nothing about validity,
//! signability, or completeness of any transaction. It contains no
//! file or device access, clocks, randomness, logging, network,
//! environment access, threads, processes, or persistence, and has no
//! Cargo dependencies.

#![deny(unsafe_code)]
#![deny(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects
)]

mod ffi;

use core::fmt;

/// Minimum accepted DER signature length in bytes.
const DER_MIN_BYTES: usize = 8;
/// Maximum accepted DER signature length in bytes.
const DER_MAX_BYTES: usize = 72;

/// Opaque parsed public key. The 64-byte internal object never
/// escapes; obtain bytes only through compressed serialization.
#[derive(Clone, Copy)]
pub struct PublicKey {
    obj: [u8; ffi::PUBKEY_OBJ_BYTES],
}

/// Opaque parsed ECDSA signature. The 64-byte internal object never
/// escapes.
#[derive(Clone, Copy)]
pub struct Signature {
    obj: [u8; ffi::SIG_OBJ_BYTES],
}

/// Fail-closed error categories for the verification boundary. Fixed
/// text only; never attacker bytes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SecpError {
    /// DER input length is outside the bounded 8..=72 container.
    DerLengthOutOfBounds,
    /// Compressed public-key parse was rejected.
    PubkeyParseFailed,
    /// Compressed serialization was rejected or produced an
    /// unexpected length.
    PubkeySerializeFailed,
    /// The tweak or the resulting point was rejected.
    TweakRejected,
    /// DER signature parse was rejected.
    SignatureParseFailed,
    /// The signature did not verify over the digest and key.
    VerificationFailed,
    /// The native call returned a code other than 0 or 1; fail closed.
    UnknownReturnCode,
}

impl fmt::Display for SecpError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let text = match self {
            Self::DerLengthOutOfBounds => "der signature length outside bounded container",
            Self::PubkeyParseFailed => "compressed public key rejected",
            Self::PubkeySerializeFailed => "public key serialization rejected",
            Self::TweakRejected => "public key tweak rejected",
            Self::SignatureParseFailed => "der signature rejected",
            Self::VerificationFailed => "signature verification failed",
            Self::UnknownReturnCode => "native call returned an unknown code",
        };
        f.write_str(text)
    }
}

/// Map a native return code: 1 is success, 0 is a well-formed
/// rejection, anything else fails closed (QK-DEC-042).
fn map_status(code: i32) -> Result<bool, SecpError> {
    match code {
        1 => Ok(true),
        0 => Ok(false),
        _ => Err(SecpError::UnknownReturnCode),
    }
}

/// Parse an exactly-33-byte compressed public key with an 02/03
/// prefix.
pub fn pubkey_parse_compressed(input: &[u8; 33]) -> Result<PublicKey, SecpError> {
    let prefix = input.first().copied().unwrap_or(0);
    if prefix != 0x02 && prefix != 0x03 {
        return Err(SecpError::PubkeyParseFailed);
    }
    let (code, obj) = ffi::pubkey_parse(input);
    if map_status(code)? {
        Ok(PublicKey { obj })
    } else {
        Err(SecpError::PubkeyParseFailed)
    }
}

/// Serialize a parsed public key to its exactly-33-byte compressed
/// form (upstream compressed flag 258, out-length 33).
pub fn pubkey_serialize_compressed(key: &PublicKey) -> Result<[u8; 33], SecpError> {
    let (code, outlen, out) = ffi::pubkey_serialize_compressed(&key.obj);
    if !map_status(code)? {
        return Err(SecpError::PubkeySerializeFailed);
    }
    let prefix = out.first().copied().unwrap_or(0);
    if outlen != ffi::COMPRESSED_PUBKEY_BYTES || (prefix != 0x02 && prefix != 0x03) {
        return Err(SecpError::PubkeySerializeFailed);
    }
    Ok(out)
}

/// Add `tweak32 * G` to a parsed public key, failing closed on an
/// out-of-range tweak or a point-at-infinity result.
pub fn pubkey_tweak_add(key: &PublicKey, tweak32: &[u8; 32]) -> Result<PublicKey, SecpError> {
    let (code, obj) = ffi::pubkey_tweak_add(&key.obj, tweak32);
    if map_status(code)? {
        Ok(PublicKey { obj })
    } else {
        Err(SecpError::TweakRejected)
    }
}

/// Parse a DER signature from a bounded container: the input is
/// rejected before any FFI call unless its length is 8..=72, then
/// copied into a fixed `[u8; 72]` buffer. High-S values are preserved,
/// never normalized.
pub fn signature_parse_der(der: &[u8]) -> Result<Signature, SecpError> {
    let len = der.len();
    if !(DER_MIN_BYTES..=DER_MAX_BYTES).contains(&len) {
        return Err(SecpError::DerLengthOutOfBounds);
    }
    let mut bounded = [0u8; DER_MAX_BYTES];
    let Some(dst) = bounded.get_mut(..len) else {
        return Err(SecpError::DerLengthOutOfBounds);
    };
    dst.copy_from_slice(der);
    let Some(view) = bounded.get(..len) else {
        return Err(SecpError::DerLengthOutOfBounds);
    };
    let (code, obj) = ffi::signature_parse_der(view);
    if map_status(code)? {
        Ok(Signature { obj })
    } else {
        Err(SecpError::SignatureParseFailed)
    }
}

/// Verify a parsed signature over a 32-byte digest against a parsed
/// public key. High-S signatures fail verification.
pub fn ecdsa_verify(
    sig: &Signature,
    digest32: &[u8; 32],
    key: &PublicKey,
) -> Result<(), SecpError> {
    let code = ffi::ecdsa_verify(&sig.obj, digest32, &key.obj);
    if map_status(code)? {
        Ok(())
    } else {
        Err(SecpError::VerificationFailed)
    }
}

#[cfg(test)]
mod tests {
    use super::{map_status, SecpError};

    #[test]
    fn return_mapping_covers_every_seam() {
        assert_eq!(map_status(1), Ok(true));
        assert_eq!(map_status(0), Ok(false));
        for unknown in [2, -1, 3, i32::MIN, i32::MAX] {
            assert_eq!(map_status(unknown), Err(SecpError::UnknownReturnCode));
        }
    }

    #[test]
    fn error_text_is_fixed() {
        assert_eq!(
            SecpError::UnknownReturnCode.to_string(),
            "native call returned an unknown code"
        );
        assert_eq!(
            SecpError::VerificationFailed.to_string(),
            "signature verification failed"
        );
    }
}
