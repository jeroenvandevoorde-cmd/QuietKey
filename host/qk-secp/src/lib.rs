//! Bounded libsecp256k1 FFI boundary (QK-DEC-040..043, QK-DEC-111).
//!
//! HOST SCAFFOLD ONLY — NOT PRODUCT CODE — NOT A WALLET — NO TARGET CLAIM.
//!
//! This crate links the vendored pinned libsecp256k1 v0.8.0 product
//! closure (QK-DEC-041). The original verification surface remains:
//! compressed public-key parse and serialization, public-key
//! tweak-add, DER signature parse, and ECDSA verify. M24 adds only an
//! opaque move-stable secret-key owner, deterministic RFC6979 ECDSA
//! signing with mandatory low-S normalization and immediate
//! verification, and bounded DER serialization. QK-DEC-113 adds only
//! purpose-bound HOST provisioning public-key creation and private-scalar
//! tweak-add over fixed caller-owned buffers; it exposes no scalar accessor
//! or general arithmetic context. All public
//! representations are fixed-size and owned:
//! compressed keys are `[u8; 33]` with an 02/03 prefix, digests and
//! tweaks are `[u8; 32]`, DER input is copied into a bounded
//! `[u8; 72]` container with length 8..=72 before any FFI call, and
//! the opaque 64-byte C objects never escape. High-S signatures are
//! not normalized and verification rejects them. Every upstream 0/1
//! return code is mapped explicitly and any other code fails closed.
//! Error values carry fixed text only, never attacker bytes.
//!
//! Secret-key import always wipes the caller's mutable source. The
//! opaque owner is deliberately non-Clone, non-Copy, non-Debug and
//! non-Display, and volatile-wipes its move-stable allocation on
//! Drop. Signing uses a fresh non-static context, the explicit pinned
//! RFC6979 function with no extra data, normalization, DER
//! serialization, then the unchanged parse/verify path against a
//! caller-supplied expected public key before anything is returned.
//! The context is destroyed on every native return path. This is HOST
//! behavior only and makes no target remanence, context-randomization,
//! side-channel, constant-time, or Gate-C claim.
//!
//! This wrapper integrates with no PSBT flow and decides nothing about
//! transaction validity, signability, threshold completeness, or
//! authorization. It contains no
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
/// Maximum DER length produced by a normalized low-S signature.
const LOW_S_DER_MAX_BYTES: usize = 71;

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

/// Opaque move-stable secret-key owner.
///
/// Construction is only through [`secret_key_import`], which wipes its
/// mutable source on every return path. This type deliberately
/// implements none of `Clone`, `Copy`, `Debug`, `Display`, equality, or
/// byte-access traits.
pub struct SecretKey {
    bytes: Box<[u8; ffi::SCALAR_BYTES]>,
}

impl Drop for SecretKey {
    fn drop(&mut self) {
        ffi::wipe_secret(self.bytes.as_mut());
    }
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
    /// Secret-key bytes do not encode a scalar in `1..n`.
    SecretKeyRejected,
    /// A non-static signing context could not be obtained.
    SigningContextUnavailable,
    /// Deterministic ECDSA signing failed.
    SigningFailed,
    /// A normalized signature could not be serialized as bounded DER.
    SignatureSerializeFailed,
    /// A newly produced signature did not verify against the expected key.
    SelfVerificationFailed,
    /// A non-static provisioning public-key context could not be obtained.
    ProvisioningContextUnavailable,
    /// A provisioning scalar could not produce a public key.
    ProvisioningPublicKeyCreateFailed,
    /// A provisioning parent/tweak pair or its result was invalid.
    ProvisioningSecretTweakRejected,
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
            Self::SecretKeyRejected => "secret key rejected",
            Self::SigningContextUnavailable => "signing context unavailable",
            Self::SigningFailed => "deterministic signing failed",
            Self::SignatureSerializeFailed => "signature serialization failed",
            Self::SelfVerificationFailed => "produced signature self-verification failed",
            Self::ProvisioningContextUnavailable => "provisioning context unavailable",
            Self::ProvisioningPublicKeyCreateFailed => {
                "provisioning scalar public-key creation failed"
            }
            Self::ProvisioningSecretTweakRejected => "provisioning secret tweak rejected",
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

/// Compute the canonical compressed public key for one fixed provisioning
/// scalar through a freshly created non-static native context.
///
/// The scalar is borrowed only for the duration of the call and is never
/// copied into an exposed owner, returned, logged, or included in an error.
/// This purpose-bound HOST seam is not a general key-generation API.
pub fn provisioning_pubkey_create(secret: &[u8; 32]) -> Result<[u8; 33], SecpError> {
    let Some((code, obj)) = ffi::provisioning_pubkey_create(secret) else {
        return Err(SecpError::ProvisioningContextUnavailable);
    };
    if !map_status(code)? {
        return Err(SecpError::ProvisioningPublicKeyCreateFailed);
    }
    let key = PublicKey { obj };
    pubkey_serialize_compressed(&key)
}

/// Add one fixed tweak to one fixed provisioning parent scalar.
///
/// Native work happens on a scratch copy that is wiped on every path. The
/// caller's `output` is byte-for-byte unchanged unless the native status is
/// exactly ordinary success. Parent and tweak are borrowed and never exposed
/// through an accessor, error, or log. This purpose-bound HOST seam performs
/// no index scanning, retry, or general scalar arithmetic.
pub fn provisioning_secret_tweak_add(
    parent: &[u8; 32],
    tweak: &[u8; 32],
    output: &mut [u8; 32],
) -> Result<(), SecpError> {
    let mut candidate = [0u8; 32];
    let code = ffi::provisioning_secret_tweak_add(parent, tweak, &mut candidate);
    let status = match code {
        Some(code) => map_status(code),
        None => Err(SecpError::ProvisioningContextUnavailable),
    };
    let result = match status {
        Ok(true) => {
            output.copy_from_slice(&candidate);
            Ok(())
        }
        Ok(false) => Err(SecpError::ProvisioningSecretTweakRejected),
        Err(error) => Err(error),
    };
    ffi::wipe_secret(&mut candidate);
    result
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

/// Import one 32-byte secret scalar into opaque move-stable storage.
///
/// `source` is volatile-wiped before this function returns, whether
/// the scalar is accepted, rejected, or the native boundary reports an
/// unexpected status. No byte accessor exists on [`SecretKey`].
pub fn secret_key_import(source: &mut [u8; 32]) -> Result<SecretKey, SecpError> {
    // Allocate the move-stable destination before introducing secret
    // bytes into it; copy directly from the caller's source rather
    // than constructing a by-value secret array temporary.
    let mut owned = SecretKey {
        bytes: Box::new([0u8; ffi::SCALAR_BYTES]),
    };
    owned.bytes.copy_from_slice(source);
    ffi::wipe_secret(source);
    let status = ffi::secret_key_verify(owned.bytes.as_ref());
    if map_status(status)? {
        Ok(owned)
    } else {
        Err(SecpError::SecretKeyRejected)
    }
}

/// Serialize an opaque signature as strict bounded DER.
///
/// `output` is changed only after the native call succeeds and its
/// reported length is inside 8..=72. Bytes after the returned length
/// are zero.
pub fn signature_serialize_der(
    sig: &Signature,
    output: &mut [u8; DER_MAX_BYTES],
) -> Result<usize, SecpError> {
    let (code, len, serialized) = ffi::signature_serialize_der(&sig.obj);
    if !map_status(code)? || !(DER_MIN_BYTES..=DER_MAX_BYTES).contains(&len) {
        return Err(SecpError::SignatureSerializeFailed);
    }
    let mut committed = [0u8; DER_MAX_BYTES];
    let Some(destination) = committed.get_mut(..len) else {
        return Err(SecpError::SignatureSerializeFailed);
    };
    let Some(source) = serialized.get(..len) else {
        return Err(SecpError::SignatureSerializeFailed);
    };
    destination.copy_from_slice(source);
    *output = committed;
    Ok(len)
}

/// Produce one deterministic RFC6979 ECDSA signature.
///
/// The native signature is always normalized, serialized to strict
/// low-S DER, reparsed through [`signature_parse_der`], and verified
/// through [`ecdsa_verify`] against `expected_key` and the exact digest
/// before the opaque result is released. No additional nonce data is
/// supplied.
pub fn ecdsa_sign_rfc6979(
    secret: &SecretKey,
    digest32: &[u8; 32],
    expected_key: &PublicKey,
) -> Result<Signature, SecpError> {
    let Some((sign_code, signed_obj)) = ffi::ecdsa_sign_rfc6979(secret.bytes.as_ref(), digest32)
    else {
        return Err(SecpError::SigningContextUnavailable);
    };
    if !map_status(sign_code)? {
        return Err(SecpError::SigningFailed);
    }

    let (normalize_code, normalized_obj) = ffi::signature_normalize(&signed_obj);
    // Both ordinary statuses are successful: zero means the signer
    // already returned low-S; one means normalization changed S.
    let _was_high = map_status(normalize_code)?;
    let normalized = Signature {
        obj: normalized_obj,
    };

    let mut der = [0u8; DER_MAX_BYTES];
    let der_len = signature_serialize_der(&normalized, &mut der)?;
    if der_len > LOW_S_DER_MAX_BYTES {
        return Err(SecpError::SignatureSerializeFailed);
    }
    let Some(der_bytes) = der.get(..der_len) else {
        return Err(SecpError::SignatureSerializeFailed);
    };
    let reparsed = signature_parse_der(der_bytes).map_err(|error| match error {
        SecpError::UnknownReturnCode => SecpError::UnknownReturnCode,
        _ => SecpError::SignatureSerializeFailed,
    })?;
    match ecdsa_verify(&reparsed, digest32, expected_key) {
        Ok(()) => Ok(reparsed),
        Err(SecpError::VerificationFailed) => Err(SecpError::SelfVerificationFailed),
        Err(error) => Err(error),
    }
}

#[cfg(test)]
mod tests {
    use super::{map_status, secret_key_import, SecpError};

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
        assert_eq!(
            SecpError::SelfVerificationFailed.to_string(),
            "produced signature self-verification failed"
        );
        assert_eq!(
            SecpError::ProvisioningContextUnavailable.to_string(),
            "provisioning context unavailable"
        );
        assert_eq!(
            SecpError::ProvisioningPublicKeyCreateFailed.to_string(),
            "provisioning scalar public-key creation failed"
        );
        assert_eq!(
            SecpError::ProvisioningSecretTweakRejected.to_string(),
            "provisioning secret tweak rejected"
        );
    }

    #[test]
    fn rejected_secret_sources_are_always_wiped() {
        for mut source in [[0u8; 32], [0xffu8; 32]] {
            assert!(matches!(
                secret_key_import(&mut source),
                Err(SecpError::SecretKeyRejected)
            ));
            assert_eq!(source, [0u8; 32]);
        }
    }
}
