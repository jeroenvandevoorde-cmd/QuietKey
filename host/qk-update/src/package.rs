//! Exact QKUP v1 framing and public-key-only package verification.

use crate::{
    der, manifest,
    sha256::{self, Sha256},
    staging::{StagedPackage, UpdatePresence},
    trust::CompiledTrust,
    ManifestFacts, ReleaseVersion, UpdateError, MANIFEST_BYTES, PACKAGE_MAGIC, PACKAGE_VERSION,
    SIGNATURE_DOMAIN,
};

const MANIFEST_START: usize = 7;
const SIGNATURE_COUNT_OFFSET: usize = MANIFEST_START + MANIFEST_BYTES;
const SIGNATURES_START: usize = SIGNATURE_COUNT_OFFSET + 1;
const ZERO_SEPARATOR: [u8; 1] = [0];
// These public test placeholders deliberately make an ordinary HOST build
// refuse verification mechanically. A production release substitutes its
// three Owner-registered anchors here as an ordinary reviewed source change;
// callers never select trust at runtime.
const COMPILED_ANCHORS: [[u8; 33]; 3] = crate::REGISTERED_TEST_ANCHORS;

struct SignatureInput<'a> {
    role: u8,
    der: der::ParsedDer<'a>,
}

#[derive(Clone, Copy)]
enum TrustPolicy {
    Production,
    #[cfg(any(test, feature = "fuzzing"))]
    Fixture,
}

/// Successfully verified package facts plus the still-private staged image.
/// This capability is intentionally neither clonable nor printable.
pub struct VerifiedPackage {
    staging: StagedPackage,
    manifest: ManifestFacts,
    publication_hash: [u8; 32],
    signature_digest: [u8; 32],
    firmware_image_sha256: [u8; 32],
    image_start: usize,
    image_length: usize,
    #[cfg(any(test, feature = "fuzzing"))]
    signature_checks: u8,
}

impl VerifiedPackage {
    /// Immutable signed manifest facts.
    pub const fn manifest(&self) -> &ManifestFacts {
        &self.manifest
    }

    /// Publication identity: SHA-256 of only the 328 manifest bytes.
    pub const fn publication_hash(&self) -> [u8; 32] {
        self.publication_hash
    }

    /// Domain-separated digest verified by both ECDSA signatures.
    pub const fn signature_digest(&self) -> [u8; 32] {
        self.signature_digest
    }

    /// SHA-256 of the exact staged candidate image bytes.
    pub const fn firmware_image_sha256(&self) -> [u8; 32] {
        self.firmware_image_sha256
    }

    /// Exact embedded candidate image length.
    pub const fn firmware_image_length(&self) -> usize {
        self.image_length
    }

    #[cfg(any(test, feature = "fuzzing"))]
    #[doc(hidden)]
    pub const fn signature_checks(&self) -> u8 {
        self.signature_checks
    }

    pub(crate) fn image_bytes(&self) -> Result<&[u8], UpdateError> {
        let end = self
            .image_start
            .checked_add(self.image_length)
            .ok_or(UpdateError::FirmwareImageTruncated)?;
        self.staging
            .bytes()
            .get(self.image_start..end)
            .ok_or(UpdateError::FirmwareImageTruncated)
    }
}

fn fixed<const N: usize>(bytes: &[u8], start: usize) -> Result<[u8; N], UpdateError> {
    let end = start.checked_add(N).ok_or(UpdateError::ManifestTruncated)?;
    bytes
        .get(start..end)
        .ok_or(UpdateError::ManifestTruncated)?
        .try_into()
        .map_err(|_| UpdateError::ManifestTruncated)
}

fn parse_signature<'a>(
    bytes: &'a [u8],
    cursor: usize,
    prior_role: Option<u8>,
) -> Result<(SignatureInput<'a>, usize), UpdateError> {
    let role = bytes
        .get(cursor)
        .copied()
        .ok_or(UpdateError::SignatureTruncated)?;
    if !(1..=3).contains(&role) {
        return Err(UpdateError::SignatureRoleOutOfRange);
    }
    if prior_role == Some(role) {
        return Err(UpdateError::DuplicateSignatureRole);
    }
    if prior_role.is_some_and(|prior| role < prior) {
        return Err(UpdateError::SignatureRoleNotAscending);
    }
    let length_at = cursor
        .checked_add(1)
        .ok_or(UpdateError::SignatureTruncated)?;
    let der_length = bytes
        .get(length_at)
        .copied()
        .map(usize::from)
        .ok_or(UpdateError::SignatureTruncated)?;
    if !(crate::MIN_DER_BYTES..=crate::MAX_LOW_S_DER_BYTES).contains(&der_length) {
        return Err(UpdateError::SignatureLengthOutOfBounds);
    }
    let der_start = cursor
        .checked_add(2)
        .ok_or(UpdateError::SignatureTruncated)?;
    let der_end = der_start
        .checked_add(der_length)
        .ok_or(UpdateError::SignatureTruncated)?;
    let der_bytes = bytes
        .get(der_start..der_end)
        .ok_or(UpdateError::SignatureTruncated)?;
    let parsed = der::parse_strict_low_s(der_bytes)?;
    Ok((SignatureInput { role, der: parsed }, der_end))
}

fn manifest_hashes(manifest_bytes: &[u8]) -> Result<([u8; 32], [u8; 32]), UpdateError> {
    let mut publication = Sha256::new();
    let mut signature = Sha256::new();
    signature
        .update(SIGNATURE_DOMAIN)
        .map_err(|_| UpdateError::InvalidSignature)?;
    signature
        .update(&ZERO_SEPARATOR)
        .map_err(|_| UpdateError::InvalidSignature)?;
    // One manifest traversal feeds both fixed-state hash owners.
    for chunk in manifest_bytes.chunks(64) {
        publication
            .update(chunk)
            .map_err(|_| UpdateError::InvalidSignature)?;
        signature
            .update(chunk)
            .map_err(|_| UpdateError::InvalidSignature)?;
    }
    Ok((
        publication
            .finalize()
            .map_err(|_| UpdateError::InvalidSignature)?,
        signature
            .finalize()
            .map_err(|_| UpdateError::InvalidSignature)?,
    ))
}

fn verify_signature(input: &SignatureInput<'_>, digest: &[u8; 32], trust: &CompiledTrust) -> bool {
    let Ok(key) = trust.role_key(input.role) else {
        return false;
    };
    let Ok(signature) = qk_secp::signature_parse_der(input.der.as_bytes()) else {
        return false;
    };
    qk_secp::ecdsa_verify(&signature, digest, key).is_ok()
}

fn verify_with_policy(
    staged: StagedPackage,
    compiled_anchors: [[u8; 33]; 3],
    trust_policy: TrustPolicy,
    committed_floor: ReleaseVersion,
    presence: UpdatePresence,
) -> Result<VerifiedPackage, UpdateError> {
    presence.enforce()?;
    let bytes = staged.bytes();
    if fixed::<4>(bytes, 0)? != PACKAGE_MAGIC {
        return Err(UpdateError::PackageMagicMismatch);
    }
    if bytes.get(4).copied() != Some(PACKAGE_VERSION) {
        return Err(UpdateError::PackageVersionMismatch);
    }
    let manifest_length = u16::from_le_bytes(fixed(bytes, 5)?);
    if usize::from(manifest_length) != MANIFEST_BYTES {
        return Err(UpdateError::ManifestLengthFieldMismatch);
    }
    let manifest_end = MANIFEST_START
        .checked_add(MANIFEST_BYTES)
        .ok_or(UpdateError::ManifestTruncated)?;
    let manifest_bytes = bytes
        .get(MANIFEST_START..manifest_end)
        .ok_or(UpdateError::ManifestTruncated)?;
    let manifest = manifest::parse(manifest_bytes)?;

    let trust = match trust_policy {
        TrustPolicy::Production => CompiledTrust::production(compiled_anchors)?,
        #[cfg(any(test, feature = "fuzzing"))]
        TrustPolicy::Fixture => CompiledTrust::fixture(compiled_anchors)?,
    };
    if manifest.signing_keyset_id() != trust.keyset_id() {
        return Err(UpdateError::SigningKeysetMismatch);
    }
    if bytes.get(SIGNATURE_COUNT_OFFSET).copied() != Some(2) {
        return Err(UpdateError::SignatureCountMismatch);
    }
    let (first, next) = parse_signature(bytes, SIGNATURES_START, None)?;
    let (second, image_start) = parse_signature(bytes, next, Some(first.role))?;

    let image_length = usize::try_from(manifest.firmware_image().byte_length())
        .map_err(|_| UpdateError::FirmwareImageLengthOutOfBounds)?;
    let image_end = image_start
        .checked_add(image_length)
        .ok_or(UpdateError::FirmwareImageTruncated)?;
    if bytes.len() < image_end {
        return Err(UpdateError::FirmwareImageTruncated);
    }
    if bytes.len() > image_end {
        return Err(UpdateError::TrailingByte);
    }
    let image = bytes
        .get(image_start..image_end)
        .ok_or(UpdateError::FirmwareImageTruncated)?;
    let firmware_image_sha256 =
        sha256::sha256(&[image]).map_err(|_| UpdateError::FirmwareImageHashMismatch)?;
    if firmware_image_sha256 != manifest.firmware_image().sha256() {
        return Err(UpdateError::FirmwareImageHashMismatch);
    }

    let (publication_hash, signature_digest) = manifest_hashes(manifest_bytes)?;
    // Both structurally valid records are attempted exactly once even if the
    // first one is cryptographically invalid.
    let first_valid = verify_signature(&first, &signature_digest, &trust);
    let second_valid = verify_signature(&second, &signature_digest, &trust);
    if !first_valid || !second_valid {
        return Err(UpdateError::InvalidSignature);
    }
    if manifest.version() <= committed_floor {
        return Err(UpdateError::NotStrictlyNewer);
    }

    Ok(VerifiedPackage {
        staging: staged,
        manifest,
        publication_hash,
        signature_digest,
        firmware_image_sha256,
        image_start,
        image_length,
        #[cfg(any(test, feature = "fuzzing"))]
        signature_checks: 2,
    })
}

/// Verify one staged package with production trust-anchor refusal enabled.
pub fn verify_staged_package(
    staged: StagedPackage,
    committed_floor: ReleaseVersion,
    presence: UpdatePresence,
) -> Result<VerifiedPackage, UpdateError> {
    verify_with_policy(
        staged,
        COMPILED_ANCHORS,
        TrustPolicy::Production,
        committed_floor,
        presence,
    )
}

/// Test/fuzz-only fixture-anchor verification seam. It does not exist in an
/// ordinary production build.
#[cfg(any(test, feature = "fuzzing"))]
#[doc(hidden)]
pub fn verify_staged_fixture_package(
    staged: StagedPackage,
    committed_floor: ReleaseVersion,
    presence: UpdatePresence,
) -> Result<VerifiedPackage, UpdateError> {
    verify_with_policy(
        staged,
        crate::REGISTERED_TEST_ANCHORS,
        TrustPolicy::Fixture,
        committed_floor,
        presence,
    )
}
