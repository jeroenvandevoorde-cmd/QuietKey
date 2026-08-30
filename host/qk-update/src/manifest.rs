//! Exact fixed-width QKFM v1 manifest parsing.

use crate::{
    UpdateError, ARTIFACT_COUNT, ARTIFACT_RECORD_BYTES, COMPATIBILITY_EPOCH, MANIFEST_BYTES,
    MANIFEST_MAGIC, MANIFEST_SCHEMA, MAX_DETACHED_ARTIFACT_BYTES, MAX_FIRMWARE_IMAGE_BYTES,
    TARGET_PLATFORM,
};

const ARTIFACTS_OFFSET: usize = 106;

/// One fixed artifact role in canonical manifest order.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum ArtifactKind {
    FirmwareImage = 1,
    Sbom = 2,
    BuildProvenanceAndToolchain = 3,
    SourceArchive = 4,
    CardProtocol = 5,
    RescueTooling = 6,
}

impl ArtifactKind {
    fn for_position(position: usize) -> Option<Self> {
        match position {
            0 => Some(Self::FirmwareImage),
            1 => Some(Self::Sbom),
            2 => Some(Self::BuildProvenanceAndToolchain),
            3 => Some(Self::SourceArchive),
            4 => Some(Self::CardProtocol),
            5 => Some(Self::RescueTooling),
            _ => None,
        }
    }

    /// Exact record kind byte.
    pub const fn code(self) -> u8 {
        self as u8
    }
}

/// One signed artifact fact.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ArtifactFact {
    kind: ArtifactKind,
    byte_length: u32,
    sha256: [u8; 32],
}

impl ArtifactFact {
    /// Artifact role.
    pub const fn kind(&self) -> ArtifactKind {
        self.kind
    }

    /// Signed artifact byte length.
    pub const fn byte_length(&self) -> u32 {
        self.byte_length
    }

    /// Signed SHA-256 digest.
    pub const fn sha256(&self) -> [u8; 32] {
        self.sha256
    }
}

/// Lexicographically ordered compatibility epoch and release sequence.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct ReleaseVersion {
    epoch: u32,
    sequence: u64,
}

impl ReleaseVersion {
    /// Construct a version fact. Parsing separately enforces the v1 epoch and
    /// nonzero sequence; mock installer state may use sequence zero as floor.
    pub const fn new(epoch: u32, sequence: u64) -> Self {
        Self { epoch, sequence }
    }

    /// Compatibility epoch.
    pub const fn epoch(&self) -> u32 {
        self.epoch
    }

    /// Release sequence.
    pub const fn sequence(&self) -> u64 {
        self.sequence
    }
}

/// Parsed immutable facts covered by the canonical manifest bytes.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ManifestFacts {
    version: ReleaseVersion,
    source_commit: [u8; 20],
    signing_keyset_id: [u8; 32],
    target_keyset_id: [u8; 32],
    artifacts: [ArtifactFact; ARTIFACT_COUNT],
}

impl ManifestFacts {
    /// Parsed version pair.
    pub const fn version(&self) -> ReleaseVersion {
        self.version
    }

    /// Informational, signed source-commit provenance bytes.
    pub const fn source_commit(&self) -> [u8; 20] {
        self.source_commit
    }

    /// Key set that must verify this manifest.
    pub const fn signing_keyset_id(&self) -> [u8; 32] {
        self.signing_keyset_id
    }

    /// Key set the candidate image reports after its first boot.
    pub const fn target_keyset_id(&self) -> [u8; 32] {
        self.target_keyset_id
    }

    /// All six canonical signed artifact facts.
    pub const fn artifacts(&self) -> &[ArtifactFact; ARTIFACT_COUNT] {
        &self.artifacts
    }

    /// Embedded firmware-image fact.
    pub const fn firmware_image(&self) -> &ArtifactFact {
        let [firmware, ..] = &self.artifacts;
        firmware
    }
}

fn fixed<const N: usize>(bytes: &[u8], start: usize) -> Result<[u8; N], UpdateError> {
    let end = start.checked_add(N).ok_or(UpdateError::ManifestTruncated)?;
    let view = bytes
        .get(start..end)
        .ok_or(UpdateError::ManifestTruncated)?;
    view.try_into().map_err(|_| UpdateError::ManifestTruncated)
}

fn u32_le(bytes: &[u8], start: usize) -> Result<u32, UpdateError> {
    Ok(u32::from_le_bytes(fixed(bytes, start)?))
}

fn u64_le(bytes: &[u8], start: usize) -> Result<u64, UpdateError> {
    Ok(u64::from_le_bytes(fixed(bytes, start)?))
}

pub(crate) fn parse(bytes: &[u8]) -> Result<ManifestFacts, UpdateError> {
    if bytes.len() != MANIFEST_BYTES {
        return Err(UpdateError::ManifestTruncated);
    }
    if fixed::<4>(bytes, 0)? != MANIFEST_MAGIC {
        return Err(UpdateError::ManifestMagicMismatch);
    }
    if bytes.get(4).copied() != Some(MANIFEST_SCHEMA) {
        return Err(UpdateError::ManifestSchemaVersionMismatch);
    }
    if fixed::<4>(bytes, 5)? != TARGET_PLATFORM {
        return Err(UpdateError::TargetPlatformMismatch);
    }
    let epoch = u32_le(bytes, 9)?;
    if epoch != COMPATIBILITY_EPOCH {
        return Err(UpdateError::CompatibilityEpochMismatch);
    }
    let sequence = u64_le(bytes, 13)?;
    if sequence == 0 {
        return Err(UpdateError::ReleaseSequenceZero);
    }
    let source_commit = fixed(bytes, 21)?;
    let signing_keyset_id = fixed(bytes, 41)?;
    let target_keyset_id = fixed(bytes, 73)?;
    if bytes.get(105).copied() != u8::try_from(ARTIFACT_COUNT).ok() {
        return Err(UpdateError::ArtifactCountMismatch);
    }

    let placeholder = ArtifactFact {
        kind: ArtifactKind::FirmwareImage,
        byte_length: 1,
        sha256: [0; 32],
    };
    let mut artifacts = [placeholder; ARTIFACT_COUNT];
    for (position, destination) in artifacts.iter_mut().enumerate() {
        let expected =
            ArtifactKind::for_position(position).ok_or(UpdateError::ArtifactKindMismatch)?;
        let delta = position
            .checked_mul(ARTIFACT_RECORD_BYTES)
            .ok_or(UpdateError::ManifestTruncated)?;
        let start = ARTIFACTS_OFFSET
            .checked_add(delta)
            .ok_or(UpdateError::ManifestTruncated)?;
        if bytes.get(start).copied() != Some(expected.code()) {
            return Err(UpdateError::ArtifactKindMismatch);
        }
        let byte_length = u32_le(
            bytes,
            start.checked_add(1).ok_or(UpdateError::ManifestTruncated)?,
        )?;
        let length_valid = if expected == ArtifactKind::FirmwareImage {
            usize::try_from(byte_length)
                .map(|length| (1..=MAX_FIRMWARE_IMAGE_BYTES).contains(&length))
                .unwrap_or(false)
        } else {
            (1..=MAX_DETACHED_ARTIFACT_BYTES).contains(&byte_length)
        };
        if !length_valid {
            return Err(if expected == ArtifactKind::FirmwareImage {
                UpdateError::FirmwareImageLengthOutOfBounds
            } else {
                UpdateError::DetachedArtifactLengthOutOfBounds
            });
        }
        let hash_start = start.checked_add(5).ok_or(UpdateError::ManifestTruncated)?;
        *destination = ArtifactFact {
            kind: expected,
            byte_length,
            sha256: fixed(bytes, hash_start)?,
        };
    }

    Ok(ManifestFacts {
        version: ReleaseVersion::new(epoch, sequence),
        source_commit,
        signing_keyset_id,
        target_keyset_id,
        artifacts,
    })
}
