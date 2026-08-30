//! Bounded QK-DEC-136 HOST firmware-update reference.
//!
//! HOST SCAFFOLD ONLY — NOT PRODUCT CODE — NOT A WALLET — NO TARGET CLAIM.
//!
//! This crate owns the exact QKFM/QKUP v1 byte grammar, public-key-only
//! package verification, one-read private staging, and an explicitly mock
//! privileged-installer/dual-slot lifecycle. It contains no private-key
//! material, signing operation, randomness, real filesystem or removable
//! media access, bootloader, slot writer, Bitcoin-anchor acceptance logic,
//! network access, or hardware integration. Its cleanup behavior establishes
//! only the exercised HOST software path.

#![deny(unsafe_code)]
#![deny(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects
)]

use core::fmt;

mod der;
mod host_mock;
mod manifest;
mod package;
mod sha256;
mod staging;
mod trust;
mod wipe;

pub use host_mock::{
    BootVersionDisplay, CommittedInstallerState, FirstBootReport, MockPrivilegedInstaller, SlotId,
};
pub use manifest::{ArtifactFact, ArtifactKind, ManifestFacts, ReleaseVersion};
#[cfg(any(test, feature = "fuzzing"))]
#[doc(hidden)]
pub use package::verify_staged_fixture_package;
pub use package::{verify_staged_package, VerifiedPackage};
pub use staging::{
    stage_from_media, MockMediaCandidate, MockMediaFaults, MockReadOnlyMedia, StagedPackage,
    UpdatePresence,
};
pub use trust::CompiledTrust;

/// Canonical signed-manifest size.
pub const MANIFEST_BYTES: usize = 328;
/// Fixed-width artifact-record size.
pub const ARTIFACT_RECORD_BYTES: usize = 37;
/// Number of required artifact records.
pub const ARTIFACT_COUNT: usize = 6;
/// Maximum embedded firmware-image bytes in this HOST profile.
pub const MAX_FIRMWARE_IMAGE_BYTES: usize = 268_435_456;
/// Maximum detached-artifact bytes in this HOST profile.
pub const MAX_DETACHED_ARTIFACT_BYTES: u32 = 1_073_741_824;
/// Maximum non-image QKUP envelope bytes.
pub const MAX_PACKAGE_ENVELOPE_BYTES: usize = 482;
/// Maximum complete QKUP bytes.
pub const MAX_PACKAGE_BYTES: usize = MAX_FIRMWARE_IMAGE_BYTES + MAX_PACKAGE_ENVELOPE_BYTES;
/// Minimum complete package bytes with two eight-byte DER signatures and a
/// one-byte embedded image.
pub const MIN_PACKAGE_BYTES: usize = 4 + 1 + 2 + 328 + 1 + 2 * (1 + 1 + 8) + 1;
/// Exact manifest magic.
pub const MANIFEST_MAGIC: [u8; 4] = *b"QKFM";
/// Exact manifest schema byte.
pub const MANIFEST_SCHEMA: u8 = 1;
/// Fixed target-platform bytes.
pub const TARGET_PLATFORM: [u8; 4] = *b"QKT1";
/// Fixed compatibility epoch.
pub const COMPATIBILITY_EPOCH: u32 = 1;
/// Exact package magic.
pub const PACKAGE_MAGIC: [u8; 4] = *b"QKUP";
/// Exact package version.
pub const PACKAGE_VERSION: u8 = 1;
/// Sole root candidate name.
pub const UPDATE_FILE_NAME: &str = "quietkey-update.qkup";
/// Domain separating firmware-package ECDSA digests.
pub const SIGNATURE_DOMAIN: &[u8; 27] = b"QuietKey/FirmwarePackage/v1";
/// Domain separating firmware key-set identifiers.
pub const KEYSET_DOMAIN: &[u8; 26] = b"QuietKey/FirmwareKeySet/v1";
/// Domain separating printed anchor fingerprints.
pub const FINGERPRINT_DOMAIN: &[u8; 37] = b"QuietKey/FirmwareAnchorFingerprint/v1";
/// Maximum accepted low-S DER length.
pub const MAX_LOW_S_DER_BYTES: usize = 71;
/// Minimum accepted DER length.
pub const MIN_DER_BYTES: usize = 8;
/// secp256k1 `floor(n / 2)`, big-endian.
pub const SECP256K1_HALF_ORDER: [u8; 32] = [
    0x7f, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0x5d, 0x57, 0x6e, 0x73, 0x57, 0xa4, 0x50, 0x1d, 0xdf, 0xe9, 0x2f, 0x46, 0x68, 0x1b, 0x20, 0xa0,
];

/// Registered public test anchors, in fixed role order.
pub const REGISTERED_TEST_ANCHORS: [[u8; 33]; 3] = [
    [
        0x02, 0xe0, 0xb2, 0xf0, 0x44, 0xce, 0x0e, 0xcd, 0xb5, 0xc2, 0xdc, 0x01, 0xf3, 0xee, 0xa4,
        0xa3, 0xe9, 0xc5, 0xf6, 0x08, 0x99, 0x27, 0x2e, 0x64, 0x2e, 0xfb, 0x8f, 0x3b, 0x03, 0x08,
        0x8e, 0xa9, 0x61,
    ],
    [
        0x02, 0x3a, 0x6f, 0x84, 0x97, 0x72, 0x13, 0xd0, 0x00, 0xc7, 0x8b, 0x39, 0xa0, 0xa5, 0x23,
        0x06, 0x92, 0x2c, 0x28, 0x4c, 0x8e, 0xf2, 0x46, 0x36, 0x9d, 0x70, 0x3e, 0xd1, 0xb2, 0xb9,
        0x04, 0x43, 0x4c,
    ],
    [
        0x03, 0xc3, 0x1f, 0x66, 0x2d, 0x41, 0x87, 0x14, 0x92, 0xd8, 0x89, 0x54, 0x29, 0x08, 0x1e,
        0x42, 0x83, 0x59, 0xfd, 0x43, 0xed, 0x77, 0xc8, 0xdd, 0xf7, 0xfb, 0x12, 0xcb, 0x04, 0x86,
        0x7e, 0x04, 0x11,
    ],
];

/// Registered full anchor fingerprints, in fixed role order.
pub const REGISTERED_TEST_FINGERPRINTS: [[u8; 32]; 3] = [
    [
        0x6a, 0x51, 0x29, 0x6f, 0xf5, 0xf0, 0x38, 0x19, 0x58, 0x00, 0x20, 0x42, 0x84, 0xd6, 0x23,
        0xc2, 0x29, 0x7d, 0xf2, 0xdd, 0x16, 0xa3, 0xa3, 0x81, 0x5b, 0x5d, 0xbf, 0xf5, 0x9a, 0x98,
        0xbf, 0x13,
    ],
    [
        0x15, 0xb6, 0x08, 0x9b, 0x82, 0xd3, 0xab, 0x8a, 0xff, 0xd1, 0xcb, 0x39, 0xb8, 0xd0, 0x0f,
        0x91, 0xb1, 0x69, 0x1c, 0x19, 0xbe, 0x70, 0xfb, 0x20, 0x69, 0x9c, 0xd9, 0xb7, 0x42, 0x04,
        0xd4, 0x5f,
    ],
    [
        0x70, 0x31, 0xd4, 0xe8, 0xa0, 0x61, 0x79, 0x5a, 0x8f, 0x8f, 0x0f, 0x63, 0x75, 0xad, 0x92,
        0x87, 0xa5, 0x47, 0x57, 0x7e, 0xbd, 0xfd, 0x7c, 0x3a, 0x90, 0xd5, 0x6d, 0xa0, 0x24, 0xc1,
        0x30, 0xac,
    ],
];

/// Registered ordered test key-set identifier.
pub const REGISTERED_TEST_KEYSET_ID: [u8; 32] = [
    0xb3, 0xa7, 0x30, 0x44, 0xf0, 0xba, 0xac, 0x9b, 0xa8, 0xdf, 0x89, 0x75, 0xad, 0xba, 0x87, 0x71,
    0x4d, 0x89, 0x63, 0x02, 0x58, 0x6f, 0x64, 0x55, 0x31, 0xfa, 0x30, 0x8f, 0x8f, 0x1e, 0xe5, 0x19,
];

const _: () = assert!(MANIFEST_BYTES == 106 + ARTIFACT_COUNT * ARTIFACT_RECORD_BYTES);
const _: () = assert!(MAX_PACKAGE_ENVELOPE_BYTES == 4 + 1 + 2 + 328 + 1 + 2 * (1 + 1 + 71));
const _: () = assert!(MAX_PACKAGE_BYTES == 268_435_938);
const _: () = assert!(MIN_PACKAGE_BYTES == 357);

/// Closed QK-DEC-136 rejection vocabulary.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum UpdateError {
    WalletSessionActive,
    CardPresent,
    MediaAlreadyRead,
    UpdateCandidateMissing,
    SecondUpdateCandidate,
    MediaReadFailed,
    StagingAllocationFailed,
    StagingCopyFailed,
    PackageLengthOutOfBounds,
    PackageMagicMismatch,
    PackageVersionMismatch,
    ManifestLengthFieldMismatch,
    ManifestTruncated,
    ManifestMagicMismatch,
    ManifestSchemaVersionMismatch,
    TargetPlatformMismatch,
    CompatibilityEpochMismatch,
    ReleaseSequenceZero,
    ArtifactCountMismatch,
    ArtifactKindMismatch,
    FirmwareImageLengthOutOfBounds,
    DetachedArtifactLengthOutOfBounds,
    CompiledAnchorMalformed,
    DuplicateCompiledAnchor,
    TestAnchorInProduction,
    SigningKeysetMismatch,
    SignatureCountMismatch,
    SignatureRoleOutOfRange,
    DuplicateSignatureRole,
    SignatureRoleNotAscending,
    SignatureLengthOutOfBounds,
    SignatureTruncated,
    MalformedDerSignature,
    HighSSignature,
    FirmwareImageTruncated,
    TrailingByte,
    FirmwareImageHashMismatch,
    InvalidSignature,
    NotStrictlyNewer,
    InstallerNotStrictlyNewer,
    InstallerKeysetMismatch,
    InvalidSlotDecision,
    BootReportMismatch,
    BootNotConfirmed,
    InvalidTransition,
}

impl fmt::Display for UpdateError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::WalletSessionActive => "wallet session active",
            Self::CardPresent => "card present",
            Self::MediaAlreadyRead => "update media already read",
            Self::UpdateCandidateMissing => "update candidate missing",
            Self::SecondUpdateCandidate => "second update candidate present",
            Self::MediaReadFailed => "update media read failed",
            Self::StagingAllocationFailed => "staging allocation failed",
            Self::StagingCopyFailed => "staging copy failed",
            Self::PackageLengthOutOfBounds => "package length out of bounds",
            Self::PackageMagicMismatch => "package magic mismatch",
            Self::PackageVersionMismatch => "package version mismatch",
            Self::ManifestLengthFieldMismatch => "manifest length field mismatch",
            Self::ManifestTruncated => "manifest truncated",
            Self::ManifestMagicMismatch => "manifest magic mismatch",
            Self::ManifestSchemaVersionMismatch => "manifest schema version mismatch",
            Self::TargetPlatformMismatch => "target platform mismatch",
            Self::CompatibilityEpochMismatch => "compatibility epoch mismatch",
            Self::ReleaseSequenceZero => "release sequence is zero",
            Self::ArtifactCountMismatch => "artifact count mismatch",
            Self::ArtifactKindMismatch => "artifact kind mismatch",
            Self::FirmwareImageLengthOutOfBounds => "firmware image length out of bounds",
            Self::DetachedArtifactLengthOutOfBounds => "detached artifact length out of bounds",
            Self::CompiledAnchorMalformed => "compiled anchor malformed",
            Self::DuplicateCompiledAnchor => "duplicate compiled anchor",
            Self::TestAnchorInProduction => "test anchor present in production",
            Self::SigningKeysetMismatch => "signing key set mismatch",
            Self::SignatureCountMismatch => "signature count mismatch",
            Self::SignatureRoleOutOfRange => "signature role out of range",
            Self::DuplicateSignatureRole => "duplicate signature role",
            Self::SignatureRoleNotAscending => "signature roles not ascending",
            Self::SignatureLengthOutOfBounds => "signature length out of bounds",
            Self::SignatureTruncated => "signature truncated",
            Self::MalformedDerSignature => "malformed der signature",
            Self::HighSSignature => "high-s signature",
            Self::FirmwareImageTruncated => "firmware image truncated",
            Self::TrailingByte => "trailing package byte",
            Self::FirmwareImageHashMismatch => "firmware image hash mismatch",
            Self::InvalidSignature => "invalid firmware signature",
            Self::NotStrictlyNewer => "firmware version is not strictly newer",
            Self::InstallerNotStrictlyNewer => "installer version is not strictly newer",
            Self::InstallerKeysetMismatch => "installer key set mismatch",
            Self::InvalidSlotDecision => "invalid slot decision",
            Self::BootReportMismatch => "boot report mismatch",
            Self::BootNotConfirmed => "successful first boot not confirmed",
            Self::InvalidTransition => "invalid update transition",
        })
    }
}

impl std::error::Error for UpdateError {}
