//! Fixed-memory HOST reference for the canonical QuietKey v2 Kit share codec
//! and opaque consuming restore mathematics.
//!
//! HOST REFERENCE ONLY -- NOT A KIT GENERATOR, SCANNER, WALLET, CARD
//! PROVISIONER, OR NORMAL-WALLET RESUME PATH -- NO TARGET, PERFORMANCE, OR
//! GATE CLAIM.
//!
//! This crate validates and encodes one exact share-frame profile, its exact
//! M18 fallback text and one deterministic logical QR symbol. It can combine
//! one valid opposite-index same-wallet pair only into an opaque, zeroizing
//! owner, rebind that owner to exact public wallet facts, and prepare one
//! non-signing replacement-B or A1-reprint mock boundary. Its own storage is
//! fixed-size; bounded allocations inherited from qk-bip32 remain separately
//! measured. It performs no I/O, logging, randomness, rendering, image
//! recognition, normalization, persistence, signing, or payload release.

#![deny(unsafe_code)]

mod fallback;
mod frame;
mod qr;
mod restore_v2;
mod secret;
mod sha256;

use core::fmt;

pub use fallback::{decode_fallback, encode_fallback};
pub use frame::{combine_frames, encode_frame, frame_metadata};
pub use qr::encode_qr;
pub use restore_v2::{
    A1ReprintDispositionV2, A1ReprintReceiptV2, A1ReprintViewV2, BoundKitRestoreV2,
    KitRestoreDispositionV2, KitRestoreErrorV2, PreparedA1ReprintV2, PreparedReplacementBV2,
    ReplacementBReceiptV2, ReplacementBViewV2, SurvivingBFactorV2,
};

/// Exact canonical Kit share-frame length in bytes.
pub const FRAME_LEN: usize = 142;
/// Exact number of M18 symbols encoding one canonical frame.
pub const FALLBACK_SYMBOLS: usize = 228;
/// Exact logical QR core width and height for version 10.
pub const QR_CORE_SIZE: usize = 57;
/// Exact logical QR width and height including the four-module quiet zone.
pub const QR_SIZE: usize = 65;
/// Exact packed-byte capacity for one 65-by-65 row-major logical QR bitmap.
pub const QR_PACKED_BYTES: usize = 529;

const _: () = assert!(FRAME_LEN * 8 + 4 == FALLBACK_SYMBOLS * 5);
const _: () = assert!(QR_CORE_SIZE + 8 == QR_SIZE);
const _: () = assert!((QR_SIZE * QR_SIZE).div_ceil(8) == QR_PACKED_BYTES);

/// Closed canonical Kit-codec rejection surface in stable precedence order.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum KitError {
    FrameLength,
    FrameChecksum,
    InvalidMagic,
    UnsupportedVersion,
    InvalidShareIndex,
    FallbackLength,
    MalformedSymbol,
    NonCanonicalPadding,
    DuplicateShare,
    SameShareIndex,
    WalletMismatch,
}

impl fmt::Display for KitError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::FrameLength => "FrameLength",
            Self::FrameChecksum => "FrameChecksum",
            Self::InvalidMagic => "InvalidMagic",
            Self::UnsupportedVersion => "UnsupportedVersion",
            Self::InvalidShareIndex => "InvalidShareIndex",
            Self::FallbackLength => "FallbackLength",
            Self::MalformedSymbol => "MalformedSymbol",
            Self::NonCanonicalPadding => "NonCanonicalPadding",
            Self::DuplicateShare => "DuplicateShare",
            Self::SameShareIndex => "SameShareIndex",
            Self::WalletMismatch => "WalletMismatch",
        })
    }
}

impl std::error::Error for KitError {}

/// Canonical envelope-share index.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ShareIndex {
    One,
    Two,
}

impl ShareIndex {
    /// Return the canonical one-byte frame representation.
    pub const fn as_u8(self) -> u8 {
        match self {
            Self::One => 1,
            Self::Two => 2,
        }
    }

    pub(crate) const fn parse(value: u8) -> Result<Self, KitError> {
        match value {
            1 => Ok(Self::One),
            2 => Ok(Self::Two),
            _ => Err(KitError::InvalidShareIndex),
        }
    }
}

/// Public non-secret facts authenticated by one canonical share frame.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct FrameMetadata {
    pub share_index: ShareIndex,
    pub wallet_id: [u8; 32],
}

/// Public non-secret facts produced by deterministic logical QR encoding.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct QrMetadata {
    pub mask: u8,
    pub penalties: [u32; 8],
}

/// Opaque combined 96-byte Kit payload owner.
///
/// No payload accessor, serializer, formatter, comparison, snapshot, cloning,
/// or copying surface is exposed. Later ratified Kit operations may consume
/// this owner without making its bytes public.
pub struct RecoveredKitPayload {
    _bytes: secret::Secret<96>,
}

impl RecoveredKitPayload {
    pub(crate) fn take(bytes: &mut [u8; 96]) -> Self {
        Self {
            _bytes: secret::Secret::take(bytes),
        }
    }
}
