//! Test-only HOST model of the QK-DEC-161 Key Card B protocol.
//!
//! This crate models the frozen byte protocol, lifecycle, persistent-integrity
//! boundary and role-B cryptographic behavior. It is not a Java Card simulator,
//! contains no applet or production code, uses no device, clock or randomness,
//! and makes no delivered-platform, target, performance or Gate claim.

#![deny(unsafe_code)]
#![deny(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

mod crypto;
mod hmac_sha512;
mod model;
mod scalar;
mod sha256;
mod sha512;
#[allow(unsafe_code)]
mod wipe;

pub use model::{CardInfo, CardModel, FaultPoint, ModelError, SignReply};
pub use qk_card_protocol::{
    Lifecycle as ModelLifecycle, Mode as ModelMode, Profile as ModelProfile,
};

/// Exact immutable card-record width.
pub const RECORD_BYTES: usize = qk_card_protocol::RECORD_BYTES;
/// Exact raw account extended-key width.
pub const EXTENDED_KEY_BYTES: usize = qk_card_protocol::RAW_XPRV_BYTES;
/// Exact descriptor width in the committed record.
pub const DESCRIPTOR_BYTES: usize = qk_card_protocol::DESCRIPTOR_BYTES;
/// Exact maximum DER signature width accepted by the protocol.
pub const MAX_DER_BYTES: usize = 72;

/// Fixed response owner width used by [`CardModel::process_apdu`].
pub const RESPONSE_BYTES: usize = qk_card_protocol::MAX_RESPONSE_BYTES;

#[cfg(feature = "fuzzing")]
#[doc(hidden)]
pub fn reset_wipe_counter() {
    wipe::reset_wiped_bytes();
}

#[cfg(feature = "fuzzing")]
#[doc(hidden)]
pub fn wipe_counter() -> usize {
    wipe::wiped_bytes()
}
