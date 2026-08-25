//! Bounded offline checker for registered card-bench trace text (QK-DEC-105).
//!
//! HOST BENCH TOOL ONLY -- NOT CARD I/O -- NOT AN APPLET -- NOT A WALLET --
//! NO TARGET OR GATE CLAIM.
//!
//! The crate parses committed mock trace text only. It has no PC/SC, reader,
//! network, cryptographic, key, provisioning, mutation, or device access.
//! Every size control is supplied explicitly by the caller; there is no
//! product or APDU-limit default. The live APDU allowlist is deliberately
//! empty, and live mode is rejected until a later Owner-ratified registration
//! adds exact commands and a separately reviewed live format.

#![forbid(unsafe_code)]

mod allowlist;
mod hex;
mod registration;
mod trace;

pub use registration::{assert_complete_assertion_set, Assertion, RegistrationError};
pub use trace::{inspect_trace, TraceError, TraceLimits, TraceMode, TraceSummary};

/// Formats one validated digest as canonical lowercase hexadecimal.
///
/// This performs no hashing. The future evidence procedure computes hashes
/// outside this dependency-free checker and supplies the resulting field.
pub fn format_sha256(digest: &[u8; 32]) -> [u8; 64] {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut encoded = [0u8; 64];
    for (index, byte) in digest.iter().copied().enumerate() {
        encoded[index * 2] = HEX[usize::from(byte >> 4)];
        encoded[index * 2 + 1] = HEX[usize::from(byte & 0x0f)];
    }
    encoded
}
