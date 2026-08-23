//! Candidate resource limits (QK-DEC-031). Candidate constants only:
//! explicit, reviewable bounds with no target-RAM or conformance claim.

/// Maximum unsigned-transaction inputs (and therefore input maps).
pub const MAX_INPUTS: usize = 100;

/// Maximum unsigned-transaction outputs (and therefore output maps).
pub const MAX_OUTPUTS: usize = 32;

/// Maximum signer-bearing records per map: partial signatures per input,
/// BIP32 derivation records per input or output map, and global xpubs.
pub const MAX_SIGNERS: usize = 15;

/// Maximum BIP32 derivation path depth in any derivation record value.
pub const MAX_PATH_DEPTH: usize = 12;

/// Hard cap on a microSD-sourced input artifact: 2 MiB.
pub const MAX_SD_INPUT_BYTES: usize = 2 * 1024 * 1024;

/// Hard cap on an assembled QR-sourced input: 256 KiB.
pub const MAX_QR_INPUT_BYTES: usize = 256 * 1024;

/// QR transport cap: maximum frame count. Enforced by the transport
/// intake layer, not by this parser (which sees only assembled bytes).
pub const MAX_QR_FRAMES: usize = 256;

/// QR transport cap: maximum scan window in seconds. Enforced by the
/// transport intake layer, not by this parser.
pub const MAX_QR_SCAN_SECONDS: usize = 120;
