//! Candidate resource limits (QK-DEC-031, QK-DEC-035; recorded under
//! the QK-DEC-034 process). Candidate constants only: explicit,
//! reviewable bounds with no target-RAM or conformance claim; final
//! values remain OPEN pending each affected registry row's freeze pack
//! and authorization.

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

/// CANDIDATE (QK-DEC-035, QK-LIM-PSBT-007): maximum complete raw key
/// bytes per record — encoded key type plus key data, excluding the
/// outer key-length prefix. HOST-scaffold candidate; no conformance
/// claim; final value OPEN.
pub const MAX_KEY_BYTES: usize = 128;

/// CANDIDATE (QK-DEC-035, QK-LIM-PSBT-008): maximum value bytes per
/// record, excluding the length prefix (1 MiB). HOST-scaffold
/// candidate; no conformance claim; final value OPEN.
pub const MAX_VALUE_BYTES: usize = 1_048_576;

/// CANDIDATE (QK-DEC-035, shared across QK-LIM-PSBT-002/009/010 and
/// explicitly covering QK-LIM-PSBT-012): maximum records per map.
/// Every known, unknown, and proprietary non-separator record counts,
/// including the required global unsigned-transaction record; the
/// count resets per map. Not an aggregate cap; the separate shared
/// signer cap remains. HOST-scaffold candidate; no conformance claim;
/// final value OPEN.
pub const MAX_RECORDS_PER_MAP: usize = 64;

/// CANDIDATE (QK-DEC-035): maximum scriptPubKey bytes for each output
/// of the global unsigned transaction (consensus MAX_SCRIPT_SIZE).
/// HOST-scaffold candidate; no conformance claim; final value OPEN.
pub const MAX_TX_OUTPUT_SCRIPT_BYTES: usize = 10_000;

/// CANDIDATE (QK-DEC-067): maximum canonical OP_RETURN payload bytes
/// accepted by the HOST-only M13 recipient-script-facts route.
/// Candidate only under QK-DEC-034; the registry freeze pack remains
/// owed and no conformance claim is made.
pub const MAX_OP_RETURN_PAYLOAD_BYTES: usize = 80;

/// CANDIDATE (QK-DEC-039): maximum inputs in one previous transaction
/// carried by a non_witness_utxo record. HOST-scaffold candidate; no
/// conformance claim; final registry value OPEN.
pub const MAX_PREVTX_INPUTS: usize = 8192;

/// CANDIDATE (QK-DEC-039): maximum outputs in one previous transaction
/// carried by a non_witness_utxo record. HOST-scaffold candidate; no
/// conformance claim; final registry value OPEN.
pub const MAX_PREVTX_OUTPUTS: usize = 8192;

/// CANDIDATE (QK-DEC-039): maximum bytes of any single scriptSig or
/// scriptPubKey inside a previous transaction. HOST-scaffold
/// candidate; no conformance claim; final registry value OPEN.
pub const MAX_PREVTX_SCRIPT_BYTES: usize = 10_000;

/// CANDIDATE (QK-DEC-039): maximum witness stack items per input of a
/// previous transaction. HOST-scaffold candidate; no conformance
/// claim; final registry value OPEN.
pub const MAX_PREVTX_WITNESS_ITEMS: usize = 1000;

/// CANDIDATE (QK-DEC-039): maximum bytes per witness stack item of a
/// previous transaction. HOST-scaffold candidate; no conformance
/// claim; final registry value OPEN.
pub const MAX_PREVTX_WITNESS_ITEM_BYTES: usize = 10_000;

/// CANDIDATE (QK-DEC-063, QK-LIM-PSBT-011): maximum descriptor child
/// index accepted by the HOST-only M12 ownership route. Candidate
/// only under QK-DEC-034; final registry value remains OPEN.
pub const MAX_CHILD_INDEX: u32 = 65_535;

/// CANDIDATE (QK-DEC-063, QK-LIM-PSBT-025): maximum inherited CKDpub
/// calls in one HOST-only M12 ownership analysis: 132 possible routes
/// times six calls. Candidate only under QK-DEC-034; final registry
/// value remains OPEN.
pub const MAX_CHILD_DERIVATIONS: usize = 792;

/// CANDIDATE (QK-DEC-072): exact maximum byte length of a D-09 v1
/// canonical review. This follows the successful M13 shape and makes no
/// target-RAM or conformance claim.
pub const MAX_CANONICAL_REVIEW_BYTES: usize = 19_272;

const _: [(); MAX_CANONICAL_REVIEW_BYTES] = [(); 124 + 5_535 + (100 * 107) + (185 + 31 * 88)];
const _: [(); 19_296] = [(); MAX_CANONICAL_REVIEW_BYTES + 23 + 1];

/// CANDIDATE (QK-DEC-110): exact maximum byte length of a D-09 v2
/// canonical review under QK-FEE-POLICY-V1. HOST candidate only; no
/// target-RAM or conformance claim.
pub const MAX_CANONICAL_REVIEW_V2_BYTES: usize = 18_934;

/// CANDIDATE (QK-DEC-110): maximum estimated fully signed virtual size
/// under the fixed v1 two-signature witness template. HOST candidate only.
pub const MAX_ESTIMATED_VSIZE: u32 = 11_886;

/// CANDIDATE (QK-DEC-110): exact maximum bytes hashed for one D-09 v2
/// review, including the 40-byte domain and one-byte separator.
pub const MAX_REVIEW_V2_HASH_TRANSCRIPT_BYTES: usize = 18_975;

const _: [(); MAX_CANONICAL_REVIEW_V2_BYTES] = [(); 162 + 5_535 + (100 * 102) + (185 + 31 * 92)];
const _: [(); MAX_REVIEW_V2_HASH_TRANSCRIPT_BYTES] = [(); MAX_CANONICAL_REVIEW_V2_BYTES + 40 + 1];
const _: [(); MAX_ESTIMATED_VSIZE as usize] = [(); 47_542_usize.div_ceil(4)];
