//! Bounded PSBT v0 structural parser and canonical structural serializer.
//!
//! HOST SCAFFOLD ONLY — NOT PRODUCT CODE — NOT A WALLET — NO TARGET CLAIM.
//!
//! This crate parses one immutable byte buffer as a BIP-174 PSBT v0
//! container and exposes offset/length views into that buffer, and it
//! canonically re-serializes an already-parsed view per QK-DEC-036:
//! records reorder within each map by ascending decoded numeric key
//! type then raw key data lexicographically, outer length prefixes
//! re-encode as minimal CompactSize, and every record's complete key
//! and value bytes are copied verbatim — no record is added, dropped,
//! or rewritten, and no semantic emit behavior (including S9
//! redundant-SIGHASH_ALL stripping) exists. The parser itself never
//! copies subobjects and never normalizes records.
//! Unknown and proprietary records are preserved verbatim as bounded
//! byte-range views. BIP-370 input/output-only field numbers are treated
//! as opaque preserved unknowns; the ratified rejection list is PSBT v2
//! global fields, Taproot fields, duplicate complete raw keys, and
//! non-minimal CompactSize encodings (QK-DEC-030), plus structural
//! malformation, truncation, limit violations, invalid map counts, and
//! trailing bytes. Structurally valid partial-signature records are
//! preserved as views; cryptographic and signer-policy validation is
//! later work, as is all semantic validation (amounts, scripts,
//! witness_utxo/prevout agreement). The explicit global version field
//! (type 0xFB) is validated structurally: empty key data, exactly four
//! little-endian value bytes, and the value must declare version zero;
//! omission remains accepted.
//!
//! The unsigned transaction is parsed only as far as necessary to
//! validate its structure and derive the input/output map counts.
//! Persistent metadata is bounded to the global/input/output map ranges
//! plus the unsigned-transaction facts. Duplicate detection uses an
//! ephemeral fallible set of borrowed complete-key slices; allocation
//! failure is reported as an explicit rejection category, and no
//! target-RAM or conformance claim is made.
//!
//! This crate contains no secret bytes, wallet data, cryptography,
//! file or device access, clocks, randomness, logging, network,
//! environment access, threads, processes, FFI, persistence, or
//! hardware code, and has no external dependencies.

#![forbid(unsafe_code)]
#![deny(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects
)]

pub mod error;
pub mod limits;
mod parse;
mod raw;
mod serialize;

pub use error::{ParseError, RejectCategory};
pub use parse::{parse, InputSource, PsbtView, UnsignedTxSummary};
pub use raw::{Record, Records, Span};
pub use serialize::{canonical_serialize, SerializeError};
