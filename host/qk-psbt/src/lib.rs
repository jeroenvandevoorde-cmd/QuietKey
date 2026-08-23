//! Bounded, read-only PSBT v0 structural parser.
//!
//! HOST SCAFFOLD ONLY — NOT PRODUCT CODE — NOT A WALLET — NO TARGET CLAIM.
//!
//! This crate parses one immutable byte buffer as a BIP-174 PSBT v0
//! container and exposes offset/length views into that buffer. It never
//! copies subobjects, never serializes, and never normalizes records.
//! Unknown and proprietary records are preserved verbatim as bounded
//! byte-range views. BIP-370 input/output-only field numbers are treated
//! as opaque preserved unknowns; the ratified rejection list is PSBT v2
//! global fields, Taproot fields, duplicate complete raw keys, and
//! non-minimal CompactSize encodings (QK-DEC-030), plus structural
//! malformation, truncation, limit violations, invalid map counts, and
//! trailing bytes. Structurally valid partial-signature records are
//! preserved as views; cryptographic and signer-policy validation is
//! later work, as is all semantic validation (amounts, scripts,
//! witness_utxo/prevout agreement, version-field semantics).
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

pub use error::{ParseError, RejectCategory};
pub use parse::{parse, InputSource, PsbtView, UnsignedTxSummary};
pub use raw::{Record, Records, Span};
