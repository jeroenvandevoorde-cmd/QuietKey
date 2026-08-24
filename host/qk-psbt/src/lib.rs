//! Bounded PSBT v0 structural parser, canonical structural serializer,
//! and bounded HOST-only semantic-subset analyzer.
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
//! later work. The M6 analyzer ([`analyze_semantic_subset`]) extracts
//! a bounded structural-candidate view of an already-parsed PSBT —
//! prevtx txid agreement, selected prevouts, MoneyRange totals and
//! fee, sighash and strict-DER/low-S signature syntax, and canonical
//! m-of-n witnessScript form — as deferred structural claims only: it
//! performs no cryptographic verification and never decides validity,
//! signability, completeness, or exportability, and it changes no
//! parsing, rejection, or serialization behavior. The separate M8
//! read-only entrypoint ([`analyze_and_verify_signatures`]) upgrades
//! those structural signature candidates to cryptographically
//! verified facts for native P2WSH canonical-multisig inputs: it
//! computes each input's BIP143 SIGHASH_ALL digest with the
//! [`bip143`] engine and verifies every existing partial signature
//! through the internal qk-secp verification boundary, returning
//! per-input verified counts and statuses plus one aggregate
//! disposition (including VERIFY_AND_EXPORT_ONLY as a returned fact
//! only). It verifies existing signatures only: no signing, no
//! signature insertion, no finalization, no export, and no
//! authorization of any later policy gate. The explicit global version field
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
//! This crate contains no secret bytes, wallet data, signing
//! capability, file or device access, clocks, randomness, logging,
//! network, environment access, threads, processes, FFI, persistence,
//! or hardware code, and has no external dependencies; its only
//! dependency is the internal verification-only `qk-secp` path crate
//! (M8), whose audited FFI boundary lives entirely in that crate. The
//! [`bip143`] module computes BIP143 SIGHASH_ALL digests only
//! (QK-DEC-044): it computes hashes, never signatures, and authorizes
//! nothing.

#![forbid(unsafe_code)]
#![deny(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects
)]

pub mod bip143;
pub mod error;
pub mod limits;
mod parse;
mod raw;
mod semantic;
mod serialize;
mod sha256;

pub use error::{ParseError, RejectCategory};
pub use parse::{parse, InputSource, PsbtView, UnsignedTxSummary};
pub use raw::{Record, Records, Span};
pub use semantic::{
    analyze_and_verify_signatures, analyze_semantic_subset, InputSemanticFacts,
    InputSignatureStatus, MalformedPush, MultisigForm, OutputSemanticFacts, ScriptToken,
    ScriptTokens, SemanticCandidate, SemanticCategory, SemanticError, VerifiedAggregateStatus,
    VerifiedInputFacts, VerifiedInputStatus, VerifiedSemanticCandidate,
};
pub use serialize::{canonical_serialize, SerializeError};
