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
//! omission remains accepted. The separate M13 HOST-only entrypoint
//! ([`analyze_recipient_script_facts`]) first completes M12 ownership
//! and M8 verification, then returns bounded raw script facts for only
//! `NotProvenOwned` outputs across six exact destination templates.
//! It performs no address encoding, display, amount warning, approval,
//! signing, insertion, finalization, or export.
//! The M14 entrypoint ([`build_review`]) binds those authoritative facts,
//! exact unsigned-transaction bytes, exact S0 SHA-256, authenticated
//! descriptor identity, and parse-retained intake provenance into the
//! bounded D-09 v1 canonical representation. [`PsbtView::source`] is the
//! only accepted source provenance; a conflicting review context rejects
//! before analysis or review allocation. The review remains session-free,
//! and its domain-separated SHA-256 commitment is computed on request.
//! The separate M23 entrypoint ([`build_review_v2`]) deliberately does not
//! cryptographically promote existing partial signatures. It requires the
//! full descriptor ownership/change route, classifies every non-change
//! output, applies `QK-FEE-POLICY-V1`, and returns an owned, session-free
//! schema-v2 review whose exact immutable-S0 identity, transaction facts,
//! fee facts, ordered warnings, sequences, and derived RBF signals are bound
//! by the v2 domain-separated hash. It performs no signing, approval,
//! threshold-completeness decision, finalization, or export.
//! The parallel v2-wallet entrypoint ([`build_review_v3`]) accepts only an
//! authenticated two-role [`qk_descriptor::DescriptorPairV2`], proves the
//! corresponding 2-of-2 ownership and change facts, applies
//! `QK-FEE-POLICY-V2`, and binds those facts under the exact schema-v3 domain.
//! It translates no earlier review schema and carries no signature,
//! completeness, approval, session, finalization, or export state.
//!
//! The unsigned transaction is parsed only as far as necessary to
//! validate its structure and derive the input/output map counts.
//! Persistent metadata is bounded to intake provenance, the
//! global/input/output map ranges, and the unsigned-transaction facts.
//! Duplicate detection uses an
//! ephemeral fallible set of borrowed complete-key slices; allocation
//! failure is reported as an explicit rejection category, and no
//! target-RAM or conformance claim is made.
//!
//! This crate contains no secret bytes, wallet data, signing
//! capability, file or device access, clocks, randomness, logging,
//! network, environment access, threads, processes, FFI, persistence,
//! or hardware code, and has no external dependencies; its only
//! dependencies are the internal `qk-descriptor` public-derivation
//! path crate (M12) and verification-only `qk-secp` path crate (M8),
//! whose audited FFI boundary lives entirely in that crate. The
//! [`bip143`] module computes BIP143 SIGHASH_ALL digests only
//! (QK-DEC-044): it computes hashes, never signatures, and authorizes
//! nothing.

#![deny(unsafe_code)]
#![deny(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects
)]

pub mod bip143;
pub mod error;
mod intake;
mod kit_sweep_v3;
pub mod limits;
mod parse;
mod raw;
mod review;
mod review_v2;
mod review_v3;
mod semantic;
mod serialize;
mod sha256;
mod wipe;

pub use error::{ParseError, RejectCategory};
pub use intake::{IntakeError, OwnedS0};
pub use kit_sweep_v3::{
    build_validated_kit_sweep_v3, KitSweepInputSigningPlanV3, KitSweepReviewHashV3,
    KitSweepV3Error, ValidatedKitSweepV3, ValidatedKitSweepV3Parts,
};
pub use parse::{parse, InputSource, PsbtView, UnsignedTxSummary};
pub use raw::{Record, Records, Span};
pub use review::{
    build_review, Review, ReviewContext, ReviewError, ReviewHash, ReviewInput, ReviewNetwork,
    ReviewOutput, ReviewOutputOwnership, ReviewRecipient,
};
pub use review_v2::{
    build_review_v2, DirectRbf, FeePolicyFacts, FeeWarning, ReviewV2, ReviewV2Error, ReviewV2Hash,
    ReviewV2Input, ReviewV2Output, ReviewV2OutputOwnership, FEE_POLICY_IDENTIFIER,
    MAX_CANONICAL_REVIEW_V2_BYTES, MAX_ESTIMATED_VSIZE, MAX_FEE_WARNINGS,
    MAX_REVIEW_V2_HASH_TRANSCRIPT_BYTES, REVIEW_V2_HASH_DOMAIN, REVIEW_V2_SCHEMA_VERSION,
};
pub use review_v3::{
    build_review_v3, FeePolicyV2Facts, ReviewV3, ReviewV3Error, ReviewV3Hash, ReviewV3Input,
    ReviewV3Output, ReviewV3OutputOwnership, FEE_POLICY_V2_IDENTIFIER,
    MAX_CANONICAL_REVIEW_V3_BYTES, MAX_ESTIMATED_VSIZE_V2, MAX_FEE_WARNINGS_V2,
    MAX_REVIEW_V3_HASH_TRANSCRIPT_BYTES, REVIEW_V3_HASH_DOMAIN, REVIEW_V3_SCHEMA_VERSION,
};
pub use semantic::{
    analyze_and_verify_signatures, analyze_descriptor_ownership, analyze_descriptor_ownership_v2,
    analyze_recipient_script_facts, analyze_semantic_subset, DescriptorOwnershipAnalysis,
    DescriptorWalletFacts, InputSemanticFacts, InputSignatureStatus, MalformedPush, MultisigForm,
    OutputOwnership, OutputSemanticFacts, ProvenWalletInput, RecipientScriptAnalysis,
    RecipientScriptFacts, RecipientType, ScriptToken, ScriptTokens, SemanticCandidate,
    SemanticCategory, SemanticError, VerifiedAggregateStatus, VerifiedInputFacts,
    VerifiedInputStatus, VerifiedSemanticCandidate, MAX_DESCRIPTOR_V2_VERIFICATION_CALLS,
};
pub use serialize::{canonical_serialize, SerializeError};
