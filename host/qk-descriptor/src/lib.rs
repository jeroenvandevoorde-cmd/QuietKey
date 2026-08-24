//! Strict paired-descriptor foundation (QK-DEC-054..056).
//!
//! HOST SCAFFOLD ONLY — NOT PRODUCT CODE — NOT A WALLET — NO TARGET CLAIM.
//!
//! This crate accepts only one fixed pair of checksummed mainnet
//! `wsh(sortedmulti(2,...))` descriptor byte forms. It exposes the
//! pair's fixed wallet-id hash and bounded public receive/change script
//! facts plus M12 role-preserving claim matching. It does not normalize
//! or serialize descriptors, prove
//! ownership or change, connect to PSBT handling, derive private
//! material, sign, finalize, export, or provide addresses.

#![deny(unsafe_code)]

mod checksum;
mod descriptor;
mod sha256;

pub use descriptor::{
    derive_change_script, derive_receive_script, match_change_derivation_claims,
    match_receive_derivation_claims, parse_descriptor_pair, DerivedScript, DescriptorDeriveError,
    DescriptorPair, DescriptorParseError,
};
