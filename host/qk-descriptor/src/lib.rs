//! Strict paired-descriptor foundation (QK-DEC-054..056, QK-DEC-121).
//!
//! HOST SCAFFOLD ONLY — NOT PRODUCT CODE — NOT A WALLET — NO TARGET CLAIM.
//!
//! The unsuffixed surface preserves the frozen v1 three-account profile.
//! The explicitly suffixed v2 surface accepts only the two-account
//! `wsh(sortedmulti(2,A,B))` profile. Both expose only a pair's fixed
//! wallet-id hash and bounded public receive/change script facts plus
//! role-preserving claim matching. This crate does not normalize or
//! serialize descriptors, prove
//! ownership or change, connect to PSBT handling, derive private
//! material, sign, finalize, export, or provide addresses.

#![deny(unsafe_code)]

mod checksum;
mod descriptor;
mod sha256;

pub use descriptor::{
    derive_change_script, derive_change_script_v2, derive_receive_script, derive_receive_script_v2,
    match_change_derivation_claims, match_change_derivation_claims_v2,
    match_receive_derivation_claims, match_receive_derivation_claims_v2, parse_descriptor_pair,
    parse_descriptor_pair_v2, DerivedScript, DerivedScriptV2, DescriptorDeriveError,
    DescriptorPair, DescriptorPairV2, DescriptorParseError,
};
