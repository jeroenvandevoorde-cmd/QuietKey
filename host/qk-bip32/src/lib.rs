//! Bounded HOST-only public BIP32 foundation (QK-DEC-048..053):
//! nonhardened CKDpub plus strict mainnet xpub decoding.
//!
//! HOST SCAFFOLD ONLY — NOT PRODUCT CODE — NOT A WALLET — NO TARGET CLAIM.
//!
//! The complete frozen public surface is [`PublicNode`],
//! [`CkdPubError`], [`derive_public_child`], [`DecodedXpub`],
//! [`XpubDecodeError`], and [`decode_mainnet_xpub`]. Nothing else is
//! public. SHA-512, HMAC-SHA512, SHA-256, Base58 arithmetic, and
//! checksum handling remain private with no general cryptographic API.
//! CKDpub evaluates exactly the presented nonhardened index and never
//! increments, scans, retries, or searches. The strict decoder accepts
//! borrowed bytes only, permits exactly mainnet xpub version 0488b21e,
//! checks SHA256d before payload semantics, and exposes only decoded
//! public fields. Both paths use only the unchanged qk-secp
//! parse/serialize/tweak-add boundary; no sixth FFI function exists.
//! No private derivation, xprv or seed handling, Base58 encoder,
//! HASH160 calculation, path policy, descriptors, ownership/change,
//! or PSBT integration. Correctness is exercised only against the
//! committed public fixtures recorded in `docs/SOURCE-REGISTER.md`;
//! **no FIPS, CAVP, or BIP32 conformance claim.**

#![deny(unsafe_code)]

mod ckdpub;
mod hmac_sha512;
mod sha256;
mod sha512;
mod xpub;

pub use ckdpub::{derive_public_child, CkdPubError, PublicNode};
pub use xpub::{decode_mainnet_xpub, DecodedXpub, XpubDecodeError};
