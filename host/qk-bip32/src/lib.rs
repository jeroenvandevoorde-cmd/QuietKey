//! Bounded HOST-only public (nonhardened) BIP32 child derivation
//! foundation (QK-DEC-048, QK-DEC-049, QK-DEC-050).
//!
//! HOST SCAFFOLD ONLY — NOT PRODUCT CODE — NOT A WALLET — NO TARGET CLAIM.
//!
//! The complete frozen public surface (QK-DEC-049) is [`PublicNode`],
//! [`CkdPubError`], and [`derive_public_child`]. Nothing else is
//! public: the FIPS 180-4 SHA-512 and FIPS 198-1 HMAC-SHA512
//! implementations are private modules with no general public hash or
//! HMAC API, and there are no public constants, modules, traits, or
//! private-derivation paths. This validator evaluates exactly the
//! presented index and never increments, scans, retries, or searches —
//! a deliberate, ratified deviation from the BIP32 skip-to-next-index
//! generation procedure. Child keys are computed only through the
//! unchanged qk-secp parse/serialize/tweak-add boundary; no sixth FFI
//! function exists. No private derivation, no xprv or seed handling,
//! no Base58 or xpub text API, no HASH160 or fingerprints, no path
//! policy, no PSBT integration. Correctness is exercised only against
//! the committed public fixtures recorded in
//! `docs/SOURCE-REGISTER.md`; **no FIPS, CAVP, or BIP32 conformance
//! claim.**

#![deny(unsafe_code)]

mod ckdpub;
mod hmac_sha512;
mod sha512;

pub use ckdpub::{derive_public_child, CkdPubError, PublicNode};
