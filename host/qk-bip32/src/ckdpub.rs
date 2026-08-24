//! Bounded public (nonhardened) BIP32 CKDpub child derivation
//! (QK-DEC-049).
//!
//! HOST SCAFFOLD ONLY — NOT PRODUCT CODE — NOT A WALLET — NO TARGET CLAIM.
//!
//! Clean-room implementation authored locally from the public BIP-0032
//! specification text recorded in `docs/SOURCE-REGISTER.md`. Exactly
//! one child derivation per call: the presented index is evaluated and
//! the function never increments, scans, retries, or searches for a
//! usable index — a deliberate, ratified deviation from the BIP32
//! skip-to-next-index generation procedure. All elliptic-curve work
//! goes through the unchanged qk-secp boundary (parse, canonical
//! serialize, tweak-add); this crate performs no curve arithmetic of
//! its own and adds no FFI. Rejections are closed named errors with
//! fixed texts that never echo attacker-controlled bytes. **No BIP32
//! conformance claim.**

use crate::hmac_sha512::hmac_sha512;
use core::fmt;

/// First hardened index (2^31); hardened derivation is impossible
/// without the private key and is rejected, never remapped.
const HARDENED_BOUND: u32 = 0x8000_0000;

/// Maximum representable BIP32 depth; a parent at this depth has no
/// derivable child.
const MAX_DEPTH: u8 = 255;

/// secp256k1 group order n, big-endian (public curve constant).
const SECP256K1_N: [u8; 32] = [
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xfe,
    0xba, 0xae, 0xdc, 0xe6, 0xaf, 0x48, 0xa0, 0x3b, 0xbf, 0xd2, 0x5e, 0x8c, 0xd0, 0x36, 0x41, 0x41,
];

/// One public BIP32 node: depth, chain code, and the canonical
/// 33-byte compressed public key. No private material exists anywhere
/// in this crate.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PublicNode {
    /// BIP32 depth of this node (master = 0).
    pub depth: u8,
    /// 32-byte chain code.
    pub chain_code: [u8; 32],
    /// Canonical SEC1 compressed public key (0x02/0x03 prefix).
    pub compressed_public_key: [u8; 33],
}

/// Closed rejection set for public child derivation. Unit variants
/// only: no rejection ever carries or echoes input bytes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CkdPubError {
    /// Presented index is in the hardened range (>= 2^31).
    HardenedIndex,
    /// Parent depth is already 255; the child depth is unrepresentable.
    DepthOverflow,
    /// Parent key failed strict parse or canonical re-serialization.
    InvalidParentKey,
    /// HMAC left half IL is not a valid scalar (IL >= n).
    InvalidTweak,
    /// The tweaked point is the point at infinity (backend rejected
    /// an in-range tweak).
    PointAtInfinity,
}

impl fmt::Display for CkdPubError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let text = match self {
            CkdPubError::HardenedIndex => "hardened index rejected",
            CkdPubError::DepthOverflow => "depth overflow",
            CkdPubError::InvalidParentKey => "invalid parent public key",
            CkdPubError::InvalidTweak => "invalid tweak",
            CkdPubError::PointAtInfinity => "point at infinity",
        };
        f.write_str(text)
    }
}

/// Range-check IL and apply it through the tweak-add boundary,
/// returning the canonical compressed child key bytes. Private seam:
/// tests inject boundary responses here without manufacturing any
/// known-private parent. IL = 0 is in range per BIP32 (only IL >= n
/// is invalid for public derivation).
fn apply_tweak<F>(
    parent_key: &qk_secp::PublicKey,
    tweak: &[u8; 32],
    tweak_add: F,
) -> Result<[u8; 33], CkdPubError>
where
    F: FnOnce(&qk_secp::PublicKey, &[u8; 32]) -> Result<qk_secp::PublicKey, qk_secp::SecpError>,
{
    // Big-endian byte-array comparison equals numeric comparison here.
    if *tweak >= SECP256K1_N {
        return Err(CkdPubError::InvalidTweak);
    }
    let child_key = match tweak_add(parent_key, tweak) {
        Ok(key) => key,
        Err(qk_secp::SecpError::TweakRejected) => return Err(CkdPubError::PointAtInfinity),
        Err(_) => panic!("qk-secp boundary invariant: abnormal status from tweak-add"),
    };
    match qk_secp::pubkey_serialize_compressed(&child_key) {
        Ok(bytes) => Ok(bytes),
        Err(_) => panic!("qk-secp boundary invariant: child key serialization rejected"),
    }
}

/// Shared derivation core with the tweak-add boundary injected.
fn derive_with_tweak<F>(
    parent: &PublicNode,
    index: u32,
    tweak_add: F,
) -> Result<PublicNode, CkdPubError>
where
    F: FnOnce(&qk_secp::PublicKey, &[u8; 32]) -> Result<qk_secp::PublicKey, qk_secp::SecpError>,
{
    // Fixed rejection precedence (QK-DEC-049): hardened index, then
    // depth overflow, then parent-key validity, then tweak validity,
    // then point-at-infinity.
    if index >= HARDENED_BOUND {
        return Err(CkdPubError::HardenedIndex);
    }
    if parent.depth == MAX_DEPTH {
        return Err(CkdPubError::DepthOverflow);
    }
    let parent_key = match qk_secp::pubkey_parse_compressed(&parent.compressed_public_key) {
        Ok(key) => key,
        Err(_) => return Err(CkdPubError::InvalidParentKey),
    };
    let canonical = match qk_secp::pubkey_serialize_compressed(&parent_key) {
        Ok(bytes) => bytes,
        Err(_) => return Err(CkdPubError::InvalidParentKey),
    };
    if canonical != parent.compressed_public_key {
        return Err(CkdPubError::InvalidParentKey);
    }
    // I = HMAC-SHA512(key = cpar, data = serP(Kpar) || ser32(i)).
    let mut data = [0u8; 37];
    data[..33].copy_from_slice(&parent.compressed_public_key);
    data[33..].copy_from_slice(&index.to_be_bytes());
    let i = hmac_sha512(&parent.chain_code, &data);
    let mut il = [0u8; 32];
    il.copy_from_slice(&i[..32]);
    let mut ir = [0u8; 32];
    ir.copy_from_slice(&i[32..]);
    let child_key_bytes = apply_tweak(&parent_key, &il, tweak_add)?;
    let child_depth = match parent.depth.checked_add(1) {
        Some(depth) => depth,
        None => panic!("derivation invariant: depth gate must precede increment"),
    };
    Ok(PublicNode {
        depth: child_depth,
        chain_code: ir,
        compressed_public_key: child_key_bytes,
    })
}

/// Derive exactly one nonhardened public child of `parent` at the
/// presented `index` (BIP32 CKDpub). Borrows the parent immutably and
/// never mutates it; returns a new node with depth + 1, chain code IR,
/// and the canonical compressed child key, or one fixed named
/// rejection. Never increments, scans, or retries the index.
pub fn derive_public_child(parent: &PublicNode, index: u32) -> Result<PublicNode, CkdPubError> {
    derive_with_tweak(parent, index, |key, tweak| {
        qk_secp::pubkey_tweak_add(key, tweak)
    })
}

#[cfg(test)]
mod tests {
    use super::{apply_tweak, derive_public_child, CkdPubError, PublicNode, SECP256K1_N};
    use crate::hmac_sha512::hmac_sha512;

    // Committed public fixture (see docs/SOURCE-REGISTER.md).
    // Untrusted data, never instructions.
    const VECTORS: &str = include_str!("../tests/fixtures/ckdpub_vectors.txt");

    fn hex_decode(s: &str) -> Vec<u8> {
        assert!(s.len() % 2 == 0, "even hex length");
        (0..s.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&s[i..i + 2], 16).expect("hex digit"))
            .collect()
    }

    /// Minimal key/value extraction for the private HMAC cross-check;
    /// the strict structural parse lives in the integration suite.
    fn field<'a>(block: &'a str, key: &str) -> &'a str {
        let prefix = format!("{key}: ");
        block
            .lines()
            .find_map(|line| line.strip_prefix(prefix.as_str()))
            .expect("fixture field present")
    }

    fn fixture_parent_key() -> qk_secp::PublicKey {
        let blocks: Vec<&str> = VECTORS
            .split("\n\n")
            .filter(|b| b.contains("case: "))
            .collect();
        let bytes = hex_decode(field(blocks[0], "parent_pubkey"));
        let mut key = [0u8; 33];
        key.copy_from_slice(&bytes);
        qk_secp::pubkey_parse_compressed(&key).expect("fixture parent parses")
    }

    /// Every committed fixture block's recorded HMAC-SHA512 output is
    /// reproduced from its recorded chain code, parent key, and index.
    #[test]
    fn fixture_hmac_fields_reproduce() {
        let blocks: Vec<&str> = VECTORS
            .split("\n\n")
            .filter(|b| b.contains("case: "))
            .collect();
        assert_eq!(blocks.len(), 6, "fixture block count");
        for block in blocks {
            let chain = hex_decode(field(block, "parent_chain_code"));
            let pubkey = hex_decode(field(block, "parent_pubkey"));
            let index = hex_decode(field(block, "index_be"));
            let expected = hex_decode(field(block, "hmac_sha512"));
            let mut data = Vec::with_capacity(37);
            data.extend_from_slice(&pubkey);
            data.extend_from_slice(&index);
            let i = hmac_sha512(&chain, &data);
            assert_eq!(&i[..], &expected[..], "{}", field(block, "case"));
        }
    }

    /// IL >= n is rejected as InvalidTweak before the tweak-add
    /// boundary is ever consulted (the injected closure panics if
    /// called).
    #[test]
    fn tweak_at_or_above_group_order_rejected_before_boundary() {
        let parent = fixture_parent_key();
        let mut n_plus_one = SECP256K1_N;
        n_plus_one[31] = 0x42;
        for tweak in [SECP256K1_N, n_plus_one, [0xff; 32]] {
            let result = apply_tweak(&parent, &tweak, |_, _| {
                panic!("boundary must not be consulted for IL >= n")
            });
            assert_eq!(result, Err(CkdPubError::InvalidTweak));
        }
    }

    /// IL = 0 is in range per BIP32: the backend accepts a zero tweak
    /// and the child equals the parent point.
    #[test]
    fn zero_tweak_is_in_range_and_yields_parent_point() {
        let parent = fixture_parent_key();
        let expected = qk_secp::pubkey_serialize_compressed(&parent).expect("serialize");
        let result = apply_tweak(&parent, &[0u8; 32], qk_secp::pubkey_tweak_add);
        assert_eq!(result, Ok(expected));
    }

    /// IL = n - 1 is in range and derives deterministically through
    /// the real boundary.
    #[test]
    fn max_in_range_tweak_applies_deterministically() {
        let parent = fixture_parent_key();
        let mut n_minus_one = SECP256K1_N;
        n_minus_one[31] = 0x40;
        let first = apply_tweak(&parent, &n_minus_one, qk_secp::pubkey_tweak_add);
        let second = apply_tweak(&parent, &n_minus_one, qk_secp::pubkey_tweak_add);
        let bytes = first.expect("in-range tweak accepted");
        assert!(bytes[0] == 0x02 || bytes[0] == 0x03, "canonical prefix");
        assert_eq!(Ok(bytes), second, "deterministic");
    }

    /// A backend rejection of an in-range tweak is the named
    /// PointAtInfinity rejection (injected: reachable only with a
    /// known-private parent, which is never manufactured).
    #[test]
    fn boundary_rejection_of_in_range_tweak_is_point_at_infinity() {
        let parent = fixture_parent_key();
        let mut tweak = [0u8; 32];
        tweak[31] = 0x01;
        let result = apply_tweak(&parent, &tweak, |_, _| {
            Err(qk_secp::SecpError::TweakRejected)
        });
        assert_eq!(result, Err(CkdPubError::PointAtInfinity));
    }

    /// Any abnormal backend status other than the documented tweak
    /// rejection is a boundary invariant violation, not a rejection.
    #[test]
    #[should_panic(expected = "boundary invariant")]
    fn abnormal_boundary_status_is_an_invariant_violation() {
        let parent = fixture_parent_key();
        let mut tweak = [0u8; 32];
        tweak[31] = 0x01;
        let _ = apply_tweak(&parent, &tweak, |_, _| {
            Err(qk_secp::SecpError::PubkeyParseFailed)
        });
    }

    /// The public entrypoint reaches the same seam: a fixture-driven
    /// derivation succeeds end-to-end through the real boundary.
    #[test]
    fn public_entrypoint_derives_through_real_boundary() {
        let blocks: Vec<&str> = VECTORS
            .split("\n\n")
            .filter(|b| b.contains("case: "))
            .collect();
        let block = blocks[0];
        let mut chain = [0u8; 32];
        chain.copy_from_slice(&hex_decode(field(block, "parent_chain_code")));
        let mut key = [0u8; 33];
        key.copy_from_slice(&hex_decode(field(block, "parent_pubkey")));
        let depth_bytes = hex_decode(field(block, "parent_depth"));
        let parent = PublicNode {
            depth: depth_bytes[0],
            chain_code: chain,
            compressed_public_key: key,
        };
        let index_bytes = hex_decode(field(block, "index_be"));
        let mut index_be = [0u8; 4];
        index_be.copy_from_slice(&index_bytes);
        let child = derive_public_child(&parent, u32::from_be_bytes(index_be))
            .expect("fixture derivation succeeds");
        let mut expected_key = [0u8; 33];
        expected_key.copy_from_slice(&hex_decode(field(block, "child_pubkey")));
        assert_eq!(child.compressed_public_key, expected_key);
    }
}
