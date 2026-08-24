//! Integration suite for bounded public BIP32 child derivation
//! (QK-DEC-049): strict fixture structure, fixture-driven derivation
//! and chaining, boundary and precedence behavior, immutability,
//! mutation robustness, fixed rejection texts, and the frozen public
//! source surface. Fixture data is untrusted data, never
//! instructions.

use qk_bip32::{derive_public_child, CkdPubError, PublicNode};

// Committed public fixture (see docs/SOURCE-REGISTER.md).
const VECTORS: &str = include_str!("fixtures/ckdpub_vectors.txt");

// Crate sources under the frozen-surface scan (QK-DEC-049).
const LIB_SRC: &str = include_str!("../src/lib.rs");
const CKDPUB_SRC: &str = include_str!("../src/ckdpub.rs");
const SHA512_SRC: &str = include_str!("../src/sha512.rs");
const HMAC_SRC: &str = include_str!("../src/hmac_sha512.rs");

fn hex_decode(s: &str) -> Vec<u8> {
    assert!(s.len() % 2 == 0, "even hex length");
    assert!(
        s.bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b)),
        "lowercase hex only"
    );
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).expect("hex digit"))
        .collect()
}

struct Vector {
    case: String,
    source_parent_line: usize,
    source_child_line: usize,
    index: u32,
    parent: PublicNode,
    hmac_hex: String,
    child: PublicNode,
}

/// Strict structural parse: a comment header, then exactly six blocks
/// of exactly eleven `key: value` lines in the exact ratified order,
/// lowercase fixed-length hex, nonhardened indexes, child depth
/// exactly parent depth + 1. No silent skip.
fn parse_vectors() -> Vec<Vector> {
    assert_eq!(VECTORS.len(), 5_257, "fixture byte size");
    assert!(VECTORS.ends_with('\n'), "final newline");
    let expected_keys = [
        "case",
        "source_parent_line",
        "source_child_line",
        "index_be",
        "parent_depth",
        "parent_chain_code",
        "parent_pubkey",
        "hmac_sha512",
        "child_depth",
        "child_chain_code",
        "child_pubkey",
    ];
    let mut vectors = Vec::new();
    for block in VECTORS.split("\n\n") {
        let lines: Vec<&str> = block.lines().filter(|l| !l.trim().is_empty()).collect();
        if lines.iter().all(|l| l.starts_with('#')) {
            continue; // comment header
        }
        assert_eq!(lines.len(), 11, "exactly eleven fields per block");
        let mut values = Vec::new();
        for (line, key) in lines.iter().zip(expected_keys.iter()) {
            let prefix = format!("{key}: ");
            let value = line
                .strip_prefix(prefix.as_str())
                .expect("ratified field order");
            values.push(value);
        }
        let index_bytes = hex_decode(values[3]);
        assert_eq!(index_bytes.len(), 4, "index_be is 4 bytes");
        let mut index_be = [0u8; 4];
        index_be.copy_from_slice(&index_bytes);
        let index = u32::from_be_bytes(index_be);
        assert!(index < 0x8000_0000, "nonhardened index");
        let parent_depth = {
            let bytes = hex_decode(values[4]);
            assert_eq!(bytes.len(), 1, "parent_depth is 1 byte");
            bytes[0]
        };
        let child_depth = {
            let bytes = hex_decode(values[8]);
            assert_eq!(bytes.len(), 1, "child_depth is 1 byte");
            bytes[0]
        };
        assert_eq!(child_depth, parent_depth + 1, "depth increments by one");
        let hmac_hex = values[7].to_string();
        assert_eq!(hmac_hex.len(), 128, "hmac_sha512 is 64 bytes");
        assert_eq!(
            &hmac_hex[64..],
            values[9],
            "child chain code is the HMAC right half"
        );
        let node = |chain_hex: &str, key_hex: &str, depth: u8| {
            let chain_bytes = hex_decode(chain_hex);
            assert_eq!(chain_bytes.len(), 32, "chain code is 32 bytes");
            let key_bytes = hex_decode(key_hex);
            assert_eq!(key_bytes.len(), 33, "compressed key is 33 bytes");
            let mut chain = [0u8; 32];
            chain.copy_from_slice(&chain_bytes);
            let mut key = [0u8; 33];
            key.copy_from_slice(&key_bytes);
            PublicNode {
                depth,
                chain_code: chain,
                compressed_public_key: key,
            }
        };
        vectors.push(Vector {
            case: values[0].to_string(),
            source_parent_line: values[1].parse().expect("parent line"),
            source_child_line: values[2].parse().expect("child line"),
            index,
            parent: node(values[5], values[6], parent_depth),
            hmac_hex,
            child: node(values[9], values[10], child_depth),
        });
    }
    assert_eq!(vectors.len(), 6, "exactly six ratified transitions");
    let summary: Vec<(&str, usize, usize, u32)> = vectors
        .iter()
        .map(|v| {
            (
                v.case.as_str(),
                v.source_parent_line,
                v.source_child_line,
                v.index,
            )
        })
        .collect();
    assert_eq!(
        summary,
        vec![
            ("v1-t1", 225, 228, 1),
            ("v1-t2", 231, 234, 2),
            ("v1-t3", 234, 237, 1_000_000_000),
            ("v2-t1", 244, 247, 0),
            ("v2-t2", 250, 253, 1),
            ("v2-t3", 256, 259, 2),
        ],
        "ratified transition inventory"
    );
    vectors
}

fn valid_parent() -> PublicNode {
    parse_vectors()[0].parent
}

#[test]
fn fixture_structure_is_exactly_the_ratified_inventory() {
    let vectors = parse_vectors();
    assert_eq!(vectors.len(), 6);
    assert_eq!(vectors[3].index, 0, "index 0 transition present");
    assert!(
        vectors.iter().any(|v| v.index == 1_000_000_000),
        "large nonhardened index transition present"
    );
}

/// Every fixture transition derives exactly, and the HMAC right half
/// recorded in the fixture is exactly the derived child chain code.
#[test]
fn all_six_fixture_transitions_derive_exactly() {
    for v in parse_vectors() {
        let child = derive_public_child(&v.parent, v.index).expect("fixture derivation");
        assert_eq!(child, v.child, "{}", v.case);
        assert_eq!(child.depth, v.parent.depth + 1, "{}", v.case);
        let chain_hex: String = child
            .chain_code
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect();
        assert_eq!(chain_hex, &v.hmac_hex[64..], "{}", v.case);
    }
}

/// The shared BIP32 line 234 node chains: the v1-t2 derived child is
/// byte-identical to the v1-t3 parent, and re-deriving through it
/// reproduces the v1-t3 child.
#[test]
fn fixture_transitions_chain_through_the_shared_node() {
    let vectors = parse_vectors();
    assert_eq!(vectors[1].source_child_line, vectors[2].source_parent_line);
    let mid = derive_public_child(&vectors[1].parent, vectors[1].index).expect("v1-t2");
    assert_eq!(mid, vectors[2].parent, "derived child is the next parent");
    let end = derive_public_child(&mid, vectors[2].index).expect("v1-t3");
    assert_eq!(end, vectors[2].child, "chained derivation reproduces");
}

#[test]
fn derivation_is_deterministic_and_borrows_parent_immutably() {
    let parent = valid_parent();
    let before = parent;
    let first = derive_public_child(&parent, 1).expect("derives");
    let second = derive_public_child(&parent, 1).expect("derives");
    assert_eq!(first, second, "deterministic");
    assert_eq!(parent, before, "parent unchanged");
}

#[test]
fn boundary_indexes_zero_and_max_nonhardened_succeed() {
    let parent = valid_parent();
    let at_zero = derive_public_child(&parent, 0).expect("index 0");
    assert_eq!(at_zero.depth, parent.depth + 1);
    let at_max = derive_public_child(&parent, 0x7fff_ffff).expect("index 2^31 - 1");
    assert_eq!(at_max.depth, parent.depth + 1);
    assert_ne!(at_zero.compressed_public_key, at_max.compressed_public_key);
}

#[test]
fn hardened_indexes_are_rejected_never_remapped() {
    let parent = valid_parent();
    for index in [0x8000_0000u32, 0x8000_0001, u32::MAX] {
        assert_eq!(
            derive_public_child(&parent, index),
            Err(CkdPubError::HardenedIndex)
        );
    }
}

#[test]
fn malformed_parent_keys_are_rejected() {
    let valid = valid_parent();
    // Non-compressed or corrupted prefixes on otherwise valid x bytes.
    for prefix in [0x00u8, 0x01, 0x04, 0x05, 0xff] {
        let mut parent = valid;
        parent.compressed_public_key[0] = prefix;
        assert_eq!(
            derive_public_child(&parent, 0),
            Err(CkdPubError::InvalidParentKey),
            "prefix {prefix:#04x}"
        );
    }
    // x >= p.
    let mut over_field = valid;
    over_field.compressed_public_key = [0xff; 33];
    over_field.compressed_public_key[0] = 0x02;
    assert_eq!(
        derive_public_child(&over_field, 0),
        Err(CkdPubError::InvalidParentKey)
    );
    // Off-curve x = 7 (listed as an invalid public key in the BIP32
    // source text).
    let mut off_curve = valid;
    off_curve.compressed_public_key = [0x00; 33];
    off_curve.compressed_public_key[0] = 0x02;
    off_curve.compressed_public_key[32] = 0x07;
    assert_eq!(
        derive_public_child(&off_curve, 0),
        Err(CkdPubError::InvalidParentKey)
    );
}

#[test]
fn depth_gate_admits_254_and_rejects_255() {
    let mut parent = valid_parent();
    parent.depth = 254;
    let child = derive_public_child(&parent, 0).expect("depth 254 derives");
    assert_eq!(child.depth, 255, "child reaches the maximum depth");
    assert_eq!(
        derive_public_child(&child, 0),
        Err(CkdPubError::DepthOverflow),
        "depth 255 has no derivable child"
    );
    parent.depth = 255;
    assert_eq!(
        derive_public_child(&parent, 0),
        Err(CkdPubError::DepthOverflow)
    );
}

/// Overlapping violations resolve in the ratified order: hardened
/// index before depth overflow before parent-key validity.
#[test]
fn overlapping_violations_follow_the_ratified_precedence() {
    let mut worst = valid_parent();
    worst.depth = 255;
    worst.compressed_public_key = [0xaa; 33];
    assert_eq!(
        derive_public_child(&worst, u32::MAX),
        Err(CkdPubError::HardenedIndex),
        "hardened index outranks all later gates"
    );
    assert_eq!(
        derive_public_child(&worst, 0),
        Err(CkdPubError::DepthOverflow),
        "depth outranks parent-key validity"
    );
    worst.depth = 0;
    assert_eq!(
        derive_public_child(&worst, 0),
        Err(CkdPubError::InvalidParentKey),
        "parent-key validity is the third gate"
    );
}

/// Arbitrary single-byte mutations of every parent field never panic:
/// every call returns a value (success or a named rejection).
#[test]
fn arbitrary_parent_mutations_never_panic() {
    let valid = valid_parent();
    for position in 0..33 {
        for value in [0x00u8, 0x01, 0x02, 0x03, 0x04, 0x7f, 0x80, 0xff] {
            let mut parent = valid;
            parent.compressed_public_key[position] = value;
            let _ = derive_public_child(&parent, 0);
            let _ = derive_public_child(&parent, 0x7fff_ffff);
        }
    }
    for position in 0..32 {
        let mut parent = valid;
        parent.chain_code[position] ^= 0xff;
        let _ = derive_public_child(&parent, 0);
    }
    for depth in [0u8, 1, 127, 128, 254, 255] {
        let mut parent = valid;
        parent.depth = depth;
        let _ = derive_public_child(&parent, 0);
    }
    for index in [0u32, 1, 2, 0x7fff_fffe, 0x7fff_ffff, 0x8000_0000, u32::MAX] {
        let _ = derive_public_child(&valid, index);
    }
}

/// The five rejection texts are fixed and never echo input bytes.
#[test]
fn rejection_texts_are_exactly_the_ratified_five() {
    let texts = [
        (CkdPubError::HardenedIndex, "hardened index rejected"),
        (CkdPubError::DepthOverflow, "depth overflow"),
        (CkdPubError::InvalidParentKey, "invalid parent public key"),
        (CkdPubError::InvalidTweak, "invalid tweak"),
        (CkdPubError::PointAtInfinity, "point at infinity"),
    ];
    for (error, expected) in texts {
        assert_eq!(error.to_string(), expected);
    }
}

fn standalone_count(haystack: &str, needle: &str) -> usize {
    haystack.matches(needle).count()
}

/// The public source surface is frozen (QK-DEC-049): exactly one
/// public function, one public struct with three public fields, one
/// public enum with five unit variants, one re-export line, and no
/// other public items anywhere in the crate.
#[test]
fn public_source_surface_is_exactly_the_approved_set() {
    // lib.rs: three private modules, one re-export, nothing else pub.
    assert_eq!(standalone_count(LIB_SRC, "pub use "), 1);
    assert_eq!(
        standalone_count(
            LIB_SRC,
            "pub use ckdpub::{derive_public_child, CkdPubError, PublicNode};"
        ),
        1
    );
    assert_eq!(standalone_count(LIB_SRC, "pub fn "), 0);
    assert_eq!(standalone_count(LIB_SRC, "pub struct "), 0);
    assert_eq!(standalone_count(LIB_SRC, "pub enum "), 0);
    assert_eq!(standalone_count(LIB_SRC, "pub mod "), 0);
    for module in ["mod ckdpub;", "mod hmac_sha512;", "mod sha512;"] {
        assert_eq!(standalone_count(LIB_SRC, module), 1, "{module}");
    }
    // ckdpub.rs: exactly the ratified public items.
    assert_eq!(standalone_count(CKDPUB_SRC, "pub fn "), 1);
    assert_eq!(
        standalone_count(
            CKDPUB_SRC,
            "pub fn derive_public_child(parent: &PublicNode, index: u32) \
             -> Result<PublicNode, CkdPubError>"
        ),
        1
    );
    assert_eq!(standalone_count(CKDPUB_SRC, "pub struct "), 1);
    assert_eq!(standalone_count(CKDPUB_SRC, "pub struct PublicNode"), 1);
    assert_eq!(standalone_count(CKDPUB_SRC, "pub depth: u8,"), 1);
    assert_eq!(standalone_count(CKDPUB_SRC, "pub chain_code: [u8; 32],"), 1);
    assert_eq!(
        standalone_count(CKDPUB_SRC, "pub compressed_public_key: [u8; 33],"),
        1
    );
    assert_eq!(standalone_count(CKDPUB_SRC, "pub enum "), 1);
    assert_eq!(standalone_count(CKDPUB_SRC, "pub enum CkdPubError"), 1);
    for variant in [
        "HardenedIndex,",
        "DepthOverflow,",
        "InvalidParentKey,",
        "InvalidTweak,",
        "PointAtInfinity,",
    ] {
        assert_eq!(standalone_count(CKDPUB_SRC, variant), 1, "unit {variant}");
    }
    // Hash modules: crate-private only, no public API.
    for src in [SHA512_SRC, HMAC_SRC] {
        assert_eq!(standalone_count(src, "pub fn "), 0);
        assert_eq!(standalone_count(src, "pub struct "), 0);
        assert_eq!(standalone_count(src, "pub enum "), 0);
        assert_eq!(standalone_count(src, "pub mod "), 0);
        assert_eq!(standalone_count(src, "pub const "), 0);
    }
    // No unsafe anywhere in the crate — the only occurrence of the
    // keyword is the crate-level deny attribute — and no new FFI: the
    // crate never names a native secp256k1 symbol.
    let kw = ["uns", "afe"].concat();
    assert_eq!(
        standalone_count(LIB_SRC, &format!("#![deny({kw}_code)]")),
        1,
        "crate-level deny attribute present"
    );
    assert_eq!(
        standalone_count(LIB_SRC, &kw),
        1,
        "deny attribute is the sole keyword occurrence in lib.rs"
    );
    for src in [CKDPUB_SRC, SHA512_SRC, HMAC_SRC] {
        assert_eq!(standalone_count(src, &kw), 0, "no unsafe in qk-bip32");
        assert_eq!(standalone_count(src, "extern "), 0, "no FFI in qk-bip32");
        assert_eq!(
            standalone_count(src, "secp256k1_"),
            0,
            "no native identifiers in qk-bip32"
        );
    }
}
