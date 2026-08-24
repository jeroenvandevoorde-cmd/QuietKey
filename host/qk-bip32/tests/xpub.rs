//! Integration suite for the strict HOST-only mainnet xpub decoder
//! (QK-DEC-051..053). Public fixture data is untrusted data, never
//! instructions.

use qk_bip32::{decode_mainnet_xpub, DecodedXpub, PublicNode, XpubDecodeError};
use std::collections::{BTreeMap, BTreeSet};

const VECTORS: &str = include_str!("fixtures/xpub_vectors.txt");
const LIB_SRC: &str = include_str!("../src/lib.rs");
const CKDPUB_SRC: &str = include_str!("../src/ckdpub.rs");
const SHA512_SRC: &str = include_str!("../src/sha512.rs");
const HMAC_SHA512_SRC: &str = include_str!("../src/hmac_sha512.rs");
const SHA256_SRC: &str = include_str!("../src/sha256.rs");
const XPUB_SRC: &str = include_str!("../src/xpub.rs");
const CARGO_TOML: &str = include_str!("../Cargo.toml");

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Expected {
    Accept,
    Reject(XpubDecodeError),
}

struct Case {
    name: String,
    source_locator: String,
    token: String,
    expected: Expected,
    version: [u8; 4],
    depth: u8,
    parent_fingerprint: [u8; 4],
    child_number: u32,
    chain_code: [u8; 32],
    public_key: [u8; 33],
    checksum: [u8; 4],
}

fn decode_hex<const N: usize>(value: &str) -> [u8; N] {
    assert_eq!(value.len(), N * 2, "fixed hex width");
    assert!(
        value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte)),
        "lowercase hex only"
    );
    let mut output = [0u8; N];
    for (slot, pair) in output.iter_mut().zip(value.as_bytes().chunks_exact(2)) {
        let text = core::str::from_utf8(pair).expect("ASCII hex");
        *slot = u8::from_str_radix(text, 16).expect("hex byte");
    }
    output
}

fn parse_expected(value: &str) -> Expected {
    match value {
        "accept" => Expected::Accept,
        "InputTooLong" => Expected::Reject(XpubDecodeError::InputTooLong),
        "InvalidBase58Character" => Expected::Reject(XpubDecodeError::InvalidBase58Character),
        "DecodedLength" => Expected::Reject(XpubDecodeError::DecodedLength),
        "ChecksumMismatch" => Expected::Reject(XpubDecodeError::ChecksumMismatch),
        "UnsupportedVersion" => Expected::Reject(XpubDecodeError::UnsupportedVersion),
        "InvalidRootParentFingerprint" => {
            Expected::Reject(XpubDecodeError::InvalidRootParentFingerprint)
        }
        "InvalidRootChildNumber" => Expected::Reject(XpubDecodeError::InvalidRootChildNumber),
        "InvalidPublicKeyPrefix" => Expected::Reject(XpubDecodeError::InvalidPublicKeyPrefix),
        "InvalidPublicKey" => Expected::Reject(XpubDecodeError::InvalidPublicKey),
        "CryptographicBackendInvariant" => {
            Expected::Reject(XpubDecodeError::CryptographicBackendInvariant)
        }
        _ => panic!("unknown expected category"),
    }
}

/// Strict parse: exactly 19 blocks of exactly 11 fields in the frozen
/// order, exact byte size and line shape, unique tokens and locators,
/// fixed field lengths, and no silent skip.
fn parse_cases() -> Vec<Case> {
    assert_eq!(VECTORS.len(), 10_404, "fixture byte size");
    assert_eq!(VECTORS.lines().count(), 241, "fixture line count");
    assert!(VECTORS.ends_with('\n'), "final LF");
    assert!(!VECTORS.contains('\r'), "LF-only fixture");
    let fields: Vec<&str> = VECTORS
        .lines()
        .filter(|line| !line.is_empty() && !line.starts_with('#'))
        .collect();
    assert_eq!(fields.len(), 19 * 11, "exact field inventory");
    let names = [
        "case",
        "source_locator",
        "token",
        "expected",
        "version",
        "depth",
        "parent_fingerprint",
        "child_number",
        "chain_code",
        "public_key",
        "checksum",
    ];
    let mut cases = Vec::new();
    for block in fields.chunks_exact(11) {
        let mut values = Vec::new();
        for (line, name) in block.iter().zip(names) {
            let prefix = format!("{name}: ");
            values.push(line.strip_prefix(&prefix).expect("field order"));
        }
        let token = values[2];
        assert!((1..=112).contains(&token.len()), "bounded token length");
        assert!(
            token.bytes().all(
                |byte| b"123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
                    .contains(&byte)
            ),
            "exact Base58 alphabet"
        );
        cases.push(Case {
            name: values[0].to_string(),
            source_locator: values[1].to_string(),
            token: token.to_string(),
            expected: parse_expected(values[3]),
            version: decode_hex(values[4]),
            depth: decode_hex::<1>(values[5])[0],
            parent_fingerprint: decode_hex(values[6]),
            child_number: u32::from_be_bytes(decode_hex(values[7])),
            chain_code: decode_hex(values[8]),
            public_key: decode_hex(values[9]),
            checksum: decode_hex(values[10]),
        });
    }
    assert_eq!(cases.len(), 19);
    let unique_names: BTreeSet<&str> = cases.iter().map(|case| case.name.as_str()).collect();
    let unique_tokens: BTreeSet<&str> = cases.iter().map(|case| case.token.as_str()).collect();
    let unique_locators: BTreeSet<&str> = cases
        .iter()
        .map(|case| case.source_locator.as_str())
        .collect();
    assert_eq!(unique_names.len(), 19, "unique case names");
    assert_eq!(unique_tokens.len(), 19, "unique public tokens");
    assert_eq!(unique_locators.len(), 19, "unique source locators");
    cases
}

fn case_by_name<'a>(cases: &'a [Case], name: &str) -> &'a Case {
    cases
        .iter()
        .find(|case| case.name == name)
        .expect("named fixture case")
}

fn expected_decoded(case: &Case) -> DecodedXpub {
    DecodedXpub {
        public_node: PublicNode {
            depth: case.depth,
            chain_code: case.chain_code,
            compressed_public_key: case.public_key,
        },
        parent_fingerprint: case.parent_fingerprint,
        child_number: case.child_number,
    }
}

fn error_name(error: XpubDecodeError) -> &'static str {
    match error {
        XpubDecodeError::InputTooLong => "InputTooLong",
        XpubDecodeError::InvalidBase58Character => "InvalidBase58Character",
        XpubDecodeError::DecodedLength => "DecodedLength",
        XpubDecodeError::ChecksumMismatch => "ChecksumMismatch",
        XpubDecodeError::UnsupportedVersion => "UnsupportedVersion",
        XpubDecodeError::InvalidRootParentFingerprint => "InvalidRootParentFingerprint",
        XpubDecodeError::InvalidRootChildNumber => "InvalidRootChildNumber",
        XpubDecodeError::InvalidPublicKeyPrefix => "InvalidPublicKeyPrefix",
        XpubDecodeError::InvalidPublicKey => "InvalidPublicKey",
        XpubDecodeError::CryptographicBackendInvariant => "CryptographicBackendInvariant",
    }
}

#[test]
fn fixture_inventory_and_histogram_are_exact() {
    let cases = parse_cases();
    assert_eq!(
        case_by_name(&cases, "line-222").checksum,
        [0xab, 0x47, 0x3b, 0x21]
    );
    assert_eq!(
        case_by_name(&cases, "line-222-final-char-8-to-9").checksum,
        [0xab, 0x47, 0x3b, 0x22]
    );
    let expected_names = [
        "line-222",
        "line-225",
        "line-228",
        "line-231",
        "line-234",
        "line-237",
        "line-244",
        "line-247",
        "line-250",
        "line-253",
        "line-256",
        "line-259",
        "line-295",
        "line-297",
        "line-300",
        "line-302",
        "line-304",
        "line-307",
        "line-222-final-char-8-to-9",
    ];
    assert_eq!(
        cases
            .iter()
            .map(|case| case.name.as_str())
            .collect::<Vec<_>>(),
        expected_names
    );
    let mut histogram = BTreeMap::new();
    for case in &cases {
        let name = match case.expected {
            Expected::Accept => "accept",
            Expected::Reject(error) => error_name(error),
        };
        *histogram.entry(name).or_insert(0usize) += 1;
    }
    assert_eq!(histogram.remove("accept"), Some(12));
    assert_eq!(histogram.remove("InvalidPublicKeyPrefix"), Some(2));
    for once in [
        "InvalidRootParentFingerprint",
        "InvalidRootChildNumber",
        "UnsupportedVersion",
        "InvalidPublicKey",
        "ChecksumMismatch",
    ] {
        assert_eq!(histogram.remove(once), Some(1), "{once}");
    }
    assert!(histogram.is_empty(), "no unratified categories");
}

#[test]
fn all_nineteen_cases_are_fully_consumed() {
    for case in parse_cases() {
        let result = decode_mainnet_xpub(case.token.as_bytes());
        match case.expected {
            Expected::Accept => {
                assert_eq!(case.version, [0x04, 0x88, 0xb2, 0x1e]);
                assert_eq!(result, Ok(expected_decoded(&case)), "{}", case.name);
            }
            Expected::Reject(error) => {
                assert_eq!(result, Err(error), "{}", case.name);
            }
        }
    }
}

#[test]
fn accepted_vectors_preserve_exact_chain_ordering_and_hardened_metadata() {
    let cases = parse_cases();
    let vector_one = [222usize, 225, 228, 231, 234, 237];
    let vector_two = [244usize, 247, 250, 253, 256, 259];
    for (expected_depth, line) in vector_one.iter().enumerate() {
        let case = case_by_name(&cases, &format!("line-{line}"));
        let decoded = decode_mainnet_xpub(case.token.as_bytes()).expect("accepted vector one");
        assert_eq!(usize::from(decoded.public_node.depth), expected_depth);
    }
    for (expected_depth, line) in vector_two.iter().enumerate() {
        let case = case_by_name(&cases, &format!("line-{line}"));
        let decoded = decode_mainnet_xpub(case.token.as_bytes()).expect("accepted vector two");
        assert_eq!(usize::from(decoded.public_node.depth), expected_depth);
    }
    for (line, child) in [
        (225usize, 0x8000_0000u32),
        (250, u32::MAX),
        (256, 0xffff_fffe),
    ] {
        let case = case_by_name(&cases, &format!("line-{line}"));
        let decoded = decode_mainnet_xpub(case.token.as_bytes()).expect("hardened metadata");
        assert_eq!(decoded.child_number, child);
    }
    assert!(
        cases
            .iter()
            .filter(|case| case.expected == Expected::Accept)
            .any(|case| case.public_key[0] == 0x02),
        "02 accepted"
    );
    assert!(
        cases
            .iter()
            .filter(|case| case.expected == Expected::Accept)
            .any(|case| case.public_key[0] == 0x03),
        "03 accepted"
    );
}

#[test]
fn byte_bound_and_alphabet_precede_all_later_work() {
    assert_eq!(
        decode_mainnet_xpub(&[b'0'; 113]),
        Err(XpubDecodeError::InputTooLong),
        "113-byte bound precedes invalid-character scan"
    );
    assert_eq!(
        decode_mainnet_xpub(&[b'1'; 112]),
        Err(XpubDecodeError::DecodedLength),
        "112 valid bytes reach decoding"
    );
    assert_eq!(
        decode_mainnet_xpub(&[b'0'; 112]),
        Err(XpubDecodeError::InvalidBase58Character),
        "112 invalid bytes reach lexical rejection"
    );
}

#[test]
fn empty_leading_one_and_overflow_lengths_fail_closed() {
    assert_eq!(
        decode_mainnet_xpub(b""),
        Err(XpubDecodeError::DecodedLength)
    );
    for input in [
        &[b'1'; 1][..],
        &[b'1'; 81][..],
        &[b'1'; 83][..],
        &[b'z'; 112][..],
    ] {
        assert_eq!(
            decode_mainnet_xpub(input),
            Err(XpubDecodeError::DecodedLength)
        );
    }
    assert_eq!(
        decode_mainnet_xpub(&[b'1'; 82]),
        Err(XpubDecodeError::ChecksumMismatch),
        "exactly 82 leading zero bytes reach checksum"
    );
}

#[test]
fn invalid_alphabet_whitespace_nul_and_non_ascii_are_never_normalized() {
    for byte in [
        b'0', b'O', b'I', b'l', b'!', b'/', b':', b' ', b'\t', b'\n', b'\r', 0x00, 0x7f, 0x80, 0xff,
    ] {
        assert_eq!(
            decode_mainnet_xpub(&[byte]),
            Err(XpubDecodeError::InvalidBase58Character),
            "byte {byte:#04x}"
        );
    }
    let cases = parse_cases();
    let token = case_by_name(&cases, "line-222").token.as_bytes();
    let mut prefixed = Vec::with_capacity(token.len() + 1);
    prefixed.push(b' ');
    prefixed.extend_from_slice(token);
    assert_eq!(
        decode_mainnet_xpub(&prefixed),
        Err(XpubDecodeError::InvalidBase58Character)
    );
    let mut suffixed = token.to_vec();
    suffixed.push(b'\n');
    assert_eq!(
        decode_mainnet_xpub(&suffixed),
        Err(XpubDecodeError::InvalidBase58Character)
    );
}

#[test]
fn checksum_precedes_unsupported_version_and_full_public_chain_is_fixed() {
    let cases = parse_cases();
    let unsupported = case_by_name(&cases, "line-304");
    let mut checksum_bad = unsupported.token.as_bytes().to_vec();
    assert_eq!(checksum_bad.last().copied(), Some(b'9'));
    *checksum_bad.last_mut().expect("nonempty token") = b'A';
    assert_eq!(
        decode_mainnet_xpub(&checksum_bad),
        Err(XpubDecodeError::ChecksumMismatch),
        "checksum rejects before unsupported-version semantics"
    );
    let chain = [
        (&[b'0'; 113][..], XpubDecodeError::InputTooLong),
        (&[b'0'; 112][..], XpubDecodeError::InvalidBase58Character),
        (&[b'z'; 112][..], XpubDecodeError::DecodedLength),
        (
            case_by_name(&cases, "line-222-final-char-8-to-9")
                .token
                .as_bytes(),
            XpubDecodeError::ChecksumMismatch,
        ),
        (
            unsupported.token.as_bytes(),
            XpubDecodeError::UnsupportedVersion,
        ),
        (
            case_by_name(&cases, "line-300").token.as_bytes(),
            XpubDecodeError::InvalidRootParentFingerprint,
        ),
        (
            case_by_name(&cases, "line-302").token.as_bytes(),
            XpubDecodeError::InvalidRootChildNumber,
        ),
        (
            case_by_name(&cases, "line-295").token.as_bytes(),
            XpubDecodeError::InvalidPublicKeyPrefix,
        ),
        (
            case_by_name(&cases, "line-307").token.as_bytes(),
            XpubDecodeError::InvalidPublicKey,
        ),
    ];
    for (input, expected) in chain {
        assert_eq!(decode_mainnet_xpub(input), Err(expected));
    }
}

#[test]
fn decoding_is_deterministic_borrowed_and_mutation_robust() {
    let cases = parse_cases();
    let source = case_by_name(&cases, "line-222").token.as_bytes().to_vec();
    let before = source.clone();
    let first = decode_mainnet_xpub(&source).expect("valid xpub");
    let second = decode_mainnet_xpub(&source).expect("valid xpub");
    assert_eq!(first, second, "deterministic");
    assert_eq!(source, before, "borrowed input unchanged");
    for position in 0..source.len() {
        for byte in 0u8..=u8::MAX {
            let mut mutated = source.clone();
            mutated[position] = byte;
            let _ = decode_mainnet_xpub(&mutated);
        }
    }
}

#[test]
fn error_texts_and_output_widths_are_fixed() {
    let texts = [
        (XpubDecodeError::InputTooLong, "input too long"),
        (
            XpubDecodeError::InvalidBase58Character,
            "invalid base58 character",
        ),
        (XpubDecodeError::DecodedLength, "decoded length invalid"),
        (XpubDecodeError::ChecksumMismatch, "checksum mismatch"),
        (
            XpubDecodeError::UnsupportedVersion,
            "unsupported extended key version",
        ),
        (
            XpubDecodeError::InvalidRootParentFingerprint,
            "root parent fingerprint must be zero",
        ),
        (
            XpubDecodeError::InvalidRootChildNumber,
            "root child number must be zero",
        ),
        (
            XpubDecodeError::InvalidPublicKeyPrefix,
            "invalid public key prefix",
        ),
        (XpubDecodeError::InvalidPublicKey, "invalid public key"),
        (
            XpubDecodeError::CryptographicBackendInvariant,
            "cryptographic backend invariant",
        ),
    ];
    for (error, text) in texts {
        assert_eq!(error.to_string(), text);
    }
    let cases = parse_cases();
    let decoded =
        decode_mainnet_xpub(case_by_name(&cases, "line-222").token.as_bytes()).expect("valid");
    assert_eq!(decoded.public_node.chain_code.len(), 32);
    assert_eq!(decoded.public_node.compressed_public_key.len(), 33);
    assert_eq!(decoded.parent_fingerprint.len(), 4);
    assert_eq!(decoded.child_number.to_be_bytes().len(), 4);
}

fn count(haystack: &str, needle: &str) -> usize {
    haystack.matches(needle).count()
}

#[test]
fn public_surface_and_private_fixed_memory_implementation_are_frozen() {
    assert_eq!(count(LIB_SRC, "pub use "), 2);
    assert_eq!(
        count(
            LIB_SRC,
            "pub use xpub::{decode_mainnet_xpub, DecodedXpub, XpubDecodeError};"
        ),
        1
    );
    assert_eq!(count(LIB_SRC, "pub mod "), 0);
    for module in [
        "mod ckdpub;",
        "mod hmac_sha512;",
        "mod sha256;",
        "mod sha512;",
        "mod xpub;",
    ] {
        assert_eq!(count(LIB_SRC, module), 1, "{module}");
    }
    assert_eq!(count(XPUB_SRC, "pub struct "), 1);
    assert_eq!(count(XPUB_SRC, "pub struct DecodedXpub"), 1);
    for field in [
        "pub public_node: PublicNode,",
        "pub parent_fingerprint: [u8; 4],",
        "pub child_number: u32,",
    ] {
        assert_eq!(count(XPUB_SRC, field), 1, "{field}");
    }
    assert_eq!(count(XPUB_SRC, "pub enum "), 1);
    assert_eq!(count(XPUB_SRC, "pub enum XpubDecodeError"), 1);
    for variant in [
        "    InputTooLong,",
        "    InvalidBase58Character,",
        "    DecodedLength,",
        "    ChecksumMismatch,",
        "    UnsupportedVersion,",
        "    InvalidRootParentFingerprint,",
        "    InvalidRootChildNumber,",
        "    InvalidPublicKeyPrefix,",
        "    InvalidPublicKey,",
        "    CryptographicBackendInvariant,",
    ] {
        assert_eq!(count(XPUB_SRC, variant), 1, "{variant}");
    }
    assert_eq!(count(XPUB_SRC, "pub fn "), 1);
    assert_eq!(count(XPUB_SRC, "pub const "), 0);
    assert_eq!(count(SHA256_SRC, "pub fn "), 0);
    assert_eq!(count(SHA256_SRC, "pub struct "), 0);
    assert_eq!(count(SHA256_SRC, "pub enum "), 0);
    assert_eq!(count(SHA256_SRC, "pub mod "), 0);
    assert_eq!(count(SHA256_SRC, "pub const "), 0);
    assert_eq!(count(XPUB_SRC, "fn encode"), 0);
    assert_eq!(count(XPUB_SRC, "fn decode_mainnet_xpub("), 1);
    assert_eq!(count(XPUB_SRC, "payload[..4] != MAINNET_XPUB_VERSION"), 1);
    for heap in ["Vec<", "String", "Box<", "vec![", "format!(", ".to_vec()"] {
        assert_eq!(count(XPUB_SRC, heap), 0, "no heap form {heap}");
        assert_eq!(count(SHA256_SRC, heap), 0, "no heap form {heap}");
    }
    let forbidden_word = ["uns", "afe"].concat();
    assert_eq!(count(LIB_SRC, &forbidden_word), 1, "deny attribute only");
    for src in [
        CKDPUB_SRC,
        SHA512_SRC,
        HMAC_SHA512_SRC,
        SHA256_SRC,
        XPUB_SRC,
    ] {
        assert_eq!(count(src, &forbidden_word), 0);
        assert_eq!(count(src, "extern "), 0);
        assert_eq!(count(src, "secp256k1_"), 0);
    }
    assert_eq!(count(CARGO_TOML, "[dependencies]"), 1);
    assert_eq!(count(CARGO_TOML, "qk-secp = { path = \"../qk-secp\" }"), 1);
    assert_eq!(count(CARGO_TOML, "[dev-dependencies]"), 0);
    assert_eq!(count(CARGO_TOML, "[build-dependencies]"), 0);
    assert_eq!(count(CKDPUB_SRC, "pub fn derive_public_child"), 1);
}
