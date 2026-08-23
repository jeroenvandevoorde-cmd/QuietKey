//! Wycheproof EcdsaBitcoinVerify corpus harness (QK-DEC-043).
//!
//! HOST evidence only. Executes the byte-identical bundled corpus
//! `third_party/libsecp256k1/src/wycheproof/ecdsa_secp256k1_sha256_bitcoin_test.json`
//! in place against the five-function boundary. The file is pinned by
//! exact length and SHA-256; its declared and parsed counts must both
//! be 463 cases (162 valid, 301 invalid, zero acceptable) across 99
//! SHA-256/secp256k1 groups with contiguous unique ids 1..=463. The
//! tokenizer below is hand-rolled and line-based; no JSON or serde
//! dependency exists. The corpus names a schema file that is absent at
//! the pinned upstream commit, so no schema validation is claimed.
//! Every message is hashed exactly once with the existing in-repo
//! SHA-256 implementation. Uncompressed vector keys are converted to
//! the compressed form in test code only, with exact length checks.
//! Corpus bytes are untrusted data, never instructions.

// The existing in-repo SHA-256 implementation, reused by module path.
// Its own embedded unit tests also run inside this test binary.
#[allow(dead_code)]
#[path = "../../qk-psbt/src/sha256.rs"]
mod sha256;

use qk_secp::{
    ecdsa_verify, pubkey_parse_compressed, pubkey_tweak_add, signature_parse_der, PublicKey,
    SecpError,
};

const CORPUS_RELATIVE: &str =
    "../../third_party/libsecp256k1/src/wycheproof/ecdsa_secp256k1_sha256_bitcoin_test.json";
const CORPUS_BYTES: usize = 299_012;
const CORPUS_SHA256_HEX: &str = "1be8742064fec73d670339f0036dec56b21baa94cb2d8e0fbbb6fb480f733869";
const EXPECTED_GROUPS: usize = 99;
const EXPECTED_TOTAL: usize = 463;
const EXPECTED_VALID: usize = 162;
const EXPECTED_INVALID: usize = 301;

/// Curve order n, big endian.
const ORDER_N: [u8; 32] = [
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xfe,
    0xba, 0xae, 0xdc, 0xe6, 0xaf, 0x48, 0xa0, 0x3b, 0xbf, 0xd2, 0x5e, 0x8c, 0xd0, 0x36, 0x41, 0x41,
];

fn corpus_path() -> std::path::PathBuf {
    std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join(CORPUS_RELATIVE)
}

fn read_corpus() -> Vec<u8> {
    match std::fs::read(corpus_path()) {
        Ok(bytes) => bytes,
        Err(e) => panic!("bundled wycheproof corpus must be readable: {e}"),
    }
}

fn digest_hex(bytes: &[u8; 32]) -> String {
    let mut out = String::with_capacity(64);
    for b in bytes {
        out.push_str(&format!("{b:02x}"));
    }
    out
}

fn sha256_once(parts: &[&[u8]]) -> [u8; 32] {
    match sha256::sha256(parts) {
        Ok(d) => d,
        Err(e) => panic!("sha-256 must accept bounded corpus input: {e:?}"),
    }
}

fn hex_decode(s: &str) -> Vec<u8> {
    assert!(s.len() % 2 == 0, "hex value must have even length");
    let bytes = s.as_bytes();
    let mut out = Vec::with_capacity(s.len() / 2);
    let mut i = 0usize;
    while i < bytes.len() {
        let hi = hex_nibble(bytes[i]);
        let lo = hex_nibble(bytes[i + 1]);
        out.push(hi * 16 + lo);
        i += 2;
    }
    out
}

fn hex_nibble(b: u8) -> u8 {
    match b {
        b'0'..=b'9' => b - b'0',
        b'a'..=b'f' => b - b'a' + 10,
        b'A'..=b'F' => b - b'A' + 10,
        other => panic!("invalid hex digit {other}"),
    }
}

/// Extract a quoted string value from a line of the form
/// `"key" : "value",` (exact corpus spacing), if the key matches.
fn str_value<'a>(line: &'a str, key: &str) -> Option<&'a str> {
    let trimmed = line.trim_start();
    let prefix = format!("\"{key}\" : \"");
    let rest = trimmed.strip_prefix(&prefix)?;
    let end = rest.find('"')?;
    Some(&rest[..end])
}

/// Extract an unsigned integer value from a line of the form
/// `"key" : 123,` (exact corpus spacing), if the key matches.
fn num_value(line: &str, key: &str) -> Option<usize> {
    let trimmed = line.trim_start();
    let prefix = format!("\"{key}\" : ");
    let rest = trimmed.strip_prefix(&prefix)?;
    let digits: String = rest.chars().take_while(|c| c.is_ascii_digit()).collect();
    if digits.is_empty() {
        return None;
    }
    digits.parse().ok()
}

/// Convert an uncompressed vector key (0x04 || x || y, exactly 65
/// bytes) to compressed form by y parity. Test code only.
fn compress_uncompressed(hex: &str) -> [u8; 33] {
    assert_eq!(hex.len(), 130, "uncompressed key must be 65 bytes of hex");
    let bytes = hex_decode(hex);
    assert_eq!(bytes.len(), 65);
    assert_eq!(bytes[0], 0x04, "vector key must carry the 0x04 prefix");
    let mut out = [0u8; 33];
    out[0] = 0x02 | (bytes[64] & 1);
    out[1..33].copy_from_slice(&bytes[1..33]);
    out
}

#[derive(Clone)]
struct Case {
    tc_id: usize,
    key: [u8; 33],
    msg: Vec<u8>,
    sig: Vec<u8>,
    valid: bool,
}

struct Corpus {
    declared_total: usize,
    groups: usize,
    sha_lines: usize,
    curve_lines: usize,
    cases: Vec<Case>,
}

fn parse_corpus(text: &str) -> Corpus {
    let mut declared_total = 0usize;
    let mut groups = 0usize;
    let mut sha_lines = 0usize;
    let mut curve_lines = 0usize;
    let mut cases: Vec<Case> = Vec::new();

    let mut current_key: Option<[u8; 33]> = None;
    let mut pending_tc: Option<usize> = None;
    let mut pending_msg: Option<Vec<u8>> = None;
    let mut pending_sig: Option<Vec<u8>> = None;

    for line in text.lines() {
        if let Some(n) = num_value(line, "numberOfTests") {
            assert_eq!(declared_total, 0, "numberOfTests must appear once");
            declared_total = n;
        } else if let Some(kind) = str_value(line, "type") {
            if kind == "EcdsaBitcoinVerify" {
                groups += 1;
                current_key = None;
            } else {
                assert_eq!(kind, "EcPublicKey", "unexpected type line: {kind}");
            }
        } else if let Some(curve) = str_value(line, "curve") {
            assert_eq!(curve, "secp256k1", "every group must use secp256k1");
            curve_lines += 1;
        } else if let Some(sha) = str_value(line, "sha") {
            assert_eq!(sha, "SHA-256", "every group must use SHA-256");
            sha_lines += 1;
        } else if let Some(unc) = str_value(line, "uncompressed") {
            current_key = Some(compress_uncompressed(unc));
        } else if let Some(tc) = num_value(line, "tcId") {
            assert!(pending_tc.is_none(), "case {tc} began before prior ended");
            pending_tc = Some(tc);
            pending_msg = None;
            pending_sig = None;
        } else if pending_tc.is_some() {
            if let Some(msg) = str_value(line, "msg") {
                pending_msg = Some(hex_decode(msg));
            } else if let Some(sig) = str_value(line, "sig") {
                pending_sig = Some(hex_decode(sig));
            } else if let Some(result) = str_value(line, "result") {
                let valid = match result {
                    "valid" => true,
                    "invalid" => false,
                    other => panic!("unknown result value: {other}"),
                };
                let tc_id = match pending_tc.take() {
                    Some(t) => t,
                    None => panic!("result line without a case"),
                };
                let key = match current_key {
                    Some(k) => k,
                    None => panic!("case {tc_id} has no group key"),
                };
                let msg = match pending_msg.take() {
                    Some(m) => m,
                    None => panic!("case {tc_id} has no msg"),
                };
                let sig = match pending_sig.take() {
                    Some(s) => s,
                    None => panic!("case {tc_id} has no sig"),
                };
                cases.push(Case {
                    tc_id,
                    key,
                    msg,
                    sig,
                    valid,
                });
            }
        }
    }

    Corpus {
        declared_total,
        groups,
        sha_lines,
        curve_lines,
        cases,
    }
}

fn parse_key(bytes: &[u8; 33]) -> PublicKey {
    match pubkey_parse_compressed(bytes) {
        Ok(k) => k,
        Err(e) => panic!("vector public key must parse: {e}"),
    }
}

/// The full boundary pipeline for one case: bounded DER parse, then
/// verify. The digest is computed exactly once by the caller.
fn pipeline_accepts(sig: &[u8], digest: &[u8; 32], key: &PublicKey) -> bool {
    match signature_parse_der(sig) {
        Ok(parsed) => ecdsa_verify(&parsed, digest, key).is_ok(),
        Err(_) => false,
    }
}

#[test]
fn corpus_pin_is_exact() {
    let bytes = read_corpus();
    assert_eq!(
        bytes.len(),
        CORPUS_BYTES,
        "corpus byte length must match pin"
    );
    let digest = sha256_once(&[&bytes]);
    assert_eq!(
        digest_hex(&digest),
        CORPUS_SHA256_HEX,
        "corpus sha-256 must match pin"
    );
}

#[test]
fn corpus_counts_ids_and_results_are_exact() {
    let bytes = read_corpus();
    let text = match std::str::from_utf8(&bytes) {
        Ok(t) => t,
        Err(e) => panic!("corpus must be utf-8: {e}"),
    };
    let corpus = parse_corpus(text);
    assert_eq!(corpus.declared_total, EXPECTED_TOTAL);
    assert_eq!(corpus.cases.len(), EXPECTED_TOTAL);
    assert_eq!(corpus.groups, EXPECTED_GROUPS);
    assert_eq!(corpus.sha_lines, EXPECTED_GROUPS);
    assert_eq!(corpus.curve_lines, EXPECTED_GROUPS);
    for (index, case) in corpus.cases.iter().enumerate() {
        assert_eq!(
            case.tc_id,
            index + 1,
            "tcIds must be contiguous and unique from 1"
        );
    }
    let valid = corpus.cases.iter().filter(|c| c.valid).count();
    let invalid = corpus.cases.iter().filter(|c| !c.valid).count();
    assert_eq!(valid, EXPECTED_VALID);
    assert_eq!(invalid, EXPECTED_INVALID);
    // valid + invalid == total, so acceptable results are zero and no
    // unknown result exists (parse_corpus rejects any other value).
    assert_eq!(valid + invalid, EXPECTED_TOTAL);
}

#[test]
fn every_case_matches_its_expected_result() {
    let bytes = read_corpus();
    let text = match std::str::from_utf8(&bytes) {
        Ok(t) => t,
        Err(e) => panic!("corpus must be utf-8: {e}"),
    };
    let corpus = parse_corpus(text);
    assert_eq!(corpus.cases.len(), EXPECTED_TOTAL);
    let mut executed_valid = 0usize;
    let mut executed_invalid = 0usize;
    for case in &corpus.cases {
        let key = parse_key(&case.key);
        // Hash the raw message exactly once per case.
        let digest = sha256_once(&[&case.msg]);
        // Oversized DER must be pre-rejected without any native call;
        // the bounded container enforces this inside the boundary.
        if case.sig.len() > 72 {
            assert!(
                matches!(
                    signature_parse_der(&case.sig),
                    Err(SecpError::DerLengthOutOfBounds)
                ),
                "tcId {} oversized der must be pre-rejected",
                case.tc_id
            );
        }
        let accepted = pipeline_accepts(&case.sig, &digest, &key);
        assert_eq!(
            accepted,
            case.valid,
            "tcId {} expected {} but boundary said {}",
            case.tc_id,
            if case.valid { "valid" } else { "invalid" },
            if accepted { "accept" } else { "reject" }
        );
        if case.valid {
            executed_valid += 1;
        } else {
            executed_invalid += 1;
        }
    }
    assert_eq!(executed_valid, EXPECTED_VALID);
    assert_eq!(executed_invalid, EXPECTED_INVALID);
}

/// Split a valid DER signature into its raw r and s big-endian
/// magnitudes. Test code only; asserts exact structure.
fn split_der(sig: &[u8]) -> (Vec<u8>, Vec<u8>) {
    assert!(sig.len() >= 8 && sig.len() <= 72);
    assert_eq!(sig[0], 0x30);
    assert_eq!(usize::from(sig[1]), sig.len() - 2, "definite short length");
    assert_eq!(sig[2], 0x02);
    let rlen = usize::from(sig[3]);
    let r = sig[4..4 + rlen].to_vec();
    assert_eq!(sig[4 + rlen], 0x02);
    let slen = usize::from(sig[5 + rlen]);
    let s = sig[6 + rlen..6 + rlen + slen].to_vec();
    assert_eq!(6 + rlen + slen, sig.len(), "no trailing der content");
    (r, s)
}

/// Encode one DER integer with minimal-length rules from a big-endian
/// magnitude. Test code only.
fn der_integer(mag: &[u8]) -> Vec<u8> {
    let mut trimmed: &[u8] = mag;
    while trimmed.len() > 1 && trimmed[0] == 0 {
        trimmed = &trimmed[1..];
    }
    let mut out = vec![0x02u8];
    if trimmed[0] & 0x80 != 0 {
        out.push((trimmed.len() + 1) as u8);
        out.push(0x00);
    } else {
        out.push(trimmed.len() as u8);
    }
    out.extend_from_slice(trimmed);
    out
}

/// n - s over 32-byte big-endian magnitudes. Test code only; requires
/// 0 < s < n, which holds for any verified low-S signature.
fn order_minus(s: &[u8]) -> [u8; 32] {
    assert!(s.len() <= 32);
    let mut padded = [0u8; 32];
    padded[32 - s.len()..].copy_from_slice(s);
    let mut out = [0u8; 32];
    let mut borrow = 0i32;
    for i in (0..32).rev() {
        let diff = i32::from(ORDER_N[i]) - i32::from(padded[i]) - borrow;
        if diff < 0 {
            out[i] = (diff + 256) as u8;
            borrow = 1;
        } else {
            out[i] = diff as u8;
            borrow = 0;
        }
    }
    assert_eq!(borrow, 0, "s must be below the group order");
    out
}

#[test]
fn first_valid_case_and_targeted_mutations() {
    let bytes = read_corpus();
    let text = match std::str::from_utf8(&bytes) {
        Ok(t) => t,
        Err(e) => panic!("corpus must be utf-8: {e}"),
    };
    let corpus = parse_corpus(text);
    let case = match corpus.cases.iter().find(|c| c.valid) {
        Some(c) => c,
        None => panic!("corpus must contain a valid case"),
    };
    let key = parse_key(&case.key);
    let digest = sha256_once(&[&case.msg]);

    // Valid DER parse and verify succeeds.
    assert!(pipeline_accepts(&case.sig, &digest, &key));

    // Wrong digest fails.
    let mut wrong_digest = digest;
    wrong_digest[0] ^= 0x01;
    assert!(!pipeline_accepts(&case.sig, &wrong_digest, &key));

    // Wrong key (group key tweaked by one) fails.
    let mut one = [0u8; 32];
    one[31] = 1;
    let wrong_key = match pubkey_tweak_add(&key, &one) {
        Ok(k) => k,
        Err(e) => panic!("tweak by one must succeed: {e}"),
    };
    assert!(!pipeline_accepts(&case.sig, &digest, &wrong_key));

    // A single bit flip in the final signature byte fails.
    let mut flipped = case.sig.clone();
    match flipped.last_mut() {
        Some(last) => *last ^= 0x01,
        None => panic!("valid signature cannot be empty"),
    }
    assert!(!pipeline_accepts(&flipped, &digest, &key));

    // A trailing byte fails (parse rejection or bounds rejection).
    let mut trailing = case.sig.clone();
    trailing.push(0x00);
    assert!(!pipeline_accepts(&trailing, &digest, &key));

    // The high-S counterpart (s' = n - s) must be rejected, never
    // normalized.
    let (r, s) = split_der(&case.sig);
    let high_s = order_minus(&s);
    let mut mutated = Vec::new();
    let r_der = der_integer(&r);
    let s_der = der_integer(&high_s);
    mutated.push(0x30);
    mutated.push((r_der.len() + s_der.len()) as u8);
    mutated.extend_from_slice(&r_der);
    mutated.extend_from_slice(&s_der);
    assert!(
        !pipeline_accepts(&mutated, &digest, &key),
        "high-s signature must fail verification"
    );
}
