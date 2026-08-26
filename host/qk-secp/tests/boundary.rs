//! Boundary tests for the bounded FFI surface (QK-DEC-042/QK-DEC-111).
//!
//! HOST evidence only. Covers the approved-surface source scan, ABI
//! shape from outside the crate, generator parse/round-trip, invalid
//! and non-curve key rejection, tweak identities and order-boundary
//! rejections, bounded-DER rejections, concurrent determinism, and a
//! fixed-seed no-panic sweep. Known-answer verify cases live in the
//! Wycheproof harness.

use qk_secp::{
    ecdsa_sign_rfc6979, ecdsa_verify, pubkey_parse_compressed, pubkey_serialize_compressed,
    pubkey_tweak_add, secret_key_import, signature_parse_der, signature_serialize_der, PublicKey,
    SecpError, Signature,
};

const LIB_SRC: &str = include_str!("../src/lib.rs");
const FFI_SRC: &str = include_str!("../src/ffi.rs");
const BUILD_SRC: &str = include_str!("../build.rs");
const SELF_SRC: &str = include_str!("boundary.rs");
const WYCHEPROOF_SRC: &str = include_str!("wycheproof.rs");

/// Generator point G, compressed.
const G_COMPRESSED: [u8; 33] =
    hex33("0279BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798");
/// 2G, compressed.
const TWO_G_COMPRESSED: [u8; 33] =
    hex33("02C6047F9441ED7D6D3045406E95C07CD85C778E4B8CEF3CA7ABAC09B95C709EE5");
/// Curve order n, big endian.
const ORDER_N: [u8; 32] = hex32("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141");
/// n - 1, big endian.
const ORDER_N_MINUS_1: [u8; 32] =
    hex32("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364140");

const fn hex_nibble(b: u8) -> u8 {
    match b {
        b'0'..=b'9' => b - b'0',
        b'a'..=b'f' => b - b'a' + 10,
        b'A'..=b'F' => b - b'A' + 10,
        _ => panic!("invalid hex digit"),
    }
}

const fn hex33(s: &str) -> [u8; 33] {
    let bytes = s.as_bytes();
    assert!(bytes.len() == 66);
    let mut out = [0u8; 33];
    let mut i = 0;
    while i < 33 {
        out[i] = hex_nibble(bytes[i * 2]) * 16 + hex_nibble(bytes[i * 2 + 1]);
        i += 1;
    }
    out
}

const fn hex32(s: &str) -> [u8; 32] {
    let bytes = s.as_bytes();
    assert!(bytes.len() == 64);
    let mut out = [0u8; 32];
    let mut i = 0;
    while i < 32 {
        out[i] = hex_nibble(bytes[i * 2]) * 16 + hex_nibble(bytes[i * 2 + 1]);
        i += 1;
    }
    out
}

fn parse_g() -> PublicKey {
    match pubkey_parse_compressed(&G_COMPRESSED) {
        Ok(k) => k,
        Err(e) => panic!("generator must parse: {e}"),
    }
}

/// Count standalone keyword occurrences of a needle: matches that are
/// not embedded in a longer identifier.
fn standalone_count(haystack: &str, needle: &str) -> usize {
    let bytes = haystack.as_bytes();
    let mut count = 0usize;
    let mut from = 0usize;
    while let Some(pos) = haystack[from..].find(needle) {
        let start = from + pos;
        let end = start + needle.len();
        let before_ok = start == 0 || {
            let c = bytes[start - 1];
            !(c.is_ascii_alphanumeric() || c == b'_')
        };
        let after_ok = end >= bytes.len() || {
            let c = bytes[end];
            !(c.is_ascii_alphanumeric() || c == b'_')
        };
        if before_ok && after_ok {
            count += 1;
        }
        from = end;
    }
    count
}

/// Collect every identifier starting with the given lowercase prefix.
fn prefixed_identifiers(haystack: &str, prefix: &str) -> Vec<String> {
    let bytes = haystack.as_bytes();
    let mut found = Vec::new();
    let mut from = 0usize;
    while let Some(pos) = haystack[from..].find(prefix) {
        let start = from + pos;
        let before_ok = start == 0 || {
            let c = bytes[start - 1];
            !(c.is_ascii_alphanumeric() || c == b'_')
        };
        let mut end = start + prefix.len();
        while end < bytes.len() && (bytes[end].is_ascii_alphanumeric() || bytes[end] == b'_') {
            end += 1;
        }
        if before_ok {
            found.push(haystack[start..end].to_string());
        }
        from = end;
    }
    found
}

#[test]
fn unsafe_appears_only_in_the_ffi_module() {
    let kw = ["uns", "afe"].concat();
    assert_eq!(
        standalone_count(LIB_SRC, &kw),
        0,
        "lib.rs must stay outside the FFI boundary"
    );
    assert_eq!(standalone_count(BUILD_SRC, &kw), 0);
    assert_eq!(standalone_count(SELF_SRC, &kw), 0);
    assert_eq!(standalone_count(WYCHEPROOF_SRC, &kw), 0);
    assert!(
        standalone_count(FFI_SRC, &kw) > 0,
        "ffi.rs is the single FFI boundary module"
    );
}

#[test]
fn extern_declarations_are_exactly_the_approved_surface() {
    let approved_fns = [
        "secp256k1_context_create",
        "secp256k1_context_destroy",
        "secp256k1_ec_pubkey_parse",
        "secp256k1_ec_pubkey_serialize",
        "secp256k1_ec_pubkey_tweak_add",
        "secp256k1_ec_seckey_verify",
        "secp256k1_ecdsa_sign",
        "secp256k1_ecdsa_signature_normalize",
        "secp256k1_ecdsa_signature_parse_der",
        "secp256k1_ecdsa_signature_serialize_der",
        "secp256k1_ecdsa_verify",
    ];
    let mut idents = prefixed_identifiers(FFI_SRC, "secp256k1_");
    idents.sort();
    idents.dedup();
    let mut expected: Vec<String> = approved_fns.iter().map(|s| s.to_string()).collect();
    expected.push("secp256k1_context_static".to_string());
    expected.push("secp256k1_nonce_function_rfc6979".to_string());
    expected.sort();
    assert_eq!(
        idents, expected,
        "ffi.rs must reference exactly the approved two statics and eleven functions"
    );
    for name in approved_fns {
        assert_eq!(
            standalone_count(FFI_SRC, &format!("fn {name}")),
            1,
            "exactly one declaration of {name}"
        );
    }
    assert_eq!(
        standalone_count(FFI_SRC, "static secp256k1_context_static"),
        1
    );
    assert_eq!(
        standalone_count(FFI_SRC, "static secp256k1_nonce_function_rfc6979"),
        1
    );
    // No other crate file references any native identifier.
    assert!(prefixed_identifiers(LIB_SRC, "secp256k1_").is_empty());
    assert!(prefixed_identifiers(BUILD_SRC, "secp256k1_").is_empty());
}

#[test]
fn public_function_surface_is_exactly_the_approved_eight() {
    let approved = [
        "pub fn pubkey_parse_compressed",
        "pub fn pubkey_serialize_compressed",
        "pub fn pubkey_tweak_add",
        "pub fn signature_parse_der",
        "pub fn ecdsa_verify",
        "pub fn secret_key_import",
        "pub fn signature_serialize_der",
        "pub fn ecdsa_sign_rfc6979",
    ];
    for decl in approved {
        assert_eq!(standalone_count(LIB_SRC, decl), 1, "missing {decl}");
    }
    assert_eq!(
        LIB_SRC.matches("pub fn ").count(),
        approved.len(),
        "lib.rs must expose exactly the eight approved public functions"
    );
    assert_eq!(FFI_SRC.matches("pub fn ").count(), 0);
    let kw = ["uns", "afe"].concat();
    assert_eq!(LIB_SRC.matches(&format!("pub {kw}")).count(), 0);
}

#[test]
fn secret_owner_surface_is_opaque_and_nonduplicating() {
    assert_eq!(standalone_count(LIB_SRC, "pub struct SecretKey"), 1);
    assert_eq!(standalone_count(LIB_SRC, "impl Drop for SecretKey"), 1);
    assert_eq!(standalone_count(LIB_SRC, "impl SecretKey"), 0);
    for forbidden in [
        "impl Clone for SecretKey",
        "impl Copy for SecretKey",
        "impl core::fmt::Debug for SecretKey",
        "impl fmt::Debug for SecretKey",
        "impl core::fmt::Display for SecretKey",
        "impl fmt::Display for SecretKey",
        "impl PartialEq for SecretKey",
        "impl Eq for SecretKey",
    ] {
        assert_eq!(standalone_count(LIB_SRC, forbidden), 0, "{forbidden}");
    }
    let struct_position = LIB_SRC
        .find("pub struct SecretKey")
        .expect("SecretKey declaration exists");
    let prefix_start = struct_position.saturating_sub(160);
    let declaration_prefix = &LIB_SRC[prefix_start..struct_position];
    assert!(
        !declaration_prefix.contains("#[derive"),
        "SecretKey must not acquire derived traits"
    );
    assert_eq!(
        core::mem::size_of::<qk_secp::SecretKey>(),
        core::mem::size_of::<usize>()
    );
    assert_eq!(
        core::mem::align_of::<qk_secp::SecretKey>(),
        core::mem::align_of::<usize>()
    );
    const DROP_IMPL: &str = "impl Drop for SecretKey {\n    fn drop(&mut self) {\n        ffi::wipe_secret(self.bytes.as_mut());\n    }\n}";
    assert_eq!(
        LIB_SRC.matches(DROP_IMPL).count(),
        1,
        "SecretKey Drop must stay coupled directly to the volatile wipe boundary"
    );
}

#[test]
fn signing_surface_is_bound_to_normalize_serialize_parse_verify_order() {
    let start = LIB_SRC
        .find("pub fn ecdsa_sign_rfc6979")
        .expect("signing function exists");
    let body = &LIB_SRC[start..];
    let sign = body
        .find("ffi::ecdsa_sign_rfc6979")
        .expect("native signing call exists");
    let normalize = body
        .find("ffi::signature_normalize")
        .expect("normalization call exists");
    let serialize = body
        .find("signature_serialize_der")
        .expect("DER serialization call exists");
    let parse = body
        .find("signature_parse_der")
        .expect("DER parse call exists");
    let verify = body
        .find("ecdsa_verify")
        .expect("self-verification call exists");
    assert!(sign < normalize);
    assert!(normalize < serialize);
    assert!(serialize < parse);
    assert!(parse < verify);

    // Keep all newly approved names type-checked from outside the crate.
    let _: fn(&mut [u8; 32]) -> Result<qk_secp::SecretKey, SecpError> = secret_key_import;
    let _: fn(&qk_secp::SecretKey, &[u8; 32], &PublicKey) -> Result<Signature, SecpError> =
        ecdsa_sign_rfc6979;
    let _: fn(&Signature, &mut [u8; 72]) -> Result<usize, SecpError> = signature_serialize_der;
}

#[test]
fn build_script_watches_the_complete_vendor_root() {
    // The complete canonicalized vendor-root watch must be present so
    // transitive header changes under src/ and include/ invalidate the
    // native build.
    assert_eq!(
        standalone_count(
            BUILD_SRC,
            r#"println!("cargo:rerun-if-changed={}", vendor.display());"#,
        ),
        1,
        "build.rs must watch the complete canonicalized vendor root"
    );
    // The narrower per-unit and include-dir watches must remain in
    // addition to — not instead of — the vendor-root watch.
    assert_eq!(
        standalone_count(
            BUILD_SRC,
            r#"println!("cargo:rerun-if-changed={}", source.display());"#,
        ),
        1,
        "per-unit source watch must remain"
    );
    assert_eq!(
        standalone_count(
            BUILD_SRC,
            r#"println!("cargo:rerun-if-changed={}", include_dir.display());"#,
        ),
        1,
        "include-dir watch must remain"
    );
}

#[test]
fn abi_shape_from_outside() {
    assert_eq!(core::mem::size_of::<PublicKey>(), 64);
    assert_eq!(core::mem::size_of::<Signature>(), 64);
    assert_eq!(core::mem::align_of::<PublicKey>(), 1);
    assert_eq!(core::mem::align_of::<Signature>(), 1);
}

#[test]
fn generator_parses_and_round_trips() {
    let g = parse_g();
    assert_eq!(pubkey_serialize_compressed(&g), Ok(G_COMPRESSED));
}

#[test]
fn invalid_public_keys_are_rejected() {
    // Uncompressed / hybrid prefixes are outside the fixed 33-byte
    // compressed form.
    for prefix in [0x00u8, 0x01, 0x04, 0x05, 0x06, 0x07, 0xff] {
        let mut key = G_COMPRESSED;
        key[0] = prefix;
        assert!(
            matches!(
                pubkey_parse_compressed(&key),
                Err(SecpError::PubkeyParseFailed)
            ),
            "prefix {prefix:#04x} must be rejected"
        );
    }
    // x >= p: not a valid field element.
    let mut overflow = [0xffu8; 33];
    overflow[0] = 0x02;
    assert!(matches!(
        pubkey_parse_compressed(&overflow),
        Err(SecpError::PubkeyParseFailed)
    ));
    // x = 0 is not on the curve (7 is a non-residue mod p).
    let mut zero_x = [0u8; 33];
    zero_x[0] = 0x02;
    assert!(matches!(
        pubkey_parse_compressed(&zero_x),
        Err(SecpError::PubkeyParseFailed)
    ));
}

#[test]
fn tweak_add_zero_is_identity() {
    let g = parse_g();
    let tweaked = match pubkey_tweak_add(&g, &[0u8; 32]) {
        Ok(k) => k,
        Err(e) => panic!("zero tweak must succeed: {e}"),
    };
    assert_eq!(pubkey_serialize_compressed(&tweaked), Ok(G_COMPRESSED));
}

#[test]
fn tweak_add_one_on_g_yields_two_g() {
    let g = parse_g();
    let mut one = [0u8; 32];
    one[31] = 1;
    let tweaked = match pubkey_tweak_add(&g, &one) {
        Ok(k) => k,
        Err(e) => panic!("tweak by one must succeed: {e}"),
    };
    assert_eq!(pubkey_serialize_compressed(&tweaked), Ok(TWO_G_COMPRESSED));
}

#[test]
fn tweak_at_or_beyond_group_boundaries_is_rejected() {
    let g = parse_g();
    // tweak == n: out of range.
    assert!(matches!(
        pubkey_tweak_add(&g, &ORDER_N),
        Err(SecpError::TweakRejected)
    ));
    // tweak == n - 1 on G: G + (n-1)G = nG = infinity.
    assert!(matches!(
        pubkey_tweak_add(&g, &ORDER_N_MINUS_1),
        Err(SecpError::TweakRejected)
    ));
    // all-ff tweak: >= n, out of range.
    assert!(matches!(
        pubkey_tweak_add(&g, &[0xffu8; 32]),
        Err(SecpError::TweakRejected)
    ));
}

#[test]
fn secret_import_accepts_n_minus_one_rejects_n_and_always_wipes_source() {
    let mut accepted_source = ORDER_N_MINUS_1;
    let accepted = secret_key_import(&mut accepted_source)
        .expect("the maximum in-range secret scalar must import");
    assert_eq!(accepted_source, [0u8; 32]);
    drop(accepted);

    let mut rejected_source = ORDER_N;
    assert!(matches!(
        secret_key_import(&mut rejected_source),
        Err(SecpError::SecretKeyRejected)
    ));
    assert_eq!(rejected_source, [0u8; 32]);
}

#[test]
fn der_container_bounds_are_enforced_before_ffi() {
    assert!(matches!(
        signature_parse_der(&[]),
        Err(SecpError::DerLengthOutOfBounds)
    ));
    assert!(matches!(
        signature_parse_der(&[0x30u8; 7]),
        Err(SecpError::DerLengthOutOfBounds)
    ));
    assert!(matches!(
        signature_parse_der(&[0x30u8; 73]),
        Err(SecpError::DerLengthOutOfBounds)
    ));
    assert!(matches!(
        signature_parse_der(&[0x30u8; 300]),
        Err(SecpError::DerLengthOutOfBounds)
    ));
    // In-bounds garbage is rejected by the parser, not the bounds.
    assert!(matches!(
        signature_parse_der(&[0xaau8; 72]),
        Err(SecpError::SignatureParseFailed)
    ));
}

/// Minimal DER for r = 0, s = 1 parses or rejects, but never verifies.
#[test]
fn zero_component_signatures_never_verify() {
    let g = parse_g();
    let digest = [0x11u8; 32];
    // 30 06 02 01 00 02 01 01  => r = 0, s = 1
    let r_zero = [0x30, 0x06, 0x02, 0x01, 0x00, 0x02, 0x01, 0x01];
    // 30 06 02 01 01 02 01 00  => r = 1, s = 0
    let s_zero = [0x30, 0x06, 0x02, 0x01, 0x01, 0x02, 0x01, 0x00];
    for der in [r_zero, s_zero] {
        match signature_parse_der(&der) {
            Ok(sig) => assert_eq!(
                ecdsa_verify(&sig, &digest, &g),
                Err(SecpError::VerificationFailed)
            ),
            Err(e) => assert_eq!(e, SecpError::SignatureParseFailed),
        }
    }
}

#[test]
fn repeated_and_concurrent_calls_are_deterministic() {
    let first = match pubkey_parse_compressed(&G_COMPRESSED) {
        Ok(k) => pubkey_serialize_compressed(&k),
        Err(e) => panic!("generator must parse: {e}"),
    };
    for _ in 0..200 {
        let again = match pubkey_parse_compressed(&G_COMPRESSED) {
            Ok(k) => pubkey_serialize_compressed(&k),
            Err(e) => panic!("generator must parse: {e}"),
        };
        assert_eq!(again, first);
    }
    let mut handles = Vec::new();
    for _ in 0..8 {
        handles.push(std::thread::spawn(|| {
            let mut one = [0u8; 32];
            one[31] = 1;
            for _ in 0..100 {
                let g = match pubkey_parse_compressed(&G_COMPRESSED) {
                    Ok(k) => k,
                    Err(e) => panic!("generator must parse: {e}"),
                };
                let doubled = match pubkey_tweak_add(&g, &one) {
                    Ok(k) => k,
                    Err(e) => panic!("tweak by one must succeed: {e}"),
                };
                assert_eq!(pubkey_serialize_compressed(&doubled), Ok(TWO_G_COMPRESSED));
                assert!(matches!(
                    pubkey_tweak_add(&g, &ORDER_N),
                    Err(SecpError::TweakRejected)
                ));
            }
        }));
    }
    for handle in handles {
        match handle.join() {
            Ok(()) => {}
            Err(_) => panic!("concurrent determinism thread panicked"),
        }
    }
}

/// Deterministic xorshift64* stream for the no-panic sweep.
struct FixedSeedRng(u64);

impl FixedSeedRng {
    fn next(&mut self) -> u64 {
        let mut x = self.0;
        x ^= x >> 12;
        x ^= x << 25;
        x ^= x >> 27;
        self.0 = x;
        x.wrapping_mul(0x2545_f491_4f6c_dd1d)
    }

    fn fill(&mut self, buf: &mut [u8]) {
        for chunk in buf.chunks_mut(8) {
            let word = self.next().to_le_bytes();
            let take = chunk.len();
            chunk.copy_from_slice(&word[..take]);
        }
    }
}

#[test]
fn fixed_seed_sweep_never_panics() {
    let mut rng = FixedSeedRng(0x9e37_79b9_7f4a_7c15);
    let g = parse_g();
    let minimal_sig = match signature_parse_der(&[0x30, 0x06, 0x02, 0x01, 0x01, 0x02, 0x01, 0x01]) {
        Ok(s) => s,
        Err(e) => panic!("minimal r=1,s=1 der must parse: {e}"),
    };
    for round in 0..2000u32 {
        let mut key = [0u8; 33];
        rng.fill(&mut key);
        key[0] = (round % 256) as u8;
        let parsed = pubkey_parse_compressed(&key);
        if let Ok(k) = parsed {
            let _ = pubkey_serialize_compressed(&k);
        }
        let mut tweak = [0u8; 32];
        rng.fill(&mut tweak);
        let _ = pubkey_tweak_add(&g, &tweak);
        let mut der = [0u8; 100];
        rng.fill(&mut der);
        let len = (rng.next() % 101) as usize;
        if let Ok(sig) = signature_parse_der(&der[..len]) {
            let mut digest = [0u8; 32];
            rng.fill(&mut digest);
            let _ = ecdsa_verify(&sig, &digest, &g);
        }
        let mut digest = [0u8; 32];
        rng.fill(&mut digest);
        assert_eq!(
            ecdsa_verify(&minimal_sig, &digest, &g),
            Err(SecpError::VerificationFailed)
        );
    }
}
