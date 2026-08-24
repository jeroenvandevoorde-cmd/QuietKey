//! Frozen public surface and fixed-memory source restrictions for M17.

const LIB: &str = include_str!("../src/lib.rs");
const AEAD: &str = include_str!("../src/aead.rs");
const CHACHA20: &str = include_str!("../src/chacha20.rs");
const HKDF: &str = include_str!("../src/hkdf_sha256.rs");
const HMAC: &str = include_str!("../src/hmac_sha256.rs");
const POLY1305: &str = include_str!("../src/poly1305.rs");
const SHA256: &str = include_str!("../src/sha256.rs");
const MANIFEST: &str = include_str!("../Cargo.toml");

fn production_prefix(source: &str) -> &str {
    source.split("\n#[cfg(test)]\n").next().unwrap_or(source)
}

#[test]
fn public_surface_is_exactly_one_error_and_two_capsule_operations() {
    let public_lines: Vec<&str> = LIB
        .lines()
        .map(str::trim_start)
        .filter(|line| line.starts_with("pub "))
        .collect();
    assert_eq!(
        public_lines,
        ["pub enum A1Error {", "pub fn encrypt(", "pub fn decrypt("],
        "complete public item surface"
    );
    for required in [
        "InvalidCapsuleLength,",
        "InvalidMagic,",
        "UnsupportedCodingVersion,",
        "UnsupportedCryptoVersion,",
        "UnsupportedNetwork,",
        "AuthenticationFailed,",
    ] {
        assert_eq!(
            LIB.matches(required).count(),
            1,
            "exact error variant {required}"
        );
    }
    assert!(
        LIB.contains("nonce: &[u8; 12]"),
        "caller supplies exact nonce"
    );
    assert!(
        LIB.contains(") -> [u8; 67]"),
        "encrypt returns exact capsule"
    );
    assert!(
        LIB.contains("capsule: &[u8]"),
        "decrypt validates presented length"
    );
    assert!(
        LIB.contains("seed_a_out: &mut [u8; 32]"),
        "fixed output buffer"
    );
    assert!(
        LIB.contains(") -> Result<(), A1Error>"),
        "closed decrypt result"
    );
    assert!(!LIB.contains("pub mod "));
    assert!(!LIB.contains("pub const "));
    assert!(!LIB.contains("pub use "));
    for source in [AEAD, CHACHA20, HKDF, HMAC, POLY1305, SHA256] {
        assert!(!source.contains("pub fn "), "no public primitive function");
        assert!(!source.contains("pub struct "), "no public primitive type");
        assert!(!source.contains("pub enum "), "no public primitive error");
    }
}

#[test]
fn capsule_wire_and_key_schedule_pins_are_present_in_production_source() {
    for required in [
        "const MAGIC: [u8; 4] = *b\"QKA1\";",
        "const CODING_VERSION: u8 = 1;",
        "const CRYPTO_VERSION: u8 = 1;",
        "const MAINNET: u8 = 1;",
        "const HEADER_LEN: usize = 7;",
        "const NONCE_LEN: usize = 12;",
        "const PLAINTEXT_LEN: usize = 32;",
        "const TAG_LEN: usize = 16;",
        "const _: [(); 67] = [(); CAPSULE_LEN];",
        "const _: [(); 39] = [(); AAD_LEN];",
    ] {
        assert!(LIB.contains(required), "{required}");
    }
    assert!(HKDF.contains("const DOCUMENT_INFO: &[u8; 14] = b\"QuietKey/A1/v1\";"));
    assert!(HKDF.contains("extract(wallet_id, a2)"));
    assert!(LIB.contains("aad[..HEADER_LEN].copy_from_slice(&capsule[..HEADER_LEN]);"));
    assert!(LIB.contains("aad[HEADER_LEN..].copy_from_slice(wallet_id);"));
}

#[test]
fn production_sources_have_no_allocation_unsafe_io_randomness_or_general_api() {
    for source in [
        production_prefix(LIB),
        production_prefix(AEAD),
        production_prefix(CHACHA20),
        production_prefix(HKDF),
        production_prefix(HMAC),
        production_prefix(POLY1305),
        production_prefix(SHA256),
    ] {
        for forbidden in [
            "Vec<",
            "Vec::",
            "vec![",
            "String",
            "Box<",
            "Box::",
            "Rc<",
            "Arc<",
            "alloc::",
            "std::",
            "unsafe fn",
            "unsafe impl",
            "unsafe {",
            "extern \"",
            "#[no_mangle]",
            "std::fs",
            "std::io",
            "std::net",
            "std::env",
            "println!",
            "eprintln!",
            "thread::",
            "SystemTime",
            "getrandom",
            "OsRng",
            "rand::",
            "random(",
        ] {
            assert!(
                !source.contains(forbidden),
                "forbidden production token {forbidden}"
            );
        }
    }
    for general_name in [
        "pub fn sha256",
        "pub fn hmac",
        "pub fn hkdf",
        "pub fn seal",
        "pub fn open",
        "pub fn chacha",
        "pub fn poly1305",
        "pub fn generate",
        "pub fn random",
    ] {
        assert!(
            !LIB.contains(general_name),
            "general API remains private: {general_name}"
        );
    }
}

#[test]
fn manifest_has_no_dependencies_or_build_surface() {
    assert!(MANIFEST.contains("[dependencies]\n"));
    let dependency_tail = MANIFEST.split_once("[dependencies]\n").unwrap().1;
    assert!(
        dependency_tail.trim().is_empty(),
        "dependency section is empty"
    );
    assert!(!MANIFEST.contains("[dev-dependencies]"));
    assert!(!MANIFEST.contains("[build-dependencies]"));
    assert!(!MANIFEST.contains("build ="));
    assert!(!MANIFEST.contains("version = \"1"));
    assert!(!MANIFEST.contains("git ="));
    assert!(!MANIFEST.contains("path ="));
}
