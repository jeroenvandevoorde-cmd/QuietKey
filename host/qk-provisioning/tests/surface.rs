//! Frozen M26 public surface and HOST-only source restrictions.

const LIB: &str = include_str!("../src/lib.rs");
const BIP39: &str = include_str!("../src/bip39.rs");
const BIP32: &str = include_str!("../src/bip32_private.rs");
const BECH32: &str = include_str!("../src/bech32.rs");
const DESCRIPTOR: &str = include_str!("../src/descriptor_build.rs");
const DICE: &str = include_str!("../src/dice.rs");
const QKEC: &str = include_str!("../src/qkec.rs");
const SECRET: &str = include_str!("../src/secret.rs");
const MANIFEST: &str = include_str!("../Cargo.toml");

fn production_prefix(source: &str) -> &str {
    source.split("\n#[cfg(test)]\n").next().unwrap_or(source)
}

#[test]
fn public_surface_is_exactly_error_artifacts_and_run_operations() {
    let public_lines: Vec<&str> = LIB
        .lines()
        .map(str::trim_start)
        .filter(|line| line.starts_with("pub "))
        .collect();
    assert_eq!(
        public_lines,
        [
            "pub enum ProvisioningError {",
            "pub struct ProvisioningArtifacts {",
            "pub account_xpubs: [[u8; 111]; 3],",
            "pub descriptors: [[u8; 445]; 2],",
            "pub wallet_id: [u8; 32],",
            "pub first_scripts: [[u8; 34]; 2],",
            "pub first_addresses: [[u8; 62]; 2],",
            "pub a1_capsule: [u8; 67],",
            "pub struct HostProvisioningRun {",
            "pub fn from_qkec(",
            "pub fn from_dice(transcripts: [&[u8]; 4]) -> Result<Self, ProvisioningError> {",
            "pub fn encrypt_a1(",
        ]
    );
    for source in [BIP39, BIP32, BECH32, DESCRIPTOR, DICE, QKEC, SECRET] {
        assert!(!source.contains("pub fn "), "private helper operation");
        assert!(!source.contains("pub struct "), "private helper type");
        assert!(!source.contains("pub enum "), "private helper error");
    }
    for forbidden in [
        "pub mod ",
        "pub use ",
        "pub fn mnemonic",
        "pub fn seed",
        "pub fn xprv",
        "pub fn scalar",
        "pub fn chain_code",
        "pub fn sha256",
        "pub fn hmac",
        "pub fn hkdf",
        "pub fn base58",
        "pub fn bech32",
        "pub fn generate",
        "pub fn random",
    ] {
        assert!(
            !LIB.contains(forbidden),
            "forbidden public surface {forbidden}"
        );
    }
}

#[test]
fn fixed_constants_and_private_traits_are_source_locked() {
    for required in [
        "const PURPOSE_PREFIX: &[u8] = b\"QuietKey/QKEC-1\";",
        "const OUTPUT_INFO: &[u8] = b\"QuietKey/256-bit-output\";",
        "b\"Seed-A\",",
        "b\"Signer-B\",",
        "b\"Signer-C\",",
        "b\"A2\"",
        "const PBKDF2_ROUNDS: usize = 2048;",
        "const PATH: [u32; 4] = [HARDENED + 48, HARDENED, HARDENED, HARDENED + 2];",
        "const HRP: &[u8] = b\"bc\";",
    ] {
        assert!(
            [QKEC, BIP39, BIP32, BECH32]
                .iter()
                .any(|source| source.contains(required)),
            "missing fixed constant {required}"
        );
    }
    for forbidden in [
        "impl Clone for Secret",
        "impl Copy for Secret",
        "impl Debug for Secret",
        "impl Display for Secret",
        "#[derive(Clone",
        "#[derive(Copy",
        "#[derive(Debug",
    ] {
        assert!(!SECRET.contains(forbidden), "secret trait {forbidden}");
    }
    assert!(SECRET.contains("impl<const N: usize> Drop for Secret<N>"));
    assert!(!LIB.contains("impl Clone for HostProvisioningRun"));
    assert!(!LIB.contains("impl Copy for HostProvisioningRun"));
    assert!(!LIB.contains("impl Debug for HostProvisioningRun"));
}

#[test]
fn production_sources_have_no_io_randomness_or_second_unsafe_boundary() {
    for source in [
        production_prefix(LIB),
        production_prefix(BIP39),
        production_prefix(BIP32),
        production_prefix(BECH32),
        production_prefix(DESCRIPTOR),
        production_prefix(DICE),
        production_prefix(QKEC),
        production_prefix(SECRET),
    ] {
        for forbidden in [
            "unsafe {",
            "unsafe fn",
            "extern \"C\"",
            "std::fs",
            "std::io",
            "std::net",
            "std::env",
            "println!",
            "eprintln!",
            "SystemTime",
            "getrandom",
            "OsRng",
            "rand::",
            "random(",
        ] {
            assert!(!source.contains(forbidden), "forbidden token {forbidden}");
        }
    }
    assert!(LIB.contains("#![deny(unsafe_code)]"));
}

#[test]
fn manifest_has_only_three_reviewed_internal_dependencies() {
    let dependency_tail = MANIFEST
        .split_once("[dependencies]\n")
        .expect("dependency section")
        .1;
    let lines: Vec<&str> = dependency_tail
        .lines()
        .filter(|line| !line.trim().is_empty())
        .collect();
    assert_eq!(
        lines,
        [
            "qk-a1 = { path = \"../qk-a1\" }",
            "qk-descriptor = { path = \"../qk-descriptor\" }",
            "qk-secp = { path = \"../qk-secp\" }",
        ]
    );
    assert!(!MANIFEST.contains("[dev-dependencies]"));
    assert!(!MANIFEST.contains("[build-dependencies]"));
    assert!(!MANIFEST.contains("git ="));
    assert!(!MANIFEST.contains("version = \"1"));
}
