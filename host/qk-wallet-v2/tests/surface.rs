//! Exact public and secret-boundary surface for QK-DEC-132.

const LIB: &str = include_str!("../src/lib.rs");
const BIP39: &str = include_str!("../src/bip39.rs");
const BIP32: &str = include_str!("../src/bip32_private.rs");
const DESCRIPTOR: &str = include_str!("../src/descriptor.rs");
const HMAC_SHA512: &str = include_str!("../src/hmac_sha512.rs");
const SECRET: &str = include_str!("../src/secret.rs");
const SPEND: &str = include_str!("../src/spend_v2.rs");
const MANIFEST: &str = include_str!("../Cargo.toml");

#[test]
fn public_surface_is_only_errors_public_facts_and_purpose_bound_operations() {
    let public_lines: Vec<&str> = LIB
        .lines()
        .map(str::trim_start)
        .filter(|line| line.starts_with("pub "))
        .collect();
    assert_eq!(
        public_lines,
        [
            "pub use spend_v2::{",
            "pub enum WalletV2Error {",
            "pub struct WalletPublicV2 {",
            "pub const fn account_xpubs(&self) -> [[u8; 111]; 2] {",
            "pub const fn origin_fingerprints(&self) -> [[u8; 4]; 2] {",
            "pub const fn descriptors(&self) -> [[u8; 306]; 2] {",
            "pub const fn wallet_id(&self) -> [u8; 32] {",
            "pub const fn first_scripts(&self) -> [[u8; 34]; 2] {",
            "pub const fn first_addresses(&self) -> [[u8; 62]; 2] {",
            "pub fn derive_wallet_v2(",
            "pub fn rebind_wallet_v2(",
        ]
    );

    for forbidden in [
        "pub mod ",
        "pub fn mnemonic",
        "pub fn seed",
        "pub fn entropy",
        "pub fn scalar",
        "pub fn chain_code",
        "pub fn xprv",
        "pub fn secret",
        "pub fn sign_digest",
        "pub fn sign_arbitrary",
        "pub fn signer",
        "pub fn payload",
        "pub fn serialize",
        "pub fn format",
        "pub fn generate",
        "pub fn random",
    ] {
        assert!(
            !LIB.contains(forbidden),
            "forbidden public surface {forbidden}"
        );
    }
    for source in [BIP39, BIP32, DESCRIPTOR, HMAC_SHA512, SECRET] {
        assert!(!source.contains("pub fn "), "private helper operation");
        assert!(!source.contains("pub struct "), "private helper type");
        assert!(!source.contains("pub enum "), "private helper error");
    }
    assert!(SPEND.contains("pub fn sign_validated_kit_sweep_v3("));
    assert!(SPEND.contains("proof: ValidatedKitSweepV3,"));
    assert!(!SPEND.contains("proof: &ValidatedKitSweepV3,"));
    assert!(SPEND.contains("pub struct WalletSignedKitSweepV3 {"));
    assert!(SPEND.contains("proof: ValidatedKitSweepV3Parts,"));
    assert!(SPEND.contains("let proof = proof.into_parts();"));
    assert!(SPEND.contains("proof.contains_existing_signature(signature.der())"));
    assert!(SPEND.contains("pub fn into_execution_parts(self) -> (ValidatedKitSweepV3Parts, WalletKitSweepSignaturesV3) {"));
    for forbidden in [
        "pub fn digest",
        "pub fn scalar",
        "pub fn secret",
        "pub fn xprv",
        "pub fn signer",
        "FnOnce",
        "FnMut",
    ] {
        assert!(
            !SPEND.contains(forbidden),
            "forbidden spend surface {forbidden}"
        );
    }
}

#[test]
fn dependencies_and_fixed_profile_are_exact() {
    assert!(MANIFEST.contains("qk-descriptor = { path = \"../qk-descriptor\" }"));
    assert!(MANIFEST.contains("qk-psbt = { path = \"../qk-psbt\" }"));
    assert!(MANIFEST.contains("qk-secp = { path = \"../qk-secp\" }"));
    for forbidden in ["qk-a1 =", "crates.io", "git =", "version = \""] {
        if forbidden == "version = \"" {
            assert_eq!(
                MANIFEST.matches(forbidden).count(),
                1,
                "package version only"
            );
        } else {
            assert!(
                !MANIFEST.contains(forbidden),
                "forbidden dependency {forbidden}"
            );
        }
    }
    assert!(BIP39.contains(
        "const WORDLIST: &str = include_str!(\"../../qk-provisioning/src/english.txt\");"
    ));
    assert!(BIP39.contains("const PBKDF2_ROUNDS: usize = 2048;"));
    assert!(
        BIP32.contains("const PATH: [u32; 4] = [HARDENED + 48, HARDENED, HARDENED, HARDENED + 2];")
    );
    assert!(!BIP39.split("#[cfg(test)]").next().unwrap().contains("Vec"));
    assert!(!HMAC_SHA512
        .split("#[cfg(test)]")
        .next()
        .unwrap()
        .contains("Vec"));
}

#[test]
fn private_owners_and_unsafe_boundary_are_locked() {
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
    assert!(SECRET.contains("bytes: [u8; N],"));
    assert!(!SECRET.contains("Box<"));
    assert!(!SECRET.contains("Box::"));
    assert!(SECRET.contains("impl<const N: usize> Drop for Secret<N>"));
    assert_eq!(
        SECRET
            .matches("unsafe { ptr::write_volatile(byte, 0) }")
            .count(),
        1
    );
    assert_eq!(
        SECRET.matches("compiler_fence(Ordering::SeqCst)").count(),
        1
    );
    assert_eq!(SECRET.matches("unsafe {").count(), 1);
    assert!(LIB.contains("#![deny(unsafe_code)]"));

    for source in [LIB, BIP39, BIP32, DESCRIPTOR, HMAC_SHA512] {
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
        ] {
            assert!(!source.contains(forbidden), "forbidden token {forbidden}");
        }
    }
}
