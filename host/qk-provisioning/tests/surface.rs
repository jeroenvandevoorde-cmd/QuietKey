//! Frozen M26 public surface and HOST-only source restrictions.

const LIB: &str = include_str!("../src/lib.rs");
const BIP39: &str = include_str!("../src/bip39.rs");
const BIP32: &str = include_str!("../src/bip32_private.rs");
const BECH32: &str = include_str!("../src/bech32.rs");
const DESCRIPTOR: &str = include_str!("../src/descriptor_build.rs");
const DICE: &str = include_str!("../src/dice.rs");
const QKEC: &str = include_str!("../src/qkec.rs");
const SECRET: &str = include_str!("../src/secret.rs");
const SHA256: &str = include_str!("../src/sha256.rs");
const SHA512: &str = include_str!("../src/sha512.rs");
const HMAC_SHA256: &str = include_str!("../src/hmac_sha256.rs");
const HMAC_SHA512: &str = include_str!("../src/hmac_sha512.rs");
const HKDF_SHA256: &str = include_str!("../src/hkdf_sha256.rs");
const RIPEMD160: &str = include_str!("../src/ripemd160.rs");
const MANIFEST: &str = include_str!("../Cargo.toml");

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
    assert!(SECRET.contains("bytes: Box<[u8; N]>,"));
    assert!(SECRET.contains("pub(crate) fn take(bytes: &mut [u8; N]) -> Self"));
    assert!(SECRET.contains("pub(crate) fn wipe(bytes: &mut [u8])"));
    assert!(SECRET.contains("#[inline(never)]\npub(crate) fn wipe(bytes: &mut [u8])"));
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
    assert!(!SECRET.contains("black_box"));
    assert!(!LIB.contains("impl Clone for HostProvisioningRun"));
    assert!(!LIB.contains("impl Copy for HostProvisioningRun"));
    assert!(!LIB.contains("impl Debug for HostProvisioningRun"));
}

#[test]
fn secret_storage_and_successful_capsule_consumption_are_source_locked() {
    let take_start = SECRET
        .find("pub(crate) fn take(bytes: &mut [u8; N]) -> Self")
        .expect("take-and-wipe constructor");
    let take_body = &SECRET[take_start..];
    let stable_copy = take_body
        .find("owned.copy_from_slice(bytes)")
        .expect("copy into stable owner");
    let source_wipe = take_body.find("wipe(bytes)").expect("caller scratch wipe");
    assert!(stable_copy < source_wipe);
    assert!(SECRET.contains("wipe(self.bytes.as_mut())"));

    let encrypt_start = LIB
        .find("pub fn encrypt_a1(")
        .expect("one capsule operation");
    let encrypt_body = &LIB[encrypt_start..];
    let capsule = encrypt_body
        .find("let capsule = qk_a1::encrypt")
        .expect("capsule construction");
    let seed_drop = encrypt_body
        .find("drop(self.seed_a.take())")
        .expect("Seed-A consumed after encryption");
    let a2_drop = encrypt_body
        .find("drop(self.a2.take())")
        .expect("A2 consumed after encryption");
    let nonce_commit = encrypt_body
        .find("self.nonce = Some(*nonce)")
        .expect("nonce state committed");
    assert!(capsule < seed_drop && seed_drop < a2_drop && a2_drop < nonce_commit);
}

#[test]
fn production_sources_have_no_io_randomness_and_only_secret_unsafe_boundary() {
    for source in [
        LIB,
        BIP39,
        BIP32,
        BECH32,
        DESCRIPTOR,
        DICE,
        QKEC,
        SHA256,
        SHA512,
        HMAC_SHA256,
        HMAC_SHA512,
        HKDF_SHA256,
        RIPEMD160,
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
    assert_eq!(SECRET.matches("#![allow(unsafe_code)]").count(), 1);
    assert!(SECRET.contains("#![deny(unsafe_op_in_unsafe_fn)]"));
    let volatile_write = SECRET
        .find("unsafe { ptr::write_volatile(byte, 0) }")
        .expect("sole volatile byte write");
    let final_fence = SECRET
        .find("compiler_fence(Ordering::SeqCst)")
        .expect("post-write compiler fence");
    assert!(volatile_write < final_fence);
    for forbidden in [
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
        assert!(
            !SECRET.contains(forbidden),
            "forbidden secret-boundary token {forbidden}"
        );
    }
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
