//! Frozen M26 residue plus the exact v2 slice-4 and slice-8 surfaces.

const LIB: &str = include_str!("../src/lib.rs");
const BIP39: &str = include_str!("../src/bip39.rs");
const BIP32: &str = include_str!("../src/bip32_private.rs");
const BECH32: &str = include_str!("../src/bech32.rs");
const DESCRIPTOR: &str = include_str!("../src/descriptor_build.rs");
const DESCRIPTOR_V2: &str = include_str!("../src/descriptor_build_v2.rs");
const DICE: &str = include_str!("../src/dice.rs");
const KIT_R: &str = include_str!("../src/kit_r.rs");
const KIT_SETUP: &str = include_str!("../src/kit_setup_v2.rs");
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
            "pub use kit_setup_v2::{",
            "pub enum ProvisioningError {",
            "pub struct ProvisioningArtifacts {",
            "pub account_xpubs: [[u8; 111]; 3],",
            "pub descriptors: [[u8; 445]; 2],",
            "pub wallet_id: [u8; 32],",
            "pub first_scripts: [[u8; 34]; 2],",
            "pub first_addresses: [[u8; 62]; 2],",
            "pub a1_capsule: [u8; 67],",
            "pub struct ProvisioningArtifactsV2 {",
            "pub account_xpubs: [[u8; 111]; 2],",
            "pub descriptors: [[u8; 306]; 2],",
            "pub wallet_id: [u8; 32],",
            "pub first_scripts: [[u8; 34]; 2],",
            "pub first_addresses: [[u8; 62]; 2],",
            "pub a1_capsule: [u8; 67],",
            "pub struct HostProvisioningRun {",
            "pub fn from_qkec(",
            "pub fn from_dice(transcripts: [&[u8]; 4]) -> Result<Self, ProvisioningError> {",
            "pub fn encrypt_a1(",
            "pub struct HostProvisioningRunV2 {",
            "pub fn from_manual_dice(transcripts: [&[u8]; 4]) -> Result<Self, ProvisioningError> {",
            "pub fn encrypt_a1(",
        ]
    );
    for source in [
        BIP39,
        BIP32,
        BECH32,
        DESCRIPTOR,
        DESCRIPTOR_V2,
        DICE,
        KIT_R,
        QKEC,
        SECRET,
    ] {
        assert!(!source.contains("pub fn "), "private helper operation");
        assert!(!source.contains("pub struct "), "private helper type");
        assert!(!source.contains("pub enum "), "private helper error");
    }
    for forbidden in [
        "pub mod ",
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
    let kit_public_lines: Vec<&str> = KIT_SETUP
        .lines()
        .map(str::trim_start)
        .filter(|line| line.starts_with("pub "))
        .collect();
    assert_eq!(
        kit_public_lines,
        [
            "pub enum KitCopyV2 {",
            "pub enum KitShareIndexV2 {",
            "pub enum KitPageDispositionV2 {",
            "pub struct KitPrintPageV2<'page> {",
            "pub const fn copy(&self) -> KitCopyV2 {",
            "pub const fn share_index(&self) -> KitShareIndexV2 {",
            "pub const fn wallet_id(&self) -> &[u8; 32] {",
            "pub const fn qr_metadata(&self) -> QrMetadata {",
            "pub fn fallback_line(&self, line: usize) -> Option<&[u8; FALLBACK_LINE_SYMBOLS]> {",
            "pub const fn qr_packed(&self) -> &[u8; QR_PACKED_BYTES] {",
            "pub struct KitSetupReceiptV2 {",
            "pub const fn wallet_id(&self) -> [u8; 32] {",
            "pub const fn copy_count(&self) -> u8 {",
            "pub const fn page_count(&self) -> u8 {",
            "pub fn emit_two_kit_copies<F>(self, mut sink: F) -> Result<KitSetupReceiptV2, ProvisioningError>",
        ]
    );
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
    assert!(!LIB.contains("impl Clone for HostProvisioningRunV2"));
    assert!(!LIB.contains("impl Copy for HostProvisioningRunV2"));
    assert!(!LIB.contains("impl Debug for HostProvisioningRunV2"));
    assert!(!LIB.contains("impl Display for HostProvisioningRunV2"));
    assert!(!LIB.contains("impl PartialEq for HostProvisioningRunV2"));
    for forbidden in [
        "impl Clone for KitPrintPageV2",
        "impl Copy for KitPrintPageV2",
        "impl Debug for KitPrintPageV2",
        "impl Display for KitPrintPageV2",
        "impl PartialEq for KitPrintPageV2",
        "pub fn frame",
        "pub fn share",
        "pub fn payload",
        "pub fn pad",
        "pub fn regenerate",
        "pub fn retry",
    ] {
        assert!(
            !KIT_SETUP.contains(forbidden),
            "forbidden Kit setup surface {forbidden}"
        );
    }
    for required in [
        "const PAGE_BUFFER_BYTES: usize = FRAME_LEN + FALLBACK_SYMBOLS + QR_PACKED_BYTES;",
        "const _: () = assert!(PAGE_BUFFER_BYTES == 899);",
        "(KitCopyV2::One, KitShareIndexV2::One),",
        "(KitCopyV2::One, KitShareIndexV2::Two),",
        "(KitCopyV2::Two, KitShareIndexV2::One),",
        "(KitCopyV2::Two, KitShareIndexV2::Two),",
        "buffers.wipe_all();",
        "let share_two = Secret::take(&mut share_two_scratch);",
    ] {
        assert!(
            KIT_SETUP.contains(required),
            "missing setup lock {required}"
        );
    }

    let v2_start = LIB
        .find("pub struct HostProvisioningRunV2")
        .expect("v2 private owner");
    let v2 = &LIB[v2_start..];
    assert!(v2.contains("payload: Secret<96>,"));
    assert!(v2.contains("kit_r_pad: Secret<96>,"));
    assert!(!v2.contains("Signer-C"));
    assert!(!v2.contains("signer_c"));
    for forbidden in [
        "pub payload:",
        "pub kit_r_pad:",
        "pub fn payload",
        "pub fn kit_r_pad",
        "pub fn secret",
        "pub fn entropy",
        "pub fn regenerate",
        "pub fn share",
    ] {
        assert!(
            !v2.contains(forbidden),
            "forbidden v2 secret surface {forbidden}"
        );
    }

    for required in [
        "const SALT_PREFIX: &[u8; 15] = b\"QuietKey/QKEC-1\";",
        "const PURPOSE: &[u8; 5] = b\"Kit-R\";",
        "const INFO_PREFIX: &[u8; 21] = b\"QuietKey/Kit-R/pad/v1\";",
        "const CEREMONY_ID_BYTES: usize = 16;",
        "const PAD_BYTES: usize = 96;",
    ] {
        assert!(
            KIT_R.contains(required),
            "missing Kit-R constant {required}"
        );
    }
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

    let v2_start = LIB
        .find("pub struct HostProvisioningRunV2")
        .expect("v2 owner");
    let v2 = &LIB[v2_start..];
    let encrypt_start = v2.find("pub fn encrypt_a1(").expect("v2 capsule operation");
    let encrypt = &v2[encrypt_start..];
    let capsule = encrypt
        .find("let capsule = qk_a1::encrypt")
        .expect("v2 capsule construction");
    let nonce_commit = encrypt
        .find("self.nonce = Some(*nonce)")
        .expect("v2 nonce state committed");
    assert!(capsule < nonce_commit);
    assert!(!encrypt[..nonce_commit].contains("self.payload.take"));
    assert!(!encrypt[..nonce_commit].contains("self.kit_r_pad.take"));
    let drop_start = v2
        .find("impl Drop for HostProvisioningRunV2")
        .expect("explicit v2 owner drop");
    let drop_body = &v2[drop_start..];
    assert!(drop_body.contains("secret::wipe(self.payload.as_mut_bytes())"));
    assert!(drop_body.contains("secret::wipe(self.kit_r_pad.as_mut_bytes())"));
    assert!(KIT_R.contains("pub(crate) fn assert_reference("));
    assert!(LIB.contains("kit_r::assert_reference("));
}

#[test]
fn production_sources_have_no_io_randomness_and_only_secret_unsafe_boundary() {
    for source in [
        LIB,
        BIP39,
        BIP32,
        BECH32,
        DESCRIPTOR,
        DESCRIPTOR_V2,
        DICE,
        KIT_R,
        KIT_SETUP,
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
fn manifest_has_only_four_reviewed_internal_dependencies() {
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
            "qk-kit = { path = \"../qk-kit\" }",
            "qk-secp = { path = \"../qk-secp\" }",
        ]
    );
    assert!(!MANIFEST.contains("[dev-dependencies]"));
    assert!(!MANIFEST.contains("[build-dependencies]"));
    assert!(!MANIFEST.contains("git ="));
    assert!(!MANIFEST.contains("version = \"1"));
}
