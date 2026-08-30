//! Default-build API, production capability, and dependency surface locks.

const LIB: &str = include_str!("../src/lib.rs");
const DER: &str = include_str!("../src/der.rs");
const HOST_MOCK: &str = include_str!("../src/host_mock.rs");
const MANIFEST_SOURCE: &str = include_str!("../src/manifest.rs");
const PACKAGE: &str = include_str!("../src/package.rs");
const SHA256: &str = include_str!("../src/sha256.rs");
const STAGING: &str = include_str!("../src/staging.rs");
const TRUST: &str = include_str!("../src/trust.rs");
const WIPE: &str = include_str!("../src/wipe.rs");
const CARGO_MANIFEST: &str = include_str!("../Cargo.toml");

fn production_prefix(source: &str) -> &str {
    source.split("\n#[cfg(test)]\n").next().unwrap_or(source)
}

#[test]
fn crate_root_public_surface_is_exact() {
    let public_lines: Vec<&str> = LIB
        .lines()
        .map(str::trim_start)
        .filter(|line| line.starts_with("pub "))
        .collect();
    assert_eq!(
        public_lines,
        [
            "pub use host_mock::{",
            "pub use manifest::{ArtifactFact, ArtifactKind, ManifestFacts, ReleaseVersion};",
            "pub use package::verify_staged_fixture_package;",
            "pub use package::{verify_staged_package, VerifiedPackage};",
            "pub use staging::{",
            "pub use trust::CompiledTrust;",
            "pub const MANIFEST_BYTES: usize = 328;",
            "pub const ARTIFACT_RECORD_BYTES: usize = 37;",
            "pub const ARTIFACT_COUNT: usize = 6;",
            "pub const MAX_FIRMWARE_IMAGE_BYTES: usize = 268_435_456;",
            "pub const MAX_DETACHED_ARTIFACT_BYTES: u32 = 1_073_741_824;",
            "pub const MAX_PACKAGE_ENVELOPE_BYTES: usize = 482;",
            "pub const MAX_PACKAGE_BYTES: usize = MAX_FIRMWARE_IMAGE_BYTES + MAX_PACKAGE_ENVELOPE_BYTES;",
            "pub const MIN_PACKAGE_BYTES: usize = 4 + 1 + 2 + 328 + 1 + 2 * (1 + 1 + 8) + 1;",
            "pub const MANIFEST_MAGIC: [u8; 4] = *b\"QKFM\";",
            "pub const MANIFEST_SCHEMA: u8 = 1;",
            "pub const TARGET_PLATFORM: [u8; 4] = *b\"QKT1\";",
            "pub const COMPATIBILITY_EPOCH: u32 = 1;",
            "pub const PACKAGE_MAGIC: [u8; 4] = *b\"QKUP\";",
            "pub const PACKAGE_VERSION: u8 = 1;",
            "pub const UPDATE_FILE_NAME: &str = \"quietkey-update.qkup\";",
            "pub const SIGNATURE_DOMAIN: &[u8; 27] = b\"QuietKey/FirmwarePackage/v1\";",
            "pub const KEYSET_DOMAIN: &[u8; 26] = b\"QuietKey/FirmwareKeySet/v1\";",
            "pub const FINGERPRINT_DOMAIN: &[u8; 37] = b\"QuietKey/FirmwareAnchorFingerprint/v1\";",
            "pub const MAX_LOW_S_DER_BYTES: usize = 71;",
            "pub const MIN_DER_BYTES: usize = 8;",
            "pub const SECP256K1_HALF_ORDER: [u8; 32] = [",
            "pub const REGISTERED_TEST_ANCHORS: [[u8; 33]; 3] = [",
            "pub const REGISTERED_TEST_FINGERPRINTS: [[u8; 32]; 3] = [",
            "pub const REGISTERED_TEST_KEYSET_ID: [u8; 32] = [",
            "pub enum UpdateError {",
        ],
        "complete crate-root public item surface"
    );
    assert!(!LIB.contains("pub mod "));
}

#[test]
fn ordinary_build_cannot_select_fixture_trust() {
    assert!(LIB.contains(
        "#[cfg(any(test, feature = \"fuzzing\"))]\n#[doc(hidden)]\npub use package::verify_staged_fixture_package;"
    ));
    assert!(PACKAGE.contains("#[cfg(any(test, feature = \"fuzzing\"))]\n    Fixture,"));
    assert!(PACKAGE.contains(
        "#[cfg(any(test, feature = \"fuzzing\"))]\n#[doc(hidden)]\npub fn verify_staged_fixture_package("
    ));
    assert!(TRUST.contains("#[cfg(any(test, feature = \"fuzzing\"))]\n    pub fn fixture("));

    let production_entry = PACKAGE
        .split_once("pub fn verify_staged_package(")
        .expect("production entry")
        .1
        .split_once("/// Test/fuzz-only fixture-anchor")
        .expect("production entry end")
        .0;
    assert!(production_entry.contains("TrustPolicy::Production,"));
    assert!(production_entry.contains("COMPILED_ANCHORS,"));
    assert!(!production_entry.contains("compiled_anchors:"));
    assert!(!production_entry.contains("TrustPolicy::Fixture,"));
    assert!(TRUST.contains("if trust.contains_registered_test_material() {"));
    assert!(TRUST.contains("return Err(UpdateError::TestAnchorInProduction);"));
}

#[test]
fn public_fact_objects_do_not_admit_unparsed_construction_or_mutation() {
    for forbidden in [
        "pub version:",
        "pub source_commit:",
        "pub signing_keyset_id:",
        "pub target_keyset_id:",
        "pub artifacts:",
        "pub kind:",
        "pub byte_length:",
        "pub sha256:",
        "pub fn set_",
        "pub fn parse(",
        "pub fn from_bytes(",
        "pub fn serialize(",
    ] {
        assert!(
            !MANIFEST_SOURCE.contains(forbidden),
            "manifest fact surface: {forbidden}"
        );
    }
    assert!(MANIFEST_SOURCE.contains("pub(crate) fn parse(bytes: &[u8])"));
    assert!(MANIFEST_SOURCE
        .contains("pub const fn artifacts(&self) -> &[ArtifactFact; ARTIFACT_COUNT]"));
    assert!(MANIFEST_SOURCE.contains("pub const fn firmware_image(&self) -> &ArtifactFact"));
}

#[test]
fn production_sources_have_no_signer_secret_real_media_network_or_anchor_acceptance() {
    let sources = [
        production_prefix(LIB),
        production_prefix(DER),
        production_prefix(HOST_MOCK),
        production_prefix(MANIFEST_SOURCE),
        production_prefix(PACKAGE),
        production_prefix(SHA256),
        production_prefix(STAGING),
        production_prefix(TRUST),
        production_prefix(WIPE),
    ];
    for source in sources {
        for forbidden in [
            "SecretKey",
            "PrivateKey",
            "secret_key",
            "private_key",
            "ecdsa_sign",
            "sign_recoverable",
            "sign_digest",
            "fn sign(",
            "getrandom",
            "OsRng",
            "rand::",
            "thread_rng",
            "SystemTime",
            "std::fs",
            "File::",
            "OpenOptions",
            "std::io",
            "std::net",
            "TcpStream",
            "UdpSocket",
            "reqwest",
            "ureq",
            "Command::new",
            "std::process",
            "bitcoin::",
            "bitcoincore_rpc",
            "OP_RETURN",
            "println!",
            "eprintln!",
            "dbg!",
        ] {
            assert!(!source.contains(forbidden), "forbidden token {forbidden}");
        }
    }

    let combined = sources.join("\n");
    assert_eq!(combined.matches("qk_secp::ecdsa_verify").count(), 1);
    assert_eq!(combined.matches("qk_secp::signature_parse_der").count(), 1);
    assert_eq!(
        combined.matches("qk_secp::pubkey_parse_compressed").count(),
        3
    );
    assert!(!combined.contains("qk_secp::secret"));
    assert!(!combined.contains("qk_secp::ecdsa_sign"));
}

#[test]
fn public_operations_are_verification_facts_or_explicit_host_mocks_only() {
    for required in [
        "pub fn stage_from_media(",
        "pub fn verify_staged_package(",
        "pub fn production(anchor_bytes: [[u8; 33]; 3])",
        "pub fn prepare_trial(",
        "pub fn attempt_first_boot(",
        "pub fn commit_confirmed_boot(",
        "pub fn fallback_to_committed(",
    ] {
        assert!(
            [STAGING, PACKAGE, TRUST, HOST_MOCK]
                .iter()
                .any(|source| source.contains(required)),
            "required bounded operation: {required}"
        );
    }

    let public_operations: Vec<&str> = [STAGING, PACKAGE, TRUST, HOST_MOCK, MANIFEST_SOURCE]
        .iter()
        .flat_map(|source| source.lines())
        .map(str::trim_start)
        .filter(|line| line.starts_with("pub fn ") || line.starts_with("pub const fn "))
        .collect();
    for line in public_operations {
        for forbidden in [
            "secret",
            "private_key",
            "sign_digest",
            "fn sign(",
            "random",
            "network",
            "socket",
            "filesystem",
            "package_bytes",
            "image_bytes",
            "into_bytes",
        ] {
            assert!(
                !line.to_ascii_lowercase().contains(forbidden),
                "forbidden public operation {line}"
            );
        }
    }
    assert!(STAGING.contains("pub struct MockReadOnlyMedia"));
    assert!(HOST_MOCK.contains("pub struct MockPrivilegedInstaller"));
    assert!(!LIB.contains("RealMedia"));
    assert!(!LIB.contains("PrivilegedInstaller;"));
}

#[test]
fn dependency_and_feature_surface_is_exact() {
    assert!(CARGO_MANIFEST.contains("[features]\nfuzzing = []\n"));
    assert!(!CARGO_MANIFEST.contains("default ="));
    let dependency_tail = CARGO_MANIFEST
        .split_once("[dependencies]\n")
        .expect("dependency section")
        .1;
    assert_eq!(
        dependency_tail.trim(),
        "qk-secp = { path = \"../qk-secp\" }"
    );
    assert!(!CARGO_MANIFEST.contains("[dev-dependencies]"));
    assert!(!CARGO_MANIFEST.contains("[build-dependencies]"));
    assert!(!CARGO_MANIFEST.contains("build ="));
    assert!(!dependency_tail.contains("version ="));
    assert!(!dependency_tail.contains("git ="));
    assert!(!dependency_tail.contains("registry ="));
}
