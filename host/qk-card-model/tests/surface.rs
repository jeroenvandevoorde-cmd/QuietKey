//! Exact crate-boundary and fixture-label checks.

const LIB: &str = include_str!("../src/lib.rs");
const MODEL: &str = include_str!("../src/model.rs");
const MANIFEST: &str = include_str!("../Cargo.toml");
const CORE_MANIFEST: &str = include_str!("../../qk-core/Cargo.toml");
const DEVICE_WIRE_MANIFEST: &str = include_str!("../../qk-device-wire/Cargo.toml");
const FIXTURE: &str = include_str!("../../qk-card-protocol/tests/fixtures/card_protocol_v1.txt");

#[test]
fn crate_is_test_only_path_dependency_code() {
    assert!(LIB.contains("Test-only HOST model"));
    assert!(FIXTURE.contains("PERMANENTLY NEVER-FUND PUBLIC PRIVATE MATERIAL"));
    assert!(MANIFEST.contains("qk-card-protocol = { path = \"../qk-card-protocol\" }"));
    assert!(MANIFEST.contains(
        "qk-secp = { path = \"../qk-secp\", features = [\"card-signature-normalization\"] }"
    ));
    assert!(!MANIFEST.contains("crates.io"));
    for forbidden in ["rand", "getrandom", "serde", "tokio", "reqwest"] {
        assert!(
            !MANIFEST.contains(forbidden),
            "forbidden dependency: {forbidden}"
        );
    }
}

#[test]
fn secret_owners_have_no_debug_clone_or_raw_secret_getter() {
    for forbidden in [
        "derive(Debug, Clone, Copy)\npub struct CardModel",
        "derive(Debug, Clone, Copy)\npub struct SignReply",
        "pub fn public_test_record",
        "PUBLIC_TEST_ACCOUNT_SEED",
        "pub fn account_xprv",
        "pub fn secret",
        "pub fn scalar",
    ] {
        assert!(!MODEL.contains(forbidden), "forbidden surface: {forbidden}");
    }
    assert!(MODEL.contains("impl Drop for SignReply"));
    assert!(MODEL.contains("impl Drop for Session"));
}

#[test]
fn model_has_no_device_network_clock_or_generic_secret_surface() {
    for forbidden in [
        "std::fs",
        "std::net",
        "std::time",
        "std::process",
        "transmit",
        "connect(",
        "pub fn read_memory",
        "pub fn wipe_card",
        "pub fn reset_card",
        "pub fn retire",
    ] {
        assert!(
            !LIB.contains(forbidden),
            "forbidden library surface: {forbidden}"
        );
        assert!(
            !MODEL.contains(forbidden),
            "forbidden model surface: {forbidden}"
        );
    }
    assert!(MODEL.contains("pub fn process_apdu"));
    assert!(MODEL.contains("pub fn emit_high_s_once"));
}

#[test]
fn model_is_absent_from_the_product_card_closures() {
    for (name, manifest) in [
        ("qk-core", CORE_MANIFEST),
        ("qk-device-wire", DEVICE_WIRE_MANIFEST),
    ] {
        assert!(
            !manifest.contains("qk-card-model"),
            "test-only model entered {name}"
        );
    }
}
