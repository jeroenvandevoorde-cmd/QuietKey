const LIB: &str = include_str!("../src/lib.rs");
const ALLOWLIST: &str = include_str!("../src/allowlist.rs");
const TRACE: &str = include_str!("../src/trace.rs");
const MAIN: &str = include_str!("../src/main.rs");
const MANIFEST: &str = include_str!("../Cargo.toml");

#[test]
fn crate_has_no_dependency_or_build_surface() {
    let dependency_tail = MANIFEST.split_once("[dependencies]\n").unwrap().1;
    assert!(dependency_tail.trim().is_empty());
    assert!(!MANIFEST.contains("[dev-dependencies]"));
    assert!(!MANIFEST.contains("[build-dependencies]"));
    assert!(!MANIFEST.contains("build ="));
    assert!(!MANIFEST.contains("git ="));
    assert!(!MANIFEST.contains("path ="));
}

#[test]
fn library_has_no_device_network_crypto_or_secret_api() {
    for forbidden in [
        "pcsc",
        "PCSC",
        "std::net",
        "TcpStream",
        "UdpSocket",
        "Command::new",
        "std::fs",
        "OpenOptions",
        "secp256k1",
        "private_key",
        "secret_key",
        "xprv",
        "PROVISION",
        "SIGN",
        "LOAD",
        "DELETE",
    ] {
        assert!(!LIB.contains(forbidden), "library surface: {forbidden}");
    }
}

#[test]
fn live_allowlist_is_literally_empty() {
    assert!(ALLOWLIST.contains("const LIVE_APDU_ALLOWLIST: [&[u8]; 0] = [];"));
    assert!(!ALLOWLIST.contains("vec!"));
}

#[test]
fn no_hash_implementation_or_implicit_limit_default_exists() {
    for source in [LIB, TRACE, MAIN] {
        for forbidden in [
            "sha2::",
            "Sha256",
            "fn sha256",
            "impl Default for TraceLimits",
            "TraceLimits::default",
            "MAX_ATR_BYTES",
            "MAX_PROTOCOL_BYTES",
            "MAX_IDENTIFIER_BYTES",
        ] {
            assert!(!source.contains(forbidden), "forbidden surface {forbidden}");
        }
    }
    assert!(TRACE.contains("pub fn new("));
    assert!(MAIN.contains(
        "<max-trace-bytes> <max-records> <max-record-bytes> <max-identifier-bytes> <max-atr-bytes>"
    ));
}
