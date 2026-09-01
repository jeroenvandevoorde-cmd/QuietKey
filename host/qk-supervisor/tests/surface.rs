//! Dependency, public-surface, and capability locks.

const LIB: &str = include_str!("../src/lib.rs");
const LIFECYCLE: &str = include_str!("../src/lifecycle.rs");
const RUNTIME: &str = include_str!("../src/runtime.rs");
const CARGO: &str = include_str!("../Cargo.toml");

#[test]
fn manifest_depends_only_on_the_pure_ipc_leaf() {
    let dependencies = CARGO
        .split_once("[dependencies]")
        .expect("dependency section")
        .1;
    assert_eq!(dependencies.trim(), "qk-ipc = { path = \"../qk-ipc\" }");
    assert!(CARGO.contains("default = []"));
    assert!(CARGO.contains("host-runtime = [\"qk-ipc/host-runtime\"]"));
    assert!(!CARGO.contains("qk-decoy"));
}

#[test]
fn crate_root_has_one_explicit_surface_and_one_feature_gated_unsafe_module() {
    assert!(LIB.contains("#![deny(unsafe_code)]"));
    assert_eq!(LIB.matches("#[allow(unsafe_code)]").count(), 1);
    assert!(!LIB.contains("mod unix_recv;"));
    assert!(LIB.contains("#[cfg(feature = \"host-runtime\")]\n#[allow(unsafe_code)]\nmod runtime;"));
    assert!(LIB.contains("pub use qk_ipc::{"));
    assert!(!LIB.contains("pub mod "));
}

#[test]
fn lifecycle_has_no_process_device_secret_or_logging_operation() {
    for forbidden in [
        "Command::new",
        "std::process",
        "UnixStream",
        "UnixListener",
        "std::fs",
        "Secret",
        "PrivateKey",
        "wallet_id",
        "println!",
        "eprintln!",
        "dbg!",
    ] {
        assert!(
            !LIFECYCLE.contains(forbidden),
            "forbidden token {forbidden}"
        );
    }
}

#[test]
fn supervisor_sources_are_entirely_safe() {
    assert!(!LIFECYCLE.contains("unsafe"));
    assert_eq!(LIB.matches("unsafe").count(), 2);
    assert!(!RUNTIME.contains("Secret"));
    assert!(!RUNTIME.contains("PrivateKey"));
    assert!(!RUNTIME.contains("println!"));
    assert!(!RUNTIME.contains("eprintln!"));
    assert!(!RUNTIME.contains("dbg!"));
}
