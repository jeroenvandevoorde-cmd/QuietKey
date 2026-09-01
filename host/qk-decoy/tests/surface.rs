const CARGO: &str = include_str!("../Cargo.toml");
const LIB: &str = include_str!("../src/lib.rs");
const CALCULATOR: &str = include_str!("../src/calculator.rs");
const PROCESS: &str = include_str!("../src/process.rs");
const PROCESS_BIN: &str = include_str!("../src/bin/qk-decoy-host.rs");

#[test]
fn manifest_has_no_dependency() {
    let binary = "[[bin]]\nname = \"qk-decoy-host\"\npath = \"src/bin/qk-decoy-host.rs\"";
    assert_eq!(CARGO.matches(binary).count(), 1);
    let dependencies = CARGO
        .split_once("[dependencies]")
        .expect("dependency section")
        .1;
    assert!(dependencies.trim().is_empty());
}

#[test]
fn crate_root_has_an_explicit_closed_surface() {
    let public_lines: Vec<&str> = LIB
        .lines()
        .map(str::trim_start)
        .filter(|line| line.starts_with("pub "))
        .collect();
    assert_eq!(
        public_lines,
        [
            "pub use calculator::{",
            "pub use process::DecoyHostProcess;",
        ]
    );
    assert!(!LIB.contains("pub mod "));
}

#[test]
fn process_owner_adds_no_controller_device_or_wallet_protocol() {
    for forbidden in [
        "qk_ipc",
        "qk_wallet",
        "qk_card",
        "qk_secp",
        "Secret",
        "PrivateKey",
        "UnixStream",
        "std::fs",
        "Command::new",
        "getrandom",
        "rand::",
        "sha256",
        "hmac",
        "println!",
        "eprintln!",
        "dbg!",
        "unsafe {",
    ] {
        assert!(!PROCESS.contains(forbidden), "process token {forbidden}");
        assert!(!PROCESS_BIN.contains(forbidden), "binary token {forbidden}");
    }
    assert!(PROCESS.contains("std::thread::park();"));
}

#[test]
fn production_source_has_no_secret_os_ipc_crypto_or_logging_surface() {
    for forbidden in [
        "qk_ipc",
        "qk_wallet",
        "qk_card",
        "qk_secp",
        "Secret",
        "PrivateKey",
        "std::net",
        "UnixStream",
        "std::fs",
        "std::process",
        "Command::new",
        "getrandom",
        "rand::",
        "sha256",
        "hmac",
        "println!",
        "eprintln!",
        "dbg!",
        "unsafe {",
    ] {
        assert!(!LIB.contains(forbidden), "crate root token {forbidden}");
        assert!(
            !CALCULATOR.contains(forbidden),
            "calculator token {forbidden}"
        );
    }
    assert!(LIB.contains("#![forbid(unsafe_code)]"));
}

#[test]
fn calculator_has_no_memory_history_scientific_or_wallet_entry_api() {
    for forbidden in [
        "pub fn memory",
        "pub fn history",
        "pub fn repeat",
        "pub fn scientific",
        "pub fn wallet",
        "pub fn authorize",
        "pub fn enter_wallet",
        "pub fn gesture",
    ] {
        assert!(!CALCULATOR.contains(forbidden), "surface token {forbidden}");
    }
}
