//! Dependency, public-surface, and capability locks.

const LIB: &str = include_str!("../src/lib.rs");
const LIFECYCLE: &str = include_str!("../src/lifecycle.rs");
const UNIX_RECV: &str = include_str!("../src/unix_recv.rs");
const CARGO: &str = include_str!("../Cargo.toml");

#[test]
fn manifest_depends_only_on_the_pure_ipc_leaf() {
    let dependencies = CARGO
        .split_once("[dependencies]")
        .expect("dependency section")
        .1;
    assert_eq!(dependencies.trim(), "qk-ipc = { path = \"../qk-ipc\" }");
    assert!(!CARGO.contains("qk-decoy"));
}

#[test]
fn crate_root_has_one_explicit_surface_and_one_unsafe_module() {
    assert!(LIB.contains("#![deny(unsafe_code)]"));
    assert_eq!(LIB.matches("#[allow(unsafe_code)]").count(), 1);
    assert!(LIB.contains("mod unix_recv;"));
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
fn unsafe_is_confined_to_recv_close_control_parse_and_wipe() {
    assert!(!LIFECYCLE.contains("unsafe"));
    assert_eq!(UNIX_RECV.matches("unsafe {").count(), 5);
    for forbidden in [
        "sendmsg(",
        "Command::new",
        "std::process",
        "rand::",
        "getrandom",
        "Secret",
        "PrivateKey",
        "println!",
        "eprintln!",
        "dbg!",
    ] {
        assert!(
            !UNIX_RECV.contains(forbidden),
            "forbidden token {forbidden}"
        );
    }
}
