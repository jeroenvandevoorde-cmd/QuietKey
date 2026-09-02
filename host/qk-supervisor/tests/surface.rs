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

#[test]
fn connector_credentials_are_platform_exact_and_checked_before_unlink() {
    for required in [
        "const SO_PEERCRED: c_int = 17;",
        "const LOCAL_PEERPID: c_int = 2;",
        "fn getpeereid(",
        "fn getpid() -> c_int;",
        "fn geteuid() -> u32;",
        "SocketPeerCredentialUnavailable",
        "SocketPeerCredentialMismatch",
        "process: getpid(),",
        "effective_user: geteuid(),",
        "fn connect_once_after_listen<F>(",
    ] {
        assert!(RUNTIME.contains(required), "missing peer lock {required}");
    }
    let connection = RUNTIME
        .split_once("fn connect_and_accept(")
        .expect("connection function")
        .1;
    let accepted = connection.find(".accept()").expect("single accept");
    let verified = connection
        .find("verify_supervisor_connector(&io)?;")
        .expect("credential verification");
    let unlinked = connection
        .find("fs::remove_file(&self.socket)")
        .expect("socket unlink");
    assert!(accepted < verified);
    assert!(verified < unlinked);
}

#[test]
fn every_child_receives_fresh_write_only_null_stderr_without_changing_other_grants() {
    assert_eq!(RUNTIME.matches("map_mock(false, 2)").count(), 3);
    assert!(RUNTIME.contains("options.read(readable).write(!readable);"));
    assert!(RUNTIME.contains("options.open(\"/dev/null\")"));
    assert!(
        RUNTIME.contains("map_mock(false, 2).map_err(|_| LauncherRuntimeError::DecoyGrantFailed)?")
    );
    assert!(
        RUNTIME.contains("map_mock(true, 3).map_err(|_| LauncherRuntimeError::DecoyGrantFailed)?")
    );
    assert!(
        RUNTIME.contains("map_mock(false, 4).map_err(|_| LauncherRuntimeError::DecoyGrantFailed)?")
    );
    for exact_map in [
        "map_descriptor(endpoint.as_raw_fd(), 0)?",
        "map_descriptor(endpoint.as_raw_fd(), 1)?",
        "map_mock(false, 3)?",
        "map_mock(true, 4)?",
        "map_mock(true, 5)?",
        "map_mock(false, 6)?",
        "map_mock(true, 3)?",
        "map_mock(false, 5)?",
    ] {
        assert!(
            RUNTIME.contains(exact_map),
            "missing descriptor map {exact_map}"
        );
    }
}

#[test]
fn normal_profile_and_inherited_device_surface_is_exact() {
    for required in [
        "pub enum LauncherProfile",
        "\"01\" => Ok(Self::SimpleRecovery)",
        "\"02\" => Ok(Self::Inheritance)",
        "\"03\" => Ok(Self::QuantumShelter)",
        "const FIRST_NORMAL_DESCRIPTOR: c_int = 7;",
        "const LAST_NORMAL_DESCRIPTOR: c_int = 14;",
        "InheritedDeviceUnavailable",
        "InheritedDeviceNotPipe",
        "InheritedDeviceDirectionMismatch",
        "InheritedDeviceAliased",
        "fcntl(descriptor, F_SETFD, FD_CLOEXEC)",
        "map_descriptor(normal.raw(7)?, 3)?",
        "map_descriptor(normal.raw(8)?, 4)?",
        "map_descriptor(normal.raw(9)?, 5)?",
        "map_descriptor(normal.raw(10)?, 6)?",
        "map_descriptor(normal.raw(11)?, 3)?",
        "map_descriptor(normal.raw(12)?, 4)?",
        "map_descriptor(normal.raw(13)?, 5)?",
        "map_descriptor(normal.raw(14)?, 6)?",
        "vec![mode.argument(), profile.argument()]",
        "drop(normal_descriptors);",
    ] {
        assert!(RUNTIME.contains(required), "missing Normal lock {required}");
    }
    assert!(LIB.contains("LauncherMode, LauncherProfile, LauncherRuntimeError"));
}
