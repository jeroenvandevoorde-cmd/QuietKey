//! Dependency, capability, unsafe, and public-surface locks.

const LIB: &str = include_str!("../src/lib.rs");
const SESSION: &str = include_str!("../src/session.rs");
const STREAM: &str = include_str!("../src/stream.rs");
const WIRE: &str = include_str!("../src/wire.rs");
const WIPE: &str = include_str!("../src/wipe.rs");
const CARGO: &str = include_str!("../Cargo.toml");
const HOST_SIM_CARGO: &str = include_str!("../../qk-host-sim/Cargo.toml");

#[test]
fn manifest_is_dependency_free_and_host_sim_does_not_depend_on_ipc() {
    let dependencies = CARGO
        .split_once("[dependencies]")
        .expect("dependency section")
        .1;
    assert!(dependencies.trim().is_empty());
    assert!(!HOST_SIM_CARGO.contains("qk-ipc"));
}

#[test]
fn crate_root_surface_is_explicit_and_has_no_public_module_escape() {
    let public_lines: Vec<&str> = LIB
        .lines()
        .map(str::trim_start)
        .filter(|line| line.starts_with("pub "))
        .collect();
    assert_eq!(
        public_lines,
        [
            "pub use session::{CoreEvent, CoreProtocol, IoEvent, IoProtocol, OutboundFrame};",
            "pub use stream::{IngestOutcome, ReceivedFrame, StreamDecoder};",
            "pub use wire::{encode_frame, parse_frame, Direction, FrameHeader, FrameRef, MessageKind};",
            "pub const MAGIC: [u8; 4] = *b\"QKIP\";",
            "pub const VERSION: u8 = 1;",
            "pub const HEADER_BYTES: usize = 32;",
            "pub const MAX_PAYLOAD_BYTES: usize = 2_097_152;",
            "pub const MAX_FRAME_BYTES: usize = HEADER_BYTES + MAX_PAYLOAD_BYTES;",
            "pub enum IpcError {",
        ]
    );
    assert!(!LIB.contains("pub mod "));
}

#[test]
fn production_sources_have_no_os_device_wallet_signer_or_logging_surface() {
    let sources = [LIB, SESSION, STREAM, WIRE, WIPE];
    for source in sources {
        for forbidden in [
            "std::net",
            "UnixStream",
            "UnixListener",
            "TcpStream",
            "UdpSocket",
            "recvmsg(",
            "sendmsg(",
            "std::fs",
            "File::",
            "OpenOptions",
            "Command::new",
            "std::process",
            "std::thread::",
            "SystemTime",
            "Instant::",
            "getrandom",
            "rand::",
            "SecretKey",
            "PrivateKey",
            "ecdsa_sign",
            "println!",
            "eprintln!",
            "dbg!",
        ] {
            assert!(!source.contains(forbidden), "forbidden token {forbidden}");
        }
    }
}

#[test]
fn unsafe_is_confined_to_the_two_volatile_wipe_functions() {
    assert_eq!(LIB.matches("unsafe").count(), 1);
    assert!(LIB.contains("#![deny(unsafe_code)]"));
    assert!(!SESSION.contains("unsafe"));
    assert!(!STREAM.contains("unsafe"));
    assert!(!WIRE.contains("unsafe"));
    assert_eq!(WIPE.matches("#[allow(unsafe_code)]").count(), 2);
    assert_eq!(WIPE.matches("unsafe {").count(), 2);
}

#[test]
fn payload_owner_does_not_clone_format_or_release_its_vector() {
    let owner = STREAM
        .split_once("pub struct ReceivedFrame {")
        .expect("received owner")
        .1
        .split_once("/// Pure, bounded decoder")
        .expect("owner end")
        .0;
    for forbidden in [
        "#[derive(",
        "impl Clone for ReceivedFrame",
        "impl Copy for ReceivedFrame",
        "impl Debug for ReceivedFrame",
        "impl Display for ReceivedFrame",
        "pub fn into_",
        "pub fn as_mut",
        "pub fn to_vec",
    ] {
        assert!(!owner.contains(forbidden), "owner surface {forbidden}");
    }
    assert!(owner.contains("pub fn payload(&self) -> &[u8]"));
}
