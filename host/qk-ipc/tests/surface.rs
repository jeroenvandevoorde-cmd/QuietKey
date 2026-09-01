//! Dependency, capability, unsafe, and public-surface locks.

const LIB: &str = include_str!("../src/lib.rs");
const SESSION: &str = include_str!("../src/session.rs");
const STREAM: &str = include_str!("../src/stream.rs");
const UNIX_RECV: &str = include_str!("../src/unix_recv.rs");
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
    assert!(CARGO.contains("[features]\nfuzzing = []\nhost-runtime = []"));
    assert!(!CARGO.contains("default = [\"host-runtime\"]"));
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
            "pub use unix_recv::{",
            "pub use wipe::{reset_wiped_bytes, wiped_bytes};",
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

fn public_methods(source: &str) -> Vec<&str> {
    source
        .lines()
        .map(str::trim_start)
        .filter(|line| line.starts_with("pub fn ") || line.starts_with("pub const fn "))
        .collect()
}

#[test]
fn every_public_method_entry_is_pinned() {
    assert_eq!(
        public_methods(SESSION),
        [
            "pub const fn direction(&self) -> Direction {",
            "pub const fn kind(&self) -> MessageKind {",
            "pub const fn session_id(&self) -> &[u8; 16] {",
            "pub const fn exchange_id(&self) -> u32 {",
            "pub fn encode(&self, payload: &[u8], output: &mut [u8]) -> Result<usize, IpcError> {",
            "pub const fn new(session_id: [u8; 16]) -> Self {",
            "pub fn fuzz_exchange_exhaustion_probe(session_id: [u8; 16]) -> IpcError {",
            "pub fn begin(&mut self) -> Result<OutboundFrame, IpcError> {",
            "pub fn request(&mut self) -> Result<OutboundFrame, IpcError> {",
            "pub fn close(&mut self) -> Result<OutboundFrame, IpcError> {",
            "pub fn accept(&mut self, frame: &ReceivedFrame) -> Result<CoreEvent, IpcError> {",
            "pub fn peer_lost(&mut self) -> IpcError {",
            "pub fn receive_failed(&mut self, error: IpcError) -> IpcError {",
            "pub const fn is_closed(&self) -> bool {",
            "pub const fn is_terminated(&self) -> bool {",
            "pub const fn new() -> Self {",
            "pub fn accept(&mut self, frame: &ReceivedFrame) -> Result<IoEvent, IpcError> {",
            "pub fn reply(&mut self) -> Result<OutboundFrame, IpcError> {",
            "pub fn peer_lost(&mut self) -> IpcError {",
            "pub fn receive_failed(&mut self, error: IpcError) -> IpcError {",
            "pub const fn is_closed(&self) -> bool {",
            "pub const fn is_terminated(&self) -> bool {",
        ]
    );
    assert_eq!(
        public_methods(STREAM),
        [
            "pub const fn consumed(&self) -> usize {",
            "pub const fn frame_ready(&self) -> bool {",
            "pub const fn header(&self) -> &FrameHeader {",
            "pub fn payload(&self) -> &[u8] {",
            "pub fn new() -> Self {",
            "pub fn ingest(",
            "pub fn take_frame(&mut self) -> Result<ReceivedFrame, IpcError> {",
            "pub fn finish(&mut self) -> IpcError {",
        ]
    );
    assert_eq!(
        public_methods(WIRE),
        [
            "pub const fn wire_value(self) -> u8 {",
            "pub const fn wire_value(self) -> u16 {",
            "pub const fn direction(self) -> Direction {",
            "pub const fn requires_payload(self) -> bool {",
            "pub const fn direction(&self) -> Direction {",
            "pub const fn kind(&self) -> MessageKind {",
            "pub const fn session_id(&self) -> &[u8; 16] {",
            "pub const fn exchange_id(&self) -> u32 {",
            "pub const fn payload_len(&self) -> u32 {",
            "pub const fn header(&self) -> &FrameHeader {",
            "pub const fn payload(&self) -> &'a [u8] {",
            "pub fn parse_frame(bytes: &[u8]) -> Result<FrameRef<'_>, IpcError> {",
            "pub fn encode_frame(",
        ]
    );
    assert_eq!(
        public_methods(WIPE),
        [
            "pub fn reset_wiped_bytes() {",
            "pub fn wiped_bytes() -> usize {",
        ]
    );
    assert_eq!(
        public_methods(UNIX_RECV),
        [
            "pub fn inherited_endpoint() -> Result<UnixStream, UnixReceiveError> {",
            "pub const fn received(&self) -> usize {",
            "pub const fn consumed(&self) -> usize {",
            "pub const fn frame_ready(&self) -> bool {",
            "pub fn receive_once(",
            "pub fn receive_bytes_once(",
        ]
    );
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
fn unsafe_is_confined_to_the_host_runtime_and_two_volatile_wipe_functions() {
    assert_eq!(LIB.matches("unsafe").count(), 2);
    assert!(LIB.contains("#![deny(unsafe_code)]"));
    assert_eq!(LIB.matches("#[allow(unsafe_code)]").count(), 1);
    assert!(!SESSION.contains("unsafe"));
    assert!(!STREAM.contains("unsafe"));
    assert!(!WIRE.contains("unsafe"));
    assert_eq!(WIPE.matches("#[allow(unsafe_code)]").count(), 2);
    assert_eq!(WIPE.matches("unsafe {").count(), 2);
    assert_eq!(UNIX_RECV.matches("unsafe {").count(), 11);
}

#[test]
fn host_runtime_unsafe_surface_is_narrow_and_has_no_secret_or_process_operation() {
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

#[test]
fn inherited_endpoint_duplication_is_atomic_close_on_exec_and_above_standard_descriptors() {
    assert!(UNIX_RECV.contains("const F_DUPFD_CLOEXEC: c_int = 1030;"));
    assert!(UNIX_RECV.contains("const F_DUPFD_CLOEXEC: c_int = 67;"));
    assert!(UNIX_RECV.contains("const FIRST_NON_STANDARD_DESCRIPTOR: c_int = 3;"));
    assert!(UNIX_RECV.contains("fcntl(source, F_DUPFD_CLOEXEC, FIRST_NON_STANDARD_DESCRIPTOR)"));
    assert!(!UNIX_RECV.contains("fn dup("));
    assert!(!UNIX_RECV.contains("F_SETFD"));
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
