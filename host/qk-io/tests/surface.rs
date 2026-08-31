//! Dependency, capability, unsafe, owner, and public-surface locks.

const CARGO: &str = include_str!("../Cargo.toml");
const LIB: &str = include_str!("../src/lib.rs");
const INNER: &str = include_str!("../src/inner.rs");
const INGRESS: &str = include_str!("../src/ingress.rs");
const EGRESS: &str = include_str!("../src/egress.rs");
const SESSION: &str = include_str!("../src/session.rs");
const MOCK: &str = include_str!("../src/mock.rs");
const WIPE: &str = include_str!("../src/wipe.rs");
const HOST_SIM_CARGO: &str = include_str!("../../qk-host-sim/Cargo.toml");
const SUPERVISOR_CARGO: &str = include_str!("../../qk-supervisor/Cargo.toml");

#[test]
fn manifest_depends_only_on_the_two_approved_transport_leaves() {
    let dependencies = CARGO
        .split_once("[dependencies]")
        .expect("dependency section")
        .1;
    assert_eq!(
        dependencies.trim(),
        "qk-bbqr = { path = \"../qk-bbqr\" }\nqk-ipc = { path = \"../qk-ipc\" }"
    );
    for forbidden in [
        "qk-a1",
        "qk-bip32",
        "qk-card-trace",
        "qk-decoy",
        "qk-descriptor",
        "qk-host-model",
        "qk-host-sim",
        "qk-kit",
        "qk-provisioning",
        "qk-psbt",
        "qk-secp",
        "qk-supervisor",
        "qk-update",
        "qk-wallet-v2",
    ] {
        assert!(!dependencies.contains(forbidden), "dependency {forbidden}");
    }
    assert!(!HOST_SIM_CARGO.contains("qk-io"));
    assert!(!SUPERVISOR_CARGO.contains("qk-io"));
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
            "pub use inner::{parse_request, Artifact, Operation, Request, Sink, Source};",
            "pub use mock::{MockInput, MockOutputWriter, OutputFault};",
            "pub use session::{BrokerError, BrokerReply, BrokerSession, BrokerState, ReplyStatus};",
            "pub use wipe::{reset_wiped_bytes, wiped_bytes};",
            "pub const INNER_VERSION: u8 = 1;",
            "pub const INNER_HEADER_BYTES: usize = 8;",
            "pub const MAX_TRANSFER_BYTES: usize = 2_097_152;",
            "pub const MAX_CHUNK_BYTES: usize = 262_144;",
            "pub const MAX_FILENAME_BYTES: usize = 64;",
            "pub const MAX_MOCK_INPUT_BYTES: usize = MAX_TRANSFER_BYTES + MAX_FILENAME_BYTES + 5;",
            "pub const A1_CANDIDATE_BYTES: usize = 67;",
            "pub const KIT_CANDIDATE_BYTES: usize = 142;",
            "pub const MAX_INNER_BODY_BYTES: usize = qk_ipc::MAX_PAYLOAD_BYTES - INNER_HEADER_BYTES;",
            "pub enum InnerError {",
            "pub const fn status_code(self) -> u16 {",
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
        public_methods(INNER),
        [
            "pub const fn wire_value(self) -> u8 {",
            "pub const fn wire_value(self) -> u8 {",
            "pub const fn wire_value(self) -> u8 {",
            "pub const fn wire_value(self) -> u8 {",
            "pub const fn operation(&self) -> Operation {",
            "pub fn parse_request(bytes: &[u8]) -> Result<Request<'_>, InnerError> {",
        ]
    );
    assert_eq!(
        public_methods(MOCK),
        [
            "pub fn try_new(source: Source, bytes: &[u8]) -> Result<Self, InnerError> {",
            "pub const fn failing(source: Source) -> Self {",
            "pub const fn is_used(&self) -> bool {",
            "pub const fn new(sink: Sink) -> Self {",
            "pub const fn with_fault(sink: Sink, fault: OutputFault) -> Self {",
            "pub const fn is_used(&self) -> bool {",
            "pub fn temporary_bytes(&self) -> Option<&[u8]> {",
            "pub fn final_bytes(&self) -> Option<&[u8]> {",
            "pub fn final_name(&self) -> Option<&[u8]> {",
        ]
    );
    assert_eq!(
        public_methods(SESSION),
        [
            "pub const fn status(&self) -> ReplyStatus {",
            "pub fn frame_bytes(&self) -> &[u8] {",
            "pub fn len(&self) -> usize {",
            "pub fn is_empty(&self) -> bool {",
            "pub const fn new() -> Self {",
            "pub const fn state(&self) -> BrokerState {",
            "pub fn accept(",
            "pub fn peer_lost(&mut self) -> BrokerError {",
        ]
    );
    assert!(public_methods(INGRESS).is_empty());
    assert!(public_methods(EGRESS).is_empty());
    assert_eq!(
        public_methods(WIPE),
        [
            "pub fn reset_wiped_bytes() {",
            "pub fn wiped_bytes() -> usize {",
        ]
    );
}

#[test]
fn production_sources_have_no_wallet_card_crypto_os_or_logging_capability() {
    let sources = [LIB, INNER, INGRESS, EGRESS, SESSION, MOCK, WIPE];
    for source in sources {
        for forbidden in [
            "qk_a1",
            "qk_bip32",
            "qk_card",
            "qk_descriptor",
            "qk_host_model",
            "qk_host_sim",
            "qk_kit",
            "qk_provisioning",
            "qk_psbt",
            "qk_secp",
            "qk_update",
            "qk_wallet",
            "SecretKey",
            "PrivateKey",
            "wallet_id",
            "std::net",
            "UnixStream",
            "UnixListener",
            "recvmsg(",
            "sendmsg(",
            "std::fs",
            "File::",
            "OpenOptions",
            "Command::new",
            "std::process",
            "getrandom",
            "rand::",
            "println!",
            "eprintln!",
            "dbg!",
        ] {
            assert!(!source.contains(forbidden), "forbidden token {forbidden}");
        }
    }
}

#[test]
fn unsafe_is_confined_to_the_two_existing_volatile_wipe_functions() {
    assert!(LIB.contains("#![deny(unsafe_code)]"));
    assert!(!INNER.contains("unsafe"));
    assert!(!INGRESS.contains("unsafe"));
    assert!(!EGRESS.contains("unsafe"));
    assert!(!SESSION.contains("unsafe"));
    assert!(!MOCK.contains("unsafe"));
    assert_eq!(WIPE.matches("#[allow(unsafe_code)]").count(), 2);
    assert_eq!(WIPE.matches("unsafe {").count(), 2);
}

fn owner_section<'a>(source: &'a str, start: &str, end: &str) -> &'a str {
    source
        .split_once(start)
        .expect("owner start")
        .1
        .split_once(end)
        .expect("owner end")
        .0
}

#[test]
fn byte_owners_cannot_clone_format_mutate_or_release_their_storage() {
    let owners = [
        owner_section(SESSION, "pub struct BrokerReply {", "enum State {"),
        owner_section(SESSION, "pub struct BrokerSession {", "impl BrokerSession"),
        owner_section(MOCK, "pub struct MockInput {", "impl MockInput"),
        owner_section(
            MOCK,
            "pub struct MockOutputWriter {",
            "impl MockOutputWriter",
        ),
    ];
    for owner in owners {
        for forbidden in [
            "#[derive(",
            "impl Clone",
            "impl Copy",
            "impl Debug",
            "impl Display",
            "pub fn into_",
            "pub fn as_mut",
            "pub fn to_vec",
            "pub fn bytes_mut",
        ] {
            assert!(!owner.contains(forbidden), "owner surface {forbidden}");
        }
    }
}
