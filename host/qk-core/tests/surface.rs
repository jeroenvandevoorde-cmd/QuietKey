//! Exact dependency, public-surface, capability, owner, and unsafe locks.

const CARGO: &str = include_str!("../Cargo.toml");
const LIB: &str = include_str!("../src/lib.rs");
const CAPABILITY: &str = include_str!("../src/capability.rs");
const ERROR: &str = include_str!("../src/error.rs");
const IO_WIRE: &str = include_str!("../src/io_wire.rs");
const SESSION: &str = include_str!("../src/session.rs");
const SESSION_ID: &str = include_str!("../src/session_id.rs");
const SETUP: &str = include_str!("../src/setup_v2.rs");
const SETUP_ARTIFACT: &str = include_str!("../src/setup_artifact_v2.rs");
const SHA256: &str = include_str!("../src/sha256.rs");
const WIPE: &str = include_str!("../src/wipe.rs");

fn cargo_section<'a>(source: &'a str, header: &str, next: Option<&str>) -> &'a str {
    let tail = source.split_once(header).expect("cargo section").1;
    match next {
        Some(next_header) => tail.split_once(next_header).expect("next cargo section").0,
        None => tail,
    }
}

#[test]
fn direct_product_and_dev_dependencies_are_exact() {
    assert_eq!(
        cargo_section(CARGO, "[dependencies]", Some("[dev-dependencies]")).trim(),
        "qk-ipc = { path = \"../qk-ipc\" }\nqk-provisioning = { path = \"../qk-provisioning\" }"
    );
    assert_eq!(
        cargo_section(CARGO, "[dev-dependencies]", None).trim(),
        "qk-host-sim = { path = \"../qk-host-sim\" }\nqk-io = { path = \"../qk-io\" }"
    );
    let product = cargo_section(CARGO, "[dependencies]", Some("[dev-dependencies]"));
    for forbidden in [
        "qk-a1",
        "qk-bbqr",
        "qk-bip32",
        "qk-card-trace",
        "qk-decoy",
        "qk-descriptor",
        "qk-host-model",
        "qk-host-sim",
        "qk-io",
        "qk-kit",
        "qk-psbt",
        "qk-secp",
        "qk-supervisor",
        "qk-update",
        "qk-wallet-v2",
    ] {
        assert!(
            !product.contains(forbidden),
            "product dependency {forbidden}"
        );
    }
}

#[test]
fn crate_root_surface_is_explicit_and_has_only_the_ring_fenced_module_escape() {
    let public_lines: Vec<&str> = LIB
        .lines()
        .map(str::trim_start)
        .filter(|line| line.starts_with("pub "))
        .collect();
    assert_eq!(
        public_lines,
        [
            "pub use capability::{",
            "pub use error::{CoreError, Interruption, IoRejection};",
            "pub use io_wire::{Operation, Source};",
            "pub use session::{",
            "pub use setup_v2::{",
            "pub const INNER_VERSION: u8 = 1;",
            "pub const INNER_HEADER_BYTES: usize = 8;",
            "pub const MAX_CHUNK_BYTES: usize = 262_144;",
            "pub const MAX_INGRESS_BYTES: usize = 2_097_152;",
            "pub mod fuzz {",
            "pub use crate::io_wire::{",
            "pub use crate::session::fuzz_start_session;",
            "pub use crate::wipe::{reset_wiped_bytes, wiped_bytes};",
        ]
    );
    assert_eq!(LIB.matches("pub mod ").count(), 1);
    assert!(LIB.contains("#[cfg(feature = \"fuzzing\")]"));
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
        public_methods(CAPABILITY),
        [
            "pub const fn wire_value(self) -> u8 {",
            "pub const fn new(",
            "pub const fn instance(&self) -> CardInstanceV2 {",
            "pub const fn role(&self) -> u8 {",
            "pub const fn wallet_id(&self) -> [u8; 32] {",
            "pub const fn account_xpub(&self) -> [u8; 111] {",
            "pub const fn name(self) -> &'static str {",
            "pub const fn new() -> Self {",
            "pub fn inject_failure(&mut self) {",
            "pub fn show(&mut self, screen: CoreScreen) -> Result<(), CoreError> {",
            "pub fn clear(&mut self) -> Result<(), CoreError> {",
            "pub const fn current(&self) -> Option<CoreScreen> {",
            "pub const fn new() -> Self {",
            "pub fn inject_failure(&mut self) {",
            "pub fn read(&mut self, key: KeypadKey) -> Result<KeypadKey, CoreError> {",
            "pub const fn new(presence: CardPresence) -> Self {",
            "pub fn inject_failure(&mut self) {",
            "pub fn observe(&mut self, presence: CardPresence) -> Result<CardPresence, CoreError> {",
            "pub const fn presence(&self) -> CardPresence {",
            "pub fn provision_b(",
            "pub fn verify_b(",
            "pub fn validate(",
            "pub const fn display(&self) -> &MockDisplay {",
            "pub fn display_mut(&mut self) -> &mut MockDisplay {",
            "pub fn keypad_mut(&mut self) -> &mut MockKeypad {",
            "pub const fn card_slot(&self) -> &MockCardSlot {",
            "pub fn card_slot_mut(&mut self) -> &mut MockCardSlot {",
        ]
    );
    assert_eq!(
        public_methods(ERROR),
        [
            "pub const fn name(self) -> &'static str {",
            "pub const fn status_code(self) -> u16 {",
            "pub const fn name(self) -> &'static str {",
        ]
    );
    assert_eq!(
        public_methods(IO_WIRE),
        [
            "pub const fn wire_value(self) -> u8 {",
            "pub const fn wire_value(self) -> u8 {",
            "pub const fn operation(self) -> Operation {",
            "pub fn encode_ingress_begin(source: Source) -> [u8; 11] {",
            "pub fn encode_ingress_read(expected_offset: u32) -> [u8; 12] {",
            "pub fn parse_response<'a>(",
        ]
    );
    assert_eq!(
        public_methods(SESSION),
        [
            "pub const fn consumed(&self) -> usize {",
            "pub const fn event(&self) -> CoreReceiveEvent {",
            "pub fn frame_bytes(&self) -> &[u8] {",
            "pub fn len(&self) -> usize {",
            "pub fn is_empty(&self) -> bool {",
            "pub const fn source(&self) -> Source {",
            "pub fn len(&self) -> usize {",
            "pub fn is_empty(&self) -> bool {",
            "pub fn fuzz_bytes(&self) -> &[u8] {",
            "pub fn start(",
            "pub const fn mode(&self) -> CoreMode {",
            "pub const fn state(&self) -> CoreState {",
            "pub const fn terminal_reason(&self) -> Option<Interruption> {",
            "pub fn current_screen(&self) -> Option<CoreScreen> {",
            "pub fn completed_ingress(&self) -> Option<&HostileIngress> {",
            "pub fn begin_ingress(&mut self, source: Source) -> Result<CoreOutbound, CoreError> {",
            "pub fn request_next_chunk(&mut self) -> Result<CoreOutbound, CoreError> {",
            "pub fn begin_close(&mut self) -> Result<CoreOutbound, CoreError> {",
            "pub fn receive(",
            "pub fn connection_closed(&mut self) -> Result<Interruption, CoreError> {",
            "pub fn interrupt(&mut self, reason: Interruption) -> Result<Interruption, CoreError> {",
            "pub fn handle_key(&mut self, key: KeypadKey) -> Result<Interruption, CoreError> {",
            "pub fn observe_card(&mut self, presence: CardPresence) -> Result<CardPresence, CoreError> {",
            "pub fn fuzz_start_session(",
        ]
    );
    assert!(public_methods(SESSION_ID).is_empty());
    assert_eq!(
        public_methods(SETUP),
        [
            "pub const fn name(self) -> &'static str {",
            "pub const fn account_xpubs(&self) -> &[[u8; 111]; 2] {",
            "pub const fn descriptors(&self) -> &[[u8; 306]; 2] {",
            "pub const fn wallet_id(&self) -> [u8; 32] {",
            "pub const fn first_scripts(&self) -> &[[u8; 34]; 2] {",
            "pub const fn first_addresses(&self) -> &[[u8; 62]; 2] {",
            "pub const fn outcome(&self) -> SetupOutcomeV2 {",
            "pub const fn outbound(&self) -> Option<&CoreOutbound> {",
            "pub fn into_outbound(self) -> Option<CoreOutbound> {",
            "pub const fn consumed(&self) -> usize {",
            "pub const fn outcome(&self) -> SetupOutcomeV2 {",
            "pub const fn outbound(&self) -> Option<&CoreOutbound> {",
            "pub fn into_outbound(self) -> Option<CoreOutbound> {",
            "pub fn start(",
            "pub fn fuzz_start(",
            "pub const fn stage(&self) -> Option<SetupStageV2> {",
            "pub const fn entropy_mode(&self) -> EntropyInputModeV2 {",
            "pub fn retained_counts(&self) -> [usize; PURPOSE_COUNT] {",
            "pub fn is_terminal(&self) -> bool {",
            "pub const fn terminal_error(&self) -> Option<SetupErrorV2> {",
            "pub const fn public_facts(&self) -> Option<&SetupPublicFactsV2> {",
            "pub fn screen(&self) -> Option<SetupScreenV2<'_>> {",
            "pub fn receive(",
            "pub fn begin_a1_print(&mut self) -> Result<SetupProgressV2, SetupErrorV2> {",
            "pub fn begin_kit_print(&mut self) -> Result<SetupProgressV2, SetupErrorV2> {",
            "pub fn apply_key(&mut self, key: KeypadKey) -> Result<SetupProgressV2, SetupErrorV2> {",
            "pub fn camera_presented(&mut self) -> Result<SetupProgressV2, SetupErrorV2> {",
            "pub fn interrupt(&mut self, reason: Interruption) -> Result<Interruption, SetupErrorV2> {",
            "pub fn observe_card(&mut self, presence: CardPresence) -> Result<CardPresence, SetupErrorV2> {",
            "pub fn provision_card(",
            "pub fn verify_card(",
            "pub fn select_spare(",
        ]
    );
    assert!(public_methods(SETUP_ARTIFACT).is_empty());
    assert!(public_methods(SHA256).is_empty());
    assert_eq!(
        public_methods(WIPE),
        [
            "pub fn reset_wiped_bytes() {",
            "pub fn wiped_bytes() -> usize {",
        ]
    );
}

#[test]
fn production_sources_have_no_signing_export_apdu_socket_or_logging_api() {
    let sources = [
        LIB,
        CAPABILITY,
        ERROR,
        IO_WIRE,
        SESSION,
        SESSION_ID,
        SETUP,
        SETUP_ARTIFACT,
        SHA256,
        WIPE,
    ];
    for source in sources {
        for forbidden in [
            "qk_a1",
            "qk_bip32",
            "qk_card_trace",
            "qk_descriptor",
            "qk_host_model",
            "qk_host_sim",
            "qk_io::",
            "qk_kit",
            "qk_psbt",
            "qk_secp",
            "qk_update",
            "qk_wallet",
            "SecretKey",
            "PrivateKey",
            "SigningKey",
            "ReviewV",
            "DescriptorPair",
            "ExportArtifact",
            "Apdu",
            "send_apdu",
            "transmit_apdu",
            "ApduCommand",
            "UnixStream",
            "UnixListener",
            "TcpStream",
            "UdpSocket",
            "recvmsg(",
            "sendmsg(",
            "Command::new",
            "std::process",
            "println!",
            "eprintln!",
            "dbg!",
        ] {
            assert!(!source.contains(forbidden), "forbidden token {forbidden}");
        }
    }
    assert_eq!(SETUP.matches("use qk_provisioning::{").count(), 1);
    assert_eq!(SETUP_ARTIFACT.matches("use qk_provisioning::{").count(), 2);
    for source in [
        LIB, CAPABILITY, ERROR, IO_WIRE, SESSION, SESSION_ID, SHA256, WIPE,
    ] {
        assert!(!source.contains("qk_provisioning"));
    }
    for forbidden in [
        "pub fn transcript",
        "pub fn nonce",
        "pub fn a1_capsule",
        "pub fn kit_page",
        "pub fn hash",
        "pub fn export",
        "pub fn sign",
    ] {
        assert!(!SETUP.contains(forbidden), "setup surface {forbidden}");
    }
}

#[test]
fn unsafe_is_confined_to_the_existing_volatile_wipe_module() {
    assert!(LIB.contains("#![deny(unsafe_code)]"));
    assert_eq!(LIB.matches("#[allow(unsafe_code)]").count(), 1);
    assert!(LIB.contains("mod wipe;"));
    assert!(!CAPABILITY.contains("unsafe {"));
    assert!(!ERROR.contains("unsafe {"));
    assert!(!IO_WIRE.contains("unsafe {"));
    assert!(!SESSION.contains("unsafe {"));
    assert!(!SESSION_ID.contains("unsafe {"));
    assert!(!SETUP.contains("unsafe {"));
    assert!(!SETUP_ARTIFACT.contains("unsafe {"));
    assert!(!SHA256.contains("unsafe {"));
    assert_eq!(WIPE.matches("#[allow(unsafe_code)]").count(), 3);
    assert_eq!(WIPE.matches("unsafe {").count(), 3);
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
fn hostile_ingress_has_no_production_byte_release_or_copy_surface() {
    let owner = owner_section(
        SESSION,
        "pub struct HostileIngress {",
        "struct IngressTransfer {",
    );
    let production = owner
        .split_once("#[cfg(feature = \"fuzzing\")]")
        .expect("ring-fenced byte seam")
        .0;
    assert_eq!(
        public_methods(production),
        [
            "pub const fn source(&self) -> Source {",
            "pub fn len(&self) -> usize {",
            "pub fn is_empty(&self) -> bool {",
        ]
    );
    assert!(owner.contains("#[cfg(feature = \"fuzzing\")]"));
    assert!(owner.contains("#[doc(hidden)]"));
    assert_eq!(
        owner.matches("pub fn fuzz_bytes(&self) -> &[u8]").count(),
        1
    );
    for forbidden in [
        "#[derive(",
        "impl Clone",
        "impl Copy",
        "impl Debug",
        "impl Display",
        "pub fn into_",
        "pub fn as_",
        "pub fn to_vec",
        "pub fn bytes_mut",
        "pub fn frame_bytes",
    ] {
        assert!(
            !production.contains(forbidden),
            "hostile owner surface {forbidden}"
        );
    }
}

#[test]
fn byte_and_session_owners_cannot_clone_format_mutate_or_release_storage() {
    let owners = [
        owner_section(
            SESSION,
            "pub struct CoreOutbound {",
            "pub struct HostileIngress {",
        ),
        owner_section(SESSION, "pub struct CoreSession {", "impl CoreSession"),
        owner_section(
            SESSION_ID,
            "pub(crate) struct SessionId {",
            "impl SessionId",
        ),
        owner_section(SETUP, "pub struct SetupSessionV2 {", "impl SetupSessionV2"),
        owner_section(
            SETUP_ARTIFACT,
            "pub(crate) struct A1PrintArtifactV2 {",
            "impl A1PrintArtifactV2",
        ),
        owner_section(
            SETUP_ARTIFACT,
            "pub(crate) struct KitPrintArtifactV2 {",
            "impl KitPrintArtifactV2",
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
