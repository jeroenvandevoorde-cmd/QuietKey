//! Exact dependency, public-surface, capability, owner, and unsafe locks.

const CARGO: &str = include_str!("../Cargo.toml");
const LIB: &str = include_str!("../src/lib.rs");
const CAPABILITY: &str = include_str!("../src/capability.rs");
const CARD_PROCESS: &str = include_str!("../src/card_process_v1.rs");
const ERROR: &str = include_str!("../src/error.rs");
const IO_WIRE: &str = include_str!("../src/io_wire.rs");
const KIT_ARTIFACT: &str = include_str!("../src/kit_artifact_v2.rs");
const KIT_INTAKE: &str = include_str!("../src/kit_intake_v2.rs");
const KIT_RESTORE: &str = include_str!("../src/kit_restore_v2.rs");
const KIT_SPEND: &str = include_str!("../src/kit_spend_v2.rs");
const NORMAL_ARTIFACT: &str = include_str!("../src/normal_artifact_v2.rs");
const NORMAL_PROCESS: &str = include_str!("../src/normal_process_v2.rs");
const NORMAL: &str = include_str!("../src/normal_v2.rs");
const PROCESS: &str = include_str!("../src/process.rs");
const PROCESS_BIN: &str = include_str!("../src/bin/qk-core-host.rs");
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
    let binary = "[[bin]]\nname = \"qk-core-host\"\npath = \"src/bin/qk-core-host.rs\"\nrequired-features = [\"host-runtime\"]";
    assert_eq!(CARGO.matches(binary).count(), 1);
    assert_eq!(
        cargo_section(CARGO, "[features]", Some("[dependencies]")).trim(),
        "default = [\"normal-v3\", \"kit-v3\"]\nfuzzing = [\"normal-v3\", \"kit-v3\", \"qk-ipc/fuzzing\"]\nhost-runtime = [\"qk-ipc/host-runtime\", \"normal-process\"]\nlegacy-normal-factor-fixture = [\"qk-device-wire/legacy-normal-factor-fixture\"]\nnormal-process = [\n    \"normal-v3\",\n    \"dep:qk-bip32\",\n    \"dep:qk-card-protocol\",\n    \"dep:qk-secp\",\n    \"qk-secp/card-signature-normalization\",\n]\nnormal-v3 = [\"qk-psbt/normal-v3\", \"qk-wallet-v2/normal-v3\"]\nkit-v3 = [\"normal-v3\", \"qk-kit/process-v3\"]"
    );
    assert_eq!(
        cargo_section(CARGO, "[dependencies]", Some("[dev-dependencies]")).trim(),
        "qk-a1 = { path = \"../qk-a1\" }\nqk-bbqr = { path = \"../qk-bbqr\" }\nqk-bip32 = { path = \"../qk-bip32\", optional = true }\nqk-card-protocol = { path = \"../qk-card-protocol\", optional = true }\nqk-descriptor = { path = \"../qk-descriptor\" }\nqk-device-wire = { path = \"../qk-device-wire\" }\nqk-ipc = { path = \"../qk-ipc\" }\nqk-kit = { path = \"../qk-kit\" }\nqk-psbt = { path = \"../qk-psbt\" }\nqk-provisioning = { path = \"../qk-provisioning\" }\nqk-secp = { path = \"../qk-secp\", optional = true }\nqk-wallet-v2 = { path = \"../qk-wallet-v2\" }"
    );
    assert_eq!(
        cargo_section(CARGO, "[dev-dependencies]", None).trim(),
        "qk-host-sim = { path = \"../qk-host-sim\" }\nqk-io = { path = \"../qk-io\" }\nqk-secp = { path = \"../qk-secp\" }"
    );
    let product = cargo_section(CARGO, "[dependencies]", Some("[dev-dependencies]"));
    for forbidden in [
        "qk-card-trace",
        "qk-decoy",
        "qk-host-model",
        "qk-host-sim",
        "qk-io",
        "qk-supervisor",
        "qk-update",
    ] {
        assert!(
            !product.contains(forbidden),
            "product dependency {forbidden}"
        );
    }
}

#[test]
fn normal_and_kit_modules_and_exports_are_feature_locked() {
    for item in [
        "mod normal_artifact_v2;",
        "mod normal_v2;",
        "pub use normal_artifact_v2::{",
        "pub use normal_v2::{",
    ] {
        assert!(
            LIB.contains(&format!("#[cfg(feature = \"normal-v3\")]\n{item}")),
            "normal surface is not feature locked: {item}"
        );
    }
    assert_eq!(LIB.matches("#[cfg(feature = \"normal-v3\")]").count(), 4);
    for item in [
        "mod card_process_v1;",
        "mod normal_process_v2;",
        "pub use card_process_v1::{",
        "pub use normal_process_v2::{",
        "pub use normal_v2::NormalCardBSigningRequestV2;",
    ] {
        assert!(LIB.contains(&format!("#[cfg(feature = \"normal-process\")]\n{item}")));
    }
    assert_eq!(
        LIB.matches("#[cfg(feature = \"normal-process\")]").count(),
        5
    );
    for item in [
        "mod kit_artifact_v2;",
        "mod kit_intake_v2;",
        "mod kit_restore_v2;",
        "mod kit_spend_v2;",
        "pub use kit_artifact_v2::{",
        "pub use kit_intake_v2::{",
        "pub use kit_restore_v2::{",
        "pub use kit_spend_v2::{",
        "pub use qk_kit::{KitRestoreDispositionV2, SurvivingBFactorV2};",
    ] {
        assert!(
            LIB.contains(&format!("#[cfg(feature = \"kit-v3\")]\n{item}")),
            "Kit surface is not feature locked: {item}"
        );
    }
    assert_eq!(LIB.matches("#[cfg(feature = \"kit-v3\")]").count(), 9);
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
            "pub use card_process_v1::{",
            "pub use error::{CoreError, Interruption, IoRejection};",
            "pub use io_wire::{Operation, Source};",
            "pub use kit_artifact_v2::{",
            "pub use kit_intake_v2::{",
            "pub use kit_restore_v2::{",
            "pub use kit_spend_v2::{",
            "pub use normal_artifact_v2::{",
            "pub use normal_process_v2::{",
            "pub use normal_v2::NormalCardBSigningRequestV2;",
            "pub use normal_v2::{",
            "pub use process::{run_core_host_process, run_normal_core_host_process, CoreHostProcessError};",
            "pub use qk_kit::{KitRestoreDispositionV2, SurvivingBFactorV2};",
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

#[test]
fn host_process_surface_is_feature_locked_and_contains_no_second_protocol_or_logging() {
    for item in [
        "mod process;",
        "pub use process::{run_core_host_process, run_normal_core_host_process, CoreHostProcessError};",
    ] {
        assert!(
            LIB.contains(&format!("#[cfg(feature = \"host-runtime\")]\n{item}")),
            "host runtime surface is not feature locked: {item}"
        );
    }
    assert_eq!(LIB.matches("#[cfg(feature = \"host-runtime\")]").count(), 2);
    assert_eq!(
        public_methods(PROCESS),
        [
            "pub fn run_core_host_process(mode: CoreMode) -> Result<(), CoreHostProcessError> {",
            "pub fn run_normal_core_host_process(profile_ascii: &[u8]) -> Result<(), CoreHostProcessError> {",
        ]
    );
    for forbidden in [
        "qk_host_sim",
        "MockInput",
        "MockOutputWriter",
        "println!",
        "eprintln!",
        "dbg!",
        "unsafe {",
        "SCM_RIGHTS",
        "sendmsg(",
        "recvmsg(",
    ] {
        assert!(!PROCESS.contains(forbidden), "process token {forbidden}");
        assert!(!PROCESS_BIN.contains(forbidden), "binary token {forbidden}");
    }
    assert!(PROCESS.contains("const RECEIVE_BYTES: usize = 1;"));
    assert!(PROCESS.contains(".begin(MessageKind::CardApduRequest)"));
    assert!(!PROCESS.contains("read_card_profile"));
    assert!(!PROCESS.contains("read_normal_factor"));
    assert!(!PROCESS.contains("MessageKind::CardReadProfile"));
    assert!(!PROCESS.contains("MessageKind::CardReadNormalFactor"));
    let active_loop = PROCESS
        .split_once("drive_qkip(&stream, &mut controller, opening)?;")
        .expect("normal opening")
        .1;
    let signing = active_loop
        .find("NormalStageV2::CardBSigning")
        .expect("card signing branch");
    let display = active_loop
        .find("devices.display_updates(&mut controller)?;")
        .expect("stage display path");
    let keypad = active_loop
        .find("let event = devices.read_keypad_event()?;")
        .expect("keypad path");
    assert!(display < signing && signing < keypad);
}

#[test]
fn host_binary_has_one_silent_unwind_boundary_and_only_the_fixed_statuses() {
    assert_eq!(
        PROCESS_BIN
            .matches("const INVOCATION_REJECTED: u8 = 64;")
            .count(),
        1
    );
    assert_eq!(
        PROCESS_BIN
            .matches("const RUNTIME_TERMINATED: u8 = 70;")
            .count(),
        1
    );
    assert_eq!(PROCESS_BIN.matches("fn main() -> ExitCode {").count(), 1);
    assert_eq!(PROCESS_BIN.matches("fn run() -> ExitCode {").count(), 1);
    assert_eq!(
        PROCESS_BIN
            .matches("std::panic::set_hook(Box::new(|_| {}));")
            .count(),
        1
    );
    assert_eq!(
        PROCESS_BIN.matches("std::panic::catch_unwind(run)").count(),
        1
    );
    assert_eq!(PROCESS_BIN.matches("ExitCode::SUCCESS").count(), 1);
    assert_eq!(PROCESS_BIN.matches("std::env::").count(), 1);
    assert!(!PROCESS_BIN.contains("var_os"));
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
            "pub fn try_new(",
            "pub const fn input_index(&self) -> u32 {",
            "pub fn der_signature(&self) -> &[u8] {",
            "pub fn try_new(",
            "pub const fn descriptors(&self) -> &[[u8; 306]; 2] {",
            "pub const fn wallet_id(&self) -> [u8; 32] {",
            "pub const fn account_xpub(&self) -> &[u8; 111] {",
            "pub fn signatures(&self) -> &[NormalCardBSignatureV2] {",
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
            "pub fn with_normal_data(presence: CardPresence, normal_data: NormalCardBDataV2) -> Self {",
            "pub fn inject_failure(&mut self) {",
            "pub fn observe(&mut self, presence: CardPresence) -> Result<CardPresence, CoreError> {",
            "pub const fn presence(&self) -> CardPresence {",
            "pub fn provision_b(&mut self, binding: CardBPublicBindingV2) -> Result<(), CardMockErrorV2> {",
            "pub fn verify_b(&mut self, binding: CardBPublicBindingV2) -> Result<(), CardMockErrorV2> {",
            "pub fn validate(",
            "pub const fn display(&self) -> &MockDisplay {",
            "pub fn display_mut(&mut self) -> &mut MockDisplay {",
            "pub fn keypad_mut(&mut self) -> &mut MockKeypad {",
            "pub const fn card_slot(&self) -> &MockCardSlot {",
            "pub fn card_slot_mut(&mut self) -> &mut MockCardSlot {",
        ]
    );
    assert_eq!(
        public_methods(CARD_PROCESS),
        [
            "pub const fn name(self) -> &'static str {",
            "pub fn try_from_response(response: ResponseRef<'_>) -> Result<Self, CardProcessErrorV1> {",
            "pub const fn profile(&self) -> u8 {",
            "pub const fn wallet_id(&self) -> [u8; 32] {",
            "pub const fn account_xpub(&self) -> [u8; RAW_XPUB_BYTES] {",
            "pub fn bind_normal_card_v1(",
            "pub fn verify_provisioned_card_v1(",
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
        public_methods(KIT_ARTIFACT),
        [
            "pub const fn serialized_len(self) -> u32 {",
            "pub const fn sha256(self) -> [u8; 32] {",
            "pub const fn total_len(self) -> u32 {",
            "pub const fn profile(&self) -> NormalProfileV2 {",
            "pub const fn route(&self) -> KitExportRouteV2 {",
            "pub const fn raw_transaction(&self) -> KitRawTransactionFactsV2 {",
            "pub const fn sd_receipt(&self) -> Option<KitSdReceiptV2> {",
            "pub const fn txid(&self) -> [u8; 32] {",
            "pub const fn wtxid(&self) -> [u8; 32] {",
            "pub const fn name(self) -> &'static str {",
            "pub const fn consumed(&self) -> usize {",
            "pub const fn outbound(&self) -> Option<&CoreOutbound> {",
            "pub fn into_outbound(self) -> Option<CoreOutbound> {",
            "pub const fn result(&self) -> Option<KitExportResultV2> {",
            "pub fn begin(",
            "pub fn receive(",
            "pub const fn result(&self) -> Option<KitExportResultV2> {",
            "pub fn next_request(&mut self) -> Result<KitExportRequestV2, KitArtifactErrorV2> {",
            "pub fn accept_response(",
        ]
    );
    assert_eq!(
        public_methods(KIT_INTAKE),
        [
            "pub const fn name(self) -> &'static str {",
            "pub const fn share_index(self) -> ShareIndex {",
            "pub const fn wallet_id(self) -> [u8; 32] {",
            "pub const fn checksum(self) -> [u8; FRAME_CHECKSUM_BYTES] {",
            "pub const fn committed_symbols(self) -> usize {",
            "pub const fn pending_row(self) -> Option<u8> {",
            "pub const fn next_line(self) -> Option<u8> {",
            "pub const fn next_column(self) -> Option<u8> {",
            "pub const fn door(self) -> KitDoorV2 {",
            "pub const fn mode(self) -> KitInputModeV2 {",
            "pub const fn page(self) -> KitShareOrdinalV2 {",
            "pub const fn fallback(self) -> KitFallbackProgressV2 {",
            "pub const fn fallback_table(self) -> &'static [[u8; 8]; 4] {",
            "pub const fn door(&self) -> KitDoorV2 {",
            "pub const fn mode(&self) -> KitInputModeV2 {",
            "pub const fn wallet_id(&self) -> [u8; 32] {",
            "pub const fn frame_identities(&self) -> [KitFrameIdentityV2; 2] {",
            "pub fn begin(door: KitDoorV2, mode: KitInputModeV2) -> Self {",
            "pub fn begin_in_core(",
            "pub fn screen(&self) -> Option<KitIntakeScreenV2> {",
            "pub const fn failure(&self) -> Option<KitIntakeErrorV2> {",
            "pub fn submit_scanner_frame(",
            "pub fn submit_scanner_ingress(",
            "pub fn submit_scanner_from_core(",
            "pub fn apply_fallback_key(",
            "pub fn apply_fallback_key_from_core(",
            "pub fn select_mode(",
            "pub fn select_mode_in_core(",
            "pub fn reselect_door(",
            "pub fn reselect_door_in_core(",
            "pub fn reject_foreign_input(",
            "pub fn reject_foreign_input_in_core(",
            "pub fn interrupt(",
            "pub fn interrupt_in_core(",
        ]
    );
    assert!(KIT_INTAKE.contains(
        "#[cfg(any(test, feature = \"fuzzing\"))]\n    #[doc(hidden)]\n    pub fn begin(door: KitDoorV2, mode: KitInputModeV2) -> Self {"
    ));
    for fuzz_only in [
        "pub fn submit_scanner_frame(",
        "pub fn submit_scanner_ingress(",
        "pub fn apply_fallback_key(",
        "pub fn select_mode(",
        "pub fn reselect_door(",
        "pub fn reject_foreign_input(",
        "pub fn interrupt(",
    ] {
        assert!(
            KIT_INTAKE.contains(&format!(
                "#[cfg(feature = \"fuzzing\")]\n    #[doc(hidden)]\n    {fuzz_only}"
            )),
            "Kit intake semantic escape is not ring fenced: {fuzz_only}"
        );
    }
    assert_eq!(
        public_methods(KIT_RESTORE),
        [
            "pub fn new(digit: u8) -> Result<Self, KitRestoreErrorV2> {",
            "pub const fn value(self) -> u8 {",
            "pub const fn stage(self) -> KitRestoreStageV2 {",
            "pub const fn wallet_id(self) -> [u8; 32] {",
            "pub const fn input_mode(self) -> KitInputModeV2 {",
            "pub const fn action(self) -> Option<KitRestoreActionV2> {",
            "pub const fn assertion_digit(self) -> Option<HumanAssertionDigitV2> {",
            "pub const fn name(self) -> &'static str {",
            "pub const fn artifact(&self) -> &KitRestoreArtifactV2 {",
            "pub const fn posture(&self) -> MandatoryFreshWalletMigrationV2 {",
            "pub fn begin(",
            "pub fn fuzz_begin(",
            "pub fn screen(&self) -> Option<KitRestoreScreenV2> {",
            "pub const fn frame_identities(&self) -> [KitFrameIdentityV2; 2] {",
            "pub const fn terminal_error(&self) -> Option<KitRestoreErrorV2> {",
            "pub const fn is_terminal(&self) -> bool {",
            "pub fn select_action(",
            "pub fn select_action_in_core(",
            "pub fn confirm_card_remains(",
            "pub fn confirm_card_remains_in_core(",
            "pub fn prepare_replacement_b(",
            "pub fn prepare_replacement_b_ingress(",
            "pub fn prepare_replacement_b_from_core(",
            "pub fn prepare_a1_reprint(",
            "pub fn prepare_a1_reprint_in_core(",
            "pub fn execute_replacement_b<F>(",
            "pub fn execute_replacement_b_in_core(",
            "pub fn begin_a1_reprint(",
            "pub fn begin_a1_reprint_in_core(",
            "pub fn reject_foreign_operation(",
            "pub fn reject_foreign_operation_in_core(",
            "pub fn interrupt(",
            "pub fn interrupt_in_core(",
            "pub fn begin_print(",
            "pub fn write_print(",
            "pub fn finish_print(",
            "pub fn begin_scan_back(",
            "pub fn request_scan_back(",
            "pub fn complete_from_core(",
            "pub fn capsule(&self) -> Option<&[u8; A1_CAPSULE_BYTES]> {",
            "pub fn complete_scan_back(",
            "pub fn complete_scan_back_ingress(",
            "pub fn reject_print(mut self) -> KitRestoreErrorV2 {",
        ]
    );
    for fuzz_only in [
        "pub fn select_action(",
        "pub fn confirm_card_remains(",
        "pub fn prepare_replacement_b(",
        "pub fn prepare_replacement_b_ingress(",
        "pub fn prepare_a1_reprint(",
        "pub fn execute_replacement_b<F>(",
        "pub fn begin_a1_reprint(",
        "pub fn capsule(&self) -> Option<&[u8; A1_CAPSULE_BYTES]> {",
        "pub fn complete_scan_back(",
        "pub fn complete_scan_back_ingress(",
        "pub fn reject_print(mut self) -> KitRestoreErrorV2 {",
        "pub fn reject_foreign_operation(",
        "pub fn interrupt(",
    ] {
        assert!(
            KIT_RESTORE.contains(&format!(
                "#[cfg(feature = \"fuzzing\")]\n    #[doc(hidden)]\n    {fuzz_only}"
            )),
            "Kit restore semantic escape is not ring fenced: {fuzz_only}"
        );
    }
    assert_eq!(
        public_methods(KIT_SPEND),
        [
            "pub fn new(digit: u8) -> Result<Self, KitSpendErrorV2> {",
            "pub const fn value(self) -> u8 {",
            "pub const fn cycle(self) -> u64 {",
            "pub const fn token(self) -> KitSpendCycleTokenV2 {",
            "pub const fn review_hash(self) -> ReviewV3Hash {",
            "pub const fn assertion_digit(self) -> KitSpendAssertionDigitV2 {",
            "pub const fn name(self) -> &'static str {",
            "pub const fn profile(self) -> NormalProfileV2 {",
            "pub const fn old_wallet_id(self) -> [u8; 32] {",
            "pub const fn replacement_wallet_id(self) -> [u8; 32] {",
            "pub const fn destination_index(self) -> u32 {",
            "pub const fn review_hash(self) -> ReviewV3Hash {",
            "pub const fn raw_transaction_len(self) -> u32 {",
            "pub const fn raw_transaction_sha256(self) -> [u8; 32] {",
            "pub const fn txid(self) -> [u8; 32] {",
            "pub const fn wtxid(self) -> [u8; 32] {",
            "pub const fn facts(&self) -> KitSpendFinalizedFactsV2 {",
            "pub const fn completeness(&self) -> CoordinatorCompletenessStatementV2 {",
            "pub fn begin(",
            "pub fn fuzz_begin(",
            "pub const fn profile(&self) -> NormalProfileV2 {",
            "pub const fn stage(&self) -> KitSpendStageV2 {",
            "pub const fn review_position(&self) -> Option<KitSpendReviewPositionV2> {",
            "pub const fn frame_identities(&self) -> [KitFrameIdentityV2; 2] {",
            "pub const fn failure(&self) -> Option<KitSpendErrorV2> {",
            "pub fn screen(&self) -> Option<KitSpendScreenV2<'_>> {",
            "pub fn submit_sweep(",
            "pub fn submit_sweep_ingress(",
            "pub fn submit_sweep_from_core(",
            "pub fn advance_review(&mut self) -> Result<KitSpendScreenV2<'_>, KitSpendErrorV2> {",
            "pub fn advance_review_in_core(",
            "pub fn confirm_all_funds(",
            "pub fn confirm_all_funds_in_core(",
            "pub fn execute(",
            "pub fn execute_in_core(",
            "pub fn reject_foreign_operation(",
            "pub fn reject_foreign_operation_in_core(",
            "pub fn interrupt(&mut self, reason: Interruption) -> Result<(), KitSpendErrorV2> {",
            "pub fn interrupt_in_core(",
        ]
    );
    for fuzz_only in [
        "pub fn submit_sweep(",
        "pub fn submit_sweep_ingress(",
        "pub fn advance_review(&mut self) -> Result<KitSpendScreenV2<'_>, KitSpendErrorV2> {",
        "pub fn confirm_all_funds(",
        "pub fn execute(",
        "pub fn reject_foreign_operation(",
        "pub fn interrupt(&mut self, reason: Interruption) -> Result<(), KitSpendErrorV2> {",
    ] {
        assert!(
            KIT_SPEND.contains(&format!(
                "#[cfg(feature = \"fuzzing\")]\n    #[doc(hidden)]\n    {fuzz_only}"
            )),
            "Kit spend semantic escape is not ring fenced: {fuzz_only}"
        );
    }
    assert_eq!(
        public_methods(NORMAL_ARTIFACT),
        [
            "pub fn parse(bytes: &[u8]) -> Result<Self, NormalArtifactErrorV2> {",
            "pub const fn route_exposure(self) -> NormalRouteExposureV2 {",
            "pub const fn sd_finalized_psbt(self) -> bool {",
            "pub const fn sd_raw_transaction(self) -> bool {",
            "pub const fn bbqr_finalized_psbt(self) -> bool {",
            "pub const fn bbqr_raw_transaction(self) -> bool {",
            "pub const fn kind(self) -> NormalArtifactKindV2 {",
            "pub const fn serialized_len(self) -> u32 {",
            "pub const fn sha256(self) -> [u8; 32] {",
            "pub const fn artifact(self) -> NormalArtifactKindV2 {",
            "pub const fn total_len(self) -> u32 {",
            "pub const fn profile(&self) -> NormalProfileV2 {",
            "pub const fn route(&self) -> NormalExportRouteV2 {",
            "pub const fn finalized_psbt(&self) -> Option<NormalArtifactFactsV2> {",
            "pub const fn raw_transaction(&self) -> Option<NormalArtifactFactsV2> {",
            "pub const fn finalized_psbt_sd_receipt(&self) -> Option<NormalSdReceiptV2> {",
            "pub const fn raw_transaction_sd_receipt(&self) -> Option<NormalSdReceiptV2> {",
            "pub const fn txid(&self) -> [u8; 32] {",
            "pub const fn wtxid(&self) -> [u8; 32] {",
            "pub const fn name(self) -> &'static str {",
            "pub fn bytes(&self) -> &[u8] {",
            "pub fn next_request(&mut self) -> Result<NormalExportRequestV2, NormalArtifactErrorV2> {",
            "pub fn accept_response(",
        ]
    );
    assert_eq!(
        public_methods(NORMAL),
        [
            "pub const fn profile(&self) -> NormalProfileV2 {",
            "pub const fn network(&self) -> ReviewNetwork {",
            "pub const fn wallet_id(&self) -> [u8; 32] {",
            "pub const fn input_count(&self) -> usize {",
            "pub const fn total_input_amount(&self) -> u64 {",
            "pub const fn total_input_amount(&self) -> u64 {",
            "pub const fn total_output_amount(&self) -> u64 {",
            "pub const fn fee(&self) -> u64 {",
            "pub const fn index(&self) -> u32 {",
            "pub const fn amount(&self) -> u64 {",
            "pub const fn script_pubkey(&self) -> &'a [u8] {",
            "pub const fn recipient(&self) -> NormalRecipientFactV2<'a> {",
            "pub const fn index(&self) -> u32 {",
            "pub const fn amount(&self) -> u64 {",
            "pub const fn script_pubkey(&self) -> &'a [u8] {",
            "pub const fn child_index(&self) -> u32 {",
            "pub const fn index(&self) -> u32 {",
            "pub const fn amount(&self) -> u64 {",
            "pub const fn script_pubkey(&self) -> &'a [u8] {",
            "pub const fn payload(&self) -> &'a [u8] {",
            "pub const fn locktime(self) -> u32 {",
            "pub const fn input_index(&self) -> u32 {",
            "pub const fn sequence(&self) -> u32 {",
            "pub const fn direct_rbf(&self) -> DirectRbf {",
            "pub const fn identifier(&self) -> &'static [u8] {",
            "pub const fn fee(&self) -> u64 {",
            "pub const fn estimated_vsize(&self) -> u32 {",
            "pub const fn fee_rate_msat_per_vbyte(&self) -> u64 {",
            "pub const fn warning(self) -> FeeWarning {",
            "pub const fn profile(self) -> NormalProfileV2 {",
            "pub const fn review_hash(self) -> ReviewV3Hash {",
            "pub const fn result(self) -> &'a NormalExportResultV2 {",
            "pub const fn cycle(self) -> u64 {",
            "pub const fn token(self) -> NormalApprovalTokenV2 {",
            "pub const fn profile(self) -> NormalProfileV2 {",
            "pub const fn review_hash(self) -> ReviewV3Hash {",
            "pub const fn cycle(self) -> u64 {",
            "pub const fn name(self) -> &'static str {",
            "pub const fn stage(&self) -> NormalStageV2 {",
            "pub const fn outbound(&self) -> Option<&CoreOutbound> {",
            "pub fn into_outbound(self) -> Option<CoreOutbound> {",
            "pub const fn wallet_id(&self) -> &[u8; 32] {",
            "pub const fn review_hash(&self) -> &ReviewV3Hash {",
            "pub const fn input_index(&self) -> u32 {",
            "pub const fn branch(&self) -> u32 {",
            "pub const fn child_index(&self) -> u32 {",
            "pub const fn digest(&self) -> &[u8; 32] {",
            "pub const fn role_b_pubkey(&self) -> &[u8; 33] {",
            "pub const fn consumed(&self) -> usize {",
            "pub const fn stage(&self) -> NormalStageV2 {",
            "pub const fn outbound(&self) -> Option<&CoreOutbound> {",
            "pub fn into_outbound(self) -> Option<CoreOutbound> {",
            "pub fn start(",
            "pub fn fuzz_start(",
            "pub const fn profile(&self) -> NormalProfileV2 {",
            "pub const fn stage(&self) -> NormalStageV2 {",
            "pub const fn review_position(&self) -> Option<NormalReviewPositionV2> {",
            "pub const fn approval_identity(&self) -> Option<NormalApprovalIdentityV2> {",
            "pub const fn result(&self) -> Option<&NormalExportResultV2> {",
            "pub const fn terminal_error(&self) -> Option<NormalErrorV2> {",
            "pub fn is_terminal(&self) -> bool {",
            "pub fn screen(&self) -> Option<NormalScreenV2<'_>> {",
            "pub fn receive(",
            "pub fn confirm_profile(&mut self) -> Result<NormalProgressV2, NormalErrorV2> {",
            "pub fn begin_psbt_intake(&mut self, source: Source) -> Result<NormalProgressV2, NormalErrorV2> {",
            "pub fn accept_card_b(&mut self) -> Result<NormalProgressV2, NormalErrorV2> {",
            "pub fn begin_a1_intake(&mut self) -> Result<NormalProgressV2, NormalErrorV2> {",
            "pub fn validate(&mut self) -> Result<NormalProgressV2, NormalErrorV2> {",
            "pub fn advance_review(&mut self) -> Result<NormalProgressV2, NormalErrorV2> {",
            "pub fn begin_approval_hold(&mut self) -> Result<NormalApprovalTokenV2, NormalErrorV2> {",
            "pub fn complete_approval_hold(",
            "pub fn choose_export(",
            "pub fn complete_result(&mut self) -> Result<NormalProgressV2, NormalErrorV2> {",
            "pub fn interrupt(&mut self, reason: Interruption) -> Result<(), NormalErrorV2> {",
        ]
    );
    assert_eq!(
        public_methods(NORMAL_PROCESS),
        [
            "pub const fn name(self) -> &'static str {",
            "pub fn start(profile_ascii: &[u8]) -> Result<Self, NormalProcessErrorV2> {",
            "pub fn fuzz_start(",
            "pub const fn selected_profile(&self) -> NormalProfileV2 {",
            "pub const fn stage(&self) -> NormalProcessStageV2 {",
            "pub const fn terminal_error(&self) -> Option<NormalProcessErrorV2> {",
            "pub const fn fuzz_last_normal_stage(&self) -> Option<NormalStageV2> {",
            "pub fn fuzz_take_display_stage(&mut self) -> Option<NormalStageV2> {",
            "pub fn screen(&self) -> Option<NormalScreenV2<'_>> {",
            "pub fn card_b_signing_request(&self) -> Option<NormalCardBSigningRequestV2> {",
            "pub fn accept_profile(&mut self, profile_wire: u8) -> Result<(), NormalProcessErrorV2> {",
            "pub fn accept_normal_factor(",
            "pub fn fuzz_accept_bound_card(",
            "pub fn reject_card(&mut self, request_kind: u8, status: u16) -> NormalProcessErrorV2 {",
            "pub fn receive_qkip(",
            "pub fn advance_automatic(&mut self) -> Result<Option<CoreOutbound>, NormalProcessErrorV2> {",
            "pub fn handle_event(",
            "pub fn accept_card_b_signature(",
        ]
    );
    assert!(NORMAL_PROCESS.contains(
        "#[cfg(feature = \"fuzzing\")]\n    #[doc(hidden)]\n    pub fn fuzz_accept_bound_card("
    ));
    assert!(NORMAL_PROCESS.contains(
        "#[cfg(any(test, feature = \"legacy-normal-factor-fixture\"))]\n    pub fn accept_normal_factor("
    ));
    assert!(NORMAL_PROCESS.contains(
        "#[cfg(any(test, feature = \"legacy-normal-factor-fixture\"))]\n    pub fn reject_card("
    ));
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
fn product_sources_have_no_apdu_socket_logging_or_direct_secret_key_api() {
    let sources = [
        LIB,
        CAPABILITY,
        ERROR,
        IO_WIRE,
        KIT_ARTIFACT,
        KIT_INTAKE,
        KIT_RESTORE,
        KIT_SPEND,
        NORMAL_ARTIFACT,
        NORMAL_PROCESS,
        NORMAL,
        SESSION,
        SESSION_ID,
        SETUP,
        SETUP_ARTIFACT,
        SHA256,
        WIPE,
    ];
    for source in sources {
        for forbidden in [
            "qk_bip32",
            "qk_card_trace",
            "qk_host_model",
            "qk_host_sim",
            "qk_io::",
            "qk_update",
            "SecretKey",
            "PrivateKey",
            "SigningKey",
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
    assert!(CARD_PROCESS.contains("use qk_bip32::decode_mainnet_xpub;"));
    for forbidden in [
        "qk_card_trace",
        "qk_host_model",
        "qk_host_sim",
        "qk_io::",
        "qk_update",
        "SecretKey",
        "PrivateKey",
        "SigningKey",
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
        assert!(
            !CARD_PROCESS.contains(forbidden),
            "card process token {forbidden}"
        );
    }
    for source in [
        LIB,
        CAPABILITY,
        ERROR,
        IO_WIRE,
        KIT_ARTIFACT,
        KIT_INTAKE,
        KIT_RESTORE,
        KIT_SPEND,
        NORMAL_ARTIFACT,
        NORMAL_PROCESS,
        SESSION,
        SESSION_ID,
        SETUP,
        SETUP_ARTIFACT,
        SHA256,
        WIPE,
    ] {
        assert!(!source.contains("qk_secp"), "qk-secp escaped Normal owner");
    }
    for required in [
        "qk_secp::normalize_card_signature_der(",
        "qk_secp::signature_parse_der(",
        "qk_secp::pubkey_parse_compressed(",
        "qk_secp::ecdsa_verify(",
    ] {
        assert!(
            NORMAL.contains(required),
            "missing card verifier {required}"
        );
    }
    for forbidden in [
        "qk_secp::secret_key_import(",
        "qk_secp::ecdsa_sign_rfc6979(",
        "qk_secp::provisioning_pubkey_create(",
        "qk_secp::provisioning_secret_tweak_add(",
    ] {
        assert!(
            !NORMAL.contains(forbidden),
            "forbidden qk-secp use {forbidden}"
        );
    }
    assert_eq!(SETUP.matches("use qk_provisioning::{").count(), 1);
    assert_eq!(SETUP_ARTIFACT.matches("use qk_provisioning::{").count(), 2);
    assert_eq!(NORMAL.matches("use qk_descriptor::").count(), 1);
    assert_eq!(NORMAL.matches("use qk_psbt::{").count(), 1);
    assert_eq!(NORMAL.matches("use qk_wallet_v2::{").count(), 1);
    assert_eq!(NORMAL.matches("qk_a1::decrypt(").count(), 1);
    assert_eq!(NORMAL_ARTIFACT.matches("qk_bbqr::").count(), 2);
    assert_eq!(KIT_ARTIFACT.matches("use qk_bbqr::{").count(), 1);
    assert_eq!(
        KIT_ARTIFACT
            .matches("use qk_psbt::FinalizedNormalV3;")
            .count(),
        1
    );
    assert_eq!(KIT_INTAKE.matches("use qk_kit::{").count(), 1);
    assert_eq!(KIT_RESTORE.matches("use qk_kit::{").count(), 1);
    assert_eq!(KIT_SPEND.matches("use qk_kit::{").count(), 1);
    assert_eq!(CAPABILITY.matches("use qk_kit::{").count(), 1);
    assert_eq!(SESSION.matches("use qk_kit::{").count(), 1);
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

    let screen = owner_section(
        NORMAL,
        "pub enum NormalScreenV2<'a> {",
        "pub struct NormalApprovalTokenV2 {",
    );
    assert!(!screen.contains("ReviewV3"));
    assert!(!screen.contains("ValidatedNormalV3"));
    assert!(screen.contains("ReviewOverview(NormalOverviewViewV2)"));
    assert!(screen.contains("ReviewFeeFacts(NormalFeeFactsViewV2)"));
    assert!(screen.contains("FinalApproval(NormalFinalApprovalViewV2)"));

    let token = owner_section(
        NORMAL,
        "pub struct NormalApprovalTokenV2 {",
        "pub struct NormalApprovalIdentityV2 {",
    );
    assert!(token.contains("session_identity: [u8; 16]"));
    assert!(!token.contains("Debug"));
}

#[test]
fn unsafe_is_confined_to_the_existing_volatile_wipe_module() {
    assert!(LIB.contains("#![deny(unsafe_code)]"));
    assert_eq!(LIB.matches("#[allow(unsafe_code)]").count(), 1);
    assert!(LIB.contains("mod wipe;"));
    assert!(!CAPABILITY.contains("unsafe {"));
    assert!(!ERROR.contains("unsafe {"));
    assert!(!IO_WIRE.contains("unsafe {"));
    assert!(!KIT_ARTIFACT.contains("unsafe {"));
    assert!(!KIT_INTAKE.contains("unsafe {"));
    assert!(!KIT_RESTORE.contains("unsafe {"));
    assert!(!KIT_SPEND.contains("unsafe {"));
    assert!(!NORMAL_ARTIFACT.contains("unsafe {"));
    assert!(!NORMAL_PROCESS.contains("unsafe {"));
    assert!(!NORMAL.contains("unsafe {"));
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
            NORMAL,
            "pub struct NormalSessionV2 {",
            "impl NormalSessionV2",
        ),
        owner_section(
            NORMAL,
            "pub struct NormalCardBSigningRequestV2 {",
            "impl NormalCardBSigningRequestV2",
        ),
        owner_section(
            NORMAL_PROCESS,
            "pub struct NormalProcessControllerV2 {",
            "impl NormalProcessControllerV2",
        ),
        owner_section(
            KIT_INTAKE,
            "pub struct KitIntakeSessionV2 {",
            "impl KitIntakeSessionV2",
        ),
        owner_section(
            KIT_RESTORE,
            "pub struct KitRestoreSessionV2 {",
            "impl KitRestoreSessionV2",
        ),
        owner_section(
            KIT_RESTORE,
            "pub struct AuthorizedA1ReprintV2 {",
            "impl AuthorizedA1ReprintV2",
        ),
        owner_section(
            KIT_SPEND,
            "pub struct KitSpendSessionV2 {",
            "impl KitSpendSessionV2",
        ),
        owner_section(
            KIT_ARTIFACT,
            "pub struct KitDeliverySessionV2 {",
            "impl KitDeliverySessionV2",
        ),
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

#[test]
fn kit_delivery_is_raw_transaction_only_and_has_no_finalized_psbt_surface() {
    for source in [KIT_ARTIFACT, KIT_SPEND] {
        for forbidden in [
            "FinalizedPsbt",
            "FinalizedPSBT",
            "finalized_psbt",
            "PsbtExport",
        ] {
            assert!(
                !source.contains(forbidden),
                "Kit PSBT export surface {forbidden}"
            );
        }
    }
    assert!(KIT_ARTIFACT.contains("BbqrFileType::Transaction"));
    assert!(KIT_ARTIFACT.contains("KitExportActionV2::Sd"));
    assert!(KIT_ARTIFACT.contains("KitExportActionV2::Bbqr { non_final_part_len }"));
}
