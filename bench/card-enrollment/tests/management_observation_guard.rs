use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};
use std::sync::atomic::{AtomicU64, Ordering};

use qk_card_enrollment::{
    SittingError, SittingMode, INITIALIZE_UPDATE_COMMAND, KEY_INFORMATION_TEMPLATE_COMMAND,
    MANAGEMENT_CARD_RECOGNITION_COMMAND, MANAGEMENT_OBSERVATION_TOOL_VERSION, SELECT_ISD_COMMAND,
    SITTING_TOOL_VERSION,
};

const LIB: &str = include_str!("../src/lib.rs");
const MAIN: &str = include_str!("../src/main.rs");
const OBSERVATION: &str = include_str!("../src/management_observation.rs");
const OBSERVATION_TRANSCRIPT: &str = include_str!("../src/management_observation_transcript.rs");
const OBSERVATION_ADAPTER: &str = include_str!("../src/pcsc_management_observation_adapter.rs");
const SITTING: &str = include_str!("../src/sitting.rs");
const MANIFEST: &str = include_str!("../Cargo.toml");

const TOOL_SOURCE: &str = "1234567890abcdef1234567890abcdef12345678";
const UTC: &str = "2026-09-07T01:02:03Z";
const READER_HEX: &str = "4964656e7469766520534352333378782076322e302055534220534320526561646572";

static NEXT_TEMP: AtomicU64 = AtomicU64::new(0);

#[test]
fn fixed_table_is_the_only_four_command_surface_in_exact_order() {
    assert_eq!(
        SELECT_ISD_COMMAND,
        [0x00, 0xa4, 0x04, 0x00, 0x08, 0xa0, 0x00, 0x00, 0x01, 0x51, 0x00, 0x00, 0x00, 0x00,]
    );
    assert_eq!(
        MANAGEMENT_CARD_RECOGNITION_COMMAND,
        [0x80, 0xca, 0x00, 0x66, 0x00]
    );
    assert_eq!(
        INITIALIZE_UPDATE_COMMAND,
        [0x80, 0x50, 0x00, 0x00, 0x08, 0x51, 0x4b, 0x46, 0x38, 0x42, 0x33, 0x56, 0x31, 0x00,]
    );
    assert_eq!(
        KEY_INFORMATION_TEMPLATE_COMMAND,
        [0x80, 0xca, 0x00, 0xe0, 0x00]
    );

    let table = OBSERVATION
        .split_once("const FIXED_COMMANDS: [FixedCommand; 4]")
        .expect("fixed four-command table")
        .1;
    let select = table.find("request: &SELECT_ISD_COMMAND").expect("SELECT");
    let recognition = table
        .find("request: &MANAGEMENT_CARD_RECOGNITION_COMMAND")
        .expect("Card Recognition Data");
    let initialize = table
        .find("request: &INITIALIZE_UPDATE_COMMAND")
        .expect("INITIALIZE UPDATE");
    let key_information = table
        .find("request: &KEY_INFORMATION_TEMPLATE_COMMAND")
        .expect("E0 Key Information Template");
    assert!(select < recognition && recognition < initialize && initialize < key_information);
    assert_eq!(OBSERVATION.matches("backend.exchange(").count(), 1);
    assert_eq!(OBSERVATION_ADAPTER.matches(".transmit(").count(), 1);
    assert!(!OBSERVATION_ADAPTER.contains("pub struct PcscManagementObservationBackend"));
    assert!(!LIB.contains("pub use pcsc::"));

    for source in [
        OBSERVATION,
        OBSERVATION_TRANSCRIPT,
        OBSERVATION_ADAPTER,
        MAIN,
    ] {
        for forbidden in [
            "EXTERNAL_AUTHENTICATE",
            "ExternalAuthenticate",
            "external_authenticate",
            "session_key",
            "private_key",
            "caller_apdu",
            "transmit2(",
            "resize(",
            "retry",
            "resend",
        ] {
            assert!(
                !source.contains(forbidden),
                "forbidden observation construct: {forbidden}"
            );
        }
    }
}

#[test]
fn live_adapter_returns_only_an_outcome_and_console_paths_are_name_only() {
    assert!(OBSERVATION_ADAPTER.contains(
        "pub fn execute_pcsc_management_observation(\n    metadata: ManagementObservationMetadata,\n) -> Result<ObservationOutcome, ObservationError>"
    ));
    assert!(!OBSERVATION_ADAPTER.contains("ObservationSummary"));
    assert!(!OBSERVATION_ADAPTER.contains("println!("));
    assert!(!OBSERVATION_ADAPTER.contains("eprintln!("));

    let command = MAIN
        .split_once("fn run_management_observation_command(")
        .expect("observation command")
        .1
        .split_once("\nfn run_sitting_command(")
        .expect("next command")
        .0;
    assert!(!command
        .lines()
        .any(|line| line.trim_start().starts_with("println!(")));
    assert!(!command.contains("{:?}"));
    assert!(!command.contains("ObservationSummary"));
    assert_eq!(
        command
            .matches("eprintln!(\"result={}\", error.name())")
            .count(),
        2
    );
}

#[test]
fn management_mode_does_not_change_the_two_frozen_sitting_modes_or_versions() {
    assert_eq!(
        SittingMode::parse("management-observe"),
        Err(SittingError::SittingModeRejected)
    );
    assert_eq!(SITTING_TOOL_VERSION, "0.0.4");
    assert_eq!(MANAGEMENT_OBSERVATION_TOOL_VERSION, "0.0.5");
    assert!(LIB.contains("pub const SITTING_TOOL_VERSION: &str = \"0.0.4\";"));
    assert!(MANIFEST.contains("version = \"0.0.5\""));
    assert!(!SITTING.contains("ManagementObserve"));
    assert!(!SITTING.contains("management-observe"));
    assert!(MAIN.contains("if sitting_name == \"management-observe\""));
}

#[test]
fn cli_rejects_wrong_binding_and_extra_command_material_before_contact() {
    let directory = TempDirectory::new();
    let output_path = directory.path().join(expected_basename());

    let mut wrong_binding_arguments = arguments(&output_path, "iMac", &[]);
    wrong_binding_arguments[6] = "J3R180-03".to_owned();
    let wrong_binding = run_cli(&wrong_binding_arguments);
    assert_named_refusal(&wrong_binding, 64, "SittingBindingMismatch");
    assert!(!output_path.exists());

    for extra in [
        "00a4040008a00000015100000000",
        "514b463842335631",
        "80ca00e000",
    ] {
        let refusal = run_cli(&arguments(&output_path, "iMac", &[extra]));
        assert_eq!(refusal.status.code(), Some(64));
        assert!(refusal.stdout.is_empty());
        let stderr = String::from_utf8(refusal.stderr).expect("ASCII usage");
        assert!(stderr.starts_with("usage: qk-card-enrollment"));
        assert!(!stderr.contains(extra));
        assert_no_private_observation(&stderr);
        assert!(!output_path.exists());
    }
}

#[test]
fn valid_metadata_with_an_existing_output_stops_before_pcsc() {
    let directory = TempDirectory::new();
    let output_path = directory.path().join(expected_basename());
    let sentinel = b"existing private output remains byte-identical\n";
    fs::write(&output_path, sentinel).expect("existing output");

    let refusal = run_cli(&arguments(&output_path, "iMac", &[]));
    assert_named_refusal(&refusal, 1, "SittingOutputCreateFailed");
    assert_eq!(fs::read(&output_path).expect("retained output"), sentinel);

    let execute = OBSERVATION_ADAPTER
        .split_once("pub fn execute_pcsc_management_observation(")
        .expect("live entry")
        .1
        .split_once("\n}\n\n#[derive(Default)]")
        .expect("entry extent")
        .0;
    let open = execute
        .find("open_observation_output(metadata.output_path())?")
        .expect("create-new output first");
    let backend = execute
        .find("PcscManagementObservationBackend::default()")
        .expect("PC/SC backend");
    assert!(open < backend);
}

fn arguments(output_path: &Path, host_alias: &str, extras: &[&str]) -> Vec<String> {
    let mut arguments = vec![
        "sitting".to_owned(),
        "management-observe".to_owned(),
        TOOL_SOURCE.to_owned(),
        UTC.to_owned(),
        host_alias.to_owned(),
        "SCR3310-01".to_owned(),
        "J3R180-02".to_owned(),
        READER_HEX.to_owned(),
        output_path.display().to_string(),
    ];
    arguments.extend(extras.iter().map(|value| (*value).to_owned()));
    arguments
}

fn run_cli(arguments: &[String]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_qk-card-enrollment"))
        .args(arguments)
        .output()
        .expect("run bounded pre-contact CLI refusal")
}

fn assert_named_refusal(output: &Output, status: i32, name: &str) {
    assert_eq!(output.status.code(), Some(status));
    assert!(output.stdout.is_empty());
    let stderr = String::from_utf8(output.stderr.clone()).expect("ASCII named refusal");
    assert_eq!(stderr, format!("result={name}\n"));
    assert_no_private_observation(&stderr);
}

fn assert_no_private_observation(output: &str) {
    for forbidden in [
        "key_version",
        "scp_i",
        "cryptogram",
        "exchange.",
        "a000000151000000",
        "514b463842335631",
    ] {
        assert!(
            !output.contains(forbidden),
            "private console field: {forbidden}"
        );
    }
}

fn expected_basename() -> String {
    format!("qk-card-sitting-v1__management-observe__J3R180-02__{UTC}.txt")
}

struct TempDirectory(PathBuf);

impl TempDirectory {
    fn new() -> Self {
        let path = std::env::temp_dir().join(format!(
            "qk-management-observation-guard-{}-{}",
            std::process::id(),
            NEXT_TEMP.fetch_add(1, Ordering::Relaxed)
        ));
        fs::create_dir(&path).expect("create bounded temporary directory");
        Self(path)
    }

    fn path(&self) -> &Path {
        self.0.as_path()
    }
}

impl Drop for TempDirectory {
    fn drop(&mut self) {
        fs::remove_dir_all(&self.0).expect("remove bounded temporary directory");
    }
}
