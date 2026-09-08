use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};
use std::sync::atomic::{AtomicU64, Ordering};

use qk_card_enrollment::{
    b6_exchange, B6Error, SittingError, SittingMode, B6_CAMPAIGN_SOURCE_COMMIT,
    B6_EXCHANGES_PER_SESSION, B6_MODE, B6_SESSION_COUNT, B6_SESSION_IDS, B6_SIGNATURES_PER_SESSION,
    B6_TOOL_VERSION, B6_TOTAL_EXCHANGES, B6_TOTAL_SIGNATURES, MANAGEMENT_OBSERVATION_TOOL_VERSION,
    MAX_SITTING_REQUEST_BYTES, SITTING_TOOL_VERSION,
};

const LIB: &str = include_str!("../src/lib.rs");
const MAIN: &str = include_str!("../src/main.rs");
const B6: &str = include_str!("../src/b6.rs");
const B6_TRANSCRIPT: &str = include_str!("../src/b6_transcript.rs");
const B6_ADAPTER: &str = include_str!("../src/pcsc_b6_adapter.rs");
const MANIFEST: &str = include_str!("../Cargo.toml");

const UTC: &str = "2026-09-07T12:34:56Z";
const READER_HEX: &str = "4964656e7469766520534352333378782076322e302055534220534320526561646572";

static NEXT_TEMP: AtomicU64 = AtomicU64::new(0);

#[test]
fn fixed_public_plan_has_ten_sessions_and_exactly_one_thousand_signatures() {
    assert_eq!(B6_MODE, "sign-golden");
    assert_eq!(B6_SESSION_COUNT, 10);
    assert_eq!(B6_SIGNATURES_PER_SESSION, 100);
    assert_eq!(B6_TOTAL_SIGNATURES, 1_000);
    assert_eq!(B6_EXCHANGES_PER_SESSION, 102);
    assert_eq!(B6_TOTAL_EXCHANGES, 1_020);
    assert_eq!(B6_SESSION_IDS.len(), B6_SESSION_COUNT);
    for (index, session_id) in B6_SESSION_IDS.iter().enumerate() {
        assert_eq!(*session_id, [0xc0 + u8::try_from(index).unwrap(); 16]);
    }

    let mut exchanges = 0usize;
    let mut signatures = 0usize;
    for session in 0..B6_SESSION_COUNT {
        for position in 0..B6_EXCHANGES_PER_SESSION {
            let exchange = b6_exchange(session, position).expect("registered B6 position");
            assert_eq!(exchange.session_index(), session);
            assert_eq!(exchange.position(), position);
            assert!(!exchange.request().is_empty());
            assert!(exchange.request().len() <= MAX_SITTING_REQUEST_BYTES);
            signatures += usize::from(exchange.input_index().is_some());
            exchanges += 1;
        }
    }
    assert_eq!(exchanges, B6_TOTAL_EXCHANGES);
    assert_eq!(signatures, B6_TOTAL_SIGNATURES);
    assert_eq!(
        b6_exchange(B6_SESSION_COUNT, 0),
        Err(B6Error::B6SequenceViolation)
    );
    assert_eq!(
        b6_exchange(0, B6_EXCHANGES_PER_SESSION),
        Err(B6Error::B6SequenceViolation)
    );
}

#[test]
fn card_facing_surface_is_one_private_fixed_plan_transmit() {
    assert_eq!(B6_ADAPTER.matches(".transmit(").count(), 1);
    assert!(B6_ADAPTER
        .contains("pub fn execute_pcsc_b6(metadata: B6Metadata) -> Result<B6Outcome, B6Error>"));
    assert!(!B6_ADAPTER.contains("pub struct"));
    assert!(!B6_ADAPTER.contains("println!("));
    assert!(!B6_ADAPTER.contains("eprintln!("));
    assert!(!B6.contains(".transmit("));
    assert!(!B6_TRANSCRIPT.contains(".transmit("));
    assert!(!MAIN.contains("caller-apdu"));
    assert!(!LIB.contains("pub use pcsc::"));
    for forbidden in [
        ".control(",
        ".get_attribute(",
        ".begin_transaction(",
        "pub fn card",
        "pub fn context",
    ] {
        assert!(!B6_ADAPTER.contains(forbidden));
    }
}

#[test]
fn every_production_source_excludes_private_signing_and_provisioning_operations() {
    let source_directory = Path::new(env!("CARGO_MANIFEST_DIR")).join("src");
    let mut pending = vec![source_directory];
    let mut paths = Vec::new();
    while let Some(directory) = pending.pop() {
        for entry in fs::read_dir(directory).expect("read production source directory") {
            let path = entry.expect("read production source entry").path();
            let metadata = fs::symlink_metadata(&path).expect("inspect production source entry");
            assert!(
                !metadata.file_type().is_symlink(),
                "source link: {}",
                path.display()
            );
            if metadata.is_dir() {
                pending.push(path);
            } else {
                assert!(
                    metadata.is_file(),
                    "non-file source entry: {}",
                    path.display()
                );
                paths.push(path);
            }
        }
    }
    paths.sort();
    assert!(!paths.is_empty());
    for path in paths {
        let bytes = fs::read(&path).expect("read production source file");
        let source = std::str::from_utf8(&bytes).expect("production source must be UTF-8");
        for forbidden in [
            concat!("ecdsa", "_sign_rfc6979"),
            concat!("secret", "_key_import"),
            concat!("provisioning", "_secret_tweak_add"),
        ] {
            assert!(
                !source.contains(forbidden),
                "forbidden operation in {}",
                path.display()
            );
        }
    }
}

#[test]
fn b6_is_not_a_legacy_sitting_mode_and_historical_versions_stay_literal() {
    assert_eq!(
        SittingMode::parse(B6_MODE),
        Err(SittingError::SittingModeRejected)
    );
    assert_eq!(SITTING_TOOL_VERSION, "0.0.4");
    assert_eq!(MANAGEMENT_OBSERVATION_TOOL_VERSION, "0.0.5");
    assert_eq!(B6_TOOL_VERSION, "0.0.7");
    assert!(LIB.contains("pub const SITTING_TOOL_VERSION: &str = \"0.0.4\";"));
    assert!(LIB.contains("pub const MANAGEMENT_OBSERVATION_TOOL_VERSION: &str = \"0.0.5\";"));
    assert!(MANIFEST.contains("version = \"0.0.8\""));
}

#[test]
fn cli_refuses_substitutions_and_existing_output_before_card_contact() {
    let directory = TempDirectory::new();
    let output_path = directory.path().join(expected_basename());

    let mut wrong_source = arguments(&output_path, &[]);
    wrong_source[1] = "1234567890abcdef1234567890abcdef12345678".to_owned();
    assert_named_refusal(
        &run_cli(&wrong_source),
        64,
        B6Error::B6BindingMismatch.name(),
    );
    assert!(!output_path.exists());

    let mut wrong_specimen = arguments(&output_path, &[]);
    wrong_specimen[5] = "J3R180-03".to_owned();
    assert_named_refusal(
        &run_cli(&wrong_specimen),
        64,
        B6Error::B6BindingMismatch.name(),
    );
    assert!(!output_path.exists());

    for extra in [
        "00a4040006f0514b32420100",
        "c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0",
        "fifth-command-field",
    ] {
        let refusal = run_cli(&arguments(&output_path, &[extra]));
        assert_eq!(refusal.status.code(), Some(64));
        assert!(refusal.stdout.is_empty());
        let stderr = String::from_utf8(refusal.stderr).unwrap();
        assert!(stderr.starts_with("usage: qk-card-enrollment"));
        assert!(!stderr.contains(extra));
        assert_no_private_facts(&stderr);
        assert!(!output_path.exists());
    }

    let sentinel = b"existing private output remains byte-identical\n";
    fs::write(&output_path, sentinel).unwrap();
    assert_named_refusal(
        &run_cli(&arguments(&output_path, &[])),
        1,
        B6Error::B6OutputCreateFailed.name(),
    );
    assert_eq!(fs::read(&output_path).unwrap(), sentinel);

    let command = MAIN
        .split_once("fn run_b6_command(")
        .expect("B6 command")
        .1
        .split_once("\nfn ")
        .expect("next command")
        .0;
    assert!(!command
        .lines()
        .any(|line| line.trim_start().starts_with("println!(")));
    assert!(!command.contains("{:?}"));
    assert!(!command.contains("B6RunSummary"));
}

fn arguments(output_path: &Path, extras: &[&str]) -> Vec<String> {
    let mut arguments = vec![
        "b6".to_owned(),
        B6_CAMPAIGN_SOURCE_COMMIT.to_owned(),
        UTC.to_owned(),
        "iMac".to_owned(),
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
        .expect("run bounded pre-contact B6 refusal")
}

fn assert_named_refusal(output: &Output, status: i32, name: &str) {
    assert_eq!(output.status.code(), Some(status));
    assert!(output.stdout.is_empty());
    let stderr = String::from_utf8(output.stderr.clone()).unwrap();
    assert_eq!(stderr, format!("result={name}\n"));
    assert_no_private_facts(&stderr);
}

fn assert_no_private_facts(output: &str) {
    for forbidden in [
        "r_hex",
        "signature_der",
        "response_hex",
        "wallet_id",
        "review_hash",
        "c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0",
    ] {
        assert!(!output.contains(forbidden));
    }
}

fn expected_basename() -> String {
    format!("qk-card-b6-v1__sign-golden__J3R180-02__{UTC}.txt")
}

struct TempDirectory(PathBuf);

impl TempDirectory {
    fn new() -> Self {
        let path = std::env::temp_dir().join(format!(
            "qk-card-b6-guard-{}-{}",
            std::process::id(),
            NEXT_TEMP.fetch_add(1, Ordering::Relaxed)
        ));
        fs::create_dir(&path).unwrap();
        Self(path)
    }

    fn path(&self) -> &Path {
        self.0.as_path()
    }
}

impl Drop for TempDirectory {
    fn drop(&mut self) {
        fs::remove_dir_all(&self.0).unwrap();
    }
}
