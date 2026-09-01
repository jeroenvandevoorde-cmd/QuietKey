use qk_decoy::{CalculatorPhase, DecoyHostProcess};
use std::process::Command;

const BINARY: &str = env!("CARGO_BIN_EXE_qk-decoy-host");

#[test]
fn child_owner_starts_in_the_exact_cleared_calculator_state() {
    let process = DecoyHostProcess::new();
    assert_eq!(process.phase(), CalculatorPhase::Entry);
    assert_eq!(process.display().as_bytes(), b"0");
}

#[test]
fn every_argument_is_an_invocation_rejection() {
    let output = Command::new(BINARY)
        .arg("extra")
        .output()
        .expect("extra argument");
    assert_eq!(output.status.code(), Some(64));
    assert!(output.stdout.is_empty() && output.stderr.is_empty());
}
