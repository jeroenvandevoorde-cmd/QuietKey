use qk_decoy::{CalculatorPhase, DecoyHostProcess};
use std::process::Command;

const BINARY: &str = env!("CARGO_BIN_EXE_qk-decoy-host");
const PROCESS_BIN: &str = include_str!("../src/bin/qk-decoy-host.rs");

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

#[test]
fn binary_has_the_exact_silent_unwind_boundary_and_closed_status_set() {
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
    assert_eq!(
        PROCESS_BIN
            .matches("std::panic::set_hook(Box::new(|_| {}));")
            .count(),
        1
    );
    assert_eq!(
        PROCESS_BIN
            .matches("match std::panic::catch_unwind(run) {")
            .count(),
        1
    );
    assert!(PROCESS_BIN.contains("Ok(status) => status,"));
    assert!(PROCESS_BIN.contains("Err(_) => ExitCode::from(RUNTIME_TERMINATED),"));
    assert_eq!(PROCESS_BIN.matches("std::env::").count(), 1);
    assert!(!PROCESS_BIN.contains("var_os"));
}
