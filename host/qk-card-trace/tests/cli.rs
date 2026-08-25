use std::io::Write;
use std::process::{Command, Output, Stdio};

const MOCK: &[u8] = include_bytes!("fixtures/mock_trace_v1.txt");
const MOCK_NAME: &str = "qk-card-trace-v1__MOCK-F8G0-D-001__MOCK-J3R180-001__20260825T120000Z.txt";

fn invoke(arguments: &[&str], input: &[u8]) -> Output {
    let mut child = Command::new(env!("CARGO_BIN_EXE_qk-card-trace"))
        .args(arguments)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn checker");
    child
        .stdin
        .as_mut()
        .expect("stdin")
        .write_all(input)
        .expect("write input");
    child.wait_with_output().expect("checker output")
}

fn stdout(output: &Output) -> String {
    String::from_utf8(output.stdout.clone()).expect("ASCII stdout")
}

#[test]
fn canonical_cli_output_contains_only_summary_identity_and_supplied_hash() {
    let output = invoke(&[MOCK_NAME, "4096", "16", "64", "32", "33"], MOCK);
    assert!(output.status.success());
    assert_eq!(
        stdout(&output),
        format!(
            "trace=PASS mode=MOCK records=3 atr=1 protocol=2 apdu_tx=0 apdu_rx=0\n\
             filename={MOCK_NAME}\n\
             raw_sha256=000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f\n"
        )
    );
    assert!(output.stderr.is_empty());
    for payload in ["3b00", "PROTOCOL 01", "PROTOCOL 0203"] {
        assert!(!stdout(&output).contains(payload));
    }
}

#[test]
fn failures_do_not_echo_trace_payload() {
    let output = invoke(&[MOCK_NAME, "16", "16", "64", "32", "33"], MOCK);
    assert_eq!(output.status.code(), Some(1));
    assert_eq!(stdout(&output), "trace=FAIL error=InputTooLarge\n");
    assert!(!stdout(&output).contains("3b00"));
}

#[test]
fn every_harness_control_is_mandatory_and_positive() {
    for arguments in [
        &[][..],
        &[MOCK_NAME][..],
        &[MOCK_NAME, "4096"][..],
        &[MOCK_NAME, "4096", "16"][..],
        &[MOCK_NAME, "4096", "16", "64"][..],
        &[MOCK_NAME, "4096", "16", "64", "32"][..],
        &[MOCK_NAME, "0", "16", "64", "32", "33"][..],
        &[MOCK_NAME, "4096", "0", "64", "32", "33"][..],
        &[MOCK_NAME, "4096", "16", "0", "32", "33"][..],
        &[MOCK_NAME, "4096", "16", "64", "0", "33"][..],
        &[MOCK_NAME, "4096", "16", "64", "32", "0"][..],
        &[MOCK_NAME, "4096", "16", "64", "32", "33", "extra"][..],
    ] {
        let output = invoke(arguments, b"");
        assert_eq!(output.status.code(), Some(64));
        assert!(output.stdout.is_empty());
        assert!(String::from_utf8(output.stderr)
            .unwrap()
            .starts_with("usage: qk-card-trace "));
    }
}
