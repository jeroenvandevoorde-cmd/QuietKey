#![cfg(feature = "host-runtime")]

use qk_ipc::{IoEvent, IoProtocol, OutboundFrame, StreamDecoder, HEADER_BYTES};
use std::io::{Read, Write};
use std::os::fd::OwnedFd;
use std::os::unix::ffi::OsStringExt;
use std::os::unix::net::UnixStream;
use std::process::{Command, ExitStatus, Stdio};

const BINARY: &str = env!("CARGO_BIN_EXE_qk-core-host");
const PROCESS_BIN: &str = include_str!("../src/bin/qk-core-host.rs");

fn encode_control(frame: OutboundFrame) -> [u8; HEADER_BYTES] {
    let mut bytes = [0u8; HEADER_BYTES];
    let length = frame.encode(&[], &mut bytes).expect("encode control");
    assert_eq!(length, HEADER_BYTES);
    bytes
}

fn read_frame(stream: &mut UnixStream, decoder: &mut StreamDecoder) -> qk_ipc::ReceivedFrame {
    let mut byte = [0u8; 1];
    loop {
        stream.read_exact(&mut byte).expect("child frame byte");
        let outcome = decoder.ingest(&byte, false).expect("decode child frame");
        if outcome.frame_ready() {
            return decoder.take_frame().expect("take child frame");
        }
    }
}

fn child_command(mode: &str, profile: Option<&str>, endpoint: UnixStream) -> std::process::Child {
    let input = endpoint.try_clone().expect("clone child endpoint");
    let input: OwnedFd = input.into();
    let output: OwnedFd = endpoint.into();
    let mut command = Command::new(BINARY);
    command.arg(mode);
    if let Some(profile) = profile {
        command.arg(profile);
    }
    command
        .stdin(Stdio::from(input))
        .stdout(Stdio::from(output))
        .stderr(Stdio::null())
        .spawn()
        .expect("spawn core child")
}

fn complete_cycle(mode: &str) -> ExitStatus {
    let (mut peer, child_endpoint) = UnixStream::pair().expect("connected pair");
    let mut child = child_command(mode, None, child_endpoint);
    let mut protocol = IoProtocol::new();
    let mut decoder = StreamDecoder::new();

    let opening = read_frame(&mut peer, &mut decoder);
    assert_eq!(protocol.accept(&opening), Ok(IoEvent::SessionOpen));
    peer.write_all(&encode_control(protocol.reply().expect("ready reply")))
        .expect("write ready");

    let closing = read_frame(&mut peer, &mut decoder);
    assert_eq!(protocol.accept(&closing), Ok(IoEvent::SessionClose));
    peer.write_all(&encode_control(protocol.reply().expect("closed reply")))
        .expect("write closed");
    child.wait().expect("wait child")
}

#[test]
fn setup_and_kit_exact_modes_complete_real_control_cycles() {
    for mode in ["setup", "kit"] {
        assert!(complete_cycle(mode).success(), "mode {mode}");
    }
}

#[test]
fn missing_unknown_and_extra_arguments_are_invocation_rejections() {
    let missing = Command::new(BINARY).output().expect("missing argument");
    assert_eq!(missing.status.code(), Some(64));
    assert!(missing.stdout.is_empty() && missing.stderr.is_empty());
    let unknown = Command::new(BINARY)
        .arg("other")
        .output()
        .expect("unknown argument");
    assert_eq!(unknown.status.code(), Some(64));
    assert!(unknown.stdout.is_empty() && unknown.stderr.is_empty());
    let extra = Command::new(BINARY)
        .args(["setup", "extra"])
        .output()
        .expect("extra argument");
    assert_eq!(extra.status.code(), Some(64));
    assert!(extra.stdout.is_empty() && extra.stderr.is_empty());
    let non_utf8 = Command::new(BINARY)
        .arg(std::ffi::OsString::from_vec(vec![0xff]))
        .output()
        .expect("non-UTF-8 argument");
    assert_eq!(non_utf8.status.code(), Some(64));
    assert!(non_utf8.stdout.is_empty() && non_utf8.stderr.is_empty());

    for arguments in [
        vec!["normal"],
        vec!["normal", "00"],
        vec!["normal", "01", "extra"],
    ] {
        let rejected = Command::new(BINARY)
            .args(arguments)
            .output()
            .expect("rejected Normal invocation");
        assert_eq!(rejected.status.code(), Some(64));
        assert!(rejected.stdout.is_empty() && rejected.stderr.is_empty());
    }
}

#[test]
fn exact_normal_profiles_pass_invocation_and_fail_closed_without_device_grants() {
    for profile in ["01", "02", "03"] {
        let output = Command::new(BINARY)
            .args(["normal", profile])
            .output()
            .expect("normal invocation");
        assert_eq!(output.status.code(), Some(70));
        assert!(output.stdout.is_empty() && output.stderr.is_empty());
    }
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
    assert_eq!(PROCESS_BIN.matches("ExitCode::SUCCESS").count(), 1);
    assert_eq!(PROCESS_BIN.matches("std::env::").count(), 1);
    assert!(!PROCESS_BIN.contains("var_os"));
}

#[test]
fn peer_loss_is_fail_closed_runtime_termination() {
    let (peer, child_endpoint) = UnixStream::pair().expect("connected pair");
    let mut child = child_command("setup", None, child_endpoint);
    drop(peer);
    assert_eq!(child.wait().expect("wait child").code(), Some(70));
}
