#![cfg(feature = "host-runtime")]

use qk_ipc::{CoreEvent, CoreProtocol, StreamDecoder, HEADER_BYTES};
use std::io::{Read, Write};
use std::os::fd::OwnedFd;
use std::os::unix::net::UnixStream;
use std::process::{Command, Stdio};

const BINARY: &str = env!("CARGO_BIN_EXE_qk-io-host");
const PROCESS_BIN: &str = include_str!("../src/bin/qk-io-host.rs");
const SESSION: [u8; 16] = [0x5a; 16];

fn spawn_io(endpoint: UnixStream) -> std::process::Child {
    let input = endpoint.try_clone().expect("clone child endpoint");
    let input: OwnedFd = input.into();
    let output: OwnedFd = endpoint.into();
    Command::new(BINARY)
        .stdin(Stdio::from(input))
        .stdout(Stdio::from(output))
        .stderr(Stdio::null())
        .spawn()
        .expect("spawn io child")
}

fn write_control(stream: &mut UnixStream, outbound: qk_ipc::OutboundFrame) {
    let mut bytes = [0u8; HEADER_BYTES];
    let length = outbound.encode(&[], &mut bytes).expect("encode control");
    assert_eq!(length, HEADER_BYTES);
    stream.write_all(&bytes).expect("write control");
}

fn read_reply(stream: &mut UnixStream, decoder: &mut StreamDecoder) -> qk_ipc::ReceivedFrame {
    let mut byte = [0u8; 1];
    loop {
        stream.read_exact(&mut byte).expect("reply byte");
        let outcome = decoder.ingest(&byte, false).expect("decode reply");
        if outcome.frame_ready() {
            return decoder.take_frame().expect("take reply");
        }
    }
}

#[test]
fn real_broker_child_completes_the_exact_control_cycle() {
    let (mut core_stream, child_endpoint) = UnixStream::pair().expect("connected pair");
    let mut child = spawn_io(child_endpoint);
    let mut protocol = CoreProtocol::new(SESSION);
    let mut decoder = StreamDecoder::new();

    write_control(&mut core_stream, protocol.begin().expect("opening"));
    assert_eq!(
        protocol.accept(&read_reply(&mut core_stream, &mut decoder)),
        Ok(CoreEvent::SessionReady)
    );
    write_control(&mut core_stream, protocol.close().expect("closing"));
    assert_eq!(
        protocol.accept(&read_reply(&mut core_stream, &mut decoder)),
        Ok(CoreEvent::SessionClosed)
    );
    assert!(child.wait().expect("wait child").success());
}

#[test]
fn extra_argument_is_an_invocation_rejection() {
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
    assert_eq!(PROCESS_BIN.matches("ExitCode::SUCCESS").count(), 1);
    assert_eq!(PROCESS_BIN.matches("std::env::").count(), 1);
    assert!(!PROCESS_BIN.contains("var_os"));
}

#[test]
fn peer_loss_is_fail_closed_runtime_termination() {
    let (peer, child_endpoint) = UnixStream::pair().expect("connected pair");
    let mut child = spawn_io(child_endpoint);
    drop(peer);
    assert_eq!(child.wait().expect("wait child").code(), Some(70));
}
