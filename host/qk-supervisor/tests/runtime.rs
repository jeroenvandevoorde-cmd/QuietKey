#![cfg(all(
    feature = "host-runtime",
    any(target_os = "linux", target_os = "macos")
))]

use qk_supervisor::{
    parse_launcher_arguments, Child, LauncherInvocationError, MockGrantSet, ProcessLifecycle,
    ProcessLifecycleAction, ProcessLifecycleError, ProcessLifecycleEvent, ProcessLifecycleOutcome,
    ProcessLifecycleState,
};
use std::ffi::OsString;
use std::fs::{self, File};
use std::os::fd::AsRawFd;
use std::os::unix::ffi::OsStringExt;
use std::os::unix::fs::{symlink, PermissionsExt};
use std::os::unix::process::CommandExt;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};
use std::time::{Duration, Instant};

extern "C" {
    fn dup2(source: i32, target: i32) -> i32;
}

fn advanced(outcome: ProcessLifecycleOutcome) -> ProcessLifecycleAction {
    match outcome {
        ProcessLifecycleOutcome::Advanced(action) => action,
        ProcessLifecycleOutcome::FailedClosed(error, _) => {
            panic!("unexpected process failure: {error}")
        }
    }
}

#[test]
fn pure_process_lifecycle_locks_order_cleanup_and_no_restart() {
    let mut lifecycle = ProcessLifecycle::new();
    assert_eq!(lifecycle.state(), ProcessLifecycleState::DecoyRunning);
    assert_eq!(
        advanced(lifecycle.apply(ProcessLifecycleEvent::WalletSessionRequested)),
        ProcessLifecycleAction::TerminateDecoy
    );
    assert_eq!(
        advanced(lifecycle.apply(ProcessLifecycleEvent::DecoyReaped)),
        ProcessLifecycleAction::PrepareRuntime
    );
    assert_eq!(
        advanced(lifecycle.apply(ProcessLifecycleEvent::RuntimePrepared)),
        ProcessLifecycleAction::InstallProductGrants
    );
    assert_eq!(
        advanced(
            lifecycle.apply(ProcessLifecycleEvent::ProductGrantsInstalled(
                MockGrantSet::product(),
            ))
        ),
        ProcessLifecycleAction::EstablishConnection
    );
    assert_eq!(
        advanced(lifecycle.apply(ProcessLifecycleEvent::ConnectionAcceptedAndUnlinked)),
        ProcessLifecycleAction::StartProductChildren
    );
    assert_eq!(
        advanced(
            lifecycle.apply(ProcessLifecycleEvent::ProductChildrenStartedAndParentEndpointsClosed,)
        ),
        ProcessLifecycleAction::WaitForSession
    );
    assert_eq!(lifecycle.state(), ProcessLifecycleState::SessionActive);
    assert_eq!(
        advanced(lifecycle.apply(ProcessLifecycleEvent::SessionCompleted)),
        ProcessLifecycleAction::ReapProductChildren
    );
    assert_eq!(
        advanced(lifecycle.apply(ProcessLifecycleEvent::ProductChildrenReaped)),
        ProcessLifecycleAction::RemoveRuntime
    );
    assert_eq!(
        advanced(lifecycle.apply(ProcessLifecycleEvent::RuntimeRemoved)),
        ProcessLifecycleAction::None
    );
    assert_eq!(lifecycle.state(), ProcessLifecycleState::Terminated);
    assert_eq!(
        lifecycle.apply(ProcessLifecycleEvent::WalletSessionRequested),
        ProcessLifecycleOutcome::FailedClosed(
            ProcessLifecycleError::SessionTerminated,
            ProcessLifecycleAction::None,
        )
    );
}

#[test]
fn every_failure_latches_and_still_requires_reap_then_runtime_removal() {
    for (event, error) in [
        (
            ProcessLifecycleEvent::ChildLost(Child::Decoy),
            ProcessLifecycleError::ChildLost,
        ),
        (
            ProcessLifecycleEvent::ChildLost(Child::Core),
            ProcessLifecycleError::ChildLost,
        ),
        (
            ProcessLifecycleEvent::ChildLost(Child::Io),
            ProcessLifecycleError::ChildLost,
        ),
        (
            ProcessLifecycleEvent::ConnectionLost,
            ProcessLifecycleError::ConnectionLost,
        ),
        (
            ProcessLifecycleEvent::StepFailed,
            ProcessLifecycleError::StepFailed,
        ),
        (
            ProcessLifecycleEvent::CleanupFailed,
            ProcessLifecycleError::CleanupFailed,
        ),
    ] {
        let mut lifecycle = ProcessLifecycle::new();
        assert_eq!(
            lifecycle.apply(event),
            ProcessLifecycleOutcome::FailedClosed(error, ProcessLifecycleAction::TerminateChildren,)
        );
        assert_eq!(lifecycle.failure(), Some(error));
        assert_eq!(
            lifecycle.apply(ProcessLifecycleEvent::ProductChildrenReaped),
            ProcessLifecycleOutcome::FailedClosed(error, ProcessLifecycleAction::RemoveRuntime,)
        );
        assert_eq!(
            lifecycle.apply(ProcessLifecycleEvent::RuntimeRemoved),
            ProcessLifecycleOutcome::FailedClosed(error, ProcessLifecycleAction::None)
        );
        assert_eq!(lifecycle.state(), ProcessLifecycleState::Terminated);
    }

    let mut cleanup = ProcessLifecycle::new();
    assert_eq!(
        cleanup.apply(ProcessLifecycleEvent::ChildLost(Child::Core)),
        ProcessLifecycleOutcome::FailedClosed(
            ProcessLifecycleError::ChildLost,
            ProcessLifecycleAction::TerminateChildren,
        )
    );
    assert_eq!(
        cleanup.apply(ProcessLifecycleEvent::ProductChildrenReaped),
        ProcessLifecycleOutcome::FailedClosed(
            ProcessLifecycleError::ChildLost,
            ProcessLifecycleAction::RemoveRuntime,
        )
    );
    assert_eq!(
        cleanup.apply(ProcessLifecycleEvent::CleanupFailed),
        ProcessLifecycleOutcome::FailedClosed(
            ProcessLifecycleError::ChildLost,
            ProcessLifecycleAction::None,
        )
    );
    assert_eq!(cleanup.state(), ProcessLifecycleState::Terminated);
}

#[test]
fn cleanup_failure_after_reap_terminates_without_reterminating_children() {
    let mut lifecycle = ProcessLifecycle::new();
    for event in [
        ProcessLifecycleEvent::WalletSessionRequested,
        ProcessLifecycleEvent::DecoyReaped,
        ProcessLifecycleEvent::RuntimePrepared,
        ProcessLifecycleEvent::ProductGrantsInstalled(MockGrantSet::product()),
        ProcessLifecycleEvent::ConnectionAcceptedAndUnlinked,
        ProcessLifecycleEvent::ProductChildrenStartedAndParentEndpointsClosed,
        ProcessLifecycleEvent::SessionCompleted,
        ProcessLifecycleEvent::ProductChildrenReaped,
    ] {
        assert!(matches!(
            lifecycle.apply(event),
            ProcessLifecycleOutcome::Advanced(_)
        ));
    }
    assert_eq!(
        lifecycle.apply(ProcessLifecycleEvent::CleanupFailed),
        ProcessLifecycleOutcome::FailedClosed(
            ProcessLifecycleError::CleanupFailed,
            ProcessLifecycleAction::None,
        )
    );
    assert_eq!(lifecycle.state(), ProcessLifecycleState::Terminated);
}

#[test]
fn invocation_parser_accepts_only_two_utf8_arguments_and_an_absent_absolute_path() {
    let path = short_test_root("parser").join("parser-absent");
    let _ = fs::remove_file(&path);
    let _ = fs::remove_dir(&path);
    let parsed =
        parse_launcher_arguments([OsString::from("normal"), path.as_os_str().to_os_string()])
            .unwrap();
    assert_eq!(parsed.mode().argument(), "normal");
    assert_eq!(parsed.runtime_directory(), path);

    for (arguments, error) in [
        (vec![], LauncherInvocationError::MissingArgument),
        (
            vec![OsString::from("setup")],
            LauncherInvocationError::MissingArgument,
        ),
        (
            vec![OsString::from("other"), path.as_os_str().to_os_string()],
            LauncherInvocationError::UnknownMode,
        ),
        (
            vec![OsString::from("kit"), OsString::from("relative")],
            LauncherInvocationError::RuntimePathNotAbsolute,
        ),
        (
            vec![
                OsString::from("setup"),
                path.as_os_str().to_os_string(),
                OsString::from("extra"),
            ],
            LauncherInvocationError::TrailingArgument,
        ),
        (
            vec![OsString::from_vec(vec![0xff]), path.into_os_string()],
            LauncherInvocationError::NonUtf8Argument,
        ),
    ] {
        assert_eq!(parse_launcher_arguments(arguments).unwrap_err(), error);
    }
}

#[test]
fn actual_launcher_runs_all_modes_silently_and_fails_closed_on_each_child_or_connection_loss() {
    let root = short_test_root("integration");
    let _ = fs::remove_dir_all(&root);
    fs::create_dir_all(&root).unwrap();
    let binaries = build_product_binaries(&root);
    let supervisor = binaries.join("qk-supervisor-host");

    for mode in ["setup", "normal", "kit"] {
        assert_output(run_launcher(&supervisor, mode, &root), 0);
    }

    let preexisting = root.join("preexisting");
    fs::create_dir(&preexisting).unwrap();
    assert_output(
        Command::new(&supervisor)
            .arg("setup")
            .arg(&preexisting)
            .output()
            .unwrap(),
        64,
    );
    fs::remove_dir(&preexisting).unwrap();
    let symlink_path = root.join("symlink-runtime");
    symlink(&root, &symlink_path).unwrap();
    assert_output(
        Command::new(&supervisor)
            .arg("setup")
            .arg(&symlink_path)
            .output()
            .unwrap(),
        64,
    );
    fs::remove_file(&symlink_path).unwrap();
    assert_output(Command::new(&supervisor).output().unwrap(), 64);
    assert_output(
        Command::new(&supervisor)
            .arg("setup")
            .arg(root.join("extra-runtime"))
            .arg("extra")
            .output()
            .unwrap(),
        64,
    );

    replace_with_exec_failure_and_test_cleanup(&binaries, &supervisor, &root, "qk-core-host");

    let failing = compile_stub(&root, "failure", "fn main() { std::process::exit(70); }");
    replace_and_test_failure(&binaries, &supervisor, &root, "qk-decoy-host", &failing);
    replace_and_test_failure(&binaries, &supervisor, &root, "qk-core-host", &failing);
    replace_and_test_failure(&binaries, &supervisor, &root, "qk-io-host", &failing);

    let disconnect = compile_stub(
        &root,
        "disconnect",
        "use std::time::Duration; extern \"C\" { fn close(fd: i32) -> i32; } fn main() { unsafe { close(0); close(1); } std::thread::sleep(Duration::from_secs(30)); }",
    );
    replace_and_test_failure(&binaries, &supervisor, &root, "qk-io-host", &disconnect);

    let eof_seen = root.join("core-eof-seen");
    let eof_observer = compile_stub(
        &root,
        "eof-observer",
        &format!(
            "use std::io::Read; use std::os::fd::FromRawFd; fn main() {{ let mut socket = unsafe {{ std::os::unix::net::UnixStream::from_raw_fd(0) }}; let mut byte = [0u8; 1]; while socket.read(&mut byte).unwrap_or(0) != 0 {{}} std::fs::write({eof_seen:?}, b\"EOF\").unwrap(); std::process::exit(70); }}"
        ),
    );
    replace_two_and_test_failure(
        &binaries,
        &supervisor,
        &root,
        ("qk-core-host", &eof_observer),
        ("qk-io-host", &failing),
    );
    assert_eq!(fs::read(&eof_seen).unwrap(), b"EOF");

    let ignoring = compile_stub(
        &root,
        "ignoring",
        "extern \"C\" { fn signal(signal: i32, handler: usize) -> usize; } fn main() { unsafe { signal(15, 1); } loop { std::thread::park(); } }",
    );
    let started = Instant::now();
    replace_two_and_test_failure(
        &binaries,
        &supervisor,
        &root,
        ("qk-core-host", &ignoring),
        ("qk-io-host", &failing),
    );
    assert!(started.elapsed() >= Duration::from_millis(900));
    assert!(started.elapsed() < Duration::from_secs(2));

    exact_inherited_descriptors_and_pretraffic_unlink_are_observed(&binaries, &supervisor, &root);

    fs::remove_dir_all(&root).unwrap();
}

fn short_test_root(label: &str) -> PathBuf {
    PathBuf::from(format!("/tmp/qk-s8-{label}-{}", std::process::id()))
}

fn build_product_binaries(root: &Path) -> PathBuf {
    let target = root.join("target");
    let manifest = Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .unwrap()
        .join("Cargo.toml");
    let cargo = std::env::var_os("CARGO").unwrap_or_else(|| OsString::from("cargo"));
    let status = Command::new(cargo)
        .arg("build")
        .arg("--offline")
        .arg("--quiet")
        .arg("--manifest-path")
        .arg(manifest)
        .arg("--target-dir")
        .arg(&target)
        .arg("-p")
        .arg("qk-supervisor")
        .arg("-p")
        .arg("qk-decoy")
        .arg("-p")
        .arg("qk-core")
        .arg("-p")
        .arg("qk-io")
        .arg("--bins")
        .arg("--features")
        .arg("qk-supervisor/host-runtime,qk-core/host-runtime,qk-io/host-runtime")
        .status()
        .unwrap();
    assert!(status.success());
    target.join("debug")
}

fn compile_stub(root: &Path, name: &str, source: &str) -> PathBuf {
    let source_path = root.join(format!("{name}.rs"));
    let output_path = root.join(name);
    fs::write(&source_path, source).unwrap();
    let status = Command::new("rustc")
        .arg("--edition=2021")
        .arg("-Dwarnings")
        .arg(&source_path)
        .arg("-o")
        .arg(&output_path)
        .status()
        .unwrap();
    assert!(status.success());
    output_path
}

fn replace_and_test_failure(
    binaries: &Path,
    supervisor: &Path,
    root: &Path,
    child_name: &str,
    replacement: &Path,
) {
    let saved = replace_child(binaries, child_name, replacement);
    assert_output(run_launcher(supervisor, "normal", root), 70);
    restore_child(binaries, child_name, &saved);
}

fn replace_with_exec_failure_and_test_cleanup(
    binaries: &Path,
    supervisor: &Path,
    root: &Path,
    child_name: &str,
) {
    let child = binaries.join(child_name);
    let saved = binaries.join(format!("{child_name}.saved"));
    fs::rename(&child, &saved).unwrap();
    fs::write(&child, b"not-an-executable").unwrap();
    fs::set_permissions(&child, fs::Permissions::from_mode(0o700)).unwrap();
    assert_output(run_launcher(supervisor, "normal", root), 70);
    fs::remove_file(&child).unwrap();
    fs::rename(saved, child).unwrap();
}

fn replace_two_and_test_failure(
    binaries: &Path,
    supervisor: &Path,
    root: &Path,
    first: (&str, &Path),
    second: (&str, &Path),
) {
    let first_saved = replace_child(binaries, first.0, first.1);
    let second_saved = replace_child(binaries, second.0, second.1);
    assert_output(run_launcher(supervisor, "normal", root), 70);
    restore_child(binaries, first.0, &first_saved);
    restore_child(binaries, second.0, &second_saved);
}

fn replace_child(binaries: &Path, child_name: &str, replacement: &Path) -> PathBuf {
    let child = binaries.join(child_name);
    let saved = binaries.join(format!("{child_name}.saved"));
    fs::rename(&child, &saved).unwrap();
    fs::copy(replacement, child).unwrap();
    saved
}

fn restore_child(binaries: &Path, child_name: &str, saved: &Path) {
    let child = binaries.join(child_name);
    fs::remove_file(&child).unwrap();
    fs::rename(saved, child).unwrap();
}

fn run_launcher(supervisor: &Path, mode: &str, root: &Path) -> Output {
    let runtime = root.join(format!("runtime-{mode}"));
    let _ = fs::remove_dir(&runtime);
    let ambient = File::open("/dev/null").unwrap();
    let mut command = Command::new(supervisor);
    command.arg(mode).arg(&runtime);
    // SAFETY: the pre-exec closure invokes only dup2 and reports its error;
    // the low and high targets model ambient inherited descriptors.
    unsafe {
        command.pre_exec(move || {
            if dup2(ambient.as_raw_fd(), 9) < 0 || dup2(ambient.as_raw_fd(), 256) < 0 {
                Err(std::io::Error::last_os_error())
            } else {
                Ok(())
            }
        });
    }
    let output = command.output().unwrap();
    assert!(!runtime.exists());
    output
}

fn exact_inherited_descriptors_and_pretraffic_unlink_are_observed(
    binaries: &Path,
    supervisor: &Path,
    root: &Path,
) {
    let decoy_pid = root.join("decoy-pid");
    let decoy_ok = root.join("decoy-grants-ok");
    let core_ok = root.join("core-grants-ok");
    let io_ok = root.join("io-grants-ok");
    let runtime = root.join("runtime-normal");
    let decoy = compile_stub(
        root,
        "decoy-inspector",
        &descriptor_inspector_source("decoy", &decoy_ok, Some(&decoy_pid), None, &runtime),
    );
    let core = compile_stub(
        root,
        "core-inspector",
        &descriptor_inspector_source("core", &core_ok, None, Some(&decoy_pid), &runtime),
    );
    let io = compile_stub(
        root,
        "io-inspector",
        &descriptor_inspector_source("io", &io_ok, None, None, &runtime),
    );
    let decoy_saved = replace_child(binaries, "qk-decoy-host", &decoy);
    let core_saved = replace_child(binaries, "qk-core-host", &core);
    let io_saved = replace_child(binaries, "qk-io-host", &io);
    assert_output(run_launcher(supervisor, "normal", root), 0);
    restore_child(binaries, "qk-decoy-host", &decoy_saved);
    restore_child(binaries, "qk-core-host", &core_saved);
    restore_child(binaries, "qk-io-host", &io_saved);
    assert_eq!(fs::read(decoy_ok).unwrap(), b"PASS");
    assert_eq!(fs::read(core_ok).unwrap(), b"PASS");
    assert_eq!(fs::read(io_ok).unwrap(), b"PASS");
}

fn descriptor_inspector_source(
    role: &str,
    sentinel: &Path,
    write_pid: Option<&Path>,
    require_reaped_pid: Option<&Path>,
    runtime: &Path,
) -> String {
    let expected = match role {
        "decoy" => "[(3, 0), (4, 1)]",
        "core" => "[(0, 2), (1, 2), (3, 1), (4, 0), (5, 0), (6, 1)]",
        "io" => "[(0, 2), (1, 2), (3, 0), (4, 0), (5, 1), (6, 1)]",
        _ => unreachable!(),
    };
    let optional_null_descriptors = match role {
        "decoy" => "[0, 1, 2]",
        "core" | "io" => "[2]",
        _ => unreachable!(),
    };
    let required_null_descriptors = match role {
        "decoy" => "[3, 4]",
        "core" | "io" => "[3, 4, 5, 6]",
        _ => unreachable!(),
    };
    let pid_write = write_pid.map_or_else(String::new, |path| {
        format!("std::fs::write({path:?}, std::process::id().to_string()).unwrap();")
    });
    let pid_check = require_reaped_pid.map_or_else(String::new, |path| {
        format!(
            "let prior: i32 = std::fs::read_to_string({path:?}).unwrap().parse().unwrap(); ok &= unsafe {{ kill(prior, 0) }} < 0;"
        )
    });
    let socket_check = if role == "decoy" {
        String::new()
    } else {
        let socket = runtime.join("qkip.sock");
        format!(
            "ok &= std::path::Path::new({runtime:?}).is_dir(); ok &= !std::path::Path::new({socket:?}).exists(); ok &= std::os::unix::net::UnixStream::connect({socket:?}).is_err();"
        )
    };
    let endpoint_check = if role == "decoy" {
        String::new()
    } else {
        "let first = std::fs::metadata(\"/dev/fd/0\").unwrap(); let second = std::fs::metadata(\"/dev/fd/1\").unwrap(); ok &= first.dev() == second.dev() && first.ino() == second.ino(); let socket = unsafe { <std::os::unix::net::UnixStream as std::os::fd::FromRawFd>::from_raw_fd(0) }; ok &= socket.local_addr().is_ok() && socket.peer_addr().is_ok(); std::mem::forget(socket);".to_owned()
    };
    let is_decoy = role == "decoy";
    let failure = sentinel.with_extension("fail");
    format!(
        r#"use std::os::unix::fs::MetadataExt; extern "C" {{ fn fcntl(fd: i32, cmd: i32, ...) -> i32; fn kill(pid: i32, signal: i32) -> i32; }} fn open(fd: i32) -> bool {{ (unsafe {{ fcntl(fd, 1) }}) >= 0 }} fn mode(fd: i32) -> i32 {{ (unsafe {{ fcntl(fd, 3) }}) & 3 }} fn main() {{ let _kill_symbol = kill; let expected: &[(i32, i32)] = &{expected}; let optional_null: &[i32] = &{optional_null_descriptors}; let mut ok = true; let mut observed = String::new(); for fd in 0..=64 {{ if open(fd) {{ observed.push_str(&format!("{{fd}}:{{}},", mode(fd))); }} let wanted = expected.iter().find(|(candidate, _)| *candidate == fd); ok &= match wanted {{ Some((_, access)) => open(fd) && mode(fd) == *access, None if optional_null.contains(&fd) => !open(fd) || mode(fd) == 2, None => !open(fd), }}; }} let null = std::fs::metadata("/dev/null").unwrap(); for fd in {required_null_descriptors} {{ let actual = std::fs::metadata(format!("/dev/fd/{{fd}}")).unwrap(); ok &= actual.rdev() == null.rdev(); }} for fd in optional_null {{ if open(*fd) {{ let actual = std::fs::metadata(format!("/dev/fd/{{fd}}")).unwrap(); ok &= actual.rdev() == null.rdev(); }} }} {endpoint_check} {pid_check} {socket_check} if !ok {{ std::fs::write({failure:?}, observed).unwrap(); std::process::exit(70); }} {pid_write} std::fs::write({sentinel:?}, b"PASS").unwrap(); if {is_decoy} {{ loop {{ std::thread::park(); }} }} }}"#,
    )
}

fn assert_output(output: Output, status: i32) {
    assert_eq!(output.status.code(), Some(status));
    assert!(output.stdout.is_empty());
    assert!(output.stderr.is_empty());
}

#[test]
fn every_named_error_has_only_its_fixed_name() {
    for error in [
        ProcessLifecycleError::InvalidTransition,
        ProcessLifecycleError::DecoyNotReaped,
        ProcessLifecycleError::GrantConflict,
        ProcessLifecycleError::ChildLost,
        ProcessLifecycleError::ConnectionLost,
        ProcessLifecycleError::StepFailed,
        ProcessLifecycleError::CleanupFailed,
        ProcessLifecycleError::SessionTerminated,
    ] {
        assert_eq!(error.to_string(), format!("{error:?}"));
    }
    let path = short_test_root("named").join("named-error-absent");
    let _ = fs::remove_dir(&path);
    let invocation_errors = [
        LauncherInvocationError::MissingArgument,
        LauncherInvocationError::NonUtf8Argument,
        LauncherInvocationError::TrailingArgument,
        LauncherInvocationError::UnknownMode,
        LauncherInvocationError::RuntimePathNotAbsolute,
        LauncherInvocationError::RuntimePathSymlink,
        LauncherInvocationError::RuntimePathExists,
        LauncherInvocationError::RuntimePathInspectionFailed,
    ];
    for error in invocation_errors {
        assert_eq!(error.to_string(), format!("{error:?}"));
    }
}
