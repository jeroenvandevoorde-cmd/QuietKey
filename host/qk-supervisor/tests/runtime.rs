#![cfg(all(
    feature = "host-runtime",
    any(target_os = "linux", target_os = "macos")
))]

use qk_supervisor::{
    parse_launcher_arguments, Child, LauncherInvocationError, LauncherRuntimeError, MockGrantSet,
    ProcessLifecycle, ProcessLifecycleAction, ProcessLifecycleError, ProcessLifecycleEvent,
    ProcessLifecycleOutcome, ProcessLifecycleState,
};
use std::ffi::OsString;
use std::fs::{self, File};
use std::os::fd::{AsRawFd, FromRawFd};
use std::os::unix::ffi::OsStringExt;
use std::os::unix::fs::{symlink, PermissionsExt};
use std::os::unix::process::CommandExt;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};
use std::time::{Duration, Instant};

extern "C" {
    fn dup2(source: i32, target: i32) -> i32;
    fn pipe(descriptors: *mut i32) -> i32;
    fn kill(process: i32, signal: i32) -> i32;
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
fn peer_credential_rejection_names_are_stable() {
    assert_eq!(
        LauncherRuntimeError::SocketPeerCredentialUnavailable.to_string(),
        "SocketPeerCredentialUnavailable"
    );
    assert_eq!(
        LauncherRuntimeError::SocketPeerCredentialMismatch.to_string(),
        "SocketPeerCredentialMismatch"
    );
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
fn invocation_parser_locks_mode_specific_arguments_profiles_and_absent_absolute_path() {
    let path = short_test_root("parser").join("parser-absent");
    let _ = fs::remove_file(&path);
    let _ = fs::remove_dir(&path);
    let parsed = parse_launcher_arguments([
        OsString::from("normal"),
        OsString::from("01"),
        path.as_os_str().to_os_string(),
    ])
    .unwrap();
    assert_eq!(parsed.mode().argument(), "normal");
    assert_eq!(parsed.profile().unwrap().argument(), "01");
    assert_eq!(parsed.runtime_directory(), path);

    for (arguments, error) in [
        (vec![], LauncherInvocationError::MissingArgument),
        (
            vec![OsString::from("setup")],
            LauncherInvocationError::MissingArgument,
        ),
        (
            vec![
                OsString::from("normal"),
                OsString::from("04"),
                path.as_os_str().to_os_string(),
            ],
            LauncherInvocationError::UnknownProfile,
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

    for mode in ["setup", "kit"] {
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
            "use std::io::Read; use std::os::fd::FromRawFd; use std::time::Duration; fn main() {{ std::thread::sleep(Duration::from_millis(100)); let mut socket = unsafe {{ std::os::unix::net::UnixStream::from_raw_fd(0) }}; let mut byte = [0u8; 1]; while socket.read(&mut byte).unwrap_or(0) != 0 {{}} std::fs::write({eof_seen:?}, b\"EOF\").unwrap(); std::process::exit(70); }}"
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

    let panic_eof_seen = root.join("panic-eof-seen");
    let default_hook_panic = compile_stub(
        &root,
        "default-hook-panic",
        "use std::io::{Read, Write}; use std::os::fd::FromRawFd; fn main() { let mut socket = unsafe { std::os::unix::net::UnixStream::from_raw_fd(0) }; socket.write_all(b\"C\").unwrap(); let mut peer = [0u8; 1]; socket.read_exact(&mut peer).unwrap(); assert_eq!(peer, *b\"I\"); panic!(\"default-hook-panic\"); }",
    );
    let panic_eof_observer = compile_stub(
        &root,
        "panic-eof-observer",
        &format!(
            "use std::io::{{Read, Write}}; use std::os::fd::FromRawFd; fn main() {{ let mut socket = unsafe {{ std::os::unix::net::UnixStream::from_raw_fd(0) }}; socket.write_all(b\"I\").unwrap(); let mut peer = [0u8; 1]; socket.read_exact(&mut peer).unwrap(); assert_eq!(peer, *b\"C\"); let mut byte = [0u8; 1]; assert_eq!(socket.read(&mut byte).unwrap(), 0); std::fs::write({panic_eof_seen:?}, b\"EOF\").unwrap(); std::process::exit(70); }}"
        ),
    );
    replace_two_and_test_failure(
        &binaries,
        &supervisor,
        &root,
        ("qk-core-host", &default_hook_panic),
        ("qk-io-host", &panic_eof_observer),
    );
    assert_eq!(fs::read(&panic_eof_seen).unwrap(), b"EOF");

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
    command.arg(mode);
    let normal_pipes = if mode == "normal" {
        command.arg("01");
        Some(normal_device_pipes())
    } else {
        None
    };
    command.arg(&runtime);
    // SAFETY: the pre-exec closure invokes only dup2 and reports its error;
    // the low and high targets model ambient inherited descriptors.
    unsafe {
        command.pre_exec(move || {
            if dup2(ambient.as_raw_fd(), 256) < 0 {
                return Err(std::io::Error::last_os_error());
            }
            if let Some((_, sources)) = &normal_pipes {
                for (index, source) in sources.iter().enumerate() {
                    if dup2(source.as_raw_fd(), 7 + index as i32) < 0 {
                        return Err(std::io::Error::last_os_error());
                    }
                }
                Ok(())
            } else if dup2(ambient.as_raw_fd(), 9) < 0 {
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

fn normal_device_pipes() -> (Vec<(File, File)>, Vec<File>) {
    let mut pairs = Vec::with_capacity(8);
    for _ in 0..8 {
        let mut raw = [-1; 2];
        // SAFETY: `raw` names exactly two writable descriptor slots and each
        // successful result is transferred into one File owner.
        assert_eq!(unsafe { pipe(raw.as_mut_ptr()) }, 0);
        // SAFETY: each descriptor was newly returned by pipe and is owned once.
        let read = unsafe { File::from_raw_fd(raw[0]) };
        let write = unsafe { File::from_raw_fd(raw[1]) };
        pairs.push((read, write));
    }
    let sources = pairs
        .iter()
        .enumerate()
        .map(|(index, (read, write))| {
            if matches!(index, 0 | 3 | 6 | 7) {
                write.try_clone().unwrap()
            } else {
                read.try_clone().unwrap()
            }
        })
        .collect();
    (pairs, sources)
}
struct InspectorPrograms {
    saved: Vec<(&'static str, PathBuf)>,
}

impl InspectorPrograms {
    fn install(binaries: &Path, root: &Path) -> Self {
        let evidence = root.join("inspector-current");
        let runtime = root.join("runtime-normal");
        let mut saved = Vec::new();
        for (role, child) in [
            ("decoy", "qk-decoy-host"),
            ("core", "qk-core-host"),
            ("io", "qk-io-host"),
        ] {
            let source = format!(
                "const ROLE: &str = {role:?};\nconst EVIDENCE_ROOT: &str = {evidence:?};\nconst RUNTIME: &str = {runtime:?};\n{}",
                include_str!("support/descriptor_inspector.rs"),
            );
            let stub = compile_stub(root, &format!("{role}-inspector"), &source);
            saved.push((child, replace_child(binaries, child, &stub)));
        }
        Self { saved }
    }

    fn restore(self, binaries: &Path) {
        for (child, saved) in self.saved {
            restore_child(binaries, child, &saved);
        }
    }
}

struct InspectorCycle {
    directory: PathBuf,
    status: std::process::ExitStatus,
    passed: bool,
}

struct InspectorChild {
    child: std::process::Child,
    reaped: bool,
}

fn group_signal(id: u32, signal: i32) -> std::io::Result<()> {
    // SAFETY: id is the leader of the test-owned process group; signal zero
    // probes that group without delivering a signal.
    if unsafe { kill(-(id as i32), signal) } == 0 {
        Ok(())
    } else {
        Err(std::io::Error::last_os_error())
    }
}

fn group_absent(id: u32) -> bool {
    matches!(group_signal(id, 0), Err(error) if error.raw_os_error() == Some(3))
}

impl Drop for InspectorChild {
    fn drop(&mut self) {
        // Also runs on parent-test unwind; only this test's group is affected.
        if !group_absent(self.child.id()) {
            let _ = group_signal(self.child.id(), 9);
        }
        if !self.reaped {
            let _ = self.child.wait();
        }
    }
}

fn utc_now() -> String {
    let output = Command::new("date")
        .args(["-u", "+%Y-%m-%dT%H:%M:%SZ"])
        .output()
        .expect("UTC clock");
    assert!(output.status.success());
    String::from_utf8(output.stdout)
        .expect("ASCII clock")
        .trim()
        .to_owned()
}

fn inspector_cycle(
    supervisor: &Path,
    root: &Path,
    label: &str,
    injection: Option<&str>,
) -> InspectorCycle {
    use std::io::Write;
    use std::process::Stdio;

    let current = root.join("inspector-current");
    fs::create_dir(&current).expect("fresh evidence directory");
    if let Some(injection) = injection {
        fs::write(current.join("inject"), injection).unwrap();
    }
    let start = utc_now();
    let clock = Instant::now();
    let runtime = root.join("runtime-normal");
    let ambient = File::open("/dev/null").unwrap();
    let (_pairs, sources) = normal_device_pipes();
    let mut command = Command::new(supervisor);
    command.args(["normal", "01"]).arg(&runtime);
    command.stdout(Stdio::from(
        File::create(current.join("launcher.stdout")).unwrap(),
    ));
    command.stderr(Stdio::from(
        File::create(current.join("launcher.stderr")).unwrap(),
    ));
    command.process_group(0);
    // SAFETY: only dup2 runs between fork and exec; all sources remain owned.
    unsafe {
        command.pre_exec(move || {
            if dup2(ambient.as_raw_fd(), 256) < 0 {
                return Err(std::io::Error::last_os_error());
            }
            for (index, source) in sources.iter().enumerate() {
                if dup2(source.as_raw_fd(), 7 + index as i32) < 0 {
                    return Err(std::io::Error::last_os_error());
                }
            }
            Ok(())
        });
    }
    let mut child = InspectorChild {
        child: command.spawn().expect("inspector launcher spawn"),
        reaped: false,
    };
    let mut timed_out = false;
    let mut termination = String::new();
    let status = loop {
        if let Some(status) = child.child.try_wait().unwrap() {
            child.reaped = true;
            break status;
        }
        if clock.elapsed() >= Duration::from_secs(30) {
            timed_out = true;
            termination.push_str(&format!(
                "group_term\t{:?}\n",
                group_signal(child.child.id(), 15)
            ));
            std::thread::sleep(Duration::from_secs(1));
            termination.push_str(&format!(
                "group_kill\t{:?}\n",
                group_signal(child.child.id(), 9)
            ));
            let status = child.child.wait().unwrap();
            child.reaped = true;
            break status;
        }
        std::thread::sleep(Duration::from_millis(10));
    };
    let reap_wait = Instant::now();
    while !group_absent(child.child.id()) && reap_wait.elapsed() < Duration::from_secs(1) {
        std::thread::sleep(Duration::from_millis(10));
    }
    let group_gone = group_absent(child.child.id());
    if !group_gone {
        termination.push_str(&format!(
            "lingering_group_kill\t{:?}\n",
            group_signal(child.child.id(), 9)
        ));
        let cleanup_wait = Instant::now();
        while !group_absent(child.child.id()) && cleanup_wait.elapsed() < Duration::from_secs(1) {
            std::thread::sleep(Duration::from_millis(10));
        }
        assert!(
            group_absent(child.child.id()),
            "unreaped group; preserve untouched evidence at {}",
            current.display()
        );
    }
    let mut record = File::create(current.join("result.tsv")).unwrap();
    let source = Command::new("git")
        .args(["rev-parse", "HEAD"])
        .output()
        .unwrap();
    assert!(source.status.success());
    writeln!(
        record,
        "source_commit\t{}",
        String::from_utf8(source.stdout).unwrap().trim()
    )
    .unwrap();
    writeln!(record, "cycle\t{label}").unwrap();
    writeln!(record, "start_utc\t{start}").unwrap();
    writeln!(record, "end_utc\t{}", utc_now()).unwrap();
    writeln!(record, "elapsed_ms\t{}", clock.elapsed().as_millis()).unwrap();
    writeln!(record, "launcher_exit\t{status}").unwrap();
    writeln!(record, "timed_out\t{timed_out}").unwrap();
    writeln!(record, "process_group_absent\t{group_gone}").unwrap();
    record.write_all(termination.as_bytes()).unwrap();
    writeln!(record, "runtime_removed\t{}", !runtime.exists()).unwrap();
    let mut passed = status.success() && !timed_out && !runtime.exists() && group_gone;
    for role in ["decoy", "core", "io"] {
        for suffix in ["evidence", "stderr"] {
            let name = format!("{role}.{suffix}");
            let content = fs::read(current.join(&name));
            match content {
                Ok(bytes) => {
                    writeln!(record, "file\t{name}\tPRESENT\t{}", bytes.len()).unwrap();
                    if suffix == "evidence" {
                        passed &= bytes.ends_with(b"result\tPASS\n");
                    } else {
                        passed &= bytes.is_empty();
                    }
                }
                Err(error) => {
                    writeln!(record, "file\t{name}\tABSENT\t{error}").unwrap();
                    passed = false;
                }
            }
        }
    }
    for name in ["launcher.stdout", "launcher.stderr"] {
        let bytes = fs::read(current.join(name)).unwrap();
        writeln!(record, "file\t{name}\tPRESENT\t{}", bytes.len()).unwrap();
        passed &= bytes.is_empty();
    }
    writeln!(record, "result\t{}", if passed { "PASS" } else { "FAIL" }).unwrap();
    record.sync_all().unwrap();
    drop(record);
    if runtime.exists() {
        fs::rename(&runtime, current.join("runtime-residue"))
            .expect("preserve leftover runtime before next fresh cycle");
    }
    let directory = root.join(label);
    fs::rename(&current, &directory).expect("retain complete per-cycle evidence");
    InspectorCycle {
        directory,
        status,
        passed,
    }
}

fn exact_inherited_descriptors_and_pretraffic_unlink_are_observed(
    binaries: &Path,
    supervisor: &Path,
    root: &Path,
) {
    let programs = InspectorPrograms::install(binaries, root);
    let cycle = inspector_cycle(supervisor, root, "normal-inspector", None);
    programs.restore(binaries);
    assert!(
        cycle.passed,
        "inspector evidence retained at {}",
        cycle.directory.display()
    );
}

#[test]
fn inspector_named_failures_and_panic_keep_both_roles_and_stderr() {
    let root = short_test_root("inspector-faults");
    fs::create_dir_all(&root).unwrap();
    let binaries = build_product_binaries(&root);
    let supervisor = binaries.join("qk-supervisor-host");
    let programs = InspectorPrograms::install(&binaries, &root);
    for (label, injection, expected) in [
        ("core-failure", "core:forced-failure", "injected_failure"),
        ("io-failure", "io:forced-failure", "injected_failure"),
        ("core-panic", "core:panic", "unexpected_panic"),
    ] {
        let cycle = inspector_cycle(&supervisor, &root, label, Some(injection));
        assert!(!cycle.passed);
        assert_eq!(
            cycle.status.code(),
            Some(70),
            "{}",
            cycle.directory.display()
        );
        let failed_role = injection.split(':').next().unwrap();
        let evidence =
            fs::read_to_string(cycle.directory.join(format!("{failed_role}.evidence"))).unwrap();
        assert!(evidence.contains(expected), "{evidence}");
        let result = fs::read_to_string(cycle.directory.join("result.tsv")).unwrap();
        for role in ["core", "io"] {
            assert!(result.contains(&format!("file\t{role}.evidence\t")));
            assert!(result.contains(&format!("file\t{role}.stderr\t")));
        }
        if injection.ends_with(":panic") {
            let stderr = fs::read_to_string(cycle.directory.join("core.stderr")).unwrap();
            assert!(
                stderr.contains("qk163 injected inspector panic"),
                "{stderr}"
            );
        }
        assert!(fs::read(cycle.directory.join("launcher.stderr"))
            .unwrap()
            .is_empty());
    }
    programs.restore(&binaries);
    println!(
        "QK-DEC-163 injected failure evidence retained: {}",
        root.display()
    );
}

struct CpuWorkers(Vec<std::process::Child>);

impl Drop for CpuWorkers {
    fn drop(&mut self) {
        for child in &mut self.0 {
            let _ = child.kill();
            let _ = child.wait();
        }
    }
}

impl CpuWorkers {
    fn require_alive(&mut self) {
        for worker in &mut self.0 {
            assert!(
                worker.try_wait().unwrap().is_none(),
                "CPU worker exited early"
            );
        }
    }

    fn start(root: &Path) -> Self {
        let count = std::thread::available_parallelism().unwrap().get();
        let mut workers = Self(Vec::new());
        for index in 0..count {
            let ready = root.join(format!("cpu-worker-{index}.ready"));
            let child = Command::new(std::env::current_exe().unwrap())
                .args(["--ignored", "--exact", "inspector_cpu_worker"])
                .env("QK163_CPU_READY", &ready)
                .stdout(std::process::Stdio::null())
                .stderr(std::process::Stdio::null())
                .spawn()
                .unwrap();
            workers.0.push(child);
            let wait = Instant::now();
            while !ready.exists() {
                assert!(
                    wait.elapsed() < Duration::from_secs(10),
                    "CPU worker readiness"
                );
                assert!(workers.0.last_mut().unwrap().try_wait().unwrap().is_none());
                std::thread::sleep(Duration::from_millis(5));
            }
        }
        workers
    }
}

#[test]
#[ignore = "worker only for the Owner-bounded QK-DEC-163 diagnosis"]
fn inspector_cpu_worker() {
    let ready = std::env::var_os("QK163_CPU_READY").expect("diagnosis worker marker");
    let mut value = 1u64;
    for _ in 0..100_000 {
        value = std::hint::black_box(value.wrapping_mul(6364136223846793005).wrapping_add(1));
    }
    fs::write(ready, b"READY\n").unwrap();
    loop {
        value = std::hint::black_box(value.wrapping_mul(6364136223846793005).wrapping_add(1));
    }
}

#[test]
#[ignore = "run exactly once for the QK-DEC-163 50-unloaded/20-loaded diagnosis"]
fn inspector_diagnosis_50_unloaded_20_loaded() {
    use std::io::Write;
    let root = short_test_root("diagnosis-163");
    fs::create_dir(&root).expect("fresh diagnosis root; never overwrite prior runs");
    let source = Command::new("git")
        .args(["rev-parse", "HEAD"])
        .output()
        .unwrap();
    assert!(source.status.success());
    fs::write(root.join("source_commit"), &source.stdout).unwrap();
    for (name, program, arguments) in [
        ("machine.txt", "uname", vec!["-sm"]),
        ("rustc.txt", "rustc", vec!["--version", "--verbose"]),
        ("cargo.txt", "cargo", vec!["--version"]),
    ] {
        let output = Command::new(program).args(arguments).output().unwrap();
        assert!(output.status.success());
        fs::write(root.join(name), output.stdout).unwrap();
    }
    fs::write(
        root.join("logical-cpus.txt"),
        format!("{}\n", std::thread::available_parallelism().unwrap().get()),
    )
    .unwrap();
    let binaries = build_product_binaries(&root);
    let supervisor = binaries.join("qk-supervisor-host");
    let programs = InspectorPrograms::install(&binaries, &root);
    let mut listing = File::create(root.join("runs.tsv")).unwrap();
    writeln!(listing, "group\trun\tresult\tdirectory").unwrap();
    let mut failures = 0;
    for (group, count) in [("unloaded", 50), ("cpu-loaded", 20)] {
        let mut workers = if group == "cpu-loaded" {
            Some(CpuWorkers::start(&root))
        } else {
            None
        };
        let process_snapshot = Command::new("ps")
            .args(["-A", "-o", "pid,ppid,pcpu,comm"])
            .output()
            .unwrap();
        assert!(process_snapshot.status.success(), "process snapshot failed");
        fs::write(
            root.join(format!("{group}-processes.txt")),
            process_snapshot.stdout,
        )
        .unwrap();
        fs::write(
            root.join(format!("{group}-processes.stderr")),
            process_snapshot.stderr,
        )
        .unwrap();
        let load = Command::new("uptime").output().unwrap();
        assert!(load.status.success(), "load snapshot failed");
        fs::write(root.join(format!("{group}-load.txt")), load.stdout).unwrap();
        fs::write(
            root.join(format!("{group}-workers.txt")),
            format!(
                "{}\n",
                workers.as_ref().map_or(0, |workers| workers.0.len())
            ),
        )
        .unwrap();
        for index in 1..=count {
            if let Some(workers) = &mut workers {
                workers.require_alive();
            }
            let label = format!("{group}-{index:02}");
            let cycle = inspector_cycle(&supervisor, &root, &label, None);
            failures += usize::from(!cycle.passed);
            writeln!(
                listing,
                "{group}\t{index}\t{}\t{label}",
                if cycle.passed { "PASS" } else { "FAIL" }
            )
            .unwrap();
            listing.sync_all().unwrap();
        }
        if let Some(workers) = &mut workers {
            workers.require_alive();
        }
        drop(workers);
    }
    programs.restore(&binaries);
    println!("QK-DEC-163 evidence: {}", root.display());
    assert_eq!(
        failures,
        0,
        "all 70 outcomes retained at {}",
        root.display()
    );
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
        LauncherInvocationError::UnknownProfile,
        LauncherInvocationError::RuntimePathNotAbsolute,
        LauncherInvocationError::RuntimePathSymlink,
        LauncherInvocationError::RuntimePathExists,
        LauncherInvocationError::RuntimePathInspectionFailed,
    ];
    for error in invocation_errors {
        assert_eq!(error.to_string(), format!("{error:?}"));
    }
}
