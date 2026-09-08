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
use std::io::Write;
use std::os::fd::{AsRawFd, FromRawFd};
use std::os::unix::ffi::OsStringExt;
use std::os::unix::fs::{symlink, PermissionsExt};
use std::os::unix::process::{CommandExt, ExitStatusExt};
use std::path::{Path, PathBuf};
use std::process::{Command, ExitStatus, Output, Stdio};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

extern "C" {
    fn dup2(source: i32, target: i32) -> i32;
    fn pipe(descriptors: *mut i32) -> i32;
    fn kill(process: i32, signal: i32) -> i32;
    fn signal(signal: i32, handler: usize) -> usize;
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
    fs::create_dir(&root).unwrap();
    let binaries = build_product_binaries(&root);
    let supervisor = binaries.join("qk-supervisor-host");

    for mode in ["setup", "kit"] {
        assert_output(run_launcher(&supervisor, mode, &root, mode), 0);
    }

    let preexisting = root.join("preexisting");
    fs::create_dir(&preexisting).unwrap();
    assert_output(
        checked_command(
            Command::new(&supervisor).arg("setup").arg(&preexisting),
            &root,
            "preexisting-runtime",
            &preexisting,
        ),
        64,
    );
    fs::remove_dir(&preexisting).unwrap();
    let symlink_path = root.join("symlink-runtime");
    symlink(&root, &symlink_path).unwrap();
    assert_output(
        checked_command(
            Command::new(&supervisor).arg("setup").arg(&symlink_path),
            &root,
            "symlink-runtime",
            &symlink_path,
        ),
        64,
    );
    fs::remove_file(&symlink_path).unwrap();
    assert_output(
        checked_command(
            &mut Command::new(&supervisor),
            &root,
            "missing-arguments",
            &root.join("missing-runtime"),
        ),
        64,
    );
    assert_output(
        checked_command(
            Command::new(&supervisor)
                .arg("setup")
                .arg(root.join("extra-runtime"))
                .arg("extra"),
            &root,
            "extra-argument",
            &root.join("extra-runtime"),
        ),
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
        "use std::time::Duration; extern \"C\" { fn close(fd: i32) -> i32; } fn main() { unsafe { close(0); close(1); } std::thread::sleep(Duration::from_secs(5)); }",
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
    let nonce = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    PathBuf::from(format!("/tmp/qk-s8-{label}-{}-{nonce}", std::process::id()))
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
    let label = format!(
        "replace-{child_name}-{}",
        replacement.file_name().unwrap().to_string_lossy()
    );
    assert_output(run_launcher(supervisor, "normal", root, &label), 70);
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
    assert_output(
        run_launcher(supervisor, "normal", root, "core-exec-failure"),
        70,
    );
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
    let label = format!(
        "pair-{}-{}",
        first.1.file_name().unwrap().to_string_lossy(),
        second.1.file_name().unwrap().to_string_lossy()
    );
    assert_output(run_launcher(supervisor, "normal", root, &label), 70);
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

fn run_launcher(supervisor: &Path, mode: &str, root: &Path, label: &str) -> HarnessOutput {
    let runtime = root.join(format!("runtime-{mode}"));
    assert!(
        !runtime.exists(),
        "prior runtime retained at {}",
        runtime.display()
    );
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
    let output = checked_command(&mut command, root, label, &runtime);
    assert!(
        !runtime.exists(),
        "runtime residue; evidence {}",
        output.directory.display()
    );
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

const LAUNCHER_DEADLINE: Duration = Duration::from_secs(30);
const LAUNCHER_POLL: Duration = Duration::from_millis(10);
const CLEANUP_PHASE: Duration = Duration::from_secs(1);
static CYCLE_NUMBER: AtomicU64 = AtomicU64::new(0);

#[derive(Debug)]
struct HarnessOutput {
    output: Output,
    directory: PathBuf,
}

#[derive(Debug)]
struct HarnessFailure {
    name: &'static str,
    cleanup_failed: bool,
    directory: PathBuf,
}

enum ReadyAction<'a> {
    None,
    Expire(&'a Path),
    Unwind(&'a Path),
}

struct HarnessChild {
    child: std::process::Child,
    status: Option<ExitStatus>,
    finished: bool,
    clock: Instant,
    evidence: File,
    directory: PathBuf,
    root: PathBuf,
    runtime: PathBuf,
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

impl HarnessChild {
    fn poll_reaped_and_absent(&mut self) -> bool {
        if self.status.is_none() {
            match self.child.try_wait() {
                Ok(status) => self.status = status,
                Err(error) => {
                    let _ = writeln!(self.evidence, "cleanup_try_wait_error\t{error}");
                }
            }
        }
        self.status.is_some() && group_absent(self.child.id())
    }

    fn cleanup(&mut self) -> bool {
        if self.poll_reaped_and_absent() {
            return true;
        }
        for (name, signal) in [("group_term", 15), ("group_kill", 9)] {
            let result = group_signal(self.child.id(), signal);
            let _ = writeln!(self.evidence, "{name}\t{result:?}");
            let phase = Instant::now();
            loop {
                if self.poll_reaped_and_absent() {
                    return true;
                }
                if phase.elapsed() >= CLEANUP_PHASE {
                    break;
                }
                std::thread::sleep(LAUNCHER_POLL);
            }
        }
        self.poll_reaped_and_absent()
    }

    fn finish(
        &mut self,
        mut first_failure: Option<&'static str>,
    ) -> Result<HarnessOutput, HarnessFailure> {
        if first_failure.is_none() && self.status.is_some() && !group_absent(self.child.id()) {
            first_failure = Some("LauncherHarnessDescendantsRemain");
        }
        let cleaned = self.cleanup();
        if !cleaned && first_failure.is_none() {
            first_failure = Some("LauncherHarnessCleanupFailed");
        }
        // If cleanup failed, a surviving writer may still append. Retain its
        // files without reading to EOF; the original failure remains primary.
        let stdout = if cleaned {
            fs::read(self.directory.join("launcher.stdout"))
        } else {
            Ok(Vec::new())
        };
        let stderr = if cleaned {
            fs::read(self.directory.join("launcher.stderr"))
        } else {
            Ok(Vec::new())
        };
        if (stdout.is_err() || stderr.is_err()) && first_failure.is_none() {
            first_failure = Some("LauncherHarnessEvidenceFailed");
        }
        let recorded = (|| -> std::io::Result<()> {
            writeln!(self.evidence, "end_utc\t{}", utc_now())?;
            writeln!(
                self.evidence,
                "elapsed_ms\t{}",
                self.clock.elapsed().as_millis()
            )?;
            writeln!(self.evidence, "launcher_status\t{:?}", self.status)?;
            writeln!(
                self.evidence,
                "launcher_exit_code\t{:?}",
                self.status.and_then(|status| status.code())
            )?;
            writeln!(
                self.evidence,
                "launcher_signal\t{:?}",
                self.status.and_then(|status| status.signal())
            )?;
            writeln!(self.evidence, "launcher_reaped\t{}", self.status.is_some())?;
            writeln!(
                self.evidence,
                "timed_out\t{}",
                first_failure == Some("LauncherHarnessTimeout")
            )?;
            writeln!(
                self.evidence,
                "process_group_absent\t{}",
                group_absent(self.child.id())
            )?;
            writeln!(
                self.evidence,
                "cleanup\t{}",
                if cleaned {
                    "PASS"
                } else {
                    "LauncherHarnessCleanupFailed"
                }
            )?;
            writeln!(self.evidence, "runtime_path\t{:?}", self.runtime)?;
            writeln!(
                self.evidence,
                "runtime_present\t{}",
                self.runtime.symlink_metadata().is_ok()
            )?;
            for name in ["launcher.stdout", "launcher.stderr"] {
                record_artifact(
                    &mut self.evidence,
                    &self.directory,
                    &self.directory.join(name),
                )?;
            }
            for entry in fs::read_dir(&self.root)? {
                let path = entry?.path();
                record_artifact(&mut self.evidence, &self.root, &path)?;
            }
            for role in ["decoy", "core", "io"] {
                for suffix in ["evidence", "stderr", "fail", "sentinel"] {
                    record_artifact(
                        &mut self.evidence,
                        &self.root,
                        &self
                            .root
                            .join("inspector-current")
                            .join(format!("{role}.{suffix}")),
                    )?;
                }
                record_artifact(
                    &mut self.evidence,
                    &self.root,
                    &self
                        .root
                        .join("target/debug")
                        .join(format!("qk-{role}-host.saved")),
                )?;
            }
            writeln!(
                self.evidence,
                "first_failure\t{}",
                first_failure.unwrap_or("none")
            )?;
            self.evidence.sync_all()
        })();
        if recorded.is_err() && first_failure.is_none() {
            first_failure = Some("LauncherHarnessEvidenceFailed");
        }
        self.finished = true;
        if let Some(name) = first_failure {
            eprintln!(
                "{name}; cleanup_failed={}; evidence {}",
                !cleaned,
                self.directory.display()
            );
            return Err(HarnessFailure {
                name,
                cleanup_failed: !cleaned,
                directory: self.directory.clone(),
            });
        }
        match (self.status, stdout, stderr) {
            (Some(status), Ok(stdout), Ok(stderr)) => Ok(HarnessOutput {
                output: Output {
                    status,
                    stdout,
                    stderr,
                },
                directory: self.directory.clone(),
            }),
            _ => Err(HarnessFailure {
                name: "LauncherHarnessEvidenceFailed",
                cleanup_failed: !cleaned,
                directory: self.directory.clone(),
            }),
        }
    }
}

impl Drop for HarnessChild {
    fn drop(&mut self) {
        if !self.finished {
            // No wait(), output pipe join, assertion, or second cleanup attempt.
            let _ = self.finish(Some("LauncherHarnessUnwind"));
        }
    }
}

fn record_artifact(record: &mut File, root: &Path, path: &Path) -> std::io::Result<()> {
    let name = path.strip_prefix(root).unwrap_or(path);
    match path.symlink_metadata() {
        Ok(metadata) => writeln!(
            record,
            "artifact\t{name:?}\tPRESENT\t{}\t{:?}",
            metadata.len(),
            metadata.file_type()
        ),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            writeln!(record, "artifact\t{name:?}\tABSENT")
        }
        Err(error) => writeln!(record, "artifact\t{name:?}\tINSPECTION_FAILED\t{error}"),
    }
}

fn source_commit_fact() -> String {
    match std::env::var("QK_TEST_SOURCE_COMMIT") {
        Ok(value) if value.len() == 40 && value.bytes().all(|byte| byte.is_ascii_hexdigit()) => {
            value
        }
        _ => "unavailable".to_owned(),
    }
}

fn utc_at(seconds: u64) -> String {
    let mut days = seconds / 86_400;
    let mut year = 1970u64;
    let leap = |year: u64| {
        year.is_multiple_of(4) && (!year.is_multiple_of(100) || year.is_multiple_of(400))
    };
    loop {
        let length = if leap(year) { 366 } else { 365 };
        if days < length {
            break;
        }
        days -= length;
        year += 1;
    }
    let lengths = [
        31,
        if leap(year) { 29 } else { 28 },
        31,
        30,
        31,
        30,
        31,
        31,
        30,
        31,
        30,
        31,
    ];
    let mut month = 0;
    while days >= lengths[month] {
        days -= lengths[month];
        month += 1;
    }
    let remaining = seconds % 86_400;
    format!(
        "{year:04}-{:02}-{:02}T{:02}:{:02}:{:02}Z",
        month + 1,
        days + 1,
        remaining / 3600,
        (remaining % 3600) / 60,
        remaining % 60
    )
}

fn utc_now() -> String {
    match SystemTime::now().duration_since(UNIX_EPOCH) {
        Ok(elapsed) => utc_at(elapsed.as_secs()),
        Err(_) => "UNAVAILABLE: clock before UNIX epoch".to_owned(),
    }
}

fn cycle_directory(root: &Path, label: &str) -> PathBuf {
    assert!(label
        .bytes()
        .all(|byte| byte.is_ascii_alphanumeric() || b"-_.".contains(&byte)));
    let number = CYCLE_NUMBER.fetch_add(1, Ordering::Relaxed);
    let directory = root.join(format!("launcher-{number:04}-{label}"));
    fs::create_dir(&directory).expect("fresh per-cycle directory; never overwrite evidence");
    directory
}

fn checked_command(
    command: &mut Command,
    root: &Path,
    label: &str,
    runtime: &Path,
) -> HarnessOutput {
    let directory = cycle_directory(root, label);
    run_command(command, root, label, runtime, &directory, ReadyAction::None).unwrap_or_else(
        |failure| {
            panic!(
                "{}; cleanup_failed={}; evidence {}",
                failure.name,
                failure.cleanup_failed,
                failure.directory.display()
            )
        },
    )
}

fn run_command(
    command: &mut Command,
    root: &Path,
    label: &str,
    runtime: &Path,
    directory: &Path,
    ready_action: ReadyAction<'_>,
) -> Result<HarnessOutput, HarnessFailure> {
    let failure = |name| HarnessFailure {
        name,
        cleanup_failed: false,
        directory: directory.to_owned(),
    };
    let mut evidence = File::options()
        .create_new(true)
        .write(true)
        .open(directory.join("harness.tsv"))
        .map_err(|_| failure("LauncherHarnessEvidenceFailed"))?;
    let prepared = (|| -> std::io::Result<()> {
        writeln!(evidence, "source_commit\t{}", source_commit_fact())?;
        writeln!(
            evidence,
            "source_commit_origin\trunner-supplied; not inspected by test"
        )?;
        writeln!(
            evidence,
            "test\t{}",
            std::thread::current().name().unwrap_or("unnamed")
        )?;
        writeln!(evidence, "cycle\t{label}")?;
        writeln!(evidence, "program\t{:?}", command.get_program())?;
        writeln!(
            evidence,
            "arguments\t{:?}",
            command.get_args().collect::<Vec<_>>()
        )?;
        writeln!(evidence, "start_utc\t{}", utc_now())?;
        for (name, stdout) in [("launcher.stdout", true), ("launcher.stderr", false)] {
            let file = File::options()
                .create_new(true)
                .write(true)
                .open(directory.join(name))?;
            if stdout {
                command.stdout(Stdio::from(file));
            } else {
                command.stderr(Stdio::from(file));
            }
        }
        evidence.sync_all()
    })();
    if let Err(error) = prepared {
        let _ = writeln!(
            evidence,
            "first_failure\tLauncherHarnessEvidenceFailed\t{error}"
        );
        return Err(failure("LauncherHarnessEvidenceFailed"));
    }
    command.process_group(0);
    let child = match command.spawn() {
        Ok(child) => child,
        Err(error) => {
            let _ = writeln!(
                evidence,
                "first_failure\tLauncherHarnessSpawnFailed\t{error}"
            );
            let _ = evidence.sync_all();
            return Err(failure("LauncherHarnessSpawnFailed"));
        }
    };
    let clock = Instant::now();
    let mut owned = HarnessChild {
        child,
        status: None,
        finished: false,
        clock,
        evidence,
        directory: directory.to_owned(),
        root: root.to_owned(),
        runtime: runtime.to_owned(),
    };
    let recorded = writeln!(
        owned.evidence,
        "launcher_pid\t{}\nprocess_group\t{}\ndeadline_ms\t{}",
        owned.child.id(),
        owned.child.id(),
        LAUNCHER_DEADLINE.as_millis()
    );
    if recorded.is_err() {
        return owned.finish(Some("LauncherHarnessEvidenceFailed"));
    }
    let first_failure = loop {
        match owned.child.try_wait() {
            Ok(Some(status)) => {
                owned.status = Some(status);
                break None;
            }
            Ok(None) => {}
            Err(error) => {
                let _ = writeln!(owned.evidence, "try_wait_error\t{error}");
                break Some("LauncherHarnessWaitFailed");
            }
        }
        match ready_action {
            ReadyAction::Expire(path) if path.exists() => {
                let _ = writeln!(owned.evidence, "ready_deadline_seam\t{:?}", path);
                break Some("LauncherHarnessTimeout");
            }
            ReadyAction::Unwind(path) if path.exists() => panic!("test-only ready unwind seam"),
            _ => {}
        }
        if clock.elapsed() >= LAUNCHER_DEADLINE {
            break Some("LauncherHarnessTimeout");
        }
        std::thread::sleep(LAUNCHER_POLL);
    };
    owned.finish(first_failure)
}

static FIXTURE_TERM: AtomicBool = AtomicBool::new(false);

extern "C" fn fixture_term(_: i32) {
    FIXTURE_TERM.store(true, Ordering::Relaxed);
}

#[test]
#[ignore = "subprocess only for deterministic QK-DEC-166 harness regressions"]
fn launcher_harness_blocking_fixture() {
    let root = PathBuf::from(std::env::var_os("QK166_FIXTURE_ROOT").expect("fixture root"));
    if std::env::var_os("QK166_DESCENDANT").is_some() {
        fs::write(
            root.join("descendant-ready"),
            format!("{}\n", std::process::id()),
        )
        .unwrap();
        loop {
            std::thread::park();
        }
    }
    // SAFETY: the handler only stores an atomic flag and is installed in this
    // single-purpose subprocess; the execed descendant keeps default SIGTERM.
    assert_ne!(
        unsafe { signal(15, fixture_term as *const () as usize) },
        usize::MAX
    );
    let mut descendant = Command::new(std::env::current_exe().unwrap())
        .args([
            "--ignored",
            "--exact",
            "launcher_harness_blocking_fixture",
            "--nocapture",
        ])
        .env("QK166_DESCENDANT", "1")
        .spawn()
        .unwrap();
    let ready_wait = Instant::now();
    while !root.join("descendant-ready").exists() {
        assert!(ready_wait.elapsed() < Duration::from_secs(10));
        assert!(descendant.try_wait().unwrap().is_none());
        std::thread::sleep(LAUNCHER_POLL);
    }
    fs::write(
        root.join("both-ready"),
        format!("{}\n{}\n", std::process::id(), descendant.id()),
    )
    .unwrap();
    while !FIXTURE_TERM.load(Ordering::Relaxed) {
        std::thread::sleep(LAUNCHER_POLL);
    }
    // The leader remains alive to reap its TERM-terminated descendant. This
    // avoids relying on an external init process to reap orphan zombies.
    let reap = Instant::now();
    loop {
        if let Some(status) = descendant.try_wait().unwrap() {
            fs::write(root.join("descendant-reaped"), format!("{status}\n")).unwrap();
            return;
        }
        assert!(reap.elapsed() < Duration::from_millis(800));
        std::thread::sleep(LAUNCHER_POLL);
    }
}

fn blocking_fixture_command(root: &Path) -> Command {
    let mut command = Command::new(std::env::current_exe().unwrap());
    command
        .args([
            "--ignored",
            "--exact",
            "launcher_harness_blocking_fixture",
            "--nocapture",
        ])
        .env("QK166_FIXTURE_ROOT", root);
    command
}

fn assert_cleaned_fixture(root: &Path, directory: &Path, failure: &str) {
    let record = fs::read_to_string(directory.join("harness.tsv")).unwrap();
    for fact in [
        format!("first_failure\t{failure}\n"),
        "launcher_reaped\ttrue\n".to_owned(),
        "process_group_absent\ttrue\n".to_owned(),
        "cleanup\tPASS\n".to_owned(),
    ] {
        assert!(record.contains(&fact), "{record}");
    }
    let ready = fs::read_to_string(root.join("both-ready")).unwrap();
    let pids: Vec<u32> = ready.lines().map(|line| line.parse().unwrap()).collect();
    assert_eq!(pids.len(), 2);
    assert!(group_absent(pids[0]));
    assert!(root.join("descendant-reaped").exists());
    assert!(directory.join("launcher.stdout").is_file());
    assert!(directory.join("launcher.stderr").is_file());
    assert!(directory.starts_with(root));
}

#[test]
fn launcher_harness_ready_timeout_reaps_leader_and_descendant_and_retains_evidence() {
    let root = short_test_root("deadline");
    fs::create_dir(&root).unwrap();
    let directory = cycle_directory(&root, "ready-timeout");
    let ready = root.join("both-ready");
    let failure = run_command(
        &mut blocking_fixture_command(&root),
        &root,
        "ready-timeout",
        &root.join("runtime"),
        &directory,
        ReadyAction::Expire(&ready),
    )
    .unwrap_err();
    assert_eq!(failure.name, "LauncherHarnessTimeout");
    assert!(!failure.cleanup_failed);
    assert_eq!(failure.directory, directory);
    assert_cleaned_fixture(&root, &directory, "LauncherHarnessTimeout");
    fs::remove_dir_all(&root).unwrap();
}

#[test]
fn launcher_harness_ready_unwind_uses_the_same_bounded_cleanup() {
    let root = short_test_root("unwind");
    fs::create_dir(&root).unwrap();
    let directory = cycle_directory(&root, "ready-unwind");
    let ready = root.join("both-ready");
    let result = std::panic::catch_unwind(|| {
        let _ = run_command(
            &mut blocking_fixture_command(&root),
            &root,
            "ready-unwind",
            &root.join("runtime"),
            &directory,
            ReadyAction::Unwind(&ready),
        );
    });
    assert!(result.is_err());
    assert_cleaned_fixture(&root, &directory, "LauncherHarnessUnwind");
    fs::remove_dir_all(&root).unwrap();
}

#[test]
fn launcher_harness_retains_ordinary_statuses_without_confusing_them_with_timeout() {
    let root = short_test_root("ordinary-exits");
    fs::create_dir(&root).unwrap();
    let binary = compile_stub(
        &root,
        "fixed-exit",
        "fn main() { std::process::exit(std::env::args().nth(1).unwrap().parse().unwrap()); }",
    );
    for code in [0, 64, 70] {
        let result = checked_command(
            Command::new(&binary).arg(code.to_string()),
            &root,
            &format!("exit-{code}"),
            &root.join("absent-runtime"),
        );
        let record = fs::read_to_string(result.directory.join("harness.tsv")).unwrap();
        assert!(record.contains("first_failure\tnone\n"));
        assert!(record.contains("timed_out\tfalse\n"));
        assert_output(result, code);
    }
    fs::remove_dir_all(&root).unwrap();
}

#[test]
fn launcher_harness_kills_a_ready_term_ignoring_leader_within_the_cleanup_bound() {
    let root = short_test_root("kill-phase");
    fs::create_dir(&root).unwrap();
    let ready = root.join("ready");
    let binary = compile_stub(
        &root,
        "ignores-term",
        &format!("extern \"C\" {{ fn signal(signal: i32, handler: usize) -> usize; }} fn main() {{ unsafe {{ signal(15, 1); }} std::fs::write({ready:?}, b\"READY\\n\").unwrap(); loop {{ std::thread::park(); }} }}"),
    );
    let directory = cycle_directory(&root, "kill-phase");
    let failure = run_command(
        &mut Command::new(&binary),
        &root,
        "kill-phase",
        &root.join("runtime"),
        &directory,
        ReadyAction::Expire(&ready),
    )
    .unwrap_err();
    assert_eq!(failure.name, "LauncherHarnessTimeout");
    assert!(!failure.cleanup_failed);
    let record = fs::read_to_string(directory.join("harness.tsv")).unwrap();
    assert!(record.contains("group_term\tOk(())\n"), "{record}");
    assert!(record.contains("group_kill\tOk(())\n"), "{record}");
    assert!(record.contains("launcher_signal\tSome(9)\n"), "{record}");
    assert!(record.contains("launcher_reaped\ttrue\n"), "{record}");
    assert!(record.contains("process_group_absent\ttrue\n"), "{record}");
    fs::remove_dir_all(&root).unwrap();
}

#[test]
fn launcher_harness_spawn_failure_preserves_the_attempt_without_a_child() {
    let root = short_test_root("spawn-failure");
    fs::create_dir(&root).unwrap();
    let directory = cycle_directory(&root, "missing-binary");
    let failure = run_command(
        Command::new(root.join("absent-binary")).arg("fixed-argument"),
        &root,
        "missing-binary",
        &root.join("runtime"),
        &directory,
        ReadyAction::None,
    )
    .unwrap_err();
    assert_eq!(failure.name, "LauncherHarnessSpawnFailed");
    assert!(!failure.cleanup_failed);
    let record = fs::read_to_string(directory.join("harness.tsv")).unwrap();
    assert!(record.contains("first_failure\tLauncherHarnessSpawnFailed\t"));
    assert!(record.contains("fixed-argument"));
    assert!(!record.contains("launcher_pid\t"));
    assert!(directory.join("launcher.stdout").exists());
    assert!(directory.join("launcher.stderr").exists());
    fs::remove_dir_all(&root).unwrap();
}

#[test]
fn launcher_harness_clock_is_utc_without_spawning_a_program() {
    assert_eq!(LAUNCHER_DEADLINE, Duration::from_secs(30));
    assert_eq!(LAUNCHER_POLL, Duration::from_millis(10));
    assert_eq!(CLEANUP_PHASE, Duration::from_secs(1));
    assert_eq!(utc_at(0), "1970-01-01T00:00:00Z");
    assert_eq!(utc_at(951_782_400), "2000-02-29T00:00:00Z");
    assert_eq!(utc_at(1_709_164_799), "2024-02-28T23:59:59Z");
    assert_eq!(utc_at(1_788_876_800), "2026-09-08T14:13:20Z");
}

fn inspector_cycle(
    supervisor: &Path,
    root: &Path,
    label: &str,
    injection: Option<&str>,
) -> InspectorCycle {
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
    let observed = run_command(
        &mut command,
        root,
        label,
        &runtime,
        &current,
        ReadyAction::None,
    )
    .unwrap_or_else(|failure| {
        panic!(
            "{}; cleanup_failed={}; evidence {}",
            failure.name,
            failure.cleanup_failed,
            failure.directory.display()
        )
    });
    let status = observed.output.status;
    let timed_out = false;
    let group_gone = true; // A successful bounded runner has reaped and checked the entire group.
    let mut record = File::create(current.join("result.tsv")).unwrap();
    writeln!(record, "source_commit\t{}", source_commit_fact()).unwrap();
    writeln!(record, "cycle\t{label}").unwrap();
    writeln!(record, "start_utc\t{start}").unwrap();
    writeln!(record, "end_utc\t{}", utc_now()).unwrap();
    writeln!(record, "elapsed_ms\t{}", clock.elapsed().as_millis()).unwrap();
    writeln!(record, "launcher_exit\t{status}").unwrap();
    writeln!(record, "timed_out\t{timed_out}").unwrap();
    writeln!(record, "process_group_absent\t{group_gone}").unwrap();
    writeln!(record, "bounded_harness\tharness.tsv").unwrap();
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
    assert!(
        cycle.passed,
        "inspector evidence retained at {}",
        cycle.directory.display()
    );
    programs.restore(binaries);
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
    fs::remove_dir_all(&root).unwrap();
}

struct CpuWorkers(Vec<std::process::Child>);

impl Drop for CpuWorkers {
    fn drop(&mut self) {
        for child in &mut self.0 {
            let _ = child.kill();
        }
        let mut reaped = vec![false; self.0.len()];
        let deadline = Instant::now();
        loop {
            for (child, done) in self.0.iter_mut().zip(&mut reaped) {
                if !*done {
                    *done = matches!(child.try_wait(), Ok(Some(_)));
                }
            }
            if reaped.iter().all(|done| *done) {
                return;
            }
            if deadline.elapsed() >= CLEANUP_PHASE {
                break;
            }
            std::thread::sleep(LAUNCHER_POLL);
        }
        for (child, done) in self.0.iter().zip(reaped) {
            if !done {
                eprintln!(
                    "LauncherHarnessCleanupFailed: CPU worker {} was not reaped",
                    child.id()
                );
            }
        }
        if !std::thread::panicking() {
            panic!("LauncherHarnessCleanupFailed");
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
    fs::write(
        root.join("source_commit"),
        format!("{}\n", source_commit_fact()),
    )
    .unwrap();
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

fn assert_output(result: HarnessOutput, status: i32) {
    let evidence = result.directory.display();
    let output = result.output;
    assert_eq!(output.status.code(), Some(status), "evidence {evidence}");
    assert!(output.stdout.is_empty(), "evidence {evidence}");
    assert!(output.stderr.is_empty(), "evidence {evidence}");
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
