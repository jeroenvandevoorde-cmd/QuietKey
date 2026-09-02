#![allow(unsafe_code)]

#[path = "../main.rs"]
mod common;

use common::{cycle_matrix, CycleSpec, FixtureError, CYCLE_TIMEOUT_MILLIS};
use core::ffi::c_int;
use std::fs;
use std::io;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd, RawFd};
use std::os::unix::process::{CommandExt, ExitStatusExt};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, ExitStatus, Stdio};
use std::thread;
use std::time::{Duration, Instant};

const FIRST_HIGH_FD: c_int = 64;
const F_DUPFD_CLOEXEC: c_int = if cfg!(target_os = "macos") { 67 } else { 1030 };
const SIGKILL: c_int = 9;
const NEGATIVE_STATUS: i32 = 70;
const POLL_MILLIS: u64 = 2;

unsafe extern "C" {
    fn close(descriptor: c_int) -> c_int;
    fn dup2(source: c_int, target: c_int) -> c_int;
    fn fcntl(descriptor: c_int, command: c_int, ...) -> c_int;
    fn kill(process: c_int, signal: c_int) -> c_int;
    fn pipe(descriptors: *mut c_int) -> c_int;
    fn setpgid(process: c_int, group: c_int) -> c_int;
}

fn main() {
    std::panic::set_hook(Box::new(|_| {}));
    let status = std::panic::catch_unwind(run).unwrap_or(Err(FixtureError::Wait));
    match status {
        Ok(summary) => {
            println!(
                "cycles={} passed={} failed={} timed_out={}",
                summary.total, summary.passed, summary.failed, summary.timed_out
            );
            if summary.failed != 0 {
                std::process::exit(70);
            }
        }
        Err(_) => std::process::exit(70),
    }
}

fn run() -> Result<Summary, FixtureError> {
    let mut arguments = std::env::args_os();
    let _ = arguments.next();
    let supervisor = PathBuf::from(arguments.next().ok_or(FixtureError::Invocation)?);
    let driver = PathBuf::from(arguments.next().ok_or(FixtureError::Invocation)?);
    if arguments.next().is_some() || !supervisor.is_file() || !driver.is_file() {
        return Err(FixtureError::Invocation);
    }
    let cycles = cycle_matrix();
    let mut summary = Summary::default();
    for (index, cycle) in cycles.into_iter().enumerate() {
        summary.total += 1;
        match run_cycle(&supervisor, &driver, index, cycle) {
            Ok(()) => summary.passed += 1,
            Err(FixtureError::Timeout) => {
                summary.failed += 1;
                summary.timed_out += 1;
            }
            Err(_) => summary.failed += 1,
        }
    }
    Ok(summary)
}

#[derive(Default)]
struct Summary {
    total: usize,
    passed: usize,
    failed: usize,
    timed_out: usize,
}

fn run_cycle(
    supervisor_path: &Path,
    driver_path: &Path,
    index: usize,
    cycle: CycleSpec,
) -> Result<(), FixtureError> {
    let pipes = PipeSet::new()?;
    let runtime = runtime_path(index)?;
    if runtime.exists() {
        return Err(FixtureError::Spawn);
    }

    let supervisor_map = pipes.supervisor_map();
    let mut supervisor = spawn_mapped(
        supervisor_path,
        [
            "normal".into(),
            cycle.profile.argument().into(),
            runtime.as_os_str().to_owned(),
        ],
        &supervisor_map,
        ProcessGroup::Leader,
    )?;
    let group = i32::try_from(supervisor.id()).map_err(|_| FixtureError::Spawn)?;

    let driver_map = pipes.driver_map();
    let mut driver_command = Command::new(driver_path);
    driver_command.args(cycle.driver_arguments());
    configure_command(&mut driver_command, &driver_map, ProcessGroup::Join(group));
    let mut driver = match driver_command.spawn() {
        Ok(child) => child,
        Err(_) => {
            kill_group(group);
            let _ = supervisor.wait();
            return Err(FixtureError::Spawn);
        }
    };
    drop(pipes);

    let deadline = Instant::now()
        .checked_add(Duration::from_millis(CYCLE_TIMEOUT_MILLIS))
        .ok_or(FixtureError::Timeout)?;
    let statuses = wait_bounded(&mut supervisor, &mut driver, group, deadline);
    let cleanup = cleanup_runtime(&runtime);
    let (supervisor_status, driver_status) = statuses?;
    cleanup?;
    let expected_supervisor = if cycle.negative.is_some() {
        status_code(supervisor_status) == Some(NEGATIVE_STATUS)
    } else {
        supervisor_status.success()
    };
    if expected_supervisor && driver_status.success() {
        Ok(())
    } else {
        Err(FixtureError::ChildStatus)
    }
}

fn wait_bounded(
    supervisor: &mut Child,
    driver: &mut Child,
    group: i32,
    deadline: Instant,
) -> Result<(ExitStatus, ExitStatus), FixtureError> {
    let mut supervisor_status = None;
    let mut driver_status = None;
    loop {
        if supervisor_status.is_none() {
            supervisor_status = supervisor.try_wait().map_err(|_| FixtureError::Wait)?;
        }
        if driver_status.is_none() {
            driver_status = driver.try_wait().map_err(|_| FixtureError::Wait)?;
        }
        if let (Some(supervisor_status), Some(driver_status)) = (supervisor_status, driver_status) {
            return Ok((supervisor_status, driver_status));
        }
        if Instant::now() >= deadline {
            kill_group(group);
            if supervisor_status.is_none() {
                let _ = supervisor.wait();
            }
            if driver_status.is_none() {
                let _ = driver.wait();
            }
            return Err(FixtureError::Timeout);
        }
        thread::sleep(Duration::from_millis(POLL_MILLIS));
    }
}

fn status_code(status: ExitStatus) -> Option<i32> {
    status.code().or_else(|| status.signal().map(|_| -1))
}

fn spawn_mapped<const N: usize>(
    program: &Path,
    arguments: [std::ffi::OsString; N],
    mappings: &[(RawFd, RawFd)],
    group: ProcessGroup,
) -> Result<Child, FixtureError> {
    let mut command = Command::new(program);
    command.args(arguments);
    configure_command(&mut command, mappings, group);
    command.spawn().map_err(|_| FixtureError::Spawn)
}

fn configure_command(command: &mut Command, mappings: &[(RawFd, RawFd)], group: ProcessGroup) {
    command
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null());
    let mappings = mappings.to_vec();
    // SAFETY: the closure invokes only async-signal-safe descriptor and
    // process-group syscalls before exec and reports failures through errno.
    unsafe {
        command.pre_exec(move || {
            for &(source, target) in &mappings {
                if dup2(source, target) < 0 {
                    return Err(io::Error::last_os_error());
                }
            }
            let group_result = match group {
                ProcessGroup::Leader => setpgid(0, 0),
                ProcessGroup::Join(group) => setpgid(0, group),
            };
            if group_result != 0 {
                return Err(io::Error::last_os_error());
            }
            Ok(())
        });
    }
}

#[derive(Clone, Copy)]
enum ProcessGroup {
    Leader,
    Join(i32),
}

struct PipeSet {
    pipes: [PipePair; 8],
}

impl PipeSet {
    fn new() -> Result<Self, FixtureError> {
        Ok(Self {
            pipes: [
                PipePair::new()?,
                PipePair::new()?,
                PipePair::new()?,
                PipePair::new()?,
                PipePair::new()?,
                PipePair::new()?,
                PipePair::new()?,
                PipePair::new()?,
            ],
        })
    }

    fn supervisor_map(&self) -> [(RawFd, RawFd); 8] {
        [
            (self.pipes[0].write.as_raw_fd(), 7),
            (self.pipes[1].read.as_raw_fd(), 8),
            (self.pipes[2].read.as_raw_fd(), 9),
            (self.pipes[3].write.as_raw_fd(), 10),
            (self.pipes[4].read.as_raw_fd(), 11),
            (self.pipes[5].read.as_raw_fd(), 12),
            (self.pipes[6].write.as_raw_fd(), 13),
            (self.pipes[7].write.as_raw_fd(), 14),
        ]
    }

    fn driver_map(&self) -> [(RawFd, RawFd); 8] {
        [
            (self.pipes[0].read.as_raw_fd(), 3),
            (self.pipes[1].write.as_raw_fd(), 4),
            (self.pipes[2].write.as_raw_fd(), 5),
            (self.pipes[3].read.as_raw_fd(), 6),
            (self.pipes[4].write.as_raw_fd(), 7),
            (self.pipes[5].write.as_raw_fd(), 8),
            (self.pipes[6].read.as_raw_fd(), 9),
            (self.pipes[7].read.as_raw_fd(), 10),
        ]
    }
}

struct PipePair {
    read: OwnedFd,
    write: OwnedFd,
}

impl PipePair {
    fn new() -> Result<Self, FixtureError> {
        let mut descriptors = [-1; 2];
        // SAFETY: `descriptors` is writable storage for exactly two fds.
        if unsafe { pipe(descriptors.as_mut_ptr()) } != 0 {
            return Err(FixtureError::Pipe);
        }
        // SAFETY: a successful pipe call returned two newly owned fds.
        let read = unsafe { OwnedFd::from_raw_fd(descriptors[0]) };
        // SAFETY: a successful pipe call returned two newly owned fds.
        let write = unsafe { OwnedFd::from_raw_fd(descriptors[1]) };
        let high_read = duplicate_high(read.as_raw_fd())?;
        let high_write = duplicate_high(write.as_raw_fd())?;
        Ok(Self {
            read: high_read,
            write: high_write,
        })
    }
}

fn duplicate_high(descriptor: RawFd) -> Result<OwnedFd, FixtureError> {
    // SAFETY: F_DUPFD_CLOEXEC duplicates one valid descriptor and returns a
    // new owned descriptor at or above the supplied minimum.
    let duplicate = unsafe { fcntl(descriptor, F_DUPFD_CLOEXEC, FIRST_HIGH_FD) };
    if duplicate < 0 {
        return Err(FixtureError::Pipe);
    }
    // SAFETY: the successful fcntl call returned a newly owned descriptor.
    Ok(unsafe { OwnedFd::from_raw_fd(duplicate) })
}

fn kill_group(group: i32) {
    // SAFETY: a negative pid selects the exact harness-created process group.
    let _ = unsafe { kill(-group, SIGKILL) };
}

fn runtime_path(index: usize) -> Result<PathBuf, FixtureError> {
    let parent = std::env::temp_dir();
    if !parent.is_absolute() {
        return Err(FixtureError::Spawn);
    }
    Ok(parent.join(format!("quietkey-s9-{}-{index}", std::process::id())))
}

fn cleanup_runtime(path: &Path) -> Result<(), FixtureError> {
    if !path.exists() {
        return Ok(());
    }
    let parent = path.parent().ok_or(FixtureError::Wait)?;
    if parent != std::env::temp_dir()
        || !path
            .file_name()
            .and_then(|name| name.to_str())
            .is_some_and(|name| name.starts_with("quietkey-s9-"))
    {
        return Err(FixtureError::Wait);
    }
    fs::remove_dir_all(path).map_err(|_| FixtureError::Wait)
}

#[allow(dead_code)]
fn close_raw(descriptor: RawFd) {
    // SAFETY: helper is retained for bounded pre-exec diagnostics only.
    let _ = unsafe { close(descriptor) };
}
