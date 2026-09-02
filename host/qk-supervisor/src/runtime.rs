//! Real HOST-only launcher boundary for the three product address spaces.

use crate::{MockGrantSet, ProcessLifecycle, ProcessLifecycleEvent, ProcessLifecycleOutcome};
#[cfg(target_os = "linux")]
use core::ffi::c_uint;
use core::ffi::{c_char, c_int, c_void};
use core::fmt;
use core::ptr;
use std::ffi::{CString, OsString};
use std::fs::{self, DirBuilder, File, OpenOptions};
use std::io;
use std::os::fd::AsRawFd;
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::{DirBuilderExt, FileTypeExt, MetadataExt, PermissionsExt};
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::{Path, PathBuf};
use std::thread;
use std::time::{Duration, Instant};

#[cfg(target_os = "linux")]
type Mode = c_uint;
#[cfg(target_os = "macos")]
type Mode = u16;

#[cfg(not(any(target_os = "linux", target_os = "macos")))]
compile_error!("qk-supervisor HOST runtime supports only Linux and Darwin");

const DECOY_PROGRAM: &str = "qk-decoy-host";
const CORE_PROGRAM: &str = "qk-core-host";
const IO_PROGRAM: &str = "qk-io-host";
const SOCKET_NAME: &str = "qkip.sock";
const EXIT_RUNTIME_TERMINATED: c_int = 70;
const STATUS_READY: u8 = 0x52;
const STATUS_EXEC_FAILED: u8 = 0x45;
const GATE_RELEASE: u8 = 0x47;
const FIRST_SAFE_SOURCE_FD: c_int = 16;
const MAX_DESCRIPTOR_SNAPSHOT_ENTRIES: usize = 65_536;
const PREEXEC_DESCRIPTOR_BOUND: c_int = 65_536;
const FIRST_NORMAL_DESCRIPTOR: c_int = 7;
const LAST_NORMAL_DESCRIPTOR: c_int = 14;
const EBADF: i32 = 9;
const ESRCH: i32 = 3;
const F_GETFD: c_int = 1;
const F_GETFL: c_int = 3;
const F_SETFD: c_int = 2;
const FD_CLOEXEC: c_int = 1;
const O_ACCMODE: c_int = 3;
const O_RDONLY: c_int = 0;
const O_WRONLY: c_int = 1;
const SIGKILL: c_int = 9;
const SIGTERM: c_int = 15;
const WNOHANG: c_int = 1;
#[cfg(target_os = "linux")]
const F_DUPFD_CLOEXEC: c_int = 1030;
#[cfg(target_os = "macos")]
const F_DUPFD_CLOEXEC: c_int = 67;
const TERMINATION_BOUND: Duration = Duration::from_secs(1);
const REAP_POLL: Duration = Duration::from_millis(1);
const DECOY_RUNNING_PROOF: Duration = Duration::from_millis(10);

extern "C" {
    fn close(descriptor: c_int) -> c_int;
    fn dup2(source: c_int, target: c_int) -> c_int;
    fn execve(
        path: *const c_char,
        arguments: *const *const c_char,
        environment: *const *const c_char,
    ) -> c_int;
    fn fcntl(descriptor: c_int, command: c_int, ...) -> c_int;
    fn fork() -> c_int;
    fn kill(process: c_int, signal: c_int) -> c_int;
    fn pipe(descriptors: *mut c_int) -> c_int;
    #[cfg(test)]
    fn pause() -> c_int;
    fn read(descriptor: c_int, buffer: *mut c_void, length: usize) -> isize;
    fn umask(mask: Mode) -> Mode;
    fn waitpid(process: c_int, status: *mut c_int, options: c_int) -> c_int;
    fn write(descriptor: c_int, buffer: *const c_void, length: usize) -> isize;
    #[cfg(test)]
    fn signal(signal: c_int, handler: usize) -> usize;
    fn _exit(status: c_int) -> !;
}

/// The three exact qk-core mode arguments.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum LauncherMode {
    Setup,
    Normal,
    Kit,
}

impl LauncherMode {
    /// Exact lowercase child argument.
    pub const fn argument(self) -> &'static str {
        match self {
            Self::Setup => "setup",
            Self::Normal => "normal",
            Self::Kit => "kit",
        }
    }

    fn parse(argument: &str) -> Result<Self, LauncherInvocationError> {
        match argument {
            "setup" => Ok(Self::Setup),
            "normal" => Ok(Self::Normal),
            "kit" => Ok(Self::Kit),
            _ => Err(LauncherInvocationError::UnknownMode),
        }
    }
}

/// Exact immutable Normal profile selected by the Owner-side invocation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum LauncherProfile {
    SimpleRecovery,
    Inheritance,
    QuantumShelter,
}

impl LauncherProfile {
    /// Exact two-byte ASCII child argument.
    pub const fn argument(self) -> &'static str {
        match self {
            Self::SimpleRecovery => "01",
            Self::Inheritance => "02",
            Self::QuantumShelter => "03",
        }
    }

    fn parse(argument: &str) -> Result<Self, LauncherInvocationError> {
        match argument {
            "01" => Ok(Self::SimpleRecovery),
            "02" => Ok(Self::Inheritance),
            "03" => Ok(Self::QuantumShelter),
            _ => Err(LauncherInvocationError::UnknownProfile),
        }
    }
}

/// Exact validated invocation passed from the thin launcher binary.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct LauncherInvocation {
    mode: LauncherMode,
    profile: Option<LauncherProfile>,
    runtime_directory: PathBuf,
}

impl LauncherInvocation {
    pub const fn mode(&self) -> LauncherMode {
        self.mode
    }

    pub const fn profile(&self) -> Option<LauncherProfile> {
        self.profile
    }

    pub fn runtime_directory(&self) -> &Path {
        &self.runtime_directory
    }
}

/// Named invocation rejection surface. These map only to process status 64.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum LauncherInvocationError {
    MissingArgument,
    NonUtf8Argument,
    TrailingArgument,
    UnknownMode,
    UnknownProfile,
    RuntimePathNotAbsolute,
    RuntimePathSymlink,
    RuntimePathExists,
    RuntimePathInspectionFailed,
}

impl fmt::Display for LauncherInvocationError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::MissingArgument => "MissingArgument",
            Self::NonUtf8Argument => "NonUtf8Argument",
            Self::TrailingArgument => "TrailingArgument",
            Self::UnknownMode => "UnknownMode",
            Self::UnknownProfile => "UnknownProfile",
            Self::RuntimePathNotAbsolute => "RuntimePathNotAbsolute",
            Self::RuntimePathSymlink => "RuntimePathSymlink",
            Self::RuntimePathExists => "RuntimePathExists",
            Self::RuntimePathInspectionFailed => "RuntimePathInspectionFailed",
        })
    }
}

impl std::error::Error for LauncherInvocationError {}

/// Closed no-secret HOST launcher failure surface. These map only to status 70.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum LauncherRuntimeError {
    ExecutableResolutionFailed,
    AmbientDescriptorCloseFailed,
    InheritedDeviceUnavailable,
    InheritedDeviceNotPipe,
    InheritedDeviceDirectionMismatch,
    InheritedDeviceAliased,
    DecoyGrantFailed,
    DecoySpawnFailed,
    DecoyNotRunning,
    DecoyTerminationFailed,
    RuntimeCreateFailed,
    RuntimePermissionMismatch,
    SocketBindFailed,
    SocketPermissionMismatch,
    SocketConnectFailed,
    SocketAcceptFailed,
    SocketUnlinkFailed,
    ProductGrantFailed,
    ProductSpawnFailed,
    ProductSessionFailed,
    ProductTerminationFailed,
    RuntimeCleanupFailed,
    LifecycleMismatch,
}

impl fmt::Display for LauncherRuntimeError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::ExecutableResolutionFailed => "ExecutableResolutionFailed",
            Self::AmbientDescriptorCloseFailed => "AmbientDescriptorCloseFailed",
            Self::InheritedDeviceUnavailable => "InheritedDeviceUnavailable",
            Self::InheritedDeviceNotPipe => "InheritedDeviceNotPipe",
            Self::InheritedDeviceDirectionMismatch => "InheritedDeviceDirectionMismatch",
            Self::InheritedDeviceAliased => "InheritedDeviceAliased",
            Self::DecoyGrantFailed => "DecoyGrantFailed",
            Self::DecoySpawnFailed => "DecoySpawnFailed",
            Self::DecoyNotRunning => "DecoyNotRunning",
            Self::DecoyTerminationFailed => "DecoyTerminationFailed",
            Self::RuntimeCreateFailed => "RuntimeCreateFailed",
            Self::RuntimePermissionMismatch => "RuntimePermissionMismatch",
            Self::SocketBindFailed => "SocketBindFailed",
            Self::SocketPermissionMismatch => "SocketPermissionMismatch",
            Self::SocketConnectFailed => "SocketConnectFailed",
            Self::SocketAcceptFailed => "SocketAcceptFailed",
            Self::SocketUnlinkFailed => "SocketUnlinkFailed",
            Self::ProductGrantFailed => "ProductGrantFailed",
            Self::ProductSpawnFailed => "ProductSpawnFailed",
            Self::ProductSessionFailed => "ProductSessionFailed",
            Self::ProductTerminationFailed => "ProductTerminationFailed",
            Self::RuntimeCleanupFailed => "RuntimeCleanupFailed",
            Self::LifecycleMismatch => "LifecycleMismatch",
        })
    }
}

impl std::error::Error for LauncherRuntimeError {}

/// Parse Setup/Kit as MODE plus path, and Normal as MODE, PROFILE plus path.
pub fn parse_launcher_arguments<I>(
    arguments: I,
) -> Result<LauncherInvocation, LauncherInvocationError>
where
    I: IntoIterator<Item = OsString>,
{
    let mut arguments = arguments.into_iter();
    let mode = arguments
        .next()
        .ok_or(LauncherInvocationError::MissingArgument)?;
    let mode = mode
        .into_string()
        .map_err(|_| LauncherInvocationError::NonUtf8Argument)?;
    let mode = LauncherMode::parse(&mode)?;
    let (profile, runtime_directory) = match mode {
        LauncherMode::Normal => {
            let profile = arguments
                .next()
                .ok_or(LauncherInvocationError::MissingArgument)?
                .into_string()
                .map_err(|_| LauncherInvocationError::NonUtf8Argument)?;
            let runtime = arguments
                .next()
                .ok_or(LauncherInvocationError::MissingArgument)?;
            (Some(LauncherProfile::parse(&profile)?), runtime)
        }
        LauncherMode::Setup | LauncherMode::Kit => (
            None,
            arguments
                .next()
                .ok_or(LauncherInvocationError::MissingArgument)?,
        ),
    };
    if arguments.next().is_some() {
        return Err(LauncherInvocationError::TrailingArgument);
    }
    let runtime_directory = runtime_directory
        .into_string()
        .map_err(|_| LauncherInvocationError::NonUtf8Argument)?;
    let runtime_directory = PathBuf::from(runtime_directory);
    validate_absent_runtime_path(&runtime_directory)?;
    Ok(LauncherInvocation {
        mode,
        profile,
        runtime_directory,
    })
}

/// Run one complete HOST-only product-process lifecycle.
pub fn run_host_launcher(
    mode: LauncherMode,
    profile: Option<LauncherProfile>,
    runtime_directory: &Path,
) -> Result<(), LauncherRuntimeError> {
    validate_runtime_again(runtime_directory)?;
    let programs = Programs::resolve()?;
    let normal_descriptors = match (mode, profile) {
        (LauncherMode::Normal, Some(_)) => Some(NormalDescriptors::claim_and_validate()?),
        (LauncherMode::Normal, None) | (LauncherMode::Setup | LauncherMode::Kit, Some(_)) => {
            return Err(LauncherRuntimeError::ProductGrantFailed)
        }
        (LauncherMode::Setup | LauncherMode::Kit, None) => None,
    };
    close_ambient_descriptors(normal_descriptors.as_ref())?;

    let decoy_spec = ExecSpec::decoy(&programs.decoy)?;
    let mut decoy = spawn_and_exec(&decoy_spec, false, LauncherRuntimeError::DecoySpawnFailed)?;
    drop(decoy_spec);
    decoy.prove_running(DECOY_RUNNING_PROOF)?;

    let mut lifecycle = ProcessLifecycle::new();
    expect_advanced(lifecycle.apply(ProcessLifecycleEvent::WalletSessionRequested))?;
    decoy
        .terminate_live_bounded()
        .map_err(|_| LauncherRuntimeError::DecoyTerminationFailed)?;
    expect_advanced(lifecycle.apply(ProcessLifecycleEvent::DecoyReaped))?;

    let mut runtime = RuntimeDirectory::create(runtime_directory)?;
    expect_advanced(lifecycle.apply(ProcessLifecycleEvent::RuntimePrepared))?;
    expect_advanced(
        lifecycle.apply(ProcessLifecycleEvent::ProductGrantsInstalled(
            MockGrantSet::product(),
        )),
    )?;

    let (core_endpoint, io_endpoint) = runtime.connect_once()?;
    expect_advanced(lifecycle.apply(ProcessLifecycleEvent::ConnectionAcceptedAndUnlinked))?;

    let core_spec = ExecSpec::core(
        &programs.core,
        mode,
        profile,
        &core_endpoint,
        normal_descriptors.as_ref(),
    )?;
    let io_spec = ExecSpec::io(&programs.io, &io_endpoint, normal_descriptors.as_ref())?;
    drop(normal_descriptors);
    drop(core_endpoint);
    drop(io_endpoint);
    let (mut io_child, mut core_child) =
        prepare_product_children(&mut lifecycle, &mut runtime, io_spec, core_spec)?;
    expect_advanced(
        lifecycle.apply(ProcessLifecycleEvent::ProductChildrenStartedAndParentEndpointsClosed),
    )?;

    if let Err(loss) = wait_for_products(&mut core_child, &mut io_child) {
        let _ = lifecycle.apply(ProcessLifecycleEvent::ChildLost(loss.child));
        cleanup_failed_product_session(
            &mut lifecycle,
            &mut core_child,
            &mut io_child,
            &mut runtime,
            loss.deadline,
        );
        return Err(LauncherRuntimeError::ProductSessionFailed);
    }

    expect_advanced(lifecycle.apply(ProcessLifecycleEvent::SessionCompleted))?;
    expect_advanced(lifecycle.apply(ProcessLifecycleEvent::ProductChildrenReaped))?;
    runtime.mark_products_reaped();
    if runtime.remove_after_reap().is_err() {
        let _ = lifecycle.apply(ProcessLifecycleEvent::CleanupFailed);
        return Err(LauncherRuntimeError::RuntimeCleanupFailed);
    }
    expect_advanced(lifecycle.apply(ProcessLifecycleEvent::RuntimeRemoved))?;
    Ok(())
}

fn validate_absent_runtime_path(path: &Path) -> Result<(), LauncherInvocationError> {
    if !path.is_absolute() {
        return Err(LauncherInvocationError::RuntimePathNotAbsolute);
    }
    match fs::symlink_metadata(path) {
        Ok(metadata) if metadata.file_type().is_symlink() => {
            Err(LauncherInvocationError::RuntimePathSymlink)
        }
        Ok(_) => Err(LauncherInvocationError::RuntimePathExists),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(()),
        Err(_) => Err(LauncherInvocationError::RuntimePathInspectionFailed),
    }
}

fn validate_runtime_again(path: &Path) -> Result<(), LauncherRuntimeError> {
    if !path.is_absolute() {
        return Err(LauncherRuntimeError::RuntimeCreateFailed);
    }
    match fs::symlink_metadata(path) {
        Ok(_) => Err(LauncherRuntimeError::RuntimeCreateFailed),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(()),
        Err(_) => Err(LauncherRuntimeError::RuntimeCreateFailed),
    }
}

fn expect_advanced(outcome: ProcessLifecycleOutcome) -> Result<(), LauncherRuntimeError> {
    match outcome {
        ProcessLifecycleOutcome::Advanced(_) => Ok(()),
        ProcessLifecycleOutcome::FailedClosed(_, _) => Err(LauncherRuntimeError::LifecycleMismatch),
    }
}

struct NormalDescriptors {
    descriptors: [OwnedDescriptor; 8],
}

impl NormalDescriptors {
    fn claim_and_validate() -> Result<Self, LauncherRuntimeError> {
        let expected = [
            O_WRONLY, O_RDONLY, O_RDONLY, O_WRONLY, O_RDONLY, O_RDONLY, O_WRONLY, O_WRONLY,
        ];
        let mut identities = [(0u64, 0u64); 8];
        for (index, descriptor) in (FIRST_NORMAL_DESCRIPTOR..=LAST_NORMAL_DESCRIPTOR).enumerate() {
            let metadata = fs::metadata(format!("/dev/fd/{descriptor}"))
                .map_err(|_| LauncherRuntimeError::InheritedDeviceUnavailable)?;
            if !metadata.file_type().is_fifo() {
                return Err(LauncherRuntimeError::InheritedDeviceNotPipe);
            }
            // SAFETY: F_GETFL has no variadic argument and changes no state.
            let flags = unsafe { fcntl(descriptor, F_GETFL) };
            if flags < 0 || flags & O_ACCMODE != expected[index] {
                return Err(LauncherRuntimeError::InheritedDeviceDirectionMismatch);
            }
            let identity = (metadata.dev(), metadata.ino());
            if identities[..index].contains(&identity) {
                return Err(LauncherRuntimeError::InheritedDeviceAliased);
            }
            identities[index] = identity;
            // SAFETY: F_SETFD accepts the exact close-on-exec flag value.
            if unsafe { fcntl(descriptor, F_SETFD, FD_CLOEXEC) } != 0 {
                return Err(LauncherRuntimeError::InheritedDeviceUnavailable);
            }
        }
        Ok(Self {
            descriptors: std::array::from_fn(|index| {
                OwnedDescriptor(FIRST_NORMAL_DESCRIPTOR + index as c_int)
            }),
        })
    }

    fn raw(&self, descriptor: c_int) -> Result<c_int, LauncherRuntimeError> {
        let index = descriptor
            .checked_sub(FIRST_NORMAL_DESCRIPTOR)
            .and_then(|value| usize::try_from(value).ok())
            .filter(|index| *index < self.descriptors.len())
            .ok_or(LauncherRuntimeError::ProductGrantFailed)?;
        Ok(self.descriptors[index].raw())
    }

    const fn preserves(&self, descriptor: c_int) -> bool {
        descriptor >= FIRST_NORMAL_DESCRIPTOR && descriptor <= LAST_NORMAL_DESCRIPTOR
    }
}

fn close_ambient_descriptors(
    normal_descriptors: Option<&NormalDescriptors>,
) -> Result<(), LauncherRuntimeError> {
    let descriptors = open_descriptor_snapshot()?;
    for descriptor in descriptors {
        if normal_descriptors.is_some_and(|normal| normal.preserves(descriptor)) {
            continue;
        }
        // SAFETY: the snapshot contains only numeric descriptors at or above
        // three. EBADF is expected for the snapshot iterator's own fd, which
        // was closed when collection ended.
        if unsafe { close(descriptor) } != 0
            && io::Error::last_os_error().raw_os_error() != Some(EBADF)
        {
            return Err(LauncherRuntimeError::AmbientDescriptorCloseFailed);
        }
    }
    let verification = open_descriptor_snapshot()?;
    for descriptor in verification {
        if normal_descriptors.is_some_and(|normal| normal.preserves(descriptor)) {
            // SAFETY: F_GETFD has no variadic argument and changes no state.
            if unsafe { fcntl(descriptor, F_GETFD) } & FD_CLOEXEC == 0 {
                return Err(LauncherRuntimeError::AmbientDescriptorCloseFailed);
            }
            continue;
        }
        // SAFETY: F_GETFD has no variadic argument and changes no state.
        if unsafe { fcntl(descriptor, F_GETFD) } >= 0
            || io::Error::last_os_error().raw_os_error() != Some(EBADF)
        {
            return Err(LauncherRuntimeError::AmbientDescriptorCloseFailed);
        }
    }
    Ok(())
}

fn open_descriptor_snapshot() -> Result<Vec<c_int>, LauncherRuntimeError> {
    let entries =
        fs::read_dir("/dev/fd").map_err(|_| LauncherRuntimeError::AmbientDescriptorCloseFailed)?;
    let mut descriptors = Vec::new();
    for entry in entries {
        let entry = entry.map_err(|_| LauncherRuntimeError::AmbientDescriptorCloseFailed)?;
        let name = entry.file_name();
        let name = name
            .to_str()
            .ok_or(LauncherRuntimeError::AmbientDescriptorCloseFailed)?;
        let descriptor = name
            .parse::<c_int>()
            .map_err(|_| LauncherRuntimeError::AmbientDescriptorCloseFailed)?;
        if descriptor < 3 {
            continue;
        }
        if descriptors.len() == MAX_DESCRIPTOR_SNAPSHOT_ENTRIES {
            return Err(LauncherRuntimeError::AmbientDescriptorCloseFailed);
        }
        descriptors
            .try_reserve(1)
            .map_err(|_| LauncherRuntimeError::AmbientDescriptorCloseFailed)?;
        descriptors.push(descriptor);
    }
    Ok(descriptors)
}

struct Programs {
    decoy: PathBuf,
    core: PathBuf,
    io: PathBuf,
}

impl Programs {
    fn resolve() -> Result<Self, LauncherRuntimeError> {
        let executable = std::env::current_exe()
            .map_err(|_| LauncherRuntimeError::ExecutableResolutionFailed)?;
        let directory = executable
            .parent()
            .ok_or(LauncherRuntimeError::ExecutableResolutionFailed)?;
        let programs = Self {
            decoy: directory.join(DECOY_PROGRAM),
            core: directory.join(CORE_PROGRAM),
            io: directory.join(IO_PROGRAM),
        };
        for path in [&programs.decoy, &programs.core, &programs.io] {
            let metadata =
                fs::metadata(path).map_err(|_| LauncherRuntimeError::ExecutableResolutionFailed)?;
            if !metadata.is_file() {
                return Err(LauncherRuntimeError::ExecutableResolutionFailed);
            }
        }
        Ok(programs)
    }
}

struct RuntimeDirectory {
    directory: PathBuf,
    socket: PathBuf,
    removed: bool,
    products_started: bool,
    products_reaped: bool,
}

impl RuntimeDirectory {
    fn create(path: &Path) -> Result<Self, LauncherRuntimeError> {
        Self::create_with_mode(path, 0o700)
    }

    fn create_with_mode(path: &Path, requested_mode: u32) -> Result<Self, LauncherRuntimeError> {
        let mut builder = DirBuilder::new();
        builder.mode(0o700);
        builder
            .create(path)
            .map_err(|_| LauncherRuntimeError::RuntimeCreateFailed)?;
        let runtime = Self {
            directory: path.to_path_buf(),
            socket: path.join(SOCKET_NAME),
            removed: false,
            products_started: false,
            products_reaped: false,
        };
        fs::set_permissions(path, fs::Permissions::from_mode(requested_mode))
            .map_err(|_| LauncherRuntimeError::RuntimeCreateFailed)?;
        let mode = fs::symlink_metadata(path)
            .map_err(|_| LauncherRuntimeError::RuntimeCreateFailed)?
            .permissions()
            .mode()
            & 0o777;
        if mode != 0o700 {
            return Err(LauncherRuntimeError::RuntimePermissionMismatch);
        }
        Ok(runtime)
    }

    fn connect_once(&mut self) -> Result<(UnixStream, UnixStream), LauncherRuntimeError> {
        let _mask = UmaskGuard::set(0o177);
        let listener =
            UnixListener::bind(&self.socket).map_err(|_| LauncherRuntimeError::SocketBindFailed)?;
        drop(_mask);
        fs::set_permissions(&self.socket, fs::Permissions::from_mode(0o600))
            .map_err(|_| LauncherRuntimeError::SocketBindFailed)?;
        let mode = fs::symlink_metadata(&self.socket)
            .map_err(|_| LauncherRuntimeError::SocketBindFailed)?
            .permissions()
            .mode()
            & 0o777;
        if mode != 0o600 {
            return Err(LauncherRuntimeError::SocketPermissionMismatch);
        }
        let core = UnixStream::connect(&self.socket)
            .map_err(|_| LauncherRuntimeError::SocketConnectFailed)?;
        let (io, _) = listener
            .accept()
            .map_err(|_| LauncherRuntimeError::SocketAcceptFailed)?;
        drop(listener);
        fs::remove_file(&self.socket).map_err(|_| LauncherRuntimeError::SocketUnlinkFailed)?;
        Ok((core, io))
    }

    fn remove_after_reap(&mut self) -> Result<(), LauncherRuntimeError> {
        if self.removed {
            return Ok(());
        }
        if self.products_started && !self.products_reaped {
            return Err(LauncherRuntimeError::RuntimeCleanupFailed);
        }
        match fs::remove_file(&self.socket) {
            Ok(()) => {}
            Err(error) if error.kind() == io::ErrorKind::NotFound => {}
            Err(_) => return Err(LauncherRuntimeError::RuntimeCleanupFailed),
        }
        fs::remove_dir(&self.directory).map_err(|_| LauncherRuntimeError::RuntimeCleanupFailed)?;
        self.removed = true;
        Ok(())
    }

    const fn mark_products_started(&mut self) {
        self.products_started = true;
    }

    const fn mark_products_reaped(&mut self) {
        self.products_reaped = true;
    }
}

impl Drop for RuntimeDirectory {
    fn drop(&mut self) {
        if !self.removed && (!self.products_started || self.products_reaped) {
            let _ = fs::remove_file(&self.socket);
            let _ = fs::remove_dir(&self.directory);
        }
    }
}

struct UmaskGuard(Mode);

impl UmaskGuard {
    fn set(mask: Mode) -> Self {
        // SAFETY: the launcher is single-threaded while the process-global
        // creation mask is changed and the previous value is retained.
        Self(unsafe { umask(mask) })
    }
}

impl Drop for UmaskGuard {
    fn drop(&mut self) {
        // SAFETY: restores exactly the value returned by the preceding call.
        unsafe {
            umask(self.0);
        }
    }
}

struct OwnedDescriptor(c_int);

impl OwnedDescriptor {
    fn duplicate(source: c_int) -> Result<Self, LauncherRuntimeError> {
        // SAFETY: F_DUPFD_CLOEXEC reads the integer lower bound and returns a
        // newly owned descriptor on success.
        let descriptor = unsafe { fcntl(source, F_DUPFD_CLOEXEC, FIRST_SAFE_SOURCE_FD) };
        if descriptor < 0 {
            Err(LauncherRuntimeError::ProductGrantFailed)
        } else {
            Ok(Self(descriptor))
        }
    }

    const fn raw(&self) -> c_int {
        self.0
    }
}

impl Drop for OwnedDescriptor {
    fn drop(&mut self) {
        // SAFETY: this owner closes its unique descriptor exactly once.
        let _ = unsafe { close(self.0) };
    }
}

struct DescriptorMap {
    source: OwnedDescriptor,
    target: c_int,
}

struct ExecSpec {
    path: CString,
    arguments: Vec<CString>,
    descriptors: Vec<DescriptorMap>,
}

impl ExecSpec {
    fn decoy(path: &Path) -> Result<Self, LauncherRuntimeError> {
        let descriptors = vec![
            map_mock(false, 2).map_err(|_| LauncherRuntimeError::DecoyGrantFailed)?,
            map_mock(true, 3).map_err(|_| LauncherRuntimeError::DecoyGrantFailed)?,
            map_mock(false, 4).map_err(|_| LauncherRuntimeError::DecoyGrantFailed)?,
        ];
        Self::new(path, &[], descriptors)
    }

    fn core(
        path: &Path,
        mode: LauncherMode,
        profile: Option<LauncherProfile>,
        endpoint: &UnixStream,
        normal: Option<&NormalDescriptors>,
    ) -> Result<Self, LauncherRuntimeError> {
        let mut descriptors = vec![
            map_descriptor(endpoint.as_raw_fd(), 0)?,
            map_descriptor(endpoint.as_raw_fd(), 1)?,
            map_mock(false, 2)?,
        ];
        let child_arguments = match (mode, profile, normal) {
            (LauncherMode::Normal, Some(profile), Some(normal)) => {
                descriptors.extend([
                    map_descriptor(normal.raw(7)?, 3)?,
                    map_descriptor(normal.raw(8)?, 4)?,
                    map_descriptor(normal.raw(9)?, 5)?,
                    map_descriptor(normal.raw(10)?, 6)?,
                ]);
                vec![mode.argument(), profile.argument()]
            }
            (LauncherMode::Setup | LauncherMode::Kit, None, None) => {
                descriptors.extend([
                    map_mock(false, 3)?,
                    map_mock(true, 4)?,
                    map_mock(true, 5)?,
                    map_mock(false, 6)?,
                ]);
                vec![mode.argument()]
            }
            _ => return Err(LauncherRuntimeError::ProductGrantFailed),
        };
        Self::new(path, &child_arguments, descriptors)
    }

    fn io(
        path: &Path,
        endpoint: &UnixStream,
        normal: Option<&NormalDescriptors>,
    ) -> Result<Self, LauncherRuntimeError> {
        let mut descriptors = vec![
            map_descriptor(endpoint.as_raw_fd(), 0)?,
            map_descriptor(endpoint.as_raw_fd(), 1)?,
            map_mock(false, 2)?,
        ];
        match normal {
            Some(normal) => descriptors.extend([
                map_descriptor(normal.raw(11)?, 3)?,
                map_descriptor(normal.raw(12)?, 4)?,
                map_descriptor(normal.raw(13)?, 5)?,
                map_descriptor(normal.raw(14)?, 6)?,
            ]),
            None => descriptors.extend([
                map_mock(true, 3)?,
                map_mock(true, 4)?,
                map_mock(false, 5)?,
                map_mock(false, 6)?,
            ]),
        }
        Self::new(path, &[], descriptors)
    }

    fn new(
        path: &Path,
        child_arguments: &[&str],
        descriptors: Vec<DescriptorMap>,
    ) -> Result<Self, LauncherRuntimeError> {
        let path = CString::new(path.as_os_str().as_bytes())
            .map_err(|_| LauncherRuntimeError::ExecutableResolutionFailed)?;
        let mut arguments = Vec::with_capacity(child_arguments.len() + 1);
        arguments.push(path.clone());
        for argument in child_arguments {
            arguments.push(
                CString::new(*argument)
                    .map_err(|_| LauncherRuntimeError::ExecutableResolutionFailed)?,
            );
        }
        Ok(Self {
            path,
            arguments,
            descriptors,
        })
    }
}

fn map_descriptor(source: c_int, target: c_int) -> Result<DescriptorMap, LauncherRuntimeError> {
    Ok(DescriptorMap {
        source: OwnedDescriptor::duplicate(source)?,
        target,
    })
}

fn map_mock(readable: bool, target: c_int) -> Result<DescriptorMap, LauncherRuntimeError> {
    let file = open_null(readable).map_err(|_| LauncherRuntimeError::ProductGrantFailed)?;
    map_descriptor(file.as_raw_fd(), target)
}

fn open_null(readable: bool) -> io::Result<File> {
    let mut options = OpenOptions::new();
    options.read(readable).write(!readable);
    options.open("/dev/null")
}

struct PipePair {
    read: OwnedDescriptor,
    write: OwnedDescriptor,
}

impl PipePair {
    fn create() -> Result<Self, LauncherRuntimeError> {
        let mut descriptors = [-1; 2];
        // SAFETY: the pointer references exactly two writable integers.
        if unsafe { pipe(descriptors.as_mut_ptr()) } != 0 {
            return Err(LauncherRuntimeError::ProductSpawnFailed);
        }
        let read = OwnedDescriptor::duplicate(descriptors[0]);
        let write = OwnedDescriptor::duplicate(descriptors[1]);
        // SAFETY: these are the two original pipe descriptors; high duplicates
        // own any successful results.
        let _ = unsafe { close(descriptors[0]) };
        let _ = unsafe { close(descriptors[1]) };
        Ok(Self {
            read: read?,
            write: write?,
        })
    }
}

struct PreparedChild {
    process: Option<ChildProcess>,
    status_read: OwnedDescriptor,
    gate_write: Option<OwnedDescriptor>,
}

impl PreparedChild {
    fn spawn(spec: &ExecSpec, gated: bool) -> Result<Self, LauncherRuntimeError> {
        let status = PipePair::create()?;
        let gate = if gated {
            Some(PipePair::create()?)
        } else {
            None
        };
        let mut argument_pointers: Vec<*const c_char> =
            spec.arguments.iter().map(|value| value.as_ptr()).collect();
        argument_pointers.push(ptr::null());
        let empty_environment = [ptr::null::<c_char>()];
        // SAFETY: all allocation and CString construction is complete before
        // fork. The child branch invokes only async-signal-safe system calls.
        let process = unsafe { fork() };
        if process < 0 {
            return Err(LauncherRuntimeError::ProductSpawnFailed);
        }
        if process == 0 {
            child_exec(
                spec,
                &status,
                gate.as_ref(),
                &argument_pointers,
                &empty_environment,
            );
        }
        drop(status.write);
        let gate_write = match gate {
            Some(gate) => {
                drop(gate.read);
                Some(gate.write)
            }
            None => None,
        };
        Ok(Self {
            process: Some(ChildProcess::new(process)),
            status_read: status.read,
            gate_write,
        })
    }

    fn wait_ready(&mut self) -> Result<(), LauncherRuntimeError> {
        match read_byte(self.status_read.raw())? {
            Some(STATUS_READY) => Ok(()),
            _ => Err(LauncherRuntimeError::ProductSpawnFailed),
        }
    }

    fn release(&mut self) -> Result<(), LauncherRuntimeError> {
        if let Some(gate) = self.gate_write.take() {
            write_byte(gate.raw(), GATE_RELEASE)?;
        }
        Ok(())
    }

    fn finish_exec(&mut self) -> Result<ChildProcess, LauncherRuntimeError> {
        match read_byte(self.status_read.raw())? {
            None => self
                .process
                .take()
                .ok_or(LauncherRuntimeError::ProductSpawnFailed),
            Some(STATUS_EXEC_FAILED) | Some(_) => Err(LauncherRuntimeError::ProductSpawnFailed),
        }
    }
}

fn spawn_and_exec(
    spec: &ExecSpec,
    gated: bool,
    error: LauncherRuntimeError,
) -> Result<ChildProcess, LauncherRuntimeError> {
    let mut child = PreparedChild::spawn(spec, gated).map_err(|_| error)?;
    child.wait_ready().map_err(|_| error)?;
    child.release().map_err(|_| error)?;
    child.finish_exec().map_err(|_| error)
}

fn prepare_product_children(
    lifecycle: &mut ProcessLifecycle,
    runtime: &mut RuntimeDirectory,
    io_spec: ExecSpec,
    core_spec: ExecSpec,
) -> Result<(ChildProcess, ChildProcess), LauncherRuntimeError> {
    let mut io_prepared = None;
    let mut core_prepared = None;
    let mut io_child = None;
    let mut core_child = None;
    let preparation = (|| -> Result<(), LauncherRuntimeError> {
        io_prepared = Some(PreparedChild::spawn(&io_spec, true)?);
        runtime.mark_products_started();
        core_prepared = Some(PreparedChild::spawn(&core_spec, true)?);
        io_prepared
            .as_mut()
            .ok_or(LauncherRuntimeError::ProductSpawnFailed)?
            .wait_ready()?;
        core_prepared
            .as_mut()
            .ok_or(LauncherRuntimeError::ProductSpawnFailed)?
            .wait_ready()?;
        drop(io_spec);
        drop(core_spec);
        io_prepared
            .as_mut()
            .ok_or(LauncherRuntimeError::ProductSpawnFailed)?
            .release()?;
        core_prepared
            .as_mut()
            .ok_or(LauncherRuntimeError::ProductSpawnFailed)?
            .release()?;
        io_child = Some(
            io_prepared
                .as_mut()
                .ok_or(LauncherRuntimeError::ProductSpawnFailed)?
                .finish_exec()?,
        );
        core_child = Some(
            core_prepared
                .as_mut()
                .ok_or(LauncherRuntimeError::ProductSpawnFailed)?
                .finish_exec()?,
        );
        Ok(())
    })();
    if preparation.is_err() {
        let _ = lifecycle.apply(ProcessLifecycleEvent::StepFailed);
        if io_child.is_none() {
            io_child = io_prepared
                .as_mut()
                .and_then(|prepared| prepared.process.take());
        }
        if core_child.is_none() {
            core_child = core_prepared
                .as_mut()
                .and_then(|prepared| prepared.process.take());
        }
        let reaped = terminate_children_shared(
            core_child.as_mut(),
            io_child.as_mut(),
            Instant::now() + TERMINATION_BOUND,
        );
        if reaped {
            runtime.mark_products_reaped();
            let _ = lifecycle.apply(ProcessLifecycleEvent::ProductChildrenReaped);
            if runtime.remove_after_reap().is_ok() {
                let _ = lifecycle.apply(ProcessLifecycleEvent::RuntimeRemoved);
            } else {
                let _ = lifecycle.apply(ProcessLifecycleEvent::CleanupFailed);
            }
        } else {
            let _ = lifecycle.apply(ProcessLifecycleEvent::CleanupFailed);
        }
        return Err(LauncherRuntimeError::ProductSpawnFailed);
    }
    Ok((
        io_child.ok_or(LauncherRuntimeError::ProductSpawnFailed)?,
        core_child.ok_or(LauncherRuntimeError::ProductSpawnFailed)?,
    ))
}

fn child_exec(
    spec: &ExecSpec,
    status: &PipePair,
    gate: Option<&PipePair>,
    arguments: &[*const c_char],
    environment: &[*const c_char],
) -> ! {
    // SAFETY: only the child branch reaches this function. Each mapping source
    // is a high close-on-exec duplicate and no two fixed targets conflict.
    unsafe {
        let _ = close(status.read.raw());
        if let Some(gate) = gate {
            let _ = close(gate.write.raw());
        }
        for mapping in &spec.descriptors {
            if dup2(mapping.source.raw(), mapping.target) < 0 {
                child_fail(status.write.raw());
            }
        }
        for descriptor in 0..=6 {
            if !spec
                .descriptors
                .iter()
                .any(|mapping| mapping.target == descriptor)
            {
                let _ = close(descriptor);
            }
        }
        if !child_descriptor_map_is_exact(spec, status, gate) {
            child_fail(status.write.raw());
        }
        if write_byte_child(status.write.raw(), STATUS_READY).is_err() {
            _exit(EXIT_RUNTIME_TERMINATED);
        }
        if let Some(gate) = gate {
            let mut byte = 0u8;
            if read(gate.read.raw(), (&mut byte as *mut u8).cast(), 1) != 1 || byte != GATE_RELEASE
            {
                child_fail(status.write.raw());
            }
            let _ = close(gate.read.raw());
        }
        execve(spec.path.as_ptr(), arguments.as_ptr(), environment.as_ptr());
        child_fail(status.write.raw());
    }
}

unsafe fn child_descriptor_map_is_exact(
    spec: &ExecSpec,
    status: &PipePair,
    gate: Option<&PipePair>,
) -> bool {
    for descriptor in 0..=6 {
        let mapping = spec
            .descriptors
            .iter()
            .find(|mapping| mapping.target == descriptor);
        match mapping {
            Some(mapping) => {
                let source_flags = fcntl(mapping.source.raw(), F_GETFL);
                let target_flags = fcntl(descriptor, F_GETFL);
                if source_flags < 0 || target_flags < 0 || source_flags & 3 != target_flags & 3 {
                    return false;
                }
            }
            None if fcntl(descriptor, F_GETFD) >= 0 => return false,
            None => {}
        }
    }
    for mapping in &spec.descriptors {
        if fcntl(mapping.source.raw(), F_GETFD) & FD_CLOEXEC == 0 {
            return false;
        }
    }
    if fcntl(status.write.raw(), F_GETFD) & FD_CLOEXEC == 0 {
        return false;
    }
    if let Some(gate) = gate {
        if fcntl(gate.read.raw(), F_GETFD) & FD_CLOEXEC == 0 {
            return false;
        }
    }
    for descriptor in 7..PREEXEC_DESCRIPTOR_BOUND {
        let flags = fcntl(descriptor, F_GETFD);
        if flags >= 0 && flags & FD_CLOEXEC == 0 {
            return false;
        }
    }
    true
}

unsafe fn child_fail(status: c_int) -> ! {
    let _ = write_byte_child(status, STATUS_EXEC_FAILED);
    _exit(EXIT_RUNTIME_TERMINATED);
}

unsafe fn write_byte_child(descriptor: c_int, byte: u8) -> Result<(), ()> {
    if write(descriptor, (&byte as *const u8).cast(), 1) == 1 {
        Ok(())
    } else {
        Err(())
    }
}

fn write_byte(descriptor: c_int, byte: u8) -> Result<(), LauncherRuntimeError> {
    loop {
        // SAFETY: the pointer references exactly one readable byte.
        let written = unsafe { write(descriptor, (&byte as *const u8).cast(), 1) };
        if written == 1 {
            return Ok(());
        }
        if written < 0 && io::Error::last_os_error().kind() == io::ErrorKind::Interrupted {
            continue;
        }
        return Err(LauncherRuntimeError::ProductSpawnFailed);
    }
}

fn read_byte(descriptor: c_int) -> Result<Option<u8>, LauncherRuntimeError> {
    loop {
        let mut byte = 0u8;
        // SAFETY: the pointer references exactly one writable byte.
        let received = unsafe { read(descriptor, (&mut byte as *mut u8).cast(), 1) };
        if received == 1 {
            return Ok(Some(byte));
        }
        if received == 0 {
            return Ok(None);
        }
        if received < 0 && io::Error::last_os_error().kind() == io::ErrorKind::Interrupted {
            continue;
        }
        return Err(LauncherRuntimeError::ProductSpawnFailed);
    }
}

struct ChildProcess {
    process: c_int,
    reaped: bool,
}

impl ChildProcess {
    const fn new(process: c_int) -> Self {
        Self {
            process,
            reaped: false,
        }
    }

    fn prove_running(&mut self, interval: Duration) -> Result<(), LauncherRuntimeError> {
        let deadline = Instant::now() + interval;
        loop {
            if self.try_wait()?.is_some() {
                return Err(LauncherRuntimeError::DecoyNotRunning);
            }
            if Instant::now() >= deadline {
                return Ok(());
            }
            thread::sleep(REAP_POLL);
        }
    }

    fn try_wait(&mut self) -> Result<Option<c_int>, LauncherRuntimeError> {
        if self.reaped {
            return Ok(Some(0));
        }
        let mut status = 0;
        loop {
            // SAFETY: `status` is one live integer and this owner is the sole
            // waiter for its exact child pid.
            let result = unsafe { waitpid(self.process, &mut status, WNOHANG) };
            if result == self.process {
                self.reaped = true;
                return Ok(Some(status));
            }
            if result == 0 {
                return Ok(None);
            }
            if io::Error::last_os_error().kind() == io::ErrorKind::Interrupted {
                continue;
            }
            return Err(LauncherRuntimeError::ProductTerminationFailed);
        }
    }

    fn wait_blocking(&mut self) -> Result<c_int, LauncherRuntimeError> {
        if self.reaped {
            return Ok(0);
        }
        let mut status = 0;
        loop {
            // SAFETY: `status` is live and this is the sole waiter.
            let result = unsafe { waitpid(self.process, &mut status, 0) };
            if result == self.process {
                self.reaped = true;
                return Ok(status);
            }
            if io::Error::last_os_error().kind() == io::ErrorKind::Interrupted {
                continue;
            }
            return Err(LauncherRuntimeError::ProductTerminationFailed);
        }
    }

    fn signal(&mut self, signal: c_int) -> Result<(), LauncherRuntimeError> {
        // SAFETY: a positive exact child pid is used; no process group form.
        if unsafe { kill(self.process, signal) } == 0 {
            return Ok(());
        }
        if io::Error::last_os_error().raw_os_error() == Some(ESRCH) && self.try_wait()?.is_some() {
            return Ok(());
        }
        Err(LauncherRuntimeError::ProductTerminationFailed)
    }

    fn terminate_live_bounded(&mut self) -> Result<(), LauncherRuntimeError> {
        if self.try_wait()?.is_some() {
            return Err(LauncherRuntimeError::DecoyNotRunning);
        }
        self.signal(SIGTERM)?;
        let status = self.wait_after_term()?;
        if status_signaled_by(status, SIGTERM) || status_signaled_by(status, SIGKILL) {
            Ok(())
        } else {
            Err(LauncherRuntimeError::DecoyTerminationFailed)
        }
    }

    fn wait_after_term(&mut self) -> Result<c_int, LauncherRuntimeError> {
        let deadline = Instant::now() + TERMINATION_BOUND;
        while Instant::now() < deadline {
            if let Some(status) = self.try_wait()? {
                return Ok(status);
            }
            thread::sleep(REAP_POLL);
        }
        self.signal(SIGKILL)?;
        self.wait_blocking()
    }
}

impl Drop for ChildProcess {
    fn drop(&mut self) {
        if !self.reaped {
            let _ = self.terminate_bounded();
        }
    }
}

fn cleanup_failed_product_session(
    lifecycle: &mut ProcessLifecycle,
    core: &mut ChildProcess,
    io: &mut ChildProcess,
    runtime: &mut RuntimeDirectory,
    deadline: Instant,
) {
    let children_reaped = terminate_children_shared(Some(core), Some(io), deadline);
    if children_reaped {
        runtime.mark_products_reaped();
        let _ = lifecycle.apply(ProcessLifecycleEvent::ProductChildrenReaped);
    } else {
        let _ = lifecycle.apply(ProcessLifecycleEvent::CleanupFailed);
    }
    if children_reaped {
        if runtime.remove_after_reap().is_ok() {
            let _ = lifecycle.apply(ProcessLifecycleEvent::RuntimeRemoved);
        } else {
            let _ = lifecycle.apply(ProcessLifecycleEvent::CleanupFailed);
        }
    }
}

fn terminate_children_shared<'a>(
    mut core: Option<&'a mut ChildProcess>,
    mut io: Option<&'a mut ChildProcess>,
    deadline: Instant,
) -> bool {
    let mut clean = true;
    for child in [&mut core, &mut io]
        .into_iter()
        .filter_map(|child| child.as_deref_mut())
    {
        match child.try_wait() {
            Ok(Some(_)) => {}
            Ok(None) => {
                if child.signal(SIGTERM).is_err() {
                    clean = false;
                }
            }
            Err(_) => clean = false,
        }
    }
    while Instant::now() < deadline {
        let mut all_reaped = true;
        for child in [&mut core, &mut io]
            .into_iter()
            .filter_map(|child| child.as_deref_mut())
        {
            if child.reaped {
                continue;
            }
            match child.try_wait() {
                Ok(Some(_)) => {}
                Ok(None) => all_reaped = false,
                Err(_) => {
                    clean = false;
                    all_reaped = false;
                }
            }
        }
        if all_reaped {
            return clean;
        }
        thread::sleep(REAP_POLL);
    }
    for child in [&mut core, &mut io]
        .into_iter()
        .filter_map(|child| child.as_deref_mut())
    {
        if !child.reaped && child.signal(SIGKILL).is_err() {
            clean = false;
        }
    }
    for child in [&mut core, &mut io]
        .into_iter()
        .filter_map(|child| child.as_deref_mut())
    {
        if !child.reaped && child.wait_blocking().is_err() {
            clean = false;
        }
    }
    clean
        && core.as_ref().is_none_or(|child| child.reaped)
        && io.as_ref().is_none_or(|child| child.reaped)
}

impl ChildProcess {
    fn terminate_bounded(&mut self) -> Result<(), LauncherRuntimeError> {
        if self.try_wait()?.is_some() {
            return Ok(());
        }
        self.signal(SIGTERM)?;
        let _ = self.wait_after_term()?;
        Ok(())
    }
}

struct ProductLoss {
    child: crate::Child,
    deadline: Instant,
}

fn wait_for_products(core: &mut ChildProcess, io: &mut ChildProcess) -> Result<(), ProductLoss> {
    let mut core_status = None;
    let mut io_status = None;
    let mut first_failure = None;
    let mut first_exit = None;
    let mut loss_deadline = None;
    loop {
        if core_status.is_none() {
            core_status = match core.try_wait() {
                Ok(status) => status,
                Err(_) => {
                    return Err(ProductLoss {
                        child: crate::Child::Core,
                        deadline: Instant::now() + TERMINATION_BOUND,
                    });
                }
            };
            if core_status.is_some() && first_exit.is_none() {
                let now = Instant::now();
                first_exit = Some(crate::Child::Core);
                loss_deadline = Some(now + TERMINATION_BOUND);
            }
            if core_status.is_some_and(|status| !status_success(status)) && first_failure.is_none()
            {
                first_failure = Some(crate::Child::Core);
            }
        }
        if io_status.is_none() {
            io_status = match io.try_wait() {
                Ok(status) => status,
                Err(_) => {
                    return Err(ProductLoss {
                        child: crate::Child::Io,
                        deadline: Instant::now() + TERMINATION_BOUND,
                    });
                }
            };
            if io_status.is_some() && first_exit.is_none() {
                let now = Instant::now();
                first_exit = Some(crate::Child::Io);
                loss_deadline = Some(now + TERMINATION_BOUND);
            }
            if io_status.is_some_and(|status| !status_success(status)) && first_failure.is_none() {
                first_failure = Some(crate::Child::Io);
            }
        }
        if core_status.is_some() && io_status.is_some() {
            return match first_failure {
                Some(child) => Err(ProductLoss {
                    child,
                    deadline: loss_deadline.unwrap_or_else(|| Instant::now() + TERMINATION_BOUND),
                }),
                None => Ok(()),
            };
        }
        // The first child's exit closes its endpoint. Give the survivor the
        // complete ratified loss bound to consume that EOF and finish its
        // closed cleanup path; a short scheduling grace period is not proof
        // that the path ran. Forced cleanup begins only at the shared bound.
        if loss_deadline.is_some_and(|deadline| Instant::now() >= deadline) {
            return Err(ProductLoss {
                child: first_failure
                    .or(first_exit)
                    .unwrap_or(if core_status.is_none() {
                        crate::Child::Core
                    } else {
                        crate::Child::Io
                    }),
                deadline: loss_deadline.unwrap_or_else(|| Instant::now() + TERMINATION_BOUND),
            });
        }
        thread::sleep(REAP_POLL);
    }
}

const fn status_success(status: c_int) -> bool {
    status & 0x7f == 0 && (status >> 8) & 0xff == 0
}

const fn status_signaled_by(status: c_int, signal: c_int) -> bool {
    status & 0x7f == signal
}

#[cfg(test)]
mod tests {
    use super::{
        fcntl, fork, pause, read_byte, signal, write_byte_child, ChildProcess, ExecSpec,
        LauncherRuntimeError, PipePair, RuntimeDirectory, F_GETFL, SIGTERM, STATUS_READY,
        TERMINATION_BOUND,
    };
    use std::fs;
    use std::os::unix::net::UnixStream;
    use std::path::Path;
    use std::time::{Duration, Instant};

    const SIGNAL_IGNORE: usize = 1;

    fn test_path(name: &str) -> std::path::PathBuf {
        std::env::temp_dir().join(format!("qk-supervisor-{name}-{}", std::process::id()))
    }

    #[test]
    fn partially_created_runtime_is_removed_when_permission_verification_fails() {
        let path = test_path("create-cleanup");
        let _ = fs::remove_dir(&path);
        assert!(matches!(
            RuntimeDirectory::create_with_mode(&path, 0o711),
            Err(LauncherRuntimeError::RuntimePermissionMismatch)
        ));
        assert!(!path.exists());
    }

    #[test]
    fn runtime_directory_is_retained_until_product_reap_is_proven() {
        let path = test_path("reap-gate");
        let _ = fs::remove_dir(&path);
        let mut runtime = RuntimeDirectory::create(&path).unwrap();
        runtime.mark_products_started();
        assert!(matches!(
            runtime.remove_after_reap(),
            Err(LauncherRuntimeError::RuntimeCleanupFailed)
        ));
        drop(runtime);
        assert!(path.is_dir());
        fs::remove_dir(path).unwrap();
    }

    #[test]
    fn decoy_spec_has_only_the_exact_keypad_and_display_grants() {
        let spec = ExecSpec::decoy(Path::new("/dev/null")).unwrap();
        let actual: Vec<_> = spec
            .descriptors
            .iter()
            .map(|mapping| {
                // SAFETY: every source is an open descriptor owned by `spec`.
                let access = unsafe { fcntl(mapping.source.raw(), F_GETFL) } & 3;
                (mapping.target, access)
            })
            .collect();
        assert_eq!(actual, [(2, 1), (3, 0), (4, 1)]);
        assert_eq!(spec.arguments.len(), 1);
    }

    #[test]
    fn product_specs_keep_their_exact_endpoint_and_device_grants_with_stderr_bound() {
        let (_, core_endpoint) = UnixStream::pair().unwrap();
        let core = ExecSpec::core(
            Path::new("/dev/null"),
            super::LauncherMode::Setup,
            None,
            &core_endpoint,
            None,
        )
        .unwrap();
        let (_, io_endpoint) = UnixStream::pair().unwrap();
        let io = ExecSpec::io(Path::new("/dev/null"), &io_endpoint, None).unwrap();
        let grants = |spec: &ExecSpec| {
            spec.descriptors
                .iter()
                .map(|mapping| {
                    // SAFETY: every source is an open descriptor owned by `spec`.
                    let access = unsafe { fcntl(mapping.source.raw(), F_GETFL) } & 3;
                    (mapping.target, access)
                })
                .collect::<Vec<_>>()
        };
        assert_eq!(
            grants(&core),
            [(0, 2), (1, 2), (2, 1), (3, 1), (4, 0), (5, 0), (6, 1)]
        );
        assert_eq!(
            grants(&io),
            [(0, 2), (1, 2), (2, 1), (3, 0), (4, 0), (5, 1), (6, 1)]
        );
    }

    #[test]
    fn child_drop_uses_the_one_second_term_then_kill_bound_and_reaps() {
        assert_eq!(TERMINATION_BOUND, Duration::from_secs(1));
        let ready = PipePair::create().unwrap();
        // SAFETY: the child executes only async-signal-safe calls and never
        // returns into the Rust test harness.
        let process = unsafe { fork() };
        assert!(process >= 0);
        if process == 0 {
            // SAFETY: SIG_IGN is the specified integer handler sentinel.
            unsafe {
                signal(SIGTERM, SIGNAL_IGNORE);
                let _ = write_byte_child(ready.write.raw(), STATUS_READY);
                loop {
                    pause();
                }
            }
        }
        drop(ready.write);
        assert_eq!(read_byte(ready.read.raw()).unwrap(), Some(STATUS_READY));
        let started = Instant::now();
        drop(ChildProcess::new(process));
        let elapsed = started.elapsed();
        assert!(elapsed >= TERMINATION_BOUND.saturating_sub(Duration::from_millis(25)));
    }
}
