//! Linux HOST-only descriptor fixture. Opens no apparatus path and uses only
//! the existing permanently public card model and anonymous inherited channels.

use crate::fixture::{self, Fault, Trace};
use qk_core::{Sec1210DescriptorReadV2, Sec1210DescriptorV2, Sec1210DescriptorWriteV2};
use qk_device_wire::{encode_frame, parse_frame, BodyRef, Capability, MessageKind, HEADER_BYTES};
use std::fs::{File, OpenOptions};
use std::io::{self, Read, Write};
use std::os::fd::{AsRawFd, FromRawFd, RawFd};
use std::os::unix::fs::OpenOptionsExt;
use std::os::unix::process::CommandExt;
use std::path::Path;
use std::process::{Child, Command, ExitStatus};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant};

const POLLIN: i16 = 0x0001;
const POLLOUT: i16 = 0x0004;
const POLLERR: i16 = 0x0008;
const POLLHUP: i16 = 0x0010;
const POLLNVAL: i16 = 0x0020;
const TCSANOW: i32 = 0;
const F_SETFD: i32 = 2;
const FD_CLOEXEC: i32 = 1;
const F_DUPFD_CLOEXEC: i32 = 1030;
const O_CLOEXEC: i32 = 0x80000;
const POLL_SLICE: Duration = Duration::from_millis(20);
const SERVER_BUDGET: Duration = Duration::from_secs(300);
const MAX_FRAME: usize = 274;

#[repr(C)]
struct PollFd {
    fd: i32,
    events: i16,
    revents: i16,
}

#[repr(align(16))]
struct TermiosStorage([u8; 256]);

#[cfg_attr(target_env = "gnu", link(name = "util"))]
extern "C" {
    fn openpty(
        master: *mut i32,
        slave: *mut i32,
        name: *mut i8,
        termios: *const core::ffi::c_void,
        winsize: *const core::ffi::c_void,
    ) -> i32;
    fn tcgetattr(fd: i32, termios: *mut core::ffi::c_void) -> i32;
    fn cfmakeraw(termios: *mut core::ffi::c_void);
    fn tcsetattr(fd: i32, action: i32, termios: *const core::ffi::c_void) -> i32;
    fn poll(fds: *mut PollFd, count: usize, timeout_ms: i32) -> i32;
    fn fcntl(fd: i32, command: i32, ...) -> i32;
    fn dup2(old: i32, new: i32) -> i32;
    fn pipe2(descriptors: *mut i32, flags: i32) -> i32;
}

pub fn pipe_pair() -> io::Result<(File, File)> {
    let mut descriptors = [-1; 2];
    // SAFETY: two live output slots are supplied to Linux pipe2; CLOEXEC stops
    // ungranted pipe ends leaking across exec and each returned fd is owned once.
    if unsafe { pipe2(descriptors.as_mut_ptr(), O_CLOEXEC) } != 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: successful pipe2 returned a fresh owned reading descriptor.
    let reader = unsafe { File::from_raw_fd(descriptors[0]) };
    // SAFETY: successful pipe2 returned a distinct fresh writing descriptor.
    let writer = unsafe { File::from_raw_fd(descriptors[1]) };
    Ok((reader, writer))
}

pub fn pty_pair() -> io::Result<(File, File)> {
    let mut master = -1;
    let mut slave = -1;
    // SAFETY: outputs are live; optional settings/name pointers are null; each
    // fresh descriptor is immediately transferred to exactly one File owner.
    let result = unsafe {
        openpty(
            &mut master,
            &mut slave,
            std::ptr::null_mut(),
            std::ptr::null(),
            std::ptr::null(),
        )
    };
    if result != 0 {
        return Err(io::Error::last_os_error());
    }
    if master < 0 || slave < 0 {
        return Err(io::Error::other("PtyDescriptorRejected"));
    }
    // SAFETY: successful openpty returned a fresh owned master descriptor.
    let master = unsafe { File::from_raw_fd(master) };
    // SAFETY: successful openpty returned a distinct fresh slave descriptor.
    let slave = unsafe { File::from_raw_fd(slave) };
    for descriptor in [&master, &slave] {
        // SAFETY: F_SETFD changes flags on the live owned descriptor; setting
        // CLOEXEC prevents ungranted PTY ends leaking into either child.
        if unsafe { fcntl(descriptor.as_raw_fd(), F_SETFD, FD_CLOEXEC) } != 0 {
            return Err(io::Error::last_os_error());
        }
    }
    let mut storage = TermiosStorage([0; 256]);
    let termios = storage.0.as_mut_ptr().cast::<core::ffi::c_void>();
    // SAFETY: this Linux-only aligned storage exceeds Linux termios, is live
    // throughout all three calls, and is initialized before either consumer.
    if unsafe { tcgetattr(slave.as_raw_fd(), termios) } != 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: tcgetattr initialized one Linux termios object in this storage.
    unsafe { cfmakeraw(termios) };
    // SAFETY: termios remains initialized and live; the descriptor is owned.
    if unsafe { tcsetattr(slave.as_raw_fd(), TCSANOW, termios) } != 0 {
        return Err(io::Error::last_os_error());
    }
    Ok((master, slave))
}

fn poll_ready(fd: RawFd, events: i16, wait: Duration) -> Result<bool, &'static str> {
    let mut descriptor = PollFd {
        fd,
        events,
        revents: 0,
    };
    let millis = i32::try_from(wait.as_millis()).unwrap_or(i32::MAX);
    // SAFETY: descriptor is one initialized Linux pollfd, live for the call.
    let result = unsafe { poll(&mut descriptor, 1, millis) };
    if result < 0 || descriptor.revents & POLLNVAL != 0 {
        return Err("HarnessPollFailed");
    }
    if result == 0 {
        return Ok(false);
    }
    let ready = descriptor.revents & (events | POLLHUP) != 0;
    if descriptor.revents & POLLERR != 0 && !ready {
        return Err("HarnessPollFailed");
    }
    Ok(ready)
}

fn transfer_wait(
    fd: RawFd,
    events: i16,
    deadline: Instant,
    stop: Option<&AtomicBool>,
) -> Result<(), &'static str> {
    loop {
        if stop.is_some_and(|stop| stop.load(Ordering::Acquire)) {
            return Err("ReaderStopped");
        }
        let remaining = deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            return Err("HarnessDeadlineExceeded");
        }
        if poll_ready(fd, events, remaining.min(POLL_SLICE))? {
            return Ok(());
        }
    }
}

fn read_until<T: Read + AsRawFd>(
    channel: &mut T,
    bytes: &mut [u8],
    deadline: Instant,
    stop: Option<&AtomicBool>,
) -> Result<(), &'static str> {
    let mut offset = 0;
    while offset < bytes.len() {
        transfer_wait(channel.as_raw_fd(), POLLIN, deadline, stop)?;
        match channel.read(&mut bytes[offset..]) {
            Ok(0) => {
                return Err(if offset == 0 {
                    "HarnessPeerClosed"
                } else {
                    "HarnessTruncated"
                })
            }
            Ok(count) => offset += count,
            Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
            Err(error) if error.raw_os_error() == Some(5) && offset == 0 => {
                return Err("HarnessPeerClosed");
            }
            Err(_) => return Err("HarnessReadFailed"),
        }
    }
    Ok(())
}

pub fn read_exact_timeout<T: Read + AsRawFd>(
    channel: &mut T,
    bytes: &mut [u8],
    budget: Duration,
) -> Result<(), &'static str> {
    read_until(channel, bytes, Instant::now() + budget, None)
}

fn write_until<T: Write + AsRawFd>(
    channel: &mut T,
    bytes: &[u8],
    deadline: Instant,
    stop: Option<&AtomicBool>,
) -> Result<(), &'static str> {
    let mut offset = 0;
    while offset < bytes.len() {
        transfer_wait(channel.as_raw_fd(), POLLOUT, deadline, stop)?;
        match channel.write(&bytes[offset..]) {
            Ok(0) => return Err("HarnessWriteZero"),
            Ok(count) => offset += count,
            Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
            Err(_) => return Err("HarnessWriteFailed"),
        }
    }
    Ok(())
}

pub fn write_all_timeout<T: Write + AsRawFd>(
    channel: &mut T,
    bytes: &[u8],
    budget: Duration,
) -> Result<(), &'static str> {
    write_until(channel, bytes, Instant::now() + budget, None)
}

pub struct ChildGuard {
    pub child: Child,
    reaped: bool,
}

impl ChildGuard {
    pub fn wait_timeout(&mut self, budget: Duration) -> Result<ExitStatus, &'static str> {
        let deadline = Instant::now() + budget;
        loop {
            match self.child.try_wait() {
                Ok(Some(status)) => {
                    self.reaped = true;
                    return Ok(status);
                }
                Ok(None) => {}
                Err(_) => return Err("HarnessWaitFailed"),
            }
            if Instant::now() >= deadline {
                self.terminate();
                return Err("HarnessChildDeadlineExceeded");
            }
            // HOST containment only; this is not a production deadline oracle.
            thread::sleep(POLL_SLICE);
        }
    }

    pub fn terminate(&mut self) {
        if !self.reaped {
            let _ = self.child.kill();
            self.reaped = self.child.wait().is_ok();
        }
    }
}

impl Drop for ChildGuard {
    fn drop(&mut self) {
        self.terminate();
    }
}

pub fn spawn_with_fds(mut command: Command, grants: &[(RawFd, RawFd)]) -> io::Result<ChildGuard> {
    let mut duplicates = Vec::new();
    for (index, &(source, target)) in grants.iter().enumerate() {
        if !(3..100).contains(&target)
            || grants[..index]
                .iter()
                .any(|(_, earlier)| *earlier == target)
        {
            return Err(io::Error::other("HarnessGrantRejected"));
        }
        // SAFETY: fcntl duplicates a borrowed live descriptor; ownership of the
        // new close-on-exec fd is transferred below, without taking the source.
        let duplicate = unsafe { fcntl(source, F_DUPFD_CLOEXEC, 100) };
        if duplicate < 0 {
            return Err(io::Error::last_os_error());
        }
        // SAFETY: successful F_DUPFD_CLOEXEC returned a fresh owned descriptor.
        duplicates.push((unsafe { File::from_raw_fd(duplicate) }, target));
    }
    // SAFETY: the child closure only calls async-signal-safe dup2 and constructs
    // an OS error on failure. Sources are disjoint high-fd owned duplicates;
    // targets cannot overwrite any source, and exec closes the CLOEXEC sources.
    unsafe {
        command.pre_exec(move || {
            for (source, target) in &duplicates {
                if dup2(source.as_raw_fd(), *target) < 0 {
                    return Err(io::Error::last_os_error());
                }
            }
            Ok(())
        });
    }
    let child = command.spawn()?;
    // Dropping Command now releases the parent's captured duplicate guards.
    drop(command);
    Ok(ChildGuard {
        child,
        reaped: false,
    })
}

#[derive(Clone, Default, Debug)]
pub struct ReaderSnapshot {
    pub commands: Vec<Vec<u8>>,
    pub apdus: Vec<Vec<u8>>,
    pub signs: usize,
    pub model_dropped: bool,
}

fn update_snapshot(shared: &Mutex<ReaderSnapshot>, trace: &Trace) -> Result<(), &'static str> {
    *shared.lock().map_err(|_| "ReaderSnapshotPoisoned")? = ReaderSnapshot {
        commands: trace.writes(),
        apdus: trace.apdus(),
        signs: trace.sign_count(),
        model_dropped: trace.descriptor_dropped(),
    };
    Ok(())
}

fn record(evidence: &mut File, kind: &str, bytes: &[u8]) -> Result<(), &'static str> {
    write!(evidence, "{kind} ").map_err(|_| "ReaderEvidenceFailed")?;
    for byte in bytes {
        write!(evidence, "{byte:02x}").map_err(|_| "ReaderEvidenceFailed")?;
    }
    writeln!(evidence).map_err(|_| "ReaderEvidenceFailed")
}

enum ModelReply {
    Bytes(Vec<u8>),
    Removed,
    Silent,
}

fn model_exchange(
    model: &mut fixture::FixtureDescriptor,
    request: &[u8],
) -> Result<ModelReply, &'static str> {
    match model
        .write(request, 5_000)
        .map_err(|_| "ReaderModelWriteFailed")?
    {
        Sec1210DescriptorWriteV2::Bytes(length) if length == request.len() => {}
        _ => return Err("ReaderModelWriteRejected"),
    }
    let mut bytes = [0; MAX_FRAME];
    match model
        .read(&mut bytes, 5_000)
        .map_err(|_| "ReaderModelReadFailed")?
    {
        Sec1210DescriptorReadV2::Bytes(length) => Ok(ModelReply::Bytes(bytes[..length].to_vec())),
        Sec1210DescriptorReadV2::EndOfStream => Ok(ModelReply::Removed),
        Sec1210DescriptorReadV2::TimedOut => Ok(ModelReply::Silent),
    }
}

enum Channel {
    Pty(File, usize),
    Reference(File, File),
}

pub struct ReaderTask {
    stop: Arc<AtomicBool>,
    snapshot: Arc<Mutex<ReaderSnapshot>>,
    worker: Option<JoinHandle<Result<(), &'static str>>>,
}

impl ReaderTask {
    pub fn start(
        master: File,
        profile: u8,
        fault: Fault,
        fragment_size: usize,
        evidence_path: &Path,
    ) -> io::Result<Self> {
        if fragment_size == 0 || fragment_size > MAX_FRAME {
            return Err(io::Error::other("ReaderFragmentSizeRejected"));
        }
        Self::start_channel(
            Channel::Pty(master, fragment_size),
            profile,
            fault,
            evidence_path,
        )
    }

    pub fn start_reference(
        requests: File,
        responses: File,
        profile: u8,
        fault: Fault,
        evidence_path: &Path,
    ) -> io::Result<Self> {
        Self::start_channel(
            Channel::Reference(requests, responses),
            profile,
            fault,
            evidence_path,
        )
    }

    fn start_channel(
        channel: Channel,
        profile: u8,
        fault: Fault,
        evidence_path: &Path,
    ) -> io::Result<Self> {
        let mut evidence = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(evidence_path)?;
        let stop = Arc::new(AtomicBool::new(false));
        let snapshot = Arc::new(Mutex::new(ReaderSnapshot::default()));
        let worker_stop = Arc::clone(&stop);
        let worker_snapshot = Arc::clone(&snapshot);
        let worker = thread::spawn(move || {
            // Rc-backed model and all card state are created on this thread.
            let (mut model, _clock, trace) = fixture::rig(profile);
            trace.set_fault(fault);
            let result = serve(
                channel,
                &mut model,
                &trace,
                &worker_snapshot,
                &worker_stop,
                &mut evidence,
            );
            drop(model);
            update_snapshot(&worker_snapshot, &trace)?;
            evidence.flush().map_err(|_| "ReaderEvidenceFailed")?;
            match result {
                Err("ReaderStopped" | "HarnessPeerClosed") => Ok(()),
                other => other,
            }
        });
        Ok(Self {
            stop,
            snapshot,
            worker: Some(worker),
        })
    }

    pub fn snapshot(&self) -> ReaderSnapshot {
        self.snapshot
            .lock()
            .expect("reader snapshot not poisoned")
            .clone()
    }

    pub fn finish(mut self) -> Result<ReaderSnapshot, &'static str> {
        self.stop.store(true, Ordering::Release);
        if let Some(worker) = self.worker.take() {
            worker.join().map_err(|_| "ReaderThreadPanicked")??;
        }
        Ok(self.snapshot())
    }
}

impl Drop for ReaderTask {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Release);
        if let Some(worker) = self.worker.take() {
            // Every I/O poll checks stop within 20 ms; model work is bounded by
            // the public fixture's one-command parser and one signature.
            let _ = worker.join();
        }
    }
}

fn serve(
    mut channel: Channel,
    model: &mut fixture::FixtureDescriptor,
    trace: &Trace,
    snapshot: &Mutex<ReaderSnapshot>,
    stop: &AtomicBool,
    evidence: &mut File,
) -> Result<(), &'static str> {
    let deadline = Instant::now() + SERVER_BUDGET;
    let mut reference_sequence = 1u8;
    let mut reference_block = 0u8;
    loop {
        let (request, reply_sequence) = match &mut channel {
            Channel::Pty(master, _) => {
                let mut header = [0; 12];
                read_until(master, &mut header, deadline, Some(stop))?;
                if header[..2] != [3, 6] {
                    return Err("ReaderFramePrefixRejected");
                }
                let length = u32::from_le_bytes(
                    header[3..7]
                        .try_into()
                        .map_err(|_| "ReaderHeaderRejected")?,
                ) as usize;
                if length > MAX_FRAME - 13 {
                    return Err("ReaderFrameLengthRejected");
                }
                let mut request = header.to_vec();
                request.resize(length + 13, 0);
                read_until(master, &mut request[12..], deadline, Some(stop)).map_err(|error| {
                    if error == "HarnessPeerClosed" {
                        "HarnessTruncated"
                    } else {
                        error
                    }
                })?;
                (request, None)
            }
            Channel::Reference(requests, _) => {
                let mut header = [0; HEADER_BYTES];
                read_until(requests, &mut header, deadline, Some(stop))?;
                let length = u32::from_le_bytes(
                    header[12..16]
                        .try_into()
                        .map_err(|_| "ReferenceHeaderRejected")?,
                ) as usize;
                if length > qk_device_wire::MAX_CARD_APDU_REQUEST_BODY_BYTES {
                    return Err("ReferenceApduLengthRejected");
                }
                let mut frame = header.to_vec();
                frame.resize(HEADER_BYTES + length, 0);
                read_until(requests, &mut frame[HEADER_BYTES..], deadline, Some(stop)).map_err(
                    |error| {
                        if error == "HarnessPeerClosed" {
                            "HarnessTruncated"
                        } else {
                            error
                        }
                    },
                )?;
                record(evidence, "qkdv.request", &frame)?;
                let parsed = parse_frame(Capability::CardRequest, &frame)
                    .map_err(|_| "ReferenceFrameRejected")?;
                let BodyRef::CardApduRequest(apdu) =
                    parsed.parsed_body().map_err(|_| "ReferenceBodyRejected")?
                else {
                    return Err("ReferenceApduKindRejected");
                };
                let mut block = vec![
                    0,
                    reference_block,
                    u8::try_from(apdu.len()).map_err(|_| "ReferenceApduLengthRejected")?,
                ];
                block.extend_from_slice(apdu);
                block.push(block.iter().fold(0, |lrc, byte| lrc ^ byte));
                let mut request = vec![3, 6, 0x6f];
                request.extend_from_slice(
                    &u32::try_from(block.len())
                        .map_err(|_| "ReferenceApduLengthRejected")?
                        .to_le_bytes(),
                );
                request.extend_from_slice(&[0, reference_sequence, 0, 0, 0]);
                request.extend_from_slice(&block);
                request.push(request.iter().fold(0, |lrc, byte| lrc ^ byte));
                reference_sequence = reference_sequence.wrapping_add(1);
                reference_block ^= 0x40;
                (request, Some(parsed.header().sequence()))
            }
        };
        record(evidence, "controller.request", &request)?;
        let reply = model_exchange(model, &request)?;
        update_snapshot(snapshot, trace)?;
        let response = match reply {
            ModelReply::Bytes(response) => response,
            ModelReply::Removed => return Ok(()),
            ModelReply::Silent => {
                // Deliberately withhold all reply bytes; keep the peer alive so
                // the real executable, not this fixture, owns timeout policy.
                let fd = match &channel {
                    Channel::Pty(master, _) => master.as_raw_fd(),
                    Channel::Reference(requests, _) => requests.as_raw_fd(),
                };
                transfer_wait(fd, POLLIN, deadline, Some(stop))?;
                return Ok(());
            }
        };
        record(evidence, "controller.response", &response)?;
        match &mut channel {
            Channel::Pty(master, fragment_size) => {
                for fragment in response.chunks(*fragment_size) {
                    write_until(master, fragment, deadline, Some(stop))?;
                }
            }
            Channel::Reference(_, responses) => {
                let length = response.len();
                if length < 17 || response[12] != 0 || response[13] & !0x40 != 0 {
                    return Err("ReferenceModelFrameRejected");
                }
                let body = &response[15..length - 2];
                let mut frame =
                    [0; HEADER_BYTES + qk_device_wire::MAX_CARD_APDU_RESPONSE_BODY_BYTES];
                let length = encode_frame(
                    Capability::CardResponse,
                    MessageKind::CardApduResponse,
                    reply_sequence.ok_or("ReferenceSequenceMissing")?,
                    body,
                    &mut frame,
                )
                .map_err(|_| "ReferenceResponseRejected")?;
                record(evidence, "qkdv.response", &frame[..length])?;
                write_until(responses, &frame[..length], deadline, Some(stop))?;
            }
        }
    }
}
