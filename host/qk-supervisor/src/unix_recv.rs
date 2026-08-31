//! One-call Linux/Darwin `recvmsg` adapter with ancillary-first rejection.

use core::ffi::{c_int, c_void};
use core::fmt;
use core::mem;
use core::ptr;
use core::sync::atomic::{compiler_fence, Ordering};
use qk_ipc::{IpcError, StreamDecoder};
use std::os::fd::AsRawFd;
use std::os::unix::net::UnixStream;

#[cfg(not(any(target_os = "linux", target_os = "macos")))]
compile_error!("qk-supervisor Unix receive adapter supports only Linux and Darwin");

const CONTROL_BYTES: usize = 256;

#[cfg(target_os = "linux")]
const SOL_SOCKET: c_int = 1;
#[cfg(target_os = "macos")]
const SOL_SOCKET: c_int = 0xffff;
const SCM_RIGHTS: c_int = 1;
#[cfg(target_os = "linux")]
const MSG_CTRUNC: c_int = 0x08;
#[cfg(target_os = "macos")]
const MSG_CTRUNC: c_int = 0x20;
#[cfg(target_os = "linux")]
const RECEIVE_FLAGS: c_int = 0x4000_0000; // MSG_CMSG_CLOEXEC
#[cfg(target_os = "macos")]
const RECEIVE_FLAGS: c_int = 0;

#[repr(C)]
struct IoVec {
    base: *mut c_void,
    len: usize,
}

#[cfg(target_os = "linux")]
#[repr(C)]
struct MessageHeader {
    name: *mut c_void,
    name_len: u32,
    iov: *mut IoVec,
    iov_len: usize,
    control: *mut c_void,
    control_len: usize,
    flags: c_int,
}

#[cfg(target_os = "macos")]
#[repr(C)]
struct MessageHeader {
    name: *mut c_void,
    name_len: u32,
    iov: *mut IoVec,
    iov_len: c_int,
    control: *mut c_void,
    control_len: u32,
    flags: c_int,
}

#[cfg(target_os = "linux")]
#[repr(C)]
#[derive(Clone, Copy)]
struct ControlHeader {
    len: usize,
    level: c_int,
    kind: c_int,
}

#[cfg(target_os = "macos")]
#[repr(C)]
#[derive(Clone, Copy)]
struct ControlHeader {
    len: u32,
    level: c_int,
    kind: c_int,
}

#[repr(C, align(8))]
struct AlignedControl([u8; CONTROL_BYTES]);

extern "C" {
    fn recvmsg(socket: c_int, message: *mut MessageHeader, flags: c_int) -> isize;
    fn close(descriptor: c_int) -> c_int;
}

/// Closed Unix receive-boundary categories.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum UnixReceiveError {
    ScratchEmpty,
    ReceiveFailed,
    UnexpectedReceiveFlags,
    Ipc(IpcError),
}

impl fmt::Display for UnixReceiveError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::ScratchEmpty => "ScratchEmpty",
            Self::ReceiveFailed => "ReceiveFailed",
            Self::UnexpectedReceiveFlags => "UnexpectedReceiveFlags",
            Self::Ipc(_) => "Ipc",
        })
    }
}

impl std::error::Error for UnixReceiveError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Ipc(error) => Some(error),
            _ => None,
        }
    }
}

/// Exact byte counts returned by one successful receive and decoder ingest.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct UnixReceiveOutcome {
    received: usize,
    consumed: usize,
    frame_ready: bool,
}

impl UnixReceiveOutcome {
    pub const fn received(&self) -> usize {
        self.received
    }

    pub const fn consumed(&self) -> usize {
        self.consumed
    }

    pub const fn frame_ready(&self) -> bool {
        self.frame_ready
    }
}

/// Perform exactly one `recvmsg` and submit its bytes and ancillary-presence
/// fact to the pure QKIP decoder.
///
/// The caller must resubmit `scratch[consumed..received]` in byte order before
/// invoking this function again when a coalesced receive contains a suffix.
pub fn receive_once(
    stream: &UnixStream,
    decoder: &mut StreamDecoder,
    scratch: &mut [u8],
) -> Result<UnixReceiveOutcome, UnixReceiveError> {
    if scratch.is_empty() {
        let _ = decoder.finish();
        return Err(UnixReceiveError::ScratchEmpty);
    }

    let mut control = AlignedControl([0; CONTROL_BYTES]);
    let mut vector = IoVec {
        base: scratch.as_mut_ptr().cast(),
        len: scratch.len(),
    };
    let mut message = message_header(&mut vector, &mut control);
    // SAFETY: the connected stream descriptor is borrowed for the call;
    // `message` points to one live iovec and one live bounded control span.
    let received = unsafe { recvmsg(stream.as_raw_fd(), &mut message, RECEIVE_FLAGS) };
    if received < 0 {
        wipe(&mut control.0);
        let _ = decoder.finish();
        return Err(UnixReceiveError::ReceiveFailed);
    }
    let received = match usize::try_from(received) {
        Ok(value) if value <= scratch.len() => value,
        _ => {
            wipe(&mut control.0);
            let _ = decoder.finish();
            return Err(UnixReceiveError::ReceiveFailed);
        }
    };
    let control_len = message_control_len(&message).min(CONTROL_BYTES);
    let ancillary_present = control_len != 0 || message.flags & MSG_CTRUNC != 0;
    close_received_rights(&control.0[..control_len]);

    if ancillary_present {
        let result = decoder.ingest(&scratch[..received], true);
        wipe(&mut scratch[..received]);
        wipe(&mut control.0);
        return Err(UnixReceiveError::Ipc(match result {
            Err(error) => error,
            Ok(_) => IpcError::InvalidTransition,
        }));
    }
    if message.flags != 0 {
        wipe(&mut scratch[..received]);
        wipe(&mut control.0);
        let _ = decoder.finish();
        return Err(UnixReceiveError::UnexpectedReceiveFlags);
    }
    wipe(&mut control.0);

    if received == 0 {
        return Err(UnixReceiveError::Ipc(decoder.finish()));
    }
    let outcome = match decoder.ingest(&scratch[..received], false) {
        Ok(outcome) => outcome,
        Err(error) => {
            wipe(&mut scratch[..received]);
            return Err(UnixReceiveError::Ipc(error));
        }
    };
    let consumed = outcome.consumed();
    wipe(&mut scratch[..consumed]);
    Ok(UnixReceiveOutcome {
        received,
        consumed,
        frame_ready: outcome.frame_ready(),
    })
}

#[cfg(target_os = "linux")]
fn message_header(vector: &mut IoVec, control: &mut AlignedControl) -> MessageHeader {
    MessageHeader {
        name: ptr::null_mut(),
        name_len: 0,
        iov: vector,
        iov_len: 1,
        control: control.0.as_mut_ptr().cast(),
        control_len: CONTROL_BYTES,
        flags: 0,
    }
}

#[cfg(target_os = "macos")]
fn message_header(vector: &mut IoVec, control: &mut AlignedControl) -> MessageHeader {
    MessageHeader {
        name: ptr::null_mut(),
        name_len: 0,
        iov: vector,
        iov_len: 1,
        control: control.0.as_mut_ptr().cast(),
        control_len: CONTROL_BYTES as u32,
        flags: 0,
    }
}

#[cfg(target_os = "linux")]
const fn message_control_len(message: &MessageHeader) -> usize {
    message.control_len
}

#[cfg(target_os = "macos")]
const fn message_control_len(message: &MessageHeader) -> usize {
    message.control_len as usize
}

#[cfg(target_os = "linux")]
const fn control_header_len(header: ControlHeader) -> usize {
    header.len
}

#[cfg(target_os = "macos")]
const fn control_header_len(header: ControlHeader) -> usize {
    header.len as usize
}

const fn control_alignment() -> usize {
    #[cfg(target_os = "linux")]
    {
        mem::size_of::<usize>()
    }
    #[cfg(target_os = "macos")]
    {
        4
    }
}

fn align_control(value: usize) -> Option<usize> {
    let alignment = control_alignment();
    value
        .checked_add(alignment.checked_sub(1)?)
        .map(|sum| sum & !(alignment - 1))
}

fn close_received_rights(control: &[u8]) {
    let header_bytes = mem::size_of::<ControlHeader>();
    let data_offset = match align_control(header_bytes) {
        Some(value) => value,
        None => return,
    };
    let mut offset = 0usize;
    while control.len().saturating_sub(offset) >= header_bytes {
        // SAFETY: the size check above covers one complete header; unaligned
        // reads avoid relying on the position of later control records.
        let header =
            unsafe { ptr::read_unaligned(control.as_ptr().add(offset).cast::<ControlHeader>()) };
        let length = control_header_len(header);
        if length < data_offset || length > control.len() - offset {
            break;
        }
        if header.level == SOL_SOCKET && header.kind == SCM_RIGHTS {
            let mut data = offset + data_offset;
            let end = offset + length;
            while end.saturating_sub(data) >= mem::size_of::<c_int>() {
                // SAFETY: the bounds check covers one integer-sized value.
                let descriptor =
                    unsafe { ptr::read_unaligned(control.as_ptr().add(data).cast::<c_int>()) };
                if descriptor >= 0 {
                    // SAFETY: SCM_RIGHTS installed this descriptor in the
                    // receiving process; it is never exposed and is closed once.
                    let _ = unsafe { close(descriptor) };
                }
                data += mem::size_of::<c_int>();
            }
        }
        let advance = match align_control(length) {
            Some(value) if value != 0 => value,
            _ => break,
        };
        offset = match offset.checked_add(advance) {
            Some(next) if next <= control.len() => next,
            _ => break,
        };
    }
}

#[inline(never)]
fn wipe(bytes: &mut [u8]) {
    for byte in bytes {
        // SAFETY: each byte is live and uniquely borrowed.
        unsafe { ptr::write_volatile(byte, 0) };
    }
    compiler_fence(Ordering::SeqCst);
}
