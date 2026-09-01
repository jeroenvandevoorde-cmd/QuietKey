//! One-call Linux/Darwin `recvmsg` adapter and inherited child endpoint.

use crate::{IpcError, StreamDecoder};
use core::ffi::{c_int, c_void};
use core::fmt;
use core::mem;
use core::ptr;
use core::sync::atomic::{compiler_fence, Ordering};
use std::os::fd::AsRawFd;
use std::os::fd::FromRawFd;
use std::os::unix::net::UnixStream;

#[cfg(not(any(target_os = "linux", target_os = "macos")))]
compile_error!("qk-ipc Unix receive adapter supports only Linux and Darwin");

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
    fn dup(descriptor: c_int) -> c_int;
    fn fcntl(descriptor: c_int, command: c_int, ...) -> c_int;
    fn getsockopt(
        socket: c_int,
        level: c_int,
        option: c_int,
        value: *mut c_void,
        value_len: *mut u32,
    ) -> c_int;
    fn getsockname(socket: c_int, address: *mut c_void, address_len: *mut u32) -> c_int;
    fn getpeername(socket: c_int, address: *mut c_void, address_len: *mut u32) -> c_int;
}

const F_SETFD: c_int = 2;
const FD_CLOEXEC: c_int = 1;
#[cfg(target_os = "linux")]
const SO_TYPE: c_int = 3;
#[cfg(target_os = "macos")]
const SO_TYPE: c_int = 0x1008;
const SOCK_STREAM: c_int = 1;
const AF_UNIX: u16 = 1;
const SOCKET_ADDRESS_BYTES: usize = 128;

/// Closed Unix receive-boundary categories.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum UnixReceiveError {
    InheritedEndpointUnavailable,
    InheritedEndpointNotStream,
    InheritedEndpointNotConnected,
    InheritedEndpointNotUnix,
    ScratchEmpty,
    ReceiveFailed,
    UnexpectedReceiveFlags,
    Ipc(IpcError),
}

impl fmt::Display for UnixReceiveError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::InheritedEndpointUnavailable => "InheritedEndpointUnavailable",
            Self::InheritedEndpointNotStream => "InheritedEndpointNotStream",
            Self::InheritedEndpointNotConnected => "InheritedEndpointNotConnected",
            Self::InheritedEndpointNotUnix => "InheritedEndpointNotUnix",
            Self::ScratchEmpty => "ScratchEmpty",
            Self::ReceiveFailed => "ReceiveFailed",
            Self::UnexpectedReceiveFlags => "UnexpectedReceiveFlags",
            Self::Ipc(_) => "Ipc",
        })
    }
}

/// Duplicate inherited standard input after proving it is one connected Unix
/// stream endpoint. The returned duplicate is close-on-exec and full duplex;
/// child roles use it for both QKIP directions.
pub fn inherited_endpoint() -> Result<UnixStream, UnixReceiveError> {
    duplicate_endpoint(0)
}

fn duplicate_endpoint(source: c_int) -> Result<UnixStream, UnixReceiveError> {
    // SAFETY: the source is merely duplicated; ownership of the inherited
    // descriptor remains with its operating-system boundary.
    let descriptor = unsafe { dup(source) };
    if descriptor < 0 {
        return Err(UnixReceiveError::InheritedEndpointUnavailable);
    }
    // SAFETY: F_SETFD consumes the integer flag argument and changes only the
    // duplicate's close-on-exec bit.
    if unsafe { fcntl(descriptor, F_SETFD, FD_CLOEXEC) } < 0 {
        close_descriptor(descriptor);
        return Err(UnixReceiveError::InheritedEndpointUnavailable);
    }
    if !is_stream_socket(descriptor) {
        close_descriptor(descriptor);
        return Err(UnixReceiveError::InheritedEndpointNotStream);
    }
    let local_family = match socket_family(descriptor, false) {
        Ok(family) => family,
        Err(error) => {
            close_descriptor(descriptor);
            return Err(error);
        }
    };
    let peer_family = match socket_family(descriptor, true) {
        Ok(family) => family,
        Err(error) => {
            close_descriptor(descriptor);
            return Err(error);
        }
    };
    if local_family != AF_UNIX || peer_family != AF_UNIX {
        close_descriptor(descriptor);
        return Err(UnixReceiveError::InheritedEndpointNotUnix);
    }
    // SAFETY: the successful checks above prove the duplicate is one live,
    // connected stream socket; ownership transfers exactly once here.
    Ok(unsafe { UnixStream::from_raw_fd(descriptor) })
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
    let received = match receive_bytes_once(stream, scratch) {
        Ok(0) => return Err(UnixReceiveError::Ipc(decoder.finish())),
        Ok(received) => received,
        Err(UnixReceiveError::Ipc(IpcError::AncillaryData)) => {
            return Err(UnixReceiveError::Ipc(match decoder.ingest(&[], true) {
                Err(error) => error,
                Ok(_) => IpcError::InvalidTransition,
            }));
        }
        Err(error) => {
            let _ = decoder.finish();
            return Err(error);
        }
    };
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

/// Perform one ancillary-safe receive without interpreting QKIP bytes.
///
/// A zero byte count is the connected peer's EOF. All received bytes are wiped
/// before any rejection is returned; successful bytes remain caller-owned.
pub fn receive_bytes_once(
    stream: &UnixStream,
    scratch: &mut [u8],
) -> Result<usize, UnixReceiveError> {
    if scratch.is_empty() {
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
        return Err(UnixReceiveError::ReceiveFailed);
    }
    let received = match usize::try_from(received) {
        Ok(value) if value <= scratch.len() => value,
        _ => {
            wipe(&mut control.0);
            return Err(UnixReceiveError::ReceiveFailed);
        }
    };
    let control_len = message_control_len(&message).min(CONTROL_BYTES);
    let returned_flags = returned_event_flags(message.flags);
    let ancillary_present = control_len != 0 || returned_flags & MSG_CTRUNC != 0;
    close_received_rights(&control.0[..control_len]);

    if ancillary_present {
        wipe(&mut scratch[..received]);
        wipe(&mut control.0);
        return Err(UnixReceiveError::Ipc(IpcError::AncillaryData));
    }
    if returned_flags != 0 {
        wipe(&mut scratch[..received]);
        wipe(&mut control.0);
        return Err(UnixReceiveError::UnexpectedReceiveFlags);
    }
    wipe(&mut control.0);
    Ok(received)
}

const fn returned_event_flags(flags: c_int) -> c_int {
    flags & !RECEIVE_FLAGS
}

fn is_stream_socket(descriptor: c_int) -> bool {
    let mut socket_type = 0i32;
    let mut length = mem::size_of::<c_int>() as u32;
    // SAFETY: both pointers refer to live initialized storage of the declared
    // length; the kernel writes only the requested SO_TYPE integer.
    let result = unsafe {
        getsockopt(
            descriptor,
            SOL_SOCKET,
            SO_TYPE,
            (&mut socket_type as *mut c_int).cast(),
            &mut length,
        )
    };
    result == 0 && length as usize == mem::size_of::<c_int>() && socket_type == SOCK_STREAM
}

fn socket_family(descriptor: c_int, peer: bool) -> Result<u16, UnixReceiveError> {
    let mut address = [0u8; SOCKET_ADDRESS_BYTES];
    let mut length = SOCKET_ADDRESS_BYTES as u32;
    // SAFETY: `address` is live writable storage and `length` is its exact
    // bound. Both calls use the same sockaddr representation contract.
    let result = unsafe {
        if peer {
            getpeername(descriptor, address.as_mut_ptr().cast(), &mut length)
        } else {
            getsockname(descriptor, address.as_mut_ptr().cast(), &mut length)
        }
    };
    if result != 0 {
        return Err(if peer {
            UnixReceiveError::InheritedEndpointNotConnected
        } else {
            UnixReceiveError::InheritedEndpointNotUnix
        });
    }
    socket_address_family(&address[..length.min(SOCKET_ADDRESS_BYTES as u32) as usize])
        .ok_or(UnixReceiveError::InheritedEndpointNotUnix)
}

#[cfg(target_os = "linux")]
fn socket_address_family(address: &[u8]) -> Option<u16> {
    let bytes: [u8; 2] = address.get(..2)?.try_into().ok()?;
    Some(u16::from_ne_bytes(bytes))
}

#[cfg(target_os = "macos")]
fn socket_address_family(address: &[u8]) -> Option<u16> {
    address.get(1).copied().map(u16::from)
}

fn close_descriptor(descriptor: c_int) {
    // SAFETY: callers pass only a live duplicate not exposed elsewhere.
    let _ = unsafe { close(descriptor) };
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

#[cfg(test)]
mod tests {
    use super::{
        duplicate_endpoint, returned_event_flags, UnixReceiveError, MSG_CTRUNC, RECEIVE_FLAGS,
    };
    use std::io::{Read, Write};
    use std::net::{TcpListener, TcpStream};
    use std::os::fd::AsRawFd;
    use std::os::unix::net::{UnixListener, UnixStream};

    #[test]
    fn inherited_endpoint_checks_are_closed_and_the_duplicate_is_full_duplex() {
        assert!(matches!(
            duplicate_endpoint(-1),
            Err(UnixReceiveError::InheritedEndpointUnavailable)
        ));

        let file = std::fs::File::open("/dev/null").unwrap();
        assert!(matches!(
            duplicate_endpoint(file.as_raw_fd()),
            Err(UnixReceiveError::InheritedEndpointNotStream)
        ));

        let directory = std::env::temp_dir();
        let path = directory.join("qk-ipc-unconnected-test.sock");
        let _ = std::fs::remove_file(&path);
        let listener = UnixListener::bind(&path).unwrap();
        assert!(matches!(
            duplicate_endpoint(listener.as_raw_fd()),
            Err(UnixReceiveError::InheritedEndpointNotConnected)
        ));
        drop(listener);
        std::fs::remove_file(path).unwrap();

        let tcp_listener = TcpListener::bind(("127.0.0.1", 0)).unwrap();
        let tcp_client = TcpStream::connect(tcp_listener.local_addr().unwrap()).unwrap();
        let (_tcp_server, _) = tcp_listener.accept().unwrap();
        assert!(matches!(
            duplicate_endpoint(tcp_client.as_raw_fd()),
            Err(UnixReceiveError::InheritedEndpointNotUnix)
        ));

        let (mut peer, endpoint) = UnixStream::pair().unwrap();
        let mut duplicate = duplicate_endpoint(endpoint.as_raw_fd()).unwrap();
        duplicate.write_all(b"to-peer").unwrap();
        let mut peer_bytes = [0u8; 7];
        peer.read_exact(&mut peer_bytes).unwrap();
        assert_eq!(&peer_bytes, b"to-peer");
        peer.write_all(b"to-child").unwrap();
        let mut child_bytes = [0u8; 8];
        duplicate.read_exact(&mut child_bytes).unwrap();
        assert_eq!(&child_bytes, b"to-child");
    }

    #[test]
    fn every_host_runtime_error_has_only_its_fixed_name() {
        use crate::IpcError;

        for error in [
            UnixReceiveError::InheritedEndpointUnavailable,
            UnixReceiveError::InheritedEndpointNotStream,
            UnixReceiveError::InheritedEndpointNotConnected,
            UnixReceiveError::InheritedEndpointNotUnix,
            UnixReceiveError::ScratchEmpty,
            UnixReceiveError::ReceiveFailed,
            UnixReceiveError::UnexpectedReceiveFlags,
            UnixReceiveError::Ipc(IpcError::AncillaryData),
        ] {
            assert_eq!(
                error.to_string(),
                format!("{error:?}").split('(').next().unwrap()
            );
        }
    }

    #[test]
    fn only_the_requested_cloexec_flag_is_masked_and_ctrunc_remains_fatal() {
        assert_eq!(returned_event_flags(RECEIVE_FLAGS), 0);
        assert_eq!(returned_event_flags(RECEIVE_FLAGS | MSG_CTRUNC), MSG_CTRUNC);
        assert_eq!(returned_event_flags(MSG_CTRUNC), MSG_CTRUNC);
    }
}
