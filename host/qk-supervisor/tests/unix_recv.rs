#![cfg(any(target_os = "linux", target_os = "macos"))]

use core::ffi::{c_int, c_void};
use core::mem;
use qk_ipc::{encode_frame, Direction, IpcError, MessageKind, StreamDecoder, HEADER_BYTES};
use qk_supervisor::{receive_once, UnixReceiveError};
use std::io::Write;
use std::os::fd::{AsRawFd, RawFd};
use std::os::unix::net::UnixStream;
use std::sync::Mutex;

static SOCKET_TEST: Mutex<()> = Mutex::new(());

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
struct ControlHeader {
    len: usize,
    level: c_int,
    kind: c_int,
}

#[repr(C, align(8))]
struct AlignedControl([u8; 64]);

#[cfg(target_os = "macos")]
#[repr(C)]
struct ControlHeader {
    len: u32,
    level: c_int,
    kind: c_int,
}

#[cfg(target_os = "linux")]
const SOL_SOCKET: c_int = 1;
#[cfg(target_os = "macos")]
const SOL_SOCKET: c_int = 0xffff;
const SCM_RIGHTS: c_int = 1;

extern "C" {
    fn sendmsg(socket: c_int, message: *const MessageHeader, flags: c_int) -> isize;
    fn fcntl(descriptor: c_int, command: c_int, ...) -> c_int;
}

const F_GETFD: c_int = 1;

fn frame(payload: &[u8]) -> Vec<u8> {
    let mut bytes = vec![0u8; HEADER_BYTES + payload.len()];
    let written = encode_frame(
        Direction::CoreToIo,
        MessageKind::OperationRequest,
        [0x42; 16],
        1,
        payload,
        &mut bytes,
    )
    .unwrap();
    bytes.truncate(written);
    bytes
}

#[test]
fn fragmentation_coalescing_and_eof_follow_the_pure_decoder() {
    let _serial = SOCKET_TEST.lock().unwrap();
    let (mut sender, receiver) = UnixStream::pair().unwrap();
    let first = frame(b"one");
    let second = frame(b"two");
    sender.write_all(&first[..9]).unwrap();
    let mut decoder = StreamDecoder::new();
    let mut scratch = [0xa5; 256];
    let partial = receive_once(&receiver, &mut decoder, &mut scratch).unwrap();
    assert_eq!(partial.received(), 9);
    assert_eq!(partial.consumed(), 9);
    assert!(!partial.frame_ready());
    assert_eq!(&scratch[..9], &[0; 9]);

    let mut joined = first[9..].to_vec();
    joined.extend_from_slice(&second);
    sender.write_all(&joined).unwrap();
    let complete = receive_once(&receiver, &mut decoder, &mut scratch).unwrap();
    assert_eq!(complete.received(), joined.len());
    assert_eq!(complete.consumed(), first.len() - 9);
    assert!(complete.frame_ready());
    assert_eq!(
        &scratch[..complete.consumed()],
        vec![0; complete.consumed()]
    );
    assert_eq!(&scratch[complete.consumed()..complete.received()], &second);
    drop(decoder.take_frame().unwrap());
    let suffix = scratch[complete.consumed()..complete.received()].to_vec();
    let resumed = decoder.ingest(&suffix, false).unwrap();
    assert_eq!(resumed.consumed(), second.len());
    assert!(resumed.frame_ready());

    drop(sender);
    drop(decoder.take_frame().unwrap());
    assert_eq!(
        receive_once(&receiver, &mut decoder, &mut scratch),
        Err(UnixReceiveError::Ipc(IpcError::PeerLost))
    );
}

#[test]
fn empty_scratch_fails_and_terminates_the_decoder() {
    let _serial = SOCKET_TEST.lock().unwrap();
    let (_sender, receiver) = UnixStream::pair().unwrap();
    let mut decoder = StreamDecoder::new();
    assert_eq!(
        receive_once(&receiver, &mut decoder, &mut []),
        Err(UnixReceiveError::ScratchEmpty)
    );
    assert_eq!(
        decoder.ingest(b"x", false),
        Err(IpcError::DecoderTerminated)
    );
}

#[test]
fn real_scm_rights_is_closed_and_rejected_before_bytes() {
    let _serial = SOCKET_TEST.lock().unwrap();
    let (sender, receiver) = UnixStream::pair().unwrap();
    let descriptor_source = std::fs::File::open("/dev/null").unwrap();
    let before = open_descriptor_count();
    send_fd(sender.as_raw_fd(), descriptor_source.as_raw_fd(), b"QKIP");

    let mut decoder = StreamDecoder::new();
    let mut scratch = [0xa5; 64];
    assert_eq!(
        receive_once(&receiver, &mut decoder, &mut scratch),
        Err(UnixReceiveError::Ipc(IpcError::AncillaryData))
    );
    assert_eq!(&scratch[..4], &[0; 4]);
    assert_eq!(
        decoder.ingest(b"anything", false),
        Err(IpcError::DecoderTerminated)
    );
    assert_eq!(open_descriptor_count(), before);
}

fn send_fd(socket: RawFd, descriptor: RawFd, payload: &[u8]) {
    let alignment = if cfg!(target_os = "linux") {
        mem::size_of::<usize>()
    } else {
        4
    };
    let header_size = mem::size_of::<ControlHeader>();
    let data_offset = (header_size + alignment - 1) & !(alignment - 1);
    let control_len = data_offset + mem::size_of::<c_int>();
    let control_space = (control_len + alignment - 1) & !(alignment - 1);
    assert!(control_space <= 64);
    let mut control = AlignedControl([0u8; 64]);
    #[cfg(target_os = "linux")]
    let header = ControlHeader {
        len: control_len,
        level: SOL_SOCKET,
        kind: SCM_RIGHTS,
    };
    #[cfg(target_os = "macos")]
    let header = ControlHeader {
        len: control_len as u32,
        level: SOL_SOCKET,
        kind: SCM_RIGHTS,
    };
    unsafe {
        core::ptr::write_unaligned(control.0.as_mut_ptr().cast::<ControlHeader>(), header);
        core::ptr::write_unaligned(
            control.0.as_mut_ptr().add(data_offset).cast::<c_int>(),
            descriptor,
        );
    }
    let mut payload = payload.to_vec();
    let mut vector = IoVec {
        base: payload.as_mut_ptr().cast(),
        len: payload.len(),
    };
    #[cfg(target_os = "linux")]
    let message = MessageHeader {
        name: core::ptr::null_mut(),
        name_len: 0,
        iov: &mut vector,
        iov_len: 1,
        control: control.0.as_mut_ptr().cast(),
        control_len: control_space,
        flags: 0,
    };
    #[cfg(target_os = "macos")]
    let message = MessageHeader {
        name: core::ptr::null_mut(),
        name_len: 0,
        iov: &mut vector,
        iov_len: 1,
        control: control.0.as_mut_ptr().cast(),
        control_len: control_space as u32,
        flags: 0,
    };
    let sent = unsafe { sendmsg(socket, &message, 0) };
    assert_eq!(sent, payload.len() as isize);
}

fn open_descriptor_count() -> usize {
    (0..4_096)
        .filter(|descriptor| {
            // SAFETY: F_GETFD reads descriptor flags and has no third argument.
            (unsafe { fcntl(*descriptor, F_GETFD) }) >= 0
        })
        .count()
}
