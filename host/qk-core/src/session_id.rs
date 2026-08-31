//! One-use qk-core process session-identity mint.

use crate::wipe;
use std::fs::OpenOptions;
use std::io::Read;
use std::sync::Mutex;

const PROCESS_NAMESPACE_BYTES: usize = 12;
const SESSION_ID_BYTES: usize = 16;
const RANDOM_SOURCE: &str = "/dev/urandom";

/// Internal session-identity mint failures, mapped by the owning shell.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum SessionIdError {
    Unavailable,
    Exhausted,
}

/// One non-clonable session identity whose complete bytes clear on drop.
pub(crate) struct SessionId {
    bytes: [u8; SESSION_ID_BYTES],
}

impl SessionId {
    pub(crate) fn as_bytes(&self) -> &[u8; SESSION_ID_BYTES] {
        &self.bytes
    }
}

impl Drop for SessionId {
    fn drop(&mut self) {
        wipe::bytes(&mut self.bytes);
    }
}

enum NamespaceState {
    Uninitialized,
    Ready([u8; PROCESS_NAMESPACE_BYTES]),
    Failed,
}

struct ProcessMint {
    namespace: NamespaceState,
    last_counter: u32,
}

impl ProcessMint {
    const fn uninitialized() -> Self {
        Self {
            namespace: NamespaceState::Uninitialized,
            last_counter: 0,
        }
    }

    #[cfg(any(test, feature = "fuzzing"))]
    const fn deterministic(namespace: [u8; PROCESS_NAMESPACE_BYTES], last_counter: u32) -> Self {
        Self {
            namespace: NamespaceState::Ready(namespace),
            last_counter,
        }
    }

    fn mint_with<F>(&mut self, load_namespace: F) -> Result<SessionId, SessionIdError>
    where
        F: FnOnce() -> Result<[u8; PROCESS_NAMESPACE_BYTES], ()>,
    {
        if matches!(self.namespace, NamespaceState::Uninitialized) {
            self.namespace = match load_namespace() {
                Ok(namespace) => NamespaceState::Ready(namespace),
                Err(()) => NamespaceState::Failed,
            };
        }

        let namespace = match &self.namespace {
            NamespaceState::Ready(namespace) => namespace,
            NamespaceState::Uninitialized | NamespaceState::Failed => {
                return Err(SessionIdError::Unavailable)
            }
        };
        let counter = self
            .last_counter
            .checked_add(1)
            .ok_or(SessionIdError::Exhausted)?;
        let mut bytes = [0u8; SESSION_ID_BYTES];
        let (namespace_bytes, counter_bytes) = bytes.split_at_mut(PROCESS_NAMESPACE_BYTES);
        namespace_bytes.copy_from_slice(namespace);
        let mut encoded_counter = counter.to_le_bytes();
        counter_bytes.copy_from_slice(&encoded_counter);
        wipe::bytes(&mut encoded_counter);
        self.last_counter = counter;
        Ok(SessionId { bytes })
    }
}

impl Drop for ProcessMint {
    fn drop(&mut self) {
        if let NamespaceState::Ready(namespace) = &mut self.namespace {
            wipe::bytes(namespace);
        }
        self.last_counter = 0;
    }
}

static PROCESS_MINT: Mutex<ProcessMint> = Mutex::new(ProcessMint::uninitialized());

/// Mint the next process-unique identity from the retained namespace.
pub(crate) fn mint_session_id() -> Result<SessionId, SessionIdError> {
    mint_locked(&PROCESS_MINT, load_process_namespace)
}

fn mint_locked<F>(
    process_mint: &Mutex<ProcessMint>,
    load_namespace: F,
) -> Result<SessionId, SessionIdError>
where
    F: FnOnce() -> Result<[u8; PROCESS_NAMESPACE_BYTES], ()>,
{
    let mut mint = process_mint
        .lock()
        .map_err(|_| SessionIdError::Unavailable)?;
    mint.mint_with(load_namespace)
}

fn load_process_namespace() -> Result<[u8; PROCESS_NAMESPACE_BYTES], ()> {
    let mut source = OpenOptions::new()
        .read(true)
        .open(RANDOM_SOURCE)
        .map_err(|_| ())?;
    read_namespace(&mut source)
}

fn read_namespace<R: Read>(source: &mut R) -> Result<[u8; PROCESS_NAMESPACE_BYTES], ()> {
    let mut namespace = [0u8; PROCESS_NAMESPACE_BYTES];
    let mut filled = 0usize;
    while filled < namespace.len() {
        let remaining = match namespace.get_mut(filled..) {
            Some(remaining) => remaining,
            None => {
                wipe::bytes(&mut namespace);
                return Err(());
            }
        };
        match source.read(remaining) {
            Ok(0) | Err(_) => {
                wipe::bytes(&mut namespace);
                return Err(());
            }
            Ok(count) => {
                filled = match filled.checked_add(count) {
                    Some(value) if value <= namespace.len() => value,
                    _ => {
                        wipe::bytes(&mut namespace);
                        return Err(());
                    }
                };
            }
        }
    }
    Ok(namespace)
}

/// Deterministic public-data mint used only by unit tests and ring-fenced fuzzing.
#[cfg(any(test, feature = "fuzzing"))]
pub(crate) struct DeterministicSessionIdMint {
    inner: ProcessMint,
}

#[cfg(any(test, feature = "fuzzing"))]
impl DeterministicSessionIdMint {
    pub(crate) const fn new(namespace: [u8; PROCESS_NAMESPACE_BYTES], last_counter: u32) -> Self {
        Self {
            inner: ProcessMint::deterministic(namespace, last_counter),
        }
    }

    pub(crate) fn mint(&mut self) -> Result<SessionId, SessionIdError> {
        self.inner.mint_with(|| Err(()))
    }
}

#[cfg(test)]
#[allow(
    clippy::arithmetic_side_effects,
    clippy::indexing_slicing,
    clippy::panic,
    clippy::unwrap_used
)]
mod tests {
    use super::{
        mint_locked, read_namespace, DeterministicSessionIdMint, ProcessMint, SessionIdError,
        PROCESS_NAMESPACE_BYTES,
    };
    use crate::wipe::{reset_wiped_bytes, wiped_bytes};
    use std::cell::Cell;
    use std::io::{self, Read};
    use std::panic::{catch_unwind, AssertUnwindSafe};
    use std::sync::{Arc, Mutex};

    struct ShortReader {
        bytes: [u8; PROCESS_NAMESPACE_BYTES],
        offset: usize,
        maximum: usize,
        calls: usize,
    }

    impl Read for ShortReader {
        fn read(&mut self, output: &mut [u8]) -> io::Result<usize> {
            self.calls += 1;
            let remaining = self.bytes.len() - self.offset;
            let count = remaining.min(self.maximum).min(output.len());
            output[..count].copy_from_slice(&self.bytes[self.offset..self.offset + count]);
            self.offset += count;
            Ok(count)
        }
    }

    #[test]
    fn deterministic_ids_are_namespace_plus_increasing_little_endian_counter() {
        let namespace = [0u8; PROCESS_NAMESPACE_BYTES];
        let mut mint = DeterministicSessionIdMint::new(namespace, 0);
        let first = mint.mint().unwrap();
        let second = mint.mint().unwrap();

        assert_eq!(&first.as_bytes()[..PROCESS_NAMESPACE_BYTES], &namespace);
        assert_eq!(&first.as_bytes()[PROCESS_NAMESPACE_BYTES..], &[1, 0, 0, 0]);
        assert_eq!(&second.as_bytes()[..PROCESS_NAMESPACE_BYTES], &namespace);
        assert_eq!(&second.as_bytes()[PROCESS_NAMESPACE_BYTES..], &[2, 0, 0, 0]);
    }

    #[test]
    fn maximum_counter_is_issued_once_then_exhaustion_is_permanent() {
        let mut mint =
            DeterministicSessionIdMint::new([0x42; PROCESS_NAMESPACE_BYTES], u32::MAX - 1);
        let final_id = mint.mint().unwrap();
        assert_eq!(
            &final_id.as_bytes()[PROCESS_NAMESPACE_BYTES..],
            &u32::MAX.to_le_bytes()
        );
        assert_eq!(mint.mint().err(), Some(SessionIdError::Exhausted));
        assert_eq!(mint.mint().err(), Some(SessionIdError::Exhausted));
    }

    #[test]
    fn short_reads_continue_on_the_same_reader_until_exactly_complete() {
        let expected = [0x6d; PROCESS_NAMESPACE_BYTES];
        let mut source = ShortReader {
            bytes: expected,
            offset: 0,
            maximum: 3,
            calls: 0,
        };
        assert_eq!(read_namespace(&mut source).unwrap(), expected);
        assert_eq!(source.calls, 4);
    }

    #[test]
    fn eof_or_read_error_fails_without_returning_partial_namespace() {
        let mut eof = io::Cursor::new([0x11; 5]);
        assert!(read_namespace(&mut eof).is_err());

        struct FailedReader;
        impl Read for FailedReader {
            fn read(&mut self, _output: &mut [u8]) -> io::Result<usize> {
                Err(io::Error::other("test-only read failure"))
            }
        }
        assert!(read_namespace(&mut FailedReader).is_err());
    }

    #[test]
    fn namespace_failure_is_latched_and_never_tries_an_alternate_source() {
        let calls = Cell::new(0usize);
        let mut mint = ProcessMint::uninitialized();
        assert_eq!(
            mint.mint_with(|| {
                calls.set(calls.get() + 1);
                Err(())
            })
            .err(),
            Some(SessionIdError::Unavailable)
        );
        assert_eq!(
            mint.mint_with(|| {
                calls.set(calls.get() + 1);
                Ok([0xa5; PROCESS_NAMESPACE_BYTES])
            })
            .err(),
            Some(SessionIdError::Unavailable)
        );
        assert_eq!(calls.get(), 1);
    }

    #[test]
    fn lock_poisoning_maps_to_unavailable_without_loading_a_source() {
        let mint = Arc::new(Mutex::new(ProcessMint::uninitialized()));
        let poisoned = Arc::clone(&mint);
        let result = catch_unwind(AssertUnwindSafe(move || {
            let _guard = poisoned.lock().unwrap();
            panic!("test-only lock poisoning");
        }));
        assert!(result.is_err());

        let called = Cell::new(false);
        assert_eq!(
            mint_locked(&mint, || {
                called.set(true);
                Ok([0x55; PROCESS_NAMESPACE_BYTES])
            })
            .err(),
            Some(SessionIdError::Unavailable)
        );
        assert!(!called.get());
    }

    #[test]
    fn every_owned_id_and_deterministic_namespace_clear_on_drop() {
        let mut mint = DeterministicSessionIdMint::new([0xc3; PROCESS_NAMESPACE_BYTES], 0);
        let id = mint.mint().unwrap();
        reset_wiped_bytes();
        drop(id);
        assert_eq!(wiped_bytes(), 16);

        reset_wiped_bytes();
        drop(mint);
        assert_eq!(wiped_bytes(), PROCESS_NAMESPACE_BYTES);
    }
}
