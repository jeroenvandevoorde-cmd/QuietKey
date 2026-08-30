//! Private optimization-resistant clearing for owned staging bytes.

use core::ops::{Deref, DerefMut};
use core::ptr;
use core::sync::atomic::{compiler_fence, Ordering};

#[cfg(test)]
use core::cell::Cell;

#[cfg(test)]
std::thread_local! {
    static WIPED_BYTES: Cell<usize> = const { Cell::new(0) };
}

/// Clear initialized bytes with observable writes.
#[allow(unsafe_code)]
#[inline(never)]
#[cfg(test)]
pub(crate) fn bytes(value: &mut [u8]) {
    #[cfg(test)]
    let byte_count = value.len();
    for byte in value {
        // SAFETY: every byte is live and uniquely borrowed for this write.
        unsafe { ptr::write_volatile(byte, 0) };
    }
    compiler_fence(Ordering::SeqCst);
    #[cfg(test)]
    WIPED_BYTES.with(|count| count.set(count.get().saturating_add(byte_count)));
}

/// Clear one complete owned allocation without forming references to spare
/// capacity, which need not contain initialized Rust values.
#[allow(unsafe_code)]
#[inline(never)]
fn allocation(pointer: *mut u8, byte_count: usize) {
    for offset in 0..byte_count {
        // SAFETY: callers provide a live allocation pointer and its exact byte
        // capacity. Raw volatile writes may initialize spare allocation bytes
        // without claiming that they previously held valid Rust values.
        unsafe { ptr::write_volatile(pointer.add(offset), 0) };
    }
    compiler_fence(Ordering::SeqCst);
    #[cfg(test)]
    WIPED_BYTES.with(|count| count.set(count.get().saturating_add(byte_count)));
}

/// Clear a byte vector's live bytes and complete spare capacity.
#[allow(unsafe_code)]
#[inline(never)]
pub(crate) fn byte_vec(value: &mut Vec<u8>) {
    let capacity = value.capacity();
    if capacity == 0 {
        compiler_fence(Ordering::SeqCst);
        return;
    }
    allocation(value.as_mut_ptr(), capacity);
}

/// Non-clonable byte-vector owner whose complete allocation is cleared on
/// ordinary return, named rejection, and stack unwind.
pub(crate) struct WipingByteVec {
    value: Vec<u8>,
}

impl WipingByteVec {
    pub(crate) const fn new() -> Self {
        Self { value: Vec::new() }
    }

    /// Adopt an existing allocation without copying it.
    #[cfg(test)]
    pub(crate) fn take(value: Vec<u8>) -> Self {
        Self { value }
    }

    /// Fallibly own one exact private copy of hostile source bytes.
    #[cfg(test)]
    pub(crate) fn try_copy_from(source: &[u8]) -> Result<Self, std::collections::TryReserveError> {
        let mut owner = Self::new();
        owner.try_reserve_exact(source.len())?;
        owner.extend_from_slice(source);
        Ok(owner)
    }

    pub(crate) fn as_slice(&self) -> &[u8] {
        &self.value
    }
}

impl Deref for WipingByteVec {
    type Target = Vec<u8>;

    fn deref(&self) -> &Self::Target {
        &self.value
    }
}

impl DerefMut for WipingByteVec {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.value
    }
}

impl Drop for WipingByteVec {
    fn drop(&mut self) {
        byte_vec(&mut self.value);
    }
}

#[cfg(test)]
pub(crate) fn reset_wiped_bytes() {
    WIPED_BYTES.with(|count| count.set(0));
}

#[cfg(test)]
pub(crate) fn wiped_bytes() -> usize {
    WIPED_BYTES.with(Cell::get)
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::panic, clippy::arithmetic_side_effects)]
mod tests {
    use super::{bytes, reset_wiped_bytes, wiped_bytes, WipingByteVec};
    use std::panic::{catch_unwind, AssertUnwindSafe};

    #[test]
    fn slice_clear_routes_every_live_byte_through_volatile_writes() {
        let mut value = [0xa5; 19];
        reset_wiped_bytes();
        bytes(&mut value);
        assert_eq!(value, [0; 19]);
        assert_eq!(wiped_bytes(), 19);
    }

    #[test]
    fn owner_clears_live_and_spare_allocation() {
        let mut owner = WipingByteVec::new();
        owner.try_reserve_exact(64).unwrap();
        owner.extend_from_slice(&[0xa5; 7]);
        let capacity = owner.capacity();
        reset_wiped_bytes();
        drop(owner);
        assert_eq!(wiped_bytes(), capacity);
    }

    #[test]
    fn copied_owner_clears_when_a_caller_catches_unwind() {
        let owner = WipingByteVec::try_copy_from(&[0x5a; 37]).unwrap();
        let capacity = owner.capacity();
        reset_wiped_bytes();
        let result = catch_unwind(AssertUnwindSafe(move || {
            let _kept_alive = owner;
            panic!("test-only caught unwind");
        }));
        assert!(result.is_err());
        assert_eq!(wiped_bytes(), capacity);
    }

    #[test]
    fn adopted_owner_keeps_cleanup_attached_to_the_allocation() {
        let mut value = Vec::with_capacity(71);
        value.extend_from_slice(&[0x3c; 8]);
        let capacity = value.capacity();
        reset_wiped_bytes();
        drop(WipingByteVec::take(value));
        assert_eq!(wiped_bytes(), capacity);
    }
}
