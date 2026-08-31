//! Optimization-resistant cleanup owners for qk-io-owned transport bytes.

use core::ptr;
use core::sync::atomic::{compiler_fence, Ordering};

#[cfg(any(test, feature = "fuzzing"))]
use std::cell::Cell;

#[cfg(any(test, feature = "fuzzing"))]
thread_local! {
    static WIPED_BYTES: Cell<usize> = const { Cell::new(0) };
}

#[allow(unsafe_code)]
#[inline(never)]
pub(crate) fn bytes(value: &mut [u8]) {
    #[cfg(any(test, feature = "fuzzing"))]
    let byte_count = value.len();
    for byte in value {
        // SAFETY: every byte is live and uniquely borrowed for this write.
        unsafe { ptr::write_volatile(byte, 0) };
    }
    compiler_fence(Ordering::SeqCst);
    #[cfg(any(test, feature = "fuzzing"))]
    WIPED_BYTES.with(|count| count.set(count.get().saturating_add(byte_count)));
}

#[allow(unsafe_code)]
#[inline(never)]
fn allocation(pointer: *mut u8, byte_count: usize) {
    for offset in 0..byte_count {
        // SAFETY: the caller supplies the live allocation pointer and its
        // exact capacity. Each raw byte write stays within that allocation.
        unsafe { ptr::write_volatile(pointer.add(offset), 0) };
    }
    compiler_fence(Ordering::SeqCst);
    #[cfg(any(test, feature = "fuzzing"))]
    WIPED_BYTES.with(|count| count.set(count.get().saturating_add(byte_count)));
}

pub(crate) struct WipingVec(Vec<u8>);

impl WipingVec {
    pub(crate) fn try_zeroed(length: usize) -> Result<Self, ()> {
        let mut value = Vec::new();
        value.try_reserve_exact(length).map_err(|_| ())?;
        value.resize(length, 0);
        Ok(Self(value))
    }

    pub(crate) fn try_from_slice(bytes: &[u8]) -> Result<Self, ()> {
        let mut value = Self::try_zeroed(bytes.len())?;
        value.as_mut_slice().copy_from_slice(bytes);
        Ok(value)
    }

    pub(crate) fn as_slice(&self) -> &[u8] {
        &self.0
    }

    pub(crate) fn as_mut_slice(&mut self) -> &mut [u8] {
        &mut self.0
    }

    pub(crate) fn len(&self) -> usize {
        self.0.len()
    }

    pub(crate) fn truncate(&mut self, length: usize) {
        self.0.truncate(length);
    }

    #[cfg(test)]
    pub(crate) fn capacity(&self) -> usize {
        self.0.capacity()
    }
}

impl Drop for WipingVec {
    fn drop(&mut self) {
        let capacity = self.0.capacity();
        if capacity == 0 {
            compiler_fence(Ordering::SeqCst);
        } else {
            allocation(self.0.as_mut_ptr(), capacity);
        }
    }
}

#[cfg(any(test, feature = "fuzzing"))]
pub fn reset_wiped_bytes() {
    WIPED_BYTES.with(|count| count.set(0));
}

#[cfg(any(test, feature = "fuzzing"))]
pub fn wiped_bytes() -> usize {
    WIPED_BYTES.with(Cell::get)
}

#[cfg(test)]
#[allow(clippy::panic, clippy::unwrap_used)]
mod tests {
    use super::{bytes, reset_wiped_bytes, wiped_bytes, WipingVec};
    use std::panic::{catch_unwind, AssertUnwindSafe};

    #[test]
    fn fixed_slice_uses_observable_writes() {
        let mut value = [0xa5; 32];
        reset_wiped_bytes();
        bytes(&mut value);
        assert_eq!(value, [0; 32]);
        assert_eq!(wiped_bytes(), 32);
    }

    #[test]
    fn allocation_owner_clears_live_and_spare_capacity() {
        let owner = WipingVec::try_zeroed(71).unwrap();
        let capacity = owner.capacity();
        reset_wiped_bytes();
        drop(owner);
        assert_eq!(wiped_bytes(), capacity);
    }

    #[test]
    fn allocation_owner_clears_during_caught_unwind() {
        let owner = WipingVec::try_zeroed(137).unwrap();
        let capacity = owner.capacity();
        reset_wiped_bytes();
        let result = catch_unwind(AssertUnwindSafe(move || {
            let _owner = owner;
            panic!("test-only caught unwind");
        }));
        assert!(result.is_err());
        assert_eq!(wiped_bytes(), capacity);
    }
}
