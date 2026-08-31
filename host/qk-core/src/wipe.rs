//! Optimization-resistant cleanup owners for qk-core-owned bytes.

use core::ptr;
use core::sync::atomic::{compiler_fence, Ordering};

#[cfg(any(test, feature = "fuzzing"))]
use std::cell::Cell;

#[cfg(any(test, feature = "fuzzing"))]
thread_local! {
    static WIPED_BYTES: Cell<usize> = const { Cell::new(0) };
}

/// Clear initialized bytes with observable writes.
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

/// Clear a complete live byte allocation, including spare capacity.
#[allow(unsafe_code)]
#[inline(never)]
fn allocation(pointer: *mut u8, byte_count: usize) {
    for offset in 0..byte_count {
        // SAFETY: the caller supplies the live allocation pointer and its exact
        // capacity. Every raw byte write remains within that allocation.
        unsafe { ptr::write_volatile(pointer.add(offset), 0) };
    }
    compiler_fence(Ordering::SeqCst);
    #[cfg(any(test, feature = "fuzzing"))]
    WIPED_BYTES.with(|count| count.set(count.get().saturating_add(byte_count)));
}

/// Fallibly allocated byte owner that clears its complete capacity on drop.
pub(crate) struct WipingVec(Vec<u8>);

impl WipingVec {
    pub(crate) fn try_zeroed(length: usize) -> Result<Self, ()> {
        let mut value = Vec::new();
        value.try_reserve_exact(length).map_err(|_| ())?;
        value.resize(length, 0);
        Ok(Self(value))
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
#[allow(
    clippy::arithmetic_side_effects,
    clippy::indexing_slicing,
    clippy::panic,
    clippy::unwrap_used
)]
mod tests {
    use super::{bytes, reset_wiped_bytes, wiped_bytes, WipingVec};
    use std::panic::{catch_unwind, AssertUnwindSafe};

    #[test]
    fn fixed_slice_is_cleared_with_exact_accounting() {
        let mut value = [0xa5; 37];
        reset_wiped_bytes();
        bytes(&mut value);
        assert_eq!(value, [0; 37]);
        assert_eq!(wiped_bytes(), 37);
    }

    #[test]
    fn allocated_owner_clears_length_and_spare_capacity() {
        let mut raw = Vec::with_capacity(137);
        raw.extend_from_slice(b"qk-core");
        let capacity = raw.capacity();
        assert!(capacity > raw.len());
        let owner = WipingVec(raw);

        reset_wiped_bytes();
        drop(owner);
        assert_eq!(wiped_bytes(), capacity);
    }

    #[test]
    fn constructor_preserves_exact_bytes_and_drop_clears_capacity() {
        let expected = b"hostile transport bytes";
        let mut owner = WipingVec::try_zeroed(expected.len()).unwrap();
        owner.as_mut_slice().copy_from_slice(expected);
        assert_eq!(owner.as_slice(), expected);
        assert_eq!(owner.len(), expected.len());
        owner.as_mut_slice()[0] = b'H';
        assert_eq!(&owner.as_slice()[..7], b"Hostile");
        let capacity = owner.0.capacity();

        reset_wiped_bytes();
        drop(owner);
        assert_eq!(wiped_bytes(), capacity);
    }

    #[test]
    fn allocation_owner_clears_during_caught_unwind() {
        let owner = WipingVec::try_zeroed(83).unwrap();
        let capacity = owner.0.capacity();
        reset_wiped_bytes();
        let result = catch_unwind(AssertUnwindSafe(move || {
            let _owner = owner;
            panic!("test-only caught unwind");
        }));
        assert!(result.is_err());
        assert_eq!(wiped_bytes(), capacity);
    }
}
