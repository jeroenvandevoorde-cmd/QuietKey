//! One private optimization-resistant byte-clearing boundary.

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

/// Clear one live writable allocation, including uninitialized spare bytes.
#[allow(unsafe_code)]
#[inline(never)]
fn allocation(pointer: *mut u8, byte_count: usize) {
    for offset in 0..byte_count {
        // SAFETY: the caller passes the live allocation pointer and its exact
        // capacity. Raw byte writes do not create typed references to spare
        // bytes and every offset remains within the allocation.
        unsafe { ptr::write_volatile(pointer.add(offset), 0) };
    }
    compiler_fence(Ordering::SeqCst);
    #[cfg(test)]
    WIPED_BYTES.with(|count| count.set(count.get().saturating_add(byte_count)));
}

/// Private fallibly allocated byte owner that clears its complete capacity.
#[derive(Default)]
pub(crate) struct WipingByteVec(Vec<u8>);

impl WipingByteVec {
    pub(crate) fn try_zeroed(length: usize) -> Result<Self, ()> {
        let mut bytes = Vec::new();
        bytes.try_reserve_exact(length).map_err(|_| ())?;
        bytes.resize(length, 0);
        Ok(Self(bytes))
    }

    pub(crate) fn as_slice(&self) -> &[u8] {
        &self.0
    }

    pub(crate) fn as_mut_slice(&mut self) -> &mut [u8] {
        &mut self.0
    }

    #[cfg(test)]
    pub(crate) fn capacity(&self) -> usize {
        self.0.capacity()
    }
}

impl Drop for WipingByteVec {
    fn drop(&mut self) {
        let capacity = self.0.capacity();
        if capacity == 0 {
            compiler_fence(Ordering::SeqCst);
            return;
        }
        allocation(self.0.as_mut_ptr(), capacity);
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
#[allow(clippy::unwrap_used, clippy::panic)]
mod tests {
    use super::{bytes, reset_wiped_bytes, wiped_bytes, WipingByteVec};
    use std::panic::{catch_unwind, AssertUnwindSafe};

    #[test]
    fn slice_clear_uses_every_byte() {
        let mut value = [0xa5; 32];
        reset_wiped_bytes();
        bytes(&mut value);
        assert_eq!(value, [0; 32]);
        assert_eq!(wiped_bytes(), 32);
    }

    #[test]
    fn allocation_owner_clears_live_and_spare_bytes() {
        let owner = WipingByteVec::try_zeroed(71).unwrap();
        let capacity = owner.capacity();
        reset_wiped_bytes();
        drop(owner);
        assert_eq!(wiped_bytes(), capacity);
    }

    #[test]
    fn allocation_owner_clears_during_caught_unwind() {
        let owner = WipingByteVec::try_zeroed(137).unwrap();
        let capacity = owner.capacity();
        reset_wiped_bytes();
        let result = catch_unwind(AssertUnwindSafe(move || {
            let _kept_alive = owner;
            panic!("test-only caught unwind");
        }));
        assert!(result.is_err());
        assert_eq!(wiped_bytes(), capacity);
    }
}
