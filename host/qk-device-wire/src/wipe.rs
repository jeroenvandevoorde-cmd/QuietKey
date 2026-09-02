//! One private optimization-resistant full-allocation clearing boundary.

use core::ptr;
use core::sync::atomic::{compiler_fence, Ordering};

#[cfg(feature = "fuzzing")]
use core::cell::Cell;

#[cfg(feature = "fuzzing")]
std::thread_local! {
    static WIPED_BYTES: Cell<usize> = const { Cell::new(0) };
}

/// Clear initialized bytes with observable writes.
#[allow(unsafe_code)]
#[inline(never)]
pub(crate) fn bytes(value: &mut [u8]) {
    #[cfg(feature = "fuzzing")]
    let byte_count = value.len();
    for byte in value {
        // SAFETY: every byte is live and uniquely borrowed for this write.
        unsafe { ptr::write_volatile(byte, 0) };
    }
    compiler_fence(Ordering::SeqCst);
    #[cfg(feature = "fuzzing")]
    WIPED_BYTES.with(|count| count.set(count.get().saturating_add(byte_count)));
}

/// Clear a live byte allocation, including spare capacity.
#[allow(unsafe_code)]
#[inline(never)]
fn allocation(pointer: *mut u8, byte_count: usize) {
    for offset in 0..byte_count {
        // SAFETY: the owner supplies its live allocation pointer and exact
        // capacity. Raw byte writes create no typed reference to spare bytes.
        unsafe { ptr::write_volatile(pointer.add(offset), 0) };
    }
    compiler_fence(Ordering::SeqCst);
    #[cfg(feature = "fuzzing")]
    WIPED_BYTES.with(|count| count.set(count.get().saturating_add(byte_count)));
}

/// Private fallibly allocated owner clearing its complete capacity on drop.
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

    #[cfg(feature = "fuzzing")]
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

#[cfg(feature = "fuzzing")]
pub fn reset_wiped_bytes() {
    WIPED_BYTES.with(|count| count.set(0));
}

#[cfg(feature = "fuzzing")]
pub fn wiped_bytes() -> usize {
    WIPED_BYTES.with(Cell::get)
}
