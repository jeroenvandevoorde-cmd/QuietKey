//! One private optimization-resistant byte-clearing boundary.

use core::mem;
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

/// Clear an owned allocation without creating references to spare capacity.
#[allow(unsafe_code)]
#[inline(never)]
fn allocation(pointer: *mut u8, byte_count: usize) {
    for offset in 0..byte_count {
        // SAFETY: callers pass a live allocation pointer and its exact byte
        // capacity. Raw volatile writes do not claim spare bytes were already
        // initialized as Rust values.
        unsafe { ptr::write_volatile(pointer.add(offset), 0) };
    }
    compiler_fence(Ordering::SeqCst);
    #[cfg(test)]
    WIPED_BYTES.with(|count| count.set(count.get().saturating_add(byte_count)));
}

/// Clear boolean occupancy facts with observable writes.
#[allow(unsafe_code)]
#[inline(never)]
pub(crate) fn bools(value: &mut [bool]) {
    #[cfg(test)]
    let byte_count = value.len();
    for item in value {
        // SAFETY: every bool is live, uniquely borrowed, and `false` is a
        // valid bool representation.
        unsafe { ptr::write_volatile(item, false) };
    }
    compiler_fence(Ordering::SeqCst);
    #[cfg(test)]
    WIPED_BYTES.with(|count| count.set(count.get().saturating_add(byte_count)));
}

/// Fixed-size byte owner whose complete value is cleared on every drop path.
pub(crate) struct ByteArray<const N: usize> {
    value: [u8; N],
}

impl<const N: usize> ByteArray<N> {
    pub(crate) const fn new(value: [u8; N]) -> Self {
        Self { value }
    }

    pub(crate) const fn value(&self) -> [u8; N] {
        self.value
    }

    pub(crate) const fn as_array(&self) -> &[u8; N] {
        &self.value
    }

    /// Move the value out while leaving a zero value for this owner's drop.
    pub(crate) fn take(&mut self) -> [u8; N] {
        core::mem::replace(&mut self.value, [0; N])
    }
}

impl<const N: usize> Drop for ByteArray<N> {
    fn drop(&mut self) {
        bytes(&mut self.value);
    }
}

/// Clear a byte vector's complete live allocation, including spare capacity.
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

/// Clear the backing allocation of an already-empty vector of plain values.
///
/// Callers must pop and drop every live element first. The vector remains
/// empty and retains its allocation solely until its ordinary deallocation.
#[allow(unsafe_code)]
#[inline(never)]
pub(crate) fn empty_vec_allocation<T>(value: &mut Vec<T>) {
    debug_assert!(value.is_empty());
    let Some(byte_count) = value.capacity().checked_mul(mem::size_of::<T>()) else {
        compiler_fence(Ordering::SeqCst);
        return;
    };
    if byte_count == 0 {
        compiler_fence(Ordering::SeqCst);
        return;
    }
    allocation(value.as_mut_ptr().cast::<u8>(), byte_count);
}

#[cfg(test)]
pub(crate) fn reset_wiped_bytes() {
    WIPED_BYTES.with(|count| count.set(0));
}

#[cfg(test)]
pub(crate) fn wiped_bytes() -> usize {
    WIPED_BYTES.with(Cell::get)
}
