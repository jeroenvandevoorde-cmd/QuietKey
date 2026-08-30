//! Private optimization-resistant owner for transaction-bearing heap bytes.

#![deny(unsafe_op_in_unsafe_fn)]

use core::ops::{Deref, DerefMut};
use core::ptr;
use core::sync::atomic::{compiler_fence, Ordering};

#[allow(unsafe_code)]
#[inline(never)]
pub(crate) fn wipe_bytes(bytes: &mut [u8]) {
    #[cfg(test)]
    let byte_count = bytes.len();
    for byte in bytes {
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
fn wipe_allocation(pointer: *mut u8, byte_count: usize) {
    for offset in 0..byte_count {
        // SAFETY: the caller proves that `pointer` owns `byte_count` writable
        // allocation bytes. Raw volatile writes do not assert that spare Vec
        // capacity was previously initialized.
        unsafe { ptr::write_volatile(pointer.add(offset), 0) };
    }
    compiler_fence(Ordering::SeqCst);
    #[cfg(test)]
    WIPED_BYTES.with(|count| count.set(count.get().saturating_add(byte_count)));
}

#[allow(unsafe_code)]
pub(crate) fn wipe_vec(bytes: &mut Vec<u8>) {
    let capacity = bytes.capacity();
    if capacity == 0 {
        compiler_fence(Ordering::SeqCst);
        return;
    }
    wipe_allocation(bytes.as_mut_ptr(), capacity);
}

/// One fixed-size scratch array cleared on every exit path.
pub(crate) struct WipingArray<const N: usize> {
    bytes: [u8; N],
}

impl<const N: usize> WipingArray<N> {
    pub(crate) const fn zeroed() -> Self {
        Self { bytes: [0; N] }
    }

    pub(crate) const fn as_slice(&self) -> &[u8; N] {
        &self.bytes
    }

    pub(crate) fn as_mut_slice(&mut self) -> &mut [u8; N] {
        &mut self.bytes
    }
}

impl<const N: usize> Drop for WipingArray<N> {
    fn drop(&mut self) {
        wipe_bytes(&mut self.bytes);
    }
}

/// One non-clonable transaction byte owner that clears its allocation on drop.
#[allow(dead_code)]
pub(crate) struct WipingVec {
    bytes: Vec<u8>,
}

#[allow(dead_code)]
impl WipingVec {
    pub(crate) fn take(bytes: Vec<u8>) -> Self {
        Self { bytes }
    }

    pub(crate) fn as_slice(&self) -> &[u8] {
        &self.bytes
    }

    pub(crate) fn as_mut_vec(&mut self) -> &mut Vec<u8> {
        &mut self.bytes
    }

    pub(crate) fn into_vec(mut self) -> Vec<u8> {
        core::mem::take(&mut self.bytes)
    }
}

impl Deref for WipingVec {
    type Target = Vec<u8>;

    fn deref(&self) -> &Self::Target {
        &self.bytes
    }
}

impl DerefMut for WipingVec {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.bytes
    }
}

impl Drop for WipingVec {
    fn drop(&mut self) {
        wipe_vec(&mut self.bytes);
    }
}

#[cfg(test)]
use core::cell::Cell;

#[cfg(test)]
std::thread_local! {
    static WIPED_BYTES: Cell<usize> = const { Cell::new(0) };
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
mod tests {
    use super::{reset_wiped_bytes, wiped_bytes, WipingVec};

    #[test]
    fn owned_heap_bytes_are_cleared_on_drop() {
        reset_wiped_bytes();
        drop(WipingVec::take(vec![0xa5; 37]));
        assert_eq!(wiped_bytes(), 37);
    }

    #[test]
    fn spare_allocation_bytes_are_cleared_with_live_transaction_bytes() {
        let mut bytes = Vec::with_capacity(64);
        bytes.extend_from_slice(&[0xa5; 7]);
        assert_eq!(bytes.capacity(), 64);
        reset_wiped_bytes();
        drop(WipingVec::take(bytes));
        assert_eq!(wiped_bytes(), 64);
    }
}
