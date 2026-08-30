//! Private optimization-resistant owner for transaction-bearing heap bytes.

#![deny(unsafe_op_in_unsafe_fn)]

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

pub(crate) fn wipe_vec(bytes: &mut Vec<u8>) {
    wipe_bytes(bytes.as_mut_slice());
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
}
