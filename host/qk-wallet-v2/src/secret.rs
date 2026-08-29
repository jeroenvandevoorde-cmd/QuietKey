//! Private fixed-size secret owner for HOST reference intermediates.

#![allow(unsafe_code)]
#![deny(unsafe_op_in_unsafe_fn)]

use core::ptr;
use core::sync::atomic::{compiler_fence, Ordering};

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

/// Optimization-resistant clearing for private scratch bytes.
#[inline(never)]
pub(crate) fn wipe(bytes: &mut [u8]) {
    #[cfg(test)]
    let byte_count = bytes.len();
    for byte in bytes {
        // SAFETY: byte is a uniquely borrowed live byte. Volatile
        // writes make the clearing operation observable to the
        // abstract machine and prevent dead-store elimination.
        unsafe { ptr::write_volatile(byte, 0) };
    }
    compiler_fence(Ordering::SeqCst);
    #[cfg(test)]
    WIPED_BYTES.with(|count| count.set(count.get().saturating_add(byte_count)));
}

/// Non-copyable, non-debuggable fixed-size bytes cleared on drop.
pub(crate) struct Secret<const N: usize> {
    bytes: [u8; N],
}

impl<const N: usize> Secret<N> {
    /// Move one caller-owned scratch buffer into this owner, then wipe the
    /// exact caller buffer before returning.
    pub(crate) fn take(bytes: &mut [u8; N]) -> Self {
        let owned = Self { bytes: *bytes };
        wipe(bytes);
        owned
    }

    pub(crate) const fn zeroed() -> Self {
        Self { bytes: [0u8; N] }
    }

    pub(crate) fn as_bytes(&self) -> &[u8; N] {
        &self.bytes
    }

    pub(crate) fn as_mut_bytes(&mut self) -> &mut [u8; N] {
        &mut self.bytes
    }
}

impl<const N: usize> Drop for Secret<N> {
    fn drop(&mut self) {
        wipe(&mut self.bytes);
    }
}

#[cfg(test)]
mod tests {
    use super::wipe;

    #[test]
    fn volatile_wipe_clears_arbitrary_slice_lengths_only() {
        for length in [0, 1, 12, 31, 32, 37, 64, 100, 128, 215] {
            let mut storage = [0xa5; 221];
            wipe(&mut storage[3..3 + length]);
            assert_eq!(storage[..3], [0xa5; 3]);
            assert!(storage[3..3 + length].iter().all(|&byte| byte == 0));
            assert!(storage[3 + length..].iter().all(|&byte| byte == 0xa5));
        }
    }
}
