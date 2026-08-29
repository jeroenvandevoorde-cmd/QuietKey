//! Private fixed-size secret ownership and optimization-resistant clearing.

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
    WIPED_BYTES.with(|count| count.get())
}

/// Clear private scratch bytes with observable volatile writes.
#[inline(never)]
pub(crate) fn wipe(bytes: &mut [u8]) {
    #[cfg(test)]
    let byte_count = bytes.len();
    for byte in bytes {
        // SAFETY: `byte` is a uniquely borrowed, live byte. A volatile write
        // makes the clearing operation observable to the abstract machine.
        unsafe { ptr::write_volatile(byte, 0) };
    }
    compiler_fence(Ordering::SeqCst);
    #[cfg(test)]
    WIPED_BYTES.with(|count| count.set(count.get().saturating_add(byte_count)));
}

/// Clear private SHA-256 words with observable volatile writes.
#[inline(never)]
pub(crate) fn wipe_u32(words: &mut [u32]) {
    for word in words {
        // SAFETY: `word` is a uniquely borrowed, live word. A volatile write
        // makes the clearing operation observable to the abstract machine.
        unsafe { ptr::write_volatile(word, 0) };
    }
    compiler_fence(Ordering::SeqCst);
}

/// Non-copyable, non-debuggable fixed-size bytes cleared on drop.
pub(crate) struct Secret<const N: usize> {
    bytes: [u8; N],
}

impl<const N: usize> Secret<N> {
    pub(crate) const fn zeroed() -> Self {
        Self { bytes: [0u8; N] }
    }

    pub(crate) fn copy_from(bytes: &[u8; N]) -> Self {
        Self { bytes: *bytes }
    }

    /// Transfer caller scratch into this owner and clear the caller scratch.
    pub(crate) fn take(bytes: &mut [u8; N]) -> Self {
        let owned = Self { bytes: *bytes };
        wipe(bytes);
        owned
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
    use super::{reset_wiped_bytes, wiped_bytes, Secret};

    #[test]
    fn taking_secret_bytes_clears_the_caller_scratch() {
        let mut scratch = [0x5au8; 96];
        let owner = Secret::take(&mut scratch);
        assert_eq!(scratch, [0u8; 96]);
        assert_eq!(owner.as_bytes(), &[0x5au8; 96]);
        drop(owner);
    }

    #[test]
    fn dropping_a_secret_routes_every_owned_byte_through_volatile_wipe() {
        reset_wiped_bytes();
        let owner = Secret::copy_from(&[0x5au8; 96]);
        drop(owner);
        assert_eq!(wiped_bytes(), 96);
    }
}
