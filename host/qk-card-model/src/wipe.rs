//! Private volatile-wipe owners for model-held secret material.

#![deny(unsafe_op_in_unsafe_fn)]

use core::ptr;
use core::sync::atomic::{compiler_fence, Ordering};

#[cfg(any(test, feature = "fuzzing"))]
use core::sync::atomic::AtomicUsize;

#[cfg(any(test, feature = "fuzzing"))]
static WIPED_BYTES: AtomicUsize = AtomicUsize::new(0);

/// Optimization-resistant clearing for private scratch bytes.
#[inline(never)]
pub(crate) fn bytes(value: &mut [u8]) {
    #[cfg(any(test, feature = "fuzzing"))]
    let len = value.len();
    for byte in value {
        // SAFETY: `byte` is a uniquely borrowed live byte. Volatile writes and
        // the following compiler fence prevent dead-store elimination.
        unsafe { ptr::write_volatile(byte, 0) };
    }
    compiler_fence(Ordering::SeqCst);
    #[cfg(any(test, feature = "fuzzing"))]
    WIPED_BYTES.fetch_add(len, Ordering::SeqCst);
}

pub(crate) fn words64(value: &mut [u64]) {
    #[cfg(any(test, feature = "fuzzing"))]
    let len = value.len().saturating_mul(core::mem::size_of::<u64>());
    for word in value {
        // SAFETY: `word` is a uniquely borrowed live word.
        unsafe { ptr::write_volatile(word, 0) };
    }
    compiler_fence(Ordering::SeqCst);
    #[cfg(any(test, feature = "fuzzing"))]
    WIPED_BYTES.fetch_add(len, Ordering::SeqCst);
}

pub(crate) fn words32(value: &mut [u32]) {
    #[cfg(any(test, feature = "fuzzing"))]
    let len = value.len().saturating_mul(core::mem::size_of::<u32>());
    for word in value {
        // SAFETY: `word` is a uniquely borrowed live word.
        unsafe { ptr::write_volatile(word, 0) };
    }
    compiler_fence(Ordering::SeqCst);
    #[cfg(any(test, feature = "fuzzing"))]
    WIPED_BYTES.fetch_add(len, Ordering::SeqCst);
}

/// Stack-resident scratch that is always cleared, including during unwind.
pub(crate) struct WipingArray<const N: usize> {
    value: [u8; N],
}

impl<const N: usize> WipingArray<N> {
    pub(crate) const fn zeroed() -> Self {
        Self { value: [0u8; N] }
    }
    pub(crate) fn from_source(source: &mut [u8; N]) -> Self {
        let value = *source;
        bytes(source);
        Self { value }
    }
    pub(crate) const fn as_array(&self) -> &[u8; N] {
        &self.value
    }
    pub(crate) fn as_mut_array(&mut self) -> &mut [u8; N] {
        &mut self.value
    }
    pub(crate) fn as_slice(&self) -> &[u8] {
        &self.value
    }
    pub(crate) fn as_mut_slice(&mut self) -> &mut [u8] {
        &mut self.value
    }
}

impl<const N: usize> Drop for WipingArray<N> {
    fn drop(&mut self) {
        bytes(&mut self.value);
    }
}

/// Stack-resident SHA word state that is always cleared on drop.
pub(crate) struct WipingWords64<const N: usize> {
    value: [u64; N],
}

impl<const N: usize> WipingWords64<N> {
    pub(crate) const fn new(value: [u64; N]) -> Self {
        Self { value }
    }
    pub(crate) const fn as_array(&self) -> &[u64; N] {
        &self.value
    }
    pub(crate) fn as_mut_array(&mut self) -> &mut [u64; N] {
        &mut self.value
    }
}

impl<const N: usize> Drop for WipingWords64<N> {
    fn drop(&mut self) {
        words64(&mut self.value);
    }
}

/// Move-stable, non-copyable and non-debuggable fixed-size secret owner.
pub(crate) struct Secret<const N: usize> {
    bytes: Box<[u8; N]>,
}

impl<const N: usize> Secret<N> {
    pub(crate) fn zeroed() -> Self {
        Self {
            bytes: Box::new([0u8; N]),
        }
    }

    pub(crate) fn from_source(source: &mut [u8; N]) -> Self {
        let mut owned = Self::zeroed();
        owned.bytes.copy_from_slice(source);
        bytes(source);
        owned
    }

    pub(crate) fn as_bytes(&self) -> &[u8; N] {
        self.bytes.as_ref()
    }

    pub(crate) fn as_mut_bytes(&mut self) -> &mut [u8; N] {
        self.bytes.as_mut()
    }
}

impl<const N: usize> Drop for Secret<N> {
    fn drop(&mut self) {
        bytes(self.bytes.as_mut());
    }
}

#[cfg(feature = "fuzzing")]
pub(crate) fn reset_wiped_bytes() {
    WIPED_BYTES.store(0, Ordering::SeqCst);
}

#[cfg(feature = "fuzzing")]
pub(crate) fn wiped_bytes() -> usize {
    WIPED_BYTES.load(Ordering::SeqCst)
}
