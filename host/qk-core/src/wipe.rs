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

/// Clear live 32-bit words with observable writes.
#[allow(unsafe_code)]
#[inline(never)]
pub(crate) fn words32(value: &mut [u32]) {
    #[cfg(any(test, feature = "fuzzing"))]
    let byte_count = value.len().saturating_mul(core::mem::size_of::<u32>());
    for word in value {
        // SAFETY: every word is live and uniquely borrowed for this write.
        unsafe { ptr::write_volatile(word, 0) };
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

    #[cfg(test)]
    pub(crate) fn allocation_bytes(&self) -> usize {
        self.0.capacity()
    }

    pub(crate) fn try_copy(value: &[u8]) -> Result<Self, ()> {
        let mut owner = Self::try_zeroed(value.len())?;
        owner.as_mut_slice().copy_from_slice(value);
        Ok(owner)
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

/// Fallibly allocated value owner that drops every live element and then
/// clears the complete backing allocation, including spare capacity.
///
/// This remains crate-private: it exists only to extend the established wipe
/// boundary to bookkeeping vectors whose values can point at secret bytes.
pub(crate) struct WipingValueVec<T>(Vec<T>);

impl<T> WipingValueVec<T> {
    pub(crate) fn try_with_capacity(capacity: usize) -> Result<Self, ()> {
        let mut value = Vec::new();
        value.try_reserve_exact(capacity).map_err(|_| ())?;
        Ok(Self(value))
    }

    pub(crate) fn from_vec(value: Vec<T>) -> Self {
        Self(value)
    }

    pub(crate) fn try_push(&mut self, value: T) -> Result<(), T> {
        if self.0.len() == self.0.capacity() {
            return Err(value);
        }
        self.0.push(value);
        Ok(())
    }

    pub(crate) fn as_slice(&self) -> &[T] {
        self.0.as_slice()
    }

    pub(crate) fn len(&self) -> usize {
        self.0.len()
    }

    #[cfg(test)]
    pub(crate) fn allocation_bytes(&self) -> usize {
        self.0.capacity().saturating_mul(core::mem::size_of::<T>())
    }
}

impl<T> Drop for WipingValueVec<T> {
    fn drop(&mut self) {
        let byte_count = self.0.capacity().saturating_mul(core::mem::size_of::<T>());
        self.0.clear();
        if byte_count == 0 {
            compiler_fence(Ordering::SeqCst);
        } else {
            allocation(self.0.as_mut_ptr().cast::<u8>(), byte_count);
        }
    }
}

/// Fixed-size secret owner whose constructor clears the caller's source.
///
/// This type stays crate-private so no product surface can become a generic
/// secret-byte container or accessor.
pub(crate) struct WipingArray<const N: usize>([u8; N]);

impl<const N: usize> WipingArray<N> {
    pub(crate) const fn zeroed() -> Self {
        Self([0; N])
    }

    pub(crate) fn take(source: &mut [u8; N]) -> Self {
        let value = *source;
        bytes(source);
        Self(value)
    }

    pub(crate) const fn as_array(&self) -> &[u8; N] {
        &self.0
    }

    pub(crate) fn as_mut_array(&mut self) -> &mut [u8; N] {
        &mut self.0
    }
}

impl<const N: usize> Drop for WipingArray<N> {
    fn drop(&mut self) {
        bytes(&mut self.0);
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
    use super::{
        bytes, reset_wiped_bytes, wiped_bytes, words32, WipingArray, WipingValueVec, WipingVec,
    };
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
    fn fixed_word_slice_is_cleared_with_byte_accounting() {
        let mut value = [0xa5a5_5a5a; 7];
        reset_wiped_bytes();
        words32(&mut value);
        assert_eq!(value, [0; 7]);
        assert_eq!(wiped_bytes(), 28);
    }

    #[test]
    fn fixed_owner_clears_plaintext_on_caught_unwind() {
        reset_wiped_bytes();
        let result = catch_unwind(AssertUnwindSafe(|| {
            let mut owner = WipingArray::<32>::zeroed();
            owner.as_mut_array().fill(0xa5);
            panic!("caught fixed-owner unwind");
        }));
        assert!(result.is_err());
        assert_eq!(wiped_bytes(), 32);
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

    #[test]
    fn value_owner_clears_live_and_spare_allocation_bytes() {
        let mut owner = WipingValueVec::<u64>::try_with_capacity(19).unwrap();
        owner.try_push(7).unwrap();
        owner.try_push(11).unwrap();
        let allocation_bytes = owner.allocation_bytes();
        assert!(allocation_bytes > 2 * core::mem::size_of::<u64>());

        reset_wiped_bytes();
        drop(owner);
        assert_eq!(wiped_bytes(), allocation_bytes);
    }

    #[test]
    fn value_owner_clears_nested_values_before_outer_allocation() {
        let mut nested = Vec::with_capacity(41);
        nested.extend_from_slice(b"DER");
        let nested_capacity = nested.capacity();
        let mut owner = WipingValueVec::try_with_capacity(5).unwrap();
        assert!(owner.try_push(WipingVec(nested)).is_ok());
        let outer_bytes = owner.allocation_bytes();

        reset_wiped_bytes();
        drop(owner);
        assert_eq!(wiped_bytes(), nested_capacity + outer_bytes);
    }

    #[test]
    fn value_owner_clears_during_caught_unwind() {
        let mut owner = WipingValueVec::<u32>::try_with_capacity(23).unwrap();
        owner.try_push(0xa5a5_5a5a).unwrap();
        let allocation_bytes = owner.allocation_bytes();
        reset_wiped_bytes();
        let result = catch_unwind(AssertUnwindSafe(move || {
            let _owner = owner;
            panic!("test-only caught unwind");
        }));
        assert!(result.is_err());
        assert_eq!(wiped_bytes(), allocation_bytes);
    }
}
