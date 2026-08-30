//! Private optimization-resistant owner for transaction-bearing heap bytes.

#![deny(unsafe_op_in_unsafe_fn)]

use core::mem;
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

/// Clear SHA-256 state and schedule words with observable writes.
#[allow(unsafe_code)]
#[inline(never)]
fn wipe_u32s(words: &mut [u32]) {
    #[cfg(test)]
    let byte_count = words.len().saturating_mul(mem::size_of::<u32>());
    for word in words {
        // SAFETY: every word is live and uniquely borrowed for this write.
        unsafe { ptr::write_volatile(word, 0) };
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

/// Clear the complete backing allocation of an already-empty value vector.
///
/// The owner below drops every live element before calling this function.
/// Raw writes then cover any stale element bytes and all spare capacity
/// without constructing references to uninitialized slots.
#[allow(unsafe_code)]
fn wipe_empty_value_allocation<T>(values: &mut Vec<T>) {
    debug_assert!(values.is_empty());
    let Some(byte_count) = values.capacity().checked_mul(mem::size_of::<T>()) else {
        compiler_fence(Ordering::SeqCst);
        return;
    };
    if byte_count == 0 {
        compiler_fence(Ordering::SeqCst);
        return;
    }
    wipe_allocation(values.as_mut_ptr().cast::<u8>(), byte_count);
}

/// One fixed-size scratch array cleared on every exit path.
pub(crate) struct WipingArray<const N: usize> {
    bytes: [u8; N],
}

impl<const N: usize> WipingArray<N> {
    pub(crate) const fn zeroed() -> Self {
        Self { bytes: [0; N] }
    }

    pub(crate) const fn new(bytes: [u8; N]) -> Self {
        Self { bytes }
    }

    pub(crate) const fn as_slice(&self) -> &[u8; N] {
        &self.bytes
    }

    pub(crate) fn as_mut_slice(&mut self) -> &mut [u8; N] {
        &mut self.bytes
    }

    pub(crate) fn take(&mut self) -> [u8; N] {
        core::mem::replace(&mut self.bytes, [0; N])
    }
}

impl<const N: usize> Drop for WipingArray<N> {
    fn drop(&mut self) {
        wipe_bytes(&mut self.bytes);
    }
}

impl Drop for crate::transaction_sha256::Sha256 {
    fn drop(&mut self) {
        wipe_u32s(&mut self.state);
        wipe_bytes(&mut self.buffer);
        wipe_bytes(&mut self.padding);
        wipe_bytes(&mut self.length_bytes);
        wipe_u32s(&mut self.schedule);
    }
}

impl Drop for crate::transaction_sha256::DigestScratch {
    fn drop(&mut self) {
        wipe_bytes(&mut self.0);
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

/// Non-clonable owner for transaction-derived value tables.
///
/// Live values are dropped first so their own fixed-byte owners run. The
/// complete now-empty allocation is then cleared, including spare capacity.
pub(crate) struct WipingValueVec<T> {
    values: Vec<T>,
}

impl<T> WipingValueVec<T> {
    pub(crate) const fn new() -> Self {
        Self { values: Vec::new() }
    }

    pub(crate) fn try_reserve_exact(
        &mut self,
        additional: usize,
    ) -> Result<(), std::collections::TryReserveError> {
        self.values.try_reserve_exact(additional)
    }

    pub(crate) fn push(&mut self, value: T) {
        self.values.push(value);
    }

    pub(crate) fn get_mut(&mut self, index: usize) -> Option<&mut T> {
        self.values.get_mut(index)
    }

    pub(crate) fn iter_mut(&mut self) -> core::slice::IterMut<'_, T> {
        self.values.iter_mut()
    }

    pub(crate) fn sort_unstable_by<F>(&mut self, compare: F)
    where
        F: FnMut(&T, &T) -> core::cmp::Ordering,
    {
        self.values.sort_unstable_by(compare);
    }

    pub(crate) fn resize_with<F>(&mut self, new_len: usize, constructor: F)
    where
        F: FnMut() -> T,
    {
        self.values.resize_with(new_len, constructor);
    }

    #[cfg(test)]
    pub(crate) fn capacity(&self) -> usize {
        self.values.capacity()
    }
}

impl<T> Deref for WipingValueVec<T> {
    type Target = [T];

    fn deref(&self) -> &Self::Target {
        &self.values
    }
}

impl<T> Extend<T> for WipingValueVec<T> {
    fn extend<I: IntoIterator<Item = T>>(&mut self, iter: I) {
        self.values.extend(iter);
    }
}

impl<T> Drop for WipingValueVec<T> {
    fn drop(&mut self) {
        self.values.clear();
        wipe_empty_value_allocation(&mut self.values);
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
    use super::{
        reset_wiped_bytes, wipe_bytes, wiped_bytes, WipingArray, WipingValueVec, WipingVec,
    };
    use crate::transaction_sha256::{DigestScratch, Sha256};
    use std::panic::{catch_unwind, AssertUnwindSafe};

    struct FixedTransactionFact([u8; 17]);

    impl Drop for FixedTransactionFact {
        fn drop(&mut self) {
            wipe_bytes(&mut self.0);
        }
    }

    #[test]
    fn fixed_owner_transfer_leaves_only_zeroes_for_drop() {
        let mut owner = WipingArray::new([0xa5; 32]);
        assert_eq!(owner.take(), [0xa5; 32]);
        assert_eq!(owner.as_slice(), &[0; 32]);
        reset_wiped_bytes();
        drop(owner);
        assert_eq!(wiped_bytes(), 32);
    }

    #[test]
    fn owned_heap_bytes_are_cleared_on_drop() {
        let bytes = vec![0xa5; 37];
        let capacity = bytes.capacity();
        reset_wiped_bytes();
        drop(WipingVec::take(bytes));
        assert_eq!(wiped_bytes(), capacity);
    }

    #[test]
    fn spare_allocation_bytes_are_cleared_with_live_transaction_bytes() {
        let mut bytes = Vec::with_capacity(64);
        bytes.extend_from_slice(&[0xa5; 7]);
        let capacity = bytes.capacity();
        reset_wiped_bytes();
        drop(WipingVec::take(bytes));
        assert_eq!(wiped_bytes(), capacity);
    }

    #[test]
    fn value_owner_clears_fixed_values_and_complete_spare_capacity() {
        let mut values = WipingValueVec::new();
        values.try_reserve_exact(3).unwrap();
        values.push(FixedTransactionFact([0xa5; 17]));
        values.push(FixedTransactionFact([0x5a; 17]));
        let allocation_bytes = values.capacity() * core::mem::size_of::<FixedTransactionFact>();
        reset_wiped_bytes();
        drop(values);
        assert_eq!(wiped_bytes(), (2 * 17) + allocation_bytes);
    }

    #[test]
    fn byte_and_value_owners_clear_during_caught_unwind() {
        let mut bytes = Vec::with_capacity(64);
        bytes.extend_from_slice(&[0xa5; 7]);
        let byte_capacity = bytes.capacity();
        let mut values = WipingValueVec::new();
        values.try_reserve_exact(2).unwrap();
        values.push(FixedTransactionFact([0x5a; 17]));
        let value_allocation = values.capacity() * core::mem::size_of::<FixedTransactionFact>();
        reset_wiped_bytes();
        let result = catch_unwind(AssertUnwindSafe(move || {
            let _bytes = WipingVec::take(bytes);
            let _values = values;
            panic!("bounded cleanup probe");
        }));
        assert!(result.is_err());
        assert_eq!(wiped_bytes(), byte_capacity + 17 + value_allocation);
    }

    #[test]
    fn transaction_sha_owner_clears_exact_state_on_drop_and_unwind() {
        let mut owner = Sha256::new();
        owner.update(b"transaction material").unwrap();
        reset_wiped_bytes();
        drop(owner);
        assert_eq!(wiped_bytes(), 296);

        reset_wiped_bytes();
        let result = catch_unwind(|| {
            let mut owner = Sha256::new();
            owner.update(b"unwind transaction material").unwrap();
            panic!("bounded cleanup probe");
        });
        assert!(result.is_err());
        assert_eq!(wiped_bytes(), 296);
    }

    #[test]
    fn transaction_digest_scratch_clears_exact_bytes_on_drop_and_unwind() {
        reset_wiped_bytes();
        drop(DigestScratch::new([0xa5; 32]));
        assert_eq!(wiped_bytes(), 32);

        reset_wiped_bytes();
        let result = catch_unwind(|| {
            let _owner = DigestScratch::new([0x5a; 32]);
            panic!("bounded cleanup probe");
        });
        assert!(result.is_err());
        assert_eq!(wiped_bytes(), 32);
    }
}
