//! One private optimization-resistant byte-clearing boundary.

use core::mem;
use core::ops::{Deref, DerefMut};
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

/// Clear 32-bit hash-state words with observable writes.
#[allow(dead_code)]
#[allow(unsafe_code)]
#[inline(never)]
pub(crate) fn u32s(value: &mut [u32]) {
    #[cfg(test)]
    let byte_count = value.len().saturating_mul(mem::size_of::<u32>());
    for word in value {
        // SAFETY: every word is live and uniquely borrowed for this write.
        unsafe { ptr::write_volatile(word, 0) };
    }
    compiler_fence(Ordering::SeqCst);
    #[cfg(test)]
    WIPED_BYTES.with(|count| count.set(count.get().saturating_add(byte_count)));
}

/// Clear one live writable storage region without creating typed references.
#[allow(unsafe_code)]
#[inline(never)]
fn allocation(pointer: *mut u8, byte_count: usize) {
    for offset in 0..byte_count {
        // SAFETY: callers pass a live writable pointer and its exact byte
        // extent. Raw volatile writes do not claim storage bytes were already
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

    pub(crate) const fn as_slice(&self) -> &[u8] {
        &self.value
    }

    #[allow(dead_code)]
    pub(crate) fn as_mut_array(&mut self) -> &mut [u8; N] {
        &mut self.value
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

impl<const N: usize> core::fmt::Debug for ByteArray<N> {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        self.value.fmt(formatter)
    }
}

impl<const N: usize> Deref for ByteArray<N> {
    type Target = [u8; N];

    fn deref(&self) -> &Self::Target {
        &self.value
    }
}

impl<const N: usize> PartialEq<[u8; N]> for ByteArray<N> {
    fn eq(&self, other: &[u8; N]) -> bool {
        self.value == *other
    }
}

impl Drop for crate::sha256::Sha256 {
    fn drop(&mut self) {
        u32s(&mut self.state);
        bytes(&mut self.buffer);
        bytes(&mut self.padding);
        bytes(&mut self.length_bytes);
        u32s(&mut self.schedule);
    }
}

impl Drop for crate::sha256::DigestScratch {
    fn drop(&mut self) {
        bytes(&mut self.0);
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
/// Callers must clear and drop every live element first. The vector remains
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

/// Drop every live value, then clear the complete retained allocation.
pub(crate) fn value_vec<T>(value: &mut Vec<T>) {
    value.clear();
    empty_vec_allocation(value);
}

/// Fixed-size owner for Copy transaction values whose complete storage is
/// cleared without ever creating an invalid live `T` representation.
pub(crate) struct WipingValueArray<T: Copy, const N: usize> {
    value: [mem::MaybeUninit<T>; N],
}

impl<T: Copy, const N: usize> WipingValueArray<T, N> {
    pub(crate) fn new(value: [T; N]) -> Self {
        Self {
            value: value.map(mem::MaybeUninit::new),
        }
    }

    #[allow(unsafe_code)]
    pub(crate) fn as_mut_array(&mut self) -> &mut [T; N] {
        // SAFETY: `new` initializes every slot from a valid T, the array
        // length and layout are unchanged, and no method de-initializes one.
        unsafe { &mut *self.value.as_mut_ptr().cast::<[T; N]>() }
    }

    #[allow(unsafe_code)]
    pub(crate) fn as_array(&self) -> &[T; N] {
        // SAFETY: `new` initializes every slot from a valid T, the array
        // length and layout are unchanged, and no method de-initializes one.
        unsafe { &*self.value.as_ptr().cast::<[T; N]>() }
    }

    #[allow(unsafe_code)]
    #[allow(dead_code)]
    pub(crate) fn as_slice(&self) -> &[T] {
        // SAFETY: every slot through N is initialized by `new` and remains
        // initialized for the entire shared borrow.
        unsafe { core::slice::from_raw_parts(self.value.as_ptr().cast::<T>(), N) }
    }
}

impl<T: Copy, const N: usize> Drop for WipingValueArray<T, N> {
    fn drop(&mut self) {
        allocation(
            self.value.as_mut_ptr().cast::<u8>(),
            mem::size_of::<[mem::MaybeUninit<T>; N]>(),
        );
    }
}

/// Nongeneric owner that clears and then deallocates one retained vector.
/// Keeping T out of this drop type prevents drop checking from extending
/// borrows that the destructor never observes.
struct RawTransactionStorage {
    pointer: *mut u8,
    length: usize,
    capacity: usize,
    byte_count: usize,
    deallocate: unsafe fn(*mut u8, usize, usize),
}

impl RawTransactionStorage {
    fn from_vec<T: Copy>(value: Vec<T>) -> Self {
        let mut source = mem::ManuallyDrop::new(value);
        let length = source.len();
        let capacity = source.capacity();
        let byte_count = capacity.checked_mul(mem::size_of::<T>());
        // Safe Vec allocations cannot exceed the allocator's representable
        // byte extent (and zero-sized T multiplies to zero), so overflow is an
        // unreachable internal invariant rather than a truncation policy.
        debug_assert!(
            byte_count.is_some(),
            "transaction storage byte extent must fit usize"
        );
        let byte_count = byte_count.unwrap_or_default();
        Self {
            pointer: source.as_mut_ptr().cast::<u8>(),
            length,
            capacity,
            byte_count,
            deallocate: deallocate_transaction_storage::<T>,
        }
    }
}

// SAFETY: this private owner has unique ownership of the retained allocation;
// moving it between threads does not move the allocation itself.
#[allow(unsafe_code)]
unsafe impl Send for RawTransactionStorage {}
// SAFETY: shared access exposes no operation on the pointer, and Drop requires
// unique access to the storage owner.
#[allow(unsafe_code)]
unsafe impl Sync for RawTransactionStorage {}

#[allow(unsafe_code)]
impl Drop for RawTransactionStorage {
    fn drop(&mut self) {
        allocation(self.pointer, self.byte_count);
        // SAFETY: `from_vec` captured this allocation's exact pointer, length,
        // capacity and matching monomorphized deallocator, and no operation can
        // reallocate it. The volatile zeroes are valid MaybeUninit storage.
        unsafe { (self.deallocate)(self.pointer, self.length, self.capacity) };
    }
}

#[allow(unsafe_code)]
unsafe fn deallocate_transaction_storage<T: Copy>(
    pointer: *mut u8,
    length: usize,
    capacity: usize,
) {
    // SAFETY: the caller supplies the exact allocation originally created as
    // Vec<T>. MaybeUninit<T> has identical allocator layout and skips reading
    // or dropping the cleared element representations.
    let storage =
        unsafe { Vec::from_raw_parts(pointer.cast::<mem::MaybeUninit<T>>(), length, capacity) };
    drop(storage);
}

/// Read-only owner for transaction-derived values.
///
/// Construction and ownership transfer remain crate-private. Public callers
/// can compare, index and iterate the retained slice, but cannot extract or
/// mutably borrow the backing vector. The initialized values are retained as
/// `MaybeUninit<T>` storage so volatile clearing never leaves an invalid live
/// Rust value. A nongeneric storage owner clears and deallocates without
/// reading or dropping a cleared `T`; the function-return marker preserves
/// covariance without claiming drop ownership of T.
pub struct TransactionMaterialVec<T: Copy> {
    storage: RawTransactionStorage,
    marker: core::marker::PhantomData<fn() -> T>,
}

impl<T: Copy> TransactionMaterialVec<T> {
    pub(crate) fn from_vec(value: Vec<T>) -> Self {
        Self {
            storage: RawTransactionStorage::from_vec(value),
            marker: core::marker::PhantomData,
        }
    }

    #[allow(unsafe_code)]
    pub(crate) fn as_mut_slice(&mut self) -> &mut [T] {
        // SAFETY: construction establishes that all `len` elements are
        // initialized `T` values, and this crate-private mutable slice cannot
        // change the retained length or allocation.
        unsafe {
            core::slice::from_raw_parts_mut(self.storage.pointer.cast::<T>(), self.storage.length)
        }
    }

    /// Borrow all values in their fixed order.
    #[must_use]
    #[allow(unsafe_code)]
    pub fn as_slice(&self) -> &[T] {
        // SAFETY: construction initializes every element through `len`, and
        // no public operation can change the length or de-initialize a slot.
        unsafe {
            core::slice::from_raw_parts(self.storage.pointer.cast::<T>(), self.storage.length)
        }
    }

    /// Number of retained values.
    #[must_use]
    pub fn len(&self) -> usize {
        self.storage.length
    }

    /// Whether no values are retained.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.storage.length == 0
    }

    /// Exact backing allocation capacity, exposed for bounded HOST evidence.
    #[must_use]
    pub fn capacity(&self) -> usize {
        self.storage.capacity
    }
}

// SAFETY: the owner uniquely retains its allocation; T: Send is exactly the
// condition required to move initialized T values between threads.
#[allow(unsafe_code)]
unsafe impl<T: Copy + Send> Send for TransactionMaterialVec<T> {}
// SAFETY: public shared access exposes only &[T], so T: Sync is the exact
// condition required to share the owner between threads.
#[allow(unsafe_code)]
unsafe impl<T: Copy + Sync> Sync for TransactionMaterialVec<T> {}

impl<T: Copy + core::fmt::Debug> core::fmt::Debug for TransactionMaterialVec<T> {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        self.as_slice().fmt(formatter)
    }
}

impl<T: Copy + PartialEq> PartialEq for TransactionMaterialVec<T> {
    fn eq(&self, other: &Self) -> bool {
        self.as_slice() == other.as_slice()
    }
}

impl<T: Copy + Eq> Eq for TransactionMaterialVec<T> {}

impl<T: Copy> Clone for TransactionMaterialVec<T> {
    fn clone(&self) -> Self {
        Self::from_vec(self.as_slice().to_vec())
    }
}

impl<T: Copy> AsRef<[T]> for TransactionMaterialVec<T> {
    fn as_ref(&self) -> &[T] {
        self.as_slice()
    }
}

impl<T: Copy> Deref for TransactionMaterialVec<T> {
    type Target = [T];

    fn deref(&self) -> &Self::Target {
        self.as_slice()
    }
}

impl<T: Copy> core::ops::Index<usize> for TransactionMaterialVec<T> {
    type Output = T;

    fn index(&self, index: usize) -> &Self::Output {
        core::ops::Index::index(self.as_slice(), index)
    }
}

impl<'a, T: Copy> IntoIterator for &'a TransactionMaterialVec<T> {
    type Item = &'a T;
    type IntoIter = core::slice::Iter<'a, T>;

    fn into_iter(self) -> Self::IntoIter {
        self.as_slice().iter()
    }
}

impl<T: Copy + PartialEq, const N: usize> PartialEq<[T; N]> for TransactionMaterialVec<T> {
    fn eq(&self, other: &[T; N]) -> bool {
        self.as_slice() == other.as_slice()
    }
}

impl<T: Copy + PartialEq> PartialEq<&[T]> for TransactionMaterialVec<T> {
    fn eq(&self, other: &&[T]) -> bool {
        self.as_slice() == *other
    }
}

/// Byte-vector construction guard that clears live and spare bytes unless
/// ownership is explicitly transferred into another wiping type.
pub(crate) struct WipingByteVec {
    value: Vec<u8>,
}

impl WipingByteVec {
    pub(crate) const fn new() -> Self {
        Self { value: Vec::new() }
    }

    pub(crate) fn into_vec(mut self) -> Vec<u8> {
        mem::take(&mut self.value)
    }
}

impl Deref for WipingByteVec {
    type Target = Vec<u8>;

    fn deref(&self) -> &Self::Target {
        &self.value
    }
}

impl DerefMut for WipingByteVec {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.value
    }
}

impl Drop for WipingByteVec {
    fn drop(&mut self) {
        byte_vec(&mut self.value);
    }
}

/// Generic vector construction guard. Live elements are dropped first, then
/// the complete now-empty backing allocation is cleared with raw writes.
pub(crate) struct WipingValueVec<T> {
    value: Vec<T>,
}

impl<T> WipingValueVec<T> {
    pub(crate) const fn new() -> Self {
        Self { value: Vec::new() }
    }

    pub(crate) fn into_vec(mut self) -> Vec<T> {
        mem::take(&mut self.value)
    }

    pub(crate) fn into_owner(mut self) -> TransactionMaterialVec<T>
    where
        T: Copy,
    {
        TransactionMaterialVec::from_vec(mem::take(&mut self.value))
    }
}

impl<T> Deref for WipingValueVec<T> {
    type Target = Vec<T>;

    fn deref(&self) -> &Self::Target {
        &self.value
    }
}

impl<T> DerefMut for WipingValueVec<T> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.value
    }
}

impl<T> Drop for WipingValueVec<T> {
    fn drop(&mut self) {
        value_vec(&mut self.value);
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
#[allow(
    clippy::arithmetic_side_effects,
    clippy::indexing_slicing,
    clippy::panic,
    clippy::unwrap_used
)]
mod tests {
    use super::{
        reset_wiped_bytes, wiped_bytes, ByteArray, TransactionMaterialVec, WipingByteVec,
        WipingValueArray, WipingValueVec,
    };
    use crate::sha256::{DigestScratch, Sha256};
    use std::cell::Cell;
    use std::panic::AssertUnwindSafe;

    #[test]
    fn byte_construction_guard_clears_live_and_spare_allocation() {
        let mut guarded = WipingByteVec::new();
        guarded.try_reserve_exact(64).unwrap();
        guarded.extend_from_slice(&[0xa5; 7]);
        let capacity = guarded.capacity();
        reset_wiped_bytes();
        drop(guarded);
        assert_eq!(wiped_bytes(), capacity);
    }

    #[test]
    fn value_construction_guard_clears_elements_and_allocation() {
        let mut guarded = WipingValueVec::new();
        guarded.try_reserve_exact(3).unwrap();
        guarded.push([0xa5u8; 32]);
        guarded.push([0x5au8; 32]);
        let allocation_bytes = guarded.capacity() * core::mem::size_of::<[u8; 32]>();
        reset_wiped_bytes();
        drop(guarded);
        assert_eq!(wiped_bytes(), allocation_bytes);
    }

    #[test]
    fn transaction_material_owner_clears_live_and_spare_allocation() {
        let mut guarded = WipingValueVec::new();
        guarded.try_reserve_exact(4).unwrap();
        guarded.push([0xa5u8; 32]);
        let owned: TransactionMaterialVec<[u8; 32]> = guarded.into_owner();
        assert_eq!(owned.len(), 1);
        let allocation_bytes = owned.capacity() * core::mem::size_of::<[u8; 32]>();
        reset_wiped_bytes();
        drop(owned);
        assert_eq!(wiped_bytes(), allocation_bytes);
    }

    #[test]
    fn transaction_material_owner_clears_exact_capacity_on_unwind() {
        let allocation_bytes = Cell::new(0usize);
        reset_wiped_bytes();
        let caught = std::panic::catch_unwind(AssertUnwindSafe(|| {
            let mut guarded = WipingValueVec::new();
            guarded.try_reserve_exact(4).unwrap();
            guarded.push([0xa5u8; 32]);
            let owned: TransactionMaterialVec<[u8; 32]> = guarded.into_owner();
            allocation_bytes.set(owned.capacity() * core::mem::size_of::<[u8; 32]>());
            std::panic::panic_any("cleanup probe");
        }));
        assert!(caught.is_err());
        assert_eq!(wiped_bytes(), allocation_bytes.get());
    }

    #[test]
    fn transaction_material_owner_never_exposes_cleared_reference_values() {
        let (moved_source, allocation_bytes) = {
            let source = vec![0xa5u8, 0x5a];
            let mut guarded = WipingValueVec::new();
            guarded.try_reserve_exact(3).unwrap();
            guarded.push(Some(source.as_slice()));
            let mut owned: TransactionMaterialVec<Option<&[u8]>> = guarded.into_owner();
            assert_eq!(owned.as_slice(), [Some(source.as_slice())]);
            owned.as_mut_slice()[0] = None;
            let allocation_bytes = owned.capacity() * core::mem::size_of::<Option<&[u8]>>();
            reset_wiped_bytes();
            (source, allocation_bytes)
        };
        assert_eq!(wiped_bytes(), allocation_bytes);
        assert_eq!(moved_source, [0xa5, 0x5a]);
    }

    #[test]
    fn fixed_value_array_clears_exact_storage_on_drop_and_unwind() {
        let source = 0xa5u8;
        let mut owned = WipingValueArray::new([Some(&source), None, Some(&source)]);
        assert_eq!(owned.as_slice(), [Some(&source), None, Some(&source)]);
        owned.as_mut_array()[1] = Some(&source);
        reset_wiped_bytes();
        drop(owned);
        assert_eq!(wiped_bytes(), core::mem::size_of::<[Option<&u8>; 3]>());

        reset_wiped_bytes();
        let caught = std::panic::catch_unwind(|| {
            let _owned = WipingValueArray::new([[0x5au8; 11]; 4]);
            std::panic::panic_any("cleanup probe");
        });
        assert!(caught.is_err());
        assert_eq!(wiped_bytes(), core::mem::size_of::<[[u8; 11]; 4]>());
    }

    #[test]
    fn sha_owner_clears_all_fixed_transaction_state_on_drop_and_unwind() {
        let mut owner = Sha256::new();
        owner.update(b"transaction material").unwrap();
        reset_wiped_bytes();
        drop(owner);
        assert_eq!(wiped_bytes(), 296);

        reset_wiped_bytes();
        let caught = std::panic::catch_unwind(|| {
            let mut owner = Sha256::new();
            owner.update(b"unwind transaction material").unwrap();
            std::panic::panic_any("cleanup probe");
        });
        assert!(caught.is_err());
        assert_eq!(wiped_bytes(), 296);
    }

    #[test]
    fn digest_scratch_clears_exact_bytes_on_drop_and_unwind() {
        reset_wiped_bytes();
        drop(DigestScratch::new([0xa5; 32]));
        assert_eq!(wiped_bytes(), 32);

        reset_wiped_bytes();
        let caught = std::panic::catch_unwind(|| {
            let _owner = DigestScratch::new([0x5a; 32]);
            std::panic::panic_any("cleanup probe");
        });
        assert!(caught.is_err());
        assert_eq!(wiped_bytes(), 32);
    }

    #[test]
    fn fixed_array_mutation_and_drop_clear_the_complete_value() {
        let mut owned = ByteArray::new([0xa5; 37]);
        owned.as_mut_array()[0] = 0x5a;
        reset_wiped_bytes();
        drop(owned);
        assert_eq!(wiped_bytes(), 37);
    }
}
