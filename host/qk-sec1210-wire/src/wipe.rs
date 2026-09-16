//! One private optimization-resistant clearing boundary.

use core::ptr;
use core::sync::atomic::{compiler_fence, Ordering};

#[cfg(test)]
use core::cell::Cell;

#[cfg(test)]
std::thread_local! {
    static WIPED_BYTES: Cell<usize> = const { Cell::new(0) };
}

/// Clear initialized bytes with observable writes.
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

/// Replace initialized fixed-storage values through observable writes.
#[inline(never)]
pub(crate) fn values<T: Copy>(value: &mut [T], replacement: T) {
    #[cfg(test)]
    let byte_count = core::mem::size_of_val(value);
    for item in value {
        // SAFETY: every item is live, uniquely borrowed and receives a valid T.
        unsafe { ptr::write_volatile(item, replacement) };
    }
    compiler_fence(Ordering::SeqCst);
    #[cfg(test)]
    WIPED_BYTES.with(|count| count.set(count.get().saturating_add(byte_count)));
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
    use super::{bytes, reset_wiped_bytes, values, wiped_bytes};
    use std::panic::{catch_unwind, AssertUnwindSafe};

    #[test]
    fn clears_complete_byte_and_value_storage() {
        let mut bytes_value = [0xa5; 32];
        let mut words = [0xa5a5_u16; 9];
        reset_wiped_bytes();
        bytes(&mut bytes_value);
        values(&mut words, 0);
        assert_eq!(bytes_value, [0; 32]);
        assert_eq!(words, [0; 9]);
        assert_eq!(wiped_bytes(), 32 + 9 * size_of::<u16>());
    }

    #[test]
    fn clearing_runs_during_caught_unwind() {
        struct Owner([u8; 47]);
        impl Drop for Owner {
            fn drop(&mut self) {
                bytes(&mut self.0);
            }
        }

        reset_wiped_bytes();
        let result = catch_unwind(AssertUnwindSafe(|| {
            let _owner = Owner([0xa5; 47]);
            panic!("test-only caught unwind");
        }));
        assert!(result.is_err());
        assert_eq!(wiped_bytes(), 47);
    }
}
