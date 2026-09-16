//! One private optimization-resistant byte-clearing boundary.

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
    use super::{bytes, reset_wiped_bytes, wiped_bytes};
    use std::panic::{catch_unwind, AssertUnwindSafe};

    #[test]
    fn clears_every_byte() {
        let mut value = [0xa5; 32];
        reset_wiped_bytes();
        bytes(&mut value);
        assert_eq!(value, [0; 32]);
        assert_eq!(wiped_bytes(), 32);
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
