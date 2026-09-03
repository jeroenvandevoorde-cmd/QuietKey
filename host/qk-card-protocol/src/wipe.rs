//! Private optimization-resistant byte clearing.

use core::ptr;
use core::sync::atomic::{compiler_fence, Ordering};

#[cfg(any(test, feature = "fuzzing"))]
use core::cell::Cell;

#[cfg(any(test, feature = "fuzzing"))]
std::thread_local! {
    static WIPED_BYTES: Cell<usize> = const { Cell::new(0) };
}

/// Clear every initialized byte through observable writes.
#[allow(unsafe_code)]
#[inline(never)]
pub(crate) fn bytes(value: &mut [u8]) {
    #[cfg(any(test, feature = "fuzzing"))]
    let byte_count = value.len();
    for byte in value {
        // SAFETY: every address belongs to the uniquely borrowed live slice.
        unsafe { ptr::write_volatile(byte, 0) };
    }
    compiler_fence(Ordering::SeqCst);
    #[cfg(any(test, feature = "fuzzing"))]
    WIPED_BYTES.with(|count| count.set(count.get().saturating_add(byte_count)));
}

/// Fixed-capacity scratch whose initialized bytes are always cleared on drop.
pub(crate) struct WipingArray<const N: usize> {
    bytes: [u8; N],
}

impl<const N: usize> WipingArray<N> {
    pub(crate) const fn zeroed() -> Self {
        Self { bytes: [0; N] }
    }

    pub(crate) fn as_slice(&self) -> &[u8] {
        &self.bytes
    }

    pub(crate) fn as_mut_slice(&mut self) -> &mut [u8] {
        &mut self.bytes
    }
}

impl<const N: usize> Drop for WipingArray<N> {
    fn drop(&mut self) {
        bytes(&mut self.bytes);
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
mod tests {
    use super::{bytes, reset_wiped_bytes, wiped_bytes, WipingArray};

    #[test]
    fn clears_every_byte() {
        let mut value = [0xa5; 32];
        reset_wiped_bytes();
        bytes(&mut value);
        assert_eq!(value, [0; 32]);
        assert_eq!(wiped_bytes(), 32);
    }

    #[test]
    fn fixed_scratch_clears_on_drop() {
        reset_wiped_bytes();
        {
            let mut value = WipingArray::<17>::zeroed();
            value.as_mut_slice().fill(0xa5);
            assert_eq!(value.as_slice(), &[0xa5; 17]);
        }
        assert_eq!(wiped_bytes(), 17);
    }
}
