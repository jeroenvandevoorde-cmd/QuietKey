//! Private fixed-size secret owner for HOST reference intermediates.

/// Non-copyable, non-debuggable fixed-size bytes cleared on drop.
pub(crate) struct Secret<const N: usize> {
    bytes: [u8; N],
}

impl<const N: usize> Secret<N> {
    pub(crate) fn new(bytes: [u8; N]) -> Self {
        Self { bytes }
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
        self.bytes.fill(0);
        core::hint::black_box(&mut self.bytes);
    }
}
