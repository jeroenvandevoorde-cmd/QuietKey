//! Private fixed-size secret owner for HOST reference intermediates.

/// Optimization-resistant clearing for private scratch bytes.
pub(crate) fn wipe(bytes: &mut [u8]) {
    bytes.fill(0);
    core::hint::black_box(bytes);
}

/// Non-copyable, non-debuggable move-stable fixed-size bytes cleared on drop.
pub(crate) struct Secret<const N: usize> {
    bytes: Box<[u8; N]>,
}

impl<const N: usize> Secret<N> {
    /// Copy one caller-owned scratch buffer into stable storage, then wipe
    /// the exact caller buffer before returning.
    pub(crate) fn take(bytes: &mut [u8; N]) -> Self {
        let mut owned = Box::new([0u8; N]);
        owned.copy_from_slice(bytes);
        wipe(bytes);
        Self { bytes: owned }
    }

    pub(crate) fn zeroed() -> Self {
        Self {
            bytes: Box::new([0u8; N]),
        }
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
        wipe(self.bytes.as_mut());
    }
}
