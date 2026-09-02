//! Volatile cleanup owners for fixture-only transported material.

use core::sync::atomic::{compiler_fence, Ordering};

pub fn bytes(value: &mut [u8]) {
    for byte in value {
        // SAFETY: `byte` is a valid uniquely borrowed byte. Volatile stores
        // and the compiler fence make the cleanup observable to the compiler.
        unsafe { core::ptr::write_volatile(byte, 0) };
    }
    compiler_fence(Ordering::SeqCst);
}

pub struct WipingVec {
    bytes: Vec<u8>,
}

impl WipingVec {
    pub fn zeroed(length: usize) -> Result<Self, ()> {
        let mut bytes = Vec::new();
        bytes.try_reserve_exact(length).map_err(|_| ())?;
        bytes.resize(length, 0);
        Ok(Self { bytes })
    }

    pub fn from_slice(value: &[u8]) -> Result<Self, ()> {
        let mut bytes = Self::zeroed(value.len())?;
        bytes.bytes.copy_from_slice(value);
        Ok(bytes)
    }

    pub fn as_slice(&self) -> &[u8] {
        &self.bytes
    }

    pub fn as_mut_slice(&mut self) -> &mut [u8] {
        &mut self.bytes
    }

    pub fn len(&self) -> usize {
        self.bytes.len()
    }

    pub fn extend(&mut self, value: &[u8]) -> Result<(), ()> {
        self.bytes.try_reserve(value.len()).map_err(|_| ())?;
        self.bytes.extend_from_slice(value);
        Ok(())
    }
}

impl Drop for WipingVec {
    fn drop(&mut self) {
        let capacity = self.bytes.capacity();
        let pointer = self.bytes.as_mut_ptr();
        for index in 0..capacity {
            // SAFETY: a Vec allocation is valid for writes across capacity.
            unsafe { core::ptr::write_volatile(pointer.add(index), 0) };
        }
        compiler_fence(Ordering::SeqCst);
    }
}
