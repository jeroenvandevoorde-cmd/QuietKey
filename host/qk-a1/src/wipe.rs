//! Private optimization-resistant cleanup boundary for HOST scratch.

#[inline(never)]
pub(crate) fn bytes(value: &mut [u8]) {
    value.fill(0);
    core::hint::black_box(value);
}

#[inline(never)]
pub(crate) fn words32(value: &mut [u32]) {
    value.fill(0);
    core::hint::black_box(value);
}

#[inline(never)]
pub(crate) fn words64(value: &mut [u64]) {
    value.fill(0);
    core::hint::black_box(value);
}
