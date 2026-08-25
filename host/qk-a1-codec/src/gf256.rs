//! Private arithmetic for GF(256) with polynomial 0x11d and alpha 0x02.

const REDUCTION: u8 = 0x1d;

pub(crate) fn add(left: u8, right: u8) -> u8 {
    left ^ right
}

pub(crate) fn multiply(mut left: u8, mut right: u8) -> u8 {
    let mut product = 0u8;
    for _ in 0..8 {
        product ^= left & 0u8.wrapping_sub(right & 1);
        let carry = left >> 7;
        left <<= 1;
        left ^= REDUCTION & 0u8.wrapping_sub(carry);
        right >>= 1;
    }
    product
}

pub(crate) fn power(mut base: u8, mut exponent: usize) -> u8 {
    let mut result = 1u8;
    while exponent != 0 {
        if exponent & 1 != 0 {
            result = multiply(result, base);
        }
        base = multiply(base, base);
        exponent >>= 1;
    }
    result
}

pub(crate) fn alpha_power(exponent: usize) -> u8 {
    power(0x02, exponent % 255)
}

pub(crate) fn inverse(value: u8) -> Option<u8> {
    (value != 0).then(|| power(value, 254))
}

pub(crate) fn divide(numerator: u8, denominator: u8) -> Option<u8> {
    inverse(denominator).map(|inverse| multiply(numerator, inverse))
}
