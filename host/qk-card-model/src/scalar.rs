//! Fixed-width secp256k1 scalar checks and addition for CKDpriv.

use crate::wipe;

pub(crate) const ORDER: [u8; 32] = [
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xfe,
    0xba, 0xae, 0xdc, 0xe6, 0xaf, 0x48, 0xa0, 0x3b, 0xbf, 0xd2, 0x5e, 0x8c, 0xd0, 0x36, 0x41, 0x41,
];

pub(crate) fn valid(value: &[u8; 32]) -> bool {
    value.iter().any(|byte| *byte != 0) && less_than(value, &ORDER)
}

fn less_than(left: &[u8; 32], right: &[u8; 32]) -> bool {
    for (&a, &b) in left.iter().zip(right.iter()) {
        if a != b {
            return a < b;
        }
    }
    false
}

/// Add two valid big-endian scalars modulo the secp256k1 order.
///
/// A 33-byte intermediate preserves the carry, so exactly one subtraction is
/// sufficient because both inputs are less than the order.
pub(crate) fn add_mod_order(parent: &[u8; 32], tweak: &[u8; 32], output: &mut [u8; 32]) -> bool {
    if !valid(parent) || !less_than(tweak, &ORDER) {
        return false;
    }
    let mut wide = wipe::WipingArray::<33>::zeroed();
    let mut carry = 0u16;
    for index in (0..32).rev() {
        let sum = u16::from(parent[index]) + u16::from(tweak[index]) + carry;
        wide.as_mut_array()[index + 1] = sum as u8;
        carry = sum >> 8;
    }
    wide.as_mut_array()[0] = carry as u8;
    let mut modulus = wipe::WipingArray::<33>::zeroed();
    modulus.as_mut_slice()[1..].copy_from_slice(&ORDER);
    if !wide_less_than(wide.as_array(), modulus.as_array()) {
        subtract_wide(wide.as_mut_array(), modulus.as_array());
    }
    output.copy_from_slice(&wide.as_slice()[1..]);
    let accepted = output.iter().any(|byte| *byte != 0);
    if !accepted {
        wipe::bytes(output);
    }
    accepted
}

/// Return `n - value` for one valid scalar. This creates the mathematically
/// equivalent high-S ECDSA sibling from the model fixture signer's low S.
pub(crate) fn negate_mod_order(value: &[u8; 32], output: &mut [u8; 32]) -> bool {
    if !valid(value) {
        return false;
    }
    let mut borrow = 0i16;
    for index in (0..32).rev() {
        let candidate = i16::from(ORDER[index]) - i16::from(value[index]) - borrow;
        if candidate < 0 {
            output[index] = (candidate + 256) as u8;
            borrow = 1;
        } else {
            output[index] = candidate as u8;
            borrow = 0;
        }
    }
    valid(output)
}

fn wide_less_than(left: &[u8; 33], right: &[u8; 33]) -> bool {
    for (&a, &b) in left.iter().zip(right.iter()) {
        if a != b {
            return a < b;
        }
    }
    false
}

fn subtract_wide(value: &mut [u8; 33], modulus: &[u8; 33]) {
    let mut borrow = 0i16;
    for index in (0..33).rev() {
        let candidate = i16::from(value[index]) - i16::from(modulus[index]) - borrow;
        if candidate < 0 {
            value[index] = (candidate + 256) as u8;
            borrow = 1;
        } else {
            value[index] = candidate as u8;
            borrow = 0;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{add_mod_order, valid, ORDER};

    #[test]
    fn zero_order_and_order_minus_one_are_pinned() {
        assert!(!valid(&[0u8; 32]));
        assert!(!valid(&ORDER));
        let mut n_minus_one = ORDER;
        n_minus_one[31] -= 1;
        assert!(valid(&n_minus_one));
    }

    #[test]
    fn addition_reduces_once_and_rejects_zero_child() {
        let mut one = [0u8; 32];
        one[31] = 1;
        let mut two = [0u8; 32];
        two[31] = 2;
        let mut output = [0u8; 32];
        assert!(add_mod_order(&one, &one, &mut output));
        assert_eq!(output, two);
        let mut n_minus_one = ORDER;
        n_minus_one[31] -= 1;
        assert!(!add_mod_order(&n_minus_one, &one, &mut output));
        assert_eq!(output, [0u8; 32]);
    }
}
