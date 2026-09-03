//! Private fixed-shape HMAC-SHA512 for BIP32 child derivation.

use crate::{sha512, wipe};

const BLOCK_BYTES: usize = 128;

pub(crate) fn hmac_32_37(key: &[u8; 32], message: &[u8; 37], output: &mut [u8; 64]) {
    let mut inner = wipe::WipingArray::<{ BLOCK_BYTES + 37 }>::zeroed();
    inner.as_mut_slice().fill(0x36);
    for (dst, source) in inner.as_mut_slice()[..32].iter_mut().zip(key.iter()) {
        *dst ^= *source;
    }
    inner.as_mut_slice()[BLOCK_BYTES..].copy_from_slice(message);
    let mut inner_hash = wipe::WipingArray::<64>::zeroed();
    sha512::hash(inner.as_slice(), inner_hash.as_mut_array());

    let mut outer = wipe::WipingArray::<{ BLOCK_BYTES + 64 }>::zeroed();
    outer.as_mut_slice().fill(0x5c);
    for (dst, source) in outer.as_mut_slice()[..32].iter_mut().zip(key.iter()) {
        *dst ^= *source;
    }
    outer.as_mut_slice()[BLOCK_BYTES..].copy_from_slice(inner_hash.as_slice());
    sha512::hash(outer.as_slice(), output);
}

#[cfg(test)]
mod tests {
    use super::hmac_32_37;

    #[test]
    fn fixed_bip32_shape_known_answer() {
        let mut key = [0u8; 32];
        for (index, byte) in key.iter_mut().enumerate() {
            *byte = index as u8;
        }
        let mut message = [0u8; 37];
        for (index, byte) in message.iter_mut().enumerate() {
            *byte = index as u8;
        }
        let mut output = [0u8; 64];
        hmac_32_37(&key, &message, &mut output);
        assert_eq!(
            output,
            [
                0xa4, 0x8f, 0x35, 0xa9, 0x49, 0x08, 0x7f, 0x39, 0x9e, 0x83, 0x4b, 0x02, 0xcd, 0x9c,
                0xf0, 0x88, 0x9d, 0x13, 0xd5, 0x16, 0xec, 0xa4, 0xb8, 0xed, 0x22, 0x77, 0x37, 0x66,
                0x58, 0xa0, 0xd0, 0x4c, 0xbb, 0xe3, 0xfc, 0x64, 0xc3, 0x4f, 0x1d, 0xa7, 0xba, 0xd6,
                0xf1, 0x1e, 0x78, 0x47, 0x95, 0xf5, 0xf9, 0x1d, 0x85, 0xda, 0x8e, 0xa6, 0xd7, 0x3a,
                0x0e, 0x70, 0xdf, 0x29, 0x0e, 0xbb, 0xde, 0xec
            ]
        );
    }
}
