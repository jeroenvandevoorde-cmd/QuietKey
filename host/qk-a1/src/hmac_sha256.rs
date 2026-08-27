//! Private fixed-memory HMAC-SHA256 following FIPS 198-1.

use crate::sha256::{sha256_into, Sha256};
use crate::wipe;

const BLOCK_LEN: usize = 64;

fn normalized_key(key: &[u8], block: &mut [u8; BLOCK_LEN]) {
    if key.len() > BLOCK_LEN {
        let mut digest = [0u8; 32];
        sha256_into(key, &mut digest);
        block[..digest.len()].copy_from_slice(&digest);
        wipe::bytes(&mut digest);
    } else {
        block[..key.len()].copy_from_slice(key);
    }
}

pub(crate) fn hmac_sha256_parts_into(key: &[u8], message_parts: &[&[u8]], result: &mut [u8; 32]) {
    let mut key_block = [0u8; BLOCK_LEN];
    normalized_key(key, &mut key_block);
    let mut inner_pad = [0x36u8; BLOCK_LEN];
    let mut outer_pad = [0x5cu8; BLOCK_LEN];
    for index in 0..BLOCK_LEN {
        inner_pad[index] ^= key_block[index];
        outer_pad[index] ^= key_block[index];
    }

    let mut inner = Sha256::new();
    inner.update(&inner_pad);
    for part in message_parts {
        inner.update(part);
    }
    let mut inner_digest = [0u8; 32];
    inner.finish(&mut inner_digest);

    let mut outer = Sha256::new();
    outer.update(&outer_pad);
    outer.update(&inner_digest);
    outer.finish(result);

    wipe::bytes(&mut key_block);
    wipe::bytes(&mut inner_pad);
    wipe::bytes(&mut outer_pad);
    wipe::bytes(&mut inner_digest);
}

pub(crate) fn hmac_sha256_into(key: &[u8], message: &[u8], result: &mut [u8; 32]) {
    hmac_sha256_parts_into(key, &[message], result);
}

#[cfg(test)]
pub(crate) fn hmac_sha256(key: &[u8], message: &[u8]) -> [u8; 32] {
    let mut result = [0u8; 32];
    hmac_sha256_into(key, message, &mut result);
    result
}

#[cfg(test)]
mod tests {
    use super::hmac_sha256;

    #[test]
    fn rfc_4231_case_one_passes() {
        assert_eq!(
            hmac_sha256(&[0x0b; 20], b"Hi There"),
            [
                0xb0, 0x34, 0x4c, 0x61, 0xd8, 0xdb, 0x38, 0x53, 0x5c, 0xa8, 0xaf, 0xce, 0xaf, 0x0b,
                0xf1, 0x2b, 0x88, 0x1d, 0xc2, 0x00, 0xc9, 0x83, 0x3d, 0xa7, 0x26, 0xe9, 0x37, 0x6c,
                0x2e, 0x32, 0xcf, 0xf7,
            ]
        );
    }
}
