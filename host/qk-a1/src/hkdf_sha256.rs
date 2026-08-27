//! Private HKDF-SHA256 following RFC 5869.

use crate::hmac_sha256::{hmac_sha256_into, hmac_sha256_parts_into};
use crate::wipe;

const HASH_LEN: usize = 32;
const MAX_OUTPUT_LEN: usize = 255 * HASH_LEN;
const DOCUMENT_INFO: &[u8; 14] = b"QuietKey/A1/v1";

pub(crate) fn extract_into(salt: &[u8], ikm: &[u8], prk: &mut [u8; HASH_LEN]) {
    hmac_sha256_into(salt, ikm, prk);
}

pub(crate) fn expand(prk: &[u8; HASH_LEN], info: &[u8], output: &mut [u8]) -> bool {
    if output.len() > MAX_OUTPUT_LEN {
        return false;
    }

    let mut previous = [0u8; HASH_LEN];
    let mut offset = 0usize;
    let mut counter = 1u8;
    while offset < output.len() {
        let count = [counter];
        let mut block = [0u8; HASH_LEN];
        if offset == 0 {
            hmac_sha256_parts_into(prk, &[info, &count], &mut block);
        } else {
            hmac_sha256_parts_into(prk, &[&previous, info, &count], &mut block);
        }
        let taken = core::cmp::min(HASH_LEN, output.len() - offset);
        output[offset..offset + taken].copy_from_slice(&block[..taken]);
        previous.copy_from_slice(&block);
        wipe::bytes(&mut block);
        offset += taken;
        counter = counter.wrapping_add(1);
    }
    wipe::bytes(&mut previous);
    true
}

pub(crate) fn derive_document_key(a2: &[u8; 32], wallet_id: &[u8; 32], key: &mut [u8; 32]) {
    let mut prk = [0u8; HASH_LEN];
    extract_into(wallet_id, a2, &mut prk);
    let expanded = expand(&prk, DOCUMENT_INFO, key);
    debug_assert!(expanded, "one SHA-256 output is within HKDF's bound");
    wipe::bytes(&mut prk);
}

#[cfg(test)]
#[allow(dead_code)]
pub(crate) fn extract(salt: &[u8], ikm: &[u8]) -> [u8; HASH_LEN] {
    let mut prk = [0u8; HASH_LEN];
    extract_into(salt, ikm, &mut prk);
    prk
}

#[cfg(test)]
mod tests {
    use super::derive_document_key;

    #[test]
    fn capsule_fixture_document_key_passes() {
        let wallet_id = [
            0xa7, 0x98, 0x90, 0xdc, 0xde, 0x9c, 0x85, 0x17, 0xad, 0x86, 0x0a, 0xb3, 0xa9, 0x07,
            0xff, 0x01, 0x65, 0x2b, 0xbe, 0x20, 0x0a, 0x56, 0x10, 0x28, 0xce, 0xb6, 0x6e, 0x22,
            0xe8, 0xc9, 0xd5, 0x43,
        ];
        assert_eq!(
            {
                let mut key = [0u8; 32];
                derive_document_key(&[0u8; 32], &wallet_id, &mut key);
                key
            },
            [
                0xb3, 0xaa, 0x6e, 0x9b, 0xc9, 0xe5, 0x6c, 0x98, 0xcb, 0x1b, 0xfd, 0x99, 0x47, 0x80,
                0xde, 0xf3, 0xc5, 0x32, 0x5f, 0x35, 0x6d, 0xee, 0x46, 0xad, 0x05, 0x08, 0x5f, 0x7c,
                0xd4, 0xe3, 0xa1, 0x26,
            ]
        );
    }
}
