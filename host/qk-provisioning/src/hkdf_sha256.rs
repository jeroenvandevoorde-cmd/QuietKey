//! Private HKDF-SHA256 following RFC 5869.

use crate::hmac_sha256::{hmac_sha256, hmac_sha256_parts};
use crate::secret::wipe;

const HASH_LEN: usize = 32;
const MAX_OUTPUT_LEN: usize = 255 * HASH_LEN;

pub(crate) fn extract(salt: &[u8], ikm: &[u8]) -> [u8; HASH_LEN] {
    hmac_sha256(salt, ikm)
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
        let mut block = if offset == 0 {
            hmac_sha256_parts(prk, &[info, &count])
        } else {
            hmac_sha256_parts(prk, &[&previous, info, &count])
        };
        let taken = core::cmp::min(HASH_LEN, output.len() - offset);
        output[offset..offset + taken].copy_from_slice(&block[..taken]);
        previous.copy_from_slice(&block);
        wipe(&mut block);
        offset += taken;
        counter = counter.wrapping_add(1);
    }
    wipe(&mut previous);
    true
}
