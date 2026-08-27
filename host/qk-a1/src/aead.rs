//! Private IETF ChaCha20-Poly1305 AEAD following RFC 8439.

use crate::{chacha20, poly1305, wipe};

fn nonce_array(nonce: &[u8]) -> Option<[u8; 12]> {
    let mut exact = [0u8; 12];
    if nonce.len() != exact.len() {
        return None;
    }
    exact.copy_from_slice(nonce);
    Some(exact)
}

fn tag_array(tag: &[u8]) -> Option<[u8; 16]> {
    let mut exact = [0u8; 16];
    if tag.len() != exact.len() {
        return None;
    }
    exact.copy_from_slice(tag);
    Some(exact)
}

fn one_time_key(key: &[u8; 32], nonce: &[u8; 12], poly_key: &mut [u8; 32]) {
    let mut first_block = [0u8; 64];
    chacha20::block_into(key, 0, nonce, &mut first_block);
    poly_key.copy_from_slice(&first_block[..32]);
    wipe::bytes(&mut first_block);
}

fn tags_equal(left: &[u8; 16], right: &[u8; 16]) -> bool {
    let mut difference = 0u8;
    for (a, b) in left.iter().zip(right) {
        difference |= a ^ b;
    }
    difference == 0
}

pub(crate) fn seal(
    key: &[u8; 32],
    nonce: &[u8],
    aad: &[u8],
    plaintext: &[u8],
    ciphertext: &mut [u8],
    tag: &mut [u8; 16],
) -> bool {
    let Some(nonce) = nonce_array(nonce) else {
        return false;
    };
    if plaintext.len() != ciphertext.len() {
        return false;
    }
    if !chacha20::xor(key, &nonce, 1, plaintext, ciphertext) {
        return false;
    }
    let mut poly_key = [0u8; 32];
    one_time_key(key, &nonce, &mut poly_key);
    poly1305::authenticate(&poly_key, aad, ciphertext, tag);
    wipe::bytes(&mut poly_key);
    true
}

pub(crate) fn open(
    key: &[u8; 32],
    nonce: &[u8],
    aad: &[u8],
    ciphertext: &[u8],
    tag: &[u8],
    plaintext: &mut [u8],
) -> bool {
    let Some(nonce) = nonce_array(nonce) else {
        return false;
    };
    if ciphertext.len() != plaintext.len() {
        return false;
    }
    let Some(tag) = tag_array(tag) else {
        return false;
    };

    let mut poly_key = [0u8; 32];
    one_time_key(key, &nonce, &mut poly_key);
    let mut expected = [0u8; 16];
    poly1305::authenticate(&poly_key, aad, ciphertext, &mut expected);
    wipe::bytes(&mut poly_key);
    let authenticated = tags_equal(&expected, &tag);
    wipe::bytes(&mut expected);
    if !authenticated {
        return false;
    }

    chacha20::xor(key, &nonce, 1, ciphertext, plaintext)
}
