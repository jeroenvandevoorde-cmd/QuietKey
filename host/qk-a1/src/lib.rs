//! Fixed-memory HOST reference for the canonical A1 capsule (QK-DEC-089).
//!
//! HOST REFERENCE ONLY -- NOT PRODUCTION CRYPTOGRAPHY -- NOT A WALLET --
//! NO TARGET OR GATE CLAIM.
//!
//! The only public operations encrypt and decrypt one exact 32-byte Seed-A
//! value under caller-supplied A2, wallet identity, and nonce bytes. SHA-256,
//! HMAC-SHA256, HKDF-SHA256, and ChaCha20-Poly1305 remain private. This crate
//! performs no allocation, I/O, logging, randomness, nonce generation,
//! rendering, or media encoding. A separately reviewed constant-time target
//! implementation remains a Gate-C obligation.

#![deny(unsafe_code)]

mod aead;
mod chacha20;
mod hkdf_sha256;
mod hmac_sha256;
mod poly1305;
mod sha256;
mod wipe;

const MAGIC: [u8; 4] = *b"QKA1";
const CODING_VERSION: u8 = 1;
const CRYPTO_VERSION: u8 = 1;
const MAINNET: u8 = 1;
const HEADER_LEN: usize = 7;
const NONCE_LEN: usize = 12;
const PLAINTEXT_LEN: usize = 32;
const TAG_LEN: usize = 16;
const AAD_LEN: usize = HEADER_LEN + 32;
const CAPSULE_LEN: usize = HEADER_LEN + NONCE_LEN + PLAINTEXT_LEN + TAG_LEN;

const NONCE_START: usize = HEADER_LEN;
const CIPHERTEXT_START: usize = NONCE_START + NONCE_LEN;
const TAG_START: usize = CIPHERTEXT_START + PLAINTEXT_LEN;

const _: [(); 67] = [(); CAPSULE_LEN];
const _: [(); 39] = [(); AAD_LEN];

/// Closed failure surface for canonical A1 capsule decryption.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum A1Error {
    InvalidCapsuleLength,
    InvalidMagic,
    UnsupportedCodingVersion,
    UnsupportedCryptoVersion,
    UnsupportedNetwork,
    AuthenticationFailed,
}

/// Encrypts one exact Seed-A value into the canonical 67-byte A1 capsule.
///
/// `nonce` is supplied by the caller. This function does not generate or
/// assess randomness and cannot enforce nonce uniqueness.
pub fn encrypt(
    a2: &[u8; 32],
    wallet_id: &[u8; 32],
    nonce: &[u8; 12],
    seed_a: &[u8; 32],
) -> [u8; 67] {
    let mut capsule = [0u8; CAPSULE_LEN];
    capsule[..4].copy_from_slice(&MAGIC);
    capsule[4] = CODING_VERSION;
    capsule[5] = CRYPTO_VERSION;
    capsule[6] = MAINNET;
    capsule[NONCE_START..CIPHERTEXT_START].copy_from_slice(nonce);

    let mut aad = [0u8; AAD_LEN];
    aad[..HEADER_LEN].copy_from_slice(&capsule[..HEADER_LEN]);
    aad[HEADER_LEN..].copy_from_slice(wallet_id);

    let mut key = [0u8; 32];
    hkdf_sha256::derive_document_key(a2, wallet_id, &mut key);
    let mut tag = [0u8; TAG_LEN];
    let sealed = aead::seal(
        &key,
        nonce,
        &aad,
        seed_a,
        &mut capsule[CIPHERTEXT_START..TAG_START],
        &mut tag,
    );
    debug_assert!(sealed, "fixed A1 dimensions are valid");
    capsule[TAG_START..].copy_from_slice(&tag);

    wipe::bytes(&mut key);
    wipe::bytes(&mut tag);
    wipe::bytes(&mut aad);
    capsule
}

/// Authenticates and decrypts one canonical A1 capsule.
///
/// Rejections follow [`A1Error`] declaration order. `seed_a_out` remains
/// byte-for-byte unchanged unless authentication succeeds.
pub fn decrypt(
    a2: &[u8; 32],
    wallet_id: &[u8; 32],
    capsule: &[u8],
    seed_a_out: &mut [u8; 32],
) -> Result<(), A1Error> {
    if capsule.len() != CAPSULE_LEN {
        return Err(A1Error::InvalidCapsuleLength);
    }
    if capsule[..4] != MAGIC {
        return Err(A1Error::InvalidMagic);
    }
    if capsule[4] != CODING_VERSION {
        return Err(A1Error::UnsupportedCodingVersion);
    }
    if capsule[5] != CRYPTO_VERSION {
        return Err(A1Error::UnsupportedCryptoVersion);
    }
    if capsule[6] != MAINNET {
        return Err(A1Error::UnsupportedNetwork);
    }

    let mut nonce = [0u8; NONCE_LEN];
    nonce.copy_from_slice(&capsule[NONCE_START..CIPHERTEXT_START]);
    let mut tag = [0u8; TAG_LEN];
    tag.copy_from_slice(&capsule[TAG_START..]);

    let mut aad = [0u8; AAD_LEN];
    aad[..HEADER_LEN].copy_from_slice(&capsule[..HEADER_LEN]);
    aad[HEADER_LEN..].copy_from_slice(wallet_id);

    let mut key = [0u8; 32];
    hkdf_sha256::derive_document_key(a2, wallet_id, &mut key);
    let mut candidate = [0u8; PLAINTEXT_LEN];
    let authenticated = aead::open(
        &key,
        &nonce,
        &aad,
        &capsule[CIPHERTEXT_START..TAG_START],
        &tag,
        &mut candidate,
    );

    wipe::bytes(&mut key);
    wipe::bytes(&mut nonce);
    wipe::bytes(&mut tag);
    wipe::bytes(&mut aad);

    if !authenticated {
        wipe::bytes(&mut candidate);
        return Err(A1Error::AuthenticationFailed);
    }

    seed_a_out.copy_from_slice(&candidate);
    wipe::bytes(&mut candidate);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::{decrypt, encrypt, A1Error};

    #[test]
    fn round_trip_and_authentication_failure_are_closed() {
        let a2 = [0x22; 32];
        let wallet_id = [0x33; 32];
        let nonce = [0x44; 12];
        let seed_a = [0x55; 32];
        let capsule = encrypt(&a2, &wallet_id, &nonce, &seed_a);

        let mut output = [0xa5; 32];
        assert_eq!(decrypt(&a2, &wallet_id, &capsule, &mut output), Ok(()));
        assert_eq!(output, seed_a);

        let mut changed = capsule;
        changed[19] ^= 1;
        output = [0xa5; 32];
        assert_eq!(
            decrypt(&a2, &wallet_id, &changed, &mut output),
            Err(A1Error::AuthenticationFailed)
        );
        assert_eq!(output, [0xa5; 32]);
    }

    #[test]
    fn structural_rejections_follow_declared_precedence() {
        let a2 = [0x22; 32];
        let wallet_id = [0x33; 32];
        let nonce = [0x44; 12];
        let seed_a = [0x55; 32];
        let capsule = encrypt(&a2, &wallet_id, &nonce, &seed_a);
        let mut output = [0xa5; 32];

        assert_eq!(
            decrypt(&a2, &wallet_id, &capsule[..66], &mut output),
            Err(A1Error::InvalidCapsuleLength)
        );
        let mut changed = capsule;
        changed[0] ^= 1;
        changed[4] ^= 1;
        assert_eq!(
            decrypt(&a2, &wallet_id, &changed, &mut output),
            Err(A1Error::InvalidMagic)
        );
        changed = capsule;
        changed[4] ^= 1;
        changed[5] ^= 1;
        assert_eq!(
            decrypt(&a2, &wallet_id, &changed, &mut output),
            Err(A1Error::UnsupportedCodingVersion)
        );
        changed = capsule;
        changed[5] ^= 1;
        changed[6] ^= 1;
        assert_eq!(
            decrypt(&a2, &wallet_id, &changed, &mut output),
            Err(A1Error::UnsupportedCryptoVersion)
        );
        changed = capsule;
        changed[6] ^= 1;
        assert_eq!(
            decrypt(&a2, &wallet_id, &changed, &mut output),
            Err(A1Error::UnsupportedNetwork)
        );
        assert_eq!(output, [0xa5; 32]);
    }
}
