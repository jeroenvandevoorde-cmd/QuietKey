//! Private fixed-profile BIP39 English entropy-to-seed chain.

use crate::hmac_sha512::hmac_sha512_into;
use crate::secret::{wipe, Secret};
use crate::sha256::sha256;
use crate::ProvisioningError;

const WORDLIST: &str = include_str!("english.txt");
#[cfg(test)]
const WORD_COUNT: usize = 2048;
const ENTROPY_BYTES: usize = 32;
const MNEMONIC_WORDS: usize = 24;
const MNEMONIC_CAPACITY: usize = 24 * 8 + 23;
const PBKDF2_ROUNDS: usize = 2048;

struct Mnemonic {
    bytes: Secret<MNEMONIC_CAPACITY>,
    len: usize,
}

impl Mnemonic {
    fn as_bytes(&self) -> &[u8] {
        &self.bytes.as_bytes()[..self.len]
    }
}

fn word_at(index: usize) -> Option<&'static str> {
    WORDLIST.lines().nth(index)
}

fn entropy_to_mnemonic(entropy: &[u8; ENTROPY_BYTES]) -> Result<Mnemonic, ProvisioningError> {
    let mut entropy_hash = sha256(entropy);
    let checksum = entropy_hash[0];
    wipe(&mut entropy_hash);
    let mut output = Secret::zeroed();
    let mut offset = 0usize;
    for word_number in 0..MNEMONIC_WORDS {
        let first_bit = word_number * 11;
        let mut index = 0usize;
        for bit in 0..11 {
            let absolute = first_bit + bit;
            let value = if absolute < ENTROPY_BYTES * 8 {
                (entropy[absolute / 8] >> (7 - absolute % 8)) & 1
            } else {
                (checksum >> (7 - (absolute - ENTROPY_BYTES * 8))) & 1
            };
            index = (index << 1) | usize::from(value);
        }
        let word = word_at(index).ok_or(ProvisioningError::CryptographicInvariant)?;
        if word_number != 0 {
            output.as_mut_bytes()[offset] = b' ';
            offset += 1;
        }
        let end = offset
            .checked_add(word.len())
            .ok_or(ProvisioningError::CryptographicInvariant)?;
        if end > MNEMONIC_CAPACITY || !word.is_ascii() {
            return Err(ProvisioningError::CryptographicInvariant);
        }
        output.as_mut_bytes()[offset..end].copy_from_slice(word.as_bytes());
        offset = end;
    }
    Ok(Mnemonic {
        bytes: output,
        len: offset,
    })
}

fn pbkdf2_hmac_sha512(
    password: &[u8],
    passphrase_nfkd_ascii: &[u8],
) -> Result<Secret<64>, ProvisioningError> {
    if !password.is_ascii() || !passphrase_nfkd_ascii.is_ascii() {
        return Err(ProvisioningError::CryptographicInvariant);
    }
    let mut salt = Vec::with_capacity(8 + passphrase_nfkd_ascii.len() + 4);
    salt.extend_from_slice(b"mnemonic");
    salt.extend_from_slice(passphrase_nfkd_ascii);
    salt.extend_from_slice(&1u32.to_be_bytes());
    let mut u = [0u8; 64];
    hmac_sha512_into(password, &salt, &mut u);
    let mut output = [0u8; 64];
    output.copy_from_slice(&u);
    for _ in 1..PBKDF2_ROUNDS {
        let mut next = [0u8; 64];
        hmac_sha512_into(password, &u, &mut next);
        wipe(&mut u);
        u.copy_from_slice(&next);
        for (slot, value) in output.iter_mut().zip(next.iter()) {
            *slot ^= *value;
        }
        wipe(&mut next);
    }
    wipe(&mut u);
    wipe(&mut salt);
    Ok(Secret::take(&mut output))
}

pub(crate) fn entropy_to_seed(entropy: &[u8; 32]) -> Result<Secret<64>, ProvisioningError> {
    let mnemonic = entropy_to_mnemonic(entropy)?;
    pbkdf2_hmac_sha512(mnemonic.as_bytes(), b"")
}

#[cfg(test)]
pub(crate) fn vector_entropy_to_mnemonic_and_seed(
    entropy: &[u8; 32],
    passphrase: &[u8],
) -> Result<(Vec<u8>, [u8; 64]), ProvisioningError> {
    let mnemonic = entropy_to_mnemonic(entropy)?;
    let visible_mnemonic = mnemonic.as_bytes().to_vec();
    let seed = pbkdf2_hmac_sha512(mnemonic.as_bytes(), passphrase)?;
    Ok((visible_mnemonic, *seed.as_bytes()))
}

#[cfg(test)]
mod tests {
    use super::{
        entropy_to_mnemonic, vector_entropy_to_mnemonic_and_seed, word_at, MNEMONIC_WORDS,
        WORDLIST, WORD_COUNT,
    };
    use crate::sha256::sha256;

    const FIXTURE: &str = include_str!("../tests/fixtures/bip39-english-256.txt");

    fn decode_hex<const N: usize>(text: &str) -> [u8; N] {
        assert_eq!(text.len(), N * 2);
        let mut output = [0u8; N];
        for (slot, position) in output.iter_mut().zip((0..text.len()).step_by(2)) {
            *slot = u8::from_str_radix(&text[position..position + 2], 16).expect("fixture hex");
        }
        output
    }

    #[test]
    fn exact_english_wordlist_shape_is_locked() {
        assert_eq!(WORDLIST.len(), 13_116);
        assert_eq!(WORDLIST.lines().count(), WORD_COUNT);
        assert!(WORDLIST.ends_with('\n'));
        assert_eq!(word_at(0), Some("abandon"));
        assert_eq!(word_at(2047), Some("zoo"));
    }

    #[test]
    fn zero_entropy_maps_to_24_words() {
        let mnemonic = entropy_to_mnemonic(&[0u8; 32]).expect("wordlist is complete");
        assert_eq!(
            mnemonic.as_bytes().split(|&byte| byte == b' ').count(),
            MNEMONIC_WORDS
        );
        assert_eq!(
            core::str::from_utf8(mnemonic.as_bytes()).expect("English ASCII"),
            "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon art"
        );
    }

    #[test]
    fn exact_eight_published_256_bit_vectors_execute() {
        assert_eq!(FIXTURE.len(), 5_477);
        assert!(FIXTURE.ends_with('\n'));
        assert!(!FIXTURE.contains('\r'));
        assert_eq!(
            sha256(FIXTURE.as_bytes()),
            decode_hex("e9d43debec8aa6dd15a5232a3d06c3352e62ce1954cc1c30faa32692602331ac")
        );
        let expected_indices = [8usize, 9, 10, 11, 14, 17, 20, 23];
        let mut source_index: Option<usize> = None;
        let mut entropy: Option<[u8; 32]> = None;
        let mut mnemonic: Option<&str> = None;
        let mut seed: Option<[u8; 64]> = None;
        let mut executed = 0usize;
        for line in FIXTURE.lines().chain(core::iter::once("")) {
            if let Some(value) = line.strip_prefix("source_index: ") {
                assert!(source_index
                    .replace(value.parse().expect("source index"))
                    .is_none());
            } else if let Some(value) = line.strip_prefix("entropy: ") {
                assert!(entropy.replace(decode_hex(value)).is_none());
            } else if let Some(value) = line.strip_prefix("mnemonic: ") {
                assert!(mnemonic.replace(value).is_none());
            } else if let Some(value) = line.strip_prefix("seed: ") {
                assert!(seed.replace(decode_hex(value)).is_none());
            } else if line.is_empty() && entropy.is_some() {
                assert_eq!(source_index.take(), Some(expected_indices[executed]));
                let (actual_mnemonic, actual_seed) = vector_entropy_to_mnemonic_and_seed(
                    &entropy.take().expect("entropy"),
                    b"TREZOR",
                )
                .expect("published ASCII profile");
                assert_eq!(
                    actual_mnemonic.as_slice(),
                    mnemonic.take().expect("mnemonic").as_bytes()
                );
                assert_eq!(actual_seed, seed.take().expect("seed"));
                executed += 1;
            }
        }
        assert_eq!(executed, 8);
    }
}
