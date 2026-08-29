//! Private deterministic Kit-R pad derivation for the v2 setup owner.

use crate::hkdf_sha256::{expand, extract};
use crate::secret::{wipe, Secret};
use crate::sha256::sha256;
use crate::ProvisioningError;

const SALT_PREFIX: &[u8; 15] = b"QuietKey/QKEC-1";
const PURPOSE: &[u8; 5] = b"Kit-R";
const INFO_PREFIX: &[u8; 21] = b"QuietKey/Kit-R/pad/v1";
const CEREMONY_ID_BYTES: usize = 16;
const SALT_INPUT_BYTES: usize = SALT_PREFIX.len() + PURPOSE.len() + CEREMONY_ID_BYTES;
const INFO_BYTES: usize = INFO_PREFIX.len() + 1 + 32;
const PAD_BYTES: usize = 96;

pub(crate) fn derive_pad(
    transcript_hash: &Secret<32>,
    wallet_id: &[u8; 32],
) -> Result<Secret<PAD_BYTES>, ProvisioningError> {
    let mut salt_input = [0u8; SALT_INPUT_BYTES];
    salt_input[..SALT_PREFIX.len()].copy_from_slice(SALT_PREFIX);
    salt_input[SALT_PREFIX.len()..SALT_PREFIX.len() + PURPOSE.len()].copy_from_slice(PURPOSE);
    salt_input[SALT_PREFIX.len() + PURPOSE.len()..].copy_from_slice(&wallet_id[..16]);
    let mut salt = sha256(&salt_input);
    wipe(&mut salt_input);

    let mut prk = extract(&salt, transcript_hash.as_bytes());
    wipe(&mut salt);
    let mut info = [0u8; INFO_BYTES];
    info[..INFO_PREFIX.len()].copy_from_slice(INFO_PREFIX);
    info[INFO_PREFIX.len()] = 0;
    info[INFO_PREFIX.len() + 1..].copy_from_slice(wallet_id);
    let mut pad = [0u8; PAD_BYTES];
    let expanded = expand(&prk, &info, &mut pad);
    wipe(&mut prk);
    wipe(&mut info);
    if !expanded {
        wipe(&mut pad);
        return Err(ProvisioningError::CryptographicInvariant);
    }
    Ok(Secret::take(&mut pad))
}

#[cfg(test)]
mod tests {
    use super::derive_pad;
    use crate::secret::Secret;
    use crate::sha256::sha256;

    fn decode_hex<const N: usize>(input: &str) -> [u8; N] {
        assert_eq!(input.len(), N * 2);
        let mut output = [0u8; N];
        for (index, slot) in output.iter_mut().enumerate() {
            *slot = u8::from_str_radix(&input[index * 2..index * 2 + 2], 16).expect("test hex");
        }
        output
    }

    #[test]
    fn public_slice_four_vector_locks_the_exact_kit_r_domain() {
        let mut transcript = [0u8; 100];
        let pattern = b"345612";
        for (index, slot) in transcript.iter_mut().enumerate() {
            *slot = pattern[index % pattern.len()];
        }
        let mut transcript_hash = sha256(&transcript);
        let transcript_hash = Secret::take(&mut transcript_hash);
        let wallet_id =
            decode_hex::<32>("d5b7e52f569ae51e7c66af14240d8e4459c6246785ce5c441773995614f60e9e");
        let expected = decode_hex::<96>(
            "01763f94ae723d45c1010173a1f2f9e18c86406ccc7903d935fc37cd50b1f83016deb4f7c563f1fb4d6aed3a0210245ff0c0edd6ac428a8233eaf65dd48a95fd159067182b0db7acaa5e3689b5d36c661d5bc4fa9060143d1ea403aed893db6c",
        );
        let pad = derive_pad(&transcript_hash, &wallet_id).expect("public Kit-R vector");
        assert_eq!(pad.as_bytes(), &expected);
    }

    #[test]
    fn wallet_identity_changes_the_derived_pad() {
        let mut transcript_hash = [0x42u8; 32];
        let transcript_hash = Secret::take(&mut transcript_hash);
        let first = derive_pad(&transcript_hash, &[0u8; 32]).expect("first pad");
        let second = derive_pad(&transcript_hash, &[1u8; 32]).expect("second pad");
        assert_ne!(first.as_bytes(), second.as_bytes());
    }
}
