//! Model-only record binding, BIP32 CKDpriv and fixture signing operations.

use crate::{
    hmac_sha512, scalar, sha256, wipe, DESCRIPTOR_BYTES, EXTENDED_KEY_BYTES, MAX_DER_BYTES,
    RECORD_BYTES,
};

const RECORD_DOMAIN: &[u8] = b"QuietKey/CardRecord/v1";
const INSTANCE_DOMAIN: &[u8] = b"QuietKey/CardInstance/v1";
const XPRV_VERSION: [u8; 4] = [0x04, 0x88, 0xad, 0xe4];
const XPUB_VERSION: [u8; 4] = [0x04, 0x88, 0xb2, 0x1e];

pub(crate) const PROFILE_OFFSET: usize = 5;
pub(crate) const ROLE_OFFSET: usize = 6;
pub(crate) const INSTANCE_OFFSET: usize = 7;
pub(crate) const WALLET_OFFSET: usize = 23;
pub(crate) const FINGERPRINT_OFFSET: usize = 55;
pub(crate) const XPRV_OFFSET: usize = 59;
pub(crate) const A2_OFFSET: usize = 137;
pub(crate) const RECEIVE_OFFSET: usize = 169;
pub(crate) const CHANGE_OFFSET: usize = 475;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum CryptoError {
    Record,
    Wallet,
    Child,
    Native,
}

pub(crate) fn record_digest(record: &[u8; RECORD_BYTES], output: &mut [u8; 32]) {
    sha256::hash(&[RECORD_DOMAIN, &[0], record], output);
}

pub(crate) fn wallet_id(record: &[u8; RECORD_BYTES], output: &mut [u8; 32]) {
    sha256::hash(
        &[
            &record[RECEIVE_OFFSET..RECEIVE_OFFSET + DESCRIPTOR_BYTES],
            &[0],
            &record[CHANGE_OFFSET..CHANGE_OFFSET + DESCRIPTOR_BYTES],
        ],
        output,
    );
}

pub(crate) fn instance_id(
    wallet_id: &[u8; 32],
    ordinal: u8,
    nonce: &[u8; 12],
    output: &mut [u8; 16],
) {
    let mut digest = wipe::WipingArray::<32>::zeroed();
    sha256::hash(
        &[INSTANCE_DOMAIN, &[0], wallet_id, &[0], &[ordinal], nonce],
        digest.as_mut_array(),
    );
    output.copy_from_slice(&digest.as_slice()[..16]);
}

/// Validate the fixed record, its bindings and raw mainnet xprv, and derive
/// the raw account xpub once for persistent storage.
pub(crate) fn validate_and_derive_xpub(
    record: &[u8; RECORD_BYTES],
    ordinal: u8,
    nonce: &[u8; 12],
    output: &mut [u8; EXTENDED_KEY_BYTES],
) -> Result<(), CryptoError> {
    if &record[..4] != b"QKCB"
        || record[4] != 1
        || !matches!(record[PROFILE_OFFSET], 1..=3)
        || record[ROLE_OFFSET] != 2
    {
        return Err(CryptoError::Record);
    }
    let xprv = &record[XPRV_OFFSET..XPRV_OFFSET + EXTENDED_KEY_BYTES];
    if xprv[..4] != XPRV_VERSION || xprv[4] != 4 || xprv[9..13] != [0x80, 0, 0, 2] || xprv[45] != 0
    {
        return Err(CryptoError::Record);
    }
    let mut scalar_source = [0u8; 32];
    scalar_source.copy_from_slice(&xprv[46..78]);
    let scalar_bytes = wipe::WipingArray::from_source(&mut scalar_source);
    if !scalar::valid(scalar_bytes.as_array()) {
        return Err(CryptoError::Record);
    }
    let mut calculated_wallet = wipe::WipingArray::<32>::zeroed();
    wallet_id(record, calculated_wallet.as_mut_array());
    if calculated_wallet.as_slice() != &record[WALLET_OFFSET..WALLET_OFFSET + 32] {
        return Err(CryptoError::Wallet);
    }
    let mut calculated_instance = wipe::WipingArray::<16>::zeroed();
    instance_id(
        calculated_wallet.as_array(),
        ordinal,
        nonce,
        calculated_instance.as_mut_array(),
    );
    if calculated_instance.as_slice() != &record[INSTANCE_OFFSET..INSTANCE_OFFSET + 16] {
        return Err(CryptoError::Wallet);
    }
    let public_result = qk_secp::provisioning_pubkey_create(scalar_bytes.as_array());
    let public = match public_result {
        Ok(value) => value,
        Err(_) => return Err(CryptoError::Native),
    };
    output[..4].copy_from_slice(&XPUB_VERSION);
    output[4..45].copy_from_slice(&xprv[4..45]);
    output[45..].copy_from_slice(&public);
    Ok(())
}

pub(crate) struct DerivedChild {
    scalar: wipe::WipingArray<32>,
    public: [u8; 33],
}

impl Drop for DerivedChild {
    fn drop(&mut self) {
        wipe::bytes(&mut self.public);
    }
}

pub(crate) fn derive_signing_child(
    record: &[u8; RECORD_BYTES],
    branch: u8,
    child_index: u32,
    inject_unwind: bool,
) -> Result<DerivedChild, CryptoError> {
    if branch > 1 || child_index > 65_535 {
        return Err(CryptoError::Child);
    }
    let xprv = &record[XPRV_OFFSET..XPRV_OFFSET + EXTENDED_KEY_BYTES];
    let mut scalar_source = [0u8; 32];
    scalar_source.copy_from_slice(&xprv[46..78]);
    let mut scalar_bytes = wipe::WipingArray::from_source(&mut scalar_source);
    let mut chain_source = [0u8; 32];
    chain_source.copy_from_slice(&xprv[13..45]);
    let mut chain = wipe::WipingArray::from_source(&mut chain_source);
    derive_child(
        scalar_bytes.as_mut_array(),
        chain.as_mut_array(),
        u32::from(branch),
        inject_unwind,
    )?;
    derive_child(
        scalar_bytes.as_mut_array(),
        chain.as_mut_array(),
        child_index,
        false,
    )?;
    let public = qk_secp::provisioning_pubkey_create(scalar_bytes.as_array())
        .map_err(|_| CryptoError::Native)?;
    Ok(DerivedChild {
        scalar: scalar_bytes,
        public,
    })
}

pub(crate) fn sign_derived_child(
    mut child: DerivedChild,
    digest: &[u8; 32],
    public_output: &mut [u8; 33],
    der_output: &mut [u8; MAX_DER_BYTES],
) -> Result<usize, CryptoError> {
    *public_output = child.public;
    let expected =
        qk_secp::pubkey_parse_compressed(public_output).map_err(|_| CryptoError::Native)?;
    let key =
        qk_secp::secret_key_import(child.scalar.as_mut_array()).map_err(|_| CryptoError::Native)?;
    let signature =
        qk_secp::ecdsa_sign_rfc6979(&key, digest, &expected).map_err(|_| CryptoError::Native)?;
    qk_secp::signature_serialize_der(&signature, der_output).map_err(|_| CryptoError::Native)
}

fn derive_child(
    scalar_bytes: &mut [u8; 32],
    chain: &mut [u8; 32],
    child_index: u32,
    inject_unwind: bool,
) -> Result<(), CryptoError> {
    let public =
        qk_secp::provisioning_pubkey_create(scalar_bytes).map_err(|_| CryptoError::Native)?;
    let mut message = wipe::WipingArray::<37>::zeroed();
    message.as_mut_slice()[..33].copy_from_slice(&public);
    message.as_mut_slice()[33..].copy_from_slice(&child_index.to_be_bytes());
    let mut material = wipe::WipingArray::<64>::zeroed();
    hmac_sha512::hmac_32_37(chain, message.as_array(), material.as_mut_array());
    let mut tweak = wipe::WipingArray::<32>::zeroed();
    tweak
        .as_mut_slice()
        .copy_from_slice(&material.as_slice()[..32]);
    let mut child = wipe::WipingArray::<32>::zeroed();
    if !scalar::add_mod_order(scalar_bytes, tweak.as_array(), child.as_mut_array()) {
        return Err(CryptoError::Child);
    }
    if inject_unwind {
        std::panic::resume_unwind(Box::new("qk-card-model injected interior crypto unwind"));
    }
    scalar_bytes.copy_from_slice(child.as_slice());
    chain.copy_from_slice(&material.as_slice()[32..]);
    Ok(())
}

/// Convert a strict low-S DER fixture signature to its strict high-S sibling.
pub(crate) fn high_s_sibling(
    input: &[u8],
    output: &mut [u8; MAX_DER_BYTES],
) -> Result<usize, CryptoError> {
    if input.len() < 8 || input.len() > MAX_DER_BYTES || input[0] != 0x30 {
        return Err(CryptoError::Native);
    }
    if usize::from(input[1]).checked_add(2) != Some(input.len()) || input[2] != 0x02 {
        return Err(CryptoError::Native);
    }
    let r_len = usize::from(input[3]);
    let r_end = 4usize.checked_add(r_len).ok_or(CryptoError::Native)?;
    if r_len == 0
        || r_end.checked_add(2).is_none_or(|end| end > input.len())
        || input[r_end] != 0x02
    {
        return Err(CryptoError::Native);
    }
    let s_len = usize::from(input[r_end + 1]);
    let s_start = r_end + 2;
    if s_len == 0 || s_start.checked_add(s_len) != Some(input.len()) || s_len > 33 {
        return Err(CryptoError::Native);
    }
    let encoded_s = &input[s_start..];
    let magnitude = if encoded_s.first() == Some(&0) {
        &encoded_s[1..]
    } else {
        encoded_s
    };
    if magnitude.is_empty() || magnitude.len() > 32 {
        return Err(CryptoError::Native);
    }
    let mut low_s = wipe::WipingArray::<32>::zeroed();
    low_s.as_mut_slice()[32 - magnitude.len()..].copy_from_slice(magnitude);
    let mut high_s = wipe::WipingArray::<32>::zeroed();
    if !scalar::negate_mod_order(low_s.as_array(), high_s.as_mut_array()) {
        return Err(CryptoError::Native);
    }
    let Some(first_nonzero) = high_s.as_slice().iter().position(|byte| *byte != 0) else {
        return Err(CryptoError::Native);
    };
    let high_magnitude = &high_s.as_slice()[first_nonzero..];
    let leading_zero = usize::from(high_magnitude[0] & 0x80 != 0);
    let encoded_high_len = high_magnitude.len() + leading_zero;
    let sequence_len = 2 + r_len + 2 + encoded_high_len;
    let total = sequence_len + 2;
    if total > output.len() {
        return Err(CryptoError::Native);
    }
    output.fill(0);
    output[0] = 0x30;
    output[1] = sequence_len as u8;
    output[2] = 0x02;
    output[3] = r_len as u8;
    output[4..r_end].copy_from_slice(&input[4..r_end]);
    output[r_end] = 0x02;
    output[r_end + 1] = encoded_high_len as u8;
    let high_start = r_end + 2;
    if leading_zero == 1 {
        output[high_start] = 0;
    }
    output[high_start + leading_zero..total].copy_from_slice(high_magnitude);
    Ok(total)
}

#[cfg(test)]
mod tests {
    use super::derive_child;

    #[test]
    fn two_step_ckdpriv_public_fixture_vector_is_locked() {
        let mut scalar = [
            0x8a, 0xc2, 0x28, 0x2a, 0x9c, 0xbd, 0xbe, 0xbb, 0xc2, 0xb2, 0x0e, 0x9f, 0xa1, 0xe3,
            0xd8, 0x5e, 0xdc, 0xf9, 0x47, 0xcc, 0xaa, 0xf7, 0xf4, 0x27, 0x33, 0xff, 0x43, 0x9b,
            0xb3, 0x59, 0x5b, 0x5c,
        ];
        let mut chain = [
            0x5f, 0x8f, 0x64, 0x53, 0x9f, 0x27, 0x73, 0x8b, 0xf2, 0x0d, 0x41, 0x02, 0x19, 0x94,
            0x3a, 0xe4, 0x07, 0x40, 0xb1, 0x22, 0xaa, 0xe2, 0x5d, 0x75, 0x97, 0xc8, 0xc0, 0x4c,
            0x23, 0x5f, 0xeb, 0x91,
        ];
        assert_eq!(derive_child(&mut scalar, &mut chain, 1, false), Ok(()));
        assert_eq!(derive_child(&mut scalar, &mut chain, 65_535, false), Ok(()));
        assert_eq!(
            scalar,
            [
                0x2e, 0xc8, 0xf7, 0x54, 0xa8, 0x24, 0xa6, 0xcd, 0x88, 0x39, 0xb5, 0x74, 0x0b, 0x16,
                0xb9, 0xb8, 0xa4, 0x3f, 0x74, 0x99, 0x5e, 0x50, 0x20, 0xca, 0x19, 0xca, 0x46, 0xa0,
                0x31, 0xa2, 0x28, 0x69,
            ]
        );
        assert_eq!(
            chain,
            [
                0xe2, 0xcf, 0xb9, 0xae, 0x1b, 0xa5, 0xf4, 0xd3, 0x48, 0x22, 0xbb, 0x3f, 0xed, 0xef,
                0x81, 0x98, 0xce, 0xbb, 0x46, 0x64, 0x1e, 0x3e, 0x70, 0x80, 0x81, 0xdf, 0xbf, 0x04,
                0x8f, 0x85, 0x59, 0xea,
            ]
        );
    }
}
