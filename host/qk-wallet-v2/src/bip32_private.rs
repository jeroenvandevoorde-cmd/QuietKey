//! Private fixed-path BIP32 derivation and mainnet xpub serialization.

use crate::hmac_sha512::hmac_sha512_into;
use crate::ripemd160::ripemd160;
use crate::secret::{wipe, Secret};
use crate::sha256::sha256;
use crate::WalletV2Error;

const HARDENED: u32 = 0x8000_0000;
const PATH: [u32; 4] = [HARDENED + 48, HARDENED, HARDENED, HARDENED + 2];
const MAINNET_XPUB: [u8; 4] = [0x04, 0x88, 0xb2, 0x1e];
const XPUB_PAYLOAD_BYTES: usize = 78;
const XPUB_CHECKED_BYTES: usize = 82;
const XPUB_TEXT_BYTES: usize = 111;
const BASE58: &[u8; 58] = b"123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";

pub(crate) struct AccountPublic {
    pub(crate) xpub: [u8; XPUB_TEXT_BYTES],
    pub(crate) origin_fingerprint: [u8; 4],
}

pub(crate) struct PrivateNode {
    scalar: Secret<32>,
    chain_code: Secret<32>,
    depth: u8,
    parent_fingerprint: [u8; 4],
    child_number: u32,
    origin_fingerprint: [u8; 4],
}

fn map_pubkey(secret: &[u8; 32], invalid: WalletV2Error) -> Result<[u8; 33], WalletV2Error> {
    qk_secp::provisioning_pubkey_create(secret).map_err(|error| map_pubkey_error(error, invalid))
}

fn map_pubkey_error(error: qk_secp::SecpError, invalid: WalletV2Error) -> WalletV2Error {
    match error {
        qk_secp::SecpError::ProvisioningPublicKeyCreateFailed => invalid,
        _ => WalletV2Error::CryptographicBackend,
    }
}

fn fingerprint(pubkey: &[u8; 33]) -> [u8; 4] {
    let digest = sha256(pubkey);
    let hash160 = ripemd160(&digest);
    [hash160[0], hash160[1], hash160[2], hash160[3]]
}

fn add_child_scalar(
    parent: &[u8; 32],
    tweak: &[u8; 32],
    child: &mut [u8; 32],
) -> Result<(), WalletV2Error> {
    // BIP32 permits IL == 0: the child scalar is then the parent scalar.
    // For every nonzero IL, public-key creation delegates the exact
    // IL < n range check to the pinned native boundary without local
    // scalar-order arithmetic.
    if tweak.iter().any(|&byte| byte != 0) {
        if let Err(error) = map_pubkey(tweak, WalletV2Error::InvalidChildTweak) {
            wipe(child);
            return Err(error);
        }
    }

    if let Err(error) = qk_secp::provisioning_secret_tweak_add(parent, tweak, child) {
        wipe(child);
        return Err(match error {
            // Parent validity is established and IL is now known to be
            // in range, so the remaining ordinary rejection is k_i == 0.
            qk_secp::SecpError::ProvisioningSecretTweakRejected => WalletV2Error::ZeroChild,
            _ => WalletV2Error::CryptographicBackend,
        });
    }
    Ok(())
}

fn master(seed: &[u8; 64]) -> Result<PrivateNode, WalletV2Error> {
    let mut material = [0u8; 64];
    hmac_sha512_into(b"Bitcoin seed", seed, &mut material);
    let mut scalar = [0u8; 32];
    scalar.copy_from_slice(&material[..32]);
    let mut chain_code = [0u8; 32];
    chain_code.copy_from_slice(&material[32..]);
    wipe(&mut material);
    let pubkey = match map_pubkey(&scalar, WalletV2Error::InvalidMasterScalar) {
        Ok(pubkey) => pubkey,
        Err(error) => {
            wipe(&mut scalar);
            wipe(&mut chain_code);
            return Err(error);
        }
    };
    let origin_fingerprint = fingerprint(&pubkey);
    Ok(PrivateNode {
        scalar: Secret::take(&mut scalar),
        chain_code: Secret::take(&mut chain_code),
        depth: 0,
        parent_fingerprint: [0u8; 4],
        child_number: 0,
        origin_fingerprint,
    })
}

fn derive_hardened(parent: PrivateNode, index: u32) -> Result<PrivateNode, WalletV2Error> {
    if index < HARDENED {
        return Err(WalletV2Error::CryptographicInvariant);
    }
    let child_depth = parent
        .depth
        .checked_add(1)
        .ok_or(WalletV2Error::CryptographicInvariant)?;
    let parent_pubkey = map_pubkey(
        parent.scalar.as_bytes(),
        WalletV2Error::CryptographicBackend,
    )?;
    let parent_fingerprint = fingerprint(&parent_pubkey);
    let mut data = [0u8; 37];
    data[1..33].copy_from_slice(parent.scalar.as_bytes());
    data[33..].copy_from_slice(&index.to_be_bytes());
    let mut material = [0u8; 64];
    hmac_sha512_into(parent.chain_code.as_bytes(), &data, &mut material);
    wipe(&mut data);
    let mut tweak = [0u8; 32];
    tweak.copy_from_slice(&material[..32]);
    let mut child_chain = [0u8; 32];
    child_chain.copy_from_slice(&material[32..]);
    wipe(&mut material);

    let mut child_scalar = [0u8; 32];
    let result = add_child_scalar(parent.scalar.as_bytes(), &tweak, &mut child_scalar);
    wipe(&mut tweak);
    result.inspect_err(|_| {
        wipe(&mut child_chain);
    })?;
    Ok(PrivateNode {
        scalar: Secret::take(&mut child_scalar),
        chain_code: Secret::take(&mut child_chain),
        depth: child_depth,
        parent_fingerprint,
        child_number: index,
        origin_fingerprint: parent.origin_fingerprint,
    })
}

fn derive_non_hardened(parent: &PrivateNode, index: u32) -> Result<PrivateNode, WalletV2Error> {
    if index >= HARDENED {
        return Err(WalletV2Error::CryptographicInvariant);
    }
    let child_depth = parent
        .depth
        .checked_add(1)
        .ok_or(WalletV2Error::CryptographicInvariant)?;
    let parent_pubkey = map_pubkey(
        parent.scalar.as_bytes(),
        WalletV2Error::CryptographicBackend,
    )?;
    let parent_fingerprint = fingerprint(&parent_pubkey);
    let mut data = [0u8; 37];
    data[..33].copy_from_slice(&parent_pubkey);
    data[33..].copy_from_slice(&index.to_be_bytes());
    let mut material = [0u8; 64];
    hmac_sha512_into(parent.chain_code.as_bytes(), &data, &mut material);
    wipe(&mut data);
    let mut tweak = [0u8; 32];
    tweak.copy_from_slice(&material[..32]);
    let mut child_chain = [0u8; 32];
    child_chain.copy_from_slice(&material[32..]);
    wipe(&mut material);

    let mut child_scalar = [0u8; 32];
    let result = add_child_scalar(parent.scalar.as_bytes(), &tweak, &mut child_scalar);
    wipe(&mut tweak);
    result.inspect_err(|_| {
        wipe(&mut child_chain);
    })?;
    Ok(PrivateNode {
        scalar: Secret::take(&mut child_scalar),
        chain_code: Secret::take(&mut child_chain),
        depth: child_depth,
        parent_fingerprint,
        child_number: index,
        origin_fingerprint: parent.origin_fingerprint,
    })
}

fn base58_encode(input: &[u8; XPUB_CHECKED_BYTES]) -> Result<[u8; XPUB_TEXT_BYTES], WalletV2Error> {
    let mut digits = [0u8; 112];
    let mut digit_count = 1usize;
    for &byte in input {
        let mut carry = u16::from(byte);
        for digit in digits[..digit_count].iter_mut() {
            let value = u16::from(*digit) * 256 + carry;
            *digit = (value % 58) as u8;
            carry = value / 58;
        }
        while carry != 0 {
            if digit_count >= digits.len() {
                return Err(WalletV2Error::CryptographicInvariant);
            }
            digits[digit_count] = (carry % 58) as u8;
            digit_count += 1;
            carry /= 58;
        }
    }
    let leading_zeroes = input.iter().take_while(|&&byte| byte == 0).count();
    if leading_zeroes + digit_count != XPUB_TEXT_BYTES {
        return Err(WalletV2Error::CryptographicInvariant);
    }
    let mut output = [b'1'; XPUB_TEXT_BYTES];
    for (position, &digit) in digits[..digit_count].iter().rev().enumerate() {
        output[leading_zeroes + position] = BASE58[usize::from(digit)];
    }
    Ok(output)
}

fn encode_xpub(node: &PrivateNode) -> Result<[u8; XPUB_TEXT_BYTES], WalletV2Error> {
    let public_key = map_pubkey(node.scalar.as_bytes(), WalletV2Error::CryptographicBackend)?;
    let mut payload = [0u8; XPUB_PAYLOAD_BYTES];
    payload[..4].copy_from_slice(&MAINNET_XPUB);
    payload[4] = node.depth;
    payload[5..9].copy_from_slice(&node.parent_fingerprint);
    payload[9..13].copy_from_slice(&node.child_number.to_be_bytes());
    payload[13..45].copy_from_slice(node.chain_code.as_bytes());
    payload[45..].copy_from_slice(&public_key);
    let first = sha256(&payload);
    let checksum = sha256(&first);
    let mut checked = [0u8; XPUB_CHECKED_BYTES];
    checked[..XPUB_PAYLOAD_BYTES].copy_from_slice(&payload);
    checked[XPUB_PAYLOAD_BYTES..].copy_from_slice(&checksum[..4]);
    base58_encode(&checked)
}

pub(crate) fn derive_account_private(seed: &[u8; 64]) -> Result<PrivateNode, WalletV2Error> {
    let mut node = master(seed)?;
    for index in PATH {
        node = derive_hardened(node, index)?;
    }
    if node.depth != 4 || node.child_number != HARDENED + 2 {
        return Err(WalletV2Error::CryptographicInvariant);
    }
    Ok(node)
}

pub(crate) fn account_public(node: &PrivateNode) -> Result<AccountPublic, WalletV2Error> {
    Ok(AccountPublic {
        xpub: encode_xpub(node)?,
        origin_fingerprint: node.origin_fingerprint,
    })
}

pub(crate) fn derive_account(seed: &[u8; 64]) -> Result<AccountPublic, WalletV2Error> {
    let node = derive_account_private(seed)?;
    account_public(&node)
}

pub(crate) fn derive_route_scalar(
    account: &PrivateNode,
    branch: u32,
    index: u32,
) -> Result<(Secret<32>, [u8; 33]), WalletV2Error> {
    if branch > 1 || index > 65_535 {
        return Err(WalletV2Error::CryptographicInvariant);
    }
    let branch_node = derive_non_hardened(account, branch)?;
    let child = derive_non_hardened(&branch_node, index)?;
    if child.depth != 6 || child.child_number != index {
        return Err(WalletV2Error::CryptographicInvariant);
    }
    let public_key = map_pubkey(child.scalar.as_bytes(), WalletV2Error::CryptographicBackend)?;
    Ok((child.scalar, public_key))
}

#[cfg(test)]
mod tests {
    use super::{
        add_child_scalar, base58_encode, derive_hardened, map_pubkey, map_pubkey_error, master,
    };
    use crate::WalletV2Error;

    const ORDER_N: [u8; 32] = [
        0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
        0xfe, 0xba, 0xae, 0xdc, 0xe6, 0xaf, 0x48, 0xa0, 0x3b, 0xbf, 0xd2, 0x5e, 0x8c, 0xd0, 0x36,
        0x41, 0x41,
    ];
    const ORDER_N_MINUS_ONE: [u8; 32] = [
        0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
        0xfe, 0xba, 0xae, 0xdc, 0xe6, 0xaf, 0x48, 0xa0, 0x3b, 0xbf, 0xd2, 0x5e, 0x8c, 0xd0, 0x36,
        0x41, 0x40,
    ];

    #[test]
    fn fixed_base58_encoder_rejects_non_xpub_geometry() {
        assert!(base58_encode(&[0u8; 82]).is_err());
    }

    #[test]
    fn bip32_zero_il_is_identity_while_order_is_rejected() {
        let mut parent = [0u8; 32];
        parent[31] = 1;
        let mut child = [0xa5u8; 32];
        assert_eq!(add_child_scalar(&parent, &[0u8; 32], &mut child), Ok(()));
        assert_eq!(child, parent);
        assert_eq!(
            add_child_scalar(&parent, &ORDER_N_MINUS_ONE, &mut child),
            Err(WalletV2Error::ZeroChild)
        );
        assert_eq!(child, [0u8; 32]);
        assert_eq!(
            add_child_scalar(&parent, &ORDER_N, &mut child),
            Err(WalletV2Error::InvalidChildTweak)
        );
    }

    #[test]
    fn master_and_fixed_path_failures_keep_their_named_categories() {
        assert_eq!(
            map_pubkey(&[0u8; 32], WalletV2Error::InvalidMasterScalar),
            Err(WalletV2Error::InvalidMasterScalar)
        );
        let node = master(&[0u8; 64]).expect("fixed seed produces a valid master node");
        assert!(matches!(
            derive_hardened(node, 0),
            Err(WalletV2Error::CryptographicInvariant)
        ));
        assert_eq!(
            map_pubkey_error(
                qk_secp::SecpError::ProvisioningContextUnavailable,
                WalletV2Error::InvalidMasterScalar,
            ),
            WalletV2Error::CryptographicBackend
        );
    }
}
