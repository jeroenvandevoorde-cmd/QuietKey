//! Private construction of the one ratified paired descriptor form.

use crate::bech32::encode_p2wsh;
use crate::bip32_private::AccountPublic;
use crate::ProvisioningError;
use qk_descriptor::{derive_change_script, derive_receive_script, parse_descriptor_pair};

const DESCRIPTOR_BYTES: usize = 445;
const BODY_BYTES: usize = 436;
const SCRIPT_BYTES: usize = 34;
const ADDRESS_BYTES: usize = 62;
const INPUT_CHARSET: &[u8] = b"0123456789()[],'/*abcdefgh@:$%{}IJKLMNOPQRSTUVWXYZ&+-.;<=>?!^_|~ijklmnopqrstuvwxyzABCDEFGH`#\"\\ ";
const CHECKSUM_CHARSET: &[u8] = b"qpzry9x8gf2tvdw0s3jn54khce6mua7l";
const GENERATORS: [u64; 5] = [
    0x00f5_dee5_1989,
    0x00a9_fdca_3312,
    0x001b_ab10_e32d,
    0x0037_06b1_677a,
    0x0064_4d62_6ffd,
];

pub(crate) struct WalletPublic {
    pub(crate) descriptors: [[u8; DESCRIPTOR_BYTES]; 2],
    pub(crate) wallet_id: [u8; 32],
    pub(crate) scripts: [[u8; SCRIPT_BYTES]; 2],
    pub(crate) addresses: [[u8; ADDRESS_BYTES]; 2],
}

struct Writer<const N: usize> {
    bytes: [u8; N],
    len: usize,
}

impl<const N: usize> Writer<N> {
    fn new() -> Self {
        Self {
            bytes: [0u8; N],
            len: 0,
        }
    }

    fn push(&mut self, input: &[u8]) -> Result<(), ProvisioningError> {
        let end = self
            .len
            .checked_add(input.len())
            .ok_or(ProvisioningError::CryptographicInvariant)?;
        if end > N {
            return Err(ProvisioningError::CryptographicInvariant);
        }
        self.bytes[self.len..end].copy_from_slice(input);
        self.len = end;
        Ok(())
    }
}

fn polymod(mut state: u64, value: u8) -> u64 {
    let high = state >> 35;
    state = ((state & 0x7_ffff_ffff) << 5) ^ u64::from(value);
    for (bit, generator) in GENERATORS.iter().enumerate() {
        if ((high >> bit) & 1) != 0 {
            state ^= generator;
        }
    }
    state
}

fn checksum(body: &[u8; BODY_BYTES]) -> Result<[u8; 8], ProvisioningError> {
    let mut state = 1u64;
    let mut class = 0u8;
    let mut class_count = 0u8;
    for &byte in body {
        let position = INPUT_CHARSET
            .iter()
            .position(|&candidate| candidate == byte)
            .ok_or(ProvisioningError::CryptographicInvariant)? as u8;
        state = polymod(state, position & 31);
        class = class * 3 + (position >> 5);
        class_count += 1;
        if class_count == 3 {
            state = polymod(state, class);
            class = 0;
            class_count = 0;
        }
    }
    if class_count != 0 {
        state = polymod(state, class);
    }
    for _ in 0..8 {
        state = polymod(state, 0);
    }
    state ^= 1;
    let mut output = [0u8; 8];
    for (position, slot) in output.iter_mut().enumerate() {
        let value = ((state >> (5 * (7 - position))) & 31) as usize;
        *slot = CHECKSUM_CHARSET[value];
    }
    Ok(output)
}

fn hex_fingerprint(value: &[u8; 4]) -> [u8; 8] {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut output = [0u8; 8];
    for (index, &byte) in value.iter().enumerate() {
        output[index * 2] = HEX[usize::from(byte >> 4)];
        output[index * 2 + 1] = HEX[usize::from(byte & 15)];
    }
    output
}

fn build_one(
    accounts: &[AccountPublic; 3],
    branch: u8,
) -> Result<[u8; DESCRIPTOR_BYTES], ProvisioningError> {
    let mut writer = Writer::<BODY_BYTES>::new();
    writer.push(b"wsh(sortedmulti(2,")?;
    for (role, account) in accounts.iter().enumerate() {
        if role != 0 {
            writer.push(b",")?;
        }
        writer.push(b"[")?;
        writer.push(&hex_fingerprint(&account.origin_fingerprint))?;
        writer.push(b"/48'/0'/0'/2']")?;
        writer.push(&account.xpub)?;
        writer.push(b"/")?;
        writer.push(&[b'0' + branch])?;
        writer.push(b"/*")?;
    }
    writer.push(b"))")?;
    if writer.len != BODY_BYTES {
        return Err(ProvisioningError::CryptographicInvariant);
    }
    let check = checksum(&writer.bytes)?;
    let mut output = [0u8; DESCRIPTOR_BYTES];
    output[..BODY_BYTES].copy_from_slice(&writer.bytes);
    output[BODY_BYTES] = b'#';
    output[BODY_BYTES + 1..].copy_from_slice(&check);
    Ok(output)
}

pub(crate) fn build_wallet(
    accounts: [AccountPublic; 3],
) -> Result<WalletPublic, ProvisioningError> {
    let receive = build_one(&accounts, 0)?;
    let change = build_one(&accounts, 1)?;
    let pair = parse_descriptor_pair(&receive, &change)
        .map_err(|_| ProvisioningError::GeneratedDescriptorInvalid)?;
    let receive_derived = derive_receive_script(&pair, 0)
        .map_err(|_| ProvisioningError::GeneratedDescriptorInvalid)?;
    let change_derived = derive_change_script(&pair, 0)
        .map_err(|_| ProvisioningError::GeneratedDescriptorInvalid)?;
    let receive_program: [u8; 32] = receive_derived.script_pubkey[2..]
        .try_into()
        .map_err(|_| ProvisioningError::CryptographicInvariant)?;
    let change_program: [u8; 32] = change_derived.script_pubkey[2..]
        .try_into()
        .map_err(|_| ProvisioningError::CryptographicInvariant)?;
    Ok(WalletPublic {
        descriptors: [receive, change],
        wallet_id: pair.wallet_id(),
        scripts: [receive_derived.script_pubkey, change_derived.script_pubkey],
        addresses: [
            encode_p2wsh(&receive_program)?,
            encode_p2wsh(&change_program)?,
        ],
    })
}
