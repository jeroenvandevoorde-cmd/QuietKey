//! Exact M28 watch-only BSMS record construction and reopened-byte binding.

use core::fmt;
use qk_descriptor::{derive_change_script, derive_receive_script, parse_descriptor_pair};
use qk_provisioning::ProvisioningArtifacts;

const DESCRIPTOR_BYTES: usize = 445;
const DESCRIPTOR_BODY_BYTES: usize = 436;
const DESCRIPTOR_CHECKSUM_BYTES: usize = 8;
const MULTIPATH_BODY_BYTES: usize = 448;
const MULTIPATH_DESCRIPTOR_BYTES: usize = 457;
const ADDRESS_BYTES: usize = 62;
const SCRIPT_PUBKEY_BYTES: usize = 34;
const ACCOUNT_COUNT: usize = 3;

const VERSION_LINE: &[u8; 8] = b"BSMS 1.0";
const RESTRICTIONS_LINE: &[u8; 20] = b"No path restrictions";
const MULTIPATH: &[u8; 5] = b"<0;1>";
const BRANCH_POSITIONS: [usize; ACCOUNT_COUNT] = [153, 292, 431];
const MULTIPATH_POSITIONS: [usize; ACCOUNT_COUNT] = [153, 296, 439];

const VERSION_NEWLINE: usize = VERSION_LINE.len();
const DESCRIPTOR_START: usize = VERSION_NEWLINE + 1;
const DESCRIPTOR_NEWLINE: usize = DESCRIPTOR_START + MULTIPATH_DESCRIPTOR_BYTES;
const RESTRICTIONS_START: usize = DESCRIPTOR_NEWLINE + 1;
const RESTRICTIONS_NEWLINE: usize = RESTRICTIONS_START + RESTRICTIONS_LINE.len();
const ADDRESS_START: usize = RESTRICTIONS_NEWLINE + 1;
const ADDRESS_NEWLINE: usize = ADDRESS_START + ADDRESS_BYTES;

/// Exact byte length of the ratified four-line M28 watch-only record.
pub const BSMS_RECORD_BYTES: usize = 551;

const INPUT_CHARSET: &[u8] = b"0123456789()[],'/*abcdefgh@:$%{}IJKLMNOPQRSTUVWXYZ&+-.;<=>?!^_|~ijklmnopqrstuvwxyzABCDEFGH`#\"\\ ";
const CHECKSUM_CHARSET: &[u8; 32] = b"qpzry9x8gf2tvdw0s3jn54khce6mua7l";
const DESCRIPTOR_GENERATORS: [u64; 5] = [
    0x00f5_dee5_1989,
    0x00a9_fdca_3312,
    0x001b_ab10_e32d,
    0x0037_06b1_677a,
    0x0064_4d62_6ffd,
];

const BECH32_HRP: &[u8; 2] = b"bc";
const BECH32_CHARSET: &[u8; 32] = b"qpzry9x8gf2tvdw0s3jn54khce6mua7l";
const BECH32_DATA_SYMBOLS: usize = 53;
const BECH32_GENERATORS: [u32; 5] = [
    0x3b6a_57b2,
    0x2650_8e6d,
    0x1ea1_19fa,
    0x3d42_33dd,
    0x2a14_62b3,
];

const _: () =
    assert!(MULTIPATH_BODY_BYTES == DESCRIPTOR_BODY_BYTES + ACCOUNT_COUNT * (MULTIPATH.len() - 1));
const _: () =
    assert!(MULTIPATH_DESCRIPTOR_BYTES == MULTIPATH_BODY_BYTES + 1 + DESCRIPTOR_CHECKSUM_BYTES);
const _: () = assert!(ADDRESS_NEWLINE + 1 == BSMS_RECORD_BYTES);
const _: () = assert!(SCRIPT_PUBKEY_BYTES == 2 + 32);

/// Closed M28 BSMS construction and reopened-record rejection surface.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum BsmsError {
    InvalidDescriptorPair,
    WalletIdMismatch,
    FirstScriptMismatch,
    FirstAddressMismatch,
    DescriptorRoundTripMismatch,
    InvalidRecordLength,
    InvalidRecordEncoding,
    InvalidVersionLine,
    InvalidDescriptorLine,
    InvalidRestrictionsLine,
    InvalidAddressLine,
}

impl fmt::Display for BsmsError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::InvalidDescriptorPair => "InvalidDescriptorPair",
            Self::WalletIdMismatch => "WalletIdMismatch",
            Self::FirstScriptMismatch => "FirstScriptMismatch",
            Self::FirstAddressMismatch => "FirstAddressMismatch",
            Self::DescriptorRoundTripMismatch => "DescriptorRoundTripMismatch",
            Self::InvalidRecordLength => "InvalidRecordLength",
            Self::InvalidRecordEncoding => "InvalidRecordEncoding",
            Self::InvalidVersionLine => "InvalidVersionLine",
            Self::InvalidDescriptorLine => "InvalidDescriptorLine",
            Self::InvalidRestrictionsLine => "InvalidRestrictionsLine",
            Self::InvalidAddressLine => "InvalidAddressLine",
        })
    }
}

impl std::error::Error for BsmsError {}

/// Immutable exact four-line M28 watch-only record and its two bound
/// coordinator-comparison address facts.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct BsmsRecord {
    bytes: [u8; BSMS_RECORD_BYTES],
    receive_address: [u8; ADDRESS_BYTES],
    change_address: [u8; ADDRESS_BYTES],
}

impl BsmsRecord {
    /// Return the exact four LF-terminated record bytes.
    #[must_use]
    pub const fn bytes(&self) -> &[u8; BSMS_RECORD_BYTES] {
        &self.bytes
    }

    /// Return the existing bound branch-0/index-0 comparison fact.
    #[must_use]
    pub const fn receive_address(&self) -> &[u8; ADDRESS_BYTES] {
        &self.receive_address
    }

    /// Return the existing bound branch-1/index-0 comparison fact.
    #[must_use]
    pub const fn change_address(&self) -> &[u8; ADDRESS_BYTES] {
        &self.change_address
    }

    /// Reparse reopened bytes, rebind them to the authoritative descriptor
    /// pair, and require exact equality with this immutable record.
    pub fn verify_reopened(
        &self,
        reopened: &[u8],
        artifacts: &ProvisioningArtifacts,
    ) -> Result<(), BsmsError> {
        let lines = parse_record(reopened)?;
        if lines.version != VERSION_LINE {
            return Err(BsmsError::InvalidVersionLine);
        }
        if !descriptor_line_is_encoded(lines.descriptor) {
            return Err(BsmsError::InvalidDescriptorLine);
        }
        if lines.restrictions != RESTRICTIONS_LINE {
            return Err(BsmsError::InvalidRestrictionsLine);
        }
        if lines.address.len() != ADDRESS_BYTES {
            return Err(BsmsError::InvalidAddressLine);
        }

        let facts = validate_artifacts(artifacts)?;
        verify_descriptor_round_trip(
            lines.descriptor,
            &artifacts.descriptors[0],
            &artifacts.descriptors[1],
        )?;
        if lines.descriptor != facts.multipath_descriptor {
            return Err(BsmsError::DescriptorRoundTripMismatch);
        }
        if lines.address != facts.receive_address {
            return Err(BsmsError::InvalidAddressLine);
        }
        if self.receive_address != facts.receive_address
            || self.change_address != facts.change_address
        {
            return Err(BsmsError::FirstAddressMismatch);
        }

        let expected = assemble_record(&facts);
        if self.bytes != expected {
            return Err(BsmsError::DescriptorRoundTripMismatch);
        }
        if reopened != self.bytes {
            return Err(BsmsError::InvalidRecordEncoding);
        }
        Ok(())
    }
}

struct ValidatedFacts {
    multipath_descriptor: [u8; MULTIPATH_DESCRIPTOR_BYTES],
    receive_address: [u8; ADDRESS_BYTES],
    change_address: [u8; ADDRESS_BYTES],
}

struct RecordLines<'a> {
    version: &'a [u8],
    descriptor: &'a [u8],
    restrictions: &'a [u8],
    address: &'a [u8],
}

/// Build the exact M28 record solely from the frozen provisioning facts.
pub(crate) fn build_record(artifacts: &ProvisioningArtifacts) -> Result<BsmsRecord, BsmsError> {
    let facts = validate_artifacts(artifacts)?;
    verify_descriptor_round_trip(
        &facts.multipath_descriptor,
        &artifacts.descriptors[0],
        &artifacts.descriptors[1],
    )?;
    let bytes = assemble_record(&facts);
    let record = BsmsRecord {
        bytes,
        receive_address: facts.receive_address,
        change_address: facts.change_address,
    };
    record.verify_reopened(&bytes, artifacts)?;
    Ok(record)
}

fn validate_artifacts(artifacts: &ProvisioningArtifacts) -> Result<ValidatedFacts, BsmsError> {
    let receive = &artifacts.descriptors[0];
    let change = &artifacts.descriptors[1];
    let pair =
        parse_descriptor_pair(receive, change).map_err(|_| BsmsError::InvalidDescriptorPair)?;
    if pair.wallet_id() != artifacts.wallet_id {
        return Err(BsmsError::WalletIdMismatch);
    }

    let receive_script =
        derive_receive_script(&pair, 0).map_err(|_| BsmsError::InvalidDescriptorPair)?;
    let change_script =
        derive_change_script(&pair, 0).map_err(|_| BsmsError::InvalidDescriptorPair)?;
    if receive_script.script_pubkey != artifacts.first_scripts[0]
        || change_script.script_pubkey != artifacts.first_scripts[1]
    {
        return Err(BsmsError::FirstScriptMismatch);
    }

    let receive_address = address_for_script(&receive_script.script_pubkey)?;
    let change_address = address_for_script(&change_script.script_pubkey)?;
    if receive_address != artifacts.first_addresses[0]
        || change_address != artifacts.first_addresses[1]
    {
        return Err(BsmsError::FirstAddressMismatch);
    }

    let multipath_descriptor = build_multipath_descriptor(receive, change)?;
    Ok(ValidatedFacts {
        multipath_descriptor,
        receive_address,
        change_address,
    })
}

fn assemble_record(facts: &ValidatedFacts) -> [u8; BSMS_RECORD_BYTES] {
    let mut output = [0u8; BSMS_RECORD_BYTES];
    output[..VERSION_NEWLINE].copy_from_slice(VERSION_LINE);
    output[VERSION_NEWLINE] = b'\n';
    output[DESCRIPTOR_START..DESCRIPTOR_NEWLINE].copy_from_slice(&facts.multipath_descriptor);
    output[DESCRIPTOR_NEWLINE] = b'\n';
    output[RESTRICTIONS_START..RESTRICTIONS_NEWLINE].copy_from_slice(RESTRICTIONS_LINE);
    output[RESTRICTIONS_NEWLINE] = b'\n';
    output[ADDRESS_START..ADDRESS_NEWLINE].copy_from_slice(&facts.receive_address);
    output[ADDRESS_NEWLINE] = b'\n';
    output
}

fn parse_record(input: &[u8]) -> Result<RecordLines<'_>, BsmsError> {
    if input.len() != BSMS_RECORD_BYTES {
        return Err(BsmsError::InvalidRecordLength);
    }
    if input
        .iter()
        .any(|&byte| byte != b'\n' && !(0x20..=0x7e).contains(&byte))
    {
        return Err(BsmsError::InvalidRecordEncoding);
    }

    let mut lines = [&input[..0]; 4];
    let mut count = 0usize;
    let mut start = 0usize;
    for (position, &byte) in input.iter().enumerate() {
        if byte == b'\n' {
            if count == lines.len() {
                return Err(BsmsError::InvalidRecordEncoding);
            }
            lines[count] = &input[start..position];
            count += 1;
            start = position + 1;
        }
    }
    if count != lines.len() || start != input.len() || lines.iter().any(|line| line.is_empty()) {
        return Err(BsmsError::InvalidRecordEncoding);
    }
    Ok(RecordLines {
        version: lines[0],
        descriptor: lines[1],
        restrictions: lines[2],
        address: lines[3],
    })
}

fn build_multipath_descriptor(
    receive: &[u8; DESCRIPTOR_BYTES],
    change: &[u8; DESCRIPTOR_BYTES],
) -> Result<[u8; MULTIPATH_DESCRIPTOR_BYTES], BsmsError> {
    let mut output = [0u8; MULTIPATH_DESCRIPTOR_BYTES];
    let mut source = 0usize;
    let mut destination = 0usize;
    for &position in &BRANCH_POSITIONS {
        if receive[position] != b'0' || change[position] != b'1' {
            return Err(BsmsError::DescriptorRoundTripMismatch);
        }
        let copied = position - source;
        output[destination..destination + copied].copy_from_slice(&receive[source..position]);
        destination += copied;
        output[destination..destination + MULTIPATH.len()].copy_from_slice(MULTIPATH);
        destination += MULTIPATH.len();
        source = position + 1;
    }
    let remaining = DESCRIPTOR_BODY_BYTES - source;
    output[destination..destination + remaining]
        .copy_from_slice(&receive[source..DESCRIPTOR_BODY_BYTES]);
    destination += remaining;
    if destination != MULTIPATH_BODY_BYTES {
        return Err(BsmsError::DescriptorRoundTripMismatch);
    }
    output[MULTIPATH_BODY_BYTES] = b'#';
    let checksum = descriptor_checksum(&output[..MULTIPATH_BODY_BYTES])
        .ok_or(BsmsError::DescriptorRoundTripMismatch)?;
    output[MULTIPATH_BODY_BYTES + 1..].copy_from_slice(&checksum);
    Ok(output)
}

fn verify_descriptor_round_trip(
    candidate: &[u8],
    receive: &[u8; DESCRIPTOR_BYTES],
    change: &[u8; DESCRIPTOR_BYTES],
) -> Result<(), BsmsError> {
    if !descriptor_line_is_encoded(candidate) {
        return Err(BsmsError::DescriptorRoundTripMismatch);
    }
    let expanded_receive = expand_multipath_descriptor(candidate, b'0')?;
    let expanded_change = expand_multipath_descriptor(candidate, b'1')?;
    if expanded_receive != *receive || expanded_change != *change {
        return Err(BsmsError::DescriptorRoundTripMismatch);
    }
    parse_descriptor_pair(&expanded_receive, &expanded_change)
        .map_err(|_| BsmsError::DescriptorRoundTripMismatch)?;
    Ok(())
}

fn expand_multipath_descriptor(
    candidate: &[u8],
    branch: u8,
) -> Result<[u8; DESCRIPTOR_BYTES], BsmsError> {
    if candidate.len() != MULTIPATH_DESCRIPTOR_BYTES || (branch != b'0' && branch != b'1') {
        return Err(BsmsError::DescriptorRoundTripMismatch);
    }
    let mut output = [0u8; DESCRIPTOR_BYTES];
    let mut source = 0usize;
    let mut destination = 0usize;
    for &position in &MULTIPATH_POSITIONS {
        if candidate.get(position..position + MULTIPATH.len()) != Some(MULTIPATH) {
            return Err(BsmsError::DescriptorRoundTripMismatch);
        }
        let copied = position - source;
        output[destination..destination + copied].copy_from_slice(&candidate[source..position]);
        destination += copied;
        output[destination] = branch;
        destination += 1;
        source = position + MULTIPATH.len();
    }
    let remaining = MULTIPATH_BODY_BYTES - source;
    output[destination..destination + remaining]
        .copy_from_slice(&candidate[source..MULTIPATH_BODY_BYTES]);
    destination += remaining;
    if destination != DESCRIPTOR_BODY_BYTES {
        return Err(BsmsError::DescriptorRoundTripMismatch);
    }
    output[DESCRIPTOR_BODY_BYTES] = b'#';
    let checksum = descriptor_checksum(&output[..DESCRIPTOR_BODY_BYTES])
        .ok_or(BsmsError::DescriptorRoundTripMismatch)?;
    output[DESCRIPTOR_BODY_BYTES + 1..].copy_from_slice(&checksum);
    Ok(output)
}

fn descriptor_line_is_encoded(line: &[u8]) -> bool {
    line.len() == MULTIPATH_DESCRIPTOR_BYTES
        && line[MULTIPATH_BODY_BYTES] == b'#'
        && line[..MULTIPATH_BODY_BYTES]
            .iter()
            .all(|&byte| charset_position(INPUT_CHARSET, byte).is_some())
        && line[MULTIPATH_BODY_BYTES + 1..]
            .iter()
            .all(|&byte| charset_position(CHECKSUM_CHARSET, byte).is_some())
        && descriptor_checksum_matches(
            &line[..MULTIPATH_BODY_BYTES],
            &line[MULTIPATH_BODY_BYTES + 1..],
        )
}

fn descriptor_polymod_step(mut state: u64, value: u8) -> u64 {
    let high = state >> 35;
    state = ((state & 0x7_ffff_ffff) << 5) ^ u64::from(value);
    for (bit, generator) in DESCRIPTOR_GENERATORS.iter().enumerate() {
        if ((high >> bit) & 1) != 0 {
            state ^= generator;
        }
    }
    state
}

fn charset_position(charset: &[u8], byte: u8) -> Option<u8> {
    charset
        .iter()
        .position(|&candidate| candidate == byte)
        .and_then(|position| u8::try_from(position).ok())
}

fn descriptor_body_state(body: &[u8]) -> Option<u64> {
    let mut state = 1u64;
    let mut class = 0u8;
    let mut class_count = 0u8;
    for &byte in body {
        let position = charset_position(INPUT_CHARSET, byte)?;
        state = descriptor_polymod_step(state, position & 31);
        class = class.checked_mul(3)?.checked_add(position >> 5)?;
        class_count += 1;
        if class_count == 3 {
            state = descriptor_polymod_step(state, class);
            class = 0;
            class_count = 0;
        }
    }
    if class_count != 0 {
        state = descriptor_polymod_step(state, class);
    }
    Some(state)
}

fn descriptor_checksum(body: &[u8]) -> Option<[u8; DESCRIPTOR_CHECKSUM_BYTES]> {
    let mut state = descriptor_body_state(body)?;
    for _ in 0..DESCRIPTOR_CHECKSUM_BYTES {
        state = descriptor_polymod_step(state, 0);
    }
    state ^= 1;
    let mut output = [0u8; DESCRIPTOR_CHECKSUM_BYTES];
    for (position, slot) in output.iter_mut().enumerate() {
        let value = ((state >> (5 * (DESCRIPTOR_CHECKSUM_BYTES - 1 - position))) & 31) as usize;
        *slot = CHECKSUM_CHARSET[value];
    }
    Some(output)
}

fn descriptor_checksum_matches(body: &[u8], checksum: &[u8]) -> bool {
    let Some(mut state) = descriptor_body_state(body) else {
        return false;
    };
    for &byte in checksum {
        let Some(position) = charset_position(CHECKSUM_CHARSET, byte) else {
            return false;
        };
        state = descriptor_polymod_step(state, position);
    }
    state == 1
}

fn address_for_script(
    script_pubkey: &[u8; SCRIPT_PUBKEY_BYTES],
) -> Result<[u8; ADDRESS_BYTES], BsmsError> {
    if script_pubkey[..2] != [0x00, 0x20] {
        return Err(BsmsError::FirstScriptMismatch);
    }
    let mut witness_program = [0u8; 32];
    witness_program.copy_from_slice(&script_pubkey[2..]);
    Ok(encode_mainnet_p2wsh(&witness_program))
}

fn bech32_polymod_step(pre: u32) -> u32 {
    let high = pre >> 25;
    let mut value = (pre & 0x01ff_ffff) << 5;
    for (bit, generator) in BECH32_GENERATORS.iter().enumerate() {
        if ((high >> bit) & 1) != 0 {
            value ^= generator;
        }
    }
    value
}

fn bech32_checksum(data: &[u8; BECH32_DATA_SYMBOLS]) -> [u8; 6] {
    let mut state = 1u32;
    for &byte in BECH32_HRP {
        state = bech32_polymod_step(state) ^ u32::from(byte >> 5);
    }
    state = bech32_polymod_step(state);
    for &byte in BECH32_HRP {
        state = bech32_polymod_step(state) ^ u32::from(byte & 31);
    }
    for &symbol in data {
        state = bech32_polymod_step(state) ^ u32::from(symbol);
    }
    for _ in 0..6 {
        state = bech32_polymod_step(state);
    }
    state ^= 1;
    let mut output = [0u8; 6];
    for (position, slot) in output.iter_mut().enumerate() {
        *slot = ((state >> (5 * (5 - position))) & 31) as u8;
    }
    output
}

fn encode_mainnet_p2wsh(program: &[u8; 32]) -> [u8; ADDRESS_BYTES] {
    let mut data = [0u8; BECH32_DATA_SYMBOLS];
    data[0] = 0;
    let mut accumulator = 0u32;
    let mut bits = 0usize;
    let mut output_position = 1usize;
    for &byte in program {
        accumulator = (accumulator << 8) | u32::from(byte);
        bits += 8;
        while bits >= 5 {
            bits -= 5;
            data[output_position] = ((accumulator >> bits) & 31) as u8;
            output_position += 1;
        }
        accumulator = if bits == 0 {
            0
        } else {
            accumulator & ((1u32 << bits) - 1)
        };
    }
    if bits != 0 {
        data[output_position] = ((accumulator << (5 - bits)) & 31) as u8;
        output_position += 1;
    }
    debug_assert_eq!(output_position, BECH32_DATA_SYMBOLS);

    let checksum = bech32_checksum(&data);
    let mut output = [0u8; ADDRESS_BYTES];
    output[..2].copy_from_slice(BECH32_HRP);
    output[2] = b'1';
    for (slot, &symbol) in output[3..3 + BECH32_DATA_SYMBOLS]
        .iter_mut()
        .zip(data.iter())
    {
        *slot = BECH32_CHARSET[usize::from(symbol)];
    }
    for (slot, &symbol) in output[3 + BECH32_DATA_SYMBOLS..]
        .iter_mut()
        .zip(checksum.iter())
    {
        *slot = BECH32_CHARSET[usize::from(symbol)];
    }
    output
}

#[cfg(test)]
mod tests {
    use super::{
        descriptor_checksum, descriptor_checksum_matches, encode_mainnet_p2wsh,
        MULTIPATH_DESCRIPTOR_BYTES,
    };

    #[test]
    fn bip380_generator_and_verifier_agree_on_exact_multipath_shape() {
        let body = b"wsh(sortedmulti(2,[11223344/48'/0'/0'/2']xpub6EiqZQxK3N68TncJuZdg57rroGjX7AXqBn8gwSLrt7Vj9fir8ATDDDFoWnugu54fVauZkchPVgrghQGGHoAZtZ4u1VuUYf1q8opoftB8ivU/<0;1>/*,[55667788/48'/0'/0'/2']xpub6Eqgj8hoQsLqdX5WW4CqKjmnAjA1N6X69AgJ3YCbrgt3u1pTZWtYcugXzBuhxgr8K2KuE43cHu5WJ4cZYH382ShQ89gfSEd6DVEhoftA7Wf/<0;1>/*,[99aabbcc/48'/0'/0'/2']xpub6ExXtrTHnNbYowbLA4xeiCK9tH8qbE1kE4Yo6ndF37UjCqz9jYcxsr9CuDUKtybCATVxz8CQGmQfQqHHNerSktMG15jgXTAgai3Fk64KTZS/<0;1>/*))";
        assert_eq!(body.len() + 9, MULTIPATH_DESCRIPTOR_BYTES);
        let checksum = descriptor_checksum(body).expect("BIP380 charset");
        assert_eq!(&checksum, b"p6vh0ugf");
        assert!(descriptor_checksum_matches(body, &checksum));
    }

    #[test]
    fn mainnet_p2wsh_encoder_matches_registered_m11_receive_zero() {
        let program = [
            0x09, 0x4b, 0xba, 0x02, 0x41, 0x77, 0xbb, 0xe0, 0xd8, 0xdf, 0x87, 0x5c, 0x26, 0xe2,
            0xf8, 0xc4, 0xd4, 0x6a, 0xfb, 0x1f, 0x7c, 0xdd, 0x8f, 0xa6, 0x56, 0x6c, 0x85, 0xb2,
            0x71, 0xd5, 0x95, 0x5e,
        ];
        assert_eq!(
            &encode_mainnet_p2wsh(&program),
            b"bc1qp99m5qjpw7a7pkxlsawzdchccn2x47cl0nwclfjkdjzmyuw4j40q6m2xrp"
        );
    }
}
