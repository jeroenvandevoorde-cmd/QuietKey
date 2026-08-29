//! Exact v2 slice-6 watch-only BSMS record construction and reopened-byte binding.

use core::fmt;
use qk_descriptor::{derive_change_script_v2, derive_receive_script_v2, parse_descriptor_pair_v2};
use qk_provisioning::ProvisioningArtifactsV2;

const DESCRIPTOR_BYTES: usize = 306;
const DESCRIPTOR_BODY_BYTES: usize = 297;
const DESCRIPTOR_CHECKSUM_BYTES: usize = 8;
const MULTIPATH_BODY_BYTES: usize = 305;
const MULTIPATH_DESCRIPTOR_BYTES: usize = 314;
const ADDRESS_BYTES: usize = 62;
const SCRIPT_PUBKEY_BYTES: usize = 34;
const ACCOUNT_COUNT: usize = 2;

const VERSION_LINE: &[u8; 8] = b"BSMS 1.0";
const RESTRICTIONS_LINE: &[u8; 20] = b"No path restrictions";
const MULTIPATH: &[u8; 5] = b"<0;1>";
const BRANCH_POSITIONS: [usize; ACCOUNT_COUNT] = [153, 292];
const MULTIPATH_POSITIONS: [usize; ACCOUNT_COUNT] = [153, 296];

const VERSION_NEWLINE: usize = VERSION_LINE.len();
const DESCRIPTOR_START: usize = VERSION_NEWLINE + 1;
const DESCRIPTOR_NEWLINE: usize = DESCRIPTOR_START + MULTIPATH_DESCRIPTOR_BYTES;
const RESTRICTIONS_START: usize = DESCRIPTOR_NEWLINE + 1;
const RESTRICTIONS_NEWLINE: usize = RESTRICTIONS_START + RESTRICTIONS_LINE.len();
const ADDRESS_START: usize = RESTRICTIONS_NEWLINE + 1;
const ADDRESS_NEWLINE: usize = ADDRESS_START + ADDRESS_BYTES;

/// Exact byte length of the ratified four-line v2 watch-only record.
pub const BSMS_RECORD_BYTES_V2: usize = 408;

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
const _: () = assert!(ADDRESS_NEWLINE + 1 == BSMS_RECORD_BYTES_V2);
const _: () = assert!(SCRIPT_PUBKEY_BYTES == 2 + 32);

/// Closed v2 BSMS construction and reopened-record rejection surface.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum BsmsErrorV2 {
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

impl fmt::Display for BsmsErrorV2 {
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

impl std::error::Error for BsmsErrorV2 {}

/// Immutable exact four-line v2 watch-only record and its two bound
/// coordinator-comparison address facts.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct BsmsRecordV2 {
    bytes: [u8; BSMS_RECORD_BYTES_V2],
    receive_address: [u8; ADDRESS_BYTES],
    change_address: [u8; ADDRESS_BYTES],
}

impl BsmsRecordV2 {
    /// Return the exact four LF-terminated record bytes.
    #[must_use]
    pub(crate) const fn bytes(&self) -> &[u8; BSMS_RECORD_BYTES_V2] {
        &self.bytes
    }

    /// Return the existing bound branch-0/index-0 comparison fact.
    #[must_use]
    pub(crate) const fn receive_address(&self) -> &[u8; ADDRESS_BYTES] {
        &self.receive_address
    }

    /// Return the existing bound branch-1/index-0 comparison fact.
    #[must_use]
    pub(crate) const fn change_address(&self) -> &[u8; ADDRESS_BYTES] {
        &self.change_address
    }

    /// Reparse reopened bytes, rebind them to the authoritative descriptor
    /// pair, and require exact equality with this immutable record.
    pub(crate) fn verify_reopened(
        &self,
        reopened: &[u8],
        binding: &BsmsBindingV2,
    ) -> Result<(), BsmsErrorV2> {
        let lines = parse_record(reopened)?;
        if lines.version != VERSION_LINE {
            return Err(BsmsErrorV2::InvalidVersionLine);
        }
        if !descriptor_line_is_encoded(lines.descriptor) {
            return Err(BsmsErrorV2::InvalidDescriptorLine);
        }
        if lines.restrictions != RESTRICTIONS_LINE {
            return Err(BsmsErrorV2::InvalidRestrictionsLine);
        }
        if lines.address.len() != ADDRESS_BYTES {
            return Err(BsmsErrorV2::InvalidAddressLine);
        }

        let facts = validate_binding(binding)?;
        verify_descriptor_round_trip(
            lines.descriptor,
            &binding.descriptors[0],
            &binding.descriptors[1],
        )?;
        if lines.descriptor != facts.multipath_descriptor {
            return Err(BsmsErrorV2::DescriptorRoundTripMismatch);
        }
        if lines.address != facts.receive_address {
            return Err(BsmsErrorV2::InvalidAddressLine);
        }
        if self.receive_address != facts.receive_address
            || self.change_address != facts.change_address
        {
            return Err(BsmsErrorV2::FirstAddressMismatch);
        }

        let expected = assemble_record(&facts);
        if self.bytes != expected {
            return Err(BsmsErrorV2::DescriptorRoundTripMismatch);
        }
        if reopened != self.bytes {
            return Err(BsmsErrorV2::InvalidRecordEncoding);
        }
        Ok(())
    }
}

/// Minimal private copy of the public v2 facts needed to rebind reopened bytes.
///
/// Account xpub copies and the A1 capsule deliberately never enter this owner.
pub(crate) struct BsmsBindingV2 {
    descriptors: [[u8; DESCRIPTOR_BYTES]; 2],
    wallet_id: [u8; 32],
    first_scripts: [[u8; SCRIPT_PUBKEY_BYTES]; 2],
    first_addresses: [[u8; ADDRESS_BYTES]; 2],
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

/// Copy only the required public binding facts and build their exact v2 record.
pub(crate) fn bind_and_build_record_v2(
    artifacts: &ProvisioningArtifactsV2,
) -> Result<(BsmsBindingV2, BsmsRecordV2), BsmsErrorV2> {
    let binding = BsmsBindingV2 {
        descriptors: artifacts.descriptors,
        wallet_id: artifacts.wallet_id,
        first_scripts: artifacts.first_scripts,
        first_addresses: artifacts.first_addresses,
    };
    let facts = validate_binding(&binding)?;
    verify_descriptor_round_trip(
        &facts.multipath_descriptor,
        &binding.descriptors[0],
        &binding.descriptors[1],
    )?;
    let bytes = assemble_record(&facts);
    let record = BsmsRecordV2 {
        bytes,
        receive_address: facts.receive_address,
        change_address: facts.change_address,
    };
    record.verify_reopened(&bytes, &binding)?;
    Ok((binding, record))
}

fn validate_binding(binding: &BsmsBindingV2) -> Result<ValidatedFacts, BsmsErrorV2> {
    let receive = &binding.descriptors[0];
    let change = &binding.descriptors[1];
    let pair = parse_descriptor_pair_v2(receive, change)
        .map_err(|_| BsmsErrorV2::InvalidDescriptorPair)?;
    if pair.wallet_id() != binding.wallet_id {
        return Err(BsmsErrorV2::WalletIdMismatch);
    }

    let receive_script =
        derive_receive_script_v2(&pair, 0).map_err(|_| BsmsErrorV2::InvalidDescriptorPair)?;
    let change_script =
        derive_change_script_v2(&pair, 0).map_err(|_| BsmsErrorV2::InvalidDescriptorPair)?;
    if receive_script.script_pubkey != binding.first_scripts[0]
        || change_script.script_pubkey != binding.first_scripts[1]
    {
        return Err(BsmsErrorV2::FirstScriptMismatch);
    }

    let receive_address = address_for_script(&receive_script.script_pubkey)?;
    let change_address = address_for_script(&change_script.script_pubkey)?;
    if receive_address != binding.first_addresses[0] || change_address != binding.first_addresses[1]
    {
        return Err(BsmsErrorV2::FirstAddressMismatch);
    }

    let multipath_descriptor = build_multipath_descriptor(receive, change)?;
    Ok(ValidatedFacts {
        multipath_descriptor,
        receive_address,
        change_address,
    })
}

fn assemble_record(facts: &ValidatedFacts) -> [u8; BSMS_RECORD_BYTES_V2] {
    let mut output = [0u8; BSMS_RECORD_BYTES_V2];
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

fn parse_record(input: &[u8]) -> Result<RecordLines<'_>, BsmsErrorV2> {
    if input.len() != BSMS_RECORD_BYTES_V2 {
        return Err(BsmsErrorV2::InvalidRecordLength);
    }
    if input
        .iter()
        .any(|&byte| byte != b'\n' && !(0x20..=0x7e).contains(&byte))
    {
        return Err(BsmsErrorV2::InvalidRecordEncoding);
    }

    let mut lines = [&input[..0]; 4];
    let mut count = 0usize;
    let mut start = 0usize;
    for (position, &byte) in input.iter().enumerate() {
        if byte == b'\n' {
            if count == lines.len() {
                return Err(BsmsErrorV2::InvalidRecordEncoding);
            }
            lines[count] = &input[start..position];
            count += 1;
            start = position + 1;
        }
    }
    if count != lines.len() || start != input.len() || lines.iter().any(|line| line.is_empty()) {
        return Err(BsmsErrorV2::InvalidRecordEncoding);
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
) -> Result<[u8; MULTIPATH_DESCRIPTOR_BYTES], BsmsErrorV2> {
    let mut output = [0u8; MULTIPATH_DESCRIPTOR_BYTES];
    let mut source = 0usize;
    let mut destination = 0usize;
    for &position in &BRANCH_POSITIONS {
        if receive[position] != b'0' || change[position] != b'1' {
            return Err(BsmsErrorV2::DescriptorRoundTripMismatch);
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
        return Err(BsmsErrorV2::DescriptorRoundTripMismatch);
    }
    output[MULTIPATH_BODY_BYTES] = b'#';
    let checksum = descriptor_checksum(&output[..MULTIPATH_BODY_BYTES])
        .ok_or(BsmsErrorV2::DescriptorRoundTripMismatch)?;
    output[MULTIPATH_BODY_BYTES + 1..].copy_from_slice(&checksum);
    Ok(output)
}

fn verify_descriptor_round_trip(
    candidate: &[u8],
    receive: &[u8; DESCRIPTOR_BYTES],
    change: &[u8; DESCRIPTOR_BYTES],
) -> Result<(), BsmsErrorV2> {
    if !descriptor_line_is_encoded(candidate) {
        return Err(BsmsErrorV2::DescriptorRoundTripMismatch);
    }
    let expanded_receive = expand_multipath_descriptor(candidate, b'0')?;
    let expanded_change = expand_multipath_descriptor(candidate, b'1')?;
    if expanded_receive != *receive || expanded_change != *change {
        return Err(BsmsErrorV2::DescriptorRoundTripMismatch);
    }
    parse_descriptor_pair_v2(&expanded_receive, &expanded_change)
        .map_err(|_| BsmsErrorV2::DescriptorRoundTripMismatch)?;
    Ok(())
}

fn expand_multipath_descriptor(
    candidate: &[u8],
    branch: u8,
) -> Result<[u8; DESCRIPTOR_BYTES], BsmsErrorV2> {
    if candidate.len() != MULTIPATH_DESCRIPTOR_BYTES || (branch != b'0' && branch != b'1') {
        return Err(BsmsErrorV2::DescriptorRoundTripMismatch);
    }
    let mut output = [0u8; DESCRIPTOR_BYTES];
    let mut source = 0usize;
    let mut destination = 0usize;
    for &position in &MULTIPATH_POSITIONS {
        if candidate.get(position..position + MULTIPATH.len()) != Some(MULTIPATH) {
            return Err(BsmsErrorV2::DescriptorRoundTripMismatch);
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
        return Err(BsmsErrorV2::DescriptorRoundTripMismatch);
    }
    output[DESCRIPTOR_BODY_BYTES] = b'#';
    let checksum = descriptor_checksum(&output[..DESCRIPTOR_BODY_BYTES])
        .ok_or(BsmsErrorV2::DescriptorRoundTripMismatch)?;
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
) -> Result<[u8; ADDRESS_BYTES], BsmsErrorV2> {
    if script_pubkey[..2] != [0x00, 0x20] {
        return Err(BsmsErrorV2::FirstScriptMismatch);
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
        let body = b"wsh(sortedmulti(2,[2fae9711/48'/0'/0'/2']xpub6E4Ac9VDE5KxfwbtXAkZacVZ3XmbMo32suyVgt2mgn8mAZbyUuNEDXuZu9D396UYikuXXJ4tFkxE89fHNboRyNzfMzG2sph4V2MuourfoYr/<0;1>/*,[72a14ab8/48'/0'/0'/2']xpub6ETbdARx7dNLzy6RiMBLWHkr39b2KhiWsu1h3RQBp5DT79KCU5b5vhL2RfbEmVf4aW6yi8hQPkY8cNxBpjAS7USKboAguDQR8CRPgctyufF/<0;1>/*))";
        assert_eq!(body.len() + 9, MULTIPATH_DESCRIPTOR_BYTES);
        let checksum = descriptor_checksum(body).expect("BIP380 charset");
        assert_eq!(&checksum, b"vnpen3f9");
        assert!(descriptor_checksum_matches(body, &checksum));
    }

    #[test]
    fn mainnet_p2wsh_encoder_matches_registered_v2_receive_zero() {
        let program = [
            0x4f, 0x20, 0x24, 0x80, 0xa9, 0x91, 0x03, 0x47, 0x42, 0xec, 0xc4, 0xba, 0x29, 0x04,
            0x91, 0x34, 0xbc, 0xd5, 0xfb, 0x79, 0xc5, 0x6b, 0xfc, 0x50, 0x22, 0x89, 0xde, 0x3e,
            0x7e, 0x0b, 0xa1, 0x04,
        ];
        assert_eq!(
            &encode_mainnet_p2wsh(&program),
            b"bc1qfuszfq9fjyp5wshvcjazjpy3xj7dt7mec44lc5pz380rulst5yzqq9yjge"
        );
    }
}
