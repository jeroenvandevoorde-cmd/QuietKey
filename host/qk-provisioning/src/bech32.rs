//! Private BIP173 mainnet witness-version-0 P2WSH encoder.

use crate::ProvisioningError;

const HRP: &[u8] = b"bc";
const CHARSET: &[u8; 32] = b"qpzry9x8gf2tvdw0s3jn54khce6mua7l";
const DATA_SYMBOLS: usize = 53;
const ADDRESS_BYTES: usize = 62;

fn polymod_step(pre: u32) -> u32 {
    let high = pre >> 25;
    let mut value = (pre & 0x01ff_ffff) << 5;
    for (bit, generator) in [
        0x3b6a_57b2u32,
        0x2650_8e6d,
        0x1ea1_19fa,
        0x3d42_33dd,
        0x2a14_62b3,
    ]
    .iter()
    .enumerate()
    {
        if ((high >> bit) & 1) != 0 {
            value ^= generator;
        }
    }
    value
}

fn create_checksum(data: &[u8; DATA_SYMBOLS]) -> [u8; 6] {
    let mut state = 1u32;
    for &byte in HRP {
        state = polymod_step(state) ^ u32::from(byte >> 5);
    }
    state = polymod_step(state);
    for &byte in HRP {
        state = polymod_step(state) ^ u32::from(byte & 31);
    }
    for &symbol in data {
        state = polymod_step(state) ^ u32::from(symbol);
    }
    for _ in 0..6 {
        state = polymod_step(state);
    }
    state ^= 1;
    let mut output = [0u8; 6];
    for (position, slot) in output.iter_mut().enumerate() {
        *slot = ((state >> (5 * (5 - position))) & 31) as u8;
    }
    output
}

pub(crate) fn encode_p2wsh(program: &[u8; 32]) -> Result<[u8; ADDRESS_BYTES], ProvisioningError> {
    let mut data = [0u8; DATA_SYMBOLS];
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
    }
    if bits != 0 {
        data[output_position] = ((accumulator << (5 - bits)) & 31) as u8;
        output_position += 1;
    }
    if output_position != DATA_SYMBOLS {
        return Err(ProvisioningError::CryptographicInvariant);
    }
    let checksum = create_checksum(&data);
    let mut output = [0u8; ADDRESS_BYTES];
    output[..2].copy_from_slice(HRP);
    output[2] = b'1';
    for (slot, &symbol) in output[3..3 + DATA_SYMBOLS].iter_mut().zip(data.iter()) {
        *slot = CHARSET[usize::from(symbol)];
    }
    for (slot, &symbol) in output[3 + DATA_SYMBOLS..].iter_mut().zip(checksum.iter()) {
        *slot = CHARSET[usize::from(symbol)];
    }
    Ok(output)
}

#[cfg(test)]
mod tests {
    use super::encode_p2wsh;

    const FIXTURE: &str = include_str!("../tests/fixtures/bip173-mainnet-p2wsh.txt");

    fn decode_hex<const N: usize>(text: &str) -> [u8; N] {
        assert_eq!(text.len(), N * 2);
        let mut output = [0u8; N];
        for (slot, position) in output.iter_mut().zip((0..text.len()).step_by(2)) {
            *slot = u8::from_str_radix(&text[position..position + 2], 16).expect("fixture hex");
        }
        output
    }

    #[test]
    fn exact_two_bip173_cases_execute() {
        assert_eq!(FIXTURE.len(), 2_016);
        assert!(FIXTURE.ends_with('\n'));
        assert!(!FIXTURE.contains('\r'));
        let mut program: Option<[u8; 32]> = None;
        let mut address: Option<&str> = None;
        let mut executed = 0usize;
        for line in FIXTURE.lines().chain(core::iter::once("")) {
            if let Some(value) = line.strip_prefix("witness_program: ") {
                assert!(program.replace(decode_hex(value)).is_none());
            } else if let Some(value) = line.strip_prefix("address: ") {
                assert!(address.replace(value).is_none());
            } else if line.is_empty() && program.is_some() {
                let expected = address.take().expect("address follows program");
                let actual = encode_p2wsh(&program.take().expect("program")).expect("v0 P2WSH");
                assert_eq!(actual.as_slice(), expected.as_bytes());
                executed += 1;
            }
        }
        assert_eq!(executed, 2);
    }
}
