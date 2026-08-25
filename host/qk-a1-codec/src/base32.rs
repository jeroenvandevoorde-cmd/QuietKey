//! Private MSB-first packing for the exact QK-DEC-090 alphabet.

const ALPHABET: &[u8; 32] = b"23456789abcdefghijkmnpqrstuvwxyz";

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum DecodeError {
    MalformedSymbol,
    NonCanonicalPadding,
}

fn value(symbol: u8) -> Option<u8> {
    ALPHABET
        .iter()
        .position(|candidate| *candidate == symbol)
        .map(|index| index as u8)
}

pub(crate) fn encode(bytes: &[u8], symbols_out: &mut [u8]) {
    debug_assert_eq!(symbols_out.len(), bytes.len().saturating_mul(8).div_ceil(5));
    let bit_len = bytes.len() * 8;
    for (symbol_index, symbol_out) in symbols_out.iter_mut().enumerate() {
        let mut symbol_value = 0u8;
        for symbol_bit in 0..5 {
            symbol_value <<= 1;
            let bit_index = symbol_index * 5 + symbol_bit;
            if bit_index < bit_len {
                symbol_value |= (bytes[bit_index / 8] >> (7 - bit_index % 8)) & 1;
            }
        }
        *symbol_out = ALPHABET[symbol_value as usize];
    }
}

pub(crate) fn decode(
    symbols: &[u8],
    erasure_mask: &[u8],
    bytes_out: &mut [u8],
    byte_erasures: &mut [bool],
) -> Result<(), DecodeError> {
    debug_assert_eq!(symbols.len(), erasure_mask.len());
    debug_assert_eq!(byte_erasures.len(), bytes_out.len());
    debug_assert_eq!(symbols.len(), bytes_out.len().saturating_mul(8).div_ceil(5));
    bytes_out.fill(0);
    byte_erasures.fill(false);
    let bit_len = bytes_out.len() * 8;

    for (symbol_index, (symbol, erased)) in symbols.iter().zip(erasure_mask.iter()).enumerate() {
        let first_bit = symbol_index * 5;
        let data_bits = core::cmp::min(5, bit_len - first_bit);
        if *erased == 1 {
            let first_byte = first_bit / 8;
            let last_byte = (first_bit + data_bits - 1) / 8;
            for byte_erased in &mut byte_erasures[first_byte..=last_byte] {
                *byte_erased = true;
            }
            continue;
        }

        let symbol_value = value(*symbol).ok_or(DecodeError::MalformedSymbol)?;
        let padding_bits = 5 - data_bits;
        if padding_bits != 0 && symbol_value & ((1u8 << padding_bits) - 1) != 0 {
            return Err(DecodeError::NonCanonicalPadding);
        }

        for symbol_bit in 0..data_bits {
            let bit_index = first_bit + symbol_bit;
            let bit = (symbol_value >> (4 - symbol_bit)) & 1;
            bytes_out[bit_index / 8] |= bit << (7 - bit_index % 8);
        }
    }

    for (byte, erased) in bytes_out.iter_mut().zip(byte_erasures.iter()) {
        if *erased {
            *byte = 0;
        }
    }
    Ok(())
}
