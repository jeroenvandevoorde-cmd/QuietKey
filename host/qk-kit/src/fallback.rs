//! Exact fixed-memory QK-DEC-129 fallback packing.

use crate::secret::wipe;
use crate::{frame, FrameMetadata, KitError, FALLBACK_SYMBOLS, FRAME_LEN};

const ALPHABET: &[u8; 32] = b"23456789abcdefghijkmnpqrstuvwxyz";
const FRAME_BITS: usize = FRAME_LEN * 8;
const FALLBACK_BITS: usize = FALLBACK_SYMBOLS * 5;
const PAD_BITS: usize = FALLBACK_BITS - FRAME_BITS;

const _: () = assert!(FRAME_LEN == 142);
const _: () = assert!(FALLBACK_SYMBOLS == 228);
const _: () = assert!(PAD_BITS == 4);

fn symbol_value(symbol: u8) -> Option<u8> {
    ALPHABET
        .iter()
        .position(|candidate| *candidate == symbol)
        .map(|index| index as u8)
}

/// Packs one already-canonical frame MSB-first into the exact fallback
/// alphabet. The caller-owned output remains unchanged on rejection.
pub(crate) fn encode(
    frame_bytes: &[u8],
    output: &mut [u8; FALLBACK_SYMBOLS],
) -> Result<(), KitError> {
    frame::validate(frame_bytes)?;

    let mut candidate = [0u8; FALLBACK_SYMBOLS];
    for (symbol_index, symbol_out) in candidate.iter_mut().enumerate() {
        let mut value = 0u8;
        for symbol_bit in 0..5 {
            value <<= 1;
            let bit_index = symbol_index * 5 + symbol_bit;
            if bit_index < FRAME_BITS {
                value |= (frame_bytes[bit_index / 8] >> (7 - bit_index % 8)) & 1;
            }
        }
        *symbol_out = ALPHABET[value as usize];
    }

    output.copy_from_slice(&candidate);
    wipe(&mut candidate);
    Ok(())
}

/// Decodes one exact unseparated fallback token and validates the reconstructed
/// frame. Length, symbol, padding, and frame checks occur in that order. The
/// caller-owned output remains unchanged on every rejection.
pub(crate) fn decode(
    symbols: &[u8],
    output: &mut [u8; FRAME_LEN],
) -> Result<FrameMetadata, KitError> {
    if symbols.len() != FALLBACK_SYMBOLS {
        return Err(KitError::FallbackLength);
    }

    let mut candidate = [0u8; FRAME_LEN];
    let mut final_value = 0u8;
    for (symbol_index, symbol) in symbols.iter().enumerate() {
        let value = match symbol_value(*symbol) {
            Some(value) => value,
            None => {
                wipe(&mut candidate);
                return Err(KitError::MalformedSymbol);
            }
        };
        if symbol_index + 1 == FALLBACK_SYMBOLS {
            final_value = value;
        }

        for symbol_bit in 0..5 {
            let bit_index = symbol_index * 5 + symbol_bit;
            if bit_index >= FRAME_BITS {
                break;
            }
            let bit = (value >> (4 - symbol_bit)) & 1;
            candidate[bit_index / 8] |= bit << (7 - bit_index % 8);
        }
    }

    if final_value & ((1u8 << PAD_BITS) - 1) != 0 {
        wipe(&mut candidate);
        return Err(KitError::NonCanonicalPadding);
    }

    let validated = match frame::validate(&candidate) {
        Ok(validated) => validated,
        Err(error) => {
            wipe(&mut candidate);
            return Err(error);
        }
    };
    let metadata = validated.metadata();
    output.copy_from_slice(&candidate);
    wipe(&mut candidate);
    Ok(metadata)
}

/// Encode one canonical frame as an exact 228-symbol fallback token.
pub fn encode_fallback(
    frame_bytes: &[u8],
    output: &mut [u8; FALLBACK_SYMBOLS],
) -> Result<(), KitError> {
    encode(frame_bytes, output)
}

/// Decode and validate one exact 228-symbol fallback token.
pub fn decode_fallback(
    symbols: &[u8],
    output: &mut [u8; FRAME_LEN],
) -> Result<FrameMetadata, KitError> {
    decode(symbols, output)
}
