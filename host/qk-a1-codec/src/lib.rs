//! Fixed-memory HOST reference for the M18 A1 print-codec candidates.
//!
//! HOST REFERENCE ONLY -- NOT A READER -- NOT A PRODUCTION PROFILE --
//! NOT A WALLET -- NO TARGET OR GATE CLAIM.
//!
//! This crate strips and reconstructs only the exact fixed QK-DEC-089 header,
//! applies one explicitly selected QK-DEC-091 shortened Reed-Solomon profile,
//! and packs or unpacks the exact QK-DEC-090 lowercase alphabet. It performs
//! no allocation, I/O, OCR, normalization, authentication, rendering,
//! randomness, or profile selection. Capsule authentication remains solely in
//! qk-a1.

#![deny(unsafe_code)]

mod base32;
mod gf256;
mod reed_solomon;

const FIXED_HEADER: [u8; 7] = [0x51, 0x4b, 0x41, 0x31, 0x01, 0x01, 0x01];
const CAPSULE_LEN: usize = 67;
const BODY_LEN: usize = 60;
const MAX_CODEWORD_LEN: usize = 80;
const MAX_SYMBOL_COUNT: usize = 128;

/// One of the three M18 calibration profiles. There is deliberately no
/// default profile.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CodecProfile {
    Rs72_60,
    Rs76_60,
    Rs80_60,
}

impl CodecProfile {
    fn parity_count(self) -> usize {
        match self {
            Self::Rs72_60 => 12,
            Self::Rs76_60 => 16,
            Self::Rs80_60 => 20,
        }
    }

    fn codeword_len(self) -> usize {
        BODY_LEN + self.parity_count()
    }

    fn symbol_count(self) -> usize {
        match self {
            Self::Rs72_60 => 116,
            Self::Rs76_60 => 122,
            Self::Rs80_60 => 128,
        }
    }
}

/// Closed encode/decode failure surface in rejection precedence order.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CodecError {
    InvalidCapsuleHeader,
    InvalidSymbolCount,
    MalformedErasureRepresentation,
    MalformedSymbol,
    NonCanonicalPadding,
    OverCapacity,
    NoUniqueCodeword,
}

/// Exact correction facts from one successful bounded decode.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct DecodeReport {
    pub corrected_errors: u8,
    pub erased_bytes: u8,
}

/// Encodes one canonical QK-DEC-089 capsule under an explicitly selected
/// calibration profile.
///
/// `symbols_out` must have the profile's exact length: 116, 122, or 128
/// bytes. It remains unchanged on rejection.
pub fn encode(
    profile: CodecProfile,
    capsule: &[u8; CAPSULE_LEN],
    symbols_out: &mut [u8],
) -> Result<(), CodecError> {
    if capsule[..FIXED_HEADER.len()] != FIXED_HEADER {
        return Err(CodecError::InvalidCapsuleHeader);
    }
    if symbols_out.len() != profile.symbol_count() {
        return Err(CodecError::InvalidSymbolCount);
    }

    let codeword_len = profile.codeword_len();
    let mut codeword = [0u8; MAX_CODEWORD_LEN];
    reed_solomon::encode(
        &capsule[FIXED_HEADER.len()..],
        profile.parity_count(),
        &mut codeword[..codeword_len],
    );

    let mut candidate = [0u8; MAX_SYMBOL_COUNT];
    base32::encode(
        &codeword[..codeword_len],
        &mut candidate[..profile.symbol_count()],
    );
    symbols_out.copy_from_slice(&candidate[..profile.symbol_count()]);
    Ok(())
}

/// Corrects and reconstructs one canonical QK-DEC-089 capsule candidate.
///
/// `symbols` and `erasure_mask` must both have the profile's exact symbol
/// count. Each mask byte is exactly zero for a known symbol or one for an
/// explicit erasure; the byte stored at an erased position is ignored. The
/// output remains unchanged on every rejection. A successful result has not
/// been authenticated and must be passed once to qk-a1.
pub fn decode(
    profile: CodecProfile,
    symbols: &[u8],
    erasure_mask: &[u8],
    capsule_out: &mut [u8; CAPSULE_LEN],
) -> Result<DecodeReport, CodecError> {
    if symbols.len() != profile.symbol_count() {
        return Err(CodecError::InvalidSymbolCount);
    }
    if erasure_mask.len() != profile.symbol_count() || erasure_mask.iter().any(|marker| *marker > 1)
    {
        return Err(CodecError::MalformedErasureRepresentation);
    }

    let codeword_len = profile.codeword_len();
    let mut codeword = [0u8; MAX_CODEWORD_LEN];
    let mut byte_erasures = [false; MAX_CODEWORD_LEN];
    match base32::decode(
        symbols,
        erasure_mask,
        &mut codeword[..codeword_len],
        &mut byte_erasures[..codeword_len],
    ) {
        Ok(()) => {}
        Err(base32::DecodeError::MalformedSymbol) => {
            return Err(CodecError::MalformedSymbol);
        }
        Err(base32::DecodeError::NonCanonicalPadding) => {
            return Err(CodecError::NonCanonicalPadding);
        }
    }

    let erased_bytes = byte_erasures.iter().filter(|erased| **erased).count();
    if erased_bytes > profile.parity_count() {
        return Err(CodecError::OverCapacity);
    }

    let corrected_errors = match reed_solomon::decode(
        &mut codeword[..codeword_len],
        &byte_erasures[..codeword_len],
        profile.parity_count(),
    ) {
        Ok(count) => count,
        Err(reed_solomon::DecodeError::OverCapacity) => {
            return Err(CodecError::OverCapacity);
        }
        Err(reed_solomon::DecodeError::NoUniqueCodeword) => {
            return Err(CodecError::NoUniqueCodeword);
        }
    };

    let mut candidate = [0u8; CAPSULE_LEN];
    candidate[..FIXED_HEADER.len()].copy_from_slice(&FIXED_HEADER);
    candidate[FIXED_HEADER.len()..].copy_from_slice(&codeword[..BODY_LEN]);
    capsule_out.copy_from_slice(&candidate);
    Ok(DecodeReport {
        corrected_errors: corrected_errors as u8,
        erased_bytes: erased_bytes as u8,
    })
}
