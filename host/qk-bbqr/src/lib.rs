//! Bounded fixed-memory HOST reference for the QuietKey M22 BBQr v1 profile.
//!
//! HOST REFERENCE ONLY -- NOT A QR READER -- NOT A RENDERER -- NOT A WALLET --
//! NO TARGET, PERFORMANCE, OR GATE CLAIM.
//!
//! This crate implements only uncompressed Base32 (`2`) PSBT (`P`) and ready-
//! to-send transaction (`T`) frames. It performs no allocation, I/O, image
//! processing, normalization, compression, randomness, stream replacement, or
//! implicit QR sizing. The caller supplies the file type, non-final part size,
//! and every output buffer. The original M22 operations remain type-P wrappers.

#![deny(unsafe_code)]

mod base32;

use core::fmt;

const HEADER_LEN: usize = 8;
const ENCODING: u8 = b'2';

/// Maximum part count accepted by the M22 HOST profile.
pub const MAX_DECLARED_PARTS: usize = 256;
/// Maximum complete ASCII frame length, including the eight-byte header.
pub const MAX_FRAME_TEXT_BYTES: usize = 4_296;
/// Maximum unpadded Base32 body length.
pub const MAX_BODY_SYMBOLS: usize = 4_288;
/// Maximum bytes decoded from one frame body.
pub const MAX_PART_DECODED_BYTES: usize = 2_680;
/// Maximum reassembled payload length.
pub const MAX_TOTAL_DECODED_BYTES: usize = 262_144;
/// Absolute submission-work ceiling for one reassembler instance.
pub const MAX_SUBMISSIONS: usize = 512;

const _: () = assert!(HEADER_LEN + MAX_BODY_SYMBOLS == MAX_FRAME_TEXT_BYTES);
const _: () = assert!(MAX_BODY_SYMBOLS * 5 / 8 == MAX_PART_DECODED_BYTES);
const _: () = assert!(MAX_DECLARED_PARTS * 2 == MAX_SUBMISSIONS);

/// Closed M22 rejection surface, listed in stable category order.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum BbqrError {
    EmptyPayload,
    PayloadTooLarge,
    InvalidNonFinalPartLength,
    TooManyParts,
    PartIndexOutOfRange,
    FrameTooShort,
    FrameTooLarge,
    InvalidMagic,
    UnsupportedEncoding,
    UnsupportedFileType,
    InvalidDeclaredPartCount,
    DeclaredPartCountExceeded,
    InvalidPartIndex,
    EmptyPart,
    Base32PaddingForbidden,
    MalformedBase32Symbol,
    NonCanonicalBase32Length,
    NonCanonicalBase32Padding,
    NonFinalPartLengthNotMultipleOfFive,
    StreamEncodingMismatch,
    StreamFileTypeMismatch,
    StreamPartCountMismatch,
    NonUniformPartLength,
    FinalPartTooLarge,
    TotalDecodedSizeExceeded,
    ConflictingDuplicate,
    DuplicateWorkExceeded,
    SubmissionWorkExceeded,
    Incomplete,
    AlreadyComplete,
}

impl fmt::Display for BbqrError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::EmptyPayload => "EmptyPayload",
            Self::PayloadTooLarge => "PayloadTooLarge",
            Self::InvalidNonFinalPartLength => "InvalidNonFinalPartLength",
            Self::TooManyParts => "TooManyParts",
            Self::PartIndexOutOfRange => "PartIndexOutOfRange",
            Self::FrameTooShort => "FrameTooShort",
            Self::FrameTooLarge => "FrameTooLarge",
            Self::InvalidMagic => "InvalidMagic",
            Self::UnsupportedEncoding => "UnsupportedEncoding",
            Self::UnsupportedFileType => "UnsupportedFileType",
            Self::InvalidDeclaredPartCount => "InvalidDeclaredPartCount",
            Self::DeclaredPartCountExceeded => "DeclaredPartCountExceeded",
            Self::InvalidPartIndex => "InvalidPartIndex",
            Self::EmptyPart => "EmptyPart",
            Self::Base32PaddingForbidden => "Base32PaddingForbidden",
            Self::MalformedBase32Symbol => "MalformedBase32Symbol",
            Self::NonCanonicalBase32Length => "NonCanonicalBase32Length",
            Self::NonCanonicalBase32Padding => "NonCanonicalBase32Padding",
            Self::NonFinalPartLengthNotMultipleOfFive => "NonFinalPartLengthNotMultipleOfFive",
            Self::StreamEncodingMismatch => "StreamEncodingMismatch",
            Self::StreamFileTypeMismatch => "StreamFileTypeMismatch",
            Self::StreamPartCountMismatch => "StreamPartCountMismatch",
            Self::NonUniformPartLength => "NonUniformPartLength",
            Self::FinalPartTooLarge => "FinalPartTooLarge",
            Self::TotalDecodedSizeExceeded => "TotalDecodedSizeExceeded",
            Self::ConflictingDuplicate => "ConflictingDuplicate",
            Self::DuplicateWorkExceeded => "DuplicateWorkExceeded",
            Self::SubmissionWorkExceeded => "SubmissionWorkExceeded",
            Self::Incomplete => "Incomplete",
            Self::AlreadyComplete => "AlreadyComplete",
        })
    }
}

impl std::error::Error for BbqrError {}

/// Closed file-type selection for the ratified uncompressed Base32 profile.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum BbqrFileType {
    Psbt,
    Transaction,
}

impl BbqrFileType {
    const fn wire_byte(self) -> u8 {
        match self {
            Self::Psbt => b'P',
            Self::Transaction => b'T',
        }
    }
}

/// Metadata returned after one canonical frame is decoded.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct DecodedFrame {
    pub declared_parts: u16,
    pub part_index: u16,
    pub decoded_len: usize,
}

/// Bounded state facts returned after one accepted unique or identical frame.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ReassemblyProgress {
    pub declared_parts: u16,
    pub received_parts: u16,
    pub identical_duplicates: u16,
    pub submissions: u16,
    pub decoded_bytes: usize,
    pub was_duplicate: bool,
    pub complete: bool,
}

#[derive(Clone, Copy)]
struct FrameHeader {
    declared_parts: u16,
    part_index: u16,
}

/// Computes the exact number of parts for an explicit non-final decoded size.
pub fn encoded_part_count(payload_len: usize, non_final_part_len: usize) -> Result<u16, BbqrError> {
    if payload_len == 0 {
        return Err(BbqrError::EmptyPayload);
    }
    if payload_len > MAX_TOTAL_DECODED_BYTES {
        return Err(BbqrError::PayloadTooLarge);
    }
    if !(5..=MAX_PART_DECODED_BYTES).contains(&non_final_part_len)
        || !non_final_part_len.is_multiple_of(5)
    {
        return Err(BbqrError::InvalidNonFinalPartLength);
    }
    let part_count = payload_len.div_ceil(non_final_part_len);
    if part_count > MAX_DECLARED_PARTS {
        return Err(BbqrError::TooManyParts);
    }
    Ok(part_count as u16)
}

/// Encodes one canonical `B$2P` frame into the fixed caller buffer.
///
/// The entire output array remains unchanged on rejection. On success the
/// returned prefix length is the complete frame; bytes after it are untouched.
pub fn encode_frame(
    payload: &[u8],
    non_final_part_len: usize,
    part_index: u16,
    output: &mut [u8; MAX_FRAME_TEXT_BYTES],
) -> Result<usize, BbqrError> {
    encode_typed_frame(
        BbqrFileType::Psbt,
        payload,
        non_final_part_len,
        part_index,
        output,
    )
}

/// Encodes one canonical `B$2P` or `B$2T` frame into the fixed caller buffer.
///
/// The entire output array remains unchanged on rejection. On success the
/// returned prefix length is the complete frame; bytes after it are untouched.
pub fn encode_typed_frame(
    file_type: BbqrFileType,
    payload: &[u8],
    non_final_part_len: usize,
    part_index: u16,
    output: &mut [u8; MAX_FRAME_TEXT_BYTES],
) -> Result<usize, BbqrError> {
    let declared_parts = encoded_part_count(payload.len(), non_final_part_len)?;
    if part_index >= declared_parts {
        return Err(BbqrError::PartIndexOutOfRange);
    }

    let start = usize::from(part_index) * non_final_part_len;
    let end = payload.len().min(start + non_final_part_len);
    let part = &payload[start..end];
    let body_len = base32::encoded_len(part.len());
    debug_assert!(body_len <= MAX_BODY_SYMBOLS);

    let mut candidate = [0u8; MAX_FRAME_TEXT_BYTES];
    candidate[..3].copy_from_slice(b"B$2");
    candidate[3] = file_type.wire_byte();
    write_base36_pair(declared_parts, &mut candidate[4..6]);
    write_base36_pair(part_index, &mut candidate[6..8]);
    base32::encode(part, &mut candidate[HEADER_LEN..HEADER_LEN + body_len]);
    let frame_len = HEADER_LEN + body_len;
    output[..frame_len].copy_from_slice(&candidate[..frame_len]);
    Ok(frame_len)
}

/// Decodes one canonical standalone `B$2P` frame into the fixed caller buffer.
///
/// The entire output array remains unchanged on rejection. Standalone decoding
/// proves per-frame syntax and geometry; cross-frame equality is enforced only
/// by [`Reassembler`].
pub fn decode_frame(
    frame: &[u8],
    output: &mut [u8; MAX_PART_DECODED_BYTES],
) -> Result<DecodedFrame, BbqrError> {
    decode_typed_frame(BbqrFileType::Psbt, frame, output)
}

/// Decodes one canonical standalone frame of the caller-selected file type.
///
/// The entire output array remains unchanged on rejection. A different or
/// unsupported fresh-stream type returns [`BbqrError::UnsupportedFileType`].
pub fn decode_typed_frame(
    file_type: BbqrFileType,
    frame: &[u8],
    output: &mut [u8; MAX_PART_DECODED_BYTES],
) -> Result<DecodedFrame, BbqrError> {
    decode_frame_for_stream(frame, file_type, None, output)
}

/// One bounded candidate-stream reassembler. Dropping it and constructing a
/// new value is the only restart operation.
pub struct Reassembler<'a> {
    output: &'a mut [u8; MAX_TOTAL_DECODED_BYTES],
    file_type: BbqrFileType,
    received: [u64; 4],
    declared_parts: Option<u16>,
    non_final_part_len: Option<usize>,
    final_part_len: Option<usize>,
    pending_final: [u8; MAX_PART_DECODED_BYTES],
    pending_final_present: bool,
    received_parts: u16,
    identical_duplicates: u16,
    submissions: u16,
    decoded_bytes: usize,
    complete_len: Option<usize>,
}

impl<'a> Reassembler<'a> {
    /// Creates one empty stream over caller-owned fixed storage.
    pub fn new(output: &'a mut [u8; MAX_TOTAL_DECODED_BYTES]) -> Self {
        Self::new_typed(BbqrFileType::Psbt, output)
    }

    /// Creates one empty caller-selected stream over fixed storage.
    pub fn new_typed(
        file_type: BbqrFileType,
        output: &'a mut [u8; MAX_TOTAL_DECODED_BYTES],
    ) -> Self {
        Self {
            output,
            file_type,
            received: [0; 4],
            declared_parts: None,
            non_final_part_len: None,
            final_part_len: None,
            pending_final: [0; MAX_PART_DECODED_BYTES],
            pending_final_present: false,
            received_parts: 0,
            identical_duplicates: 0,
            submissions: 0,
            decoded_bytes: 0,
            complete_len: None,
        }
    }

    /// Examines one frame and advances the candidate stream at most once.
    ///
    /// Every examined call consumes one submission, including named
    /// rejections. A cap-rejected call and an `AlreadyComplete` call perform no
    /// further work and do not increase the counter.
    pub fn submit(&mut self, frame: &[u8]) -> Result<ReassemblyProgress, BbqrError> {
        if self.complete_len.is_some() {
            return Err(BbqrError::AlreadyComplete);
        }

        let submission_cap = self
            .declared_parts
            .map_or(MAX_SUBMISSIONS, |count| usize::from(count) * 2);
        if usize::from(self.submissions) >= submission_cap {
            return Err(BbqrError::SubmissionWorkExceeded);
        }
        self.submissions += 1;

        let mut part = [0u8; MAX_PART_DECODED_BYTES];
        let decoded =
            decode_frame_for_stream(frame, self.file_type, self.declared_parts, &mut part)?;
        if self.declared_parts.is_none()
            && usize::from(self.submissions) > usize::from(decoded.declared_parts) * 2
        {
            return Err(BbqrError::SubmissionWorkExceeded);
        }
        let part = &part[..decoded.decoded_len];

        if self.has_received(decoded.part_index) {
            if !self.stored_part_equals(decoded.part_index, part) {
                return Err(BbqrError::ConflictingDuplicate);
            }
            if self.identical_duplicates >= decoded.declared_parts {
                return Err(BbqrError::DuplicateWorkExceeded);
            }
            self.identical_duplicates += 1;
            return Ok(self.progress(true));
        }

        let is_final = decoded.part_index + 1 == decoded.declared_parts;
        let mut next_non_final_len = self.non_final_part_len;
        let mut next_final_len = self.final_part_len;
        if is_final {
            if let Some(non_final_len) = next_non_final_len {
                if decoded.decoded_len > non_final_len {
                    return Err(BbqrError::FinalPartTooLarge);
                }
                checked_total_len(decoded.declared_parts, non_final_len, decoded.decoded_len)?;
            } else if decoded.declared_parts > 1 {
                let minimum_non_final_len = decoded.decoded_len.max(5).div_ceil(5) * 5;
                checked_total_len(
                    decoded.declared_parts,
                    minimum_non_final_len,
                    decoded.decoded_len,
                )?;
            }
            next_final_len = Some(decoded.decoded_len);
        } else if let Some(non_final_len) = next_non_final_len {
            if decoded.decoded_len != non_final_len {
                return Err(BbqrError::NonUniformPartLength);
            }
        } else {
            next_non_final_len = Some(decoded.decoded_len);
            if let Some(final_len) = next_final_len {
                if final_len > decoded.decoded_len {
                    return Err(BbqrError::FinalPartTooLarge);
                }
                checked_total_len(decoded.declared_parts, decoded.decoded_len, final_len)?;
            } else {
                checked_minimum_total_len(decoded.declared_parts, decoded.decoded_len)?;
            }
        }

        let next_decoded_bytes = self
            .decoded_bytes
            .checked_add(decoded.decoded_len)
            .filter(|total| *total <= MAX_TOTAL_DECODED_BYTES)
            .ok_or(BbqrError::TotalDecodedSizeExceeded)?;

        if self.declared_parts.is_none() {
            self.declared_parts = Some(decoded.declared_parts);
        }
        self.non_final_part_len = next_non_final_len;
        self.final_part_len = next_final_len;

        if decoded.declared_parts == 1 {
            self.output[..decoded.decoded_len].copy_from_slice(part);
        } else if is_final {
            if let Some(non_final_len) = self.non_final_part_len {
                let offset = (usize::from(decoded.declared_parts) - 1) * non_final_len;
                self.output[offset..offset + decoded.decoded_len].copy_from_slice(part);
            } else {
                self.pending_final[..decoded.decoded_len].copy_from_slice(part);
                self.pending_final_present = true;
            }
        } else {
            let non_final_len = self
                .non_final_part_len
                .expect("validated non-final geometry is present");
            let offset = usize::from(decoded.part_index) * non_final_len;
            self.output[offset..offset + decoded.decoded_len].copy_from_slice(part);
            if self.pending_final_present {
                let final_len = self
                    .final_part_len
                    .expect("pending final length is present");
                let final_offset = (usize::from(decoded.declared_parts) - 1) * non_final_len;
                self.output[final_offset..final_offset + final_len]
                    .copy_from_slice(&self.pending_final[..final_len]);
                self.pending_final_present = false;
            }
        }

        self.mark_received(decoded.part_index);
        self.received_parts += 1;
        self.decoded_bytes = next_decoded_bytes;
        if self.received_parts == decoded.declared_parts {
            let complete_len = if decoded.declared_parts == 1 {
                self.final_part_len
                    .expect("single-frame payload is the final part")
            } else {
                checked_total_len(
                    decoded.declared_parts,
                    self.non_final_part_len
                        .expect("complete multi-frame geometry is present"),
                    self.final_part_len
                        .expect("complete multi-frame final part is present"),
                )?
            };
            debug_assert_eq!(complete_len, self.decoded_bytes);
            self.complete_len = Some(complete_len);
        }
        Ok(self.progress(false))
    }

    /// Returns the exact assembled payload only after complete index coverage.
    pub fn payload(&self) -> Result<&[u8], BbqrError> {
        let length = self.complete_len.ok_or(BbqrError::Incomplete)?;
        Ok(&self.output[..length])
    }

    fn progress(&self, was_duplicate: bool) -> ReassemblyProgress {
        ReassemblyProgress {
            declared_parts: self
                .declared_parts
                .expect("progress exists only for an established stream"),
            received_parts: self.received_parts,
            identical_duplicates: self.identical_duplicates,
            submissions: self.submissions,
            decoded_bytes: self.decoded_bytes,
            was_duplicate,
            complete: self.complete_len.is_some(),
        }
    }

    fn has_received(&self, index: u16) -> bool {
        let index = usize::from(index);
        self.received[index / 64] & (1u64 << (index % 64)) != 0
    }

    fn mark_received(&mut self, index: u16) {
        let index = usize::from(index);
        self.received[index / 64] |= 1u64 << (index % 64);
    }

    fn stored_part_equals(&self, index: u16, candidate: &[u8]) -> bool {
        let declared_parts = self
            .declared_parts
            .expect("received data has an established stream");
        let is_final = index + 1 == declared_parts;
        if is_final && self.pending_final_present {
            return self.final_part_len == Some(candidate.len())
                && self.pending_final[..candidate.len()] == *candidate;
        }
        let part_len = if is_final {
            match self.final_part_len {
                Some(length) if length == candidate.len() => length,
                _ => return false,
            }
        } else {
            match self.non_final_part_len {
                Some(length) if length == candidate.len() => length,
                _ => return false,
            }
        };
        let stride = self.non_final_part_len.unwrap_or(part_len);
        let offset = usize::from(index) * stride;
        self.output[offset..offset + part_len] == *candidate
    }
}

fn decode_frame_for_stream(
    frame: &[u8],
    expected_file_type: BbqrFileType,
    established_count: Option<u16>,
    output: &mut [u8; MAX_PART_DECODED_BYTES],
) -> Result<DecodedFrame, BbqrError> {
    let header = parse_header(frame, expected_file_type, established_count)?;
    let body = &frame[HEADER_LEN..];
    if body.is_empty() {
        return Err(BbqrError::EmptyPart);
    }
    if body.contains(&b'=') {
        return Err(BbqrError::Base32PaddingForbidden);
    }
    if body
        .iter()
        .any(|symbol| !matches!(*symbol, b'A'..=b'Z' | b'2'..=b'7'))
    {
        return Err(BbqrError::MalformedBase32Symbol);
    }
    let decoded_len = base32::decoded_len(body.len())?;
    debug_assert!(decoded_len <= MAX_PART_DECODED_BYTES);

    let mut candidate = [0u8; MAX_PART_DECODED_BYTES];
    base32::decode(body, &mut candidate[..decoded_len])?;
    if header.part_index + 1 < header.declared_parts && !decoded_len.is_multiple_of(5) {
        return Err(BbqrError::NonFinalPartLengthNotMultipleOfFive);
    }
    output[..decoded_len].copy_from_slice(&candidate[..decoded_len]);
    Ok(DecodedFrame {
        declared_parts: header.declared_parts,
        part_index: header.part_index,
        decoded_len,
    })
}

fn parse_header(
    frame: &[u8],
    expected_file_type: BbqrFileType,
    established_count: Option<u16>,
) -> Result<FrameHeader, BbqrError> {
    if frame.len() > MAX_FRAME_TEXT_BYTES {
        return Err(BbqrError::FrameTooLarge);
    }
    if frame.len() < HEADER_LEN {
        return Err(BbqrError::FrameTooShort);
    }
    if frame[..2] != *b"B$" {
        return Err(BbqrError::InvalidMagic);
    }

    if established_count.is_some() {
        if frame[2] != ENCODING {
            return Err(BbqrError::StreamEncodingMismatch);
        }
        if frame[3] != expected_file_type.wire_byte() {
            return Err(BbqrError::StreamFileTypeMismatch);
        }
    } else {
        if frame[2] != ENCODING {
            return Err(BbqrError::UnsupportedEncoding);
        }
        if frame[3] != expected_file_type.wire_byte() {
            return Err(BbqrError::UnsupportedFileType);
        }
    }

    let declared_parts =
        parse_base36_pair(&frame[4..6]).ok_or(BbqrError::InvalidDeclaredPartCount)?;
    if declared_parts == 0 {
        return Err(BbqrError::InvalidDeclaredPartCount);
    }
    if let Some(expected) = established_count {
        if declared_parts != expected {
            return Err(BbqrError::StreamPartCountMismatch);
        }
    } else if usize::from(declared_parts) > MAX_DECLARED_PARTS {
        return Err(BbqrError::DeclaredPartCountExceeded);
    }

    let part_index = parse_base36_pair(&frame[6..8]).ok_or(BbqrError::InvalidPartIndex)?;
    if part_index >= declared_parts {
        return Err(BbqrError::InvalidPartIndex);
    }
    Ok(FrameHeader {
        declared_parts,
        part_index,
    })
}

fn checked_minimum_total_len(
    declared_parts: u16,
    non_final_part_len: usize,
) -> Result<usize, BbqrError> {
    checked_total_len(declared_parts, non_final_part_len, 1)
}

fn checked_total_len(
    declared_parts: u16,
    non_final_part_len: usize,
    final_part_len: usize,
) -> Result<usize, BbqrError> {
    usize::from(declared_parts - 1)
        .checked_mul(non_final_part_len)
        .and_then(|prefix| prefix.checked_add(final_part_len))
        .filter(|total| *total <= MAX_TOTAL_DECODED_BYTES)
        .ok_or(BbqrError::TotalDecodedSizeExceeded)
}

fn parse_base36_pair(pair: &[u8]) -> Option<u16> {
    debug_assert_eq!(pair.len(), 2);
    let high = base36_digit(pair[0])?;
    let low = base36_digit(pair[1])?;
    Some(u16::from(high) * 36 + u16::from(low))
}

fn write_base36_pair(value: u16, output: &mut [u8]) {
    debug_assert_eq!(output.len(), 2);
    debug_assert!(value < 36 * 36);
    output[0] = base36_symbol((value / 36) as u8);
    output[1] = base36_symbol((value % 36) as u8);
}

fn base36_digit(symbol: u8) -> Option<u8> {
    match symbol {
        b'0'..=b'9' => Some(symbol - b'0'),
        b'A'..=b'Z' => Some(symbol - b'A' + 10),
        _ => None,
    }
}

fn base36_symbol(value: u8) -> u8 {
    match value {
        0..=9 => b'0' + value,
        10..=35 => b'A' + value - 10,
        _ => unreachable!("base36 value is checked by the caller"),
    }
}
