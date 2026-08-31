//! Independent ingress-only QK-DEC-144 peer grammar.

use crate::error::{CoreError, IoRejection};
use crate::{INNER_HEADER_BYTES, INNER_VERSION, MAX_CHUNK_BYTES, MAX_INGRESS_BYTES};

const INGRESS_BEGIN_BODY_BYTES: usize = 3;
const INGRESS_READ_BODY_BYTES: usize = 4;
const INGRESS_BEGIN_RESPONSE_BYTES: usize = 5;
const INGRESS_READ_PREFIX_BYTES: usize = 9;
const MAX_INNER_BODY_BYTES: usize = 2_097_144;
const MAX_INGRESS_BYTES_U32: u32 = 2_097_152;

/// Exact ingress operation byte.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Operation {
    IngressBegin,
    IngressRead,
}

impl Operation {
    /// Exact QK-DEC-144 opcode.
    pub const fn wire_value(self) -> u8 {
        match self {
            Self::IngressBegin => 0x01,
            Self::IngressRead => 0x02,
        }
    }
}

/// Exact hostile input-source tag.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Source {
    CameraA1Candidate,
    CameraKitCandidate,
    CameraBbqrPsbt,
    MediaPsbt,
}

impl Source {
    /// Exact QK-DEC-144 source byte.
    pub const fn wire_value(self) -> u8 {
        match self {
            Self::CameraA1Candidate => 0x01,
            Self::CameraKitCandidate => 0x02,
            Self::CameraBbqrPsbt => 0x03,
            Self::MediaPsbt => 0x04,
        }
    }

    const fn parse(value: u8) -> Result<Self, CoreError> {
        match value {
            0x01 => Ok(Self::CameraA1Candidate),
            0x02 => Ok(Self::CameraKitCandidate),
            0x03 => Ok(Self::CameraBbqrPsbt),
            0x04 => Ok(Self::MediaPsbt),
            _ => Err(CoreError::ResponseSourceOutOfRange),
        }
    }

    const fn valid_total(self, total_len: u32) -> bool {
        match self {
            Self::CameraA1Candidate => total_len == 67,
            Self::CameraKitCandidate => total_len == 142,
            Self::CameraBbqrPsbt => total_len >= 1 && total_len <= 262_144,
            Self::MediaPsbt => total_len >= 1 && total_len <= 2_097_152,
        }
    }
}

/// Exact metadata retained for the one outstanding operation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ExpectedResponse {
    IngressBegin {
        source: Source,
    },
    IngressRead {
        expected_offset: u32,
        total_len: u32,
    },
}

impl ExpectedResponse {
    /// Exact operation whose byte must be echoed by the peer.
    pub const fn operation(self) -> Operation {
        match self {
            Self::IngressBegin { .. } => Operation::IngressBegin,
            Self::IngressRead { .. } => Operation::IngressRead,
        }
    }
}

/// One borrowed successful peer response.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Response<'a> {
    IngressBegin {
        source: Source,
        total_len: u32,
    },
    IngressRead {
        offset: u32,
        final_chunk: bool,
        chunk: &'a [u8],
    },
}

/// Form the sole canonical IngressBegin request in a caller-owned fixed buffer.
pub fn encode_ingress_begin(source: Source) -> [u8; 11] {
    [
        INNER_VERSION,
        Operation::IngressBegin.wire_value(),
        0,
        0,
        3,
        0,
        0,
        0,
        source.wire_value(),
        0,
        0,
    ]
}

/// Form the sole canonical IngressRead request in a caller-owned fixed buffer.
pub fn encode_ingress_read(expected_offset: u32) -> [u8; 12] {
    let [offset_0, offset_1, offset_2, offset_3] = expected_offset.to_le_bytes();
    [
        INNER_VERSION,
        Operation::IngressRead.wire_value(),
        0,
        0,
        4,
        0,
        0,
        0,
        offset_0,
        offset_1,
        offset_2,
        offset_3,
    ]
}

/// Parse exactly one complete hostile peer response for the outstanding request.
pub fn parse_response<'a>(
    bytes: &'a [u8],
    expected: ExpectedResponse,
) -> Result<Response<'a>, CoreError> {
    if bytes.len() < INNER_HEADER_BYTES {
        return Err(CoreError::ResponseHeaderTruncated);
    }
    if byte_at(bytes, 0)? != INNER_VERSION {
        return Err(CoreError::ResponseVersionMismatch);
    }
    if byte_at(bytes, 1)? != expected.operation().wire_value() {
        return Err(CoreError::ResponseOpcodeMismatch);
    }

    let status = read_u16(bytes, 2)?;
    let body_len =
        usize::try_from(read_u32(bytes, 4)?).map_err(|_| CoreError::ResponseBodyLengthExceeded)?;
    if body_len > MAX_INNER_BODY_BYTES {
        return Err(CoreError::ResponseBodyLengthExceeded);
    }
    let complete_len = INNER_HEADER_BYTES
        .checked_add(body_len)
        .ok_or(CoreError::ResponseBodyLengthExceeded)?;
    if bytes.len() < complete_len {
        return Err(CoreError::ResponseBodyTruncated);
    }
    if bytes.len() > complete_len {
        return Err(CoreError::ResponseTrailingByte);
    }
    let body = bytes
        .get(INNER_HEADER_BYTES..complete_len)
        .ok_or(CoreError::ResponseBodyTruncated)?;

    if status != 0 {
        let rejection =
            IoRejection::from_status(status).ok_or(CoreError::ResponseStatusOutOfRange)?;
        if !body.is_empty() {
            return Err(CoreError::ResponseErrorBodyNonEmpty);
        }
        return Err(CoreError::IoRejected(rejection));
    }

    match expected {
        ExpectedResponse::IngressBegin { source } => parse_begin_success(body, source),
        ExpectedResponse::IngressRead {
            expected_offset,
            total_len,
        } => parse_read_success(body, expected_offset, total_len),
    }
}

fn parse_begin_success(body: &[u8], expected_source: Source) -> Result<Response<'_>, CoreError> {
    require_exact(body, INGRESS_BEGIN_RESPONSE_BYTES)?;
    let source = Source::parse(byte_at(body, 0)?)?;
    if source != expected_source {
        return Err(CoreError::ResponseSourceMismatch);
    }
    let total_len = read_u32(body, 1)?;
    if !source.valid_total(total_len) {
        return Err(CoreError::ResponseTotalLengthMismatch);
    }
    Ok(Response::IngressBegin { source, total_len })
}

fn parse_read_success<'a>(
    body: &'a [u8],
    expected_offset: u32,
    total_len: u32,
) -> Result<Response<'a>, CoreError> {
    if body.len() < INGRESS_READ_PREFIX_BYTES {
        return Err(CoreError::ResponseBodyTruncated);
    }
    let offset = read_u32(body, 0)?;
    let chunk_len_u32 = read_u32(body, 4)?;
    let chunk_len =
        usize::try_from(chunk_len_u32).map_err(|_| CoreError::ResponseChunkLengthExceeded)?;
    let complete_len = INGRESS_READ_PREFIX_BYTES
        .checked_add(chunk_len)
        .ok_or(CoreError::ResponseBodyLengthExceeded)?;
    if body.len() < complete_len {
        return Err(CoreError::ResponseBodyTruncated);
    }
    if body.len() > complete_len {
        return Err(CoreError::ResponseTrailingByte);
    }
    if offset != expected_offset {
        return Err(CoreError::ResponseOffsetMismatch);
    }
    if chunk_len == 0 {
        return Err(CoreError::ResponseChunkLengthZero);
    }
    if chunk_len > MAX_CHUNK_BYTES {
        return Err(CoreError::ResponseChunkLengthExceeded);
    }
    let end = offset
        .checked_add(chunk_len_u32)
        .ok_or(CoreError::ResponseTransferLengthExceeded)?;
    if end > total_len || total_len > MAX_INGRESS_BYTES_U32 {
        return Err(CoreError::ResponseTransferLengthExceeded);
    }
    let final_byte = byte_at(body, 8)?;
    let final_chunk = match final_byte {
        0 => false,
        1 => true,
        _ => return Err(CoreError::ResponseFinalOutOfRange),
    };
    if final_chunk != (end == total_len) {
        return Err(CoreError::ResponseFinalMismatch);
    }
    let chunk = body
        .get(INGRESS_READ_PREFIX_BYTES..complete_len)
        .ok_or(CoreError::ResponseBodyTruncated)?;
    Ok(Response::IngressRead {
        offset,
        final_chunk,
        chunk,
    })
}

fn require_exact(bytes: &[u8], expected: usize) -> Result<(), CoreError> {
    if bytes.len() < expected {
        Err(CoreError::ResponseBodyTruncated)
    } else if bytes.len() > expected {
        Err(CoreError::ResponseTrailingByte)
    } else {
        Ok(())
    }
}

fn byte_at(bytes: &[u8], offset: usize) -> Result<u8, CoreError> {
    bytes
        .get(offset)
        .copied()
        .ok_or(CoreError::ResponseBodyTruncated)
}

fn read_u16(bytes: &[u8], offset: usize) -> Result<u16, CoreError> {
    let end = offset
        .checked_add(2)
        .ok_or(CoreError::ResponseBodyTruncated)?;
    let raw: &[u8; 2] = bytes
        .get(offset..end)
        .ok_or(CoreError::ResponseBodyTruncated)?
        .try_into()
        .map_err(|_| CoreError::ResponseBodyTruncated)?;
    Ok(u16::from_le_bytes(*raw))
}

fn read_u32(bytes: &[u8], offset: usize) -> Result<u32, CoreError> {
    let end = offset
        .checked_add(4)
        .ok_or(CoreError::ResponseBodyTruncated)?;
    let raw: &[u8; 4] = bytes
        .get(offset..end)
        .ok_or(CoreError::ResponseBodyTruncated)?
        .try_into()
        .map_err(|_| CoreError::ResponseBodyTruncated)?;
    Ok(u32::from_le_bytes(*raw))
}

const _: () = assert!(INGRESS_BEGIN_BODY_BYTES == 3);
const _: () = assert!(INGRESS_READ_BODY_BYTES == 4);
const _: () = assert!(MAX_INNER_BODY_BYTES == 2_097_144);
const _: () = assert!(MAX_INGRESS_BYTES == 2_097_152);

#[cfg(test)]
mod tests {
    use super::*;

    fn success(opcode: u8, body: &[u8]) -> Vec<u8> {
        let mut output = vec![INNER_VERSION, opcode, 0, 0];
        output.extend_from_slice(&(body.len() as u32).to_le_bytes());
        output.extend_from_slice(body);
        output
    }

    #[test]
    fn request_bytes_are_exact() {
        assert_eq!(
            encode_ingress_begin(Source::CameraKitCandidate),
            [1, 1, 0, 0, 3, 0, 0, 0, 2, 0, 0]
        );
        assert_eq!(
            encode_ingress_read(0x4433_2211),
            [1, 2, 0, 0, 4, 0, 0, 0, 0x11, 0x22, 0x33, 0x44]
        );
    }

    #[test]
    fn all_seventy_one_rejections_round_trip() {
        let mut count = 0usize;
        for status in 1u16..=0x011e {
            let Some(rejection) = IoRejection::from_status(status) else {
                continue;
            };
            count = count.checked_add(1).unwrap_or(usize::MAX);
            assert_eq!(rejection.status_code(), status);
            let [status_0, status_1] = status.to_le_bytes();
            let response = [1, 1, status_0, status_1, 0, 0, 0, 0];
            assert_eq!(
                parse_response(
                    &response,
                    ExpectedResponse::IngressBegin {
                        source: Source::CameraA1Candidate,
                    }
                ),
                Err(CoreError::IoRejected(rejection))
            );
        }
        assert_eq!(count, 71);
    }

    #[test]
    fn successful_chunks_require_exact_offset_and_finality() {
        let mut body = vec![0, 0, 0, 0, 3, 0, 0, 0, 1];
        body.extend_from_slice(&[0xaa, 0xbb, 0xcc]);
        let response = success(2, &body);
        assert_eq!(
            parse_response(
                &response,
                ExpectedResponse::IngressRead {
                    expected_offset: 0,
                    total_len: 3,
                }
            ),
            Ok(Response::IngressRead {
                offset: 0,
                final_chunk: true,
                chunk: &[0xaa, 0xbb, 0xcc],
            })
        );

        let mut nonfinal_body = vec![0, 0, 0, 0, 3, 0, 0, 0, 0];
        nonfinal_body.extend_from_slice(&[0xaa, 0xbb, 0xcc]);
        let response = success(2, &nonfinal_body);
        assert_eq!(
            parse_response(
                &response,
                ExpectedResponse::IngressRead {
                    expected_offset: 0,
                    total_len: 3,
                }
            ),
            Err(CoreError::ResponseFinalMismatch)
        );
    }
}
