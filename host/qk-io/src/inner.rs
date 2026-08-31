//! Exact QK-DEC-143 operation-request grammar.

use crate::{InnerError, INNER_HEADER_BYTES, INNER_VERSION, MAX_INNER_BODY_BYTES};

/// Exact operation byte.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Operation {
    IngressBegin,
    IngressRead,
    EgressBegin,
    EgressWrite,
    EgressFinish,
}

impl Operation {
    pub const fn wire_value(self) -> u8 {
        match self {
            Self::IngressBegin => 0x01,
            Self::IngressRead => 0x02,
            Self::EgressBegin => 0x03,
            Self::EgressWrite => 0x04,
            Self::EgressFinish => 0x05,
        }
    }

    fn parse(value: u8) -> Result<Self, InnerError> {
        match value {
            0x01 => Ok(Self::IngressBegin),
            0x02 => Ok(Self::IngressRead),
            0x03 => Ok(Self::EgressBegin),
            0x04 => Ok(Self::EgressWrite),
            0x05 => Ok(Self::EgressFinish),
            _ => Err(InnerError::OperationOutOfRange),
        }
    }
}

/// Exact input-source tag.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Source {
    CameraA1Candidate,
    CameraKitCandidate,
    CameraBbqrPsbt,
    MediaPsbt,
}

impl Source {
    pub const fn wire_value(self) -> u8 {
        match self {
            Self::CameraA1Candidate => 0x01,
            Self::CameraKitCandidate => 0x02,
            Self::CameraBbqrPsbt => 0x03,
            Self::MediaPsbt => 0x04,
        }
    }

    fn parse(value: u8) -> Result<Self, InnerError> {
        match value {
            0x01 => Ok(Self::CameraA1Candidate),
            0x02 => Ok(Self::CameraKitCandidate),
            0x03 => Ok(Self::CameraBbqrPsbt),
            0x04 => Ok(Self::MediaPsbt),
            _ => Err(InnerError::SourceOutOfRange),
        }
    }
}

/// Exact output-sink tag.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Sink {
    Sd,
    Bbqr,
    Print,
}

impl Sink {
    pub const fn wire_value(self) -> u8 {
        match self {
            Self::Sd => 0x01,
            Self::Bbqr => 0x02,
            Self::Print => 0x03,
        }
    }

    fn parse(value: u8) -> Result<Self, InnerError> {
        match value {
            0x01 => Ok(Self::Sd),
            0x02 => Ok(Self::Bbqr),
            0x03 => Ok(Self::Print),
            _ => Err(InnerError::SinkOutOfRange),
        }
    }
}

/// Exact output-artifact tag.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Artifact {
    FinalizedPsbt,
    RawTransaction,
    WatchOnlyBsms,
    A1PrintArtifact,
    KitPrintArtifact,
}

impl Artifact {
    pub const fn wire_value(self) -> u8 {
        match self {
            Self::FinalizedPsbt => 0x01,
            Self::RawTransaction => 0x02,
            Self::WatchOnlyBsms => 0x03,
            Self::A1PrintArtifact => 0x04,
            Self::KitPrintArtifact => 0x05,
        }
    }

    fn parse(value: u8) -> Result<Self, InnerError> {
        match value {
            0x01 => Ok(Self::FinalizedPsbt),
            0x02 => Ok(Self::RawTransaction),
            0x03 => Ok(Self::WatchOnlyBsms),
            0x04 => Ok(Self::A1PrintArtifact),
            0x05 => Ok(Self::KitPrintArtifact),
            _ => Err(InnerError::ArtifactOutOfRange),
        }
    }
}

/// One borrowed, completely parsed operation request.
#[derive(Clone, Copy, Eq, PartialEq)]
pub enum Request<'a> {
    IngressBegin {
        source: Source,
        aux: &'a [u8],
    },
    IngressRead {
        expected_offset: u32,
    },
    EgressBegin {
        sink: Sink,
        artifact: Artifact,
        total_len: u32,
        aux: &'a [u8],
    },
    EgressWrite {
        offset: u32,
        chunk: &'a [u8],
    },
    EgressFinish,
}

impl Request<'_> {
    pub const fn operation(&self) -> Operation {
        match self {
            Self::IngressBegin { .. } => Operation::IngressBegin,
            Self::IngressRead { .. } => Operation::IngressRead,
            Self::EgressBegin { .. } => Operation::EgressBegin,
            Self::EgressWrite { .. } => Operation::EgressWrite,
            Self::EgressFinish => Operation::EgressFinish,
        }
    }
}

/// Parse exactly one complete QK-DEC-143 request body.
pub fn parse_request(bytes: &[u8]) -> Result<Request<'_>, InnerError> {
    if bytes.len() < INNER_HEADER_BYTES {
        return Err(InnerError::InnerHeaderTruncated);
    }
    if bytes[0] != INNER_VERSION {
        return Err(InnerError::InnerVersionMismatch);
    }
    if bytes[2] != 0 || bytes[3] != 0 {
        return Err(InnerError::RequestReservedNonZero);
    }
    let operation = Operation::parse(bytes[1])?;
    let body_len = read_u32(&bytes[4..8]) as usize;
    if body_len > MAX_INNER_BODY_BYTES {
        return Err(InnerError::BodyLengthExceeded);
    }
    let complete_len = INNER_HEADER_BYTES
        .checked_add(body_len)
        .ok_or(InnerError::BodyLengthExceeded)?;
    if bytes.len() < complete_len {
        return Err(InnerError::BodyTruncated);
    }
    if bytes.len() > complete_len {
        return Err(InnerError::TrailingByte);
    }
    let body = &bytes[INNER_HEADER_BYTES..];
    match operation {
        Operation::IngressBegin => parse_ingress_begin(body),
        Operation::IngressRead => {
            require_exact(body, 4)?;
            Ok(Request::IngressRead {
                expected_offset: read_u32(body),
            })
        }
        Operation::EgressBegin => parse_egress_begin(body),
        Operation::EgressWrite => parse_egress_write(body),
        Operation::EgressFinish => {
            require_exact(body, 0)?;
            Ok(Request::EgressFinish)
        }
    }
}

fn parse_ingress_begin(body: &[u8]) -> Result<Request<'_>, InnerError> {
    if body.len() < 3 {
        return Err(InnerError::BodyTruncated);
    }
    let source = Source::parse(body[0])?;
    let aux_len = usize::from(u16::from_le_bytes([body[1], body[2]]));
    let aux = exact_tail(body, 3, aux_len)?;
    Ok(Request::IngressBegin { source, aux })
}

fn parse_egress_begin(body: &[u8]) -> Result<Request<'_>, InnerError> {
    if body.len() < 8 {
        return Err(InnerError::BodyTruncated);
    }
    let sink = Sink::parse(body[0])?;
    let artifact = Artifact::parse(body[1])?;
    let total_len = read_u32(&body[2..6]);
    let aux_len = usize::from(u16::from_le_bytes([body[6], body[7]]));
    let aux = exact_tail(body, 8, aux_len)?;
    Ok(Request::EgressBegin {
        sink,
        artifact,
        total_len,
        aux,
    })
}

fn parse_egress_write(body: &[u8]) -> Result<Request<'_>, InnerError> {
    if body.len() < 8 {
        return Err(InnerError::BodyTruncated);
    }
    let offset = read_u32(&body[..4]);
    let chunk_len = read_u32(&body[4..8]) as usize;
    let chunk = exact_tail(body, 8, chunk_len)?;
    Ok(Request::EgressWrite { offset, chunk })
}

fn exact_tail(bytes: &[u8], start: usize, length: usize) -> Result<&[u8], InnerError> {
    let end = start
        .checked_add(length)
        .ok_or(InnerError::BodyLengthExceeded)?;
    if bytes.len() < end {
        return Err(InnerError::BodyTruncated);
    }
    if bytes.len() > end {
        return Err(InnerError::TrailingByte);
    }
    Ok(&bytes[start..end])
}

fn require_exact(bytes: &[u8], length: usize) -> Result<(), InnerError> {
    if bytes.len() < length {
        Err(InnerError::BodyTruncated)
    } else if bytes.len() > length {
        Err(InnerError::TrailingByte)
    } else {
        Ok(())
    }
}

fn read_u32(bytes: &[u8]) -> u32 {
    u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]])
}
