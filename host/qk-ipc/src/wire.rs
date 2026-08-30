//! Exact QKIP header and complete-frame codec.

use crate::{IpcError, HEADER_BYTES, MAGIC, MAX_FRAME_BYTES, MAX_PAYLOAD_BYTES, VERSION};

/// Exact endpoint direction byte.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Direction {
    CoreToIo,
    IoToCore,
}

impl Direction {
    /// Return the canonical direction byte.
    pub const fn wire_value(self) -> u8 {
        match self {
            Self::CoreToIo => 0x01,
            Self::IoToCore => 0x02,
        }
    }

    fn parse(value: u8) -> Result<Self, IpcError> {
        match value {
            0x01 => Ok(Self::CoreToIo),
            0x02 => Ok(Self::IoToCore),
            _ => Err(IpcError::DirectionOutOfRange),
        }
    }
}

/// Exact role-bound message kind.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum MessageKind {
    SessionOpen,
    OperationRequest,
    SessionClose,
    SessionReady,
    OperationResponse,
    SessionClosed,
}

impl MessageKind {
    /// Return the canonical little-endian kind value as an integer.
    pub const fn wire_value(self) -> u16 {
        match self {
            Self::SessionOpen => 0x0001,
            Self::OperationRequest => 0x0002,
            Self::SessionClose => 0x0003,
            Self::SessionReady => 0x0101,
            Self::OperationResponse => 0x0102,
            Self::SessionClosed => 0x0103,
        }
    }

    /// Return the only direction under which this kind is valid.
    pub const fn direction(self) -> Direction {
        match self {
            Self::SessionOpen | Self::OperationRequest | Self::SessionClose => Direction::CoreToIo,
            Self::SessionReady | Self::OperationResponse | Self::SessionClosed => {
                Direction::IoToCore
            }
        }
    }

    /// Return whether the kind requires a nonempty opaque payload.
    pub const fn requires_payload(self) -> bool {
        matches!(self, Self::OperationRequest | Self::OperationResponse)
    }

    fn parse(value: u16) -> Result<Self, IpcError> {
        match value {
            0x0001 => Ok(Self::SessionOpen),
            0x0002 => Ok(Self::OperationRequest),
            0x0003 => Ok(Self::SessionClose),
            0x0101 => Ok(Self::SessionReady),
            0x0102 => Ok(Self::OperationResponse),
            0x0103 => Ok(Self::SessionClosed),
            _ => Err(IpcError::KindOutOfRange),
        }
    }
}

/// Parsed immutable header facts.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct FrameHeader {
    direction: Direction,
    kind: MessageKind,
    pub(crate) session_id: [u8; 16],
    exchange_id: u32,
    payload_len: u32,
}

impl FrameHeader {
    /// Message direction.
    pub const fn direction(&self) -> Direction {
        self.direction
    }

    /// Role-bound message kind.
    pub const fn kind(&self) -> MessageKind {
        self.kind
    }

    /// Session identity bytes exactly as carried on the wire.
    pub const fn session_id(&self) -> &[u8; 16] {
        &self.session_id
    }

    /// Exchange identifier.
    pub const fn exchange_id(&self) -> u32 {
        self.exchange_id
    }

    /// Declared payload length.
    pub const fn payload_len(&self) -> u32 {
        self.payload_len
    }
}

/// One borrowed, completely parsed frame.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct FrameRef<'a> {
    header: FrameHeader,
    payload: &'a [u8],
}

impl<'a> FrameRef<'a> {
    /// Parsed immutable header facts.
    pub const fn header(&self) -> &FrameHeader {
        &self.header
    }

    /// Exact opaque payload bytes.
    pub const fn payload(&self) -> &'a [u8] {
        self.payload
    }
}

pub(crate) fn parse_header(bytes: &[u8; HEADER_BYTES]) -> Result<FrameHeader, IpcError> {
    if bytes[0..4] != MAGIC {
        return Err(IpcError::MagicMismatch);
    }
    if bytes[4] != VERSION {
        return Err(IpcError::VersionMismatch);
    }
    let direction = Direction::parse(bytes[5])?;
    let kind = MessageKind::parse(u16::from_le_bytes([bytes[6], bytes[7]]))?;
    if kind.direction() != direction {
        return Err(IpcError::DirectionKindMismatch);
    }

    let mut session_id = [0u8; 16];
    session_id.copy_from_slice(&bytes[8..24]);
    let exchange_id = u32::from_le_bytes([bytes[24], bytes[25], bytes[26], bytes[27]]);
    if exchange_id == 0 {
        return Err(IpcError::ExchangeIdZero);
    }
    let payload_len = u32::from_le_bytes([bytes[28], bytes[29], bytes[30], bytes[31]]);
    if payload_len as usize > MAX_PAYLOAD_BYTES {
        return Err(IpcError::PayloadLengthExceeded);
    }

    Ok(FrameHeader {
        direction,
        kind,
        session_id,
        exchange_id,
        payload_len,
    })
}

pub(crate) fn validate_payload_shape(
    kind: MessageKind,
    payload_len: usize,
) -> Result<(), IpcError> {
    if kind.requires_payload() {
        if payload_len == 0 {
            return Err(IpcError::OperationPayloadEmpty);
        }
    } else if payload_len != 0 {
        return Err(IpcError::ControlPayloadNotEmpty);
    }
    Ok(())
}

/// Parse exactly one complete frame with no trailing byte.
pub fn parse_frame(bytes: &[u8]) -> Result<FrameRef<'_>, IpcError> {
    let header_bytes: &[u8; HEADER_BYTES] = bytes
        .get(..HEADER_BYTES)
        .ok_or(IpcError::HeaderTruncated)?
        .try_into()
        .map_err(|_| IpcError::HeaderTruncated)?;
    let header = parse_header(header_bytes)?;
    let payload_len = header.payload_len as usize;
    let frame_len = HEADER_BYTES
        .checked_add(payload_len)
        .ok_or(IpcError::PayloadLengthExceeded)?;
    if bytes.len() < frame_len {
        return Err(IpcError::PayloadTruncated);
    }
    if bytes.len() > frame_len {
        return Err(IpcError::TrailingByte);
    }
    let payload = bytes
        .get(HEADER_BYTES..frame_len)
        .ok_or(IpcError::PayloadTruncated)?;
    validate_payload_shape(header.kind, payload.len())?;
    Ok(FrameRef { header, payload })
}

/// Encode one exact frame into a caller-owned output prefix.
///
/// The complete output remains unchanged on rejection. Bytes after the
/// returned prefix remain untouched on success.
pub fn encode_frame(
    direction: Direction,
    kind: MessageKind,
    session_id: [u8; 16],
    exchange_id: u32,
    payload: &[u8],
    output: &mut [u8],
) -> Result<usize, IpcError> {
    if kind.direction() != direction {
        return Err(IpcError::DirectionKindMismatch);
    }
    if exchange_id == 0 {
        return Err(IpcError::ExchangeIdZero);
    }
    if payload.len() > MAX_PAYLOAD_BYTES {
        return Err(IpcError::PayloadLengthExceeded);
    }
    validate_payload_shape(kind, payload.len())?;
    let frame_len = HEADER_BYTES
        .checked_add(payload.len())
        .ok_or(IpcError::PayloadLengthExceeded)?;
    if frame_len > MAX_FRAME_BYTES || output.len() < frame_len {
        return Err(IpcError::OutputBufferTooSmall);
    }

    let mut header = [0u8; HEADER_BYTES];
    header[0..4].copy_from_slice(&MAGIC);
    header[4] = VERSION;
    header[5] = direction.wire_value();
    header[6..8].copy_from_slice(&kind.wire_value().to_le_bytes());
    header[8..24].copy_from_slice(&session_id);
    header[24..28].copy_from_slice(&exchange_id.to_le_bytes());
    let payload_len = u32::try_from(payload.len()).map_err(|_| IpcError::PayloadLengthExceeded)?;
    header[28..32].copy_from_slice(&payload_len.to_le_bytes());

    output[..HEADER_BYTES].copy_from_slice(&header);
    output[HEADER_BYTES..frame_len].copy_from_slice(payload);
    Ok(frame_len)
}
