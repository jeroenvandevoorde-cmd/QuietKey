//! Bounded QuietKey process-IPC wire and endpoint-state reference.
//!
//! HOST REFERENCE ONLY -- NOT A SOCKET ADAPTER -- NOT A WALLET -- NO TARGET,
//! PRIVILEGE-ENFORCEMENT, PERFORMANCE, PRODUCTION, OR GATE CLAIM.
//!
//! This dependency-free leaf implements the QK-DEC-140 `QKIP` envelope and
//! pure protocol state. It performs no socket, filesystem, process, clock,
//! randomness, wallet, card, camera, display, signing, logging, or persistence
//! operation. A later supervisor-owned operating-system boundary must report
//! whether a receive carried ancillary data; this crate rejects that fact
//! before interpreting bytes.

#![deny(unsafe_code)]

mod session;
mod stream;
mod wipe;
mod wire;

use core::fmt;

pub use session::{CoreEvent, CoreProtocol, IoEvent, IoProtocol, OutboundFrame};
pub use stream::{IngestOutcome, ReceivedFrame, StreamDecoder};
#[cfg(feature = "fuzzing")]
#[doc(hidden)]
pub use wipe::{reset_wiped_bytes, wiped_bytes};
pub use wire::{encode_frame, parse_frame, Direction, FrameHeader, FrameRef, MessageKind};

/// Exact QK-DEC-140 frame magic.
pub const MAGIC: [u8; 4] = *b"QKIP";
/// Exact QK-DEC-140 wire version.
pub const VERSION: u8 = 1;
/// Exact fixed header length.
pub const HEADER_BYTES: usize = 32;
/// Conservative HOST-only payload ceiling.
pub const MAX_PAYLOAD_BYTES: usize = 2_097_152;
/// Conservative HOST-only complete-frame ceiling.
pub const MAX_FRAME_BYTES: usize = HEADER_BYTES + MAX_PAYLOAD_BYTES;

const _: () = assert!(HEADER_BYTES == 4 + 1 + 1 + 2 + 16 + 4 + 4);
const _: () = assert!(MAX_FRAME_BYTES == 2_097_184);

/// Closed QK-DEC-140 rejection vocabulary in fixed category order.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum IpcError {
    DecoderTerminated,
    SessionTerminated,
    AncillaryData,
    HeaderTruncated,
    MagicMismatch,
    VersionMismatch,
    DirectionOutOfRange,
    KindOutOfRange,
    DirectionKindMismatch,
    ExchangeIdZero,
    PayloadLengthExceeded,
    PayloadTruncated,
    TrailingByte,
    ControlPayloadNotEmpty,
    OperationPayloadEmpty,
    OutputBufferTooSmall,
    PayloadAllocationFailed,
    UnexpectedDirection,
    SessionIdMismatch,
    UnexpectedMessageKind,
    ExchangeIdReuse,
    ExchangeIdRegression,
    ExchangeIdSkipped,
    ExchangeIdExhausted,
    ResponseIdMismatch,
    OutstandingExchange,
    NoOutstandingExchange,
    SessionNotReady,
    SessionClosed,
    InvalidTransition,
    PeerLost,
    ConnectionClosedMidFrame,
}

impl fmt::Display for IpcError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::DecoderTerminated => "DecoderTerminated",
            Self::SessionTerminated => "SessionTerminated",
            Self::AncillaryData => "AncillaryData",
            Self::HeaderTruncated => "HeaderTruncated",
            Self::MagicMismatch => "MagicMismatch",
            Self::VersionMismatch => "VersionMismatch",
            Self::DirectionOutOfRange => "DirectionOutOfRange",
            Self::KindOutOfRange => "KindOutOfRange",
            Self::DirectionKindMismatch => "DirectionKindMismatch",
            Self::ExchangeIdZero => "ExchangeIdZero",
            Self::PayloadLengthExceeded => "PayloadLengthExceeded",
            Self::PayloadTruncated => "PayloadTruncated",
            Self::TrailingByte => "TrailingByte",
            Self::ControlPayloadNotEmpty => "ControlPayloadNotEmpty",
            Self::OperationPayloadEmpty => "OperationPayloadEmpty",
            Self::OutputBufferTooSmall => "OutputBufferTooSmall",
            Self::PayloadAllocationFailed => "PayloadAllocationFailed",
            Self::UnexpectedDirection => "UnexpectedDirection",
            Self::SessionIdMismatch => "SessionIdMismatch",
            Self::UnexpectedMessageKind => "UnexpectedMessageKind",
            Self::ExchangeIdReuse => "ExchangeIdReuse",
            Self::ExchangeIdRegression => "ExchangeIdRegression",
            Self::ExchangeIdSkipped => "ExchangeIdSkipped",
            Self::ExchangeIdExhausted => "ExchangeIdExhausted",
            Self::ResponseIdMismatch => "ResponseIdMismatch",
            Self::OutstandingExchange => "OutstandingExchange",
            Self::NoOutstandingExchange => "NoOutstandingExchange",
            Self::SessionNotReady => "SessionNotReady",
            Self::SessionClosed => "SessionClosed",
            Self::InvalidTransition => "InvalidTransition",
            Self::PeerLost => "PeerLost",
            Self::ConnectionClosedMidFrame => "ConnectionClosedMidFrame",
        })
    }
}

impl std::error::Error for IpcError {}
