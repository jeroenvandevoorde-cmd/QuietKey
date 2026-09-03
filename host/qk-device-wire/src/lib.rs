//! Bounded QuietKey HOST mock-device wire and pure transfer state.
//!
//! HOST REFERENCE ONLY -- NOT A DEVICE DRIVER -- NO TARGET, HARDWARE,
//! PERFORMANCE, PRODUCTION, OR GATE CLAIM.
//!
//! The default surface performs no filesystem, process, socket, card, camera,
//! display, keypad, storage, randomness, logging, or persistence operation.

#![deny(unsafe_code)]

mod session;
mod stream;
#[allow(unsafe_code)]
mod wipe;
mod wire;

use core::fmt;

pub use session::{ExchangeProtocol, InputTransfer, OneWayProtocol, OutboundFrame, OutputTransfer};
pub use stream::{IngestOutcome, ReceivedFrame, StreamDecoder};
#[cfg(feature = "fuzzing")]
#[doc(hidden)]
pub use wipe::{reset_wiped_bytes, wiped_bytes};
pub use wire::{
    encode_frame, parse_body, parse_frame, Artifact, ArtifactFactRef, BodyRef, Capability,
    CardRequestBody, CardResponseBody, DeviceRejection, DirectRbf, DisplayBody, FrameHeader,
    FrameRef, InputBody, KeypadBody, LogicalKey, MessageKind, Network, NormalFactorRef,
    NormalStage, OutputBody, OutputReplyBody, Profile, ReceiptFact, RecipientOwnership,
    RecipientType, ResultBody, ReviewBody, Route, SignatureIter, SignatureRecordRef, Source,
    Warning,
};

/// Exact QK-DEC-156 frame magic.
pub const MAGIC: [u8; 4] = *b"QKDV";
/// Exact QK-DEC-156 wire version.
pub const VERSION: u8 = 1;
/// Exact fixed header length.
pub const HEADER_BYTES: usize = 16;
/// Absolute HOST body ceiling; narrower per-kind caps always prevail.
pub const MAX_BODY_BYTES: usize = 2_097_152;
/// Absolute HOST complete-frame ceiling.
pub const MAX_FRAME_BYTES: usize = HEADER_BYTES + MAX_BODY_BYTES;
/// Exact maximum device chunk.
pub const MAX_CHUNK_BYTES: usize = 262_144;
/// Exact maximum chunk body, including input final flag.
pub const MAX_CHUNK_BODY_BYTES: usize = 262_153;
/// Exact ratified output-begin cap.
pub const MAX_OUTPUT_BEGIN_BODY_BYTES: usize = 73;
/// Exact maximum display body.
pub const MAX_DISPLAY_BODY_BYTES: usize = 180;
/// Exact maximum keypad body.
pub const MAX_KEYPAD_BODY_BYTES: usize = 17;
/// Exact maximum card NormalFactor body cap.
pub const MAX_CARD_FACTOR_BODY_BYTES: usize = 11_790;
/// Exact raw proprietary APDU command cap.
pub const MAX_CARD_APDU_REQUEST_BODY_BYTES: usize = 221;
/// Exact raw proprietary APDU response-plus-status cap.
pub const MAX_CARD_APDU_RESPONSE_BODY_BYTES: usize = 218;
/// Exact maximum filename bytes.
pub const MAX_FILENAME_BYTES: usize = 64;

const _: () = assert!(HEADER_BYTES == 4 + 1 + 1 + 1 + 1 + 4 + 4);
const _: () = assert!(MAX_FRAME_BYTES == 2_097_168);
const _: () = assert!(MAX_CHUNK_BODY_BYTES == 4 + 4 + 1 + MAX_CHUNK_BYTES);

/// Closed QK-DEC-156 rejection vocabulary in ratified category order.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DeviceError {
    DecoderTerminated,
    HeaderTruncated,
    MagicMismatch,
    VersionMismatch,
    CapabilityOutOfRange,
    CapabilityMismatch,
    KindOutOfRange,
    CapabilityKindMismatch,
    ReservedNonZero,
    SequenceZero,
    SequenceReplay,
    SequenceRegression,
    SequenceSkipped,
    SequenceExhausted,
    OutstandingExchange,
    NoOutstandingExchange,
    ResponseSequenceMismatch,
    ResponseKindMismatch,
    BodyLengthExceeded,
    BodyTruncated,
    TrailingByte,
    UnexpectedFrame,
    ConnectionClosedMidFrame,
    PeerLost,
    OutputBufferTooSmall,
    AllocationFailed,
    BodyLengthMismatch,
    ValueOutOfRange,
    NestedLengthMismatch,
    CountExceeded,
    IndexOrderMismatch,
    OffsetMismatch,
    ChunkLengthZero,
    ChunkLengthExceeded,
    FinalFlagOutOfRange,
    FinalFlagMismatch,
    TransferLengthExceeded,
    TransferIncomplete,
    SourceMismatch,
    FilenameRejected,
    ArtifactMismatch,
    DeviceRejected,
    LegacyNormalFactorRejected,
}

impl DeviceError {
    /// Stable non-hostile rejection name.
    pub const fn name(self) -> &'static str {
        match self {
            Self::DecoderTerminated => "DecoderTerminated",
            Self::HeaderTruncated => "HeaderTruncated",
            Self::MagicMismatch => "MagicMismatch",
            Self::VersionMismatch => "VersionMismatch",
            Self::CapabilityOutOfRange => "CapabilityOutOfRange",
            Self::CapabilityMismatch => "CapabilityMismatch",
            Self::KindOutOfRange => "KindOutOfRange",
            Self::CapabilityKindMismatch => "CapabilityKindMismatch",
            Self::ReservedNonZero => "ReservedNonZero",
            Self::SequenceZero => "SequenceZero",
            Self::SequenceReplay => "SequenceReplay",
            Self::SequenceRegression => "SequenceRegression",
            Self::SequenceSkipped => "SequenceSkipped",
            Self::SequenceExhausted => "SequenceExhausted",
            Self::OutstandingExchange => "OutstandingExchange",
            Self::NoOutstandingExchange => "NoOutstandingExchange",
            Self::ResponseSequenceMismatch => "ResponseSequenceMismatch",
            Self::ResponseKindMismatch => "ResponseKindMismatch",
            Self::BodyLengthExceeded => "BodyLengthExceeded",
            Self::BodyTruncated => "BodyTruncated",
            Self::TrailingByte => "TrailingByte",
            Self::UnexpectedFrame => "UnexpectedFrame",
            Self::ConnectionClosedMidFrame => "ConnectionClosedMidFrame",
            Self::PeerLost => "PeerLost",
            Self::OutputBufferTooSmall => "OutputBufferTooSmall",
            Self::AllocationFailed => "AllocationFailed",
            Self::BodyLengthMismatch => "BodyLengthMismatch",
            Self::ValueOutOfRange => "ValueOutOfRange",
            Self::NestedLengthMismatch => "NestedLengthMismatch",
            Self::CountExceeded => "CountExceeded",
            Self::IndexOrderMismatch => "IndexOrderMismatch",
            Self::OffsetMismatch => "OffsetMismatch",
            Self::ChunkLengthZero => "ChunkLengthZero",
            Self::ChunkLengthExceeded => "ChunkLengthExceeded",
            Self::FinalFlagOutOfRange => "FinalFlagOutOfRange",
            Self::FinalFlagMismatch => "FinalFlagMismatch",
            Self::TransferLengthExceeded => "TransferLengthExceeded",
            Self::TransferIncomplete => "TransferIncomplete",
            Self::SourceMismatch => "SourceMismatch",
            Self::FilenameRejected => "FilenameRejected",
            Self::ArtifactMismatch => "ArtifactMismatch",
            Self::DeviceRejected => "DeviceRejected",
            Self::LegacyNormalFactorRejected => "LegacyNormalFactorRejected",
        }
    }
}

impl fmt::Display for DeviceError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.name())
    }
}

impl std::error::Error for DeviceError {}
