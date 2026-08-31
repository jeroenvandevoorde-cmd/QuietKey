//! HOST-only QuietKey no-secret transport-broker reference.
//!
//! This crate owns only bounded opaque transport bytes and the QK-DEC-143
//! inner protocol. Camera, removable-media, and print behavior are injected
//! mock boundaries. It contains no wallet, semantic-validation, card,
//! approval, signing, key, logging, persistence, or real device operation.

#![deny(unsafe_code)]

mod egress;
mod ingress;
mod inner;
mod mock;
mod session;
mod wipe;

use core::fmt;

pub use inner::{parse_request, Artifact, Operation, Request, Sink, Source};
pub use mock::{MockInput, MockOutputWriter, OutputFault};
pub use session::{BrokerError, BrokerReply, BrokerSession, BrokerState, ReplyStatus};
#[cfg(feature = "fuzzing")]
#[doc(hidden)]
pub use wipe::{reset_wiped_bytes, wiped_bytes};

/// Exact QK-DEC-143 inner-protocol version.
pub const INNER_VERSION: u8 = 1;
/// Exact request/response inner-header width.
pub const INNER_HEADER_BYTES: usize = 8;
/// Exact HOST-only transfer ceiling inherited from the QKIP payload scaffold.
pub const MAX_TRANSFER_BYTES: usize = 2_097_152;
/// Exact HOST-only deterministic transfer chunk.
pub const MAX_CHUNK_BYTES: usize = 262_144;
/// Exact HOST-only filename ceiling.
pub const MAX_FILENAME_BYTES: usize = 64;
/// Largest encoded HOST mock input record.
pub const MAX_MOCK_INPUT_BYTES: usize = MAX_TRANSFER_BYTES + MAX_FILENAME_BYTES + 5;
/// Exact already-extracted A1 capsule candidate width.
pub const A1_CANDIDATE_BYTES: usize = 67;
/// Exact canonical Kit-share candidate width.
pub const KIT_CANDIDATE_BYTES: usize = 142;
/// Largest inner body that can fit under one QKIP payload.
pub const MAX_INNER_BODY_BYTES: usize = qk_ipc::MAX_PAYLOAD_BYTES - INNER_HEADER_BYTES;

const _: () = assert!(MAX_TRANSFER_BYTES == qk_ipc::MAX_PAYLOAD_BYTES);
const _: () = assert!(MAX_TRANSFER_BYTES == MAX_CHUNK_BYTES * 8);
const _: () = assert!(MAX_INNER_BODY_BYTES == 2_097_144);

/// Closed inner-operation rejection surface in QK-DEC-143 order.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum InnerError {
    InnerHeaderTruncated,
    InnerVersionMismatch,
    RequestReservedNonZero,
    OperationOutOfRange,
    BodyLengthExceeded,
    BodyTruncated,
    TrailingByte,
    UnexpectedBoundary,
    BoundaryMissing,
    SourceKindMismatch,
    SourceAlreadyUsed,
    WriterKindMismatch,
    WriterAlreadyUsed,
    ActiveTransfer,
    NoActiveTransfer,
    WrongTransferDirection,
    SourceLengthMismatch,
    DeclaredLengthZero,
    DeclaredLengthExceeded,
    OffsetMismatch,
    ChunkLengthZero,
    ChunkLengthExceeded,
    TransferLengthExceeded,
    TransferIncomplete,
    SourceOutOfRange,
    SinkOutOfRange,
    ArtifactOutOfRange,
    SinkArtifactMismatch,
    InvalidFilename,
    InvalidBbqrPartLength,
    AllocationFailed,
    SourceReadFailed,
    OutputCollision,
    OutputCreateFailed,
    OutputWriteFailed,
    OutputSyncFailed,
    OutputCloseFailed,
    OutputReopenFailed,
    OutputReadbackMismatch,
    OutputRenameFailed,
    PrintFailed,
    Bbqr(qk_bbqr::BbqrError),
}

impl InnerError {
    /// Exact nonzero response status code.
    pub const fn status_code(self) -> u16 {
        match self {
            Self::InnerHeaderTruncated => 0x0001,
            Self::InnerVersionMismatch => 0x0002,
            Self::RequestReservedNonZero => 0x0003,
            Self::OperationOutOfRange => 0x0004,
            Self::BodyLengthExceeded => 0x0005,
            Self::BodyTruncated => 0x0006,
            Self::TrailingByte => 0x0007,
            Self::UnexpectedBoundary => 0x0008,
            Self::BoundaryMissing => 0x0009,
            Self::SourceKindMismatch => 0x000a,
            Self::SourceAlreadyUsed => 0x000b,
            Self::WriterKindMismatch => 0x000c,
            Self::WriterAlreadyUsed => 0x000d,
            Self::ActiveTransfer => 0x000e,
            Self::NoActiveTransfer => 0x000f,
            Self::WrongTransferDirection => 0x0010,
            Self::SourceLengthMismatch => 0x0011,
            Self::DeclaredLengthZero => 0x0012,
            Self::DeclaredLengthExceeded => 0x0013,
            Self::OffsetMismatch => 0x0014,
            Self::ChunkLengthZero => 0x0015,
            Self::ChunkLengthExceeded => 0x0016,
            Self::TransferLengthExceeded => 0x0017,
            Self::TransferIncomplete => 0x0018,
            Self::SourceOutOfRange => 0x0019,
            Self::SinkOutOfRange => 0x001a,
            Self::ArtifactOutOfRange => 0x001b,
            Self::SinkArtifactMismatch => 0x001c,
            Self::InvalidFilename => 0x001d,
            Self::InvalidBbqrPartLength => 0x001e,
            Self::AllocationFailed => 0x001f,
            Self::SourceReadFailed => 0x0020,
            Self::OutputCollision => 0x0021,
            Self::OutputCreateFailed => 0x0022,
            Self::OutputWriteFailed => 0x0023,
            Self::OutputSyncFailed => 0x0024,
            Self::OutputCloseFailed => 0x0025,
            Self::OutputReopenFailed => 0x0026,
            Self::OutputReadbackMismatch => 0x0027,
            Self::OutputRenameFailed => 0x0028,
            Self::PrintFailed => 0x0029,
            Self::Bbqr(error) => 0x0101 + bbqr_error_index(error),
        }
    }
}

impl fmt::Display for InnerError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Bbqr(error) => error.fmt(formatter),
            _ => formatter.write_str(inner_error_name(*self)),
        }
    }
}

impl std::error::Error for InnerError {}

const fn inner_error_name(error: InnerError) -> &'static str {
    match error {
        InnerError::InnerHeaderTruncated => "InnerHeaderTruncated",
        InnerError::InnerVersionMismatch => "InnerVersionMismatch",
        InnerError::RequestReservedNonZero => "RequestReservedNonZero",
        InnerError::OperationOutOfRange => "OperationOutOfRange",
        InnerError::BodyLengthExceeded => "BodyLengthExceeded",
        InnerError::BodyTruncated => "BodyTruncated",
        InnerError::TrailingByte => "TrailingByte",
        InnerError::UnexpectedBoundary => "UnexpectedBoundary",
        InnerError::BoundaryMissing => "BoundaryMissing",
        InnerError::SourceKindMismatch => "SourceKindMismatch",
        InnerError::SourceAlreadyUsed => "SourceAlreadyUsed",
        InnerError::WriterKindMismatch => "WriterKindMismatch",
        InnerError::WriterAlreadyUsed => "WriterAlreadyUsed",
        InnerError::ActiveTransfer => "ActiveTransfer",
        InnerError::NoActiveTransfer => "NoActiveTransfer",
        InnerError::WrongTransferDirection => "WrongTransferDirection",
        InnerError::SourceLengthMismatch => "SourceLengthMismatch",
        InnerError::DeclaredLengthZero => "DeclaredLengthZero",
        InnerError::DeclaredLengthExceeded => "DeclaredLengthExceeded",
        InnerError::OffsetMismatch => "OffsetMismatch",
        InnerError::ChunkLengthZero => "ChunkLengthZero",
        InnerError::ChunkLengthExceeded => "ChunkLengthExceeded",
        InnerError::TransferLengthExceeded => "TransferLengthExceeded",
        InnerError::TransferIncomplete => "TransferIncomplete",
        InnerError::SourceOutOfRange => "SourceOutOfRange",
        InnerError::SinkOutOfRange => "SinkOutOfRange",
        InnerError::ArtifactOutOfRange => "ArtifactOutOfRange",
        InnerError::SinkArtifactMismatch => "SinkArtifactMismatch",
        InnerError::InvalidFilename => "InvalidFilename",
        InnerError::InvalidBbqrPartLength => "InvalidBbqrPartLength",
        InnerError::AllocationFailed => "AllocationFailed",
        InnerError::SourceReadFailed => "SourceReadFailed",
        InnerError::OutputCollision => "OutputCollision",
        InnerError::OutputCreateFailed => "OutputCreateFailed",
        InnerError::OutputWriteFailed => "OutputWriteFailed",
        InnerError::OutputSyncFailed => "OutputSyncFailed",
        InnerError::OutputCloseFailed => "OutputCloseFailed",
        InnerError::OutputReopenFailed => "OutputReopenFailed",
        InnerError::OutputReadbackMismatch => "OutputReadbackMismatch",
        InnerError::OutputRenameFailed => "OutputRenameFailed",
        InnerError::PrintFailed => "PrintFailed",
        InnerError::Bbqr(_) => "Bbqr",
    }
}

const fn bbqr_error_index(error: qk_bbqr::BbqrError) -> u16 {
    use qk_bbqr::BbqrError;
    match error {
        BbqrError::EmptyPayload => 0,
        BbqrError::PayloadTooLarge => 1,
        BbqrError::InvalidNonFinalPartLength => 2,
        BbqrError::TooManyParts => 3,
        BbqrError::PartIndexOutOfRange => 4,
        BbqrError::FrameTooShort => 5,
        BbqrError::FrameTooLarge => 6,
        BbqrError::InvalidMagic => 7,
        BbqrError::UnsupportedEncoding => 8,
        BbqrError::UnsupportedFileType => 9,
        BbqrError::InvalidDeclaredPartCount => 10,
        BbqrError::DeclaredPartCountExceeded => 11,
        BbqrError::InvalidPartIndex => 12,
        BbqrError::EmptyPart => 13,
        BbqrError::Base32PaddingForbidden => 14,
        BbqrError::MalformedBase32Symbol => 15,
        BbqrError::NonCanonicalBase32Length => 16,
        BbqrError::NonCanonicalBase32Padding => 17,
        BbqrError::NonFinalPartLengthNotMultipleOfFive => 18,
        BbqrError::StreamEncodingMismatch => 19,
        BbqrError::StreamFileTypeMismatch => 20,
        BbqrError::StreamPartCountMismatch => 21,
        BbqrError::NonUniformPartLength => 22,
        BbqrError::FinalPartTooLarge => 23,
        BbqrError::TotalDecodedSizeExceeded => 24,
        BbqrError::ConflictingDuplicate => 25,
        BbqrError::DuplicateWorkExceeded => 26,
        BbqrError::SubmissionWorkExceeded => 27,
        BbqrError::Incomplete => 28,
        BbqrError::AlreadyComplete => 29,
    }
}
