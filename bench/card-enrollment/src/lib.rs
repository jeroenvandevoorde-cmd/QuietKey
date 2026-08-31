//! QuietKey F8 HOST card-enrollment boundary (QK-DEC-147).
//!
//! This crate can enumerate PC/SC readers and capture reset, protocol, and
//! ATR observations. Its active APDU allowlist is empty and its safe adapter
//! exposes no transmit operation.

#![forbid(unsafe_code)]

mod model;
mod pcsc_adapter;
mod transcript;

pub use model::{
    authorize_operation, run_enrollment, CaptureAttempt, CardCapture, EnrollmentBackend,
    EnrollmentError, EnrollmentEvent, EnrollmentMetadata, EnrollmentMode, EnrollmentOperation,
    EnrollmentOutcome, EnrollmentRecord, NegotiatedProtocol, ValidatedMetadata,
};
pub use pcsc_adapter::PcscEnrollmentBackend;
pub use transcript::encode_transcript;

pub const ACTIVE_ALLOWLIST_ID: &str = "QK-F8-ENROLL-EMPTY-V1";
pub const TRANSCRIPT_VERSION: &str = "QK-CARD-ENROLLMENT-V1";
pub const TOOL_VERSION: &str = env!("CARGO_PKG_VERSION");

pub const MAX_READER_LIST_BYTES: usize = 4_096;
pub const MAX_READERS: usize = 32;
pub const MAX_READER_NAME_BYTES: usize = 255;
pub const MAX_ATR_BYTES: usize = 33;
pub const MAX_TRANSCRIPT_BYTES: usize = 16_384;
