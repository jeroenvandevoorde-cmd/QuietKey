//! QuietKey F8 HOST card-observation boundary (QK-DEC-147/QK-DEC-153).
//!
//! This crate can enumerate PC/SC readers and capture reset, protocol, and
//! ATR observations. Generic APDU transmission remains unavailable; the
//! identity path owns exactly two private, literal, source-pinned reads.

#![forbid(unsafe_code)]

mod identity;
mod identity_transcript;
mod model;
mod pcsc_adapter;
mod pcsc_identity_adapter;
mod transcript;

pub use identity::{
    run_identity, validate_card_recognition_response, validate_cplc_response, IdentityAttempt,
    IdentityBackend, IdentityError, IdentityEvent, IdentityExchange, IdentityOperation,
    IdentityOutcome, IdentityRecord, CARD_RECOGNITION_COMMAND, CPLC_COMMAND,
    MAX_IDENTITY_RESPONSE_BYTES, REGISTERED_J3R180_ATR,
};
pub use identity_transcript::encode_identity_transcript;
pub use model::{
    authorize_operation, run_enrollment, CaptureAttempt, CardCapture, EnrollmentBackend,
    EnrollmentError, EnrollmentEvent, EnrollmentMetadata, EnrollmentMode, EnrollmentOperation,
    EnrollmentOutcome, EnrollmentRecord, NegotiatedProtocol, ValidatedMetadata,
};
pub use pcsc_adapter::PcscEnrollmentBackend;
pub use pcsc_identity_adapter::execute_pcsc_identity;
pub use transcript::encode_transcript;

pub const ACTIVE_ALLOWLIST_ID: &str = "QK-F8-ENROLL-EMPTY-V1";
pub const TRANSCRIPT_VERSION: &str = "QK-CARD-ENROLLMENT-V1";
// The completed enrollment evidence protocol remains byte-frozen at 0.0.1.
pub const TOOL_VERSION: &str = "0.0.1";
pub const IDENTITY_ALLOWLIST_ID: &str = "QK-F8-IDENT-V1";
pub const IDENTITY_TRANSCRIPT_VERSION: &str = "QK-CARD-IDENTITY-V1";
pub const IDENTITY_TOOL_VERSION: &str = env!("CARGO_PKG_VERSION");

pub const MAX_READER_LIST_BYTES: usize = 4_096;
pub const MAX_READERS: usize = 32;
pub const MAX_READER_NAME_BYTES: usize = 255;
pub const MAX_ATR_BYTES: usize = 33;
pub const MAX_TRANSCRIPT_BYTES: usize = 16_384;
