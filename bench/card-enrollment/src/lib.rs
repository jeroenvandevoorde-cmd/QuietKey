//! QuietKey F8 HOST card-observation boundary (QK-DEC-147/QK-DEC-153-SUP-002).
//!
//! This crate can enumerate PC/SC readers and capture reset, protocol, and
//! ATR observations. Generic APDU transmission remains unavailable; the
//! identity path owns exactly three private, literal, source-pinned commands.
//! The sitting path owns one separately registered fixed exchange table.

#![forbid(unsafe_code)]

mod identity;
mod identity_transcript;
mod model;
mod pcsc_adapter;
mod pcsc_identity_adapter;
mod pcsc_sitting_adapter;
mod sitting;
mod sitting_transcript;
mod transcript;

pub use identity::{
    run_identity, validate_card_recognition_response, validate_cplc_response,
    validate_select_response, IdentityAttempt, IdentityBackend, IdentityError, IdentityEvent,
    IdentityExchange, IdentityOperation, IdentityOutcome, IdentityRecord, CARD_RECOGNITION_COMMAND,
    CPLC_COMMAND, MAX_IDENTITY_RESPONSE_BYTES, REGISTERED_J3R180_ATR,
    SELECT_DEFAULT_APPLICATION_COMMAND,
};
pub use identity_transcript::encode_identity_transcript;
pub use model::{
    authorize_operation, run_enrollment, CaptureAttempt, CardCapture, EnrollmentBackend,
    EnrollmentError, EnrollmentEvent, EnrollmentMetadata, EnrollmentMode, EnrollmentOperation,
    EnrollmentOutcome, EnrollmentRecord, NegotiatedProtocol, ValidatedMetadata,
};
pub use pcsc_adapter::PcscEnrollmentBackend;
pub use pcsc_identity_adapter::execute_pcsc_identity;
pub use pcsc_sitting_adapter::execute_pcsc_sitting;
pub use sitting::{
    fixed_sitting_plan, run_fixed_sitting_plan, sitting_output_basename, validate_sitting_binding,
    validate_sitting_output_path, SittingError, SittingExchange, SittingMetadata, SittingMode,
    SittingOutcome, SittingPlan, SittingRunSummary, SittingTransportFailure, CANONICAL_CAP_BYTES,
    CANONICAL_CAP_SHA256, GOLDEN_FIXTURE_BLOB, GOLDEN_FIXTURE_BYTES, GOLDEN_FIXTURE_LF,
    GOLDEN_FIXTURE_PATH, GOLDEN_FIXTURE_SHA256, MAX_SITTING_CAPTURE_BYTES,
    MAX_SITTING_REQUEST_BYTES, MAX_SITTING_RESPONSE_BYTES, SITTING_APPLET_SOURCE_COMMIT,
    SITTING_CAMPAIGN_SOURCE_COMMIT, SITTING_PLAN_VERSION, SITTING_READER_NAME,
};
pub use sitting_transcript::{SittingTranscript, SITTING_TRANSCRIPT_VERSION};
pub use transcript::encode_transcript;

pub const ACTIVE_ALLOWLIST_ID: &str = "QK-F8-ENROLL-EMPTY-V1";
pub const TRANSCRIPT_VERSION: &str = "QK-CARD-ENROLLMENT-V1";
// The completed enrollment evidence protocol remains byte-frozen at 0.0.1.
pub const TOOL_VERSION: &str = "0.0.1";
pub const IDENTITY_ALLOWLIST_ID: &str = "QK-F8-IDENT-V2";
pub const IDENTITY_TRANSCRIPT_VERSION: &str = "QK-CARD-IDENTITY-V2";
pub const IDENTITY_TOOL_VERSION: &str = "0.0.3";
pub const SITTING_TOOL_VERSION: &str = env!("CARGO_PKG_VERSION");

pub const MAX_READER_LIST_BYTES: usize = 4_096;
pub const MAX_READERS: usize = 32;
pub const MAX_READER_NAME_BYTES: usize = 255;
pub const MAX_ATR_BYTES: usize = 33;
pub const MAX_TRANSCRIPT_BYTES: usize = 16_384;
pub const MAX_SITTING_TRANSCRIPT_BYTES: usize = 32_768;
