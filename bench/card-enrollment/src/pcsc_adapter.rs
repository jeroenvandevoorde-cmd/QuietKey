//! Safe-wrapper adapter. The implementation is added after the model surface
//! is pinned; this placeholder keeps the dependency foundation buildable.

use crate::{CaptureAttempt, EnrollmentBackend, EnrollmentError};

#[derive(Debug, Default)]
pub struct PcscEnrollmentBackend;

impl PcscEnrollmentBackend {
    pub const fn new() -> Self {
        Self
    }
}

impl EnrollmentBackend for PcscEnrollmentBackend {
    fn enumerate_readers(&mut self) -> Result<Vec<Vec<u8>>, EnrollmentError> {
        Err(EnrollmentError::ReaderEnumerationFailed)
    }

    fn capture_card(&mut self, _reader_name: &[u8]) -> CaptureAttempt {
        CaptureAttempt::ConnectFailed
    }
}
