//! Bounded one-use HOST mock transport boundaries.

use crate::wipe::{self, WipingVec};
use crate::{InnerError, Sink, Source, MAX_FILENAME_BYTES, MAX_MOCK_INPUT_BYTES};

/// One injected input source whose bytes can cross the boundary once.
pub struct MockInput {
    source: Source,
    bytes: Option<WipingVec>,
    fail_read: bool,
    used: bool,
}

impl MockInput {
    /// Construct one available patterned byte source.
    pub fn try_new(source: Source, bytes: &[u8]) -> Result<Self, InnerError> {
        if bytes.len() > MAX_MOCK_INPUT_BYTES {
            return Err(InnerError::DeclaredLengthExceeded);
        }
        let bytes = WipingVec::try_from_slice(bytes).map_err(|_| InnerError::AllocationFailed)?;
        Ok(Self {
            source,
            bytes: Some(bytes),
            fail_read: false,
            used: false,
        })
    }

    /// Construct one source that fails on its sole read attempt.
    pub const fn failing(source: Source) -> Self {
        Self {
            source,
            bytes: None,
            fail_read: true,
            used: false,
        }
    }

    /// Whether this source has already been consumed or discarded.
    pub const fn is_used(&self) -> bool {
        self.used
    }

    pub(crate) fn take(&mut self, expected: Source) -> Result<WipingVec, InnerError> {
        if self.used {
            return Err(InnerError::SourceAlreadyUsed);
        }
        self.used = true;
        let bytes = self.bytes.take();
        if self.source != expected {
            return Err(InnerError::SourceKindMismatch);
        }
        if self.fail_read {
            return Err(InnerError::SourceReadFailed);
        }
        bytes.ok_or(InnerError::SourceReadFailed)
    }

    pub(crate) fn discard(&mut self) -> Result<(), InnerError> {
        if self.used {
            return Err(InnerError::SourceAlreadyUsed);
        }
        self.used = true;
        self.bytes = None;
        Ok(())
    }
}

/// One exact injected writer failure point.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum OutputFault {
    None,
    Collision,
    Create,
    Write,
    Sync,
    Close,
    Reopen,
    ReadbackMismatch,
    Rename,
    Print,
}

/// One caller-owned HOST mock sink.
///
/// Retained bytes represent an external device boundary, not broker state,
/// and are cleared when this mock is dropped.
pub struct MockOutputWriter {
    sink: Sink,
    fault: OutputFault,
    used: bool,
    temporary: Option<WipingVec>,
    final_bytes: Option<WipingVec>,
    final_name: [u8; MAX_FILENAME_BYTES],
    final_name_len: usize,
}

impl MockOutputWriter {
    /// Construct one success-path mock writer.
    pub const fn new(sink: Sink) -> Self {
        Self::with_fault(sink, OutputFault::None)
    }

    /// Construct one writer with an exact injected failure point.
    pub const fn with_fault(sink: Sink, fault: OutputFault) -> Self {
        Self {
            sink,
            fault,
            used: false,
            temporary: None,
            final_bytes: None,
            final_name: [0; MAX_FILENAME_BYTES],
            final_name_len: 0,
        }
    }

    /// Whether the one-use boundary has been consumed or discarded.
    pub const fn is_used(&self) -> bool {
        self.used
    }

    /// Mock temporary residue after an Sd failure.
    pub fn temporary_bytes(&self) -> Option<&[u8]> {
        self.temporary.as_ref().map(WipingVec::as_slice)
    }

    /// Complete mock output after success.
    pub fn final_bytes(&self) -> Option<&[u8]> {
        self.final_bytes.as_ref().map(WipingVec::as_slice)
    }

    /// Complete final filename after successful Sd rename.
    pub fn final_name(&self) -> Option<&[u8]> {
        (self.final_name_len != 0).then_some(&self.final_name[..self.final_name_len])
    }

    pub(crate) fn write_sd(&mut self, name: &[u8], data: &[u8]) -> Result<(), InnerError> {
        self.begin(Sink::Sd)?;
        if self.fault == OutputFault::Collision {
            return Err(InnerError::OutputCollision);
        }
        if self.fault == OutputFault::Create {
            return Err(InnerError::OutputCreateFailed);
        }
        self.temporary =
            Some(WipingVec::try_from_slice(data).map_err(|_| InnerError::AllocationFailed)?);
        if self.fault == OutputFault::Write {
            return Err(InnerError::OutputWriteFailed);
        }
        if self.fault == OutputFault::Sync {
            return Err(InnerError::OutputSyncFailed);
        }
        if self.fault == OutputFault::Close {
            return Err(InnerError::OutputCloseFailed);
        }
        if self.fault == OutputFault::Reopen {
            return Err(InnerError::OutputReopenFailed);
        }
        if self.fault == OutputFault::ReadbackMismatch {
            if let Some(first) = self
                .temporary
                .as_mut()
                .and_then(|value| value.as_mut_slice().first_mut())
            {
                *first ^= 1;
            }
            return Err(InnerError::OutputReadbackMismatch);
        }
        if self.temporary.as_ref().map(WipingVec::as_slice) != Some(data) {
            return Err(InnerError::OutputReadbackMismatch);
        }
        if self.fault == OutputFault::Rename {
            return Err(InnerError::OutputRenameFailed);
        }
        self.final_name[..name.len()].copy_from_slice(name);
        self.final_name_len = name.len();
        self.final_bytes = self.temporary.take();
        Ok(())
    }

    pub(crate) fn write_print(&mut self, data: &[u8]) -> Result<(), InnerError> {
        self.begin(Sink::Print)?;
        if self.fault != OutputFault::None {
            return Err(InnerError::PrintFailed);
        }
        self.final_bytes =
            Some(WipingVec::try_from_slice(data).map_err(|_| InnerError::AllocationFailed)?);
        Ok(())
    }

    pub(crate) fn discard(&mut self) -> Result<(), InnerError> {
        if self.used {
            return Err(InnerError::WriterAlreadyUsed);
        }
        self.used = true;
        Ok(())
    }

    fn begin(&mut self, expected: Sink) -> Result<(), InnerError> {
        if self.used {
            return Err(InnerError::WriterAlreadyUsed);
        }
        self.used = true;
        if self.sink != expected {
            return Err(InnerError::WriterKindMismatch);
        }
        Ok(())
    }
}

impl Drop for MockOutputWriter {
    fn drop(&mut self) {
        wipe::bytes(&mut self.final_name);
        self.final_name_len = 0;
    }
}

#[cfg(test)]
mod tests {
    use super::{MockInput, MockOutputWriter, OutputFault};
    use crate::{InnerError, Sink, Source};

    #[test]
    fn input_is_consumed_on_kind_mismatch() {
        let mut input = MockInput::try_new(Source::CameraKitCandidate, &[7; 142]).unwrap();
        assert!(matches!(
            input.take(Source::CameraA1Candidate),
            Err(InnerError::SourceKindMismatch)
        ));
        assert!(input.is_used());
        assert!(matches!(
            input.take(Source::CameraKitCandidate),
            Err(InnerError::SourceAlreadyUsed)
        ));
    }

    #[test]
    fn sd_final_name_exists_only_after_complete_success() {
        let name = b"qk-00000000000000000000000000000000-final.tx";
        let mut success = MockOutputWriter::new(Sink::Sd);
        success.write_sd(name, b"payload").unwrap();
        assert_eq!(success.final_name(), Some(name.as_slice()));
        assert_eq!(success.final_bytes(), Some(b"payload".as_slice()));
        assert!(success.temporary_bytes().is_none());

        let mut failed = MockOutputWriter::with_fault(Sink::Sd, OutputFault::Rename);
        assert_eq!(
            failed.write_sd(name, b"payload"),
            Err(InnerError::OutputRenameFailed)
        );
        assert!(failed.final_name().is_none());
        assert!(failed.final_bytes().is_none());
        assert_eq!(failed.temporary_bytes(), Some(b"payload".as_slice()));
    }
}
