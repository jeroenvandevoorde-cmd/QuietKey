use core::fmt;

use crate::{MAX_ATR_BYTES, MAX_READERS, MAX_READER_NAME_BYTES};

const MAX_ALIAS_BYTES: usize = 64;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum EnrollmentMode {
    Enumerate,
    Enroll,
}

impl EnrollmentMode {
    pub(crate) const fn as_str(self) -> &'static str {
        match self {
            Self::Enumerate => "ENUMERATE",
            Self::Enroll => "ENROLL",
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum NegotiatedProtocol {
    T0,
    T1,
    Raw,
}

impl NegotiatedProtocol {
    pub(crate) const fn as_str(self) -> &'static str {
        match self {
            Self::T0 => "T0",
            Self::T1 => "T1",
            Self::Raw => "RAW",
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum EnrollmentOperation {
    EnumerateReaders,
    ExclusiveConnect,
    Reset,
    CaptureAtr,
    CaptureProtocol,
    Disconnect,
    Transmit,
}

impl EnrollmentOperation {
    pub(crate) const fn as_str(self) -> &'static str {
        match self {
            Self::EnumerateReaders => "EnumerateReaders",
            Self::ExclusiveConnect => "ExclusiveConnect",
            Self::Reset => "Reset",
            Self::CaptureAtr => "CaptureAtr",
            Self::CaptureProtocol => "CaptureProtocol",
            Self::Disconnect => "Disconnect",
            Self::Transmit => "Transmit",
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum EnrollmentError {
    SourceCommitInvalid,
    TimestampInvalid,
    HostAliasInvalid,
    ReaderAliasInvalid,
    SpecimenAliasInvalid,
    SelectedReaderInvalid,
    SelectedReaderUnexpected,
    ContextUnavailable,
    ReaderEnumerationFailed,
    ReaderListTooLarge,
    ReaderCountExceeded,
    ReaderNameEmpty,
    ReaderNameTooLong,
    ReaderNameContainsNul,
    SelectedReaderMissing,
    SelectedReaderDuplicate,
    ConnectFailed,
    ResetFailed,
    StatusFailed,
    AtrEmpty,
    AtrTooLong,
    ProtocolUnavailable,
    ProtocolUnsupported,
    DisconnectFailed,
    BoundaryPanicked,
    ApduTransmitNotAuthorized,
    TranscriptTooLarge,
    OutputFailed,
}

impl EnrollmentError {
    pub const fn name(self) -> &'static str {
        match self {
            Self::SourceCommitInvalid => "SourceCommitInvalid",
            Self::TimestampInvalid => "TimestampInvalid",
            Self::HostAliasInvalid => "HostAliasInvalid",
            Self::ReaderAliasInvalid => "ReaderAliasInvalid",
            Self::SpecimenAliasInvalid => "SpecimenAliasInvalid",
            Self::SelectedReaderInvalid => "SelectedReaderInvalid",
            Self::SelectedReaderUnexpected => "SelectedReaderUnexpected",
            Self::ContextUnavailable => "ContextUnavailable",
            Self::ReaderEnumerationFailed => "ReaderEnumerationFailed",
            Self::ReaderListTooLarge => "ReaderListTooLarge",
            Self::ReaderCountExceeded => "ReaderCountExceeded",
            Self::ReaderNameEmpty => "ReaderNameEmpty",
            Self::ReaderNameTooLong => "ReaderNameTooLong",
            Self::ReaderNameContainsNul => "ReaderNameContainsNul",
            Self::SelectedReaderMissing => "SelectedReaderMissing",
            Self::SelectedReaderDuplicate => "SelectedReaderDuplicate",
            Self::ConnectFailed => "ConnectFailed",
            Self::ResetFailed => "ResetFailed",
            Self::StatusFailed => "StatusFailed",
            Self::AtrEmpty => "AtrEmpty",
            Self::AtrTooLong => "AtrTooLong",
            Self::ProtocolUnavailable => "ProtocolUnavailable",
            Self::ProtocolUnsupported => "ProtocolUnsupported",
            Self::DisconnectFailed => "DisconnectFailed",
            Self::BoundaryPanicked => "BoundaryPanicked",
            Self::ApduTransmitNotAuthorized => "ApduTransmitNotAuthorized",
            Self::TranscriptTooLarge => "TranscriptTooLarge",
            Self::OutputFailed => "OutputFailed",
        }
    }
}

impl fmt::Display for EnrollmentError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.name())
    }
}

impl std::error::Error for EnrollmentError {}

pub fn authorize_operation(operation: EnrollmentOperation) -> Result<(), EnrollmentError> {
    match operation {
        EnrollmentOperation::Transmit => Err(EnrollmentError::ApduTransmitNotAuthorized),
        EnrollmentOperation::EnumerateReaders
        | EnrollmentOperation::ExclusiveConnect
        | EnrollmentOperation::Reset
        | EnrollmentOperation::CaptureAtr
        | EnrollmentOperation::CaptureProtocol
        | EnrollmentOperation::Disconnect => Ok(()),
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct EnrollmentMetadata {
    pub mode: EnrollmentMode,
    pub source_commit: String,
    pub timestamp_utc: String,
    pub host_alias: String,
    pub reader_alias: String,
    pub specimen_alias: Option<String>,
    pub selected_reader_name: Option<Vec<u8>>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ValidatedMetadata(EnrollmentMetadata);

impl EnrollmentMetadata {
    pub fn validate(self) -> Result<ValidatedMetadata, EnrollmentError> {
        if !is_lower_hex(&self.source_commit, 40) {
            return Err(EnrollmentError::SourceCommitInvalid);
        }
        if !is_utc_second(&self.timestamp_utc) {
            return Err(EnrollmentError::TimestampInvalid);
        }
        if self.host_alias != "iMac" || !is_alias(&self.host_alias) {
            return Err(EnrollmentError::HostAliasInvalid);
        }
        if self.reader_alias != "SCR3310-01" || !is_alias(&self.reader_alias) {
            return Err(EnrollmentError::ReaderAliasInvalid);
        }
        match self.mode {
            EnrollmentMode::Enumerate => {
                if self.specimen_alias.is_some() {
                    return Err(EnrollmentError::SpecimenAliasInvalid);
                }
                if self.selected_reader_name.is_some() {
                    return Err(EnrollmentError::SelectedReaderUnexpected);
                }
            }
            EnrollmentMode::Enroll => {
                let Some(specimen) = self.specimen_alias.as_deref() else {
                    return Err(EnrollmentError::SpecimenAliasInvalid);
                };
                if !matches!(specimen, "J3R180-01" | "J3R180-02" | "J3R180-03") {
                    return Err(EnrollmentError::SpecimenAliasInvalid);
                }
                let Some(reader) = self.selected_reader_name.as_deref() else {
                    return Err(EnrollmentError::SelectedReaderInvalid);
                };
                validate_reader_name(reader).map_err(|_| EnrollmentError::SelectedReaderInvalid)?;
            }
        }
        Ok(ValidatedMetadata(self))
    }
}

impl ValidatedMetadata {
    pub(crate) fn inner(&self) -> &EnrollmentMetadata {
        &self.0
    }
}

fn is_alias(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= MAX_ALIAS_BYTES
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-'))
}

fn is_lower_hex(value: &str, length: usize) -> bool {
    value.len() == length
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn is_utc_second(value: &str) -> bool {
    let bytes = value.as_bytes();
    if bytes.len() != 20
        || bytes[4] != b'-'
        || bytes[7] != b'-'
        || bytes[10] != b'T'
        || bytes[13] != b':'
        || bytes[16] != b':'
        || bytes[19] != b'Z'
        || bytes.iter().enumerate().any(|(index, byte)| {
            !matches!(index, 4 | 7 | 10 | 13 | 16 | 19) && !byte.is_ascii_digit()
        })
    {
        return false;
    }
    let number = |start: usize, end: usize| -> u32 {
        bytes[start..end]
            .iter()
            .fold(0, |value, byte| value * 10 + u32::from(byte - b'0'))
    };
    let month = number(5, 7);
    let day = number(8, 10);
    let hour = number(11, 13);
    let minute = number(14, 16);
    let second = number(17, 19);
    (1..=12).contains(&month)
        && (1..=31).contains(&day)
        && hour <= 23
        && minute <= 59
        && second <= 59
}

fn validate_reader_name(reader: &[u8]) -> Result<(), EnrollmentError> {
    if reader.is_empty() {
        return Err(EnrollmentError::ReaderNameEmpty);
    }
    if reader.len() > MAX_READER_NAME_BYTES {
        return Err(EnrollmentError::ReaderNameTooLong);
    }
    if reader.contains(&0) {
        return Err(EnrollmentError::ReaderNameContainsNul);
    }
    Ok(())
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CardCapture {
    pub atr: Vec<u8>,
    pub protocol: NegotiatedProtocol,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum CaptureAttempt {
    ConnectFailed,
    ResetFailed,
    StatusFailed,
    ProtocolUnavailable { atr: Vec<u8> },
    ProtocolUnsupported { atr: Vec<u8> },
    DisconnectFailed(CardCapture),
    BoundaryPanicked,
    Success(CardCapture),
}

pub trait EnrollmentBackend {
    fn enumerate_readers(&mut self) -> Result<Vec<Vec<u8>>, EnrollmentError>;
    fn capture_card(&mut self, reader_name: &[u8]) -> CaptureAttempt;
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum EnrollmentOutcome {
    Pass,
    Reject(EnrollmentError),
}

impl EnrollmentOutcome {
    pub(crate) const fn as_str(self) -> &'static str {
        match self {
            Self::Pass => "PASS",
            Self::Reject(error) => error.name(),
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct EnrollmentEvent {
    pub operation: EnrollmentOperation,
    pub outcome: EnrollmentOutcome,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct EnrollmentRecord {
    pub metadata: ValidatedMetadata,
    pub readers: Vec<Vec<u8>>,
    pub events: Vec<EnrollmentEvent>,
    pub capture: Option<CardCapture>,
    pub outcome: EnrollmentOutcome,
}

pub fn run_enrollment<B: EnrollmentBackend>(
    metadata: ValidatedMetadata,
    backend: &mut B,
) -> EnrollmentRecord {
    let mut record = EnrollmentRecord {
        metadata,
        readers: Vec::new(),
        events: Vec::with_capacity(6),
        capture: None,
        outcome: EnrollmentOutcome::Pass,
    };
    if authorize_operation(EnrollmentOperation::EnumerateReaders).is_err() {
        return reject(
            record,
            EnrollmentOperation::EnumerateReaders,
            EnrollmentError::ApduTransmitNotAuthorized,
        );
    }
    let readers = match backend.enumerate_readers() {
        Ok(readers) => readers,
        Err(_) => {
            return reject(
                record,
                EnrollmentOperation::EnumerateReaders,
                EnrollmentError::ReaderEnumerationFailed,
            );
        }
    };
    if readers.len() > MAX_READERS {
        return reject(
            record,
            EnrollmentOperation::EnumerateReaders,
            EnrollmentError::ReaderCountExceeded,
        );
    }
    for reader in &readers {
        if let Err(error) = validate_reader_name(reader) {
            return reject(record, EnrollmentOperation::EnumerateReaders, error);
        }
    }
    record.readers = readers;
    push_pass(&mut record, EnrollmentOperation::EnumerateReaders);

    if record.metadata.inner().mode == EnrollmentMode::Enumerate {
        return record;
    }

    let selected = record
        .metadata
        .inner()
        .selected_reader_name
        .as_deref()
        .expect("validated enroll metadata has a selected reader");
    match record
        .readers
        .iter()
        .filter(|reader| reader.as_slice() == selected)
        .count()
    {
        0 => {
            return set_outcome(record, EnrollmentError::SelectedReaderMissing);
        }
        1 => {}
        _ => {
            return set_outcome(record, EnrollmentError::SelectedReaderDuplicate);
        }
    }

    match backend.capture_card(selected) {
        CaptureAttempt::ConnectFailed => reject(
            record,
            EnrollmentOperation::ExclusiveConnect,
            EnrollmentError::ConnectFailed,
        ),
        CaptureAttempt::ResetFailed => {
            push_pass(&mut record, EnrollmentOperation::ExclusiveConnect);
            reject(
                record,
                EnrollmentOperation::Reset,
                EnrollmentError::ResetFailed,
            )
        }
        CaptureAttempt::StatusFailed => {
            push_pass(&mut record, EnrollmentOperation::ExclusiveConnect);
            push_pass(&mut record, EnrollmentOperation::Reset);
            reject(
                record,
                EnrollmentOperation::CaptureAtr,
                EnrollmentError::StatusFailed,
            )
        }
        CaptureAttempt::ProtocolUnavailable { atr } => {
            push_capture_prefix(&mut record, &atr);
            reject(
                record,
                EnrollmentOperation::CaptureProtocol,
                EnrollmentError::ProtocolUnavailable,
            )
        }
        CaptureAttempt::ProtocolUnsupported { atr } => {
            push_capture_prefix(&mut record, &atr);
            reject(
                record,
                EnrollmentOperation::CaptureProtocol,
                EnrollmentError::ProtocolUnsupported,
            )
        }
        CaptureAttempt::DisconnectFailed(capture) => {
            if let Err(error) = validate_capture(&capture) {
                return reject(record, EnrollmentOperation::CaptureAtr, error);
            }
            push_capture_success(&mut record, capture);
            reject(
                record,
                EnrollmentOperation::Disconnect,
                EnrollmentError::DisconnectFailed,
            )
        }
        CaptureAttempt::BoundaryPanicked => set_outcome(record, EnrollmentError::BoundaryPanicked),
        CaptureAttempt::Success(capture) => {
            if let Err(error) = validate_capture(&capture) {
                return reject(record, EnrollmentOperation::CaptureAtr, error);
            }
            push_capture_success(&mut record, capture);
            push_pass(&mut record, EnrollmentOperation::Disconnect);
            record
        }
    }
}

fn validate_capture(capture: &CardCapture) -> Result<(), EnrollmentError> {
    if capture.atr.is_empty() {
        return Err(EnrollmentError::AtrEmpty);
    }
    if capture.atr.len() > MAX_ATR_BYTES {
        return Err(EnrollmentError::AtrTooLong);
    }
    Ok(())
}

fn push_capture_prefix(record: &mut EnrollmentRecord, atr: &[u8]) {
    push_pass(record, EnrollmentOperation::ExclusiveConnect);
    push_pass(record, EnrollmentOperation::Reset);
    if atr.is_empty() {
        record.events.push(EnrollmentEvent {
            operation: EnrollmentOperation::CaptureAtr,
            outcome: EnrollmentOutcome::Reject(EnrollmentError::AtrEmpty),
        });
    } else if atr.len() > MAX_ATR_BYTES {
        record.events.push(EnrollmentEvent {
            operation: EnrollmentOperation::CaptureAtr,
            outcome: EnrollmentOutcome::Reject(EnrollmentError::AtrTooLong),
        });
    } else {
        push_pass(record, EnrollmentOperation::CaptureAtr);
    }
}

fn push_capture_success(record: &mut EnrollmentRecord, capture: CardCapture) {
    push_pass(record, EnrollmentOperation::ExclusiveConnect);
    push_pass(record, EnrollmentOperation::Reset);
    push_pass(record, EnrollmentOperation::CaptureAtr);
    push_pass(record, EnrollmentOperation::CaptureProtocol);
    record.capture = Some(capture);
}

fn push_pass(record: &mut EnrollmentRecord, operation: EnrollmentOperation) {
    record.events.push(EnrollmentEvent {
        operation,
        outcome: EnrollmentOutcome::Pass,
    });
}

fn reject(
    mut record: EnrollmentRecord,
    operation: EnrollmentOperation,
    error: EnrollmentError,
) -> EnrollmentRecord {
    record.events.push(EnrollmentEvent {
        operation,
        outcome: EnrollmentOutcome::Reject(error),
    });
    record.outcome = EnrollmentOutcome::Reject(error);
    record
}

fn set_outcome(mut record: EnrollmentRecord, error: EnrollmentError) -> EnrollmentRecord {
    record.outcome = EnrollmentOutcome::Reject(error);
    record
}

#[cfg(test)]
mod tests {
    use super::{EnrollmentError, EnrollmentMetadata, EnrollmentMode};

    fn metadata() -> EnrollmentMetadata {
        EnrollmentMetadata {
            mode: EnrollmentMode::Enroll,
            source_commit: "0123456789abcdef0123456789abcdef01234567".to_owned(),
            timestamp_utc: "2026-08-31T12:34:56Z".to_owned(),
            host_alias: "iMac".to_owned(),
            reader_alias: "SCR3310-01".to_owned(),
            specimen_alias: Some("J3R180-02".to_owned()),
            selected_reader_name: Some(b"Identiv SCR3310".to_vec()),
        }
    }

    #[test]
    fn metadata_is_exact() {
        assert!(metadata().validate().is_ok());
        let mut invalid = metadata();
        invalid.source_commit.make_ascii_uppercase();
        assert_eq!(
            invalid.validate(),
            Err(EnrollmentError::SourceCommitInvalid)
        );
        let mut invalid = metadata();
        invalid.timestamp_utc = "2026-08-31T12:34:60Z".to_owned();
        assert_eq!(invalid.validate(), Err(EnrollmentError::TimestampInvalid));
        let mut invalid = metadata();
        invalid.specimen_alias = Some("J3R180-04".to_owned());
        assert_eq!(
            invalid.validate(),
            Err(EnrollmentError::SpecimenAliasInvalid)
        );
    }
}
