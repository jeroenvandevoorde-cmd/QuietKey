use core::fmt;

use crate::{
    EnrollmentMode, NegotiatedProtocol, ValidatedMetadata, MAX_ATR_BYTES, MAX_READERS,
    MAX_READER_LIST_BYTES, MAX_READER_NAME_BYTES,
};

pub const CARD_RECOGNITION_COMMAND: [u8; 5] = [0x80, 0xca, 0x00, 0x66, 0x00];
pub const CPLC_COMMAND: [u8; 5] = [0x80, 0xca, 0x9f, 0x7f, 0x00];
pub const REGISTERED_J3R180_ATR: [u8; 15] = [
    0x3b, 0xd5, 0x18, 0xff, 0x81, 0x91, 0xfe, 0x1f, 0xc3, 0x80, 0x73, 0xc8, 0x21, 0x10, 0x0a,
];
pub const MAX_IDENTITY_RESPONSE_BYTES: usize = 258;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum IdentityError {
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
    RegisteredAtrMismatch,
    IdentityProtocolMismatch,
    CardRecognitionTransmitFailed,
    CardRecognitionResponseTooLong,
    CardRecognitionResponseTooShort,
    CardRecognitionStatusRejected,
    CardRecognitionOuterTagMismatch,
    CardRecognitionLengthMalformed,
    CardRecognitionTrailingByte,
    CardRecognitionFirstNestedTagMismatch,
    CplcTransmitFailed,
    CplcResponseLengthMismatch,
    CplcStatusRejected,
    CplcTagMismatch,
    CplcLengthMismatch,
    IdentitySequenceViolation,
    TranscriptTooLarge,
    OutputFailed,
}

impl IdentityError {
    pub const fn name(self) -> &'static str {
        match self {
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
            Self::RegisteredAtrMismatch => "RegisteredAtrMismatch",
            Self::IdentityProtocolMismatch => "IdentityProtocolMismatch",
            Self::CardRecognitionTransmitFailed => "CardRecognitionTransmitFailed",
            Self::CardRecognitionResponseTooLong => "CardRecognitionResponseTooLong",
            Self::CardRecognitionResponseTooShort => "CardRecognitionResponseTooShort",
            Self::CardRecognitionStatusRejected => "CardRecognitionStatusRejected",
            Self::CardRecognitionOuterTagMismatch => "CardRecognitionOuterTagMismatch",
            Self::CardRecognitionLengthMalformed => "CardRecognitionLengthMalformed",
            Self::CardRecognitionTrailingByte => "CardRecognitionTrailingByte",
            Self::CardRecognitionFirstNestedTagMismatch => "CardRecognitionFirstNestedTagMismatch",
            Self::CplcTransmitFailed => "CplcTransmitFailed",
            Self::CplcResponseLengthMismatch => "CplcResponseLengthMismatch",
            Self::CplcStatusRejected => "CplcStatusRejected",
            Self::CplcTagMismatch => "CplcTagMismatch",
            Self::CplcLengthMismatch => "CplcLengthMismatch",
            Self::IdentitySequenceViolation => "IdentitySequenceViolation",
            Self::TranscriptTooLarge => "TranscriptTooLarge",
            Self::OutputFailed => "OutputFailed",
        }
    }
}

impl fmt::Display for IdentityError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.name())
    }
}

impl std::error::Error for IdentityError {}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum IdentityOperation {
    EnumerateReaders,
    ExclusiveConnect,
    Reset,
    CaptureAtr,
    CaptureProtocol,
    TransmitCardRecognition,
    ReceiveCardRecognition,
    TransmitCplc,
    ReceiveCplc,
    Disconnect,
}

impl IdentityOperation {
    pub(crate) const fn as_str(self) -> &'static str {
        match self {
            Self::EnumerateReaders => "EnumerateReaders",
            Self::ExclusiveConnect => "ExclusiveConnect",
            Self::Reset => "Reset",
            Self::CaptureAtr => "CaptureAtr",
            Self::CaptureProtocol => "CaptureProtocol",
            Self::TransmitCardRecognition => "TransmitCardRecognition",
            Self::ReceiveCardRecognition => "ReceiveCardRecognition",
            Self::TransmitCplc => "TransmitCplc",
            Self::ReceiveCplc => "ReceiveCplc",
            Self::Disconnect => "Disconnect",
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum IdentityOutcome {
    Pass,
    Reject(IdentityError),
}

impl IdentityOutcome {
    pub(crate) const fn as_str(self) -> &'static str {
        match self {
            Self::Pass => "PASS",
            Self::Reject(error) => error.name(),
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct IdentityEvent {
    pub operation: IdentityOperation,
    pub outcome: IdentityOutcome,
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct IdentityExchange {
    pub request: Option<Vec<u8>>,
    pub response: Option<Vec<u8>>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct IdentityAttempt {
    pub events: Vec<IdentityEvent>,
    pub observed_atr: Option<Vec<u8>>,
    pub observed_protocol: Option<NegotiatedProtocol>,
    pub exchanges: [IdentityExchange; 2],
    pub disconnected: Option<bool>,
    pub outcome: IdentityOutcome,
}

impl IdentityAttempt {
    pub(crate) fn new() -> Self {
        Self {
            events: Vec::with_capacity(9),
            observed_atr: None,
            observed_protocol: None,
            exchanges: core::array::from_fn(|_| IdentityExchange::default()),
            disconnected: None,
            outcome: IdentityOutcome::Pass,
        }
    }

    pub(crate) fn push_pass(&mut self, operation: IdentityOperation) {
        self.events.push(IdentityEvent {
            operation,
            outcome: IdentityOutcome::Pass,
        });
    }

    pub(crate) fn reject(&mut self, operation: IdentityOperation, error: IdentityError) {
        self.events.push(IdentityEvent {
            operation,
            outcome: IdentityOutcome::Reject(error),
        });
        if self.outcome == IdentityOutcome::Pass {
            self.outcome = IdentityOutcome::Reject(error);
        }
    }

    pub(crate) fn finish_disconnect(&mut self, disconnected: bool) {
        self.disconnected = Some(disconnected);
        if disconnected {
            self.push_pass(IdentityOperation::Disconnect);
        } else {
            self.reject(
                IdentityOperation::Disconnect,
                IdentityError::DisconnectFailed,
            );
        }
    }
}

pub trait IdentityBackend {
    fn enumerate_readers(&mut self) -> Result<Vec<Vec<u8>>, IdentityError>;
    fn capture_identity(&mut self, reader_name: &[u8]) -> IdentityAttempt;
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct IdentityRecord {
    pub metadata: ValidatedMetadata,
    pub readers: Vec<Vec<u8>>,
    pub events: Vec<IdentityEvent>,
    pub observed_atr: Option<Vec<u8>>,
    pub observed_protocol: Option<NegotiatedProtocol>,
    pub exchanges: [IdentityExchange; 2],
    pub disconnected: Option<bool>,
    pub outcome: IdentityOutcome,
}

pub fn run_identity<B: IdentityBackend>(
    metadata: ValidatedMetadata,
    backend: &mut B,
) -> IdentityRecord {
    let mut record = IdentityRecord {
        metadata,
        readers: Vec::new(),
        events: Vec::with_capacity(10),
        observed_atr: None,
        observed_protocol: None,
        exchanges: core::array::from_fn(|_| IdentityExchange::default()),
        disconnected: None,
        outcome: IdentityOutcome::Pass,
    };
    if record.metadata.inner().mode != EnrollmentMode::Enroll {
        return reject_enumeration(record, IdentityError::IdentitySequenceViolation);
    }
    let readers = match backend.enumerate_readers() {
        Ok(readers) => readers,
        Err(error) => return reject_enumeration(record, normalize_enumeration_error(error)),
    };
    if readers.len() > MAX_READERS {
        return reject_enumeration(record, IdentityError::ReaderCountExceeded);
    }
    let list_bytes = readers.iter().try_fold(1usize, |total, reader| {
        total.checked_add(reader.len())?.checked_add(1)
    });
    if list_bytes.is_none_or(|length| length > MAX_READER_LIST_BYTES) {
        return reject_enumeration(record, IdentityError::ReaderListTooLarge);
    }
    record.readers = readers;
    for reader in &record.readers {
        if let Err(error) = validate_reader_name(reader) {
            return reject_enumeration(record, error);
        }
    }
    record.events.push(IdentityEvent {
        operation: IdentityOperation::EnumerateReaders,
        outcome: IdentityOutcome::Pass,
    });

    let selected = record
        .metadata
        .inner()
        .selected_reader_name
        .as_deref()
        .expect("validated enrollment metadata has a selected reader");
    match record
        .readers
        .iter()
        .filter(|reader| reader.as_slice() == selected)
        .count()
    {
        0 => return set_outcome(record, IdentityError::SelectedReaderMissing),
        1 => {}
        _ => return set_outcome(record, IdentityError::SelectedReaderDuplicate),
    }

    let attempt = backend.capture_identity(selected);
    record.events.extend_from_slice(&attempt.events);
    record.observed_atr = attempt.observed_atr;
    record.observed_protocol = attempt.observed_protocol;
    record.exchanges = attempt.exchanges;
    record.disconnected = attempt.disconnected;
    record.outcome = attempt.outcome;
    if validate_attempt(&record).is_err() {
        record.outcome = IdentityOutcome::Reject(IdentityError::IdentitySequenceViolation);
    }
    record
}

fn normalize_enumeration_error(error: IdentityError) -> IdentityError {
    match error {
        IdentityError::ReaderListTooLarge | IdentityError::BoundaryPanicked => error,
        _ => IdentityError::ReaderEnumerationFailed,
    }
}

fn reject_enumeration(mut record: IdentityRecord, error: IdentityError) -> IdentityRecord {
    record.events.push(IdentityEvent {
        operation: IdentityOperation::EnumerateReaders,
        outcome: IdentityOutcome::Reject(error),
    });
    record.outcome = IdentityOutcome::Reject(error);
    record
}

fn set_outcome(mut record: IdentityRecord, error: IdentityError) -> IdentityRecord {
    record.outcome = IdentityOutcome::Reject(error);
    record
}

fn validate_reader_name(reader: &[u8]) -> Result<(), IdentityError> {
    if reader.is_empty() {
        return Err(IdentityError::ReaderNameEmpty);
    }
    if reader.len() > MAX_READER_NAME_BYTES {
        return Err(IdentityError::ReaderNameTooLong);
    }
    if reader.contains(&0) {
        return Err(IdentityError::ReaderNameContainsNul);
    }
    Ok(())
}

fn validate_attempt(record: &IdentityRecord) -> Result<(), IdentityError> {
    let first = &record.exchanges[0];
    let second = &record.exchanges[1];
    if first
        .request
        .as_deref()
        .is_some_and(|request| request != CARD_RECOGNITION_COMMAND)
        || second
            .request
            .as_deref()
            .is_some_and(|request| request != CPLC_COMMAND)
        || first.response.is_some() && first.request.is_none()
        || second.response.is_some() && second.request.is_none()
        || second.request.is_some()
            && first
                .response
                .as_deref()
                .is_none_or(|response| validate_card_recognition_response(response).is_err())
    {
        return Err(IdentityError::IdentitySequenceViolation);
    }
    if record.outcome == IdentityOutcome::Pass {
        if record.observed_atr.as_deref() != Some(REGISTERED_J3R180_ATR.as_slice())
            || record.observed_protocol != Some(NegotiatedProtocol::T1)
            || record.disconnected != Some(true)
            || first.request.as_deref() != Some(CARD_RECOGNITION_COMMAND.as_slice())
            || second.request.as_deref() != Some(CPLC_COMMAND.as_slice())
        {
            return Err(IdentityError::IdentitySequenceViolation);
        }
        validate_card_recognition_response(
            first
                .response
                .as_deref()
                .ok_or(IdentityError::IdentitySequenceViolation)?,
        )?;
        validate_cplc_response(
            second
                .response
                .as_deref()
                .ok_or(IdentityError::IdentitySequenceViolation)?,
        )?;
        let expected = [
            IdentityOperation::EnumerateReaders,
            IdentityOperation::ExclusiveConnect,
            IdentityOperation::Reset,
            IdentityOperation::CaptureAtr,
            IdentityOperation::CaptureProtocol,
            IdentityOperation::TransmitCardRecognition,
            IdentityOperation::ReceiveCardRecognition,
            IdentityOperation::TransmitCplc,
            IdentityOperation::ReceiveCplc,
            IdentityOperation::Disconnect,
        ];
        if record.events.len() != expected.len()
            || record
                .events
                .iter()
                .zip(expected)
                .any(|(event, operation)| {
                    event.operation != operation || event.outcome != IdentityOutcome::Pass
                })
        {
            return Err(IdentityError::IdentitySequenceViolation);
        }
    }
    if record
        .observed_atr
        .as_deref()
        .is_some_and(|atr| atr.is_empty() || atr.len() > MAX_ATR_BYTES)
        || record.events.len() > 10
    {
        return Err(IdentityError::IdentitySequenceViolation);
    }
    Ok(())
}

pub fn validate_card_recognition_response(response: &[u8]) -> Result<(), IdentityError> {
    if response.len() > MAX_IDENTITY_RESPONSE_BYTES {
        return Err(IdentityError::CardRecognitionResponseTooLong);
    }
    if response.len() < 2 {
        return Err(IdentityError::CardRecognitionResponseTooShort);
    }
    if response[response.len() - 2..] != [0x90, 0x00] {
        return Err(IdentityError::CardRecognitionStatusRejected);
    }
    if response.len() < 5 {
        return Err(IdentityError::CardRecognitionResponseTooShort);
    }
    let body = &response[..response.len() - 2];
    if body[0] != 0x66 {
        return Err(IdentityError::CardRecognitionOuterTagMismatch);
    }
    let (header_length, value_length) = match body[1] {
        length @ 0x00..=0x7f => (2usize, usize::from(length)),
        0x81 if body.len() >= 3 && (0x80..=0xfd).contains(&body[2]) => {
            (3usize, usize::from(body[2]))
        }
        _ => return Err(IdentityError::CardRecognitionLengthMalformed),
    };
    let expected = header_length
        .checked_add(value_length)
        .ok_or(IdentityError::CardRecognitionLengthMalformed)?;
    if body.len() < expected {
        return Err(IdentityError::CardRecognitionLengthMalformed);
    }
    if body.len() > expected {
        return Err(IdentityError::CardRecognitionTrailingByte);
    }
    if value_length == 0 || body[header_length] != 0x73 {
        return Err(IdentityError::CardRecognitionFirstNestedTagMismatch);
    }
    Ok(())
}

pub fn validate_cplc_response(response: &[u8]) -> Result<(), IdentityError> {
    if response.len() < 2 {
        return Err(IdentityError::CplcResponseLengthMismatch);
    }
    if response[response.len() - 2..] != [0x90, 0x00] {
        return Err(IdentityError::CplcStatusRejected);
    }
    if response.len() != 47 {
        return Err(IdentityError::CplcResponseLengthMismatch);
    }
    if response[..2] != [0x9f, 0x7f] {
        return Err(IdentityError::CplcTagMismatch);
    }
    if response[2] != 0x2a {
        return Err(IdentityError::CplcLengthMismatch);
    }
    Ok(())
}
