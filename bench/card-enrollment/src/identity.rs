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
    if validate_identity_record(&record).is_err() {
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

pub(crate) fn validate_identity_record(record: &IdentityRecord) -> Result<(), IdentityError> {
    if record.metadata.inner().mode != EnrollmentMode::Enroll
        || record.events.len() > 10
        || record.readers.len() > MAX_READERS
    {
        return sequence_violation();
    }
    let list_bytes = record.readers.iter().try_fold(1usize, |total, reader| {
        total.checked_add(reader.len())?.checked_add(1)
    });
    if list_bytes.is_none_or(|length| length > MAX_READER_LIST_BYTES) {
        return sequence_violation();
    }

    if record.events.is_empty() {
        if !record.readers.is_empty()
            || record.observed_atr.is_some()
            || record.observed_protocol.is_some()
            || record
                .exchanges
                .iter()
                .any(|exchange| exchange.request.is_some() || exchange.response.is_some())
            || record.disconnected.is_some()
            || !matches!(
                record.outcome,
                IdentityOutcome::Reject(
                    IdentityError::ContextUnavailable | IdentityError::BoundaryPanicked
                )
            )
        {
            return sequence_violation();
        }
        return Ok(());
    }

    let enumeration = record.events[0];
    if enumeration.operation != IdentityOperation::EnumerateReaders {
        return sequence_violation();
    }
    if let IdentityOutcome::Reject(error) = enumeration.outcome {
        if record.events.len() != 1
            || record.outcome != enumeration.outcome
            || record.observed_atr.is_some()
            || record.observed_protocol.is_some()
            || record
                .exchanges
                .iter()
                .any(|exchange| exchange.request.is_some() || exchange.response.is_some())
            || record.disconnected.is_some()
            || !valid_enumeration_rejection(error, &record.readers)
        {
            return sequence_violation();
        }
        return Ok(());
    }

    if record
        .readers
        .iter()
        .any(|reader| validate_reader_name(reader).is_err())
    {
        return sequence_violation();
    }
    let selected = record
        .metadata
        .inner()
        .selected_reader_name
        .as_deref()
        .ok_or(IdentityError::IdentitySequenceViolation)?;
    let selected_count = record
        .readers
        .iter()
        .filter(|reader| reader.as_slice() == selected)
        .count();
    if record.events.len() == 1 {
        let expected = match selected_count {
            0 => IdentityError::SelectedReaderMissing,
            1 => return sequence_violation(),
            _ => IdentityError::SelectedReaderDuplicate,
        };
        if record.outcome != IdentityOutcome::Reject(expected)
            || record.observed_atr.is_some()
            || record.observed_protocol.is_some()
            || record
                .exchanges
                .iter()
                .any(|exchange| exchange.request.is_some() || exchange.response.is_some())
            || record.disconnected.is_some()
        {
            return sequence_violation();
        }
        return Ok(());
    }
    if selected_count != 1 {
        return sequence_violation();
    }

    validate_event_sequence(record)?;
    validate_observations(record)?;
    validate_exchanges(record)?;
    validate_disconnect(record)?;

    let first_rejection = record.events.iter().find_map(|event| match event.outcome {
        IdentityOutcome::Pass => None,
        IdentityOutcome::Reject(error) => Some(error),
    });
    let expected_outcome = first_rejection.map_or(IdentityOutcome::Pass, IdentityOutcome::Reject);
    if record.outcome != expected_outcome {
        return sequence_violation();
    }
    Ok(())
}

fn validate_event_sequence(record: &IdentityRecord) -> Result<(), IdentityError> {
    const OPERATIONS: [IdentityOperation; 10] = [
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
    let mut expected_index = 0usize;
    let mut rejected = false;
    for (index, event) in record.events.iter().enumerate() {
        if rejected {
            if index + 1 != record.events.len() || event.operation != IdentityOperation::Disconnect
            {
                return sequence_violation();
            }
        } else if OPERATIONS.get(expected_index) != Some(&event.operation) {
            return sequence_violation();
        }
        match event.outcome {
            IdentityOutcome::Pass => {
                if rejected {
                    continue;
                }
                expected_index += 1;
            }
            IdentityOutcome::Reject(error) => {
                if !valid_operation_rejection(event.operation, error) {
                    return sequence_violation();
                }
                if event.operation == IdentityOperation::ExclusiveConnect
                    || event.operation == IdentityOperation::Disconnect
                {
                    if index + 1 != record.events.len() {
                        return sequence_violation();
                    }
                } else if !rejected
                    && (record.events.get(index + 1).map(|next| next.operation)
                        != Some(IdentityOperation::Disconnect)
                        || index + 2 != record.events.len())
                {
                    return sequence_violation();
                }
                rejected = true;
            }
        }
    }
    if !rejected && expected_index != OPERATIONS.len() {
        return sequence_violation();
    }
    Ok(())
}

fn validate_observations(record: &IdentityRecord) -> Result<(), IdentityError> {
    let atr_event = event_for(record, IdentityOperation::CaptureAtr);
    let protocol_event = event_for(record, IdentityOperation::CaptureProtocol);
    match atr_event.map(|event| event.outcome) {
        None => {
            if record.observed_atr.is_some() || record.observed_protocol.is_some() {
                return sequence_violation();
            }
        }
        Some(IdentityOutcome::Pass) => {
            if record.observed_atr.as_deref() != Some(REGISTERED_J3R180_ATR.as_slice()) {
                return sequence_violation();
            }
        }
        Some(IdentityOutcome::Reject(error)) => match error {
            IdentityError::StatusFailed | IdentityError::BoundaryPanicked => {
                if record.observed_atr.is_some() || record.observed_protocol.is_some() {
                    return sequence_violation();
                }
            }
            IdentityError::AtrEmpty => {
                if record.observed_atr.as_deref() != Some(&[]) {
                    return sequence_violation();
                }
            }
            IdentityError::AtrTooLong => {
                if record
                    .observed_atr
                    .as_deref()
                    .is_none_or(|atr| atr.len() <= MAX_ATR_BYTES)
                {
                    return sequence_violation();
                }
            }
            IdentityError::RegisteredAtrMismatch => {
                if record.observed_atr.as_deref().is_none_or(|atr| {
                    atr.is_empty()
                        || atr.len() > MAX_ATR_BYTES
                        || atr == REGISTERED_J3R180_ATR.as_slice()
                }) {
                    return sequence_violation();
                }
            }
            _ => return sequence_violation(),
        },
    }
    match protocol_event.map(|event| event.outcome) {
        None => {}
        Some(IdentityOutcome::Pass) => {
            if record.observed_protocol != Some(NegotiatedProtocol::T1) {
                return sequence_violation();
            }
        }
        Some(IdentityOutcome::Reject(IdentityError::ProtocolUnavailable)) => {
            if record.observed_protocol.is_some() {
                return sequence_violation();
            }
        }
        Some(IdentityOutcome::Reject(IdentityError::IdentityProtocolMismatch)) => {
            if !matches!(
                record.observed_protocol,
                Some(NegotiatedProtocol::T0 | NegotiatedProtocol::Raw)
            ) {
                return sequence_violation();
            }
        }
        Some(IdentityOutcome::Reject(_)) => return sequence_violation(),
    }
    Ok(())
}

fn validate_exchanges(record: &IdentityRecord) -> Result<(), IdentityError> {
    let first = &record.exchanges[0];
    let second = &record.exchanges[1];
    validate_exchange(
        event_for(record, IdentityOperation::TransmitCardRecognition),
        event_for(record, IdentityOperation::ReceiveCardRecognition),
        first,
        &CARD_RECOGNITION_COMMAND,
        validate_card_recognition_response,
    )?;
    validate_exchange(
        event_for(record, IdentityOperation::TransmitCplc),
        event_for(record, IdentityOperation::ReceiveCplc),
        second,
        &CPLC_COMMAND,
        validate_cplc_response,
    )?;
    Ok(())
}

fn validate_exchange(
    transmit: Option<&IdentityEvent>,
    receive: Option<&IdentityEvent>,
    exchange: &IdentityExchange,
    command: &[u8; 5],
    validate_response: fn(&[u8]) -> Result<(), IdentityError>,
) -> Result<(), IdentityError> {
    if transmit.is_none() {
        if exchange.request.is_some() || exchange.response.is_some() || receive.is_some() {
            return sequence_violation();
        }
        return Ok(());
    }
    if exchange.request.as_deref() != Some(command.as_slice()) {
        return sequence_violation();
    }
    match transmit.map(|event| event.outcome) {
        Some(IdentityOutcome::Pass) => {
            let response = exchange
                .response
                .as_deref()
                .ok_or(IdentityError::IdentitySequenceViolation)?;
            let receive = receive.ok_or(IdentityError::IdentitySequenceViolation)?;
            let parsed = validate_response(response);
            match (receive.outcome, parsed) {
                (IdentityOutcome::Pass, Ok(())) => {}
                (IdentityOutcome::Reject(recorded), Err(actual)) if recorded == actual => {}
                _ => return sequence_violation(),
            }
        }
        Some(IdentityOutcome::Reject(_)) => {
            if receive.is_some() || exchange.response.is_some() {
                return sequence_violation();
            }
        }
        None => return sequence_violation(),
    }
    Ok(())
}

fn validate_disconnect(record: &IdentityRecord) -> Result<(), IdentityError> {
    match event_for(record, IdentityOperation::Disconnect).map(|event| event.outcome) {
        None if record.disconnected.is_none() => Ok(()),
        Some(IdentityOutcome::Pass) if record.disconnected == Some(true) => Ok(()),
        Some(IdentityOutcome::Reject(
            IdentityError::DisconnectFailed | IdentityError::BoundaryPanicked,
        )) if record.disconnected == Some(false) => Ok(()),
        _ => sequence_violation(),
    }
}

fn valid_enumeration_rejection(error: IdentityError, readers: &[Vec<u8>]) -> bool {
    match error {
        IdentityError::ReaderEnumerationFailed
        | IdentityError::ReaderListTooLarge
        | IdentityError::ReaderCountExceeded
        | IdentityError::BoundaryPanicked
        | IdentityError::IdentitySequenceViolation => readers.is_empty(),
        IdentityError::ReaderNameEmpty
        | IdentityError::ReaderNameTooLong
        | IdentityError::ReaderNameContainsNul => {
            readers
                .iter()
                .find_map(|reader| validate_reader_name(reader).err())
                == Some(error)
        }
        _ => false,
    }
}

fn valid_operation_rejection(operation: IdentityOperation, error: IdentityError) -> bool {
    match operation {
        IdentityOperation::EnumerateReaders => false,
        IdentityOperation::ExclusiveConnect => matches!(
            error,
            IdentityError::ConnectFailed | IdentityError::BoundaryPanicked
        ),
        IdentityOperation::Reset => {
            matches!(
                error,
                IdentityError::ResetFailed | IdentityError::BoundaryPanicked
            )
        }
        IdentityOperation::CaptureAtr => matches!(
            error,
            IdentityError::StatusFailed
                | IdentityError::AtrEmpty
                | IdentityError::AtrTooLong
                | IdentityError::RegisteredAtrMismatch
                | IdentityError::BoundaryPanicked
        ),
        IdentityOperation::CaptureProtocol => matches!(
            error,
            IdentityError::ProtocolUnavailable | IdentityError::IdentityProtocolMismatch
        ),
        IdentityOperation::TransmitCardRecognition => matches!(
            error,
            IdentityError::CardRecognitionTransmitFailed
                | IdentityError::CardRecognitionResponseTooLong
                | IdentityError::BoundaryPanicked
        ),
        IdentityOperation::ReceiveCardRecognition => matches!(
            error,
            IdentityError::CardRecognitionResponseTooLong
                | IdentityError::CardRecognitionResponseTooShort
                | IdentityError::CardRecognitionStatusRejected
                | IdentityError::CardRecognitionOuterTagMismatch
                | IdentityError::CardRecognitionLengthMalformed
                | IdentityError::CardRecognitionTrailingByte
                | IdentityError::CardRecognitionFirstNestedTagMismatch
        ),
        IdentityOperation::TransmitCplc => matches!(
            error,
            IdentityError::CplcTransmitFailed
                | IdentityError::CplcResponseLengthMismatch
                | IdentityError::BoundaryPanicked
        ),
        IdentityOperation::ReceiveCplc => matches!(
            error,
            IdentityError::CplcResponseLengthMismatch
                | IdentityError::CplcStatusRejected
                | IdentityError::CplcTagMismatch
                | IdentityError::CplcLengthMismatch
        ),
        IdentityOperation::Disconnect => matches!(
            error,
            IdentityError::DisconnectFailed | IdentityError::BoundaryPanicked
        ),
    }
}

fn event_for(record: &IdentityRecord, operation: IdentityOperation) -> Option<&IdentityEvent> {
    record
        .events
        .iter()
        .find(|event| event.operation == operation)
}

fn sequence_violation<T>() -> Result<T, IdentityError> {
    Err(IdentityError::IdentitySequenceViolation)
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
