//! Fixed QK-DEC-165-SUP-001 management observation and mockable execution engine.

use core::fmt;
use std::io::Write;
use std::panic::{catch_unwind, AssertUnwindSafe};
use std::path::{Path, PathBuf};

use crate::{
    validate_card_recognition_response, validate_select_response, EnrollmentMode,
    ManagementObservationTranscript, NegotiatedProtocol, SittingError, SittingTransportFailure,
    ValidatedMetadata, MAX_ATR_BYTES, MAX_READERS, MAX_READER_LIST_BYTES, MAX_READER_NAME_BYTES,
    REGISTERED_J3R180_ATR, SITTING_READER_NAME,
};

pub const MANAGEMENT_OBSERVATION_MODE: &str = "management-observe";
pub const MAX_OBSERVATION_RESPONSE_BYTES: usize = 258;

pub const SELECT_ISD_COMMAND: [u8; 14] = [
    0x00, 0xa4, 0x04, 0x00, 0x08, 0xa0, 0x00, 0x00, 0x01, 0x51, 0x00, 0x00, 0x00, 0x00,
];
pub const MANAGEMENT_CARD_RECOGNITION_COMMAND: [u8; 5] = [0x80, 0xca, 0x00, 0x66, 0x00];
pub const INITIALIZE_UPDATE_COMMAND: [u8; 14] = [
    0x80, 0x50, 0x00, 0x00, 0x08, 0x51, 0x4b, 0x46, 0x38, 0x42, 0x33, 0x56, 0x31, 0x00,
];
pub const KEY_INFORMATION_TEMPLATE_COMMAND: [u8; 5] = [0x80, 0xca, 0x00, 0xe0, 0x00];

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ObservationPhase {
    WriteHeader,
    EstablishContext,
    EnumerateReaders,
    SelectReader,
    ExclusiveConnect,
    Reset,
    CaptureStatus,
    CaptureAtr,
    CaptureProtocol,
    SelectIsd,
    CardRecognition,
    InitializeUpdate,
    KeyInformation,
    Disconnect,
    Finalize,
}

impl ObservationPhase {
    pub const fn name(self) -> &'static str {
        match self {
            Self::WriteHeader => "WriteHeader",
            Self::EstablishContext => "EstablishContext",
            Self::EnumerateReaders => "EnumerateReaders",
            Self::SelectReader => "SelectReader",
            Self::ExclusiveConnect => "ExclusiveConnect",
            Self::Reset => "Reset",
            Self::CaptureStatus => "CaptureStatus",
            Self::CaptureAtr => "CaptureAtr",
            Self::CaptureProtocol => "CaptureProtocol",
            Self::SelectIsd => "SelectIsd",
            Self::CardRecognition => "CardRecognition",
            Self::InitializeUpdate => "InitializeUpdate",
            Self::KeyInformation => "KeyInformation",
            Self::Disconnect => "Disconnect",
            Self::Finalize => "Finalize",
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ObservationError {
    Sitting(SittingError),
    ObservationResponseLengthRejected,
    ObservationStatusRejected,
    ObservationTlvRejected,
    ObservationScpRejected,
    ObservationInitializeLengthRejected,
}

impl ObservationError {
    pub const fn name(self) -> &'static str {
        match self {
            Self::Sitting(error) => error.name(),
            Self::ObservationResponseLengthRejected => "ObservationResponseLengthRejected",
            Self::ObservationStatusRejected => "ObservationStatusRejected",
            Self::ObservationTlvRejected => "ObservationTlvRejected",
            Self::ObservationScpRejected => "ObservationScpRejected",
            Self::ObservationInitializeLengthRejected => "ObservationInitializeLengthRejected",
        }
    }
}

impl From<SittingError> for ObservationError {
    fn from(error: SittingError) -> Self {
        Self::Sitting(error)
    }
}

impl fmt::Display for ObservationError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.name())
    }
}

impl std::error::Error for ObservationError {}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ObservationOutcome {
    Pass,
    Reject(ObservationError),
}

impl ObservationOutcome {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Pass => "PASS",
            Self::Reject(error) => error.name(),
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ObservationFailure {
    pub phase: ObservationPhase,
    pub error: ObservationError,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct InitializationFields {
    pub body_len: usize,
    pub key_version: u8,
    pub scp_version: u8,
    pub scp_i: Option<u8>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ObservationStatus {
    pub atr: Vec<u8>,
    pub protocol: Option<NegotiatedProtocol>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ObservationSummary {
    pub transmit_calls: usize,
    pub received_responses: usize,
    pub initialization: Option<InitializationFields>,
    pub first_failure: Option<ObservationFailure>,
    pub disconnect: Option<ObservationOutcome>,
    pub outcome: ObservationOutcome,
}

impl ObservationSummary {
    const fn new() -> Self {
        Self {
            transmit_calls: 0,
            received_responses: 0,
            initialization: None,
            first_failure: None,
            disconnect: None,
            outcome: ObservationOutcome::Pass,
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ManagementObservationMetadata {
    enrollment: ValidatedMetadata,
    output_path: PathBuf,
}

impl ManagementObservationMetadata {
    pub fn new(
        enrollment: ValidatedMetadata,
        output_path: PathBuf,
    ) -> Result<Self, ObservationError> {
        validate_management_observation_binding(&enrollment)?;
        validate_management_observation_output_path(
            &enrollment.inner().timestamp_utc,
            output_path.as_path(),
        )?;
        Ok(Self {
            enrollment,
            output_path,
        })
    }

    pub fn output_path(&self) -> &Path {
        self.output_path.as_path()
    }

    pub(crate) const fn enrollment(&self) -> &ValidatedMetadata {
        &self.enrollment
    }
}

pub fn validate_management_observation_binding(
    metadata: &ValidatedMetadata,
) -> Result<(), ObservationError> {
    let metadata = metadata.inner();
    if metadata.mode != EnrollmentMode::Enroll
        || metadata.host_alias != "iMac"
        || metadata.reader_alias != "SCR3310-01"
        || metadata.specimen_alias.as_deref() != Some("J3R180-02")
        || metadata.selected_reader_name.as_deref() != Some(SITTING_READER_NAME)
    {
        return Err(SittingError::SittingBindingMismatch.into());
    }
    Ok(())
}

pub fn management_observation_output_basename(timestamp_utc: &str) -> String {
    format!("qk-card-sitting-v1__{MANAGEMENT_OBSERVATION_MODE}__J3R180-02__{timestamp_utc}.txt")
}

pub fn validate_management_observation_output_path(
    timestamp_utc: &str,
    path: &Path,
) -> Result<(), ObservationError> {
    if !path.is_absolute() || path.parent().is_none() {
        return Err(SittingError::SittingOutputPathRejected.into());
    }
    let Some(name) = path.file_name().and_then(|name| name.to_str()) else {
        return Err(SittingError::SittingOutputPathRejected.into());
    };
    if name != management_observation_output_basename(timestamp_utc) {
        return Err(SittingError::SittingOutputNameMismatch.into());
    }
    Ok(())
}

pub trait ManagementObservationBackend {
    fn establish_context(&mut self) -> Result<(), SittingError>;
    fn enumerate_readers(&mut self) -> Result<Vec<Vec<u8>>, SittingError>;
    fn connect_exclusive(&mut self, reader_name: &[u8]) -> Result<(), SittingError>;
    fn is_connected(&self) -> bool;
    fn reset(&mut self) -> Result<(), SittingError>;
    fn capture_status(&mut self) -> Result<ObservationStatus, SittingError>;
    fn exchange(
        &mut self,
        request: &[u8],
        response: &mut [u8; MAX_OBSERVATION_RESPONSE_BYTES],
    ) -> Result<usize, SittingTransportFailure>;
    fn disconnect_leave_card(&mut self) -> Result<(), SittingError>;
}

#[derive(Clone, Copy)]
struct FixedCommand {
    phase: ObservationPhase,
    request: &'static [u8],
}

const FIXED_COMMANDS: [FixedCommand; 4] = [
    FixedCommand {
        phase: ObservationPhase::SelectIsd,
        request: &SELECT_ISD_COMMAND,
    },
    FixedCommand {
        phase: ObservationPhase::CardRecognition,
        request: &MANAGEMENT_CARD_RECOGNITION_COMMAND,
    },
    FixedCommand {
        phase: ObservationPhase::InitializeUpdate,
        request: &INITIALIZE_UPDATE_COMMAND,
    },
    FixedCommand {
        phase: ObservationPhase::KeyInformation,
        request: &KEY_INFORMATION_TEMPLATE_COMMAND,
    },
];

pub fn run_management_observation<B, W>(
    metadata: &ManagementObservationMetadata,
    backend: &mut B,
    transcript: &mut ManagementObservationTranscript<W>,
) -> ObservationSummary
where
    B: ManagementObservationBackend,
    W: Write,
{
    let mut summary = ObservationSummary::new();
    let mut connection_attempted = false;

    if let Err(error) = transcript_call(|| transcript.write_header(metadata)) {
        reject(&mut summary, ObservationPhase::WriteHeader, error);
        return finish_run(backend, transcript, summary, connection_attempted);
    }
    if let Err(error) = record_pass(transcript, ObservationPhase::WriteHeader) {
        reject(&mut summary, ObservationPhase::WriteHeader, error);
        return finish_run(backend, transcript, summary, connection_attempted);
    }

    if let Err(error) = backend_sitting_call(|| backend.establish_context()) {
        reject_and_record(
            transcript,
            &mut summary,
            ObservationPhase::EstablishContext,
            error,
        );
        return finish_run(backend, transcript, summary, connection_attempted);
    }
    if let Err(error) = record_pass(transcript, ObservationPhase::EstablishContext) {
        reject(&mut summary, ObservationPhase::EstablishContext, error);
        return finish_run(backend, transcript, summary, connection_attempted);
    }

    let readers = match backend_sitting_call(|| backend.enumerate_readers()) {
        Ok(readers) => readers,
        Err(error) => {
            reject_and_record(
                transcript,
                &mut summary,
                ObservationPhase::EnumerateReaders,
                error,
            );
            return finish_run(backend, transcript, summary, connection_attempted);
        }
    };
    if let Err(error) = transcript_call(|| transcript.record_readers(&readers)) {
        reject(&mut summary, ObservationPhase::EnumerateReaders, error);
        return finish_run(backend, transcript, summary, connection_attempted);
    }
    if let Err(error) = validate_readers(&readers) {
        reject_and_record(
            transcript,
            &mut summary,
            ObservationPhase::EnumerateReaders,
            error,
        );
        return finish_run(backend, transcript, summary, connection_attempted);
    }
    if let Err(error) = record_pass(transcript, ObservationPhase::EnumerateReaders) {
        reject(&mut summary, ObservationPhase::EnumerateReaders, error);
        return finish_run(backend, transcript, summary, connection_attempted);
    }

    let selected_count = readers
        .iter()
        .filter(|reader| reader.as_slice() == SITTING_READER_NAME)
        .count();
    let selected_result = match selected_count {
        1 => Ok(()),
        0 => Err(SittingError::SittingSelectedReaderMissing.into()),
        _ => Err(SittingError::SittingSelectedReaderDuplicate.into()),
    };
    if let Err(error) = selected_result {
        reject_and_record(
            transcript,
            &mut summary,
            ObservationPhase::SelectReader,
            error,
        );
        return finish_run(backend, transcript, summary, connection_attempted);
    }
    if let Err(error) = record_pass(transcript, ObservationPhase::SelectReader) {
        reject(&mut summary, ObservationPhase::SelectReader, error);
        return finish_run(backend, transcript, summary, connection_attempted);
    }

    connection_attempted = true;
    if let Err(error) = backend_sitting_call(|| backend.connect_exclusive(SITTING_READER_NAME)) {
        reject_and_record(
            transcript,
            &mut summary,
            ObservationPhase::ExclusiveConnect,
            error,
        );
        return finish_run(backend, transcript, summary, connection_attempted);
    }
    if let Err(error) = record_pass(transcript, ObservationPhase::ExclusiveConnect) {
        reject(&mut summary, ObservationPhase::ExclusiveConnect, error);
        return finish_run(backend, transcript, summary, connection_attempted);
    }

    if let Err(error) = backend_sitting_call(|| backend.reset()) {
        reject_and_record(transcript, &mut summary, ObservationPhase::Reset, error);
        return finish_run(backend, transcript, summary, connection_attempted);
    }
    if let Err(error) = record_pass(transcript, ObservationPhase::Reset) {
        reject(&mut summary, ObservationPhase::Reset, error);
        return finish_run(backend, transcript, summary, connection_attempted);
    }

    let status = match backend_sitting_call(|| backend.capture_status()) {
        Ok(status) => status,
        Err(error) => {
            reject_and_record(
                transcript,
                &mut summary,
                ObservationPhase::CaptureStatus,
                error,
            );
            return finish_run(backend, transcript, summary, connection_attempted);
        }
    };
    if let Err(error) = transcript_call(|| transcript.record_status(&status.atr, status.protocol)) {
        reject(&mut summary, ObservationPhase::CaptureStatus, error);
        return finish_run(backend, transcript, summary, connection_attempted);
    }
    if status.atr.is_empty() || status.atr.len() > MAX_ATR_BYTES {
        let error = SittingError::SittingAtrRejected.into();
        reject_and_record(
            transcript,
            &mut summary,
            ObservationPhase::CaptureStatus,
            error,
        );
        return finish_run(backend, transcript, summary, connection_attempted);
    }
    if let Err(error) = record_pass(transcript, ObservationPhase::CaptureStatus) {
        reject(&mut summary, ObservationPhase::CaptureStatus, error);
        return finish_run(backend, transcript, summary, connection_attempted);
    }
    if status.atr != REGISTERED_J3R180_ATR {
        let error = SittingError::SittingAtrRejected.into();
        reject_and_record(
            transcript,
            &mut summary,
            ObservationPhase::CaptureAtr,
            error,
        );
        return finish_run(backend, transcript, summary, connection_attempted);
    }
    if let Err(error) = record_pass(transcript, ObservationPhase::CaptureAtr) {
        reject(&mut summary, ObservationPhase::CaptureAtr, error);
        return finish_run(backend, transcript, summary, connection_attempted);
    }
    if status.protocol != Some(NegotiatedProtocol::T1) {
        let error = SittingError::SittingProtocolMismatch.into();
        reject_and_record(
            transcript,
            &mut summary,
            ObservationPhase::CaptureProtocol,
            error,
        );
        return finish_run(backend, transcript, summary, connection_attempted);
    }
    if let Err(error) = record_pass(transcript, ObservationPhase::CaptureProtocol) {
        reject(&mut summary, ObservationPhase::CaptureProtocol, error);
        return finish_run(backend, transcript, summary, connection_attempted);
    }

    for (index, command) in FIXED_COMMANDS.iter().enumerate() {
        if let Err(error) =
            transcript_call(|| transcript.record_request(index, command.phase, command.request))
        {
            reject(&mut summary, command.phase, error);
            return finish_run(backend, transcript, summary, connection_attempted);
        }
        summary.transmit_calls += 1;
        let mut response = [0u8; MAX_OBSERVATION_RESPONSE_BYTES];
        let exchange_result = catch_unwind(AssertUnwindSafe(|| {
            backend.exchange(command.request, &mut response)
        }));
        let response_len = match exchange_result {
            Ok(Ok(length)) if length <= response.len() => length,
            Ok(Ok(_)) | Ok(Err(SittingTransportFailure::CaptureExceeded)) => {
                let error = ObservationError::ObservationResponseLengthRejected;
                reject_and_record(transcript, &mut summary, command.phase, error);
                return finish_run(backend, transcript, summary, connection_attempted);
            }
            Ok(Err(SittingTransportFailure::Failed)) => {
                let error = SittingError::SittingTransmitFailed.into();
                reject_and_record(transcript, &mut summary, command.phase, error);
                return finish_run(backend, transcript, summary, connection_attempted);
            }
            Ok(Err(SittingTransportFailure::BoundaryPanicked)) | Err(_) => {
                let error = SittingError::SittingBoundaryPanicked.into();
                reject_and_record(transcript, &mut summary, command.phase, error);
                return finish_run(backend, transcript, summary, connection_attempted);
            }
        };
        summary.received_responses += 1;
        let response = &response[..response_len];
        if let Err(error) =
            transcript_call(|| transcript.record_response(index, command.phase, response))
        {
            reject(&mut summary, command.phase, error);
            return finish_run(backend, transcript, summary, connection_attempted);
        }
        let initialization = match validate_response(command.phase, response) {
            Ok(initialization) => initialization,
            Err(error) => {
                reject_and_record(transcript, &mut summary, command.phase, error);
                return finish_run(backend, transcript, summary, connection_attempted);
            }
        };
        if let Some(fields) = initialization {
            summary.initialization = Some(fields);
            if let Err(error) = transcript_call(|| transcript.record_initialization_fields(&fields))
            {
                reject(&mut summary, command.phase, error);
                return finish_run(backend, transcript, summary, connection_attempted);
            }
        }
        if let Err(error) = record_pass(transcript, command.phase) {
            reject(&mut summary, command.phase, error);
            return finish_run(backend, transcript, summary, connection_attempted);
        }
    }

    finish_run(backend, transcript, summary, connection_attempted)
}

fn validate_readers(readers: &[Vec<u8>]) -> Result<(), ObservationError> {
    if readers.len() > MAX_READERS {
        return Err(SittingError::SittingReaderCountExceeded.into());
    }
    let list_bytes = readers.iter().try_fold(1usize, |total, reader| {
        total.checked_add(reader.len())?.checked_add(1)
    });
    if list_bytes.is_none_or(|length| length > MAX_READER_LIST_BYTES) {
        return Err(SittingError::SittingReaderListTooLarge.into());
    }
    if readers.iter().any(|reader| {
        reader.is_empty() || reader.len() > MAX_READER_NAME_BYTES || reader.contains(&0)
    }) {
        return Err(SittingError::SittingReaderNameRejected.into());
    }
    Ok(())
}

fn validate_response(
    phase: ObservationPhase,
    response: &[u8],
) -> Result<Option<InitializationFields>, ObservationError> {
    if !(2..=MAX_OBSERVATION_RESPONSE_BYTES).contains(&response.len()) {
        return Err(ObservationError::ObservationResponseLengthRejected);
    }
    if response[response.len() - 2..] != [0x90, 0x00] {
        return Err(ObservationError::ObservationStatusRejected);
    }
    match phase {
        ObservationPhase::SelectIsd => validate_select_response(response)
            .map(|()| None)
            .map_err(|_| ObservationError::ObservationTlvRejected),
        ObservationPhase::CardRecognition => validate_card_recognition_response(response)
            .map(|()| None)
            .map_err(|_| ObservationError::ObservationTlvRejected),
        ObservationPhase::InitializeUpdate => validate_initialize_update(response).map(Some),
        ObservationPhase::KeyInformation => {
            validate_complete_outer_tlv(&response[..response.len() - 2], 0xe0)?;
            Ok(None)
        }
        _ => Err(SittingError::SittingSequenceViolation.into()),
    }
}

fn validate_complete_outer_tlv(body: &[u8], expected_tag: u8) -> Result<(), ObservationError> {
    if body.len() < 2 || body[0] != expected_tag {
        return Err(ObservationError::ObservationTlvRejected);
    }
    let (header_len, value_len) = match body[1] {
        length @ 0x00..=0x7f => (2usize, usize::from(length)),
        0x81 if body.len() >= 3 && (0x80..=0xfd).contains(&body[2]) => {
            (3usize, usize::from(body[2]))
        }
        _ => return Err(ObservationError::ObservationTlvRejected),
    };
    if header_len.checked_add(value_len) != Some(body.len()) {
        return Err(ObservationError::ObservationTlvRejected);
    }
    Ok(())
}

fn validate_initialize_update(response: &[u8]) -> Result<InitializationFields, ObservationError> {
    let body = &response[..response.len() - 2];
    if body.len() < 12 {
        return Err(ObservationError::ObservationInitializeLengthRejected);
    }
    let key_version = body[10];
    let scp_version = body[11];
    let (expected_len, scp_i) = match scp_version {
        0x01 | 0x02 => (28usize, None),
        0x03 => {
            let Some(&scp_i) = body.get(12) else {
                return Err(ObservationError::ObservationInitializeLengthRejected);
            };
            let expected_len = 29usize
                + if scp_i & 0x01 != 0 { 16 } else { 0 }
                + if scp_i & 0x10 != 0 { 3 } else { 0 };
            (expected_len, Some(scp_i))
        }
        _ => return Err(ObservationError::ObservationScpRejected),
    };
    if body.len() != expected_len {
        return Err(ObservationError::ObservationInitializeLengthRejected);
    }
    Ok(InitializationFields {
        body_len: body.len(),
        key_version,
        scp_version,
        scp_i,
    })
}

fn backend_sitting_call<T, F>(call: F) -> Result<T, ObservationError>
where
    F: FnOnce() -> Result<T, SittingError>,
{
    match catch_unwind(AssertUnwindSafe(call)) {
        Ok(Ok(value)) => Ok(value),
        Ok(Err(error)) => Err(error.into()),
        Err(_) => Err(SittingError::SittingBoundaryPanicked.into()),
    }
}

fn transcript_call<F>(call: F) -> Result<(), ObservationError>
where
    F: FnOnce() -> Result<(), ObservationError>,
{
    match catch_unwind(AssertUnwindSafe(call)) {
        Ok(result) => result,
        Err(_) => Err(SittingError::SittingBoundaryPanicked.into()),
    }
}

fn record_pass<W: Write>(
    transcript: &mut ManagementObservationTranscript<W>,
    phase: ObservationPhase,
) -> Result<(), ObservationError> {
    transcript_call(|| transcript.record_event(phase, ObservationOutcome::Pass))
}

fn reject(summary: &mut ObservationSummary, phase: ObservationPhase, error: ObservationError) {
    if summary.first_failure.is_none() {
        summary.first_failure = Some(ObservationFailure { phase, error });
        summary.outcome = ObservationOutcome::Reject(error);
    }
}

fn reject_and_record<W: Write>(
    transcript: &mut ManagementObservationTranscript<W>,
    summary: &mut ObservationSummary,
    phase: ObservationPhase,
    error: ObservationError,
) {
    reject(summary, phase, error);
    if let Err(later) =
        transcript_call(|| transcript.record_event(phase, ObservationOutcome::Reject(error)))
    {
        reject(summary, phase, later);
    }
}

fn finish_run<B, W>(
    backend: &mut B,
    transcript: &mut ManagementObservationTranscript<W>,
    mut summary: ObservationSummary,
    connection_attempted: bool,
) -> ObservationSummary
where
    B: ManagementObservationBackend,
    W: Write,
{
    if let Err(error) = transcript_call(|| {
        transcript.record_counts(summary.transmit_calls, summary.received_responses)
    }) {
        reject(&mut summary, ObservationPhase::Finalize, error);
    }

    let should_disconnect = if connection_attempted {
        match catch_unwind(AssertUnwindSafe(|| backend.is_connected())) {
            Ok(connected) => connected,
            Err(_) => {
                reject(
                    &mut summary,
                    ObservationPhase::Disconnect,
                    SittingError::SittingBoundaryPanicked.into(),
                );
                true
            }
        }
    } else {
        false
    };
    if should_disconnect {
        let disconnect_outcome = match backend_sitting_call(|| backend.disconnect_leave_card()) {
            Ok(()) => ObservationOutcome::Pass,
            Err(error) => {
                reject(&mut summary, ObservationPhase::Disconnect, error);
                ObservationOutcome::Reject(error)
            }
        };
        summary.disconnect = Some(disconnect_outcome);
        if let Err(error) = transcript_call(|| transcript.record_disconnect(disconnect_outcome)) {
            reject(&mut summary, ObservationPhase::Disconnect, error);
        }
    } else if let Err(error) = transcript_call(|| transcript.record_disconnect_none()) {
        reject(&mut summary, ObservationPhase::Disconnect, error);
    }

    if let Err(error) =
        transcript_call(|| transcript.record_first_failure(summary.first_failure.as_ref()))
    {
        reject(&mut summary, ObservationPhase::Finalize, error);
    }
    if let Err(error) = transcript_call(|| transcript.record_result(summary.outcome)) {
        reject(&mut summary, ObservationPhase::Finalize, error);
    }
    summary
}

const _: () = assert!(MAX_OBSERVATION_RESPONSE_BYTES == 258);
