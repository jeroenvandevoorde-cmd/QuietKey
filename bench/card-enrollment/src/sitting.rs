//! Fixed QK-DEC-165 applet sitting plans and fail-closed execution engine.

use core::fmt;
use std::panic::{catch_unwind, AssertUnwindSafe};
use std::path::{Path, PathBuf};

use crate::{EnrollmentMode, SittingTranscript, ValidatedMetadata, MAX_SITTING_TRANSCRIPT_BYTES};

pub const SITTING_PLAN_VERSION: &str = "1";
pub const SITTING_CAMPAIGN_SOURCE_COMMIT: &str = "17f3b26acc97930d94d5acec9d3b4dd83dcda31a";
pub const SITTING_APPLET_SOURCE_COMMIT: &str = "7e3407f8607f580f5f9df29ae28428d894b483f2";
pub const CANONICAL_CAP_BYTES: usize = 49_313;
pub const CANONICAL_CAP_SHA256: &str =
    "b20ba762d4c5b6c92f8f121980b425b295dcb2c2d3e4cad2a3b405be4efbb52f";
pub const GOLDEN_FIXTURE_PATH: &str = "host/qk-card-protocol/tests/fixtures/card_protocol_v1.txt";
pub const GOLDEN_FIXTURE_BYTES: usize = 17_919;
pub const GOLDEN_FIXTURE_LF: usize = 94;
pub const GOLDEN_FIXTURE_SHA256: &str =
    "5019c642ec61c1042043c0b325658e06d54bbcd3648c2e168b742e9af139bbe4";
pub const GOLDEN_FIXTURE_BLOB: &str = "a43001772504ca62180893958d6c23a28be51430";
pub const SITTING_READER_NAME: &[u8] = b"Identive SCR33xx v2.0 USB SC Reader";
pub const MAX_SITTING_REQUEST_BYTES: usize = 221;
pub const MAX_SITTING_RESPONSE_BYTES: usize = 218;
pub const MAX_SITTING_CAPTURE_BYTES: usize = 258;

const INSTALL_PLAN: &str = include_str!("../tests/fixtures/sitting_install_v1.tsv");
const PROVISION_PLAN: &str = include_str!("../tests/fixtures/sitting_provision_v1.tsv");

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SittingMode {
    InstallInfo,
    ProvisionGolden,
}

impl SittingMode {
    pub fn parse(value: &str) -> Result<Self, SittingError> {
        match value {
            "install-info" => Ok(Self::InstallInfo),
            "provision-golden" => Ok(Self::ProvisionGolden),
            _ => Err(SittingError::SittingModeRejected),
        }
    }

    pub const fn as_str(self) -> &'static str {
        match self {
            Self::InstallInfo => "install-info",
            Self::ProvisionGolden => "provision-golden",
        }
    }

    const fn expected_exchanges(self) -> usize {
        match self {
            Self::InstallInfo => 3,
            Self::ProvisionGolden => 17,
        }
    }

    const fn fixture(self) -> &'static str {
        match self {
            Self::InstallInfo => INSTALL_PLAN,
            Self::ProvisionGolden => PROVISION_PLAN,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SittingError {
    SittingModeRejected,
    SittingBindingMismatch,
    SittingOutputPathRejected,
    SittingOutputNameMismatch,
    SittingOutputCreateFailed,
    SittingOutputWriteFailed,
    SittingOutputFlushFailed,
    SittingContextUnavailable,
    SittingReaderEnumerationFailed,
    SittingReaderListTooLarge,
    SittingReaderCountExceeded,
    SittingReaderNameRejected,
    SittingSelectedReaderMissing,
    SittingSelectedReaderDuplicate,
    SittingConnectFailed,
    SittingResetFailed,
    SittingStatusFailed,
    SittingAtrRejected,
    SittingProtocolMismatch,
    SittingTransmitFailed,
    SittingResponseCaptureExceeded,
    SittingResponseLimitExceeded,
    SittingResponseMismatch,
    SittingDisconnectFailed,
    SittingBoundaryPanicked,
    SittingSequenceViolation,
    SittingTranscriptTooLarge,
}

impl SittingError {
    pub const fn name(self) -> &'static str {
        match self {
            Self::SittingModeRejected => "SittingModeRejected",
            Self::SittingBindingMismatch => "SittingBindingMismatch",
            Self::SittingOutputPathRejected => "SittingOutputPathRejected",
            Self::SittingOutputNameMismatch => "SittingOutputNameMismatch",
            Self::SittingOutputCreateFailed => "SittingOutputCreateFailed",
            Self::SittingOutputWriteFailed => "SittingOutputWriteFailed",
            Self::SittingOutputFlushFailed => "SittingOutputFlushFailed",
            Self::SittingContextUnavailable => "SittingContextUnavailable",
            Self::SittingReaderEnumerationFailed => "SittingReaderEnumerationFailed",
            Self::SittingReaderListTooLarge => "SittingReaderListTooLarge",
            Self::SittingReaderCountExceeded => "SittingReaderCountExceeded",
            Self::SittingReaderNameRejected => "SittingReaderNameRejected",
            Self::SittingSelectedReaderMissing => "SittingSelectedReaderMissing",
            Self::SittingSelectedReaderDuplicate => "SittingSelectedReaderDuplicate",
            Self::SittingConnectFailed => "SittingConnectFailed",
            Self::SittingResetFailed => "SittingResetFailed",
            Self::SittingStatusFailed => "SittingStatusFailed",
            Self::SittingAtrRejected => "SittingAtrRejected",
            Self::SittingProtocolMismatch => "SittingProtocolMismatch",
            Self::SittingTransmitFailed => "SittingTransmitFailed",
            Self::SittingResponseCaptureExceeded => "SittingResponseCaptureExceeded",
            Self::SittingResponseLimitExceeded => "SittingResponseLimitExceeded",
            Self::SittingResponseMismatch => "SittingResponseMismatch",
            Self::SittingDisconnectFailed => "SittingDisconnectFailed",
            Self::SittingBoundaryPanicked => "SittingBoundaryPanicked",
            Self::SittingSequenceViolation => "SittingSequenceViolation",
            Self::SittingTranscriptTooLarge => "SittingTranscriptTooLarge",
        }
    }
}

impl fmt::Display for SittingError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.name())
    }
}

impl std::error::Error for SittingError {}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SittingOutcome {
    Pass,
    Reject(SittingError),
}

impl SittingOutcome {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Pass => "PASS",
            Self::Reject(error) => error.name(),
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SittingMetadata {
    mode: SittingMode,
    enrollment: ValidatedMetadata,
    output_path: PathBuf,
}

impl SittingMetadata {
    pub fn new(
        mode: SittingMode,
        enrollment: ValidatedMetadata,
        output_path: PathBuf,
    ) -> Result<Self, SittingError> {
        validate_sitting_binding(&enrollment)?;
        validate_sitting_output_path(
            mode,
            &enrollment.inner().timestamp_utc,
            output_path.as_path(),
        )?;
        Ok(Self {
            mode,
            enrollment,
            output_path,
        })
    }

    pub const fn mode(&self) -> SittingMode {
        self.mode
    }

    pub fn output_path(&self) -> &Path {
        self.output_path.as_path()
    }

    pub(crate) fn enrollment(&self) -> &ValidatedMetadata {
        &self.enrollment
    }
}

pub fn validate_sitting_binding(metadata: &ValidatedMetadata) -> Result<(), SittingError> {
    let metadata = metadata.inner();
    if metadata.mode != EnrollmentMode::Enroll
        || metadata.host_alias != "iMac"
        || metadata.reader_alias != "SCR3310-01"
        || metadata.specimen_alias.as_deref() != Some("J3R180-02")
        || metadata.selected_reader_name.as_deref() != Some(SITTING_READER_NAME)
        || metadata.source_commit != SITTING_CAMPAIGN_SOURCE_COMMIT
    {
        return Err(SittingError::SittingBindingMismatch);
    }
    Ok(())
}

pub fn sitting_output_basename(mode: SittingMode, timestamp_utc: &str) -> String {
    format!(
        "qk-card-sitting-v1__{}__J3R180-02__{timestamp_utc}.txt",
        mode.as_str()
    )
}

pub fn validate_sitting_output_path(
    mode: SittingMode,
    timestamp_utc: &str,
    path: &Path,
) -> Result<(), SittingError> {
    if !path.is_absolute() || path.parent().is_none() {
        return Err(SittingError::SittingOutputPathRejected);
    }
    let Some(name) = path.file_name().and_then(|name| name.to_str()) else {
        return Err(SittingError::SittingOutputPathRejected);
    };
    if name != sitting_output_basename(mode, timestamp_utc) {
        return Err(SittingError::SittingOutputNameMismatch);
    }
    Ok(())
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SittingExchange {
    index: usize,
    phase: String,
    name: String,
    request: Vec<u8>,
    expected_response: Vec<u8>,
}

impl SittingExchange {
    pub const fn index(&self) -> usize {
        self.index
    }

    pub fn phase(&self) -> &str {
        &self.phase
    }

    pub fn name(&self) -> &str {
        &self.name
    }

    pub fn request(&self) -> &[u8] {
        &self.request
    }

    pub fn expected_response(&self) -> &[u8] {
        &self.expected_response
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SittingPlan {
    mode: SittingMode,
    exchanges: Vec<SittingExchange>,
}

impl SittingPlan {
    pub const fn mode(&self) -> SittingMode {
        self.mode
    }

    pub fn exchanges(&self) -> &[SittingExchange] {
        &self.exchanges
    }
}

pub fn fixed_sitting_plan(mode: SittingMode) -> Result<SittingPlan, SittingError> {
    let fixture = mode.fixture();
    if !fixture.is_ascii() || !fixture.ends_with('\n') || fixture.contains('\r') {
        return Err(SittingError::SittingSequenceViolation);
    }
    let mut header_seen = false;
    let mut exchanges = Vec::with_capacity(mode.expected_exchanges());
    for line in fixture.lines() {
        if line.starts_with('#') {
            if header_seen {
                return Err(SittingError::SittingSequenceViolation);
            }
            continue;
        }
        if !header_seen {
            if line != "index\tphase\tname\trequest_hex\tresponse_hex" {
                return Err(SittingError::SittingSequenceViolation);
            }
            header_seen = true;
            continue;
        }
        let mut fields = line.split('\t');
        let index = fields
            .next()
            .and_then(|value| value.parse::<usize>().ok())
            .ok_or(SittingError::SittingSequenceViolation)?;
        let phase = fields
            .next()
            .ok_or(SittingError::SittingSequenceViolation)?;
        let name = fields
            .next()
            .ok_or(SittingError::SittingSequenceViolation)?;
        let request = decode_lower_hex(
            fields
                .next()
                .ok_or(SittingError::SittingSequenceViolation)?,
        )?;
        let expected_response = decode_lower_hex(
            fields
                .next()
                .ok_or(SittingError::SittingSequenceViolation)?,
        )?;
        if fields.next().is_some()
            || index != exchanges.len()
            || phase.is_empty()
            || name.is_empty()
            || request.len() > MAX_SITTING_REQUEST_BYTES
            || expected_response.len() > MAX_SITTING_RESPONSE_BYTES
            || request.get(1) == Some(&0x15)
        {
            return Err(SittingError::SittingSequenceViolation);
        }
        exchanges.push(SittingExchange {
            index,
            phase: phase.to_owned(),
            name: name.to_owned(),
            request,
            expected_response,
        });
    }
    if !header_seen
        || exchanges.len() != mode.expected_exchanges()
        || !plan_shape_is_exact(mode, &exchanges)
    {
        return Err(SittingError::SittingSequenceViolation);
    }
    Ok(SittingPlan { mode, exchanges })
}

fn decode_lower_hex(value: &str) -> Result<Vec<u8>, SittingError> {
    if value.is_empty()
        || !value.len().is_multiple_of(2)
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err(SittingError::SittingSequenceViolation);
    }
    let (pairs, remainder) = value.as_bytes().as_chunks::<2>();
    if !remainder.is_empty() {
        return Err(SittingError::SittingSequenceViolation);
    }
    pairs
        .iter()
        .map(|pair| {
            let high = hex_digit(pair[0])?;
            let low = hex_digit(pair[1])?;
            Ok((high << 4) | low)
        })
        .collect()
}

fn hex_digit(byte: u8) -> Result<u8, SittingError> {
    match byte {
        b'0'..=b'9' => Ok(byte - b'0'),
        b'a'..=b'f' => Ok(byte - b'a' + 10),
        _ => Err(SittingError::SittingSequenceViolation),
    }
}

fn plan_shape_is_exact(mode: SittingMode, exchanges: &[SittingExchange]) -> bool {
    let expected: &[(&str, &str)] = match mode {
        SittingMode::InstallInfo => &[
            ("install", "select"),
            ("install", "setup-open"),
            ("install", "setup-info"),
        ],
        SittingMode::ProvisionGolden => &[
            ("provision", "select"),
            ("provision", "setup-open"),
            ("provision", "setup-begin"),
            ("provision", "setup-write-0"),
            ("provision", "setup-write-192"),
            ("provision", "setup-write-384"),
            ("provision", "setup-write-576"),
            ("provision", "setup-write-768"),
            ("provision", "setup-commit"),
            ("readback", "select"),
            ("readback", "setup-open"),
            ("readback", "setup-info"),
            ("readback", "read-d1-0"),
            ("readback", "read-d1-192"),
            ("readback", "read-d2-0"),
            ("readback", "read-d2-192"),
            ("readback", "export-a2-purpose-01"),
        ],
    };
    exchanges
        .iter()
        .zip(expected)
        .all(|(exchange, (phase, name))| exchange.phase == *phase && exchange.name == *name)
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SittingTransportFailure {
    Failed,
    CaptureExceeded,
    BoundaryPanicked,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SittingRunSummary {
    pub transmit_calls: usize,
    pub received_responses: usize,
    pub outcome: SittingOutcome,
}

pub fn run_fixed_sitting_plan<W, F>(
    plan: &SittingPlan,
    transcript: &mut SittingTranscript<W>,
    mut exchange_call: F,
) -> SittingRunSummary
where
    W: std::io::Write,
    F: FnMut(&[u8], &mut [u8; MAX_SITTING_CAPTURE_BYTES]) -> Result<usize, SittingTransportFailure>,
{
    let mut summary = SittingRunSummary {
        transmit_calls: 0,
        received_responses: 0,
        outcome: SittingOutcome::Pass,
    };
    for exchange in plan.exchanges() {
        if let Err(error) = transcript.record_request(exchange) {
            summary.outcome = SittingOutcome::Reject(error);
            return summary;
        }
        let mut response = [0u8; MAX_SITTING_CAPTURE_BYTES];
        summary.transmit_calls += 1;
        let call_result = catch_unwind(AssertUnwindSafe(|| {
            exchange_call(exchange.request(), &mut response)
        }));
        let response_len = match call_result {
            Ok(Ok(length)) if length <= response.len() => length,
            Ok(Ok(_)) | Ok(Err(SittingTransportFailure::CaptureExceeded)) => {
                return reject_run(
                    summary,
                    transcript,
                    exchange,
                    SittingError::SittingResponseCaptureExceeded,
                );
            }
            Ok(Err(SittingTransportFailure::Failed)) => {
                return reject_run(
                    summary,
                    transcript,
                    exchange,
                    SittingError::SittingTransmitFailed,
                );
            }
            Ok(Err(SittingTransportFailure::BoundaryPanicked)) | Err(_) => {
                return reject_run(
                    summary,
                    transcript,
                    exchange,
                    SittingError::SittingBoundaryPanicked,
                );
            }
        };
        summary.received_responses += 1;
        if let Err(error) = transcript.record_response(exchange, &response[..response_len]) {
            summary.outcome = SittingOutcome::Reject(error);
            return summary;
        }
        if response_len > MAX_SITTING_RESPONSE_BYTES {
            return reject_run(
                summary,
                transcript,
                exchange,
                SittingError::SittingResponseLimitExceeded,
            );
        }
        if response[..response_len] != *exchange.expected_response() {
            return reject_run(
                summary,
                transcript,
                exchange,
                SittingError::SittingResponseMismatch,
            );
        }
        if let Err(error) = transcript.record_comparison(exchange, SittingOutcome::Pass) {
            summary.outcome = SittingOutcome::Reject(error);
            return summary;
        }
    }
    summary
}

fn reject_run<W: std::io::Write>(
    mut summary: SittingRunSummary,
    transcript: &mut SittingTranscript<W>,
    exchange: &SittingExchange,
    error: SittingError,
) -> SittingRunSummary {
    summary.outcome = SittingOutcome::Reject(error);
    let _ = transcript.record_comparison(exchange, summary.outcome);
    summary
}

const _: () = assert!(MAX_SITTING_TRANSCRIPT_BYTES == 32_768);
