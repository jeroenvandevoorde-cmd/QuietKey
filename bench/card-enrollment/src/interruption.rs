//! Fixed public-GOLDEN interruption observations; no physical atomicity claim.

use std::ffi::OsStr;
use std::fmt;
use std::io::Write;
use std::panic::{catch_unwind, AssertUnwindSafe};
use std::path::{Path, PathBuf};

use crate::sitting::{validate_named_output_path, validate_specimen_binding};
use crate::{
    InterruptionTranscript, NegotiatedProtocol, ObservationStatus, SittingError, ValidatedMetadata,
    MAX_READERS, MAX_READER_LIST_BYTES, MAX_READER_NAME_BYTES, MAX_SITTING_CAPTURE_BYTES,
    MAX_SITTING_REQUEST_BYTES, MAX_SITTING_RESPONSE_BYTES, REGISTERED_J3R180_ATR,
    SITTING_READER_NAME,
};

pub const INTERRUPTION_PLAN: &str = include_str!("../tests/fixtures/sitting_interruption_v1.tsv");
pub const INTERRUPTION_PLAN_BYTES: usize = 13_506;
pub const INTERRUPTION_PLAN_LF: usize = 57;
pub const INTERRUPTION_PLAN_SHA256: &str =
    "48c57da772e4e57e955add911e528403881e211eabb37743d5bd59ed6c075cbc";
pub const INTERRUPTION_TOOL_VERSION: &str = "0.0.8";
pub const REMOVAL_WAIT_ENV: &str = "QK_CARD_REMOVAL_WAIT_MS";

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum InterruptionMode {
    InterruptGolden,
    ClassifyGolden,
    AbortStagingGolden,
}
impl InterruptionMode {
    pub fn parse(value: &str) -> Result<Self, InterruptionError> {
        match value {
            "interrupt-golden" => Ok(Self::InterruptGolden),
            "classify-golden" => Ok(Self::ClassifyGolden),
            "abort-staging-golden" => Ok(Self::AbortStagingGolden),
            _ => Err(InterruptionError::ModeRejected),
        }
    }
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::InterruptGolden => "interrupt-golden",
            Self::ClassifyGolden => "classify-golden",
            Self::AbortStagingGolden => "abort-staging-golden",
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum InterruptionTrial {
    UnpowerFinalWrite,
    UnpowerSecondWrite,
    RemoveCommit1,
    RemoveCommit2,
}
impl InterruptionTrial {
    pub fn parse(value: &str) -> Result<Self, InterruptionError> {
        match value {
            "unpower-final-write" => Ok(Self::UnpowerFinalWrite),
            "unpower-second-write" => Ok(Self::UnpowerSecondWrite),
            "remove-commit-1" => Ok(Self::RemoveCommit1),
            "remove-commit-2" => Ok(Self::RemoveCommit2),
            _ => Err(InterruptionError::TrialRejected),
        }
    }
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::UnpowerFinalWrite => "unpower-final-write",
            Self::UnpowerSecondWrite => "unpower-second-write",
            Self::RemoveCommit1 => "remove-commit-1",
            Self::RemoveCommit2 => "remove-commit-2",
        }
    }
    pub const fn is_removal(self) -> bool {
        matches!(self, Self::RemoveCommit1 | Self::RemoveCommit2)
    }
    pub const fn checkpoint(self) -> &'static str {
        match self {
            Self::UnpowerFinalWrite => "after-final-write-781",
            Self::UnpowerSecondWrite => "after-second-write-384",
            Self::RemoveCommit1 | Self::RemoveCommit2 => "commit-dispatch",
        }
    }
    fn classifier(self) -> &'static str {
        match self {
            Self::UnpowerFinalWrite => "classifier-7",
            Self::UnpowerSecondWrite => "classifier-4",
            Self::RemoveCommit1 | Self::RemoveCommit2 => "classifier-8",
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RemovalWaitMs(u32);
impl RemovalWaitMs {
    pub fn parse(value: Option<&OsStr>) -> Result<Self, InterruptionError> {
        let value = value.ok_or(InterruptionError::RemovalWaitMissing)?;
        let value = value
            .to_str()
            .ok_or(InterruptionError::RemovalWaitInvalid)?;
        if value.is_empty() || value.len() > 10 || !value.bytes().all(|byte| byte.is_ascii_digit())
        {
            return Err(InterruptionError::RemovalWaitInvalid);
        }
        let value = value
            .parse::<u32>()
            .map_err(|_| InterruptionError::RemovalWaitInvalid)?;
        if !(1_000..=600_000).contains(&value) {
            return Err(InterruptionError::RemovalWaitInvalid);
        }
        Ok(Self(value))
    }
    pub const fn get(self) -> u32 {
        self.0
    }
}

pub fn removal_wait_for<F>(
    mode: InterruptionMode,
    trial: InterruptionTrial,
    read: F,
) -> Result<Option<RemovalWaitMs>, InterruptionError>
where
    F: FnOnce() -> Option<std::ffi::OsString>,
{
    if mode == InterruptionMode::InterruptGolden && trial.is_removal() {
        RemovalWaitMs::parse(read().as_deref()).map(Some)
    } else {
        Ok(None)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum InterruptionError {
    Sitting(SittingError),
    ModeRejected,
    TrialRejected,
    PlanRejected,
    RemovalWaitMissing,
    RemovalWaitInvalid,
    RemovalNotObserved,
    RemovalWaitTimedOut,
    ReaderStateRejected,
    ResponseRetired,
    LifecycleRejected,
    InfoRejected,
    RecoveryNotStaging,
    Native(pcsc::Error),
}
impl InterruptionError {
    pub const fn name(self) -> &'static str {
        match self {
            Self::Sitting(error) => error.name(),
            Self::ModeRejected => "InterruptionModeRejected",
            Self::TrialRejected => "InterruptionTrialRejected",
            Self::PlanRejected => "InterruptionPlanRejected",
            Self::RemovalWaitMissing => "InterruptionRemovalWaitMissing",
            Self::RemovalWaitInvalid => "InterruptionRemovalWaitInvalid",
            Self::RemovalNotObserved => "InterruptionRemovalNotObserved",
            Self::RemovalWaitTimedOut => "InterruptionRemovalWaitTimedOut",
            Self::ReaderStateRejected => "InterruptionReaderStateRejected",
            Self::ResponseRetired => "InterruptionResponseRetired",
            Self::InfoRejected => "InterruptionInfoRejected",
            Self::LifecycleRejected => "InterruptionLifecycleRejected",
            Self::RecoveryNotStaging => "InterruptionRecoveryNotStaging",
            Self::Native(_) => "InterruptionNativeFailure",
        }
    }
}
impl From<SittingError> for InterruptionError {
    fn from(value: SittingError) -> Self {
        Self::Sitting(value)
    }
}
impl fmt::Display for InterruptionError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.name())
    }
}
impl std::error::Error for InterruptionError {}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RawCardState {
    Unprovisioned,
    StagingIncomplete,
    StagingComplete,
    CommittedGolden,
}
impl RawCardState {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Unprovisioned => "UNPROVISIONED",
            Self::StagingIncomplete => "STAGING_INCOMPLETE",
            Self::StagingComplete => "STAGING_COMPLETE",
            Self::CommittedGolden => "COMMITTED_GOLDEN",
        }
    }
    fn branch(self) -> &'static str {
        match self {
            Self::Unprovisioned => "info-unprovisioned",
            Self::StagingIncomplete => "info-staging-incomplete",
            Self::StagingComplete => "info-staging-complete",
            Self::CommittedGolden => "info-committed",
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum InterruptionOutcome {
    Interrupted,
    Classified(RawCardState),
    RecoveredUnprovisioned,
    Reject(InterruptionError),
}
impl InterruptionOutcome {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Interrupted => "INTERRUPTION_RECORDED",
            Self::Classified(_) => "CLASSIFIED",
            Self::RecoveredUnprovisioned => "RECOVERED_UNPROVISIONED",
            Self::Reject(error) => error.name(),
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct InterruptionMetadata {
    pub(crate) mode: InterruptionMode,
    pub(crate) trial: InterruptionTrial,
    pub(crate) enrollment: ValidatedMetadata,
    output: PathBuf,
    pub(crate) removal_wait: Option<RemovalWaitMs>,
}
impl InterruptionMetadata {
    pub fn new(
        mode: InterruptionMode,
        trial: InterruptionTrial,
        enrollment: ValidatedMetadata,
        output: PathBuf,
        removal_wait: Option<RemovalWaitMs>,
    ) -> Result<Self, InterruptionError> {
        validate_specimen_binding(&enrollment, "J3R180-03")?;
        validate_named_output_path(
            &interruption_output_basename(mode, trial, &enrollment.inner().timestamp_utc),
            &output,
        )?;
        if (mode == InterruptionMode::InterruptGolden && trial.is_removal())
            != removal_wait.is_some()
        {
            return Err(InterruptionError::RemovalWaitMissing);
        }
        Ok(Self {
            mode,
            trial,
            enrollment,
            output,
            removal_wait,
        })
    }
    pub fn output_path(&self) -> &Path {
        &self.output
    }
    pub const fn needs_removal_wait(&self) -> bool {
        self.removal_wait.is_some()
    }
}
pub fn interruption_output_basename(
    mode: InterruptionMode,
    trial: InterruptionTrial,
    utc: &str,
) -> String {
    format!(
        "qk-card-sitting-v1__{}__{}__J3R180-03__{utc}.txt",
        mode.as_str(),
        trial.as_str()
    )
}

#[derive(Clone, Copy, Debug)]
pub struct InterruptionPlanRow {
    pub branch: &'static str,
    pub index: usize,
    pub name: &'static str,
    pub request_hex: &'static str,
    pub response_hex: &'static str,
}
pub fn interruption_plan() -> Result<Vec<InterruptionPlanRow>, InterruptionError> {
    let mut result = Vec::with_capacity(51);
    for line in INTERRUPTION_PLAN.lines().skip(6) {
        let fields: Vec<_> = line.split('\t').collect();
        if fields.len() != 5 || result.len() == 51 {
            return Err(InterruptionError::PlanRejected);
        }
        let index = fields[1]
            .parse()
            .map_err(|_| InterruptionError::PlanRejected)?;
        let valid_hex = |hex: &str, cap: usize| {
            !hex.is_empty()
                && hex.len().is_multiple_of(2)
                && hex.len() <= cap * 2
                && hex
                    .bytes()
                    .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
        };
        if !valid_hex(fields[3], MAX_SITTING_REQUEST_BYTES)
            || !valid_hex(fields[4], MAX_SITTING_RESPONSE_BYTES)
            || fields[3].get(2..4) == Some("15")
        {
            return Err(InterruptionError::PlanRejected);
        }
        result.push(InterruptionPlanRow {
            branch: fields[0],
            index,
            name: fields[2],
            request_hex: fields[3],
            response_hex: fields[4],
        });
    }
    if result.len() != 51 {
        return Err(InterruptionError::PlanRejected);
    }
    Ok(result)
}

pub trait InterruptionBackend {
    fn establish_context(&mut self) -> Result<(), InterruptionError>;
    fn enumerate_readers(&mut self) -> Result<Vec<Vec<u8>>, InterruptionError>;
    fn connect_exclusive(&mut self) -> Result<(), InterruptionError>;
    fn is_connected(&self) -> bool;
    fn capture_status(&mut self) -> Result<ObservationStatus, InterruptionError>;
    fn exchange(
        &mut self,
        request: &[u8],
        response: &mut [u8; MAX_SITTING_CAPTURE_BYTES],
    ) -> Result<usize, InterruptionError>;
    fn unpower(&mut self) -> Result<(), InterruptionError>;
    fn signal_removal(&mut self) -> Result<(), InterruptionError>;
    fn wait_removal(&mut self, timeout: RemovalWaitMs) -> Result<pcsc::State, InterruptionError>;
    fn disconnect_leave_card(&mut self) -> Result<(), InterruptionError>;
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct InterruptionSummary {
    pub transmit_calls: usize,
    pub received_responses: usize,
    pub outcome: InterruptionOutcome,
}

// Safe, testable cleanup of fixture/capture scratch; this is not a volatile-memory or Gate claim.
pub(crate) struct ClearOnDrop<'a, const N: usize>(pub(crate) &'a mut [u8; N]);
impl<const N: usize> Drop for ClearOnDrop<'_, N> {
    fn drop(&mut self) {
        self.0.fill(0);
        std::hint::black_box(&mut *self.0);
        std::sync::atomic::compiler_fence(std::sync::atomic::Ordering::SeqCst);
    }
}

fn decode(hex: &str, output: &mut [u8]) -> Result<usize, InterruptionError> {
    if hex.len() / 2 > output.len() || !hex.len().is_multiple_of(2) {
        return Err(InterruptionError::PlanRejected);
    }
    let digit = |b: u8| match b {
        b'0'..=b'9' => Ok(b - b'0'),
        b'a'..=b'f' => Ok(b - b'a' + 10),
        _ => Err(InterruptionError::PlanRejected),
    };
    for (n, pair) in hex.as_bytes().as_chunks::<2>().0.iter().enumerate() {
        output[n] = (digit(pair[0])? << 4) | digit(pair[1])?;
    }
    Ok(hex.len() / 2)
}

fn call<T>(f: impl FnOnce() -> Result<T, InterruptionError>) -> Result<T, InterruptionError> {
    catch_unwind(AssertUnwindSafe(f)).unwrap_or(Err(SittingError::SittingBoundaryPanicked.into()))
}

pub fn run_interruption<B: InterruptionBackend, W: Write>(
    metadata: &InterruptionMetadata,
    backend: &mut B,
    transcript: &mut InterruptionTranscript<W>,
) -> InterruptionSummary {
    let mut summary = InterruptionSummary {
        transmit_calls: 0,
        received_responses: 0,
        outcome: InterruptionOutcome::Reject(InterruptionError::PlanRejected),
    };
    let result = call(|| run_inner(metadata, backend, transcript, &mut summary));
    summary.outcome = result.unwrap_or_else(InterruptionOutcome::Reject);
    let disconnected = if backend.is_connected() {
        let result = call(|| backend.disconnect_leave_card());
        if let Err(error) = result {
            retain_first(&mut summary.outcome, error);
        }
        transcript.boundary("disconnect", result)
    } else {
        transcript.field("disconnect", "NO_LOCAL_CARD_HANDLE")
    };
    if let Err(error) = disconnected {
        retain_first(&mut summary.outcome, error);
    }
    if let Err(error) = transcript.finish(&summary) {
        retain_first(&mut summary.outcome, error);
    }
    summary
}

fn retain_first(outcome: &mut InterruptionOutcome, error: InterruptionError) {
    if !matches!(outcome, InterruptionOutcome::Reject(_)) {
        *outcome = InterruptionOutcome::Reject(error);
    }
}

fn run_inner<B: InterruptionBackend, W: Write>(
    m: &InterruptionMetadata,
    b: &mut B,
    t: &mut InterruptionTranscript<W>,
    s: &mut InterruptionSummary,
) -> Result<InterruptionOutcome, InterruptionError> {
    t.header(m)?;
    let plan = interruption_plan()?;
    let context = call(|| b.establish_context());
    let recorded = t.boundary("EstablishContext", context);
    context?;
    recorded?;
    let readers = call(|| b.enumerate_readers())?;
    if readers.len() > MAX_READERS {
        return Err(SittingError::SittingReaderCountExceeded.into());
    }
    let mut total = 1usize;
    for reader in &readers {
        if reader.is_empty() || reader.len() > MAX_READER_NAME_BYTES || reader.contains(&0) {
            return Err(SittingError::SittingReaderNameRejected.into());
        }
        total = total
            .checked_add(reader.len() + 1)
            .ok_or(SittingError::SittingReaderListTooLarge)?;
    }
    if total > MAX_READER_LIST_BYTES {
        return Err(SittingError::SittingReaderListTooLarge.into());
    }
    t.readers(&readers)?;
    match readers
        .iter()
        .filter(|r| r.as_slice() == SITTING_READER_NAME)
        .count()
    {
        0 => return Err(SittingError::SittingSelectedReaderMissing.into()),
        1 => {}
        _ => return Err(SittingError::SittingSelectedReaderDuplicate.into()),
    }
    let connected = call(|| b.connect_exclusive());
    let recorded = t.boundary("ExclusiveConnect", connected);
    connected?;
    recorded?;
    let status = call(|| b.capture_status())?;
    t.observation(&status)?;
    if status.atr != REGISTERED_J3R180_ATR {
        return Err(SittingError::SittingAtrRejected.into());
    }
    if status.protocol != Some(NegotiatedProtocol::T1) {
        return Err(SittingError::SittingProtocolMismatch.into());
    }
    if m.mode == InterruptionMode::InterruptGolden {
        for row in plan.iter().filter(|row| row.branch == m.trial.as_str()) {
            let commit = m.trial.is_removal() && row.index == 8;
            exchange(
                row,
                b,
                t,
                s,
                if commit {
                    Match::CommitRemoval
                } else {
                    Match::Exact
                },
            )?;
        }
        if let Some(timeout) = m.removal_wait {
            let result = call(|| b.wait_removal(timeout));
            if let Ok(state) = result {
                t.field("removal_event_state", &format!("{:#x}", state.bits()))?;
            }
            let observed = result.and_then(validate_removal_state);
            let recorded = t.boundary("removal_wait_outcome", observed);
            observed?;
            recorded?;
            t.field(
                "boundary_observation",
                "reader reported EMPTY after COMMIT dispatch",
            )?;
        } else {
            t.field("requested_disposition", "UnpowerCard")?;
            let result = call(|| b.unpower());
            let recorded = t.boundary("unpower_return", result);
            result?;
            recorded?;
            t.field(
                "boundary_observation",
                "UnpowerCard request returned; physical effect unproven",
            )?;
        }
        return Ok(InterruptionOutcome::Interrupted);
    }
    for row in plan.iter().filter(|row| row.branch == m.trial.classifier()) {
        exchange(row, b, t, s, Match::Exact)?;
        if row.index == 1 {
            t.field(
                "session_observation",
                "old session rejected after reselection",
            )?;
        }
    }
    let info = plan
        .iter()
        .find(|row| row.branch == "info-unprovisioned")
        .ok_or(InterruptionError::PlanRejected)?;
    let state =
        exchange(info, b, t, s, Match::Info(&plan))?.ok_or(InterruptionError::InfoRejected)?;
    t.field("raw_classification", state.as_str())?;
    if m.mode == InterruptionMode::ClassifyGolden {
        return Ok(InterruptionOutcome::Classified(state));
    }
    if !matches!(
        state,
        RawCardState::StagingIncomplete | RawCardState::StagingComplete
    ) {
        return Err(InterruptionError::RecoveryNotStaging);
    }
    t.field(
        "recovery_action",
        "explicit SETUP ABORT then reselection and UNPROVISIONED INFO",
    )?;
    for row in plan.iter().filter(|row| row.branch == "abort-recovery") {
        exchange(row, b, t, s, Match::Exact)?;
    }
    t.field("recovery_endpoint", "UNPROVISIONED")?;
    Ok(InterruptionOutcome::RecoveredUnprovisioned)
}

enum Match<'a> {
    Exact,
    CommitRemoval,
    Info(&'a [InterruptionPlanRow]),
}
pub fn validate_removal_state(state: pcsc::State) -> Result<(), InterruptionError> {
    let allowed = pcsc::State::EMPTY | pcsc::State::CHANGED;
    if state.intersects(pcsc::State::UNKNOWN | pcsc::State::UNAVAILABLE) {
        Err(InterruptionError::ReaderStateRejected)
    } else if state.contains(pcsc::State::EMPTY) && (state & !allowed).is_empty() {
        Ok(())
    } else {
        Err(InterruptionError::RemovalNotObserved)
    }
}
fn exchange<B: InterruptionBackend, W: Write>(
    row: &InterruptionPlanRow,
    b: &mut B,
    t: &mut InterruptionTranscript<W>,
    s: &mut InterruptionSummary,
    matching: Match<'_>,
) -> Result<Option<RawCardState>, InterruptionError> {
    let mut request = [0u8; MAX_SITTING_REQUEST_BYTES];
    let request = ClearOnDrop(&mut request);
    let request_len = decode(row.request_hex, request.0)?;
    t.request(row, &request.0[..request_len])?;
    if matches!(matching, Match::CommitRemoval) {
        t.field("human_signal", "REMOVE_CARD_AT_COMMIT_DISPATCH")?;
        let result = call(|| b.signal_removal());
        let recorded = t.boundary("human_signal_return", result);
        result?;
        recorded?;
    }
    let mut response = [0u8; MAX_SITTING_CAPTURE_BYTES];
    let response = ClearOnDrop(&mut response);
    s.transmit_calls += 1;
    let result = call(|| b.exchange(&request.0[..request_len], response.0));
    let checked = (|| {
        let length = match result {
            Ok(n) if n <= MAX_SITTING_CAPTURE_BYTES => n,
            Ok(_) => return Err(SittingError::SittingResponseCaptureExceeded.into()),
            Err(error) => {
                let recorded = t.transport(row, error);
                if matches!(matching, Match::CommitRemoval)
                    && matches!(
                        error,
                        InterruptionError::Native(
                            pcsc::Error::RemovedCard | pcsc::Error::NoSmartcard
                        )
                    )
                {
                    recorded?;
                    t.field(
                        "commit_response",
                        "ABSENT; removal still requires status-change observation",
                    )?;
                    t.comparison(row, "ABSENT_EXPECTED_REMOVAL_PENDING")?;
                    return Ok(None);
                }
                return Err(error);
            }
        };
        s.received_responses += 1;
        t.response(row, &response.0[..length])?;
        if length > MAX_SITTING_RESPONSE_BYTES {
            return Err(SittingError::SittingResponseLimitExceeded.into());
        }
        if response.0[..length].ends_with(&[0x6f, 0x0f]) {
            return Err(InterruptionError::ResponseRetired);
        }
        if response.0[..length].ends_with(&[0x6f, 0x07]) {
            return Err(InterruptionError::LifecycleRejected);
        }
        let mut expected = [0u8; MAX_SITTING_RESPONSE_BYTES];
        let expected = ClearOnDrop(&mut expected);
        let state = if let Match::Info(plan) = matching {
            let mut matched = None;
            for state in [
                RawCardState::Unprovisioned,
                RawCardState::StagingIncomplete,
                RawCardState::StagingComplete,
                RawCardState::CommittedGolden,
            ] {
                let alternative = plan
                    .iter()
                    .find(|r| r.branch == state.branch())
                    .ok_or(InterruptionError::PlanRejected)?;
                let count = decode(alternative.response_hex, expected.0)?;
                if response.0[..length] == expected.0[..count] {
                    matched = Some(state);
                    break;
                }
            }
            Some(matched.ok_or(InterruptionError::InfoRejected)?)
        } else {
            let count = decode(row.response_hex, expected.0)?;
            if response.0[..length] != expected.0[..count] {
                return Err(SittingError::SittingResponseMismatch.into());
            }
            None
        };
        t.comparison(row, "PASS")?;
        Ok(state)
    })();
    if let Err(error) = checked {
        let _ = t.comparison(row, error.name());
    }
    checked
}

#[cfg(test)]
mod cleanup_tests {
    use super::ClearOnDrop;
    #[test]
    fn scratch_is_cleared_after_completion_and_unwind() {
        let mut bytes = [0xa5; 258];
        {
            let _owner = ClearOnDrop(&mut bytes);
        }
        assert_eq!(bytes, [0; 258]);
        bytes.fill(0xb6);
        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let _owner = ClearOnDrop(&mut bytes);
            panic!("cleanup probe");
        }));
        assert!(result.is_err());
        assert_eq!(bytes, [0; 258]);
    }
}
