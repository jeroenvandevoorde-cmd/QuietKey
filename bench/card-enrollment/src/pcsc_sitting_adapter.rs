//! Private PC/SC adapter for the two QK-DEC-165 fixed sitting plans.

use std::ffi::CString;
use std::fs::{File, OpenOptions, Permissions};
use std::mem;
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::panic::{catch_unwind, AssertUnwindSafe};
use std::path::Path;

use pcsc::{Context, Disposition, Protocol, Protocols, Scope, ShareMode};

use crate::{
    fixed_sitting_plan, run_fixed_sitting_plan, NegotiatedProtocol, SittingError, SittingMetadata,
    SittingOutcome, SittingRunSummary, SittingTranscript, SittingTransportFailure, MAX_ATR_BYTES,
    MAX_READERS, MAX_READER_LIST_BYTES, MAX_READER_NAME_BYTES, REGISTERED_J3R180_ATR,
    SITTING_READER_NAME,
};

const _: [(); MAX_ATR_BYTES] = [(); pcsc::MAX_ATR_SIZE];

pub fn execute_pcsc_sitting(metadata: SittingMetadata) -> Result<SittingOutcome, SittingError> {
    let file = open_sitting_output(metadata.output_path())?;
    let mut transcript = SittingTranscript::new(file);
    transcript.write_header(&metadata)?;

    let plan = match fixed_sitting_plan(metadata.mode()) {
        Ok(plan) => plan,
        Err(error) => {
            return Ok(finish_without_card(transcript, "LoadFixedPlan", error));
        }
    };
    let context = match catch_unwind(|| Context::establish(Scope::User)) {
        Ok(Ok(context)) => context,
        Ok(Err(_)) => {
            return Ok(finish_without_card(
                transcript,
                "EstablishContext",
                SittingError::SittingContextUnavailable,
            ));
        }
        Err(_) => {
            return Ok(finish_without_card(
                transcript,
                "EstablishContext",
                SittingError::SittingBoundaryPanicked,
            ));
        }
    };
    if let Err(error) = transcript.record_event("EstablishContext", SittingOutcome::Pass) {
        return Ok(finish_without_card(transcript, "RecordContext", error));
    }

    let mut reader_buffer = [0u8; MAX_READER_LIST_BYTES];
    let readers: Vec<Vec<u8>> = match catch_unwind(AssertUnwindSafe(|| {
        context
            .list_readers(&mut reader_buffer)
            .map(|items| items.map(|reader| reader.to_bytes().to_vec()).collect())
    })) {
        Ok(Ok(readers)) => readers,
        Ok(Err(pcsc::Error::InsufficientBuffer)) => {
            return Ok(finish_without_card(
                transcript,
                "EnumerateReaders",
                SittingError::SittingReaderListTooLarge,
            ));
        }
        Ok(Err(_)) => {
            return Ok(finish_without_card(
                transcript,
                "EnumerateReaders",
                SittingError::SittingReaderEnumerationFailed,
            ));
        }
        Err(_) => {
            return Ok(finish_without_card(
                transcript,
                "EnumerateReaders",
                SittingError::SittingBoundaryPanicked,
            ));
        }
    };
    if readers.len() > MAX_READERS {
        return Ok(finish_without_card(
            transcript,
            "EnumerateReaders",
            SittingError::SittingReaderCountExceeded,
        ));
    }
    let reader_bytes = readers.iter().try_fold(1usize, |total, reader| {
        total.checked_add(reader.len())?.checked_add(1)
    });
    if reader_bytes.is_none_or(|length| length > MAX_READER_LIST_BYTES) {
        return Ok(finish_without_card(
            transcript,
            "EnumerateReaders",
            SittingError::SittingReaderListTooLarge,
        ));
    }
    if let Err(error) = transcript.record_readers(&readers) {
        return Ok(finish_without_card(transcript, "RecordReaders", error));
    }
    if readers.iter().any(|reader| {
        reader.is_empty() || reader.len() > MAX_READER_NAME_BYTES || reader.contains(&0)
    }) {
        return Ok(finish_without_card(
            transcript,
            "ValidateReaderNames",
            SittingError::SittingReaderNameRejected,
        ));
    }
    let selected_count = readers
        .iter()
        .filter(|reader| reader.as_slice() == SITTING_READER_NAME)
        .count();
    if selected_count == 0 {
        return Ok(finish_without_card(
            transcript,
            "SelectReader",
            SittingError::SittingSelectedReaderMissing,
        ));
    }
    if selected_count != 1 {
        return Ok(finish_without_card(
            transcript,
            "SelectReader",
            SittingError::SittingSelectedReaderDuplicate,
        ));
    }
    if let Err(error) = transcript.record_event("EnumerateReaders", SittingOutcome::Pass) {
        return Ok(finish_without_card(transcript, "RecordReaderEvent", error));
    }

    let reader = match CString::new(SITTING_READER_NAME) {
        Ok(reader) => reader,
        Err(_) => {
            return Ok(finish_without_card(
                transcript,
                "SelectReader",
                SittingError::SittingReaderNameRejected,
            ));
        }
    };
    let mut card = match catch_unwind(AssertUnwindSafe(|| {
        context.connect(&reader, ShareMode::Exclusive, Protocols::ANY)
    })) {
        Ok(Ok(card)) => card,
        Ok(Err(_)) => {
            return Ok(finish_without_card(
                transcript,
                "ExclusiveConnect",
                SittingError::SittingConnectFailed,
            ));
        }
        Err(_) => {
            return Ok(finish_without_card(
                transcript,
                "ExclusiveConnect",
                SittingError::SittingBoundaryPanicked,
            ));
        }
    };
    if let Err(error) = transcript.record_event("ExclusiveConnect", SittingOutcome::Pass) {
        return Ok(finish_with_card(
            transcript,
            card,
            reject(error),
            zero_counts(),
        ));
    }

    match catch_unwind(AssertUnwindSafe(|| {
        card.reconnect(ShareMode::Exclusive, Protocols::ANY, Disposition::ResetCard)
    })) {
        Ok(Ok(())) => {}
        Ok(Err(_)) => {
            let outcome = reject(SittingError::SittingResetFailed);
            let _ = transcript.record_event("Reset", outcome);
            return Ok(finish_with_card(transcript, card, outcome, zero_counts()));
        }
        Err(_) => {
            let outcome = reject(SittingError::SittingBoundaryPanicked);
            let _ = transcript.record_event("Reset", outcome);
            return Ok(finish_with_card(transcript, card, outcome, zero_counts()));
        }
    }
    if let Err(error) = transcript.record_event("Reset", SittingOutcome::Pass) {
        return Ok(finish_with_card(
            transcript,
            card,
            reject(error),
            zero_counts(),
        ));
    }

    let mut names_buffer = [0u8; MAX_READER_LIST_BYTES];
    let mut atr_buffer = [0u8; MAX_ATR_BYTES];
    let (atr, protocol) = match catch_unwind(AssertUnwindSafe(|| {
        card.status2(&mut names_buffer, &mut atr_buffer)
            .map(|status| (status.atr().to_vec(), status.protocol2()))
    })) {
        Ok(Ok(observation)) => observation,
        Ok(Err(_)) => {
            let outcome = reject(SittingError::SittingStatusFailed);
            let _ = transcript.record_event("CaptureStatus", outcome);
            return Ok(finish_with_card(transcript, card, outcome, zero_counts()));
        }
        Err(_) => {
            let outcome = reject(SittingError::SittingBoundaryPanicked);
            let _ = transcript.record_event("CaptureStatus", outcome);
            return Ok(finish_with_card(transcript, card, outcome, zero_counts()));
        }
    };
    let observed_protocol = protocol.map(|protocol| match protocol {
        Protocol::T0 => NegotiatedProtocol::T0,
        Protocol::T1 => NegotiatedProtocol::T1,
        Protocol::RAW => NegotiatedProtocol::Raw,
    });
    if let Err(error) = transcript.record_observation(&atr, observed_protocol) {
        return Ok(finish_with_card(
            transcript,
            card,
            reject(error),
            zero_counts(),
        ));
    }
    if let Err(error) = transcript.record_event("CaptureStatus", SittingOutcome::Pass) {
        return Ok(finish_with_card(
            transcript,
            card,
            reject(error),
            zero_counts(),
        ));
    }
    if atr != REGISTERED_J3R180_ATR {
        let outcome = reject(SittingError::SittingAtrRejected);
        let _ = transcript.record_event("CaptureAtr", outcome);
        return Ok(finish_with_card(transcript, card, outcome, zero_counts()));
    }
    if let Err(error) = transcript.record_event("CaptureAtr", SittingOutcome::Pass) {
        return Ok(finish_with_card(
            transcript,
            card,
            reject(error),
            zero_counts(),
        ));
    }
    if observed_protocol != Some(NegotiatedProtocol::T1) {
        let outcome = reject(SittingError::SittingProtocolMismatch);
        let _ = transcript.record_event("CaptureProtocol", outcome);
        return Ok(finish_with_card(transcript, card, outcome, zero_counts()));
    }
    if let Err(error) = transcript.record_event("CaptureProtocol", SittingOutcome::Pass) {
        return Ok(finish_with_card(
            transcript,
            card,
            reject(error),
            zero_counts(),
        ));
    }

    let summary =
        run_fixed_sitting_plan(
            &plan,
            &mut transcript,
            |request, response| match catch_unwind(AssertUnwindSafe(|| {
                card.transmit(request, response).map(|bytes| bytes.len())
            })) {
                Ok(Ok(length)) => Ok(length),
                Ok(Err(pcsc::Error::InsufficientBuffer)) => {
                    Err(SittingTransportFailure::CaptureExceeded)
                }
                Ok(Err(_)) => Err(SittingTransportFailure::Failed),
                Err(_) => Err(SittingTransportFailure::BoundaryPanicked),
            },
        );
    Ok(finish_with_card(transcript, card, summary.outcome, summary))
}

fn open_sitting_output(path: &Path) -> Result<File, SittingError> {
    let file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(path)
        .map_err(|_| SittingError::SittingOutputCreateFailed)?;
    file.set_permissions(Permissions::from_mode(0o600))
        .map_err(|_| SittingError::SittingOutputCreateFailed)?;
    let mode = file
        .metadata()
        .map_err(|_| SittingError::SittingOutputCreateFailed)?
        .permissions()
        .mode()
        & 0o777;
    if mode != 0o600 {
        return Err(SittingError::SittingOutputCreateFailed);
    }
    Ok(file)
}

fn reject(error: SittingError) -> SittingOutcome {
    SittingOutcome::Reject(error)
}

fn zero_counts() -> SittingRunSummary {
    SittingRunSummary {
        transmit_calls: 0,
        received_responses: 0,
        outcome: SittingOutcome::Pass,
    }
}

fn finish_without_card<W: std::io::Write>(
    mut transcript: SittingTranscript<W>,
    operation: &str,
    error: SittingError,
) -> SittingOutcome {
    let mut outcome = reject(error);
    let _ = transcript.record_event(operation, outcome);
    retain_first(&mut outcome, transcript.record_counts(0, 0).err());
    retain_first(&mut outcome, transcript.record_disconnect_none().err());
    let result_error = transcript.record_result(outcome).err();
    retain_first(&mut outcome, result_error);
    outcome
}

fn finish_with_card<W: std::io::Write>(
    mut transcript: SittingTranscript<W>,
    card: pcsc::Card,
    mut outcome: SittingOutcome,
    summary: SittingRunSummary,
) -> SittingOutcome {
    retain_first(
        &mut outcome,
        transcript
            .record_counts(summary.transmit_calls, summary.received_responses)
            .err(),
    );
    let disconnect_outcome =
        match catch_unwind(AssertUnwindSafe(|| card.disconnect(Disposition::LeaveCard))) {
            Ok(Ok(())) => SittingOutcome::Pass,
            Ok(Err((card, _))) => {
                mem::forget(card);
                reject(SittingError::SittingDisconnectFailed)
            }
            Err(_) => reject(SittingError::SittingBoundaryPanicked),
        };
    if let SittingOutcome::Reject(error) = disconnect_outcome {
        retain_first(&mut outcome, Some(error));
    }
    retain_first(
        &mut outcome,
        transcript.record_disconnect(disconnect_outcome).err(),
    );
    let result_error = transcript.record_result(outcome).err();
    retain_first(&mut outcome, result_error);
    outcome
}

fn retain_first(outcome: &mut SittingOutcome, later: Option<SittingError>) {
    if matches!(outcome, SittingOutcome::Pass) {
        if let Some(error) = later {
            *outcome = reject(error);
        }
    }
}

#[cfg(test)]
mod tests {
    use std::fs;
    use std::io::Write;
    use std::os::unix::fs::{symlink, PermissionsExt};
    use std::path::PathBuf;
    use std::sync::atomic::{AtomicU64, Ordering};

    use super::{open_sitting_output, retain_first};
    use crate::{SittingError, SittingOutcome};

    static NEXT_TEMP: AtomicU64 = AtomicU64::new(0);

    #[test]
    fn disconnect_failure_never_replaces_an_earlier_rejection() {
        let mut prior = SittingOutcome::Reject(SittingError::SittingResponseMismatch);
        retain_first(&mut prior, Some(SittingError::SittingDisconnectFailed));
        assert_eq!(
            prior,
            SittingOutcome::Reject(SittingError::SittingResponseMismatch)
        );

        let mut pass = SittingOutcome::Pass;
        retain_first(&mut pass, Some(SittingError::SittingDisconnectFailed));
        assert_eq!(
            pass,
            SittingOutcome::Reject(SittingError::SittingDisconnectFailed)
        );
    }

    #[test]
    fn output_open_is_create_new_mode_0600_and_never_follows_an_existing_link() {
        let directory = private_temp_directory();
        let output = directory.join("record.txt");
        let mut file = open_sitting_output(&output).expect("first create-new open");
        assert_eq!(
            file.metadata()
                .expect("output metadata")
                .permissions()
                .mode()
                & 0o777,
            0o600
        );
        file.write_all(b"retained\n").expect("write retained bytes");
        file.flush().expect("flush retained bytes");
        drop(file);

        assert!(matches!(
            open_sitting_output(&output),
            Err(SittingError::SittingOutputCreateFailed)
        ));
        assert_eq!(fs::read(&output).expect("retained output"), b"retained\n");

        let target = directory.join("target.txt");
        let link = directory.join("linked-output.txt");
        fs::write(&target, b"target-retained\n").expect("write target");
        symlink(&target, &link).expect("create test link");
        assert!(matches!(
            open_sitting_output(&link),
            Err(SittingError::SittingOutputCreateFailed)
        ));
        assert_eq!(
            fs::read(&target).expect("unchanged target"),
            b"target-retained\n"
        );
        fs::remove_dir_all(&directory).expect("remove bounded test directory");
    }

    fn private_temp_directory() -> PathBuf {
        let suffix = NEXT_TEMP.fetch_add(1, Ordering::Relaxed);
        let directory = std::env::temp_dir().join(format!(
            "qk-card-sitting-open-test-{}-{suffix}",
            std::process::id()
        ));
        fs::create_dir(&directory).expect("create bounded test directory");
        directory
    }
}
