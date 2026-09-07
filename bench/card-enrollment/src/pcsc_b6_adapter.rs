//! Private PC/SC boundary for the fixed B6 signature campaign.

use std::ffi::CString;
use std::fs::{File, OpenOptions, Permissions};
use std::mem;
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::panic::{catch_unwind, AssertUnwindSafe};
use std::path::Path;
use std::time::{SystemTime, UNIX_EPOCH};

use pcsc::{Context, Disposition, Protocol, Protocols, Scope, ShareMode};

use crate::{
    run_b6, B6Error, B6Metadata, B6Outcome, B6Transcript, NegotiatedProtocol,
    SittingTransportFailure, MAX_ATR_BYTES, MAX_READERS, MAX_READER_LIST_BYTES,
    MAX_READER_NAME_BYTES, REGISTERED_J3R180_ATR, SITTING_READER_NAME,
};

const _: [(); MAX_ATR_BYTES] = [(); pcsc::MAX_ATR_SIZE];

pub fn execute_pcsc_b6(metadata: B6Metadata) -> Result<B6Outcome, B6Error> {
    let file = open_b6_output(metadata.output_path())?;
    let mut transcript = B6Transcript::new(file);
    transcript.write_header(&metadata)?;

    let context = match catch_unwind(|| Context::establish(Scope::User)) {
        Ok(Ok(context)) => context,
        Ok(Err(_)) => {
            return Ok(finish_without_card(
                transcript,
                "EstablishContext",
                B6Error::B6ContextUnavailable,
            ));
        }
        Err(_) => {
            return Ok(finish_without_card(
                transcript,
                "EstablishContext",
                B6Error::B6BoundaryPanicked,
            ));
        }
    };
    if let Err(error) = transcript.record_event("EstablishContext", B6Outcome::Pass) {
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
                B6Error::B6ReaderListTooLarge,
            ));
        }
        Ok(Err(_)) => {
            return Ok(finish_without_card(
                transcript,
                "EnumerateReaders",
                B6Error::B6ReaderEnumerationFailed,
            ));
        }
        Err(_) => {
            return Ok(finish_without_card(
                transcript,
                "EnumerateReaders",
                B6Error::B6BoundaryPanicked,
            ));
        }
    };
    if readers.len() > MAX_READERS {
        return Ok(finish_without_card(
            transcript,
            "EnumerateReaders",
            B6Error::B6ReaderCountExceeded,
        ));
    }
    let reader_bytes = readers.iter().try_fold(1usize, |total, reader| {
        total.checked_add(reader.len())?.checked_add(1)
    });
    if reader_bytes.is_none_or(|length| length > MAX_READER_LIST_BYTES) {
        return Ok(finish_without_card(
            transcript,
            "EnumerateReaders",
            B6Error::B6ReaderListTooLarge,
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
            B6Error::B6ReaderNameRejected,
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
            B6Error::B6SelectedReaderMissing,
        ));
    }
    if selected_count != 1 {
        return Ok(finish_without_card(
            transcript,
            "SelectReader",
            B6Error::B6SelectedReaderDuplicate,
        ));
    }
    if let Err(error) = transcript.record_event("EnumerateReaders", B6Outcome::Pass) {
        return Ok(finish_without_card(transcript, "RecordReaderEvent", error));
    }

    let reader = match CString::new(SITTING_READER_NAME) {
        Ok(reader) => reader,
        Err(_) => {
            return Ok(finish_without_card(
                transcript,
                "SelectReader",
                B6Error::B6ReaderNameRejected,
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
                B6Error::B6ConnectFailed,
            ));
        }
        Err(_) => {
            return Ok(finish_without_card(
                transcript,
                "ExclusiveConnect",
                B6Error::B6BoundaryPanicked,
            ));
        }
    };
    if let Err(error) = transcript.record_event("ExclusiveConnect", B6Outcome::Pass) {
        return Ok(finish_with_card(transcript, card, reject(error), 0, 0));
    }

    match catch_unwind(AssertUnwindSafe(|| {
        card.reconnect(ShareMode::Exclusive, Protocols::ANY, Disposition::ResetCard)
    })) {
        Ok(Ok(())) => {}
        Ok(Err(_)) => {
            let outcome = reject(B6Error::B6ResetFailed);
            let _ = transcript.record_event("Reset", outcome);
            return Ok(finish_with_card(transcript, card, outcome, 0, 0));
        }
        Err(_) => {
            let outcome = reject(B6Error::B6BoundaryPanicked);
            let _ = transcript.record_event("Reset", outcome);
            return Ok(finish_with_card(transcript, card, outcome, 0, 0));
        }
    }
    if let Err(error) = transcript.record_event("Reset", B6Outcome::Pass) {
        return Ok(finish_with_card(transcript, card, reject(error), 0, 0));
    }

    let mut names_buffer = [0u8; MAX_READER_LIST_BYTES];
    let mut atr_buffer = [0u8; MAX_ATR_BYTES];
    let (atr, protocol) = match catch_unwind(AssertUnwindSafe(|| {
        card.status2(&mut names_buffer, &mut atr_buffer)
            .map(|status| (status.atr().to_vec(), status.protocol2()))
    })) {
        Ok(Ok(observation)) => observation,
        Ok(Err(_)) => {
            let outcome = reject(B6Error::B6StatusFailed);
            let _ = transcript.record_event("CaptureStatus", outcome);
            return Ok(finish_with_card(transcript, card, outcome, 0, 0));
        }
        Err(_) => {
            let outcome = reject(B6Error::B6BoundaryPanicked);
            let _ = transcript.record_event("CaptureStatus", outcome);
            return Ok(finish_with_card(transcript, card, outcome, 0, 0));
        }
    };
    let observed_protocol = protocol.map(|protocol| match protocol {
        Protocol::T0 => NegotiatedProtocol::T0,
        Protocol::T1 => NegotiatedProtocol::T1,
        Protocol::RAW => NegotiatedProtocol::Raw,
    });
    if let Err(error) = transcript.record_observation(&atr, observed_protocol) {
        return Ok(finish_with_card(transcript, card, reject(error), 0, 0));
    }
    if let Err(error) = transcript.record_event("CaptureStatus", B6Outcome::Pass) {
        return Ok(finish_with_card(transcript, card, reject(error), 0, 0));
    }
    if atr != REGISTERED_J3R180_ATR {
        let outcome = reject(B6Error::B6AtrRejected);
        let _ = transcript.record_event("CaptureAtr", outcome);
        return Ok(finish_with_card(transcript, card, outcome, 0, 0));
    }
    if let Err(error) = transcript.record_event("CaptureAtr", B6Outcome::Pass) {
        return Ok(finish_with_card(transcript, card, reject(error), 0, 0));
    }
    if observed_protocol != Some(NegotiatedProtocol::T1) {
        let outcome = reject(B6Error::B6ProtocolMismatch);
        let _ = transcript.record_event("CaptureProtocol", outcome);
        return Ok(finish_with_card(transcript, card, outcome, 0, 0));
    }
    if let Err(error) = transcript.record_event("CaptureProtocol", B6Outcome::Pass) {
        return Ok(finish_with_card(transcript, card, reject(error), 0, 0));
    }

    let mut boundary_transmits = 0usize;
    let mut boundary_responses = 0usize;
    let run = catch_unwind(AssertUnwindSafe(|| {
        run_b6(
            &mut transcript,
            |request, response| {
                boundary_transmits += 1;
                match catch_unwind(AssertUnwindSafe(|| {
                    card.transmit(request, response).map(|bytes| bytes.len())
                })) {
                    Ok(Ok(length)) => {
                        boundary_responses += 1;
                        Ok(length)
                    }
                    Ok(Err(pcsc::Error::InsufficientBuffer)) => {
                        Err(SittingTransportFailure::CaptureExceeded)
                    }
                    Ok(Err(_)) => Err(SittingTransportFailure::Failed),
                    Err(_) => Err(SittingTransportFailure::BoundaryPanicked),
                }
            },
            utc_now,
        )
    }));
    let (outcome, transmit_calls, received_responses) = match run {
        Ok(summary) => (
            summary.outcome,
            summary.transmit_calls,
            summary.received_responses,
        ),
        Err(_) => (
            reject(B6Error::B6BoundaryPanicked),
            boundary_transmits,
            boundary_responses,
        ),
    };
    Ok(finish_with_card(
        transcript,
        card,
        outcome,
        transmit_calls,
        received_responses,
    ))
}

fn open_b6_output(path: &Path) -> Result<File, B6Error> {
    let file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(path)
        .map_err(|_| B6Error::B6OutputCreateFailed)?;
    file.set_permissions(Permissions::from_mode(0o600))
        .map_err(|_| B6Error::B6OutputCreateFailed)?;
    if file
        .metadata()
        .map_err(|_| B6Error::B6OutputCreateFailed)?
        .permissions()
        .mode()
        & 0o777
        != 0o600
    {
        return Err(B6Error::B6OutputCreateFailed);
    }
    Ok(file)
}

fn reject(error: B6Error) -> B6Outcome {
    B6Outcome::Reject(error)
}

fn finish_without_card<W: std::io::Write>(
    mut transcript: B6Transcript<W>,
    operation: &str,
    error: B6Error,
) -> B6Outcome {
    let mut outcome = reject(error);
    let _ = transcript.record_event(operation, outcome);
    retain_first(&mut outcome, transcript.record_counts(0, 0).err());
    retain_first(&mut outcome, transcript.record_disconnect_none().err());
    let result_error = transcript.record_result(outcome).err();
    retain_first(&mut outcome, result_error);
    outcome
}

fn finish_with_card<W: std::io::Write>(
    mut transcript: B6Transcript<W>,
    card: pcsc::Card,
    mut outcome: B6Outcome,
    transmit_calls: usize,
    received_responses: usize,
) -> B6Outcome {
    retain_first(
        &mut outcome,
        transcript
            .record_counts(transmit_calls, received_responses)
            .err(),
    );
    let disconnect_outcome =
        match catch_unwind(AssertUnwindSafe(|| card.disconnect(Disposition::LeaveCard))) {
            Ok(Ok(())) => B6Outcome::Pass,
            Ok(Err((card, _))) => {
                mem::forget(card);
                reject(B6Error::B6DisconnectFailed)
            }
            Err(_) => reject(B6Error::B6BoundaryPanicked),
        };
    if let B6Outcome::Reject(error) = disconnect_outcome {
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

fn retain_first(outcome: &mut B6Outcome, later: Option<B6Error>) {
    if matches!(outcome, B6Outcome::Pass) {
        if let Some(error) = later {
            *outcome = reject(error);
        }
    }
}

fn utc_now() -> Result<String, B6Error> {
    let seconds = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| B6Error::B6ClockFailed)?
        .as_secs();
    format_utc_second(seconds).ok_or(B6Error::B6ClockFailed)
}

fn format_utc_second(seconds: u64) -> Option<String> {
    let days = i64::try_from(seconds / 86_400).ok()?;
    let second_of_day = seconds % 86_400;
    let hour = second_of_day / 3_600;
    let minute = (second_of_day % 3_600) / 60;
    let second = second_of_day % 60;

    let shifted = days.checked_add(719_468)?;
    let era = shifted.div_euclid(146_097);
    let day_of_era = shifted - era * 146_097;
    let year_of_era =
        (day_of_era - day_of_era / 1_460 + day_of_era / 36_524 - day_of_era / 146_096) / 365;
    let mut year = year_of_era + era * 400;
    let day_of_year = day_of_era - (365 * year_of_era + year_of_era / 4 - year_of_era / 100);
    let month_prime = (5 * day_of_year + 2) / 153;
    let day = day_of_year - (153 * month_prime + 2) / 5 + 1;
    let month = month_prime + if month_prime < 10 { 3 } else { -9 };
    year += i64::from(month <= 2);
    if !(1970..=9999).contains(&year) {
        return None;
    }
    Some(format!(
        "{year:04}-{month:02}-{day:02}T{hour:02}:{minute:02}:{second:02}Z"
    ))
}

#[cfg(test)]
mod tests {
    use std::fs;
    use std::io::Write;
    use std::os::unix::fs::{symlink, PermissionsExt};
    use std::path::PathBuf;
    use std::sync::atomic::{AtomicU64, Ordering};

    use super::{format_utc_second, open_b6_output, retain_first};
    use crate::{B6Error, B6Outcome};

    static NEXT_TEMP: AtomicU64 = AtomicU64::new(0);

    #[test]
    fn utc_clock_format_covers_epoch_leap_day_and_upper_bound() {
        assert_eq!(
            format_utc_second(0).as_deref(),
            Some("1970-01-01T00:00:00Z")
        );
        assert_eq!(
            format_utc_second(951_827_696).as_deref(),
            Some("2000-02-29T12:34:56Z")
        );
        assert_eq!(
            format_utc_second(253_402_300_799).as_deref(),
            Some("9999-12-31T23:59:59Z")
        );
        assert_eq!(format_utc_second(253_402_300_800), None);
    }

    #[test]
    fn output_is_private_create_new_and_never_follows_an_existing_link() {
        let directory = private_temp_directory();
        let output = directory.join("record.txt");
        let mut file = open_b6_output(&output).expect("first create-new open");
        assert_eq!(file.metadata().unwrap().permissions().mode() & 0o777, 0o600);
        file.write_all(b"retained\n").expect("write retained bytes");
        file.flush().expect("flush retained bytes");
        drop(file);

        assert_eq!(
            open_b6_output(&output).unwrap_err(),
            B6Error::B6OutputCreateFailed
        );
        assert_eq!(fs::read(&output).unwrap(), b"retained\n");

        let target = directory.join("target.txt");
        let link = directory.join("linked-output.txt");
        fs::write(&target, b"target-retained\n").unwrap();
        symlink(&target, &link).unwrap();
        assert_eq!(
            open_b6_output(&link).unwrap_err(),
            B6Error::B6OutputCreateFailed
        );
        assert_eq!(fs::read(&target).unwrap(), b"target-retained\n");
        fs::remove_dir_all(&directory).unwrap();
    }

    #[test]
    fn cleanup_retains_the_first_failure() {
        let mut prior = B6Outcome::Reject(B6Error::B6SignatureVerificationFailed);
        retain_first(&mut prior, Some(B6Error::B6DisconnectFailed));
        assert_eq!(
            prior,
            B6Outcome::Reject(B6Error::B6SignatureVerificationFailed)
        );

        let mut pass = B6Outcome::Pass;
        retain_first(&mut pass, Some(B6Error::B6DisconnectFailed));
        assert_eq!(pass, B6Outcome::Reject(B6Error::B6DisconnectFailed));
    }

    fn private_temp_directory() -> PathBuf {
        let suffix = NEXT_TEMP.fetch_add(1, Ordering::Relaxed);
        let directory = std::env::temp_dir().join(format!(
            "qk-card-b6-open-test-{}-{suffix}",
            std::process::id()
        ));
        fs::create_dir(&directory).unwrap();
        directory
    }
}
