use std::cell::RefCell;
use std::io::{self, Write};
use std::path::PathBuf;
use std::rc::Rc;

use qk_card_enrollment::{
    fixed_sitting_plan, run_fixed_sitting_plan, sitting_output_basename, EnrollmentError,
    EnrollmentMetadata, EnrollmentMode, SittingError, SittingMetadata, SittingMode, SittingOutcome,
    SittingTranscript, SittingTransportFailure, SITTING_CAMPAIGN_SOURCE_COMMIT,
    SITTING_READER_NAME,
};

const UTC: &str = "2026-09-06T20:00:00Z";

fn enrollment(source_commit: &str, specimen: &str, reader: &[u8]) -> EnrollmentMetadata {
    EnrollmentMetadata {
        mode: EnrollmentMode::Enroll,
        source_commit: source_commit.to_owned(),
        timestamp_utc: UTC.to_owned(),
        host_alias: "iMac".to_owned(),
        reader_alias: "SCR3310-01".to_owned(),
        specimen_alias: Some(specimen.to_owned()),
        selected_reader_name: Some(reader.to_vec()),
    }
}

fn output_path(mode: SittingMode) -> PathBuf {
    PathBuf::from("/tmp").join(sitting_output_basename(mode, UTC))
}

fn sitting_metadata(mode: SittingMode) -> SittingMetadata {
    SittingMetadata::new(
        mode,
        enrollment(
            SITTING_CAMPAIGN_SOURCE_COMMIT,
            "J3R180-02",
            SITTING_READER_NAME,
        )
        .validate()
        .expect("valid enrollment metadata"),
        output_path(mode),
    )
    .expect("valid sitting metadata")
}

#[test]
fn only_registered_modes_bindings_source_and_output_name_are_accepted() {
    assert_eq!(
        SittingMode::parse("install-info"),
        Ok(SittingMode::InstallInfo)
    );
    assert_eq!(
        SittingMode::parse("provision-golden"),
        Ok(SittingMode::ProvisionGolden)
    );
    assert_eq!(
        SittingMode::parse("other"),
        Err(SittingError::SittingModeRejected)
    );
    let _ = sitting_metadata(SittingMode::InstallInfo);

    for (host, reader_alias, expected) in [
        (
            "other-host",
            "SCR3310-01",
            EnrollmentError::HostAliasInvalid,
        ),
        ("iMac", "other-reader", EnrollmentError::ReaderAliasInvalid),
    ] {
        let mut metadata = enrollment(
            SITTING_CAMPAIGN_SOURCE_COMMIT,
            "J3R180-02",
            SITTING_READER_NAME,
        );
        metadata.host_alias = host.to_owned();
        metadata.reader_alias = reader_alias.to_owned();
        assert_eq!(metadata.validate(), Err(expected));
    }

    let enumerate = EnrollmentMetadata {
        mode: EnrollmentMode::Enumerate,
        source_commit: SITTING_CAMPAIGN_SOURCE_COMMIT.to_owned(),
        timestamp_utc: UTC.to_owned(),
        host_alias: "iMac".to_owned(),
        reader_alias: "SCR3310-01".to_owned(),
        specimen_alias: None,
        selected_reader_name: None,
    }
    .validate()
    .expect("valid enumeration metadata");
    assert_eq!(
        SittingMetadata::new(
            SittingMode::InstallInfo,
            enumerate,
            output_path(SittingMode::InstallInfo),
        ),
        Err(SittingError::SittingBindingMismatch)
    );

    let wrong_source = enrollment(
        "0000000000000000000000000000000000000000",
        "J3R180-02",
        SITTING_READER_NAME,
    )
    .validate()
    .expect("well-formed alternate source");
    assert_eq!(
        SittingMetadata::new(
            SittingMode::InstallInfo,
            wrong_source,
            output_path(SittingMode::InstallInfo),
        ),
        Err(SittingError::SittingBindingMismatch)
    );

    for (specimen, reader) in [
        ("J3R180-03", SITTING_READER_NAME),
        ("J3R180-02", b"another reader".as_slice()),
    ] {
        let metadata = enrollment(SITTING_CAMPAIGN_SOURCE_COMMIT, specimen, reader)
            .validate()
            .expect("well-formed alternate binding");
        assert_eq!(
            SittingMetadata::new(
                SittingMode::InstallInfo,
                metadata,
                output_path(SittingMode::InstallInfo),
            ),
            Err(SittingError::SittingBindingMismatch)
        );
    }

    let metadata = enrollment(
        SITTING_CAMPAIGN_SOURCE_COMMIT,
        "J3R180-02",
        SITTING_READER_NAME,
    )
    .validate()
    .expect("valid binding");
    assert_eq!(
        SittingMetadata::new(
            SittingMode::InstallInfo,
            metadata.clone(),
            PathBuf::from(sitting_output_basename(SittingMode::InstallInfo, UTC)),
        ),
        Err(SittingError::SittingOutputPathRejected)
    );
    assert_eq!(
        SittingMetadata::new(
            SittingMode::InstallInfo,
            metadata,
            PathBuf::from("/tmp/wrong.txt"),
        ),
        Err(SittingError::SittingOutputNameMismatch)
    );
}

#[test]
fn fixed_engine_stops_on_first_mismatch_and_retains_exact_counts() {
    let plan = fixed_sitting_plan(SittingMode::ProvisionGolden).expect("registered plan");
    let mut transcript = SittingTranscript::new(Vec::new());
    let mut attempted = Vec::new();
    let summary = run_fixed_sitting_plan(&plan, &mut transcript, |request, response| {
        let index = attempted.len();
        attempted.push(request.to_vec());
        let expected = plan.exchanges()[index].expected_response();
        response[..expected.len()].copy_from_slice(expected);
        if index == 4 {
            response[0] ^= 1;
        }
        Ok(expected.len())
    });
    assert_eq!(
        summary.outcome,
        SittingOutcome::Reject(SittingError::SittingResponseMismatch)
    );
    assert_eq!(summary.transmit_calls, 5);
    assert_eq!(summary.received_responses, 5);
    assert_eq!(attempted.len(), 5);
    let text = String::from_utf8(transcript.into_inner()).expect("ASCII transcript");
    assert!(text.contains("apdu.4.rx_hex="));
    assert!(text.contains("apdu.4.comparison=SittingResponseMismatch\n"));
    assert!(!text.contains("apdu.5.tx_hex="));
}

#[test]
fn fixed_engine_records_oversize_response_before_stopping() {
    let plan = fixed_sitting_plan(SittingMode::InstallInfo).expect("registered plan");
    let mut transcript = SittingTranscript::new(Vec::new());
    let summary = run_fixed_sitting_plan(&plan, &mut transcript, |_request, response| {
        response[..219].fill(0x5a);
        Ok(219)
    });
    assert_eq!(
        summary,
        qk_card_enrollment::SittingRunSummary {
            transmit_calls: 1,
            received_responses: 1,
            outcome: SittingOutcome::Reject(SittingError::SittingResponseLimitExceeded),
        }
    );
    let text = String::from_utf8(transcript.into_inner()).expect("ASCII transcript");
    assert!(text.contains(&format!("apdu.0.rx_hex={}\n", "5a".repeat(219))));
    assert!(text.contains("apdu.0.comparison=SittingResponseLimitExceeded\n"));
    assert!(!text.contains("apdu.1.tx_hex="));
}

#[test]
fn transport_failures_and_panics_are_named_and_never_continue() {
    let plan = fixed_sitting_plan(SittingMode::InstallInfo).expect("registered plan");
    for (failure, expected) in [
        (
            SittingTransportFailure::Failed,
            SittingError::SittingTransmitFailed,
        ),
        (
            SittingTransportFailure::CaptureExceeded,
            SittingError::SittingResponseCaptureExceeded,
        ),
        (
            SittingTransportFailure::BoundaryPanicked,
            SittingError::SittingBoundaryPanicked,
        ),
    ] {
        let mut transcript = SittingTranscript::new(Vec::new());
        let mut attempts = 0;
        let summary = run_fixed_sitting_plan(&plan, &mut transcript, |_request, _response| {
            attempts += 1;
            Err(failure)
        });
        assert_eq!(summary.outcome, SittingOutcome::Reject(expected));
        assert_eq!(summary.transmit_calls, 1);
        assert_eq!(summary.received_responses, 0);
        assert_eq!(attempts, 1);
    }

    let mut transcript = SittingTranscript::new(Vec::new());
    let mut attempts = 0;
    let summary = run_fixed_sitting_plan(&plan, &mut transcript, |_request, response| {
        let index = attempts;
        attempts += 1;
        if index == 1 {
            panic!("injected exchange boundary panic");
        }
        let expected = plan.exchanges()[index].expected_response();
        response[..expected.len()].copy_from_slice(expected);
        Ok(expected.len())
    });
    assert_eq!(
        summary.outcome,
        SittingOutcome::Reject(SittingError::SittingBoundaryPanicked)
    );
    assert_eq!(summary.transmit_calls, 2);
    assert_eq!(summary.received_responses, 1);
    assert_eq!(attempts, 2);
}

#[derive(Clone, Copy)]
enum InjectedFailure {
    Write(usize),
    Flush(usize),
    PanicWrite(usize),
    PanicFlush(usize),
}

#[derive(Default)]
struct WriterCounts {
    writes: usize,
    flushes: usize,
}

struct FailingWriter {
    failure: InjectedFailure,
    counts: Rc<RefCell<WriterCounts>>,
}

impl Write for FailingWriter {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        let mut counts = self.counts.borrow_mut();
        let call = counts.writes;
        counts.writes += 1;
        match self.failure {
            InjectedFailure::Write(at) if call == at => {
                Err(io::Error::other("injected write failure"))
            }
            InjectedFailure::PanicWrite(at) if call == at => {
                panic!("injected writer panic")
            }
            _ => Ok(bytes.len()),
        }
    }

    fn flush(&mut self) -> io::Result<()> {
        let mut counts = self.counts.borrow_mut();
        let call = counts.flushes;
        counts.flushes += 1;
        match self.failure {
            InjectedFailure::Flush(at) if call == at => {
                Err(io::Error::other("injected flush failure"))
            }
            InjectedFailure::PanicFlush(at) if call == at => {
                panic!("injected flush boundary panic")
            }
            _ => Ok(()),
        }
    }
}

fn run_with_writer_failure(failure: InjectedFailure) -> (usize, SittingOutcome) {
    let plan = fixed_sitting_plan(SittingMode::InstallInfo).expect("registered plan");
    let counts = Rc::new(RefCell::new(WriterCounts::default()));
    let writer = FailingWriter { failure, counts };
    let mut transcript = SittingTranscript::new(writer);
    let mut attempts = 0;
    let summary = run_fixed_sitting_plan(&plan, &mut transcript, |_request, response| {
        let expected = plan.exchanges()[attempts].expected_response();
        response[..expected.len()].copy_from_slice(expected);
        attempts += 1;
        Ok(expected.len())
    });
    (attempts, summary.outcome)
}

#[test]
fn every_write_and_flush_failure_point_stops_before_the_next_exchange() {
    for point in 0..36 {
        let (attempts, outcome) = run_with_writer_failure(InjectedFailure::Write(point));
        assert_eq!(
            outcome,
            SittingOutcome::Reject(SittingError::SittingOutputWriteFailed),
            "write point {point}"
        );
        let expected_attempts = point / 12 + usize::from(point % 12 >= 6);
        assert_eq!(attempts, expected_attempts, "write point {point}");
    }
    for point in 0..18 {
        let (attempts, outcome) = run_with_writer_failure(InjectedFailure::Flush(point));
        assert_eq!(
            outcome,
            SittingOutcome::Reject(SittingError::SittingOutputFlushFailed),
            "flush point {point}"
        );
        let expected_attempts = point / 6 + usize::from(point % 6 >= 3);
        assert_eq!(attempts, expected_attempts, "flush point {point}");
    }
    let (attempts, outcome) = run_with_writer_failure(InjectedFailure::PanicWrite(12));
    assert_eq!(attempts, 1);
    assert_eq!(
        outcome,
        SittingOutcome::Reject(SittingError::SittingBoundaryPanicked)
    );
    let (attempts, outcome) = run_with_writer_failure(InjectedFailure::PanicFlush(6));
    assert_eq!(attempts, 1);
    assert_eq!(
        outcome,
        SittingOutcome::Reject(SittingError::SittingBoundaryPanicked)
    );
}
