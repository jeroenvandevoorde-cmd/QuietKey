use qk_card_enrollment::{
    authorize_operation, run_enrollment, CaptureAttempt, CardCapture, EnrollmentBackend,
    EnrollmentError, EnrollmentEvent, EnrollmentMetadata, EnrollmentMode, EnrollmentOperation,
    EnrollmentOutcome, NegotiatedProtocol, MAX_READERS, MAX_READER_NAME_BYTES,
};

const READER: &[u8] = b"Identiv SCR3310 v2.0";

#[derive(Clone)]
struct MockBackend {
    readers: Result<Vec<Vec<u8>>, EnrollmentError>,
    attempt: CaptureAttempt,
    captures: usize,
}

impl EnrollmentBackend for MockBackend {
    fn enumerate_readers(&mut self) -> Result<Vec<Vec<u8>>, EnrollmentError> {
        self.readers.clone()
    }

    fn capture_card(&mut self, reader_name: &[u8]) -> CaptureAttempt {
        assert_eq!(reader_name, READER);
        self.captures += 1;
        self.attempt.clone()
    }
}

fn metadata(mode: EnrollmentMode) -> qk_card_enrollment::ValidatedMetadata {
    EnrollmentMetadata {
        mode,
        source_commit: "0123456789abcdef0123456789abcdef01234567".to_owned(),
        timestamp_utc: "2026-08-31T12:34:56Z".to_owned(),
        host_alias: "iMac".to_owned(),
        reader_alias: "SCR3310-01".to_owned(),
        specimen_alias: (mode == EnrollmentMode::Enroll).then(|| "J3R180-02".to_owned()),
        selected_reader_name: (mode == EnrollmentMode::Enroll).then(|| READER.to_vec()),
    }
    .validate()
    .expect("fixture metadata")
}

fn backend(attempt: CaptureAttempt) -> MockBackend {
    MockBackend {
        readers: Ok(vec![READER.to_vec()]),
        attempt,
        captures: 0,
    }
}

#[test]
fn active_policy_authorizes_only_non_apdu_observations() {
    for operation in [
        EnrollmentOperation::EnumerateReaders,
        EnrollmentOperation::ExclusiveConnect,
        EnrollmentOperation::Reset,
        EnrollmentOperation::CaptureAtr,
        EnrollmentOperation::CaptureProtocol,
        EnrollmentOperation::Disconnect,
    ] {
        assert_eq!(authorize_operation(operation), Ok(()));
    }
    for _ in 0..32 {
        assert_eq!(
            authorize_operation(EnrollmentOperation::Transmit),
            Err(EnrollmentError::ApduTransmitNotAuthorized)
        );
    }
}

#[test]
fn success_observes_the_exact_six_step_order() {
    let capture = CardCapture {
        atr: vec![0x3b, 0x80, 0x01],
        protocol: NegotiatedProtocol::T1,
    };
    let mut backend = backend(CaptureAttempt::Success(capture.clone()));
    let record = run_enrollment(metadata(EnrollmentMode::Enroll), &mut backend);
    assert_eq!(backend.captures, 1);
    assert_eq!(record.capture, Some(capture));
    assert_eq!(record.outcome, EnrollmentOutcome::Pass);
    assert_eq!(
        record.events,
        [
            EnrollmentEvent {
                operation: EnrollmentOperation::EnumerateReaders,
                outcome: EnrollmentOutcome::Pass,
            },
            EnrollmentEvent {
                operation: EnrollmentOperation::ExclusiveConnect,
                outcome: EnrollmentOutcome::Pass,
            },
            EnrollmentEvent {
                operation: EnrollmentOperation::Reset,
                outcome: EnrollmentOutcome::Pass,
            },
            EnrollmentEvent {
                operation: EnrollmentOperation::CaptureAtr,
                outcome: EnrollmentOutcome::Pass,
            },
            EnrollmentEvent {
                operation: EnrollmentOperation::CaptureProtocol,
                outcome: EnrollmentOutcome::Pass,
            },
            EnrollmentEvent {
                operation: EnrollmentOperation::Disconnect,
                outcome: EnrollmentOutcome::Pass,
            },
        ]
    );
}

#[test]
fn enumeration_never_opens_a_card() {
    let mut backend = backend(CaptureAttempt::BoundaryPanicked);
    let record = run_enrollment(metadata(EnrollmentMode::Enumerate), &mut backend);
    assert_eq!(backend.captures, 0);
    assert_eq!(record.outcome, EnrollmentOutcome::Pass);
    assert_eq!(record.events.len(), 1);
    assert_eq!(
        record.events[0].operation,
        EnrollmentOperation::EnumerateReaders
    );
}

#[test]
fn reader_and_selection_bounds_are_named() {
    let cases = [
        (Vec::new(), EnrollmentError::ReaderNameEmpty),
        (
            vec![b'A'; MAX_READER_NAME_BYTES + 1],
            EnrollmentError::ReaderNameTooLong,
        ),
        (
            b"bad\0reader".to_vec(),
            EnrollmentError::ReaderNameContainsNul,
        ),
    ];
    for (reader, expected) in cases {
        let mut backend = backend(CaptureAttempt::ConnectFailed);
        backend.readers = Ok(vec![reader]);
        let record = run_enrollment(metadata(EnrollmentMode::Enroll), &mut backend);
        assert_eq!(record.outcome, EnrollmentOutcome::Reject(expected));
        assert_eq!(backend.captures, 0);
    }

    let mut too_many = backend(CaptureAttempt::ConnectFailed);
    too_many.readers = Ok((0..=MAX_READERS).map(|_| b"reader".to_vec()).collect());
    let record = run_enrollment(metadata(EnrollmentMode::Enroll), &mut too_many);
    assert_eq!(
        record.outcome,
        EnrollmentOutcome::Reject(EnrollmentError::ReaderCountExceeded)
    );

    let mut missing = backend(CaptureAttempt::ConnectFailed);
    missing.readers = Ok(vec![b"another reader".to_vec()]);
    assert_eq!(
        run_enrollment(metadata(EnrollmentMode::Enroll), &mut missing).outcome,
        EnrollmentOutcome::Reject(EnrollmentError::SelectedReaderMissing)
    );

    let mut duplicate = backend(CaptureAttempt::ConnectFailed);
    duplicate.readers = Ok(vec![READER.to_vec(), READER.to_vec()]);
    assert_eq!(
        run_enrollment(metadata(EnrollmentMode::Enroll), &mut duplicate).outcome,
        EnrollmentOutcome::Reject(EnrollmentError::SelectedReaderDuplicate)
    );
}

#[test]
fn each_capture_failure_has_a_stable_primary_result() {
    let cases = [
        (
            CaptureAttempt::ConnectFailed,
            EnrollmentError::ConnectFailed,
        ),
        (
            CaptureAttempt::ResetFailed { disconnected: true },
            EnrollmentError::ResetFailed,
        ),
        (
            CaptureAttempt::ResetPanicked { disconnected: true },
            EnrollmentError::BoundaryPanicked,
        ),
        (
            CaptureAttempt::StatusFailed { disconnected: true },
            EnrollmentError::StatusFailed,
        ),
        (
            CaptureAttempt::StatusPanicked { disconnected: true },
            EnrollmentError::BoundaryPanicked,
        ),
        (
            CaptureAttempt::ProtocolUnavailable {
                atr: vec![0x3b],
                disconnected: true,
            },
            EnrollmentError::ProtocolUnavailable,
        ),
        (
            CaptureAttempt::ProtocolUnsupported {
                atr: vec![0x3b],
                disconnected: true,
            },
            EnrollmentError::ProtocolUnsupported,
        ),
        (
            CaptureAttempt::DisconnectFailed(CardCapture {
                atr: vec![0x3b],
                protocol: NegotiatedProtocol::T0,
            }),
            EnrollmentError::DisconnectFailed,
        ),
        (
            CaptureAttempt::BoundaryPanicked,
            EnrollmentError::BoundaryPanicked,
        ),
    ];
    for (attempt, expected) in cases {
        let mut backend = backend(attempt);
        let record = run_enrollment(metadata(EnrollmentMode::Enroll), &mut backend);
        assert_eq!(record.outcome, EnrollmentOutcome::Reject(expected));
    }
}

#[test]
fn disconnect_failure_is_recorded_without_replacing_primary_failure() {
    let mut backend = backend(CaptureAttempt::StatusFailed {
        disconnected: false,
    });
    let record = run_enrollment(metadata(EnrollmentMode::Enroll), &mut backend);
    assert_eq!(
        record.outcome,
        EnrollmentOutcome::Reject(EnrollmentError::StatusFailed)
    );
    assert_eq!(
        record.events.last(),
        Some(&EnrollmentEvent {
            operation: EnrollmentOperation::Disconnect,
            outcome: EnrollmentOutcome::Reject(EnrollmentError::DisconnectFailed),
        })
    );
}

#[test]
fn deterministic_replay_is_byte_for_byte_equal_at_the_typed_boundary() {
    let attempt = CaptureAttempt::Success(CardCapture {
        atr: vec![0x3b, 0x01, 0x02, 0x03],
        protocol: NegotiatedProtocol::Raw,
    });
    let first = run_enrollment(
        metadata(EnrollmentMode::Enroll),
        &mut backend(attempt.clone()),
    );
    let second = run_enrollment(metadata(EnrollmentMode::Enroll), &mut backend(attempt));
    assert_eq!(first, second);
}
