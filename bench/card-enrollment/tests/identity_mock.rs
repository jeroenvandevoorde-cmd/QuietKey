use qk_card_enrollment::{
    run_identity, validate_card_recognition_response, validate_cplc_response, EnrollmentMetadata,
    EnrollmentMode, IdentityAttempt, IdentityBackend, IdentityError, IdentityEvent,
    IdentityExchange, IdentityOperation, IdentityOutcome, NegotiatedProtocol,
    CARD_RECOGNITION_COMMAND, CPLC_COMMAND, MAX_IDENTITY_RESPONSE_BYTES, REGISTERED_J3R180_ATR,
};

const READER: &[u8] = b"Identive SCR33xx v2.0 USB SC Reader";

#[derive(Clone)]
struct MockBackend {
    readers: Result<Vec<Vec<u8>>, IdentityError>,
    attempt: IdentityAttempt,
    captures: usize,
}

impl IdentityBackend for MockBackend {
    fn enumerate_readers(&mut self) -> Result<Vec<Vec<u8>>, IdentityError> {
        self.readers.clone()
    }

    fn capture_identity(&mut self, reader_name: &[u8]) -> IdentityAttempt {
        assert_eq!(reader_name, READER);
        self.captures += 1;
        self.attempt.clone()
    }
}

fn metadata() -> qk_card_enrollment::ValidatedMetadata {
    EnrollmentMetadata {
        mode: EnrollmentMode::Enroll,
        source_commit: "0123456789abcdef0123456789abcdef01234567".to_owned(),
        timestamp_utc: "2026-09-01T12:34:56Z".to_owned(),
        host_alias: "iMac".to_owned(),
        reader_alias: "SCR3310-01".to_owned(),
        specimen_alias: Some("J3R180-02".to_owned()),
        selected_reader_name: Some(READER.to_vec()),
    }
    .validate()
    .expect("fixture metadata")
}

fn card_recognition() -> Vec<u8> {
    vec![0x66, 0x03, 0x73, 0x01, 0x00, 0x90, 0x00]
}

fn cplc() -> Vec<u8> {
    let mut response = vec![0x9f, 0x7f, 0x2a];
    response.extend(0u8..42);
    response.extend([0x90, 0x00]);
    response
}

fn success_attempt() -> IdentityAttempt {
    let operations = [
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
    IdentityAttempt {
        events: operations
            .into_iter()
            .map(|operation| IdentityEvent {
                operation,
                outcome: IdentityOutcome::Pass,
            })
            .collect(),
        observed_atr: Some(REGISTERED_J3R180_ATR.to_vec()),
        observed_protocol: Some(NegotiatedProtocol::T1),
        exchanges: [
            IdentityExchange {
                request: Some(CARD_RECOGNITION_COMMAND.to_vec()),
                response: Some(card_recognition()),
            },
            IdentityExchange {
                request: Some(CPLC_COMMAND.to_vec()),
                response: Some(cplc()),
            },
        ],
        disconnected: Some(true),
        outcome: IdentityOutcome::Pass,
    }
}

#[test]
fn success_is_the_exact_two_command_sequence() {
    let mut backend = MockBackend {
        readers: Ok(vec![READER.to_vec()]),
        attempt: success_attempt(),
        captures: 0,
    };
    let record = run_identity(metadata(), &mut backend);
    assert_eq!(backend.captures, 1);
    assert_eq!(record.outcome, IdentityOutcome::Pass);
    assert_eq!(record.events.len(), 10);
    assert_eq!(
        record.events[0].operation,
        IdentityOperation::EnumerateReaders
    );
    assert_eq!(
        record.exchanges[0].request,
        Some(CARD_RECOGNITION_COMMAND.to_vec())
    );
    assert_eq!(record.exchanges[1].request, Some(CPLC_COMMAND.to_vec()));
    assert_eq!(record.observed_atr, Some(REGISTERED_J3R180_ATR.to_vec()));
    assert_eq!(record.observed_protocol, Some(NegotiatedProtocol::T1));
    assert_eq!(record.disconnected, Some(true));
}

#[test]
fn second_command_without_valid_first_response_is_a_sequence_violation() {
    let mut attempt = success_attempt();
    attempt.exchanges[0].response = Some(vec![0x6a, 0x82]);
    let mut backend = MockBackend {
        readers: Ok(vec![READER.to_vec()]),
        attempt,
        captures: 0,
    };
    assert_eq!(
        run_identity(metadata(), &mut backend).outcome,
        IdentityOutcome::Reject(IdentityError::IdentitySequenceViolation)
    );
}

#[test]
fn reader_selection_is_checked_before_contact() {
    let mut backend = MockBackend {
        readers: Ok(vec![b"another reader".to_vec()]),
        attempt: success_attempt(),
        captures: 0,
    };
    assert_eq!(
        run_identity(metadata(), &mut backend).outcome,
        IdentityOutcome::Reject(IdentityError::SelectedReaderMissing)
    );
    assert_eq!(backend.captures, 0);
}

#[test]
fn card_recognition_parser_locks_precedence_and_canonical_length() {
    assert_eq!(
        validate_card_recognition_response(&card_recognition()),
        Ok(())
    );
    assert_eq!(
        validate_card_recognition_response(&vec![0; MAX_IDENTITY_RESPONSE_BYTES + 1]),
        Err(IdentityError::CardRecognitionResponseTooLong)
    );
    assert_eq!(
        validate_card_recognition_response(&[]),
        Err(IdentityError::CardRecognitionResponseTooShort)
    );
    assert_eq!(
        validate_card_recognition_response(&[0x66, 0x01, 0x73, 0x6a, 0x82]),
        Err(IdentityError::CardRecognitionStatusRejected)
    );
    assert_eq!(
        validate_card_recognition_response(&[0x67, 0x01, 0x73, 0x90, 0x00]),
        Err(IdentityError::CardRecognitionOuterTagMismatch)
    );
    assert_eq!(
        validate_card_recognition_response(&[0x66, 0x81, 0x01, 0x73, 0x90, 0x00]),
        Err(IdentityError::CardRecognitionLengthMalformed)
    );
    assert_eq!(
        validate_card_recognition_response(&[0x66, 0x01, 0x73, 0x00, 0x90, 0x00]),
        Err(IdentityError::CardRecognitionTrailingByte)
    );
    assert_eq!(
        validate_card_recognition_response(&[0x66, 0x01, 0x72, 0x90, 0x00]),
        Err(IdentityError::CardRecognitionFirstNestedTagMismatch)
    );

    let mut long = vec![0x66, 0x81, 0x80, 0x73];
    long.extend(vec![0; 127]);
    long.extend([0x90, 0x00]);
    assert_eq!(validate_card_recognition_response(&long), Ok(()));
}

#[test]
fn cplc_parser_requires_the_exact_47_byte_shape() {
    assert_eq!(validate_cplc_response(&cplc()), Ok(()));
    assert_eq!(
        validate_cplc_response(&[0x6a, 0x82]),
        Err(IdentityError::CplcStatusRejected)
    );
    let mut wrong_tag = cplc();
    wrong_tag[1] = 0x7e;
    assert_eq!(
        validate_cplc_response(&wrong_tag),
        Err(IdentityError::CplcTagMismatch)
    );
    let mut wrong_length = cplc();
    wrong_length[2] = 0x29;
    assert_eq!(
        validate_cplc_response(&wrong_length),
        Err(IdentityError::CplcLengthMismatch)
    );
    assert_eq!(
        validate_cplc_response(&cplc()[..46]),
        Err(IdentityError::CplcStatusRejected)
    );
}
