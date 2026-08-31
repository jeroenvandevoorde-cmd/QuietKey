use qk_card_enrollment::{
    encode_transcript, CardCapture, EnrollmentError, EnrollmentEvent, EnrollmentMetadata,
    EnrollmentMode, EnrollmentOperation, EnrollmentOutcome, EnrollmentRecord, NegotiatedProtocol,
    ACTIVE_ALLOWLIST_ID, MAX_READERS, MAX_READER_NAME_BYTES, MAX_TRANSCRIPT_BYTES, TOOL_VERSION,
    TRANSCRIPT_VERSION,
};

fn metadata() -> qk_card_enrollment::ValidatedMetadata {
    EnrollmentMetadata {
        mode: EnrollmentMode::Enroll,
        source_commit: "0123456789abcdef0123456789abcdef01234567".to_owned(),
        timestamp_utc: "2026-08-31T12:34:56Z".to_owned(),
        host_alias: "iMac".to_owned(),
        reader_alias: "SCR3310-01".to_owned(),
        specimen_alias: Some("J3R180-02".to_owned()),
        selected_reader_name: Some(vec![0x41, 0x80, 0xff]),
    }
    .validate()
    .expect("fixture metadata")
}

fn success_record() -> EnrollmentRecord {
    EnrollmentRecord {
        metadata: metadata(),
        readers: vec![vec![0x41, 0x80, 0xff]],
        events: vec![
            event(EnrollmentOperation::EnumerateReaders),
            event(EnrollmentOperation::ExclusiveConnect),
            event(EnrollmentOperation::Reset),
            event(EnrollmentOperation::CaptureAtr),
            event(EnrollmentOperation::CaptureProtocol),
            event(EnrollmentOperation::Disconnect),
        ],
        observed_atr: Some(vec![0x3b, 0x80, 0x01, 0x00, 0xff]),
        observed_protocol: Some(NegotiatedProtocol::T1),
        capture: Some(CardCapture {
            atr: vec![0x3b, 0x80, 0x01, 0x00, 0xff],
            protocol: NegotiatedProtocol::T1,
        }),
        outcome: EnrollmentOutcome::Pass,
    }
}

const fn event(operation: EnrollmentOperation) -> EnrollmentEvent {
    EnrollmentEvent {
        operation,
        outcome: EnrollmentOutcome::Pass,
    }
}

#[test]
fn canonical_success_transcript_is_byte_exact() {
    let actual = encode_transcript(&success_record()).expect("transcript");
    let expected = concat!(
        "QK-CARD-ENROLLMENT-V1\n",
        "allowlist=QK-F8-ENROLL-EMPTY-V1\n",
        "tool_version=0.0.1\n",
        "source_commit=0123456789abcdef0123456789abcdef01234567\n",
        "timestamp_utc=2026-08-31T12:34:56Z\n",
        "host_alias=iMac\n",
        "reader_alias=SCR3310-01\n",
        "specimen_alias=J3R180-02\n",
        "mode=ENROLL\n",
        "reader_count=1\n",
        "reader.0.name_hex=4180ff\n",
        "selected_reader_name_hex=4180ff\n",
        "event_count=6\n",
        "event.0=EnumerateReaders:PASS\n",
        "event.1=ExclusiveConnect:PASS\n",
        "event.2=Reset:PASS\n",
        "event.3=CaptureAtr:PASS\n",
        "event.4=CaptureProtocol:PASS\n",
        "event.5=Disconnect:PASS\n",
        "protocol=T1\n",
        "atr_hex=3b800100ff\n",
        "apdu_tx_count=0\n",
        "apdu_rx_count=0\n",
        "result=PASS\n",
    )
    .as_bytes();
    assert_eq!(TRANSCRIPT_VERSION, "QK-CARD-ENROLLMENT-V1");
    assert_eq!(ACTIVE_ALLOWLIST_ID, "QK-F8-ENROLL-EMPTY-V1");
    assert_eq!(TOOL_VERSION, "0.0.1");
    assert_eq!(actual, expected);
    assert!(actual.is_ascii());
    assert!(actual.ends_with(b"\n"));
    assert!(!actual.contains(&b'\r'));
    assert!(!actual.contains(&0));
}

#[test]
fn named_rejection_and_cleanup_outcome_are_byte_exact() {
    let mut record = success_record();
    record.capture = None;
    record.observed_atr = None;
    record.observed_protocol = None;
    record.events.truncate(3);
    record.events[2].outcome = EnrollmentOutcome::Reject(EnrollmentError::ResetFailed);
    record.events.push(EnrollmentEvent {
        operation: EnrollmentOperation::Disconnect,
        outcome: EnrollmentOutcome::Reject(EnrollmentError::DisconnectFailed),
    });
    record.outcome = EnrollmentOutcome::Reject(EnrollmentError::ResetFailed);
    let transcript = String::from_utf8(encode_transcript(&record).expect("transcript"))
        .expect("canonical transcript is ASCII");
    assert!(transcript.contains("event.2=Reset:ResetFailed\n"));
    assert!(transcript.contains("event.3=Disconnect:DisconnectFailed\n"));
    assert!(transcript.contains("protocol=NONE\natr_hex=NONE\n"));
    assert!(transcript.ends_with("result=ResetFailed\n"));
    assert_eq!(transcript.matches("apdu_tx_count=0\n").count(), 1);
    assert_eq!(transcript.matches("apdu_rx_count=0\n").count(), 1);
}

#[test]
fn every_observed_byte_is_lowercase_hex_without_normalization() {
    let transcript = String::from_utf8(encode_transcript(&success_record()).expect("transcript"))
        .expect("canonical transcript is ASCII");
    assert!(transcript.contains("reader.0.name_hex=4180ff\n"));
    assert!(transcript.contains("selected_reader_name_hex=4180ff\n"));
    assert!(transcript.contains("atr_hex=3b800100ff\n"));
    assert!(!transcript.contains("4180FF"));
    assert!(!transcript.contains("3B800100FF"));
}

#[test]
fn oversized_canonical_transcript_is_rejected_before_release() {
    let mut record = success_record();
    record.readers = (0..MAX_READERS)
        .map(|index| vec![b'A' + u8::try_from(index % 26).expect("bounded"); MAX_READER_NAME_BYTES])
        .collect();
    assert_eq!(
        encode_transcript(&record),
        Err(EnrollmentError::TranscriptTooLarge)
    );
    assert_eq!(MAX_TRANSCRIPT_BYTES, 16_384);
}

#[test]
fn encoding_is_deterministic() {
    let first = encode_transcript(&success_record()).expect("transcript");
    let second = encode_transcript(&success_record()).expect("transcript");
    assert_eq!(first, second);
}
