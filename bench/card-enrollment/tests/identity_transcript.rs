use qk_card_enrollment::{
    encode_identity_transcript, EnrollmentMetadata, EnrollmentMode, IdentityError, IdentityEvent,
    IdentityExchange, IdentityOperation, IdentityOutcome, IdentityRecord, NegotiatedProtocol,
    CARD_RECOGNITION_COMMAND, CPLC_COMMAND, IDENTITY_ALLOWLIST_ID, IDENTITY_TOOL_VERSION,
    IDENTITY_TRANSCRIPT_VERSION, REGISTERED_J3R180_ATR,
};

fn record() -> IdentityRecord {
    let reader = b"Identive SCR33xx v2.0 USB SC Reader".to_vec();
    let metadata = EnrollmentMetadata {
        mode: EnrollmentMode::Enroll,
        source_commit: "0123456789abcdef0123456789abcdef01234567".to_owned(),
        timestamp_utc: "2026-09-01T12:34:56Z".to_owned(),
        host_alias: "iMac".to_owned(),
        reader_alias: "SCR3310-01".to_owned(),
        specimen_alias: Some("J3R180-02".to_owned()),
        selected_reader_name: Some(reader.clone()),
    }
    .validate()
    .expect("fixture metadata");
    let operations = [
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
    let mut cplc = vec![0x9f, 0x7f, 0x2a];
    cplc.extend(0u8..42);
    cplc.extend([0x90, 0x00]);
    IdentityRecord {
        metadata,
        readers: vec![reader],
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
                response: Some(vec![0x66, 0x03, 0x73, 0x01, 0x00, 0x90, 0x00]),
            },
            IdentityExchange {
                request: Some(CPLC_COMMAND.to_vec()),
                response: Some(cplc),
            },
        ],
        disconnected: Some(true),
        outcome: IdentityOutcome::Pass,
    }
}

#[test]
fn canonical_identity_transcript_is_byte_exact() {
    let actual = encode_identity_transcript(&record()).expect("transcript");
    let expected = concat!(
        "QK-CARD-IDENTITY-V1\n",
        "allowlist=QK-F8-IDENT-V1\n",
        "tool_version=0.0.2\n",
        "source_commit=0123456789abcdef0123456789abcdef01234567\n",
        "timestamp_utc=2026-09-01T12:34:56Z\n",
        "host_alias=iMac\n",
        "reader_alias=SCR3310-01\n",
        "specimen_alias=J3R180-02\n",
        "mode=IDENTITY\n",
        "reader_count=1\n",
        "reader.0.name_hex=4964656e7469766520534352333378782076322e302055534220534320526561646572\n",
        "selected_reader_name_hex=4964656e7469766520534352333378782076322e302055534220534320526561646572\n",
        "event_count=10\n",
        "event.0=EnumerateReaders:PASS\n",
        "event.1=ExclusiveConnect:PASS\n",
        "event.2=Reset:PASS\n",
        "event.3=CaptureAtr:PASS\n",
        "event.4=CaptureProtocol:PASS\n",
        "event.5=TransmitCardRecognition:PASS\n",
        "event.6=ReceiveCardRecognition:PASS\n",
        "event.7=TransmitCplc:PASS\n",
        "event.8=ReceiveCplc:PASS\n",
        "event.9=Disconnect:PASS\n",
        "protocol=T1\n",
        "atr_hex=3bd518ff8191fe1fc38073c821100a\n",
        "apdu_tx_count=2\n",
        "apdu_rx_count=2\n",
        "apdu.0.tx_hex=80ca006600\n",
        "apdu.0.rx_hex=66037301009000\n",
        "apdu.1.tx_hex=80ca9f7f00\n",
        "apdu.1.rx_hex=9f7f2a000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728299000\n",
        "disconnect=PASS\n",
        "result=PASS\n",
    )
    .as_bytes();
    assert_eq!(IDENTITY_TRANSCRIPT_VERSION, "QK-CARD-IDENTITY-V1");
    assert_eq!(IDENTITY_ALLOWLIST_ID, "QK-F8-IDENT-V1");
    assert_eq!(IDENTITY_TOOL_VERSION, "0.0.2");
    assert_eq!(actual, expected);
    assert!(actual.is_ascii());
    assert!(actual.ends_with(b"\n"));
    assert!(!actual.contains(&b'\r'));
    assert!(!actual.contains(&0));
}

#[test]
fn failed_transmit_records_request_without_inventing_a_response() {
    let mut record = record();
    record.events.truncate(6);
    record.events[5].outcome =
        IdentityOutcome::Reject(qk_card_enrollment::IdentityError::CardRecognitionTransmitFailed);
    record.events.push(IdentityEvent {
        operation: IdentityOperation::Disconnect,
        outcome: IdentityOutcome::Pass,
    });
    record.exchanges[0].response = None;
    record.exchanges[1] = IdentityExchange::default();
    record.outcome =
        IdentityOutcome::Reject(qk_card_enrollment::IdentityError::CardRecognitionTransmitFailed);
    let text =
        String::from_utf8(encode_identity_transcript(&record).expect("transcript")).expect("ASCII");
    assert!(text.contains("apdu_tx_count=1\napdu_rx_count=0\n"));
    assert!(text.contains("apdu.0.tx_hex=80ca006600\napdu.0.rx_hex=NONE\n"));
    assert!(text.contains("apdu.1.tx_hex=NONE\napdu.1.rx_hex=NONE\n"));
    assert!(text.ends_with("result=CardRecognitionTransmitFailed\n"));
}

#[test]
fn encoding_is_deterministic() {
    assert_eq!(
        encode_identity_transcript(&record()).expect("first"),
        encode_identity_transcript(&record()).expect("second")
    );
}

#[test]
fn contradictory_failure_records_never_encode() {
    let mut wrong_result = record();
    wrong_result.outcome =
        IdentityOutcome::Reject(qk_card_enrollment::IdentityError::CardRecognitionTransmitFailed);

    let mut invented_response = record();
    invented_response.events.truncate(6);
    invented_response.events[5].outcome =
        IdentityOutcome::Reject(qk_card_enrollment::IdentityError::CardRecognitionTransmitFailed);
    invented_response.events.push(IdentityEvent {
        operation: IdentityOperation::Disconnect,
        outcome: IdentityOutcome::Pass,
    });
    invented_response.exchanges[1] = IdentityExchange::default();
    invented_response.outcome =
        IdentityOutcome::Reject(qk_card_enrollment::IdentityError::CardRecognitionTransmitFailed);

    let mut wrong_disconnect = record();
    wrong_disconnect.disconnected = Some(false);

    let mut oversized_response = record();
    oversized_response.events.truncate(7);
    oversized_response.events[6].outcome =
        IdentityOutcome::Reject(IdentityError::CardRecognitionResponseTooLong);
    oversized_response.events.push(IdentityEvent {
        operation: IdentityOperation::Disconnect,
        outcome: IdentityOutcome::Pass,
    });
    oversized_response.exchanges[0].response = Some(vec![0; 259]);
    oversized_response.exchanges[1] = IdentityExchange::default();
    oversized_response.outcome =
        IdentityOutcome::Reject(IdentityError::CardRecognitionResponseTooLong);

    for malformed in [
        wrong_result,
        invented_response,
        wrong_disconnect,
        oversized_response,
    ] {
        assert_eq!(
            encode_identity_transcript(&malformed),
            Err(qk_card_enrollment::IdentityError::IdentitySequenceViolation)
        );
    }
}

#[test]
fn reachable_failure_records_remain_canonical_evidence() {
    let mut context_failure = record();
    context_failure.readers.clear();
    context_failure.events.clear();
    context_failure.observed_atr = None;
    context_failure.observed_protocol = None;
    context_failure.exchanges = core::array::from_fn(|_| IdentityExchange::default());
    context_failure.disconnected = None;
    context_failure.outcome = IdentityOutcome::Reject(IdentityError::ContextUnavailable);

    let mut missing_reader = context_failure.clone();
    missing_reader.readers.push(b"another reader".to_vec());
    missing_reader.events.push(IdentityEvent {
        operation: IdentityOperation::EnumerateReaders,
        outcome: IdentityOutcome::Pass,
    });
    missing_reader.outcome = IdentityOutcome::Reject(IdentityError::SelectedReaderMissing);

    let mut wrong_atr = record();
    wrong_atr.events.truncate(4);
    wrong_atr.events[3].outcome = IdentityOutcome::Reject(IdentityError::RegisteredAtrMismatch);
    wrong_atr.events.push(IdentityEvent {
        operation: IdentityOperation::Disconnect,
        outcome: IdentityOutcome::Pass,
    });
    wrong_atr.observed_atr = Some(vec![0x3b]);
    wrong_atr.exchanges = core::array::from_fn(|_| IdentityExchange::default());
    wrong_atr.disconnected = Some(true);
    wrong_atr.outcome = IdentityOutcome::Reject(IdentityError::RegisteredAtrMismatch);

    for canonical in [context_failure, missing_reader, wrong_atr] {
        assert!(encode_identity_transcript(&canonical).is_ok());
    }
}
