use qk_card_trace::{inspect_trace, TraceError, TraceLimits, TraceMode};

const MOCK: &[u8] = include_bytes!("fixtures/mock_trace_v1.txt");
const MOCK_NAME: &str = "qk-card-trace-v1__MOCK-F8G0-D-001__MOCK-J3R180-001__20260825T120000Z.txt";

fn limits() -> TraceLimits {
    TraceLimits::new(4096, 16, 64, 32, 33).expect("fixture-only explicit limits")
}

fn changed(from: &str, to: &str) -> Vec<u8> {
    String::from_utf8(MOCK.to_vec())
        .expect("fixture ASCII")
        .replacen(from, to, 1)
        .into_bytes()
}

#[test]
fn canonical_mock_trace_returns_metadata_without_payloads() {
    let summary = inspect_trace(MOCK, MOCK_NAME, limits()).expect("canonical mock trace");
    assert_eq!(summary.mode, TraceMode::Mock);
    assert_eq!(summary.records, 3);
    assert_eq!(summary.atr_records, 1);
    assert_eq!(summary.protocol_records, 2);
    assert_eq!(summary.apdu_commands, 0);
    assert_eq!(summary.apdu_responses, 0);
    assert_eq!(summary.expected_filename, MOCK_NAME);
    assert_eq!(
        summary.raw_artifact_sha256,
        core::array::from_fn::<_, 32, _>(|index| index as u8)
    );
}

#[test]
fn caller_supplies_every_nonzero_harness_control() {
    for values in [
        (0, 1, 1, 1, 1),
        (1, 0, 1, 1, 1),
        (1, 1, 0, 1, 1),
        (1, 1, 1, 0, 1),
        (1, 1, 1, 1, 0),
    ] {
        assert_eq!(
            TraceLimits::new(values.0, values.1, values.2, values.3, values.4),
            Err(TraceError::InvalidHarnessLimit)
        );
    }
    assert!(TraceLimits::new(1, 1, 1, 1, 1).is_ok());
}

#[test]
fn input_byte_and_record_caps_are_caller_controlled() {
    assert_eq!(
        inspect_trace(
            MOCK,
            MOCK_NAME,
            TraceLimits::new(MOCK.len() - 1, 16, 64, 32, 33).unwrap()
        ),
        Err(TraceError::InputTooLarge)
    );
    assert_eq!(
        inspect_trace(
            MOCK,
            MOCK_NAME,
            TraceLimits::new(4096, 2, 64, 32, 33).unwrap()
        ),
        Err(TraceError::TooManyRecords)
    );
}

#[test]
fn exact_filename_is_bound_to_header_identity() {
    assert_eq!(
        inspect_trace(MOCK, "different.txt", limits()),
        Err(TraceError::FilenameMismatch)
    );
    let input = changed("run_id=MOCK-F8G0-D-001", "run_id=MOCK-F8G0-D-002");
    assert_eq!(
        inspect_trace(&input, MOCK_NAME, limits()),
        Err(TraceError::FilenameMismatch)
    );
}

#[test]
fn ascii_lf_envelope_is_exact() {
    assert_eq!(
        inspect_trace(b"", MOCK_NAME, limits()),
        Err(TraceError::EmptyInput)
    );
    let mut non_ascii = MOCK.to_vec();
    non_ascii[0] = 0xff;
    assert_eq!(
        inspect_trace(&non_ascii, MOCK_NAME, limits()),
        Err(TraceError::NonAscii)
    );
    let crlf = String::from_utf8(MOCK.to_vec())
        .unwrap()
        .replace('\n', "\r\n");
    assert_eq!(
        inspect_trace(crlf.as_bytes(), MOCK_NAME, limits()),
        Err(TraceError::CarriageReturn)
    );
    assert_eq!(
        inspect_trace(&MOCK[..MOCK.len() - 1], MOCK_NAME, limits()),
        Err(TraceError::MissingFinalLf)
    );
}

#[test]
fn magic_and_header_order_fail_closed() {
    assert_eq!(
        inspect_trace(
            &changed("QK-CARD-TRACE-V1", "QK-CARD-TRACE-V2"),
            MOCK_NAME,
            limits()
        ),
        Err(TraceError::InvalidMagic)
    );
    assert_eq!(
        inspect_trace(&changed("run_id=", "not_run_id="), MOCK_NAME, limits()),
        Err(TraceError::InvalidHeader)
    );
}

#[test]
fn identifiers_mode_and_timestamp_are_canonical() {
    assert_eq!(
        inspect_trace(
            &changed("MOCK-F8G0-D-001", "mock-f8g0-d-001"),
            MOCK_NAME,
            limits()
        ),
        Err(TraceError::InvalidIdentifier)
    );
    assert_eq!(
        inspect_trace(&changed("mode=MOCK", "mode=TEST"), MOCK_NAME, limits()),
        Err(TraceError::InvalidMode)
    );
    assert_eq!(
        inspect_trace(
            &changed("20260825T120000Z", "20261325T120000Z"),
            MOCK_NAME,
            limits()
        ),
        Err(TraceError::InvalidTimestamp)
    );
}

#[test]
fn identifier_length_is_caller_controlled() {
    assert_eq!(
        inspect_trace(
            MOCK,
            MOCK_NAME,
            TraceLimits::new(4096, 16, 64, 8, 33).unwrap()
        ),
        Err(TraceError::InvalidIdentifier)
    );
}

#[test]
fn mock_aliases_are_explicitly_separated() {
    let input = changed("specimen_id=MOCK-J3R180-001", "specimen_id=TEST-J3R180-001");
    let name = "qk-card-trace-v1__MOCK-F8G0-D-001__TEST-J3R180-001__20260825T120000Z.txt";
    assert_eq!(
        inspect_trace(&input, name, limits()),
        Err(TraceError::MockIdentityMismatch)
    );
}

#[test]
fn allowlist_and_supplied_hash_fields_are_canonical() {
    assert_eq!(
        inspect_trace(
            &changed("QK-F8-G0-EMPTY-V1", "QK-F8-G0-OTHER-V1"),
            MOCK_NAME,
            limits()
        ),
        Err(TraceError::UnsupportedAllowlist)
    );
    assert_eq!(
        inspect_trace(
            &changed(
                "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f",
                "000102030405060708090A0b0c0d0e0f101112131415161718191a1b1c1d1e1f"
            ),
            MOCK_NAME,
            limits()
        ),
        Err(TraceError::InvalidDigest)
    );
}

#[test]
fn record_count_is_positive_canonical_and_exact() {
    assert_eq!(
        inspect_trace(
            &changed("record_count=3", "record_count=0"),
            MOCK_NAME,
            limits()
        ),
        Err(TraceError::InvalidRecordCount)
    );
    assert_eq!(
        inspect_trace(
            &changed("record_count=3", "record_count=03"),
            MOCK_NAME,
            limits()
        ),
        Err(TraceError::InvalidRecordCount)
    );
    assert_eq!(
        inspect_trace(
            &changed("record_count=3", "record_count=4"),
            MOCK_NAME,
            limits()
        ),
        Err(TraceError::RecordCountMismatch)
    );
}

#[test]
fn sequence_and_time_are_canonical_and_monotonic() {
    assert_eq!(
        inspect_trace(&changed("000001 125", "000002 125"), MOCK_NAME, limits()),
        Err(TraceError::InvalidSequence)
    );
    assert_eq!(
        inspect_trace(&changed("000001 125", "000001 0125"), MOCK_NAME, limits()),
        Err(TraceError::InvalidRecord)
    );
    assert_eq!(
        inspect_trace(&changed("000002 125", "000002 124"), MOCK_NAME, limits()),
        Err(TraceError::NonMonotonicTime)
    );
}

#[test]
fn hex_payloads_are_lowercase_even_and_bounded() {
    assert_eq!(
        inspect_trace(&changed("PROTOCOL 01", "PROTOCOL 0A"), MOCK_NAME, limits()),
        Err(TraceError::InvalidHex)
    );
    assert_eq!(
        inspect_trace(&changed("PROTOCOL 01", "PROTOCOL 0"), MOCK_NAME, limits()),
        Err(TraceError::InvalidHex)
    );
    assert_eq!(
        inspect_trace(
            MOCK,
            MOCK_NAME,
            TraceLimits::new(4096, 16, 1, 32, 33).unwrap()
        ),
        Err(TraceError::RecordTooLarge)
    );
}

#[test]
fn atr_is_first_unique_nonempty_and_caller_bounded() {
    let no_first_atr = changed("000000 0 ATR 3b00", "000000 0 PROTOCOL 01");
    assert_eq!(
        inspect_trace(&no_first_atr, MOCK_NAME, limits()),
        Err(TraceError::ProtocolBeforeAtr)
    );
    let duplicate = changed("000001 125 PROTOCOL 01", "000001 125 ATR 3b00");
    assert_eq!(
        inspect_trace(&duplicate, MOCK_NAME, limits()),
        Err(TraceError::DuplicateAtr)
    );
    let one_byte_mock_atr = changed("ATR 3b00", "ATR 3b");
    assert!(inspect_trace(&one_byte_mock_atr, MOCK_NAME, limits()).is_ok());
    assert_eq!(
        inspect_trace(
            MOCK,
            MOCK_NAME,
            TraceLimits::new(4096, 16, 64, 32, 1).unwrap()
        ),
        Err(TraceError::InvalidAtrLength)
    );
}

#[test]
fn at_least_one_protocol_observation_is_required() {
    let input = String::from_utf8(MOCK.to_vec())
        .unwrap()
        .replace("record_count=3", "record_count=1")
        .split("000001")
        .next()
        .unwrap()
        .to_owned();
    assert_eq!(
        inspect_trace(input.as_bytes(), MOCK_NAME, limits()),
        Err(TraceError::ProtocolMissing)
    );
}

#[test]
fn mock_trace_cannot_smuggle_apdu_records() {
    assert_eq!(
        inspect_trace(
            &changed("000002 125 PROTOCOL 0203", "000002 125 APDU_TX 00a4040000"),
            MOCK_NAME,
            limits()
        ),
        Err(TraceError::ApduRecordNotAuthorized)
    );
    assert_eq!(
        inspect_trace(
            &changed("000002 125 PROTOCOL 0203", "000002 125 APDU_RX 9000"),
            MOCK_NAME,
            limits()
        ),
        Err(TraceError::ApduRecordNotAuthorized)
    );
}
