use qk_card_trace::{inspect_trace, TraceError, TraceLimits};

const MOCK: &[u8] = include_bytes!("fixtures/mock_trace_v1.txt");
const MOCK_NAME: &str = "qk-card-trace-v1__MOCK-F8G0-D-001__MOCK-J3R180-001__20260825T120000Z.txt";

fn limits() -> TraceLimits {
    TraceLimits::new(4096, 16, 512, 32, 33).unwrap()
}

fn changed(from: &str, to: &str) -> Vec<u8> {
    String::from_utf8(MOCK.to_vec())
        .expect("fixture ASCII")
        .replacen(from, to, 1)
        .into_bytes()
}

#[test]
fn live_mode_is_not_authorized_by_the_empty_registration() {
    assert_eq!(
        inspect_trace(&changed("mode=MOCK", "mode=LIVE"), MOCK_NAME, limits()),
        Err(TraceError::LiveModeNotAuthorized)
    );
}

#[test]
fn select_record_is_not_authorized_in_mock_scaffolding() {
    let input = changed("000002 125 PROTOCOL 0203", "000002 125 APDU_TX 00a4040000");
    assert_eq!(
        inspect_trace(&input, MOCK_NAME, limits()),
        Err(TraceError::ApduRecordNotAuthorized)
    );
}

#[test]
fn generic_get_data_record_is_not_authorized_in_mock_scaffolding() {
    let input = changed("000002 125 PROTOCOL 0203", "000002 125 APDU_TX 80ca000000");
    assert_eq!(
        inspect_trace(&input, MOCK_NAME, limits()),
        Err(TraceError::ApduRecordNotAuthorized)
    );
}

#[test]
fn management_record_is_not_authorized_in_mock_scaffolding() {
    let input = changed("000002 125 PROTOCOL 0203", "000002 125 APDU_TX 80e6000000");
    assert_eq!(
        inspect_trace(&input, MOCK_NAME, limits()),
        Err(TraceError::ApduRecordNotAuthorized)
    );
}

#[test]
fn response_record_is_not_authorized_in_mock_scaffolding() {
    let input = changed("000002 125 PROTOCOL 0203", "000002 125 APDU_RX 9000");
    assert_eq!(
        inspect_trace(&input, MOCK_NAME, limits()),
        Err(TraceError::ApduRecordNotAuthorized)
    );
}
