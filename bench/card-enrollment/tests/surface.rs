const LIB: &str = include_str!("../src/lib.rs");
const MODEL: &str = include_str!("../src/model.rs");
const ADAPTER: &str = include_str!("../src/pcsc_adapter.rs");
const MAIN: &str = include_str!("../src/main.rs");
const MANIFEST: &str = include_str!("../Cargo.toml");

#[test]
fn production_roots_forbid_unsafe_code() {
    assert_eq!(LIB.matches("#![forbid(unsafe_code)]").count(), 1);
    assert_eq!(MAIN.matches("#![forbid(unsafe_code)]").count(), 1);
    for source in [LIB, MODEL, ADAPTER, MAIN] {
        assert!(!source.contains(concat!("extern", " \"C\"")));
        assert!(!source.contains(concat!("pcsc", "_sys")));
        assert!(!source.contains(concat!("pcsc", "-sys")));
    }
}

#[test]
fn safe_adapter_exposes_no_apdu_or_raw_handle_operation() {
    for source in [LIB, MODEL, ADAPTER, MAIN] {
        assert!(!source.contains(".transmit("));
        assert!(!source.contains(".control("));
        assert!(!source.contains(".get_attribute("));
        assert!(!source.contains(".begin_transaction("));
        assert!(!source.contains("pub fn card"));
        assert!(!source.contains("pub fn context"));
    }
    assert!(MODEL.contains("fn enumerate_readers(&mut self)"));
    assert!(MODEL.contains("fn capture_card(&mut self, reader_name: &[u8])"));
    assert_eq!(ADAPTER.matches("fn capture_card(").count(), 1);
    assert_eq!(ADAPTER.matches("mem::forget(card)").count(), 2);
    assert_eq!(ADAPTER.matches("Disposition::ResetCard").count(), 1);
}

#[test]
fn active_policy_has_one_explicit_transmit_refusal() {
    assert!(MODEL.contains(
        "EnrollmentOperation::Transmit => Err(EnrollmentError::ApduTransmitNotAuthorized)"
    ));
    assert_eq!(ADAPTER.matches("Transmit").count(), 0);
    assert_eq!(MAIN.matches("Transmit").count(), 0);
}

#[test]
fn manifest_has_only_the_reviewed_safe_wrapper_dependency() {
    let dependency_section = MANIFEST
        .split_once("[dependencies]\n")
        .expect("dependency section")
        .1
        .split_once("\n[")
        .expect("following section")
        .0;
    let entries: Vec<_> = dependency_section
        .lines()
        .filter(|line| !line.trim().is_empty() && !line.trim_start().starts_with('#'))
        .collect();
    assert_eq!(entries, ["pcsc = { version = \"=2.9.0\" }"]);
}

#[test]
fn public_reexports_are_the_reviewed_boundary() {
    let expected = [
        "authorize_operation",
        "run_enrollment",
        "CaptureAttempt",
        "CardCapture",
        "EnrollmentBackend",
        "EnrollmentError",
        "EnrollmentEvent",
        "EnrollmentMetadata",
        "EnrollmentMode",
        "EnrollmentOperation",
        "EnrollmentOutcome",
        "EnrollmentRecord",
        "NegotiatedProtocol",
        "ValidatedMetadata",
        "PcscEnrollmentBackend",
        "encode_transcript",
    ];
    for name in expected {
        assert!(LIB.contains(name), "missing reviewed public item: {name}");
    }
    assert!(!LIB.contains("pub use pcsc::"));
}
