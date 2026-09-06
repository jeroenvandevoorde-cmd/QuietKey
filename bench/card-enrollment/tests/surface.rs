const LIB: &str = include_str!("../src/lib.rs");
const IDENTITY: &str = include_str!("../src/identity.rs");
const IDENTITY_TRANSCRIPT: &str = include_str!("../src/identity_transcript.rs");
const MODEL: &str = include_str!("../src/model.rs");
const ADAPTER: &str = include_str!("../src/pcsc_adapter.rs");
const IDENTITY_ADAPTER: &str = include_str!("../src/pcsc_identity_adapter.rs");
const SITTING: &str = include_str!("../src/sitting.rs");
const SITTING_TRANSCRIPT: &str = include_str!("../src/sitting_transcript.rs");
const SITTING_ADAPTER: &str = include_str!("../src/pcsc_sitting_adapter.rs");
const TRANSCRIPT: &str = include_str!("../src/transcript.rs");
const MAIN: &str = include_str!("../src/main.rs");
const MANIFEST: &str = include_str!("../Cargo.toml");

#[test]
fn production_roots_forbid_unsafe_code() {
    assert_eq!(LIB.matches("#![forbid(unsafe_code)]").count(), 1);
    assert_eq!(MAIN.matches("#![forbid(unsafe_code)]").count(), 1);
    for source in [
        LIB,
        IDENTITY,
        IDENTITY_TRANSCRIPT,
        MODEL,
        ADAPTER,
        IDENTITY_ADAPTER,
        SITTING,
        SITTING_TRANSCRIPT,
        SITTING_ADAPTER,
        TRANSCRIPT,
        MAIN,
    ] {
        assert!(!source.contains(concat!("extern", " \"C\"")));
        assert!(!source.contains(concat!("pcsc", "_sys")));
        assert!(!source.contains(concat!("pcsc", "-sys")));
    }
}

#[test]
fn safe_adapter_exposes_only_the_three_private_fixed_transmits() {
    for source in [
        LIB,
        IDENTITY,
        IDENTITY_TRANSCRIPT,
        MODEL,
        ADAPTER,
        TRANSCRIPT,
        SITTING,
        SITTING_TRANSCRIPT,
        MAIN,
    ] {
        assert!(!source.contains(".transmit("));
    }
    assert_eq!(IDENTITY_ADAPTER.matches(".transmit(").count(), 3);
    assert_eq!(SITTING_ADAPTER.matches(".transmit(").count(), 1);
    for source in [
        LIB,
        IDENTITY,
        IDENTITY_TRANSCRIPT,
        MODEL,
        ADAPTER,
        IDENTITY_ADAPTER,
        SITTING,
        SITTING_TRANSCRIPT,
        SITTING_ADAPTER,
        TRANSCRIPT,
        MAIN,
    ] {
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
    assert_eq!(
        IDENTITY_ADAPTER.matches("Disposition::ResetCard").count(),
        1
    );
    assert_eq!(
        IDENTITY_ADAPTER
            .matches("SELECT_DEFAULT_APPLICATION_COMMAND")
            .count(),
        3
    );
    assert_eq!(
        IDENTITY_ADAPTER.matches("CARD_RECOGNITION_COMMAND").count(),
        3
    );
    assert_eq!(IDENTITY_ADAPTER.matches("CPLC_COMMAND").count(), 3);
    let select_transmit = IDENTITY_ADAPTER
        .find("card.transmit(&SELECT_DEFAULT_APPLICATION_COMMAND")
        .expect("fixed SELECT transmit");
    let card_recognition_transmit = IDENTITY_ADAPTER
        .find("card.transmit(&CARD_RECOGNITION_COMMAND")
        .expect("fixed Card Recognition transmit");
    let cplc_transmit = IDENTITY_ADAPTER
        .find("card.transmit(&CPLC_COMMAND")
        .expect("fixed CPLC transmit");
    assert!(select_transmit < card_recognition_transmit);
    assert!(card_recognition_transmit < cplc_transmit);
    assert!(IDENTITY.contains("fn capture_identity(&mut self, reader_name: &[u8])"));
    assert!(!IDENTITY.contains("apdu: &[u8]"));
    assert!(!IDENTITY_ADAPTER.contains("apdu: &[u8]"));
    assert!(
        IDENTITY_ADAPTER
            .find("attempt.observed_protocol = observed_protocol;")
            .expect("protocol observation")
            < IDENTITY_ADAPTER
                .find("if atr.is_empty()")
                .expect("ATR rejection precedence"),
        "the returned protocol must be retained even when ATR validation rejects"
    );
}

#[test]
fn active_policy_has_one_explicit_transmit_refusal() {
    assert!(MODEL.contains(
        "EnrollmentOperation::Transmit => Err(EnrollmentError::ApduTransmitNotAuthorized)"
    ));
    assert_eq!(ADAPTER.matches("Transmit").count(), 0);
    assert!(!MAIN.contains("caller-apdu"));
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
        "run_identity",
        "validate_select_response",
        "validate_card_recognition_response",
        "validate_cplc_response",
        "IdentityAttempt",
        "IdentityBackend",
        "IdentityError",
        "IdentityEvent",
        "IdentityExchange",
        "IdentityOperation",
        "IdentityOutcome",
        "IdentityRecord",
        "execute_pcsc_identity",
        "encode_identity_transcript",
    ];
    for name in expected {
        assert!(LIB.contains(name), "missing reviewed public item: {name}");
    }
    assert!(!LIB.contains("pub use pcsc::"));
    assert!(!LIB.contains("PcscIdentityBackend"));
    assert!(!IDENTITY_ADAPTER.contains("pub struct PcscIdentityBackend"));
    assert!(!IDENTITY_ADAPTER.contains("pub fn new()"));
    assert!(IDENTITY_ADAPTER.contains("pub fn execute_pcsc_identity("));
    assert!(SITTING_ADAPTER.contains("pub fn execute_pcsc_sitting("));
    assert!(!SITTING_ADAPTER.contains("pub struct"));
    assert!(!SITTING.contains("apdu: &[u8]"));
}

#[test]
fn sitting_dev_dependencies_and_historical_version_literal_are_exact() {
    let dev_section = MANIFEST
        .split_once("[dev-dependencies]\n")
        .expect("dev dependency section")
        .1
        .split_once("\n[")
        .expect("following section")
        .0;
    let entries: Vec<_> = dev_section
        .lines()
        .filter(|line| !line.trim().is_empty() && !line.trim_start().starts_with('#'))
        .collect();
    assert_eq!(
        entries,
        [
            "qk-card-model = { path = \"../../host/qk-card-model\" }",
            "qk-card-protocol = { path = \"../../host/qk-card-protocol\" }",
        ]
    );
    assert!(LIB.contains("pub const IDENTITY_TOOL_VERSION: &str = \"0.0.3\";"));
    assert!(LIB.contains("pub const SITTING_TOOL_VERSION: &str = env!(\"CARGO_PKG_VERSION\");"));
}
