use std::cell::RefCell;
use std::io::{self, Write};
use std::path::PathBuf;
use std::rc::Rc;

use qk_card_enrollment::{
    EnrollmentMetadata, EnrollmentMode, InitializationFields, ManagementObservationMetadata,
    ManagementObservationTranscript, NegotiatedProtocol, ObservationError, ObservationFailure,
    ObservationOutcome, ObservationPhase, SittingError, MANAGEMENT_OBSERVATION_ALLOWLIST_ID,
    MANAGEMENT_OBSERVATION_TOOL_VERSION, MANAGEMENT_OBSERVATION_TRANSCRIPT_VERSION,
    MAX_SITTING_TRANSCRIPT_BYTES, REGISTERED_J3R180_ATR, SITTING_CAMPAIGN_SOURCE_COMMIT,
    SITTING_READER_NAME,
};

const TOOL_SOURCE: &str = "1234567890abcdef1234567890abcdef12345678";
const UTC: &str = "2026-09-07T01:02:03Z";

fn metadata() -> ManagementObservationMetadata {
    let enrollment = EnrollmentMetadata {
        mode: EnrollmentMode::Enroll,
        source_commit: TOOL_SOURCE.to_owned(),
        timestamp_utc: UTC.to_owned(),
        host_alias: "iMac".to_owned(),
        reader_alias: "SCR3310-01".to_owned(),
        specimen_alias: Some("J3R180-02".to_owned()),
        selected_reader_name: Some(SITTING_READER_NAME.to_vec()),
    }
    .validate()
    .expect("valid Owner-supplied tool source and metadata");
    ManagementObservationMetadata::new(
        enrollment,
        PathBuf::from(format!(
            "/tmp/qk-card-sitting-v1__management-observe__J3R180-02__{UTC}.txt"
        )),
    )
    .expect("valid observation metadata")
}

#[test]
fn complete_private_transcript_is_ascii_lf_bounded_and_source_separated() {
    let metadata = metadata();
    let mut transcript = ManagementObservationTranscript::new(Vec::new());
    transcript.write_header(&metadata).expect("header");
    transcript
        .record_event(ObservationPhase::WriteHeader, ObservationOutcome::Pass)
        .expect("header event");
    transcript
        .record_readers(&[SITTING_READER_NAME.to_vec()])
        .expect("reader inventory");
    transcript
        .record_status(&REGISTERED_J3R180_ATR, Some(NegotiatedProtocol::T1))
        .expect("status");

    let exchanges = [
        (
            ObservationPhase::SelectIsd,
            vec![0x00, 0xa4, 0x04, 0x00],
            vec![0x6f, 0x00, 0x90, 0x00],
        ),
        (
            ObservationPhase::CardRecognition,
            vec![0x80, 0xca, 0x00, 0x66, 0x00],
            vec![0x66, 0x01, 0x73, 0x90, 0x00],
        ),
        (
            ObservationPhase::InitializeUpdate,
            vec![0x80, 0x50, 0x00, 0x00],
            vec![0xde, 0xad, 0xbe, 0xef, 0x90, 0x00],
        ),
        (
            ObservationPhase::KeyInformation,
            vec![0x80, 0xca, 0x00, 0xe0, 0x00],
            vec![0xe0, 0x00, 0x90, 0x00],
        ),
    ];
    for (index, (phase, request, response)) in exchanges.iter().enumerate() {
        transcript
            .record_request(index, *phase, request)
            .expect("request");
        transcript
            .record_response(index, *phase, response)
            .expect("private response");
        if *phase == ObservationPhase::InitializeUpdate {
            transcript
                .record_initialization_fields(&InitializationFields {
                    body_len: 28,
                    key_version: 0x4a,
                    scp_version: 0x02,
                    scp_i: None,
                })
                .expect("parsed initialization fields");
        }
        transcript
            .record_event(*phase, ObservationOutcome::Pass)
            .expect("phase event");
    }
    transcript.record_counts(4, 4).expect("counts");
    transcript
        .record_first_failure(None)
        .expect("no first failure");
    transcript
        .record_disconnect(ObservationOutcome::Pass)
        .expect("disconnect");
    transcript
        .record_result(ObservationOutcome::Pass)
        .expect("result");

    let expected_len = transcript.bytes_written();
    assert!(expected_len <= MAX_SITTING_TRANSCRIPT_BYTES);
    let bytes = transcript.into_inner();
    assert_eq!(bytes.len(), expected_len);
    assert!(bytes.is_ascii());
    assert!(bytes.ends_with(b"\n"));
    assert!(!bytes.contains(&b'\r'));
    let text = String::from_utf8(bytes).expect("ASCII transcript");
    assert!(text.starts_with(&format!("{MANAGEMENT_OBSERVATION_TRANSCRIPT_VERSION}\n")));
    assert!(text.contains(&format!(
        "allowlist={MANAGEMENT_OBSERVATION_ALLOWLIST_ID}\n"
    )));
    assert_eq!(MANAGEMENT_OBSERVATION_TOOL_VERSION, "0.0.5");
    assert!(text.contains("tool_version=0.0.5\n"));
    assert!(text.contains(&format!("source_commit={TOOL_SOURCE}\n")));
    assert!(text.contains(&format!(
        "campaign_source_commit={SITTING_CAMPAIGN_SOURCE_COMMIT}\n"
    )));
    assert_ne!(TOOL_SOURCE, SITTING_CAMPAIGN_SOURCE_COMMIT);
    assert!(text.contains("visibility=PRIVATE_CUSTODY_ONLY\n"));
    assert!(!text.contains("visibility=PUBLIC"));
    assert!(text.contains("exchange.2.rx_hex=deadbeef9000\n"));
    assert!(!text.contains("cryptogram="));
    assert!(text.contains("initialize.body_bytes=28\n"));
    assert!(text.contains("initialize.key_version_hex=4a\n"));
    assert!(text.contains("initialize.scp_version_hex=02\n"));
    assert!(text.contains("initialize.scp_i_hex=NONE\n"));
    assert!(text.contains("transmit_call_count=4\n"));
    assert!(text.contains("received_response_count=4\n"));
    assert!(text.contains("first_failure=NONE\n"));
    assert!(text.contains("disconnect=PASS\n"));
    assert!(text.ends_with("result=PASS\n"));

    for (index, (phase, _, _)) in exchanges.iter().enumerate().take(3) {
        let tx = text
            .find(&format!("exchange.{index}.tx_hex="))
            .expect("request");
        let rx = text
            .find(&format!("exchange.{index}.rx_hex="))
            .expect("response");
        let pass = text
            .find(&format!("={}:PASS", phase.name()))
            .expect("validation event");
        let next_tx = text
            .find(&format!("exchange.{}.tx_hex=", index + 1))
            .expect("next request");
        assert!(tx < rx && rx < pass && pass < next_tx);
    }
}

#[test]
fn full_258_byte_response_is_retained_as_private_lowercase_hex() {
    let response: Vec<u8> = (0u8..=255).chain([0x90, 0x00]).collect();
    assert_eq!(response.len(), 258);
    let mut transcript = ManagementObservationTranscript::new(Vec::new());
    transcript
        .record_response(2, ObservationPhase::InitializeUpdate, &response)
        .expect("bounded full response");
    let text = String::from_utf8(transcript.into_inner()).expect("ASCII transcript");
    assert_eq!(text, format!("exchange.2.rx_hex={}\n", hex(&response)));
}

#[test]
fn first_failure_is_encoded_once_with_its_exact_phase_and_name() {
    let failure = ObservationFailure {
        phase: ObservationPhase::InitializeUpdate,
        error: ObservationError::ObservationScpRejected,
    };
    let mut transcript = ManagementObservationTranscript::new(Vec::new());
    transcript
        .record_first_failure(Some(&failure))
        .expect("first failure");
    transcript
        .record_result(ObservationOutcome::Reject(failure.error))
        .expect("result");
    let text = String::from_utf8(transcript.into_inner()).expect("ASCII transcript");
    assert_eq!(
        text,
        "first_failure=InitializeUpdate:ObservationScpRejected\nevent_count=0\nresult=ObservationScpRejected\n"
    );
}

#[test]
fn transcript_cap_is_terminal_and_never_allows_later_output() {
    let mut transcript = ManagementObservationTranscript::new(Vec::new());
    let response = [0xa5; 258];
    loop {
        match transcript.record_response(999_999, ObservationPhase::KeyInformation, &response) {
            Ok(()) => {}
            Err(error) => {
                assert_eq!(
                    error,
                    ObservationError::Sitting(SittingError::SittingTranscriptTooLarge)
                );
                break;
            }
        }
    }
    let before = transcript.bytes_written();
    assert!(before <= MAX_SITTING_TRANSCRIPT_BYTES);
    assert_eq!(
        transcript.record_result(ObservationOutcome::Pass),
        Err(ObservationError::Sitting(
            SittingError::SittingTranscriptTooLarge
        ))
    );
    assert_eq!(transcript.bytes_written(), before);
    assert_eq!(transcript.into_inner().len(), before);
}

#[derive(Clone, Copy)]
enum WriterBehavior {
    Pass,
    WriteError,
    FlushError,
    WritePanic,
    FlushPanic,
    PartialThenError,
}

#[test]
fn every_completed_line_is_flushed_before_the_next_record() {
    let state = Rc::new(RefCell::new(WriterState::default()));
    let writer = HostileWriter {
        behavior: WriterBehavior::Pass,
        state: Rc::clone(&state),
    };
    let mut transcript = ManagementObservationTranscript::new(writer);
    transcript.write_header(&metadata()).expect("header");
    transcript
        .record_request(0, ObservationPhase::SelectIsd, &[0x00, 0xa4])
        .expect("request");
    transcript
        .record_response(0, ObservationPhase::SelectIsd, &[0x90, 0x00])
        .expect("response");
    transcript
        .record_event(ObservationPhase::SelectIsd, ObservationOutcome::Pass)
        .expect("validation event");
    let state = state.borrow();
    let completed_lines = state.bytes.iter().filter(|byte| **byte == b'\n').count();
    assert_eq!(state.flushes, completed_lines);
    assert_eq!(state.flushes, 17);
}

#[derive(Default)]
struct WriterState {
    bytes: Vec<u8>,
    writes: usize,
    flushes: usize,
}

struct HostileWriter {
    behavior: WriterBehavior,
    state: Rc<RefCell<WriterState>>,
}

impl Write for HostileWriter {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        let mut state = self.state.borrow_mut();
        let call = state.writes;
        state.writes += 1;
        match self.behavior {
            WriterBehavior::WriteError => Err(io::Error::other("write failure")),
            WriterBehavior::WritePanic => panic!("write panic"),
            WriterBehavior::PartialThenError if call == 0 => {
                let accepted = bytes.len().max(2) / 2;
                state.bytes.extend_from_slice(&bytes[..accepted]);
                Ok(accepted)
            }
            WriterBehavior::PartialThenError => Err(io::Error::other("partial write failure")),
            _ => {
                state.bytes.extend_from_slice(bytes);
                Ok(bytes.len())
            }
        }
    }

    fn flush(&mut self) -> io::Result<()> {
        let mut state = self.state.borrow_mut();
        state.flushes += 1;
        match self.behavior {
            WriterBehavior::FlushError => Err(io::Error::other("flush failure")),
            WriterBehavior::FlushPanic => panic!("flush panic"),
            _ => Ok(()),
        }
    }
}

#[test]
fn output_errors_panics_and_partial_writes_are_named_and_terminal() {
    for (behavior, expected) in [
        (
            WriterBehavior::WriteError,
            SittingError::SittingOutputWriteFailed,
        ),
        (
            WriterBehavior::FlushError,
            SittingError::SittingOutputFlushFailed,
        ),
        (
            WriterBehavior::WritePanic,
            SittingError::SittingBoundaryPanicked,
        ),
        (
            WriterBehavior::FlushPanic,
            SittingError::SittingBoundaryPanicked,
        ),
        (
            WriterBehavior::PartialThenError,
            SittingError::SittingOutputWriteFailed,
        ),
    ] {
        let state = Rc::new(RefCell::new(WriterState::default()));
        let writer = HostileWriter {
            behavior,
            state: Rc::clone(&state),
        };
        let mut transcript = ManagementObservationTranscript::new(writer);
        assert_eq!(
            transcript.record_event(ObservationPhase::WriteHeader, ObservationOutcome::Pass),
            Err(ObservationError::Sitting(expected))
        );
        let writes = state.borrow().writes;
        let flushes = state.borrow().flushes;
        let retained = state.borrow().bytes.clone();
        assert_eq!(
            transcript.record_result(ObservationOutcome::Pass),
            Err(ObservationError::Sitting(expected))
        );
        assert_eq!(state.borrow().writes, writes);
        assert_eq!(state.borrow().flushes, flushes);
        assert_eq!(state.borrow().bytes, retained);
    }
}

fn hex(input: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut output = String::with_capacity(input.len() * 2);
    for byte in input {
        output.push(char::from(HEX[usize::from(byte >> 4)]));
        output.push(char::from(HEX[usize::from(byte & 0x0f)]));
    }
    output
}
