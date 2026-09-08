use std::cell::RefCell;
use std::io::{self, Write};
use std::path::PathBuf;
use std::rc::Rc;

use qk_card_enrollment::{
    b6_exchange, b6_output_basename, B6Error, B6Metadata, B6Observer, B6Outcome, B6SignatureFacts,
    B6Transcript, EnrollmentMetadata, EnrollmentMode, NegotiatedProtocol, B6_PLAN_SHA256,
    B6_TOOL_VERSION, B6_TRANSCRIPT_LIMIT_ID, B6_TRANSCRIPT_VERSION, CANONICAL_CAP_BYTES,
    CANONICAL_CAP_SHA256, GOLDEN_FIXTURE_BLOB, GOLDEN_FIXTURE_BYTES, GOLDEN_FIXTURE_LF,
    GOLDEN_FIXTURE_PATH, GOLDEN_FIXTURE_SHA256, MAX_B6_TRANSCRIPT_BYTES, MAX_READERS,
    MAX_READER_NAME_BYTES, MAX_SITTING_CAPTURE_BYTES, MAX_SITTING_TRANSCRIPT_BYTES,
    REGISTERED_J3R180_ATR, SITTING_APPLET_SOURCE_COMMIT, SITTING_CAMPAIGN_SOURCE_COMMIT,
    SITTING_READER_NAME,
};

const UTC: &str = "2026-09-07T16:00:00Z";

fn metadata() -> B6Metadata {
    let enrollment = EnrollmentMetadata {
        mode: EnrollmentMode::Enroll,
        source_commit: SITTING_CAMPAIGN_SOURCE_COMMIT.to_owned(),
        timestamp_utc: UTC.to_owned(),
        host_alias: "iMac".to_owned(),
        reader_alias: "SCR3310-01".to_owned(),
        specimen_alias: Some("J3R180-02".to_owned()),
        selected_reader_name: Some(SITTING_READER_NAME.to_vec()),
    }
    .validate()
    .expect("valid registered apparatus");
    B6Metadata::new(
        enrollment,
        PathBuf::from("/tmp").join(b6_output_basename(UTC)),
    )
    .expect("valid B6 metadata")
}

#[derive(Clone, Copy, Default)]
enum Failure {
    #[default]
    None,
    Write,
    Flush,
    WritePanic,
    FlushPanic,
}

#[derive(Default)]
struct WriterState {
    bytes: Vec<u8>,
    flush_points: Vec<usize>,
    failure: Failure,
    calls: usize,
}

#[derive(Clone, Default)]
struct ObservedWriter(Rc<RefCell<WriterState>>);

impl Write for ObservedWriter {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        let mut state = self.0.borrow_mut();
        state.calls += 1;
        match state.failure {
            Failure::Write => Err(io::Error::other("synthetic write failure")),
            Failure::WritePanic => panic!("synthetic write panic"),
            _ => {
                state.bytes.extend_from_slice(bytes);
                Ok(bytes.len())
            }
        }
    }

    fn flush(&mut self) -> io::Result<()> {
        let mut state = self.0.borrow_mut();
        state.calls += 1;
        match state.failure {
            Failure::Flush => Err(io::Error::other("synthetic flush failure")),
            Failure::FlushPanic => panic!("synthetic flush panic"),
            _ => {
                let end = state.bytes.len();
                state.flush_points.push(end);
                Ok(())
            }
        }
    }
}

fn text(writer: &ObservedWriter) -> String {
    String::from_utf8(writer.0.borrow().bytes.clone()).expect("ASCII transcript")
}

#[test]
fn header_binds_every_sitting_identity_and_the_expanded_b6_plan() {
    let mut transcript = B6Transcript::new(Vec::new());
    transcript.write_header(&metadata()).expect("header");
    let bytes = transcript.into_inner();
    assert!(bytes.is_ascii());
    assert!(bytes.ends_with(b"\n"));
    assert!(!bytes.contains(&b'\r'));
    assert!(!bytes.contains(&0));
    let text = String::from_utf8(bytes).expect("ASCII");
    assert!(text.starts_with(&format!("{B6_TRANSCRIPT_VERSION}\n")));
    for (field, value) in [
        ("plan_version", "1".to_owned()),
        ("plan_sha256", B6_PLAN_SHA256.to_owned()),
        ("tool_version", B6_TOOL_VERSION.to_owned()),
        ("source_commit", SITTING_CAMPAIGN_SOURCE_COMMIT.to_owned()),
        (
            "campaign_source_commit",
            SITTING_CAMPAIGN_SOURCE_COMMIT.to_owned(),
        ),
        (
            "applet_source_commit",
            SITTING_APPLET_SOURCE_COMMIT.to_owned(),
        ),
        ("canonical_cap_bytes", CANONICAL_CAP_BYTES.to_string()),
        ("canonical_cap_sha256", CANONICAL_CAP_SHA256.to_owned()),
        ("golden_fixture_path", GOLDEN_FIXTURE_PATH.to_owned()),
        ("golden_fixture_bytes", GOLDEN_FIXTURE_BYTES.to_string()),
        ("golden_fixture_lf", GOLDEN_FIXTURE_LF.to_string()),
        ("golden_fixture_sha256", GOLDEN_FIXTURE_SHA256.to_owned()),
        ("golden_fixture_blob", GOLDEN_FIXTURE_BLOB.to_owned()),
        ("transcript_limit_id", B6_TRANSCRIPT_LIMIT_ID.to_owned()),
        ("transcript_limit_bytes", "2097152".to_owned()),
        ("timestamp_utc", UTC.to_owned()),
        ("host_alias", "iMac".to_owned()),
        ("reader_alias", "SCR3310-01".to_owned()),
        ("specimen_alias", "J3R180-02".to_owned()),
        ("output_basename", b6_output_basename(UTC)),
    ] {
        assert!(text.contains(&format!("{field}={value}\n")), "{field}");
    }
    assert_eq!(B6_TOOL_VERSION, "0.0.7");
    assert_eq!(
        SITTING_CAMPAIGN_SOURCE_COMMIT,
        "d706e0dbe4826bb2b65a5e00ed61ccd8921cc22c"
    );
    assert_eq!(
        SITTING_APPLET_SOURCE_COMMIT,
        "d706e0dbe4826bb2b65a5e00ed61ccd8921cc22c"
    );
    assert_eq!(CANONICAL_CAP_BYTES, 40_914);
    assert_eq!(
        CANONICAL_CAP_SHA256,
        "edad47ec29421b5802281f6426d72a8c5994831cc7a265d223ede6234310b8ae"
    );
    assert_eq!(B6_TRANSCRIPT_VERSION, "QK-CARD-B6-V1");
    assert_eq!(MAX_B6_TRANSCRIPT_BYTES, 2_097_152);
    assert_eq!(MAX_SITTING_TRANSCRIPT_BYTES, 32_768);
}

#[test]
fn full_transcript_shape_records_all_bytes_and_facts_below_its_own_cap() {
    let writer = ObservedWriter::default();
    let mut transcript = B6Transcript::new(writer.clone());
    transcript.write_header(&metadata()).expect("header");
    transcript
        .record_readers(&[SITTING_READER_NAME.to_vec()])
        .expect("reader inventory");
    transcript
        .record_observation(&REGISTERED_J3R180_ATR, Some(NegotiatedProtocol::T1))
        .expect("observation");
    for session in 0..10 {
        transcript.session_start(session, UTC).expect("start");
        for position in 0..102 {
            let exchange = b6_exchange(session, position).expect("compiled exchange");
            transcript.record_request(&exchange).expect("tx");
            let response = match position {
                0 => vec![0x90, 0x00],
                1 => vec![0x11; 23],
                _ => vec![0x22; 164],
            };
            transcript
                .record_response(&exchange, &response)
                .expect("raw rx");
            if position >= 2 {
                let mut r = [0u8; 32];
                r[28..].copy_from_slice(&((session * 100 + position - 1) as u32).to_be_bytes());
                transcript
                    .record_signature(
                        &exchange,
                        B6SignatureFacts {
                            normalized: position % 2 == 0,
                            r,
                            verified: true,
                        },
                    )
                    .expect("signature facts");
            }
            transcript
                .record_comparison(&exchange, B6Outcome::Pass)
                .expect("comparison");
        }
        transcript
            .session_end(session, UTC, B6Outcome::Pass)
            .expect("end");
    }
    transcript.record_counts(1020, 1020).expect("counts");
    transcript
        .record_disconnect(B6Outcome::Pass)
        .expect("disconnect");
    transcript.record_result(B6Outcome::Pass).expect("result");
    let state = writer.0.borrow();
    assert_eq!(transcript.bytes_written(), state.bytes.len());
    assert!((800_000..1_100_000).contains(&state.bytes.len()));
    assert!(state.bytes.len() <= MAX_B6_TRANSCRIPT_BYTES);
    assert!(state.bytes.len() > MAX_SITTING_TRANSCRIPT_BYTES);
    let text = String::from_utf8(state.bytes.clone()).expect("ASCII");
    let line_ends: Vec<_> = state
        .bytes
        .iter()
        .enumerate()
        .filter_map(|(index, byte)| (*byte == b'\n').then_some(index + 1))
        .collect();
    assert_eq!(state.flush_points, line_ends, "every line was flushed");
    for session in 0..10 {
        assert!(text.contains(&format!("session.{session}.start_utc={UTC}\n")));
        assert!(text.contains(&format!("session.{session}.end_utc={UTC}\n")));
        assert!(text.contains(&format!("session.{session}.result=PASS\n")));
    }
    assert_eq!(text.matches(".tx_hex=").count(), 1020);
    assert_eq!(text.matches(".rx_hex=").count(), 1020);
    assert_eq!(text.matches(".comparison=PASS\n").count(), 1020);
    assert_eq!(text.matches(".normalized=").count(), 1000);
    assert_eq!(text.matches(".r_hex=").count(), 1000);
    assert_eq!(text.matches(".verify=PASS\n").count(), 1000);
    assert!(text.contains("signature_fact_count=1000\n"));
    assert!(text.contains("normalization_changed_count=500\n"));
    assert!(text.contains(&format!("apdu.2.r_hex={}1\n", "0".repeat(63))));
    assert!(text.contains("transmit_call_count=1020\n"));
    assert!(text.contains("received_response_count=1020\n"));
    assert!(text.ends_with("result=PASS\n"));
    for index in 0..1020 {
        let tx = text.find(&format!("apdu.{index}.tx_hex=")).expect("tx");
        let rx = text.find(&format!("apdu.{index}.rx_hex=")).expect("rx");
        let compared = text
            .find(&format!("apdu.{index}.comparison=PASS\n"))
            .expect("comparison");
        assert!(tx < rx && rx < compared);
        if index != 1019 {
            let next = text
                .find(&format!("apdu.{}.tx_hex=", index + 1))
                .expect("next tx");
            assert!(compared < next);
        }
    }
}

#[test]
fn hostile_response_and_named_failure_remain_before_session_end() {
    let mut transcript = B6Transcript::new(Vec::new());
    let exchange = b6_exchange(0, 2).expect("first SIGN");
    transcript.session_start(0, UTC).expect("start");
    transcript.record_request(&exchange).expect("request");
    let hostile = [0x6f, 0x0d];
    transcript.record_response(&exchange, &hostile).expect("rx");
    let failure = B6Outcome::Reject(B6Error::B6StatusRejected);
    transcript
        .record_comparison(&exchange, failure)
        .expect("failure comparison");
    transcript.session_end(0, UTC, failure).expect("end");
    transcript.record_counts(1, 1).expect("counts");
    transcript
        .record_disconnect(B6Outcome::Pass)
        .expect("disconnect");
    transcript.record_result(failure).expect("failure result");
    let text = String::from_utf8(transcript.into_inner()).expect("ASCII");
    let rx = text.find("apdu.2.rx_hex=6f0d\n").expect("raw response");
    let compared = text
        .find("apdu.2.comparison=B6StatusRejected\n")
        .expect("named rejection");
    let ended = text.find("session.0.end_utc=").expect("end timestamp");
    assert!(rx < compared && compared < ended);
    assert!(text.ends_with("result=B6StatusRejected\n"));
    assert!(text.contains("apdu.2.normalized=NOT_EVALUATED\n"));
    assert!(text.contains("apdu.2.r_hex=NONE\n"));
    assert!(text.contains("apdu.2.verify=NOT_EVALUATED\n"));
}

#[test]
fn failed_curve_fact_and_normalization_change_are_logged_without_a_claim() {
    let mut transcript = B6Transcript::new(Vec::new());
    let exchange = b6_exchange(1, 2).expect("later SIGN");
    transcript
        .record_signature(
            &exchange,
            B6SignatureFacts {
                normalized: true,
                r: [0x12; 32],
                verified: false,
            },
        )
        .expect("computed facts before curve rejection");
    transcript
        .record_result(B6Outcome::Reject(B6Error::B6SignatureVerificationFailed))
        .expect("rejection");
    let text = String::from_utf8(transcript.into_inner()).expect("ASCII");
    assert!(text.contains("apdu.104.normalized=true\n"));
    assert!(text.contains(&format!("apdu.104.r_hex={}\n", "12".repeat(32))));
    assert!(text.contains("apdu.104.verify=FAIL\n"));
    assert!(text.contains("normalization_changed_count=1\n"));
    assert!(text.contains("signature_fact_count=1\n"));
    assert!(!text.contains("quality"));
    assert!(!text.contains("entropy"));
}

#[test]
fn writer_failures_and_unwinds_preserve_evidence_and_block_later_writes() {
    for (failure, expected) in [
        (Failure::Write, B6Error::B6OutputWriteFailed),
        (Failure::Flush, B6Error::B6OutputFlushFailed),
        (Failure::WritePanic, B6Error::B6BoundaryPanicked),
        (Failure::FlushPanic, B6Error::B6BoundaryPanicked),
    ] {
        let writer = ObservedWriter::default();
        let mut transcript = B6Transcript::new(writer.clone());
        transcript
            .record_event("BeforeFault", B6Outcome::Pass)
            .expect("preserved prefix");
        let prefix = text(&writer);
        writer.0.borrow_mut().failure = failure;
        assert_eq!(
            transcript.record_event("Fault", B6Outcome::Pass),
            Err(expected)
        );
        let retained = text(&writer);
        assert!(retained.starts_with(&prefix));
        if matches!(failure, Failure::Flush | Failure::FlushPanic) {
            assert!(retained.contains("event.1=Fault:PASS\n"));
        }
        writer.0.borrow_mut().failure = Failure::None;
        let call_count = writer.0.borrow().calls;
        assert_eq!(transcript.record_result(B6Outcome::Pass), Err(expected));
        assert_eq!(
            transcript.session_end(0, UTC, B6Outcome::Pass),
            Err(expected)
        );
        assert_eq!(writer.0.borrow().calls, call_count);
        assert_eq!(text(&writer), retained);
        assert_eq!(transcript.bytes_written(), retained.len());
    }
}

#[test]
fn format_injection_and_unbounded_observations_are_named_before_output() {
    for operation in ["", "x\ny", "x\ry", "x\0y", "x\ty", "x=y", "\u{80}"] {
        let mut transcript = B6Transcript::new(Vec::new());
        assert_eq!(
            transcript.record_event(operation, B6Outcome::Pass),
            Err(B6Error::B6SequenceViolation)
        );
        assert!(transcript.into_inner().is_empty());
    }
    for (session, utc) in [(10, UTC), (0, "yesterday"), (0, "2026-09-07T16:00:00Z\n")] {
        let mut transcript = B6Transcript::new(Vec::new());
        assert_eq!(
            transcript.session_start(session, utc),
            Err(B6Error::B6SequenceViolation)
        );
        assert!(transcript.into_inner().is_empty());
    }
    let mut transcript = B6Transcript::new(Vec::new());
    assert_eq!(
        transcript.record_readers(&vec![vec![b'x']; MAX_READERS + 1]),
        Err(B6Error::B6ReaderCountExceeded)
    );
    assert!(transcript.into_inner().is_empty());
    let mut transcript = B6Transcript::new(Vec::new());
    assert_eq!(
        transcript.record_readers(&[vec![b'x'; MAX_READER_NAME_BYTES + 1]]),
        Err(B6Error::B6ReaderNameRejected)
    );
    assert!(transcript.into_inner().is_empty());
    let mut transcript = B6Transcript::new(Vec::new());
    let exchange = b6_exchange(0, 0).expect("SELECT");
    assert_eq!(
        transcript.record_response(&exchange, &[0; MAX_SITTING_CAPTURE_BYTES + 1]),
        Err(B6Error::B6ResponseCaptureExceeded)
    );
    assert!(transcript.into_inner().is_empty());
}

#[test]
fn writer_drop_does_not_discard_or_replace_a_flushed_failure_record() {
    let writer = ObservedWriter::default();
    let before_drop;
    {
        let mut transcript = B6Transcript::new(writer.clone());
        transcript
            .record_result(B6Outcome::Reject(B6Error::B6RepeatedR))
            .expect("retained failure");
        before_drop = text(&writer);
    }
    assert_eq!(text(&writer), before_drop);
    assert!(before_drop.ends_with("result=B6RepeatedR\n"));
}
