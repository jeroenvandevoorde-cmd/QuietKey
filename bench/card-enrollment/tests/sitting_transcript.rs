use std::path::PathBuf;

use qk_card_enrollment::{
    fixed_sitting_plan, run_fixed_sitting_plan, sitting_output_basename, EnrollmentMetadata,
    EnrollmentMode, NegotiatedProtocol, SittingError, SittingMetadata, SittingMode, SittingOutcome,
    SittingTranscript, CANONICAL_CAP_SHA256, IDENTITY_TOOL_VERSION, MAX_SITTING_TRANSCRIPT_BYTES,
    REGISTERED_J3R180_ATR, SITTING_CAMPAIGN_SOURCE_COMMIT, SITTING_READER_NAME,
    SITTING_TOOL_VERSION, SITTING_TRANSCRIPT_VERSION,
};

const UTC: &str = "2026-09-06T20:00:00Z";

fn metadata(mode: SittingMode) -> SittingMetadata {
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
    .expect("valid enrollment metadata");
    SittingMetadata::new(
        mode,
        enrollment,
        PathBuf::from("/tmp").join(sitting_output_basename(mode, UTC)),
    )
    .expect("valid sitting metadata")
}

#[test]
fn complete_transcript_is_ascii_lf_bounded_and_orders_each_flush_point() {
    let metadata = metadata(SittingMode::InstallInfo);
    let plan = fixed_sitting_plan(metadata.mode()).expect("registered plan");
    let mut transcript = SittingTranscript::new(Vec::new());
    transcript.write_header(&metadata).expect("header");
    transcript
        .record_event("EstablishContext", SittingOutcome::Pass)
        .expect("context event");
    transcript
        .record_readers(&[SITTING_READER_NAME.to_vec()])
        .expect("reader inventory");
    transcript
        .record_event("EnumerateReaders", SittingOutcome::Pass)
        .expect("reader event");
    transcript
        .record_event("ExclusiveConnect", SittingOutcome::Pass)
        .expect("connection event");
    transcript
        .record_event("Reset", SittingOutcome::Pass)
        .expect("reset event");
    transcript
        .record_observation(&REGISTERED_J3R180_ATR, Some(NegotiatedProtocol::T1))
        .expect("card observation");
    transcript
        .record_event("CaptureAtr", SittingOutcome::Pass)
        .expect("ATR event");
    transcript
        .record_event("CaptureProtocol", SittingOutcome::Pass)
        .expect("protocol event");
    let mut index = 0;
    let summary = run_fixed_sitting_plan(&plan, &mut transcript, |_request, response| {
        let expected = plan.exchanges()[index].expected_response();
        response[..expected.len()].copy_from_slice(expected);
        index += 1;
        Ok(expected.len())
    });
    assert_eq!(summary.outcome, SittingOutcome::Pass);
    transcript
        .record_counts(summary.transmit_calls, summary.received_responses)
        .expect("counts");
    transcript
        .record_disconnect(SittingOutcome::Pass)
        .expect("disconnect");
    transcript
        .record_result(SittingOutcome::Pass)
        .expect("result");
    assert!(transcript.bytes_written() <= MAX_SITTING_TRANSCRIPT_BYTES);
    let bytes = transcript.into_inner();
    assert!(bytes.is_ascii());
    assert!(bytes.ends_with(b"\n"));
    assert!(!bytes.contains(&b'\r'));
    let text = String::from_utf8(bytes).expect("ASCII transcript");
    assert!(text.starts_with(&format!("{SITTING_TRANSCRIPT_VERSION}\n")));
    assert!(text.contains("plan_version=1\n"));
    assert!(text.contains("tool_version=0.0.4\n"));
    assert!(text.contains(&format!("source_commit={SITTING_CAMPAIGN_SOURCE_COMMIT}\n")));
    assert!(text.contains(&format!(
        "campaign_source_commit={SITTING_CAMPAIGN_SOURCE_COMMIT}\n"
    )));
    assert!(text.contains(&format!("canonical_cap_sha256={CANONICAL_CAP_SHA256}\n")));
    assert!(text.contains("reader_count=1\n"));
    assert!(text.contains("protocol=T1\n"));
    assert!(text.contains("transmit_call_count=3\n"));
    assert!(text.contains("received_response_count=3\n"));
    assert!(text.contains("disconnect=PASS\n"));
    assert!(text.ends_with("result=PASS\n"));

    for pair in plan.exchanges().windows(2) {
        let current = pair[0].index();
        let next = pair[1].index();
        let tx = text.find(&format!("apdu.{current}.tx_hex=")).expect("tx");
        let rx = text.find(&format!("apdu.{current}.rx_hex=")).expect("rx");
        let comparison = text
            .find(&format!("apdu.{current}.comparison=PASS"))
            .expect("comparison");
        let next_tx = text.find(&format!("apdu.{next}.tx_hex=")).expect("next tx");
        assert!(tx < rx && rx < comparison && comparison < next_tx);
    }
}

#[test]
fn transcript_enforces_the_exact_byte_ceiling() {
    let mut transcript = SittingTranscript::new(Vec::new());
    let mut final_error = None;
    for _ in 0..MAX_SITTING_TRANSCRIPT_BYTES {
        if let Err(error) =
            transcript.record_event("BoundedRepeatedEventName", SittingOutcome::Pass)
        {
            final_error = Some(error);
            break;
        }
    }
    assert_eq!(final_error, Some(SittingError::SittingTranscriptTooLarge));
    assert!(transcript.bytes_written() <= MAX_SITTING_TRANSCRIPT_BYTES);
}

#[test]
fn sitting_version_bump_does_not_change_the_historical_identity_version() {
    assert_eq!(SITTING_TOOL_VERSION, "0.0.4");
    assert_eq!(IDENTITY_TOOL_VERSION, "0.0.3");
}
