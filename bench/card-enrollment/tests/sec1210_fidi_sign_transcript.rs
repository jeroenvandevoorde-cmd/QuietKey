use qk_card_enrollment::*;
use qk_sec1210_wire::{Decoder, Message, RawFrameSpan, RawObservation, Response};

fn complete() -> Sec1210FidiSignSummary {
    Sec1210FidiSignSummary {
        request_count: 107,
        response_count: 107,
        event_count: 0,
        captured_rx_bytes: 18_400,
        read_fragment_count: 2_300,
        apdu_transmit_count: 102,
        apdu_response_count: 102,
        apdu_accepted_count: 102,
        signature_fact_count: 100,
        signature_accepted_count: 100,
        normalization_changed_count: 51,
        completed_sessions: 1,
        wtx_count: 0,
        time_extension_count: 0,
        set_parameters_accepted: true,
        ifs_accepted: true,
        local_handle_released: true,
        session_start_utc: Some("2026-09-14T00:00:00Z".into()),
        session_end_utc: Some("2026-09-14T00:00:40Z".into()),
        failure: None,
    }
}

fn failed() -> Sec1210FidiSignSummary {
    let mut summary = complete();
    summary.failure = Some(Sec1210FidiSignError::TranscriptLimit);
    summary
}

fn parameters_reply(status: u8, error: u8, protocol: u8, payload: &[u8]) -> Box<Response> {
    let mut bytes = vec![0x03, 0x06, 0x82];
    bytes.extend_from_slice(&(payload.len() as u32).to_le_bytes());
    bytes.extend_from_slice(&[0, 4, status, error, protocol]);
    bytes.extend_from_slice(payload);
    bytes.push(bytes.iter().fold(0, |xor, byte| xor ^ byte));
    let mut decoder = Decoder::default();
    let mut response = None;
    for byte in bytes {
        if let Some(Message::Response(reply)) = decoder.push(byte).unwrap() {
            response = Some(reply);
        }
    }
    decoder.finish().unwrap();
    response.unwrap()
}

#[test]
fn one_megabyte_cap_reserves_terminal_records_and_stays_latched() {
    let mut transcript = Sec1210FidiSignTranscript::new(Vec::new());
    while transcript.field("record", &"a".repeat(512)).is_ok() {}
    assert!(transcript.bytes_written() > MAX_SEC1210_FIDI_READBACK_TRANSCRIPT_BYTES);
    assert!(transcript.bytes_written() <= 1_048_576 - 8_192);
    assert_eq!(
        transcript.field("later", "not written"),
        Err(Sec1210FidiSignError::TranscriptLimit)
    );
    transcript.finish(&failed()).unwrap();
    let bytes = transcript.into_inner();
    assert!(bytes.len() <= MAX_SEC1210_FIDI_SIGN_TRANSCRIPT_BYTES);
    let text = String::from_utf8(bytes).unwrap();
    assert!(text.contains("transcript_overflow=TRUE\n"));
    assert!(text.ends_with(&format!(
        "result={}\n",
        Sec1210FidiSignError::TranscriptLimit.name()
    )));
    assert!(!text.contains("later="));
}

#[test]
fn overflow_cannot_turn_an_otherwise_complete_summary_into_pass() {
    let mut transcript = Sec1210FidiSignTranscript::new(Vec::new());
    assert_eq!(
        transcript.field("oversize", &"a".repeat(8_193)),
        Err(Sec1210FidiSignError::TranscriptLimit)
    );
    transcript.finish(&complete()).unwrap();
    let text = String::from_utf8(transcript.into_inner()).unwrap();
    assert!(text.contains("transcript_overflow=TRUE\n"));
    assert!(!text.contains("result=PASS\n"));
}

#[test]
fn field_injection_is_rejected_before_output() {
    for value in ["a\nb", "a\rb", "a\0b", "é"] {
        let mut transcript = Sec1210FidiSignTranscript::new(Vec::new());
        assert!(transcript.field("x", value).is_err());
        assert!(transcript.into_inner().is_empty());
    }
    for name in ["x\nresult", "x\rresult", "x\0result", "é", "x=result", ""] {
        let mut transcript = Sec1210FidiSignTranscript::new(Vec::new());
        assert!(transcript.field(name, "x").is_err());
        assert!(transcript.into_inner().is_empty());
    }
    let mut transcript = Sec1210FidiSignTranscript::new(Vec::new());
    assert_eq!(
        transcript.hex("x", &[0; 4_097]),
        Err(Sec1210FidiSignError::TranscriptLimit)
    );
    assert!(transcript.into_inner().is_empty());
}

#[test]
fn partial_io_failure_is_sticky_and_preserves_the_written_prefix() {
    struct Limited {
        bytes: Vec<u8>,
    }
    impl std::io::Write for Limited {
        fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
            if self.bytes.len() == 4 {
                return Err(std::io::Error::other("full"));
            }
            let count = bytes.len().min(4 - self.bytes.len());
            self.bytes.extend_from_slice(&bytes[..count]);
            Ok(count)
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }
    let mut transcript = Sec1210FidiSignTranscript::new(Limited { bytes: vec![] });
    assert_eq!(
        transcript.field("x", "1234"),
        Err(Sec1210FidiSignError::TranscriptIo)
    );
    assert_eq!(
        transcript.hex("x", &[0; 4_097]),
        Err(Sec1210FidiSignError::TranscriptIo)
    );
    assert_eq!(
        transcript.finish(&failed()),
        Err(Sec1210FidiSignError::TranscriptIo)
    );
    assert_eq!(transcript.into_inner().bytes, b"x=12");
}

#[test]
fn flush_failure_is_sticky_without_manufacturing_a_result_line() {
    struct FailFlush(Vec<u8>);
    impl std::io::Write for FailFlush {
        fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
            self.0.extend_from_slice(bytes);
            Ok(bytes.len())
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Err(std::io::Error::other("flush"))
        }
    }
    let mut transcript = Sec1210FidiSignTranscript::new(FailFlush(Vec::new()));
    assert_eq!(
        transcript.field("x", "1"),
        Err(Sec1210FidiSignError::TranscriptIo)
    );
    assert_eq!(
        transcript.finish(&complete()),
        Err(Sec1210FidiSignError::TranscriptIo)
    );
    assert_eq!(transcript.into_inner().0, b"x=1\n");
}

#[test]
fn header_binds_sign_subset_parent_public_fields_and_all_new_limits() {
    let utc = "2026-09-14T00:00:00Z";
    let metadata = Sec1210FidiSignMetadata::new(
        "a".repeat(40),
        utc.into(),
        "RIG-HOST-PI3B-01",
        "J3R180-03",
        std::env::temp_dir().join(sec1210_fidi_sign_output_basename(utc)),
    )
    .unwrap();
    let mut transcript = Sec1210FidiSignTranscript::new(Vec::new());
    transcript.header(&metadata).unwrap();
    let text = String::from_utf8(transcript.into_inner()).unwrap();
    assert!(text.starts_with("QK-CARD-SITTING-V1\n"));
    for line in [
        "visibility=PRIVATE_CUSTODY_ONLY",
        "allowlist=QK-DEC-167-SUP-013",
        "tool_version=0.0.13",
        "mode=sec1210-fidi-sign",
        "campaign_source_commit=d706e0dbe4826bb2b65a5e00ed61ccd8921cc22c",
        "applet_source_commit=d706e0dbe4826bb2b65a5e00ed61ccd8921cc22c",
        "canonical_cap_bytes=40914",
        "canonical_cap_sha256=edad47ec29421b5802281f6426d72a8c5994831cc7a265d223ede6234310b8ae",
        "parent_b6_plan_sha256=44ca636942407f6523d5641cf1bf4396bb07b980ec534395514dee0abd31b348",
        "parent_b6_plan_bytes=132360",
        "parent_b6_plan_requests=1020",
        "plan_sha256=ad0ffd7e79ebb8500a4f94a5f06aa527ec59537a59923956170f45cfdbdf3659",
        "plan_bytes=13236",
        "plan_requests=102",
        "b6.session_id_hex=c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0",
        "b6.wallet_id_hex=d5b7e52f569ae51e7c66af14240d8e4459c6246785ce5c441773995614f60e9e",
        "b6.review_hash_hex=9c5de46f2ac5f29f6c9335b4016b65fe96aa0cd04e3a6b5b7224389db5fae3a3",
        "b6.digest_hex=0d3d0763b43943f0f5342003355f8359fff4ba942dae2286becc635dc88d8386",
        "b6.public_key_hex=039ad8f874de32ed2b168124da668f7ac6dbb5f8d9330da245ecf7098538bef79f",
        "set_parameters.requested_bmFindexDindex=18",
        "t1.initial_ifsd=32",
        "t1.requested_ifsd=254",
        "outer_watchdog_required_seconds=300",
    ] {
        assert!(text.lines().any(|actual| actual == line), "{line}");
    }
    assert_eq!(FIDI_SIGN_LIMITS.len(), 15);
    assert_eq!(
        FIDI_SIGN_LIMITS.map(|(_, value)| value),
        [
            "254", "254", "258", "128", "16", "512", "5000", "1190", "30000", "1..24", "8", "8",
            "64", "32768", "1048576",
        ]
    );
    for (id, value) in FIDI_SIGN_LIMITS {
        assert_eq!(
            text.lines()
                .filter(|line| *line == format!("{id}={value}"))
                .count(),
            1
        );
        assert!(!FIDI_READBACK_LIMITS.iter().any(|(old, _)| old == &id));
        assert!(!IFS_READBACK_LIMITS.iter().any(|(old, _)| old == &id));
        assert!(!READBACK_LIMITS.iter().any(|(old, _)| old == &id));
    }
    let mut identifiers = FIDI_SIGN_LIMITS.map(|(id, _)| id);
    identifiers.sort();
    assert!(identifiers.windows(2).all(|pair| pair[0] != pair[1]));
    assert_eq!(MAX_SEC1210_FIDI_SIGN_TRANSCRIPT_BYTES, 1_048_576);
    assert_eq!(MAX_SEC1210_FIDI_READBACK_TRANSCRIPT_BYTES, 262_144);
    assert_eq!(MAX_SITTING_TRANSCRIPT_BYTES, 32_768);
}

#[test]
fn baseline_parameters_and_set_parameters_candidate_are_separate_and_exact() {
    let mut transcript = Sec1210FidiSignTranscript::new(Vec::new());
    transcript
        .observation(
            0,
            &RawObservation::Parameters {
                protocol: 1,
                bytes: [0x11, 0x10, 0xff, 0x4d, 0, 0xfe, 0],
            },
            false,
        )
        .unwrap();
    let payload = [0x18, 0x10, 0xff, 0x4d, 0, 0xfe, 0];
    transcript
        .set_parameters_reply(&parameters_reply(0, 0, 1, &payload))
        .unwrap();
    transcript
        .observation(
            1,
            &RawObservation::Parameters {
                protocol: 1,
                bytes: payload,
            },
            true,
        )
        .unwrap();
    let text = String::from_utf8(transcript.into_inner()).unwrap();
    assert_eq!(text.matches("parameters_hex=").count(), 1);
    assert!(text.contains("parameters_hex=1110ff4d00fe00\n"));
    assert!(text.contains("set_parameters.response_hex=1810ff4d00fe00\n"));
    assert!(text.contains("set_parameters.bStatus=00\n"));
    assert!(text.contains("set_parameters.bError=00\n"));
    assert!(text.contains("set_parameters.bProtocolNum=01\n"));
    assert!(text.contains("observation.1=SetParameters protocol=01 ifsc=fe edc_bit=0\n"));

    let mut transcript = Sec1210FidiSignTranscript::new(Vec::new());
    transcript
        .set_parameters_reply(&parameters_reply(0x40, 0x0a, 1, &[0x18]))
        .unwrap();
    let text = String::from_utf8(transcript.into_inner()).unwrap();
    assert!(text.contains("set_parameters.bStatus=40\n"));
    assert!(text.contains("set_parameters.bError=0a\n"));
    assert!(text.ends_with("set_parameters.response_hex=18\n"));
}

#[test]
fn reader_extension_observation_retains_nonfinal_frame_bounds_and_deadlines() {
    let mut transcript = Sec1210FidiSignTranscript::new(Vec::new());
    transcript
        .observation(
            5,
            &RawObservation::TimeExtension {
                ordinal: 256,
                sequence: 0,
                multiplier: 255,
                apdu_count: 2,
                invocation_count: 3,
                command_deadline_ms: 12_345,
                apdu_deadline_ms: 30_000,
                span: RawFrameSpan {
                    start_rx_offset: 100,
                    end_rx_offset: 113,
                },
            },
            false,
        )
        .unwrap();
    transcript
        .observation(
            6,
            &RawObservation::Transfer {
                ordinal: 256,
                sequence: 0,
                payload_bytes: 169,
            },
            false,
        )
        .unwrap();
    let text = String::from_utf8(transcript.into_inner()).unwrap();
    assert_eq!(text,
        "observation.5=TimeExtension ordinal=256 sequence=0 multiplier=255 apdu_count=2 invocation_count=3 command_deadline_ms=12345 apdu_deadline_ms=30000 start_rx_offset=100 end_rx_offset=113\nobservation.6=Transfer ordinal=256 sequence=0 payload_bytes=169\n");
    assert!(!text.contains("signature"));
}

#[test]
fn footer_keeps_original_failure_when_overflow_occurs_later() {
    let mut transcript = Sec1210FidiSignTranscript::new(Vec::new());
    assert!(transcript.field("too_big", &"x".repeat(8_193)).is_err());
    let mut summary = complete();
    summary.failure = Some(Sec1210FidiSignError::B6(B6Error::B6RepeatedR));
    transcript.finish(&summary).unwrap();
    let text = String::from_utf8(transcript.into_inner()).unwrap();
    assert!(text.contains("transcript_overflow=TRUE\n"));
    assert!(text.ends_with("first_failure=B6RepeatedR\nresult=B6RepeatedR\n"));
}

#[test]
fn footer_preserves_extension_counts_and_requires_the_full_session_for_pass() {
    let mut summary = complete();
    summary.wtx_count = 2;
    summary.time_extension_count = 3;
    summary.request_count += 2;
    summary.response_count += 2;
    let mut transcript = Sec1210FidiSignTranscript::new(Vec::new());
    transcript
        .field(
            "session.0.start_utc",
            summary.session_start_utc.as_deref().unwrap(),
        )
        .unwrap();
    transcript.finish(&summary).unwrap();
    let text = String::from_utf8(transcript.into_inner()).unwrap();
    assert_eq!(text.matches("session.0.start_utc=").count(), 1);
    for line in [
        "request_count=109",
        "response_count=109",
        "event_count=0",
        "wtx_count=2",
        "time_extension_count=3",
        "apdu_accepted_count=102",
        "signature_fact_count=100",
        "signature_accepted_count=100",
        "normalization_changed_count=51",
        "completed_sessions=1",
        "session.0.start_utc=2026-09-14T00:00:00Z",
        "session.0.end_utc=2026-09-14T00:00:40Z",
        "set_parameters_accepted=PASS",
        "ifs_accepted=PASS",
        "local_handle_released=PASS",
        "kernel_close_result=UNOBSERVED",
        "transcript_overflow=FALSE",
        "first_failure=NONE",
        "result=PASS",
    ] {
        assert!(text.lines().any(|actual| actual == line), "{line}");
    }
    let mut boundary = complete();
    boundary.wtx_count = 405;
    boundary.request_count = 512;
    boundary.response_count = 512;
    boundary.event_count = 64;
    boundary.captured_rx_bytes = 32_768;
    boundary.time_extension_count = 8 * 102;
    let mut transcript = Sec1210FidiSignTranscript::new(Vec::new());
    transcript
        .field(
            "session.0.start_utc",
            boundary.session_start_utc.as_deref().unwrap(),
        )
        .unwrap();
    transcript.finish(&boundary).unwrap();
    assert!(String::from_utf8(transcript.into_inner())
        .unwrap()
        .ends_with("result=PASS\n"));
    for field in 0..17 {
        let mut summary = complete();
        match field {
            0 => summary.set_parameters_accepted = false,
            1 => summary.ifs_accepted = false,
            2 => summary.apdu_accepted_count = 101,
            3 => summary.signature_accepted_count = 99,
            4 => summary.completed_sessions = 0,
            5 => summary.local_handle_released = false,
            6 => summary.session_end_utc = None,
            7 => summary.apdu_response_count = 101,
            8 => summary.normalization_changed_count = 101,
            9 => summary.request_count = 108,
            10 => summary.response_count = 106,
            11 => {
                summary.wtx_count = 406;
                summary.request_count = 513;
                summary.response_count = 513;
            }
            12 => summary.event_count = 65,
            13 => summary.captured_rx_bytes = 32_769,
            14 => summary.wtx_count = 8 * 102 + 1,
            15 => summary.time_extension_count = 8 * 102 + 1,
            _ => summary.wtx_count = usize::MAX,
        }
        let mut transcript = Sec1210FidiSignTranscript::new(Vec::new());
        transcript.finish(&summary).unwrap();
        let text = String::from_utf8(transcript.into_inner()).unwrap();
        assert!(!text.contains("result=PASS\n"), "field {field}");
    }
}
