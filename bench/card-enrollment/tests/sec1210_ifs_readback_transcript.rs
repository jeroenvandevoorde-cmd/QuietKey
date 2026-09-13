use qk_card_enrollment::*;
fn failed() -> Sec1210IfsReadbackSummary {
    Sec1210IfsReadbackSummary {
        request_count: 0,
        response_count: 0,
        event_count: 0,
        captured_rx_bytes: 0,
        apdu_transmit_count: 0,
        apdu_response_count: 0,
        ifs_accepted: false,
        continuation_count: 0,
        local_handle_released: false,
        failure: Some(Sec1210IfsReadbackError::TranscriptLimit),
    }
}
#[test]
fn new_cap_is_independent_and_reserves_terminal_records() {
    let mut t = Sec1210IfsReadbackTranscript::new(Vec::new());
    while t.field("record", &"a".repeat(512)).is_ok() {}
    assert!(t.bytes_written() > MAX_SITTING_TRANSCRIPT_BYTES);
    assert_eq!(
        t.field("later", "not written"),
        Err(Sec1210IfsReadbackError::TranscriptLimit)
    );
    t.finish(&failed()).unwrap();
    let bytes = t.into_inner();
    assert!(bytes.len() <= 262144);
    let s = String::from_utf8(bytes).unwrap();
    assert!(s.contains("transcript_overflow=TRUE\n"));
    assert!(s.ends_with("result=Sec1210IfsReadbackTranscriptLimit\n"));
}
#[test]
fn field_injection_and_oversize_hex_fail_before_output() {
    for value in ["a\nb", "a\rb", "a\0b", "é"] {
        let mut t = Sec1210IfsReadbackTranscript::new(Vec::new());
        assert!(t.field("x", value).is_err());
        assert!(t.into_inner().is_empty());
    }
    let mut t = Sec1210IfsReadbackTranscript::new(Vec::new());
    assert!(t.hex("x", &[0; 4097]).is_err());
    assert!(t.field("x", &"x".repeat(8193)).is_err());
    assert!(t.into_inner().is_empty());
}
#[test]
fn io_failure_is_sticky_and_preserves_the_written_prefix() {
    struct Limited {
        bytes: Vec<u8>,
    }
    impl std::io::Write for Limited {
        fn write(&mut self, b: &[u8]) -> std::io::Result<usize> {
            if self.bytes.len() == 4 {
                return Err(std::io::Error::other("full"));
            }
            let n = b.len().min(4 - self.bytes.len());
            self.bytes.extend(&b[..n]);
            Ok(n)
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }
    let mut t = Sec1210IfsReadbackTranscript::new(Limited { bytes: vec![] });
    assert_eq!(
        t.field("x", "1234"),
        Err(Sec1210IfsReadbackError::TranscriptIo)
    );
    assert_eq!(
        t.finish(&failed()),
        Err(Sec1210IfsReadbackError::TranscriptIo)
    );
    assert_eq!(t.into_inner().bytes, b"x=12");
}
#[test]
fn limit_values_match_the_qualified_leaves_without_reusing_probe_ids() {
    assert_eq!(
        IFS_READBACK_LIMITS.map(|(_, n)| n),
        [
            qk_t1::MAX_EXCHANGES as u64,
            qk_sec1210_wire::READBACK_MAX_COMMANDS as u64,
            qk_sec1210_wire::READBACK_COMMAND_BUDGET_MS,
            qk_t1::APDU_BUDGET_MS,
            qk_sec1210_wire::READBACK_MAX_EVENTS as u64,
            qk_sec1210_wire::READBACK_MAX_RECEIVED_BYTES as u64,
            MAX_SEC1210_IFS_READBACK_TRANSCRIPT_BYTES as u64
        ]
    );
    let mut ids = IFS_READBACK_LIMITS.map(|(id, _)| id);
    ids.sort();
    assert!(ids.windows(2).all(|w| w[0] != w[1]));
    assert_eq!(MAX_SITTING_TRANSCRIPT_BYTES, 32768);
    assert_eq!(qk_sec1210_wire::MAX_RECEIVED_BYTES, 4096);
    for (id, _) in IFS_READBACK_LIMITS {
        assert!(!READBACK_LIMITS.iter().any(|(old, _)| *old == id));
    }
}

#[test]
fn header_binds_the_new_authority_and_retained_public_identities() {
    let utc = "2026-09-13T00:00:00Z";
    let metadata = Sec1210IfsReadbackMetadata::new(
        "a".repeat(40),
        utc.into(),
        "RIG-HOST-PI3B-01",
        "J3R180-03",
        std::env::temp_dir().join(sec1210_ifs_readback_output_basename(utc)),
    )
    .unwrap();
    let mut t = Sec1210IfsReadbackTranscript::new(Vec::new());
    t.header(&metadata).unwrap();
    let text = String::from_utf8(t.into_inner()).unwrap();
    for line in [
        "allowlist=QK-DEC-167-SUP-007",
        "tool_version=0.0.11",
        "mode=sec1210-ifs-readback",
        "campaign_source_commit=d706e0dbe4826bb2b65a5e00ed61ccd8921cc22c",
        "applet_source_commit=d706e0dbe4826bb2b65a5e00ed61ccd8921cc22c",
        "canonical_cap_bytes=40914",
        "canonical_cap_sha256=edad47ec29421b5802281f6426d72a8c5994831cc7a265d223ede6234310b8ae",
        "plan_sha256=6cedbdc6f53c8100e042b8d3e06ebef2a2c56b42e98bbfa32b3a951f39084c36",
        "plan_bytes=2943",
        "plan_lf=13",
    ] {
        assert!(text.lines().any(|actual| actual == line), "{line}");
    }
    for (id, value) in IFS_READBACK_LIMITS {
        assert!(text.lines().any(|line| line == format!("{id}={value}")));
    }
    assert!(text.starts_with("QK-CARD-SITTING-V1\n"));
}
