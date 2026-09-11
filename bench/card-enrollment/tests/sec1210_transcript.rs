use qk_card_enrollment::{
    Sec1210Error as E, Sec1210Summary, Sec1210Transcript, MAX_SITTING_TRANSCRIPT_BYTES,
};
fn summary() -> Sec1210Summary {
    Sec1210Summary {
        request_count: 0,
        response_count: 0,
        event_count: 0,
        received_bytes: 0,
        local_handle_released: false,
        failure: Some(E::TranscriptLimit),
    }
}
#[test]
fn cap_reserves_terminal_evidence_and_never_exceeds_existing_sitting_limit() {
    let mut t = Sec1210Transcript::new(Vec::new());
    loop {
        if t.field("bounded", &"a".repeat(256)).is_err() {
            break;
        }
    }
    assert_eq!(t.field("later", "forbidden"), Err(E::TranscriptLimit));
    t.finish(&summary()).unwrap();
    let b = t.into_inner();
    assert!(b.len() <= MAX_SITTING_TRANSCRIPT_BYTES);
    let text = String::from_utf8(b).unwrap();
    assert!(text.contains("transcript_overflow=TRUE"));
    assert!(text.ends_with("result=Sec1210TranscriptLimit\n"));
}
#[test]
fn multiline_and_nonascii_values_are_refused_before_write() {
    for value in ["a\nb", "a\rb", "a\0b", "é"] {
        let mut t = Sec1210Transcript::new(Vec::new());
        assert_eq!(t.field("x", value), Err(E::MetadataRejected));
        assert!(t.into_inner().is_empty());
    }
}
#[test]
fn overlong_values_and_capture_are_refused_before_allocation() {
    let mut t = Sec1210Transcript::new(Vec::new());
    assert_eq!(t.field("x", &"x".repeat(8193)), Err(E::TranscriptLimit));
    assert_eq!(t.hex("x", &[0; 4097]), Err(E::TranscriptLimit));
    assert!(t.into_inner().is_empty());
}
#[test]
fn writer_error_preserves_prefix_and_refuses_followup() {
    struct Writer {
        bytes: Vec<u8>,
        left: usize,
    }
    impl std::io::Write for Writer {
        fn write(&mut self, b: &[u8]) -> std::io::Result<usize> {
            if self.left == 0 {
                return Err(std::io::Error::other("disk"));
            }
            let n = b.len().min(self.left);
            self.bytes.extend(&b[..n]);
            self.left -= n;
            Ok(n)
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }
    let mut t = Sec1210Transcript::new(Writer {
        bytes: vec![],
        left: 4,
    });
    assert_eq!(t.field("x", "123456"), Err(E::TranscriptIo));
    assert_eq!(t.field("y", "2"), Err(E::TranscriptIo));
    assert_eq!(t.into_inner().bytes, b"x=12");
}
