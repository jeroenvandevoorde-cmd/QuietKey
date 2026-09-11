use qk_card_enrollment::{
    run_sec1210, sec1210_output_basename, Sec1210Error as E, Sec1210Metadata, Sec1210Summary,
    Sec1210Transcript, Sec1210Transport,
};
use std::collections::VecDeque;

fn metadata() -> Sec1210Metadata {
    Sec1210Metadata::new(
        "a".repeat(40),
        "2026-09-11T00:00:00Z".into(),
        "RIG-HOST-PI3B-01",
        "J3R180-03",
        std::env::temp_dir().join(sec1210_output_basename("2026-09-11T00:00:00Z")),
    )
    .unwrap()
}
fn frame(kind: u8, seq: u8, status: u8, payload: &[u8]) -> Vec<u8> {
    let mut b = vec![3, 6, kind];
    b.extend_from_slice(&(payload.len() as u32).to_le_bytes());
    b.extend_from_slice(&[0, seq, status, 0, 0]);
    b.extend_from_slice(payload);
    b.push(b.iter().fold(0, |a, b| a ^ b));
    b
}
fn status() -> Vec<u8> {
    frame(0x81, 1, 1, &[])
}
fn atr() -> Vec<u8> {
    frame(
        0x80,
        2,
        0,
        &[
            0x3b, 0xd5, 0x18, 0xff, 0x81, 0x91, 0xfe, 0x1f, 0xc3, 0x80, 0x73, 0xc8, 0x21, 0x10,
            0x0a,
        ],
    )
}
struct Mock {
    reads: VecDeque<(Vec<u8>, u64)>,
    writes: Vec<Vec<u8>>,
    calls: Vec<&'static str>,
    fail: Option<&'static str>,
    partial: Option<usize>,
    configured: i32,
    open: bool,
}
impl Default for Mock {
    fn default() -> Self {
        Self {
            reads: VecDeque::from([(status(), 10), (atr(), 10)]),
            writes: vec![],
            calls: vec![],
            fail: None,
            partial: None,
            configured: 0,
            open: false,
        }
    }
}
impl Sec1210Transport for Mock {
    fn configure(&mut self) -> Result<i32, E> {
        self.calls.push("configure");
        if self.fail == Some("configure") {
            Err(E::SttyUnavailable)
        } else {
            Ok(self.configured)
        }
    }
    fn open(&mut self) -> Result<(), E> {
        self.calls.push("open");
        if self.fail == Some("open") {
            return Err(E::OpenFailed);
        }
        self.open = true;
        Ok(())
    }
    fn write_once(&mut self, b: &[u8]) -> Result<usize, E> {
        self.calls.push("write");
        self.writes.push(b.to_vec());
        if self.fail == Some("write") {
            Err(E::WriteFailed)
        } else {
            Ok(self.partial.unwrap_or(b.len()))
        }
    }
    fn pause_after_write(&mut self) -> Result<(), E> {
        self.calls.push("pause");
        Ok(())
    }
    fn read(&mut self, b: &mut [u8]) -> Result<(usize, u64), E> {
        self.calls.push("read");
        if self.fail == Some("panic") {
            panic!("mock read unwind");
        }
        if self.fail == Some("read") {
            return Err(E::ReadFailed);
        }
        if self.fail == Some("length") {
            return Ok((b.len() + 1, 10));
        }
        let (bytes, time) = self.reads.pop_front().unwrap_or((vec![], 5000));
        b[..bytes.len()].copy_from_slice(&bytes);
        Ok((bytes.len(), time))
    }
    fn release(&mut self) -> Result<bool, E> {
        self.calls.push("release");
        let open = self.open;
        self.open = false;
        if self.fail == Some("release") {
            Err(E::CloseFailed)
        } else {
            Ok(open)
        }
    }
}
fn run(mock: &mut Mock) -> (Sec1210Summary, String) {
    let mut t = Sec1210Transcript::new(Vec::new());
    let s = run_sec1210(&metadata(), mock, &mut t);
    (s, String::from_utf8(t.into_inner()).unwrap())
}

#[test]
fn fixed_public_mock_sitting_passes_without_any_device() {
    let mut m = Mock::default();
    let (s, t) = run(&mut m);
    assert_eq!(s.failure, None);
    assert_eq!(
        (s.request_count, s.response_count, s.event_count),
        (2, 2, 0)
    );
    assert_eq!(
        m.writes,
        vec![
            vec![3, 6, 0x65, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0x61],
            vec![3, 6, 0x62, 0, 0, 0, 0, 0, 2, 2, 0, 0, 0x67]
        ]
    );
    assert_eq!(
        m.calls,
        vec![
            "configure",
            "open",
            "write",
            "pause",
            "read",
            "write",
            "pause",
            "read",
            "release"
        ]
    );
    assert!(t.starts_with("QK-CARD-SITTING-V1\n"));
    assert!(t.ends_with("first_failure=NONE\nresult=PASS\n"));
    assert!(t.contains("tool_version=0.0.9\n"));
    assert!(t.contains("apdu_transmit_count=0\n"));
    assert!(t.contains("kernel_close_result=UNOBSERVED\n"));
}
#[test]
fn independently_repeated_public_inputs_reproduce_full_transcript() {
    let (s1, t1) = run(&mut Mock::default());
    let (s2, t2) = run(&mut Mock::default());
    assert_eq!(s1, s2);
    assert_eq!(t1, t2);
    // This reproduction binds supplied observations, not an unmeasured device.
    assert!(t1.contains("command.1.request_hex=03066500000000000100000061\n"));
    assert!(t1.contains("command.2.request_hex=03066200000000000202000067\n"));
}
#[test]
fn every_byte_read_fragment_is_retained_and_accepted() {
    let mut m = Mock {
        reads: status()
            .into_iter()
            .chain(atr())
            .map(|b| (vec![b], 10))
            .collect(),
        ..Default::default()
    };
    let (s, t) = run(&mut m);
    assert_eq!(s.failure, None);
    assert_eq!(s.received_bytes, 41);
    assert_eq!(t.matches(".rx_hex=").count(), 41);
}
#[test]
fn zero_byte_reads_are_not_eof_and_deadline_is_not_restarted() {
    let mut m = Mock {
        reads: VecDeque::from([(vec![], 500), (vec![], 4500), (status(), 4999), (atr(), 10)]),
        ..Default::default()
    };
    assert_eq!(run(&mut m).0.failure, None);
    let mut m = Mock {
        reads: VecDeque::from([(vec![3], 4999), (vec![], 5000)]),
        ..Default::default()
    };
    let (s, t) = run(&mut m);
    assert_eq!(
        s.failure,
        Some(E::Wire(qk_sec1210_wire::Error::PartialFrameDeadline))
    );
    assert_eq!(m.writes.len(), 1);
    assert!(t.contains("local_handle_released=PASS"));
}
#[test]
fn late_response_bytes_are_captured_before_timeout_rejection() {
    let mut m = Mock {
        reads: VecDeque::from([(status(), 5001)]),
        ..Default::default()
    };
    let (s, t) = run(&mut m);
    assert_eq!(
        s.failure,
        Some(E::Wire(qk_sec1210_wire::Error::DeadlineExceeded))
    );
    assert_eq!(s.received_bytes, 13);
    assert!(t.contains("read.0.rx_hex=03068100000000000101000084"));
    assert_eq!(m.writes.len(), 1);
}
#[test]
fn first_fault_stops_next_command_and_preserves_event_facts() {
    let mut m = Mock {
        reads: VecDeque::from([(vec![0x50, 3, 0], 10)]),
        ..Default::default()
    };
    let (s, t) = run(&mut m);
    assert_eq!(s.event_count, 1);
    assert_eq!(
        s.failure,
        Some(E::Wire(qk_sec1210_wire::Error::PrefixRejected))
    );
    assert!(t.contains("SlotChange bitmap=03 slot1_bits=0"));
    assert!(t.contains("read.0.rx_hex=500300"));
    assert_eq!(m.writes.len(), 1);
}
#[test]
fn hardware_event_details_survive_terminal_fault() {
    let mut m = Mock {
        reads: VecDeque::from([(vec![0x51, 0, 1, 1], 10)]),
        ..Default::default()
    };
    let (s, t) = run(&mut m);
    assert_eq!(
        s.failure,
        Some(E::Wire(qk_sec1210_wire::Error::HardwareError))
    );
    assert!(t.contains("HardwareError slot=0 sequence=1 code=01"));
}
#[test]
fn configuration_and_open_failures_never_write() {
    for phase in ["configure", "open"] {
        let mut m = Mock {
            fail: Some(phase),
            ..Default::default()
        };
        let (s, _) = run(&mut m);
        assert!(s.failure.is_some());
        assert!(m.writes.is_empty());
        assert_eq!(m.calls.last(), Some(&"release"));
    }
    let mut m = Mock {
        configured: 1,
        ..Default::default()
    };
    let (s, t) = run(&mut m);
    assert_eq!(s.failure, Some(E::SttyFailed));
    assert_eq!(m.calls, vec!["configure", "release"]);
    assert!(t.contains("stty.exit=1"));
}
#[test]
fn write_failure_and_partial_write_never_read_or_retry() {
    for n in [0, 1, 12] {
        let mut m = Mock {
            partial: Some(n),
            ..Default::default()
        };
        let (s, t) = run(&mut m);
        assert_eq!(
            s.failure,
            Some(E::Wire(qk_sec1210_wire::Error::PartialWrite))
        );
        assert!(!m.calls.contains(&"read"));
        assert!(t.contains(&format!("write_bytes={n}")));
    }
    let mut m = Mock {
        fail: Some("write"),
        ..Default::default()
    };
    assert_eq!(run(&mut m).0.failure, Some(E::WriteFailed));
    assert_eq!(m.writes.len(), 1);
}
#[test]
fn read_failure_and_unwind_release_handle_without_retry() {
    for (phase, expected) in [
        ("read", E::ReadFailed),
        ("panic", E::BoundaryPanicked),
        ("length", E::ReadLengthRejected),
    ] {
        let mut m = Mock {
            fail: Some(phase),
            ..Default::default()
        };
        let (s, t) = run(&mut m);
        assert_eq!(s.failure, Some(expected));
        assert_eq!(m.calls.last(), Some(&"release"));
        assert!(!m.open);
        assert!(t.contains(expected.name()));
        assert_eq!(m.writes.len(), 1);
    }
}
#[test]
fn successful_exchange_requires_local_release() {
    let mut m = Mock {
        fail: Some("release"),
        ..Default::default()
    };
    let (s, t) = run(&mut m);
    assert_eq!(s.failure, Some(E::CloseFailed));
    assert!(!t.ends_with("result=PASS\n"));
}
#[test]
fn transcript_failure_prevents_later_device_actions() {
    struct Broken;
    impl std::io::Write for Broken {
        fn write(&mut self, _: &[u8]) -> std::io::Result<usize> {
            Err(std::io::Error::other("fail"))
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }
    let mut m = Mock::default();
    let s = run_sec1210(&metadata(), &mut m, &mut Sec1210Transcript::new(Broken));
    assert_eq!(s.failure, Some(E::TranscriptIo));
    assert_eq!(m.calls, vec!["release"]);
}

#[test]
fn transcript_exhaustion_during_capture_stops_with_reserved_failure_footer() {
    let mut m = Mock {
        reads: std::iter::repeat_n((Vec::new(), 10), 1000).collect(),
        ..Default::default()
    };
    let (s, t) = run(&mut m);
    assert_eq!(s.failure, Some(E::TranscriptLimit));
    assert!(t.contains("transcript_overflow=TRUE\n"));
    assert!(t.ends_with("result=Sec1210TranscriptLimit\n"));
    assert!(t.len() <= 32768);
    assert_eq!(m.writes.len(), 1);
    assert!(!m.open);
}
