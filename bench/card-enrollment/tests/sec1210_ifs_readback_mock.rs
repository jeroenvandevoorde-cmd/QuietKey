use qk_card_enrollment::*;
use std::cell::Cell;
use std::collections::VecDeque;
use std::rc::Rc;

#[test]
fn complete_unchained_transcripts_agree_and_counts_are_observed() {
    for width in [1, 2, 8, 274] {
        let mut first = Mock::from_stream(width, stream_a(254));
        let (s, t) = run(&mut first);
        assert_eq!(s.failure, None, "{t}");
        assert_eq!(
            (s.request_count, s.response_count, s.captured_rx_bytes),
            (12, 12, 1172)
        );
        assert_eq!(
            (
                s.apdu_transmit_count,
                s.apdu_response_count,
                s.continuation_count
            ),
            (8, 8, 0)
        );
        assert!(s.ifs_accepted && s.local_handle_released);
        assert_eq!(
            (s, t.clone()),
            run(&mut Mock::from_stream(width, stream_b(254)))
        );
        assert!(t.contains("ifs.request_hex=00c101fe3e\n"));
        assert!(t.contains("ifs.response_hex=00e101fe1e\nifs.comparison=PASS\n"));
        for line in [
            "ifs.receive_bound_before=36",
            "ifs.receive_bound_after=258",
            "ifs.send_sequence_before=0",
            "ifs.receive_sequence_before=0",
            "ifs.send_sequence_after=0",
            "ifs.receive_sequence_after=0",
            "t1.5.send_sequence=0",
            "t1.5.receive_sequence=0",
        ] {
            assert!(t.lines().any(|l| l == line), "{line}");
        }
        for label in 9..=16 {
            assert!(t.contains(&format!("apdu.{label}.comparison=PASS\n")));
        }
        assert!(first.expected.is_empty() && first.reads.is_empty());
    }
}

#[test]
fn only_exact_ifs_echo_activates_the_bound_and_no_rejection_retries() {
    let mut wrong_len = block(0xe1, &[0xfe]);
    wrong_len[2] = 2;
    let mut wrong_lrc = block(0xe1, &[0xfe]);
    wrong_lrc[4] ^= 1;
    let mut wrong_nad = block(0xe1, &[0xfe]);
    wrong_nad[0] = 1;
    wrong_nad[4] ^= 1;
    for (payload, error) in [
        (wrong_len, "T1BlockLengthRejected"),
        (wrong_lrc, "T1ChecksumRejected"),
        (wrong_nad, "T1NadRejected"),
        (block(0xe5, &[0xfe]), "T1PcbRejected"),
        (block(0xe1, &[]), "T1ControlLengthRejected"),
        (block(0xe1, &[0xfd]), "T1IfsRejected"),
        (block(0xc1, &[0xfe]), "T1IfsRejected"),
        (block(0, &[0x90, 0]), "T1IfsRejected"),
        (block(0x80, &[]), "T1UnexpectedRBlock"),
        (block(0xc3, &[1]), "T1WtxRejected"),
        (block(0xc0, &[]), "T1ResynchRejected"),
        (block(0xc2, &[]), "T1AbortRejected"),
        (block(0, &[0; 254]), "T1BlockLengthRejected"),
    ] {
        let mut m = Mock::new(274);
        m.reads[3].0 = ccid(0x80, 4, 0, 0, &payload);
        let (s, t) = run(&mut m);
        assert_eq!(s.failure.unwrap().name(), error, "{t}");
        assert_eq!((s.apdu_transmit_count, s.apdu_response_count), (0, 0));
        assert_eq!(m.writes.len(), 4);
        assert!(!s.ifs_accepted);
        assert!(s.local_handle_released);
        assert!(t.contains("ifs.receive_bound_after=36\n"));
        assert!(t.contains(&format!("ifs.comparison={error}\n")));
        assert!(!t.contains("apdu.9.tx_hex="));
    }
}

#[test]
fn unsolicited_ifs_and_wtx_after_activation_remain_terminal() {
    for (payload, error) in [
        (block(0xe1, &[0xfe]), "T1IfsRejected"),
        (block(0xc1, &[0xfe]), "T1IfsRejected"),
        (block(0xc3, &[1]), "T1WtxRejected"),
    ] {
        let mut m = Mock::new(274);
        m.reads[4].0 = ccid(0x80, 5, 0, 0, &payload);
        let (s, t) = run(&mut m);
        assert_eq!(s.failure.unwrap().name(), error, "{t}");
        assert_eq!((s.apdu_transmit_count, s.apdu_response_count), (1, 0));
        assert!(s.ifs_accepted && s.local_handle_released);
        assert_eq!(m.writes.len(), 5);
    }
}

#[test]
fn activated_transport_bound_does_not_expand_the_golden_response() {
    let mut m = Mock::new(274);
    // The wire accepts all 258 payload bytes. SELECT still requires only 9000.
    m.reads[4].0 = ccid(0x80, 5, 0, 0, &block(0, &[0; 254]));
    let (s, t) = run(&mut m);
    assert_eq!(s.failure.unwrap().name(), "T1ResponseLengthRejected", "{t}");
    assert!(t.contains("observation.4=Transfer sequence=5 payload_bytes=258\n"));
    assert!(t.contains("read.4.comparison=PASS\n"));
    assert_eq!(s.apdu_response_count, 0);
    assert_eq!(m.writes.len(), 5);
}

#[test]
fn block_above_258_bytes_is_rejected_after_successful_activation() {
    let mut m = Mock::new(274);
    m.reads[4].0 = ccid(0x80, 5, 0, 0, &block(0, &[0; 255]));
    let (s, t) = run(&mut m);
    assert_eq!(s.failure.unwrap().name(), "T1BlockLengthRejected", "{t}");
    assert!(t.contains("observation.4=Transfer sequence=5 payload_bytes=259\n"));
    assert!(t.contains("read.4.comparison=PASS\n"));
    assert_eq!(s.apdu_response_count, 0);
    assert!(s.ifs_accepted && s.local_handle_released);
    assert_eq!(m.writes.len(), 5);
}

#[test]
fn zero_length_reads_and_coalesced_ifs_event_remain_reproducible() {
    let mut m = Mock::new(274);
    let response = m.reads[3].0.clone();
    m.reads[3].0 = [vec![0x50, 3], response].concat();
    m.reads.insert(3, (vec![], 0));
    let (s, t) = run(&mut m);
    assert_eq!(s.failure, None, "{t}");
    assert_eq!(s.event_count, 1);
    assert!(t.contains("read.3.elapsed_ms=10\nread.3.monotonic_ms=43\nread.3.rx_hex=\n"));
    let indices: Vec<usize> = t
        .lines()
        .filter_map(|l| l.strip_prefix("observation."))
        .map(|l| l.split('=').next().unwrap().parse().unwrap())
        .collect();
    assert_eq!(indices, (0..38).collect::<Vec<_>>());
}

#[test]
fn late_and_partial_ifs_responses_never_reach_an_apdu() {
    for partial in [false, true] {
        let mut m = Mock::new(274);
        let response = m.reads[3].0.clone();
        if partial {
            m.reads[3] = (response[..4].to_vec(), 1);
            m.reads.insert(4, (response[4..].to_vec(), 5000));
        } else {
            m.reads[3].1 = 5000;
        }
        let (s, t) = run(&mut m);
        let expected = if partial {
            "Sec1210PartialFrameDeadline"
        } else {
            "Sec1210DeadlineExceeded"
        };
        assert_eq!(s.failure.unwrap().name(), expected, "{t}");
        assert_eq!(s.apdu_transmit_count, 0);
        assert_eq!(m.writes.len(), 4);
        assert!(!s.ifs_accepted);
        assert_eq!(s.captured_rx_bytes, 79);
        assert!(s.local_handle_released);
    }
}

#[test]
fn ifs_transcript_work_is_inside_its_absolute_budget() {
    struct SlowWriter {
        clock: Rc<Cell<u64>>,
        bytes: Vec<u8>,
    }
    impl std::io::Write for SlowWriter {
        fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
            self.bytes.extend_from_slice(bytes);
            if bytes.starts_with(b"ifs.request_hex=") {
                self.clock.set(5000);
            }
            Ok(bytes.len())
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }
    let mut m = Mock::new(274);
    let mut transcript = Sec1210IfsReadbackTranscript::new(SlowWriter {
        clock: m.extra_clock.clone(),
        bytes: vec![],
    });
    let utc = "2026-09-12T00:00:00Z";
    let metadata = Sec1210IfsReadbackMetadata::new(
        "a".repeat(40),
        utc.into(),
        "RIG-HOST-PI3B-01",
        "J3R180-03",
        std::env::temp_dir().join(sec1210_ifs_readback_output_basename(utc)),
    )
    .unwrap();
    let s = run_sec1210_ifs_readback(&metadata, &mut m, &mut transcript);
    assert_eq!(s.failure.unwrap().name(), "T1DeadlineExceeded");
    assert_eq!(m.writes.len(), 3);
    assert!(!s.ifs_accepted);
    assert_eq!(s.apdu_transmit_count, 0);
}

#[test]
fn transcript_overflow_retains_first_failure_and_releases_without_retry() {
    let mut m = Mock::new(274);
    m.reads = std::iter::repeat_n((vec![], 0), 5000).collect();
    let (s, t) = run(&mut m);
    assert_eq!(s.failure, Some(Sec1210IfsReadbackError::TranscriptLimit));
    assert!(s.local_handle_released);
    assert_eq!(m.writes.len(), 1);
    assert!(t.len() <= MAX_SEC1210_IFS_READBACK_TRANSCRIPT_BYTES);
    assert!(t.contains("transcript_overflow=TRUE\n"));
    assert!(t.ends_with("first_failure=Sec1210IfsReadbackTranscriptLimit\nresult=Sec1210IfsReadbackTranscriptLimit\n"));
}

#[test]
fn malformed_ifs_rejection_survives_a_diagnostic_write_failure() {
    struct Fail;
    impl std::io::Write for Fail {
        fn write(&mut self, b: &[u8]) -> std::io::Result<usize> {
            if b.starts_with(b"ifs.comparison=") {
                return Err(std::io::Error::other("injected diagnostic failure"));
            }
            Ok(b.len())
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }
    let mut m = Mock::new(274);
    m.reads[3].0 = ccid(0x80, 4, 0, 0, &block(0xe1, &[0xfd]));
    let utc = "2026-09-12T00:00:00Z";
    let metadata = Sec1210IfsReadbackMetadata::new(
        "a".repeat(40),
        utc.into(),
        "RIG-HOST-PI3B-01",
        "J3R180-03",
        std::env::temp_dir().join(sec1210_ifs_readback_output_basename(utc)),
    )
    .unwrap();
    let s = run_sec1210_ifs_readback(
        &metadata,
        &mut m,
        &mut Sec1210IfsReadbackTranscript::new(Fail),
    );
    assert_eq!(s.failure.unwrap().name(), "T1IfsRejected");
    assert_eq!(m.writes.len(), 4);
    assert!(s.local_handle_released);
}

const FIXTURE: &str = include_str!("fixtures/sitting_committed_readback_v1.tsv");
fn unhex(s: &str) -> Vec<u8> {
    s.as_bytes()
        .as_chunks::<2>()
        .0
        .iter()
        .map(|b| u8::from_str_radix(std::str::from_utf8(b).unwrap(), 16).unwrap())
        .collect()
}
fn ccid(kind: u8, seq: u8, status: u8, parameter: u8, payload: &[u8]) -> Vec<u8> {
    let mut b = vec![3, 6, kind];
    b.extend((payload.len() as u32).to_le_bytes());
    b.extend([0, seq, status, 0, parameter]);
    b.extend(payload);
    b.push(b.iter().fold(0, |a, b| a ^ b));
    b
}
fn block(pcb: u8, inf: &[u8]) -> Vec<u8> {
    let mut b = vec![0, pcb, inf.len() as u8];
    b.extend(inf);
    b.push(b.iter().fold(0, |a, b| a ^ b));
    b
}
fn stream_a(chunk_size: usize) -> (Vec<Vec<u8>>, Vec<Vec<u8>>) {
    let mut tx = vec![
        unhex("03066500000000000100000061"),
        unhex("03066200000000000202000067"),
        unhex("03066c0000000000030000006a"),
        unhex("03066f05000000000400000000c101fe3e6b"),
    ];
    let mut rx = vec![
        ccid(0x81, 1, 1, 1, &[]),
        ccid(0x80, 2, 0, 0, &unhex("3bd518ff8191fe1fc38073c821100a")),
        ccid(0x82, 3, 0, 1, &[0x11, 0x10, 0, 0x4d, 0, 0xfe, 0]),
        ccid(0x80, 4, 0, 0, &block(0xe1, &[0xfe])),
    ];
    let mut ns = 0;
    let mut nr = 0;
    for a in fixed_sitting_plan(SittingMode::CommittedReadback)
        .unwrap()
        .exchanges()
    {
        for (i, chunk) in a.expected_response().chunks(chunk_size).enumerate() {
            let outgoing = if i == 0 {
                block(ns << 6, a.request())
            } else {
                block(0x80 | (nr << 4), &[])
            };
            let seq = (tx.len() + 1) as u8;
            tx.push(ccid(0x6f, seq, 0, 0, &outgoing));
            let more = (i + 1) * chunk_size < a.expected_response().len();
            rx.push(ccid(
                0x80,
                seq,
                0,
                0,
                &block((nr << 6) | if more { 0x20 } else { 0 }, chunk),
            ));
            nr ^= 1;
        }
        ns ^= 1;
    }
    (tx, rx)
}
// Independently parse the frozen TSV and serialize flat indexed packet fields.
// No production codec, plan parser, or constructor-A framing helper is used.
fn stream_b(chunk_size: usize) -> (Vec<Vec<u8>>, Vec<Vec<u8>>) {
    let rows: Vec<_> = FIXTURE
        .lines()
        .filter(|l| l.as_bytes().first().is_some_and(u8::is_ascii_digit))
        .map(|l| l.split('\t').collect::<Vec<_>>())
        .collect();
    let mut requests = vec![
        unhex("03066500000000000100000061"),
        unhex("03066200000000000202000067"),
        unhex("03066c0000000000030000006a"),
        unhex("03066f05000000000400000000c101fe3e6b"),
    ];
    let mut responses = vec![
        unhex("03068100000000000101000185"),
        unhex("0306800f00000000020000003bd518ff8191fe1fc38073c821100a00"),
        unhex("0306820700000000030000011110004d00fe0000"),
        unhex("03068005000000000400000000e101fe1e84"),
    ];
    // Last two trailer bytes are independently recomputed, not asserted facts.
    for packet in &mut responses[1..] {
        let last = packet.len() - 1;
        packet[last] = packet[..last].iter().copied().reduce(|x, y| x ^ y).unwrap();
    }
    let mut ordinal = 0usize;
    for (apdu, row) in rows.iter().enumerate() {
        let command = unhex(row[3]);
        let expected = unhex(row[4]);
        for (fragment, part) in expected.chunks(chunk_size).enumerate() {
            let mut pair = Vec::new();
            for sending in [true, false] {
                let inf = if sending {
                    if fragment == 0 {
                        command.as_slice()
                    } else {
                        &[]
                    }
                } else {
                    part
                };
                let pcb = if sending {
                    if fragment == 0 {
                        (apdu % 2) as u8 * 64
                    } else {
                        128 + (ordinal % 2) as u8 * 16
                    }
                } else {
                    (ordinal % 2) as u8 * 64
                        + if (fragment + 1) * chunk_size < expected.len() {
                            32
                        } else {
                            0
                        }
                };
                let mut bytes = vec![0u8; 17 + inf.len()];
                bytes[0] = 3;
                bytes[1] = 6;
                bytes[2] = if sending { 0x6f } else { 0x80 };
                bytes[3] = (inf.len() + 4) as u8;
                bytes[8] = (ordinal + 5) as u8;
                bytes[13] = pcb;
                bytes[14] = inf.len() as u8;
                bytes[15..15 + inf.len()].copy_from_slice(inf);
                for k in 12..15 + inf.len() {
                    bytes[15 + inf.len()] ^= bytes[k];
                }
                for k in 0..16 + inf.len() {
                    bytes[16 + inf.len()] ^= bytes[k];
                }
                pair.push(bytes);
            }
            requests.push(pair.remove(0));
            responses.push(pair.remove(0));
            ordinal += 1;
        }
    }
    (requests, responses)
}

struct Mock {
    extra_clock: Rc<Cell<u64>>,
    expected: VecDeque<Vec<u8>>,
    reads: VecDeque<(Vec<u8>, u64)>,
    writes: Vec<Vec<u8>>,
    now: u64,
    sent_at: u64,
    open: bool,
    failure: Option<&'static str>,
    write_cost: u64,
    configure: i32,
}
impl Mock {
    fn new(width: usize) -> Self {
        Self::from_stream(width, stream_a(32))
    }
    fn from_stream(width: usize, (tx, rx): (Vec<Vec<u8>>, Vec<Vec<u8>>)) -> Self {
        Self {
            extra_clock: Rc::new(Cell::new(0)),
            expected: tx.into(),
            reads: rx
                .into_iter()
                .flat_map(|b| b.chunks(width).map(|c| (c.to_vec(), 1)).collect::<Vec<_>>())
                .collect(),
            writes: vec![],
            now: 0,
            sent_at: 0,
            open: false,
            failure: None,
            write_cost: 0,
            configure: 0,
        }
    }
}
impl Sec1210Transport for Mock {
    fn configure(&mut self) -> Result<i32, Sec1210Error> {
        Ok(self.configure)
    }
    fn open(&mut self) -> Result<(), Sec1210Error> {
        self.open = true;
        Ok(())
    }
    fn write_once(&mut self, b: &[u8]) -> Result<usize, Sec1210Error> {
        assert_eq!(Some(b), self.expected.pop_front().as_deref());
        self.writes.push(b.to_vec());
        self.now += self.write_cost;
        self.sent_at = self.now;
        if self.failure == Some("partial")
            || (self.failure == Some("ifs-partial") && self.writes.len() == 4)
        {
            Ok(b.len() - 1)
        } else {
            Ok(b.len())
        }
    }
    fn pause_after_write(&mut self) -> Result<(), Sec1210Error> {
        self.now += 10;
        Ok(())
    }
    fn read(&mut self, b: &mut [u8]) -> Result<(usize, u64), Sec1210Error> {
        if self.failure == Some("panic") {
            panic!("mock unwind");
        }
        if self.failure == Some("read") {
            return Err(Sec1210Error::ReadFailed);
        }
        let (bytes, delta) = self.reads.pop_front().unwrap_or((vec![], 5000));
        self.now += delta;
        b[..bytes.len()].copy_from_slice(&bytes);
        Ok((bytes.len(), self.now - self.sent_at))
    }
    fn release(&mut self) -> Result<bool, Sec1210Error> {
        let existed = self.open;
        self.open = false;
        if self.failure == Some("release") {
            Err(Sec1210Error::CloseFailed)
        } else {
            Ok(existed)
        }
    }
}
impl Sec1210ReadbackTransport for Mock {
    fn now_ms(&mut self) -> u64 {
        self.now + self.extra_clock.get()
    }
}
fn run(m: &mut Mock) -> (Sec1210IfsReadbackSummary, String) {
    let utc = "2026-09-12T00:00:00Z";
    let metadata = Sec1210IfsReadbackMetadata::new(
        "a".repeat(40),
        utc.into(),
        "RIG-HOST-PI3B-01",
        "J3R180-03",
        std::env::temp_dir().join(sec1210_ifs_readback_output_basename(utc)),
    )
    .unwrap();
    let mut transcript = Sec1210IfsReadbackTranscript::new(Vec::new());
    let summary = run_sec1210_ifs_readback(&metadata, m, &mut transcript);
    (summary, String::from_utf8(transcript.into_inner()).unwrap())
}

#[test]
fn two_independent_constructors_agree_on_every_wire_byte() {
    for chunk in [32, 254] {
        assert_eq!(stream_a(chunk), stream_b(chunk));
        assert_eq!(
            stream_a(chunk).0[3],
            unhex("03066f05000000000400000000c101fe3e6b")
        );
        assert_eq!(
            stream_a(chunk).1[3],
            unhex("03068005000000000400000000e101fe1e84")
        );
    }
}
#[test]
fn complete_chained_public_golden_stream_is_reconstructed_without_device() {
    let mut m = Mock::new(8);
    let (s, t) = run(&mut m);
    assert_eq!(s.failure, None, "{t}");
    assert_eq!(
        (s.request_count, s.response_count, s.event_count),
        (37, 37, 0)
    );
    assert_eq!((s.apdu_transmit_count, s.apdu_response_count), (8, 8));
    assert!(m.expected.is_empty() && m.reads.is_empty());
    assert!(t.contains("tool_version=0.0.11\n"));
    assert!(t.contains("parameters_hex=1110004d00fe00\n"));
    assert!(t.contains("QK-LIM-BENCH-T1-IFS-READBACK-TRANSCRIPT-V1=262144\n"));
    assert!(t.ends_with("first_failure=NONE\nresult=PASS\n"));
    assert_eq!(s.continuation_count, 25);
    assert!(s.ifs_accepted);
    assert_eq!((s, t), run(&mut Mock::from_stream(8, stream_b(32))));
}
#[test]
fn every_byte_fragments_and_whole_packets_have_same_acceptance() {
    for width in [1, 2, 3, 8, 274] {
        let (s, t) = run(&mut Mock::new(width));
        assert_eq!(s.failure, None, "{width}: {t}");
        assert_eq!(s.apdu_response_count, 8);
    }
}
#[test]
fn coalesced_event_and_response_indices_are_strictly_increasing() {
    let mut m = Mock::new(274);
    let mut bytes = vec![0x50, 3];
    bytes.extend(m.reads.pop_front().unwrap().0);
    m.reads.push_front((bytes, 1));
    let (s, t) = run(&mut m);
    assert_eq!(s.failure, None, "{t}");
    assert_eq!(s.event_count, 1);
    let indices: Vec<usize> = t
        .lines()
        .filter_map(|l| l.strip_prefix("observation."))
        .map(|s| s.split('=').next().unwrap().parse().unwrap())
        .collect();
    assert_eq!(indices, (0..38).collect::<Vec<_>>());
}
#[test]
fn response_prefix_mismatch_stops_before_another_ack() {
    let mut m = Mock::new(274);
    // INFO is the third APDU, first chained response (command7).
    let mut bad = m.reads[6].0.clone();
    bad[15] ^= 1;
    let n = bad.len();
    bad[n - 2] ^= 1;
    bad[n - 1] = bad[..n - 1].iter().fold(0, |a, b| a ^ b);
    m.reads[6].0 = bad;
    let (s, t) = run(&mut m);
    assert_eq!(
        s.failure,
        Some(Sec1210IfsReadbackError::T1(qk_t1::Error::ResponseMismatch)),
        "{t}"
    );
    assert_eq!(m.writes.len(), 7);
    assert_eq!(s.apdu_response_count, 2);
    assert!(s.local_handle_released);
}
#[test]
fn late_raw_bytes_are_retained_and_never_acknowledged() {
    let mut m = Mock::new(274);
    m.reads[0].1 = 5000;
    let (s, t) = run(&mut m);
    assert_eq!(
        s.failure,
        Some(Sec1210IfsReadbackError::Wire(
            qk_sec1210_wire::ReadbackError::Wire(qk_sec1210_wire::Error::DeadlineExceeded)
        ))
    );
    assert!(t.contains("read.0.rx_hex="));
    assert_eq!(s.captured_rx_bytes, 13);
    assert_eq!(m.writes.len(), 1);
}
#[test]
fn time_extensions_and_parameter_failures_stop_before_apdus() {
    for (body, expected) in [
        (ccid(0x81, 3, 0x80, 0, &[]), "Sec1210TimeExtensionRejected"),
        (
            ccid(0x82, 3, 0, 1, &[0, 0, 0, 0, 0, 0xfd, 0]),
            "Sec1210IfscRejected",
        ),
        (
            ccid(0x82, 3, 0, 1, &[0, 1, 0, 0, 0, 0xfe, 0]),
            "Sec1210LrcModeRejected",
        ),
    ] {
        let mut m = Mock::new(274);
        m.reads[2].0 = body;
        let (s, t) = run(&mut m);
        assert_eq!(s.failure.unwrap().name(), expected, "{t}");
        assert_eq!(s.apdu_transmit_count, 0);
        assert_eq!(m.writes.len(), 3);
    }
}
#[test]
fn all_other_parameter_bytes_are_observations_only() {
    let mut m = Mock::new(274);
    m.reads[2].0 = ccid(0x82, 3, 0, 1, &[255, 254, 255, 255, 255, 254, 255]);
    let (s, t) = run(&mut m);
    assert_eq!(s.failure, None, "{t}");
    assert!(t.contains("parameters_hex=fffefffffffeff"));
}
#[test]
fn native_and_unwind_failures_release_the_handle_without_followup() {
    for fail in ["partial", "read", "panic", "release"] {
        let mut m = Mock::new(274);
        m.failure = Some(fail);
        let (s, _) = run(&mut m);
        assert!(s.failure.is_some());
        assert!(!m.open);
        if fail != "release" {
            assert_eq!(m.writes.len(), 1);
        }
    }
    let mut m = Mock::new(274);
    m.configure = 7;
    let (s, _) = run(&mut m);
    assert!(s.failure.is_some());
    assert!(m.writes.is_empty());
}

#[test]
fn partial_ifs_write_and_cleanup_failure_preserve_the_first_failure() {
    let mut m = Mock::new(274);
    m.failure = Some("ifs-partial");
    let (s, t) = run(&mut m);
    assert_eq!(s.failure.unwrap().name(), "Sec1210PartialWrite", "{t}");
    assert_eq!(m.writes.len(), 4);
    assert_eq!(s.apdu_transmit_count, 0);
    assert!(!s.ifs_accepted);
    assert!(s.local_handle_released);

    let mut m = Mock::new(274);
    m.failure = Some("release");
    m.reads[3].0 = ccid(0x80, 4, 0, 0, &block(0xe1, &[0xfd]));
    let (s, t) = run(&mut m);
    assert_eq!(s.failure.unwrap().name(), "T1IfsRejected", "{t}");
    assert!(!m.open);
    assert_eq!(m.writes.len(), 4);
    assert_eq!(s.apdu_transmit_count, 0);
}
#[test]
fn write_time_is_inside_the_absolute_command_deadline() {
    let mut m = Mock::new(274);
    m.write_cost = 5000;
    let (s, _) = run(&mut m);
    assert_eq!(s.failure.unwrap().name(), "Sec1210DeadlineExceeded");
    assert_eq!(m.writes.len(), 1);
}

#[test]
fn recording_raw_bytes_cannot_bypass_the_absolute_response_deadline() {
    struct SlowWriter {
        bytes: Vec<u8>,
        clock: Rc<Cell<u64>>,
    }
    impl std::io::Write for SlowWriter {
        fn write(&mut self, b: &[u8]) -> std::io::Result<usize> {
            self.bytes.extend_from_slice(b);
            if b.starts_with(b"read.0.rx_hex=") {
                self.clock.set(5000);
            }
            Ok(b.len())
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }
    let mut m = Mock::new(274);
    let mut t = Sec1210IfsReadbackTranscript::new(SlowWriter {
        bytes: vec![],
        clock: m.extra_clock.clone(),
    });
    let utc = "2026-09-12T00:00:00Z";
    let metadata = Sec1210IfsReadbackMetadata::new(
        "a".repeat(40),
        utc.into(),
        "RIG-HOST-PI3B-01",
        "J3R180-03",
        std::env::temp_dir().join(sec1210_ifs_readback_output_basename(utc)),
    )
    .unwrap();
    let s = run_sec1210_ifs_readback(&metadata, &mut m, &mut t);
    assert_eq!(s.failure.unwrap().name(), "Sec1210DeadlineExceeded");
    assert_eq!(m.writes.len(), 1);
    assert_eq!(s.captured_rx_bytes, 13);
    let text = String::from_utf8(t.into_inner().bytes).unwrap();
    assert!(text.contains("read.0.rx_hex="));
    assert!(text.contains("read.0.validation_ms=5011\n"));
}

#[test]
fn chained_timely_ccid_responses_cannot_renew_the_apdu_deadline() {
    let mut m = Mock::new(274);
    // The INFO response occupies five normal blocks; split it into eight to
    // cross 30s while every individual CCID response arrives before 5s.
    let plan = fixed_sitting_plan(SittingMode::CommittedReadback).unwrap();
    let info = plan.exchanges()[2].expected_response();
    m.expected.truncate(6);
    m.reads.truncate(6);
    let mut nr = 0;
    for (i, part) in info.chunks(20).enumerate() {
        let seq = (i + 7) as u8;
        let outgoing = if i == 0 {
            block(0, plan.exchanges()[2].request())
        } else {
            block(0x80 | (nr << 4), &[])
        };
        m.expected.push_back(ccid(0x6f, seq, 0, 0, &outgoing));
        m.reads.push_back((
            ccid(
                0x80,
                seq,
                0,
                0,
                &block(
                    (nr << 6) | if (i + 1) * 20 < info.len() { 0x20 } else { 0 },
                    part,
                ),
            ),
            4000,
        ));
        nr ^= 1;
    }
    let (s, t) = run(&mut m);
    assert_eq!(s.failure.unwrap().name(), "T1DeadlineExceeded", "{t}");
    assert_eq!(s.apdu_response_count, 2);
    assert_eq!(m.writes.len(), 14); // Six earlier commands plus eight timely exchanges.
}

#[test]
fn diagnostic_writer_failure_cannot_replace_an_observed_protocol_rejection() {
    struct FailWriter(&'static [u8]);
    impl std::io::Write for FailWriter {
        fn write(&mut self, b: &[u8]) -> std::io::Result<usize> {
            if b.starts_with(self.0) {
                return Err(std::io::Error::other("injected diagnostic failure"));
            }
            Ok(b.len())
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }
    for (wire_error, marker, expected) in [
        (
            true,
            &b"read.0.validation_ms="[..],
            "Sec1210TimeExtensionRejected",
        ),
        (false, &b"t1.5.comparison="[..], "T1SequenceRejected"),
    ] {
        let mut m = Mock::new(274);
        if wire_error {
            m.reads[0].0 = ccid(0x81, 1, 0x81, 0, &[]);
        } else {
            m.reads[4].0 = ccid(0x80, 5, 0, 0, &block(0x40, &[0x90, 0]));
        }
        let mut t = Sec1210IfsReadbackTranscript::new(FailWriter(marker));
        let utc = "2026-09-12T00:00:00Z";
        let metadata = Sec1210IfsReadbackMetadata::new(
            "a".repeat(40),
            utc.into(),
            "RIG-HOST-PI3B-01",
            "J3R180-03",
            std::env::temp_dir().join(sec1210_ifs_readback_output_basename(utc)),
        )
        .unwrap();
        let s = run_sec1210_ifs_readback(&metadata, &mut m, &mut t);
        assert_eq!(s.failure.unwrap().name(), expected);
        assert!(s.local_handle_released);
        assert_eq!(m.writes.len(), if wire_error { 1 } else { 5 });
    }
}
