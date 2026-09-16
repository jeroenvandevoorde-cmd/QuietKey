#![cfg(feature = "sec1210-production")]

use qk_core::{
    CardTransportErrorV2, Sec1210ClockErrorV2, Sec1210DescriptorErrorV2, Sec1210DescriptorReadV2,
    Sec1210DescriptorV2, Sec1210DescriptorWriteV2, Sec1210MonotonicClockV2, Sec1210TransportV2,
    QK_LIM_APDU_012_COMMAND_INF_BYTES, QK_LIM_APDU_013_RESPONSE_INF_BYTES,
    QK_LIM_APDU_014_MAX_WTX_MULTIPLIER, QK_LIM_APDU_015_MAX_WTX_PER_APDU,
    QK_LIM_APDU_016_MAX_TIME_EXTENSIONS_PER_APDU, QK_LIM_APDU_017_MAX_CONTROLLER_COMMANDS,
    QK_LIM_APDU_018_MAX_RECEIVED_BYTES, QK_LIM_APDU_019_BASE_COMMAND_WAIT_MS,
    QK_LIM_APDU_020_APDU_DEADLINE_MS,
};
use std::cell::RefCell;
use std::collections::VecDeque;
use std::rc::Rc;

const ATR: [u8; 15] = [
    0x3b, 0xd5, 0x18, 0xff, 0x81, 0x91, 0xfe, 0x1f, 0xc3, 0x80, 0x73, 0xc8, 0x21, 0x10, 0x0a,
];
const GET_PARAMETERS: [u8; 7] = [0x11, 0x10, 0xff, 0x4d, 0x00, 0xfe, 0x00];
const SET_PARAMETERS: [u8; 7] = [0x18, 0x10, 0xff, 0x4d, 0x00, 0xfe, 0x00];
const IFS_RESPONSE: [u8; 5] = [0x00, 0xe1, 0x01, 0xfe, 0x1e];

#[derive(Default)]
struct TraceState {
    writes: Vec<Vec<u8>>,
    write_waits: Vec<u64>,
    read_waits: Vec<u64>,
}

#[derive(Clone)]
struct WriteTrace(Rc<RefCell<TraceState>>);

impl WriteTrace {
    fn new() -> Self {
        Self(Rc::new(RefCell::new(TraceState::default())))
    }

    fn values(&self) -> Vec<Vec<u8>> {
        self.0.borrow().writes.clone()
    }

    fn write_waits(&self) -> Vec<u64> {
        self.0.borrow().write_waits.clone()
    }

    fn read_waits(&self) -> Vec<u64> {
        self.0.borrow().read_waits.clone()
    }
}

enum ReadStep {
    Bytes(Vec<u8>),
    TimedOut,
    End,
    Failed,
}

struct MockDescriptor {
    reads: VecDeque<ReadStep>,
    writes: WriteTrace,
    short_write_at: Option<usize>,
    failed_write_at: Option<usize>,
    timed_out_write_at: Option<usize>,
}

impl MockDescriptor {
    fn new(reads: Vec<ReadStep>, writes: WriteTrace) -> Self {
        Self {
            reads: reads.into(),
            writes,
            short_write_at: None,
            failed_write_at: None,
            timed_out_write_at: None,
        }
    }

    fn short_write_at(mut self, ordinal: usize) -> Self {
        self.short_write_at = Some(ordinal);
        self
    }

    fn failed_write_at(mut self, ordinal: usize) -> Self {
        self.failed_write_at = Some(ordinal);
        self
    }

    fn timed_out_write_at(mut self, ordinal: usize) -> Self {
        self.timed_out_write_at = Some(ordinal);
        self
    }
}

impl Sec1210DescriptorV2 for MockDescriptor {
    fn write(
        &mut self,
        bytes: &[u8],
        maximum_wait_ms: u64,
    ) -> Result<Sec1210DescriptorWriteV2, Sec1210DescriptorErrorV2> {
        let ordinal = self.writes.0.borrow().writes.len() + 1;
        {
            let mut trace = self.writes.0.borrow_mut();
            trace.writes.push(bytes.to_vec());
            trace.write_waits.push(maximum_wait_ms);
        }
        if self.failed_write_at == Some(ordinal) {
            return Err(Sec1210DescriptorErrorV2);
        }
        if self.timed_out_write_at == Some(ordinal) {
            return Ok(Sec1210DescriptorWriteV2::TimedOut);
        }
        Ok(Sec1210DescriptorWriteV2::Bytes(
            if self.short_write_at == Some(ordinal) {
                bytes.len().saturating_sub(1)
            } else {
                bytes.len()
            },
        ))
    }

    fn read(
        &mut self,
        output: &mut [u8],
        maximum_wait_ms: u64,
    ) -> Result<Sec1210DescriptorReadV2, Sec1210DescriptorErrorV2> {
        self.writes.0.borrow_mut().read_waits.push(maximum_wait_ms);
        match self.reads.pop_front().unwrap_or(ReadStep::End) {
            ReadStep::Bytes(bytes) => {
                if bytes.len() > output.len() {
                    return Ok(Sec1210DescriptorReadV2::Bytes(bytes.len()));
                }
                output[..bytes.len()].copy_from_slice(&bytes);
                Ok(Sec1210DescriptorReadV2::Bytes(bytes.len()))
            }
            ReadStep::TimedOut => Ok(Sec1210DescriptorReadV2::TimedOut),
            ReadStep::End => Ok(Sec1210DescriptorReadV2::EndOfStream),
            ReadStep::Failed => Err(Sec1210DescriptorErrorV2),
        }
    }
}

struct StepClock {
    now: u64,
    scripted: VecDeque<Result<u64, Sec1210ClockErrorV2>>,
}

impl StepClock {
    fn ticking() -> Self {
        Self {
            now: 0,
            scripted: VecDeque::new(),
        }
    }

    fn scripted(values: impl IntoIterator<Item = Result<u64, Sec1210ClockErrorV2>>) -> Self {
        Self {
            now: 0,
            scripted: values.into_iter().collect(),
        }
    }
}

impl Sec1210MonotonicClockV2 for StepClock {
    fn now_ms(&mut self) -> Result<u64, Sec1210ClockErrorV2> {
        if let Some(value) = self.scripted.pop_front() {
            if let Ok(value) = value {
                self.now = value.saturating_add(1);
                return Ok(value);
            }
            return value;
        }
        let value = self.now;
        self.now = self.now.saturating_add(1);
        Ok(value)
    }
}

fn response(
    message_type: u8,
    sequence: u8,
    status: u8,
    error: u8,
    parameter: u8,
    payload: &[u8],
) -> Vec<u8> {
    let mut frame = vec![0x03, 0x06, message_type];
    frame.extend_from_slice(&(payload.len() as u32).to_le_bytes());
    frame.extend_from_slice(&[0, sequence, status, error, parameter]);
    frame.extend_from_slice(payload);
    let checksum = frame.iter().fold(0u8, |value, byte| value ^ byte);
    frame.push(checksum);
    frame
}

fn replace_checked_byte(frame: &mut [u8], index: usize, value: u8) {
    frame[index] = value;
    let checksum = frame.len() - 1;
    frame[checksum] = frame[..checksum]
        .iter()
        .fold(0u8, |current, byte| current ^ byte);
}

fn data(sequence: u8, payload: &[u8]) -> Vec<u8> {
    response(0x80, sequence, 0, 0, 0, payload)
}

fn t1_i(sequence: u8, payload: &[u8]) -> Vec<u8> {
    let mut block = vec![0, sequence << 6, payload.len() as u8];
    block.extend_from_slice(payload);
    let lrc = block.iter().fold(0u8, |value, byte| value ^ byte);
    block.push(lrc);
    block
}

fn t1_wtx(multiplier: u8) -> Vec<u8> {
    vec![0, 0xc3, 1, multiplier, 0xc2 ^ multiplier]
}

fn t1_control(pcb: u8, payload: &[u8]) -> Vec<u8> {
    let mut block = vec![0, pcb, payload.len() as u8];
    block.extend_from_slice(payload);
    let lrc = block.iter().fold(0u8, |value, byte| value ^ byte);
    block.push(lrc);
    block
}

fn initialization_reads_with_atr(atr: &[u8]) -> Vec<ReadStep> {
    vec![
        ReadStep::Bytes(response(0x81, 1, 1, 0, 1, &[])),
        ReadStep::Bytes(data(2, atr)),
        ReadStep::Bytes(response(0x82, 3, 0, 0, 1, &GET_PARAMETERS)),
        ReadStep::Bytes(response(0x82, 4, 0, 0, 1, &SET_PARAMETERS)),
        ReadStep::Bytes(data(5, &IFS_RESPONSE)),
    ]
}

fn initialization_reads() -> Vec<ReadStep> {
    initialization_reads_with_atr(&ATR)
}

fn initialized(
    extra: Vec<ReadStep>,
) -> (Sec1210TransportV2<MockDescriptor, StepClock>, WriteTrace) {
    let trace = WriteTrace::new();
    let mut reads = initialization_reads();
    reads.extend(extra);
    let descriptor = MockDescriptor::new(reads, trace.clone());
    let mut transport = Sec1210TransportV2::new(descriptor, StepClock::ticking());
    transport.initialize().expect("fixed initialization");
    (transport, trace)
}

fn hex(value: &str) -> Vec<u8> {
    value
        .as_bytes()
        .chunks_exact(2)
        .map(|pair| {
            let digit = |byte| match byte {
                b'0'..=b'9' => byte - b'0',
                b'a'..=b'f' => byte - b'a' + 10,
                _ => 0xff,
            };
            (digit(pair[0]) << 4) | digit(pair[1])
        })
        .collect()
}

fn assert_transport_error<T>(
    result: Result<T, CardTransportErrorV2>,
    expected: CardTransportErrorV2,
) {
    match result {
        Err(actual) => assert_eq!(actual, expected),
        Ok(_) => panic!("expected {}", expected.name()),
    }
}

#[test]
fn production_limits_and_exact_five_initialization_writes_are_pinned() {
    assert_eq!(QK_LIM_APDU_012_COMMAND_INF_BYTES, 254);
    assert_eq!(QK_LIM_APDU_013_RESPONSE_INF_BYTES, 254);
    assert_eq!(QK_LIM_APDU_014_MAX_WTX_MULTIPLIER, 24);
    assert_eq!(QK_LIM_APDU_015_MAX_WTX_PER_APDU, 8);
    assert_eq!(QK_LIM_APDU_016_MAX_TIME_EXTENSIONS_PER_APDU, 8);
    assert_eq!(QK_LIM_APDU_017_MAX_CONTROLLER_COMMANDS, 977);
    assert_eq!(QK_LIM_APDU_018_MAX_RECEIVED_BYTES, 52_797);
    assert_eq!(QK_LIM_APDU_019_BASE_COMMAND_WAIT_MS, 5_000);
    assert_eq!(QK_LIM_APDU_020_APDU_DEADLINE_MS, 30_000);

    let (transport, trace) = initialized(Vec::new());
    assert_eq!(transport.controller_command_count(), 5);
    assert_eq!(transport.received_byte_count(), 99);
    assert_eq!(transport.event_count(), 0);
    assert_eq!(transport.failure(), None);
    assert_eq!(
        trace.values(),
        [
            "03066500000000000100000061",
            "03066200000000000202000067",
            "03066c0000000000030000006a",
            "0306610700000000040100001810ff4d00fe0022",
            "03066f05000000000500000000c101fe3e6a",
        ]
        .map(hex)
    );
}

#[test]
fn structural_atr_profile_is_not_a_registered_byte_pin() {
    const DISTINCT_VALID_ATR: [u8; 9] = [0x3b, 0x90, 0x18, 0x81, 0x91, 0xdd, 0x1f, 0x02, 0x58];
    assert_ne!(DISTINCT_VALID_ATR.as_slice(), ATR);
    let trace = WriteTrace::new();
    let descriptor = MockDescriptor::new(
        initialization_reads_with_atr(&DISTINCT_VALID_ATR),
        trace.clone(),
    );
    let mut transport = Sec1210TransportV2::new(descriptor, StepClock::ticking());
    assert_eq!(transport.initialize(), Ok(()));
    assert_eq!(trace.values().len(), 5);

    let mut invalid_atr = ATR;
    invalid_atr[0] = 0x3f;
    let trace = WriteTrace::new();
    let descriptor = MockDescriptor::new(initialization_reads_with_atr(&invalid_atr), trace);
    let mut transport = Sec1210TransportV2::new(descriptor, StepClock::ticking());
    assert_eq!(
        transport.initialize(),
        Err(CardTransportErrorV2::Sec1210AtrProfileRejected)
    );
}

#[test]
fn fragmented_frames_and_a_coalesced_event_then_response_are_accepted() {
    let mut slot = vec![0x50, 0x03];
    slot.extend(response(0x81, 1, 1, 0, 1, &[]));
    let mut reads = vec![ReadStep::Bytes(slot)];
    for frame in initialization_reads().into_iter().skip(1) {
        let ReadStep::Bytes(bytes) = frame else {
            unreachable!()
        };
        reads.extend(bytes.into_iter().map(|byte| ReadStep::Bytes(vec![byte])));
    }
    let trace = WriteTrace::new();
    let mut transport =
        Sec1210TransportV2::new(MockDescriptor::new(reads, trace), StepClock::ticking());
    assert_eq!(transport.initialize(), Ok(()));
    assert_eq!(transport.event_count(), 1);
    assert_eq!(transport.received_byte_count(), 101);
}

#[test]
fn first_failure_is_sticky_and_no_later_write_occurs() {
    let mut reads = initialization_reads();
    let ReadStep::Bytes(frame) = &mut reads[0] else {
        unreachable!()
    };
    frame[12] ^= 1;
    let trace = WriteTrace::new();
    let mut transport = Sec1210TransportV2::new(
        MockDescriptor::new(reads, trace.clone()),
        StepClock::ticking(),
    );
    let first = CardTransportErrorV2::Sec1210ChecksumRejected;
    assert_eq!(transport.initialize(), Err(first));
    assert_eq!(transport.initialize(), Err(first));
    assert_transport_error(transport.transmit_apdu(&[0]), first);
    assert_eq!(transport.failure(), Some(first));
    assert_eq!(trace.values().len(), 1);
}

#[test]
fn application_apdu_limit_rejects_109_before_write() {
    let mut extra = Vec::new();
    for index in 0..108usize {
        let sequence = (6usize + index) as u8;
        extra.push(ReadStep::Bytes(data(
            sequence,
            &t1_i((index & 1) as u8, &[0x90, 0x00]),
        )));
    }
    let (mut transport, trace) = initialized(extra);
    for _ in 0..108 {
        assert_eq!(
            transport.transmit_apdu(&[0x00]).unwrap().bytes(),
            [0x90, 0x00]
        );
    }
    let writes = trace.values().len();
    assert_eq!(transport.application_apdu_count(), 108);
    assert_transport_error(
        transport.transmit_apdu(&[0x00]),
        CardTransportErrorV2::Sec1210ApplicationApduLimitExceeded,
    );
    assert_eq!(trace.values().len(), writes);
}

#[test]
fn session_command_limit_rejects_command_978_before_write() {
    let mut extra = Vec::new();
    let mut controller_sequence = 6u8;
    for application_sequence in 0..108u8 {
        for _ in 0..8 {
            extra.push(ReadStep::Bytes(data(controller_sequence, &t1_wtx(1))));
            controller_sequence = controller_sequence.wrapping_add(1);
        }
        extra.push(ReadStep::Bytes(data(
            controller_sequence,
            &t1_i(application_sequence & 1, &[0x90, 0x00]),
        )));
        controller_sequence = controller_sequence.wrapping_add(1);
    }

    let (mut transport, trace) = initialized(extra);
    for _ in 0..108 {
        assert_eq!(
            transport.transmit_apdu(&[0x00]).unwrap().bytes(),
            [0x90, 0x00]
        );
    }
    let writes = trace.values().len();
    assert_eq!(transport.controller_command_count(), 977);
    assert_eq!(transport.application_apdu_count(), 108);
    assert_transport_error(
        transport.transmit_apdu(&[0x00]),
        CardTransportErrorV2::Sec1210SessionCommandLimitExceeded,
    );
    assert_eq!(trace.values().len(), writes);
}

fn one_apdu_with_wtx(multipliers: &[u8]) -> (Vec<ReadStep>, usize) {
    let mut sequence = 6u8;
    let mut reads = Vec::new();
    for multiplier in multipliers {
        reads.push(ReadStep::Bytes(data(sequence, &t1_wtx(*multiplier))));
        sequence = sequence.wrapping_add(1);
    }
    reads.push(ReadStep::Bytes(data(sequence, &t1_i(0, &[0x90, 0x00]))));
    (reads, usize::from(sequence).saturating_sub(5))
}

#[test]
fn wtx_multipliers_one_and_twenty_four_are_bounded_and_carried_in_bbwi() {
    for multiplier in [1, 24] {
        let (reads, _) = one_apdu_with_wtx(&[multiplier]);
        let (mut transport, trace) = initialized(reads);
        assert_eq!(
            transport.transmit_apdu(&[0x00]).unwrap().bytes(),
            [0x90, 0x00]
        );
        assert_eq!(transport.wtx_count(), 1);
        let writes = trace.values();
        assert_eq!(writes.len(), 7);
        assert_eq!(writes[6][9], multiplier);
        assert_eq!(
            &writes[6][12..17],
            &[0, 0xe3, 1, multiplier, 0xe2 ^ multiplier]
        );
        assert_eq!(
            trace.write_waits()[6],
            if multiplier == 1 { 5_000 } else { 28_560 }
        );
    }
}

#[test]
fn wtx_zero_and_twenty_five_reject_before_a_response_write() {
    for multiplier in [0, 25] {
        let (reads, _) = one_apdu_with_wtx(&[multiplier]);
        let (mut transport, trace) = initialized(reads);
        assert_transport_error(
            transport.transmit_apdu(&[0]),
            CardTransportErrorV2::T1WtxMultiplierRejected,
        );
        assert_eq!(trace.values().len(), 6);
    }
}

#[test]
fn eighth_wtx_passes_and_ninth_rejects_without_a_tenth_apdu_write() {
    let eight = [1u8; 8];
    let (reads, _) = one_apdu_with_wtx(&eight);
    let (mut transport, trace) = initialized(reads);
    assert!(transport.transmit_apdu(&[0]).is_ok());
    assert_eq!(transport.wtx_count(), 8);
    assert_eq!(trace.values().len(), 14);

    let nine = [1u8; 9];
    let (reads, _) = one_apdu_with_wtx(&nine);
    let (mut transport, trace) = initialized(reads);
    assert_transport_error(
        transport.transmit_apdu(&[0]),
        CardTransportErrorV2::T1WtxLimitExceeded,
    );
    assert_eq!(trace.values().len(), 14);
}

fn time_extension(sequence: u8, multiplier: u8) -> ReadStep {
    ReadStep::Bytes(response(0x80, sequence, 0x80, multiplier, 0, &[]))
}

#[test]
fn reader_time_extensions_one_and_eight_pass_while_nine_rejects() {
    for count in [1usize, 8] {
        let mut reads = (0..count).map(|_| time_extension(6, 1)).collect::<Vec<_>>();
        reads.push(ReadStep::Bytes(data(6, &t1_i(0, &[0x90, 0]))));
        let (mut transport, _) = initialized(reads);
        assert!(transport.transmit_apdu(&[0]).is_ok());
        assert_eq!(transport.reader_time_extension_count(), count);
    }

    let reads = (0..9).map(|_| time_extension(6, 1)).collect();
    let (mut transport, trace) = initialized(reads);
    assert_transport_error(
        transport.transmit_apdu(&[0]),
        CardTransportErrorV2::Sec1210TimeExtensionLimitExceeded,
    );
    assert_eq!(trace.values().len(), 6);

    let (mut transport, _) = initialized(vec![ReadStep::Bytes(response(0x81, 6, 0x80, 1, 0, &[]))]);
    assert_transport_error(
        transport.transmit_apdu(&[0]),
        CardTransportErrorV2::Sec1210TimeExtensionRejected,
    );

    let (mut transport, _) =
        initialized(vec![ReadStep::Bytes(response(0x80, 6, 0x80, 1, 0, &[0]))]);
    assert_transport_error(
        transport.transmit_apdu(&[0]),
        CardTransportErrorV2::Sec1210TimeExtensionShapeRejected,
    );
}

#[test]
fn descriptor_write_read_eof_timeout_partial_and_clock_failures_are_named() {
    let cases = [
        (
            MockDescriptor::new(initialization_reads(), WriteTrace::new()).failed_write_at(1),
            StepClock::ticking(),
            CardTransportErrorV2::Sec1210DescriptorWriteFailed,
        ),
        (
            MockDescriptor::new(initialization_reads(), WriteTrace::new()).short_write_at(1),
            StepClock::ticking(),
            CardTransportErrorV2::Sec1210PartialWrite,
        ),
        (
            MockDescriptor::new(initialization_reads(), WriteTrace::new()).timed_out_write_at(1),
            StepClock::ticking(),
            CardTransportErrorV2::Sec1210DeadlineExceeded,
        ),
        (
            MockDescriptor::new(vec![ReadStep::Failed], WriteTrace::new()),
            StepClock::ticking(),
            CardTransportErrorV2::Sec1210DescriptorReadFailed,
        ),
        (
            MockDescriptor::new(vec![ReadStep::End], WriteTrace::new()),
            StepClock::ticking(),
            CardTransportErrorV2::Sec1210DescriptorClosed,
        ),
        (
            MockDescriptor::new(vec![ReadStep::Bytes(Vec::new())], WriteTrace::new()),
            StepClock::ticking(),
            CardTransportErrorV2::Sec1210DescriptorClosed,
        ),
        (
            MockDescriptor::new(vec![ReadStep::TimedOut], WriteTrace::new()),
            StepClock::ticking(),
            CardTransportErrorV2::Sec1210DeadlineExceeded,
        ),
        (
            MockDescriptor::new(
                vec![ReadStep::Bytes(vec![3, 6, 0x81]), ReadStep::TimedOut],
                WriteTrace::new(),
            ),
            StepClock::ticking(),
            CardTransportErrorV2::Sec1210PartialFrameDeadline,
        ),
        (
            MockDescriptor::new(
                vec![ReadStep::Bytes(vec![3, 6, 0x81]), ReadStep::End],
                WriteTrace::new(),
            ),
            StepClock::ticking(),
            CardTransportErrorV2::Sec1210Truncated,
        ),
        (
            MockDescriptor::new(initialization_reads(), WriteTrace::new()),
            StepClock::scripted([Ok(2), Ok(1)]),
            CardTransportErrorV2::Sec1210ClockRegression,
        ),
        (
            MockDescriptor::new(initialization_reads(), WriteTrace::new()),
            StepClock::scripted([Err(Sec1210ClockErrorV2)]),
            CardTransportErrorV2::Sec1210ClockFailed,
        ),
    ];
    for (descriptor, clock, expected) in cases {
        let mut transport = Sec1210TransportV2::new(descriptor, clock);
        assert_eq!(transport.initialize(), Err(expected), "{}", expected.name());
    }
}

fn clock(values: &[u64]) -> StepClock {
    StepClock::scripted(values.iter().copied().map(Ok))
}

#[test]
fn controller_deadline_is_bounded_before_at_and_after_and_includes_write_work() {
    let trace = WriteTrace::new();
    let descriptor = MockDescriptor::new(
        vec![initialization_reads().into_iter().next().unwrap()],
        trace.clone(),
    );
    let mut transport = Sec1210TransportV2::new(descriptor, clock(&[0, 0, 0, 4_999]));
    assert_eq!(
        transport.initialize(),
        Err(CardTransportErrorV2::Sec1210DescriptorClosed)
    );
    assert_eq!(trace.values().len(), 2, "the 4,999 ms reply was accepted");
    assert_eq!(trace.write_waits()[0], 5_000);
    assert_eq!(trace.read_waits()[0], 5_000);

    for boundary in [5_000, 5_001] {
        let trace = WriteTrace::new();
        let descriptor = MockDescriptor::new(initialization_reads(), trace.clone());
        let mut transport = Sec1210TransportV2::new(descriptor, clock(&[0, boundary]));
        assert_eq!(
            transport.initialize(),
            Err(CardTransportErrorV2::Sec1210DeadlineExceeded)
        );
        assert_eq!(trace.values().len(), 1);
        assert!(trace.read_waits().is_empty());
    }

    let trace = WriteTrace::new();
    let descriptor = MockDescriptor::new(initialization_reads(), trace.clone());
    let mut transport = Sec1210TransportV2::new(descriptor, clock(&[0, 0, 0, 5_000]));
    assert_eq!(
        transport.initialize(),
        Err(CardTransportErrorV2::Sec1210DeadlineExceeded)
    );
    assert_eq!(trace.values().len(), 1);
    assert_eq!(trace.read_waits(), [5_000]);
}

#[test]
fn ifs_and_apdu_absolute_deadlines_stop_before_write_and_clip_wtx_wait() {
    let mut values = vec![0; 16];
    values.extend([0, 5_000]);
    let trace = WriteTrace::new();
    let descriptor = MockDescriptor::new(initialization_reads(), trace.clone());
    let mut transport = Sec1210TransportV2::new(descriptor, clock(&values));
    assert_eq!(
        transport.initialize(),
        Err(CardTransportErrorV2::T1DeadlineExceeded)
    );
    assert_eq!(
        trace.values().len(),
        4,
        "IFS was not written at its deadline"
    );

    let mut values = vec![0; 22];
    values.extend([
        1_000, 1_000, 1_000, 1_000, 1_000, 1_000, 1_000, 1_000, 31_000,
    ]);
    let trace = WriteTrace::new();
    let mut reads = initialization_reads();
    reads.push(ReadStep::Bytes(data(6, &t1_wtx(24))));
    let descriptor = MockDescriptor::new(reads, trace.clone());
    let mut transport = Sec1210TransportV2::new(descriptor, clock(&values));
    transport.initialize().unwrap();
    assert_transport_error(
        transport.transmit_apdu(&[0]),
        CardTransportErrorV2::T1DeadlineExceeded,
    );
    assert_eq!(
        trace.values().len(),
        6,
        "WTX response was not written at 30,000 ms"
    );

    let mut values = vec![0; 22];
    values.extend([
        1_000, 1_000, 1_000, 1_000, 1_000, 1_000, 1_000, 1_000, 30_000, 30_000, 30_000, 30_000,
        30_000,
    ]);
    let trace = WriteTrace::new();
    let mut reads = initialization_reads();
    reads.push(ReadStep::Bytes(data(6, &t1_wtx(24))));
    reads.push(ReadStep::Bytes(data(7, &t1_i(0, &[0x90, 0]))));
    let descriptor = MockDescriptor::new(reads, trace.clone());
    let mut transport = Sec1210TransportV2::new(descriptor, clock(&values));
    transport.initialize().unwrap();
    assert_eq!(transport.transmit_apdu(&[0]).unwrap().bytes(), [0x90, 0]);
    assert_eq!(*trace.write_waits().last().unwrap(), 1_000);
    assert_eq!(*trace.read_waits().last().unwrap(), 1_000);
}

#[test]
fn reader_time_extension_does_not_renew_the_original_command_deadline() {
    let mut values = vec![0; 22];
    values.extend([1_000, 1_000, 1_000, 1_000, 1_000, 2_000, 5_999, 6_000]);
    let trace = WriteTrace::new();
    let mut reads = initialization_reads();
    reads.push(time_extension(6, 1));
    reads.push(ReadStep::Bytes(data(6, &t1_i(0, &[0x90, 0]))));
    let descriptor = MockDescriptor::new(reads, trace.clone());
    let mut transport = Sec1210TransportV2::new(descriptor, clock(&values));
    transport.initialize().unwrap();
    assert_transport_error(
        transport.transmit_apdu(&[0]),
        CardTransportErrorV2::Sec1210DeadlineExceeded,
    );
    assert_eq!(*trace.read_waits().last().unwrap(), 1);
}

#[test]
fn combined_faults_follow_the_fixed_validation_and_clock_precedence() {
    let mut wrong_slot = response(0x80, 2, 0x43, 1, 1, &[]);
    replace_checked_byte(&mut wrong_slot, 7, 1);
    let cases = [
        (wrong_slot, CardTransportErrorV2::Sec1210SlotRejected),
        (
            response(0x80, 2, 0x43, 1, 1, &[]),
            CardTransportErrorV2::Sec1210SequenceRejected,
        ),
        (
            response(0x80, 1, 0x03, 1, 1, &[]),
            CardTransportErrorV2::Sec1210StatusReserved,
        ),
        (
            response(0x80, 1, 0x41, 1, 1, &[]),
            CardTransportErrorV2::Sec1210CommandFailed,
        ),
        (
            response(0x80, 1, 0x01, 1, 1, &[]),
            CardTransportErrorV2::Sec1210ResponseTypeRejected,
        ),
        (
            response(0x81, 1, 0x02, 1, 1, &[]),
            CardTransportErrorV2::Sec1210StatusErrorRejected,
        ),
    ];
    for (bytes, expected) in cases {
        let trace = WriteTrace::new();
        let descriptor = MockDescriptor::new(vec![ReadStep::Bytes(bytes)], trace);
        let mut transport = Sec1210TransportV2::new(descriptor, StepClock::ticking());
        assert_eq!(transport.initialize(), Err(expected));
    }

    let mut malformed = response(0x81, 1, 1, 0, 1, &[]);
    *malformed.last_mut().unwrap() ^= 1;
    let trace = WriteTrace::new();
    let descriptor = MockDescriptor::new(vec![ReadStep::Bytes(malformed)], trace);
    let mut transport = Sec1210TransportV2::new(descriptor, clock(&[0, 0, 0, 5_000]));
    assert_eq!(
        transport.initialize(),
        Err(CardTransportErrorV2::Sec1210DeadlineExceeded)
    );

    let trace = WriteTrace::new();
    let descriptor = MockDescriptor::new(initialization_reads(), trace).failed_write_at(1);
    let mut transport = Sec1210TransportV2::new(
        descriptor,
        StepClock::scripted([Ok(0), Err(Sec1210ClockErrorV2)]),
    );
    assert_eq!(
        transport.initialize(),
        Err(CardTransportErrorV2::Sec1210ClockFailed)
    );

    let trace = WriteTrace::new();
    let descriptor = MockDescriptor::new(vec![ReadStep::Failed], trace);
    let mut transport = Sec1210TransportV2::new(descriptor, clock(&[2, 2, 2, 1]));
    assert_eq!(
        transport.initialize(),
        Err(CardTransportErrorV2::Sec1210ClockRegression)
    );
}

#[test]
fn malformed_wire_families_keep_distinct_names() {
    let mut checksum = response(0x81, 1, 1, 0, 1, &[]);
    *checksum.last_mut().unwrap() ^= 1;
    let mut wrong_slot = response(0x81, 1, 1, 0, 1, &[]);
    replace_checked_byte(&mut wrong_slot, 7, 1);
    let mut wrong_sequence = response(0x81, 1, 1, 0, 1, &[]);
    replace_checked_byte(&mut wrong_sequence, 8, 2);
    let mut trailing = response(0x81, 1, 1, 0, 1, &[]);
    trailing.push(0);
    let wire_cases = vec![
        (vec![0x52], CardTransportErrorV2::Sec1210PrefixRejected),
        (
            vec![0x03, 0x06, 0x81, 0x06, 0x01, 0x00, 0x00],
            CardTransportErrorV2::Sec1210LengthExceeded,
        ),
        (checksum, CardTransportErrorV2::Sec1210ChecksumRejected),
        (vec![0x03, 0x15, 0x16], CardTransportErrorV2::Sec1210Nack),
        (wrong_slot, CardTransportErrorV2::Sec1210SlotRejected),
        (
            wrong_sequence,
            CardTransportErrorV2::Sec1210SequenceRejected,
        ),
        (
            response(0x80, 1, 1, 0, 1, &[]),
            CardTransportErrorV2::Sec1210ResponseTypeRejected,
        ),
        (
            response(0x81, 1, 3, 0, 1, &[]),
            CardTransportErrorV2::Sec1210StatusReserved,
        ),
        (
            response(0x81, 1, 0x41, 1, 1, &[]),
            CardTransportErrorV2::Sec1210CommandFailed,
        ),
        (
            response(0x81, 1, 0x81, 1, 0, &[]),
            CardTransportErrorV2::Sec1210TimeExtensionRejected,
        ),
        (
            response(0x81, 1, 1, 1, 1, &[]),
            CardTransportErrorV2::Sec1210StatusErrorRejected,
        ),
        (
            response(0x81, 1, 0, 0, 1, &[]),
            CardTransportErrorV2::Sec1210AlreadyActive,
        ),
        (
            response(0x81, 1, 2, 0, 1, &[]),
            CardTransportErrorV2::Sec1210CardRemoved,
        ),
        (
            response(0x81, 1, 1, 0, 1, &[0]),
            CardTransportErrorV2::Sec1210PayloadRejected,
        ),
        (
            vec![0x50, 0xf1],
            CardTransportErrorV2::Sec1210EventBitmapRejected,
        ),
        (vec![0x50, 0x02], CardTransportErrorV2::Sec1210CardRemoved),
        (
            vec![0x51, 0, 1, 1],
            CardTransportErrorV2::Sec1210HardwareError,
        ),
        (
            vec![0x51, 1, 1, 1],
            CardTransportErrorV2::Sec1210SlotRejected,
        ),
        (
            vec![0x51, 0, 2, 1],
            CardTransportErrorV2::Sec1210SequenceRejected,
        ),
        (trailing, CardTransportErrorV2::Sec1210TrailingData),
    ];
    for (bytes, expected) in wire_cases {
        let trace = WriteTrace::new();
        let mut transport = Sec1210TransportV2::new(
            MockDescriptor::new(vec![ReadStep::Bytes(bytes)], trace),
            StepClock::ticking(),
        );
        assert_eq!(transport.initialize(), Err(expected));
    }
}

#[test]
fn exact_parameters_and_ifs_gates_reject_by_stable_name() {
    let mut bad_get = initialization_reads();
    bad_get[2] = ReadStep::Bytes(response(
        0x82,
        3,
        0,
        0,
        1,
        &[0x11, 0x11, 0xff, 0x4d, 0, 0xfe, 0],
    ));
    let trace = WriteTrace::new();
    let mut transport =
        Sec1210TransportV2::new(MockDescriptor::new(bad_get, trace), StepClock::ticking());
    assert_eq!(
        transport.initialize(),
        Err(CardTransportErrorV2::Sec1210ParametersRejected)
    );

    let mut reserved_ifsc = initialization_reads();
    reserved_ifsc[2] = ReadStep::Bytes(response(
        0x82,
        3,
        0,
        0,
        1,
        &[0x11, 0x10, 0xff, 0x4d, 0, 0xff, 0],
    ));
    let trace = WriteTrace::new();
    let mut transport = Sec1210TransportV2::new(
        MockDescriptor::new(reserved_ifsc, trace),
        StepClock::ticking(),
    );
    assert_eq!(
        transport.initialize(),
        Err(CardTransportErrorV2::Sec1210ParametersRejected)
    );

    let mut bad_set = initialization_reads();
    bad_set[3] = ReadStep::Bytes(response(0x82, 4, 0, 0, 1, &GET_PARAMETERS));
    let trace = WriteTrace::new();
    let mut transport =
        Sec1210TransportV2::new(MockDescriptor::new(bad_set, trace), StepClock::ticking());
    assert_eq!(
        transport.initialize(),
        Err(CardTransportErrorV2::Sec1210SetParametersEchoRejected)
    );

    let mut bad_ifs = initialization_reads();
    bad_ifs[4] = ReadStep::Bytes(data(5, &t1_control(0xe1, &[0xfd])));
    let trace = WriteTrace::new();
    let mut transport =
        Sec1210TransportV2::new(MockDescriptor::new(bad_ifs, trace), StepClock::ticking());
    assert_eq!(
        transport.initialize(),
        Err(CardTransportErrorV2::T1IfsRejected)
    );
}

#[test]
fn malformed_t1_families_keep_distinct_names() {
    let mut checksum = t1_i(0, &[0x90, 0x00]);
    *checksum.last_mut().unwrap() ^= 1;
    let mut wrong_nad = t1_i(0, &[0x90, 0x00]);
    replace_checked_byte(&mut wrong_nad, 0, 1);
    let t1_cases = vec![
        (vec![0, 0, 0], CardTransportErrorV2::T1BlockLengthRejected),
        (checksum, CardTransportErrorV2::T1ChecksumRejected),
        (wrong_nad, CardTransportErrorV2::T1NadRejected),
        (t1_control(0x04, &[]), CardTransportErrorV2::T1PcbRejected),
        (
            t1_control(0x80, &[0]),
            CardTransportErrorV2::T1ControlLengthRejected,
        ),
        (
            t1_control(0x81, &[]),
            CardTransportErrorV2::T1RetransmissionRejected,
        ),
        (
            t1_control(0xc0, &[]),
            CardTransportErrorV2::T1ResynchRejected,
        ),
        (t1_control(0xc2, &[]), CardTransportErrorV2::T1AbortRejected),
        (
            t1_control(0x80, &[]),
            CardTransportErrorV2::T1UnexpectedRBlock,
        ),
        (
            t1_i(1, &[0x90, 0]),
            CardTransportErrorV2::T1SequenceRejected,
        ),
        (
            t1_control(0x20, &[0x90, 0]),
            CardTransportErrorV2::T1ChainingRejected,
        ),
        (
            t1_control(0xe3, &[1]),
            CardTransportErrorV2::T1WtxResponseRejected,
        ),
        (
            t1_control(0xc3, &[1, 2]),
            CardTransportErrorV2::T1ControlLengthRejected,
        ),
    ];
    for (block, expected) in t1_cases {
        let (mut transport, _) = initialized(vec![ReadStep::Bytes(data(6, &block))]);
        assert_transport_error(transport.transmit_apdu(&[0]), expected);
    }
}

#[test]
fn application_command_and_response_bounds_reject_before_follow_on_write() {
    let (mut transport, trace) = initialized(Vec::new());
    let writes = trace.values().len();
    assert_transport_error(
        transport.transmit_apdu(&[]),
        CardTransportErrorV2::Sec1210ApplicationCommandLengthRejected,
    );
    assert_eq!(trace.values().len(), writes);

    let (mut transport, trace) = initialized(Vec::new());
    let writes = trace.values().len();
    assert_transport_error(
        transport.transmit_apdu(&vec![0xa5; 222]),
        CardTransportErrorV2::Sec1210ApplicationCommandLengthRejected,
    );
    assert_eq!(trace.values().len(), writes);

    let response_payload = vec![0xa5; 218];
    let (mut transport, trace) =
        initialized(vec![ReadStep::Bytes(data(6, &t1_i(0, &response_payload)))]);
    assert_eq!(
        transport.transmit_apdu(&vec![0xa5; 221]).unwrap().bytes(),
        response_payload
    );
    assert_eq!(trace.values().len(), 6);

    let response_payload = vec![0xa5; 219];
    let (mut transport, trace) =
        initialized(vec![ReadStep::Bytes(data(6, &t1_i(0, &response_payload)))]);
    assert_transport_error(
        transport.transmit_apdu(&vec![0xa5; 221]),
        CardTransportErrorV2::Sec1210ApplicationResponseLengthRejected,
    );
    assert_eq!(trace.values().len(), 6);
}

#[test]
fn sixty_four_events_pass_and_sixty_fifth_rejects() {
    let mut accepted = Vec::new();
    for _ in 0..64 {
        accepted.extend_from_slice(&[0x50, 0x03]);
    }
    accepted.extend(response(0x81, 1, 1, 0, 1, &[]));
    let mut reads = vec![ReadStep::Bytes(accepted)];
    reads.extend(initialization_reads().into_iter().skip(1));
    let trace = WriteTrace::new();
    let mut transport =
        Sec1210TransportV2::new(MockDescriptor::new(reads, trace), StepClock::ticking());
    assert_eq!(transport.initialize(), Ok(()));
    assert_eq!(transport.event_count(), 64);

    let mut rejected = Vec::new();
    for _ in 0..65 {
        rejected.extend_from_slice(&[0x50, 0x03]);
    }
    let trace = WriteTrace::new();
    let mut transport = Sec1210TransportV2::new(
        MockDescriptor::new(vec![ReadStep::Bytes(rejected)], trace),
        StepClock::ticking(),
    );
    assert_eq!(
        transport.initialize(),
        Err(CardTransportErrorV2::Sec1210EventLimitExceeded)
    );
}

#[test]
fn reset_wipes_counts_but_cannot_reopen_a_failed_transport() {
    let mut first = initialization_reads().remove(0);
    let ReadStep::Bytes(frame) = &mut first else {
        unreachable!()
    };
    frame[12] ^= 1;
    let trace = WriteTrace::new();
    let descriptor = MockDescriptor::new(vec![first], trace.clone());
    let mut transport = Sec1210TransportV2::new(descriptor, StepClock::ticking());
    let failure = CardTransportErrorV2::Sec1210ChecksumRejected;
    assert_eq!(transport.initialize(), Err(failure));
    let writes = trace.values().len();
    transport.reset();
    assert_eq!(transport.failure(), Some(failure));
    assert_eq!(transport.controller_command_count(), 0);
    assert_eq!(transport.received_byte_count(), 0);
    assert_eq!(transport.event_count(), 0);
    assert_eq!(transport.application_apdu_count(), 0);
    assert_eq!(transport.initialize(), Err(failure));
    assert_transport_error(transport.transmit_apdu(&[0]), failure);
    assert_eq!(trace.values().len(), writes);
}

#[test]
fn reset_clears_a_live_transport_without_io_and_allows_fresh_initialization() {
    let mut reads = initialization_reads();
    reads.push(ReadStep::Bytes(data(6, &t1_i(0, &[0x90, 0]))));
    reads.extend(initialization_reads());
    let trace = WriteTrace::new();
    let descriptor = MockDescriptor::new(reads, trace.clone());
    let mut transport = Sec1210TransportV2::new(descriptor, StepClock::ticking());
    assert_eq!(transport.initialize(), Ok(()));
    assert_eq!(transport.transmit_apdu(&[0]).unwrap().bytes(), [0x90, 0]);
    let writes = trace.values().len();
    transport.reset();
    assert_eq!(transport.failure(), None);
    assert_eq!(transport.controller_command_count(), 0);
    assert_eq!(transport.received_byte_count(), 0);
    assert_eq!(transport.event_count(), 0);
    assert_eq!(transport.application_apdu_count(), 0);
    assert_eq!(transport.initialize(), Ok(()));
    assert_eq!(trace.values().len(), writes + 5);
}

#[test]
fn public_errors_are_fieldless_and_names_are_fixed_ascii() {
    let errors = [
        CardTransportErrorV2::Sec1210DescriptorReadFailed,
        CardTransportErrorV2::Sec1210DescriptorWriteFailed,
        CardTransportErrorV2::Sec1210DescriptorClosed,
        CardTransportErrorV2::Sec1210ClockFailed,
        CardTransportErrorV2::Sec1210ClockRegression,
        CardTransportErrorV2::Sec1210StateRejected,
        CardTransportErrorV2::Sec1210ApplicationCommandLengthRejected,
        CardTransportErrorV2::Sec1210ApplicationResponseLengthRejected,
        CardTransportErrorV2::Sec1210ApplicationApduLimitExceeded,
        CardTransportErrorV2::Sec1210AtrProfileRejected,
        CardTransportErrorV2::Sec1210SessionCommandLimitExceeded,
        CardTransportErrorV2::Sec1210SessionReceiveLimitExceeded,
        CardTransportErrorV2::Sec1210EventLimitExceeded,
        CardTransportErrorV2::Sec1210PrefixRejected,
        CardTransportErrorV2::Sec1210LengthExceeded,
        CardTransportErrorV2::Sec1210Truncated,
        CardTransportErrorV2::Sec1210ChecksumRejected,
        CardTransportErrorV2::Sec1210Nack,
        CardTransportErrorV2::Sec1210SlotRejected,
        CardTransportErrorV2::Sec1210SequenceRejected,
        CardTransportErrorV2::Sec1210ResponseTypeRejected,
        CardTransportErrorV2::Sec1210StatusReserved,
        CardTransportErrorV2::Sec1210CommandFailed,
        CardTransportErrorV2::Sec1210TimeExtensionRejected,
        CardTransportErrorV2::Sec1210StatusErrorRejected,
        CardTransportErrorV2::Sec1210AlreadyActive,
        CardTransportErrorV2::Sec1210CardRemoved,
        CardTransportErrorV2::Sec1210IccStatusRejected,
        CardTransportErrorV2::Sec1210PayloadRejected,
        CardTransportErrorV2::Sec1210ChainingRejected,
        CardTransportErrorV2::Sec1210EventBitmapRejected,
        CardTransportErrorV2::Sec1210HardwareError,
        CardTransportErrorV2::Sec1210UnsolicitedResponse,
        CardTransportErrorV2::Sec1210TrailingData,
        CardTransportErrorV2::Sec1210SequenceViolation,
        CardTransportErrorV2::Sec1210PartialWrite,
        CardTransportErrorV2::Sec1210DeadlineExceeded,
        CardTransportErrorV2::Sec1210PartialFrameDeadline,
        CardTransportErrorV2::Sec1210ParametersRejected,
        CardTransportErrorV2::Sec1210SetParametersEchoRejected,
        CardTransportErrorV2::Sec1210TimeExtensionShapeRejected,
        CardTransportErrorV2::Sec1210TimeExtensionLimitExceeded,
        CardTransportErrorV2::T1BlockLengthRejected,
        CardTransportErrorV2::T1ChecksumRejected,
        CardTransportErrorV2::T1NadRejected,
        CardTransportErrorV2::T1PcbRejected,
        CardTransportErrorV2::T1ControlLengthRejected,
        CardTransportErrorV2::T1RetransmissionRejected,
        CardTransportErrorV2::T1WtxRejected,
        CardTransportErrorV2::T1IfsRejected,
        CardTransportErrorV2::T1ResynchRejected,
        CardTransportErrorV2::T1AbortRejected,
        CardTransportErrorV2::T1UnexpectedRBlock,
        CardTransportErrorV2::T1SequenceRejected,
        CardTransportErrorV2::T1StateRejected,
        CardTransportErrorV2::T1CommandLengthRejected,
        CardTransportErrorV2::T1ResponseLengthRejected,
        CardTransportErrorV2::T1ResponseMismatch,
        CardTransportErrorV2::T1PartialWrite,
        CardTransportErrorV2::T1ExchangeLimitExceeded,
        CardTransportErrorV2::T1ApduLimitExceeded,
        CardTransportErrorV2::T1DeadlineExceeded,
        CardTransportErrorV2::T1ClockRegression,
        CardTransportErrorV2::T1WtxMultiplierRejected,
        CardTransportErrorV2::T1WtxLimitExceeded,
        CardTransportErrorV2::T1WtxResponseRejected,
        CardTransportErrorV2::T1ChainingRejected,
    ];
    assert_eq!(core::mem::size_of::<CardTransportErrorV2>(), 1);
    for error in errors {
        assert!(error.name().is_ascii());
        assert!(!error.name().contains(':'));
        assert_eq!(format!("{error:?}"), error.name());
    }
}
