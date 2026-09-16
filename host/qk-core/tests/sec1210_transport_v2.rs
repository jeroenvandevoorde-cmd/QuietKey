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
use qk_sec1210_wire::MAX_PRODUCTION_ATR_BYTES;
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

fn with_tck<const N: usize>(mut atr: [u8; N]) -> [u8; N] {
    let last = atr.len() - 1;
    atr[last] = atr[1..last].iter().fold(0u8, |sum, byte| sum ^ byte);
    atr
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
    assert_eq!(QK_LIM_APDU_018_MAX_RECEIVED_BYTES, 52_815);
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
fn maximum_structural_atr_drives_the_setup_receive_bound() {
    let atr = with_tck([
        0x3b, 0xff, 0x18, 0x00, 0xff, 0x81, 0xf1, 0xfe, 0x00, 0x00, 0xd1, 0x00, 0x00, 0x7f, 0x02,
        0x00, 0x00, 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c,
        0x0d, 0x0e, 0x00,
    ]);
    assert_eq!(atr.len(), MAX_PRODUCTION_ATR_BYTES);
    let trace = WriteTrace::new();
    let descriptor = MockDescriptor::new(initialization_reads_with_atr(&atr), trace.clone());
    let mut transport = Sec1210TransportV2::new(descriptor, StepClock::ticking());

    assert_eq!(transport.initialize(), Ok(()));
    assert_eq!(transport.controller_command_count(), 5);
    assert_eq!(transport.received_byte_count(), 117);
    assert_eq!(transport.event_count(), 0);
    assert_eq!(transport.failure(), None);
    assert_eq!(trace.values().len(), 5);
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

#[cfg(target_os = "linux")]
mod linux_pty {
    use super::*;
    #[cfg(feature = "normal-process")]
    use std::collections::BTreeMap;
    use std::fs::File;
    use std::io::{Read, Write};
    use std::os::fd::{AsRawFd, FromRawFd, RawFd};
    use std::ptr;
    use std::thread;
    #[cfg(feature = "normal-process")]
    use std::time::Instant;

    #[cfg(feature = "normal-process")]
    use qk_card_protocol::{
        parse_response, DescriptorSelector, Instruction, ResponseRef, DESCRIPTOR_BYTES,
    };
    #[cfg(feature = "normal-process")]
    use qk_core::{bind_normal_card_v1, CardInfoV1, NormalProfileV2};
    #[cfg(feature = "normal-process")]
    use qk_device_wire::{
        encode_frame, parse_frame, BodyRef, Capability, MessageKind, HEADER_BYTES,
    };

    #[cfg(feature = "normal-process")]
    const QKDV_FIXTURE: &str =
        include_str!("../../qk-card-protocol/tests/fixtures/card_protocol_v1.txt");
    #[cfg(feature = "normal-process")]
    const CCID_ORACLE: &str = include_str!(
        "../../../bench/card-enrollment/tests/fixtures/sitting_committed_readback_v1.tsv"
    );
    const POLLIN: i16 = 0x0001;
    const POLLOUT: i16 = 0x0004;
    const POLLERR: i16 = 0x0008;
    const POLLHUP: i16 = 0x0010;
    const POLLNVAL: i16 = 0x0020;
    const TCSANOW: i32 = 0;
    const SERVER_WAIT_MS: i32 = 2_000;

    #[repr(C)]
    struct PollFd {
        fd: i32,
        events: i16,
        revents: i16,
    }

    #[repr(align(16))]
    struct TermiosStorage([u8; 256]);

    #[cfg_attr(target_env = "gnu", link(name = "util"))]
    extern "C" {
        fn openpty(
            master: *mut i32,
            slave: *mut i32,
            name: *mut i8,
            termios: *const core::ffi::c_void,
            winsize: *const core::ffi::c_void,
        ) -> i32;
        fn tcgetattr(fd: i32, termios: *mut core::ffi::c_void) -> i32;
        fn cfmakeraw(termios: *mut core::ffi::c_void);
        fn tcsetattr(fd: i32, action: i32, termios: *const core::ffi::c_void) -> i32;
        fn poll(fds: *mut PollFd, count: usize, timeout_ms: i32) -> i32;
    }

    fn pty_pair() -> (File, File) {
        let mut master = -1;
        let mut slave = -1;
        // SAFETY: both output pointers are live, the optional name and settings
        // pointers are null, and successful descriptors are immediately owned.
        let opened = unsafe {
            openpty(
                &mut master,
                &mut slave,
                ptr::null_mut(),
                ptr::null(),
                ptr::null(),
            )
        };
        assert_eq!(
            opened,
            0,
            "openpty failed: {}",
            std::io::Error::last_os_error()
        );
        assert!(
            master >= 0 && slave >= 0,
            "openpty returned invalid descriptors"
        );
        // SAFETY: openpty returned two fresh, owned descriptors.
        let master = unsafe { File::from_raw_fd(master) };
        // SAFETY: openpty returned two fresh, owned descriptors.
        let slave = unsafe { File::from_raw_fd(slave) };

        let mut storage = TermiosStorage([0; 256]);
        let termios = storage.0.as_mut_ptr().cast::<core::ffi::c_void>();
        // SAFETY: storage is aligned and larger than Linux termios; tcgetattr
        // initializes it before cfmakeraw and tcsetattr consume it.
        assert_eq!(unsafe { tcgetattr(slave.as_raw_fd(), termios) }, 0);
        // SAFETY: termios now contains one initialized Linux termios value.
        unsafe { cfmakeraw(termios) };
        // SAFETY: termios remains initialized and live for this call.
        assert_eq!(unsafe { tcsetattr(slave.as_raw_fd(), TCSANOW, termios) }, 0);
        (master, slave)
    }

    fn poll_ready(fd: RawFd, events: i16, timeout_ms: i32) -> Result<bool, ()> {
        let mut descriptor = PollFd {
            fd,
            events,
            revents: 0,
        };
        // SAFETY: descriptor is one initialized pollfd and remains live.
        let result = unsafe { poll(&mut descriptor, 1, timeout_ms) };
        if result < 0 || descriptor.revents & (POLLERR | POLLNVAL) != 0 {
            return Err(());
        }
        if result == 0 {
            return Ok(false);
        }
        Ok(descriptor.revents & (events | POLLHUP) != 0)
    }

    struct PtyDescriptor(File);

    impl Sec1210DescriptorV2 for PtyDescriptor {
        fn write(
            &mut self,
            bytes: &[u8],
            maximum_wait_ms: u64,
        ) -> Result<Sec1210DescriptorWriteV2, Sec1210DescriptorErrorV2> {
            let timeout = i32::try_from(maximum_wait_ms).unwrap_or(i32::MAX);
            match poll_ready(self.0.as_raw_fd(), POLLOUT, timeout) {
                Ok(false) => return Ok(Sec1210DescriptorWriteV2::TimedOut),
                Err(()) => return Err(Sec1210DescriptorErrorV2),
                Ok(true) => {}
            }
            self.0
                .write(bytes)
                .map(Sec1210DescriptorWriteV2::Bytes)
                .map_err(|_| Sec1210DescriptorErrorV2)
        }

        fn read(
            &mut self,
            bytes: &mut [u8],
            maximum_wait_ms: u64,
        ) -> Result<Sec1210DescriptorReadV2, Sec1210DescriptorErrorV2> {
            let timeout = i32::try_from(maximum_wait_ms).unwrap_or(i32::MAX);
            match poll_ready(self.0.as_raw_fd(), POLLIN, timeout) {
                Ok(false) => return Ok(Sec1210DescriptorReadV2::TimedOut),
                Err(()) => return Err(Sec1210DescriptorErrorV2),
                Ok(true) => {}
            }
            match self.0.read(bytes) {
                Ok(0) => Ok(Sec1210DescriptorReadV2::EndOfStream),
                Ok(count) => Ok(Sec1210DescriptorReadV2::Bytes(count)),
                Err(_) => Err(Sec1210DescriptorErrorV2),
            }
        }
    }

    #[cfg(feature = "normal-process")]
    struct InstantClock(Instant);

    #[cfg(feature = "normal-process")]
    impl InstantClock {
        fn new() -> Self {
            Self(Instant::now())
        }
    }

    #[cfg(feature = "normal-process")]
    impl Sec1210MonotonicClockV2 for InstantClock {
        fn now_ms(&mut self) -> Result<u64, Sec1210ClockErrorV2> {
            u64::try_from(self.0.elapsed().as_millis()).map_err(|_| Sec1210ClockErrorV2)
        }
    }

    struct ServerExchange {
        expected: Vec<u8>,
        response: Vec<u8>,
    }

    fn read_exact_bounded(file: &mut File, output: &mut [u8]) {
        let mut offset = 0;
        while offset < output.len() {
            assert_eq!(
                poll_ready(file.as_raw_fd(), POLLIN, SERVER_WAIT_MS),
                Ok(true),
                "fake reader timed out waiting for a request"
            );
            let count = file.read(&mut output[offset..]).expect("fake reader read");
            assert!(count > 0, "fake reader saw request EOF");
            offset += count;
        }
    }

    fn read_request(file: &mut File) -> Vec<u8> {
        let mut header = [0u8; 12];
        read_exact_bounded(file, &mut header);
        assert_eq!(&header[..2], &[0x03, 0x06]);
        let payload = u32::from_le_bytes(header[3..7].try_into().expect("CCID length"));
        let payload = usize::try_from(payload).expect("bounded CCID request length");
        assert!(payload <= 254, "fake reader request exceeds production INF");
        let mut frame = header.to_vec();
        let mut tail = vec![0u8; payload + 1];
        read_exact_bounded(file, &mut tail);
        frame.extend_from_slice(&tail);
        assert_eq!(frame.iter().fold(0u8, |value, byte| value ^ byte), 0);
        frame
    }

    fn write_all_bounded(file: &mut File, bytes: &[u8]) {
        for fragment in bytes.chunks(7) {
            assert_eq!(
                poll_ready(file.as_raw_fd(), POLLOUT, SERVER_WAIT_MS),
                Ok(true),
                "fake reader timed out writing a response"
            );
            file.write_all(fragment)
                .expect("fake reader response write");
        }
    }

    fn serve(mut master: File, exchanges: Vec<ServerExchange>) -> Vec<Vec<u8>> {
        let mut requests = Vec::new();
        for exchange in exchanges {
            let request = read_request(&mut master);
            assert_eq!(request, exchange.expected);
            requests.push(request);
            if exchange.response.is_empty() {
                return requests;
            }
            write_all_bounded(&mut master, &exchange.response);
        }
        requests
    }

    fn with_pty<T, C>(
        exchanges: Vec<ServerExchange>,
        clock: C,
        client: impl FnOnce(&mut Sec1210TransportV2<PtyDescriptor, C>) -> T,
    ) -> (T, Vec<Vec<u8>>)
    where
        C: Sec1210MonotonicClockV2,
    {
        let (master, slave) = pty_pair();
        let master_guard = exchanges
            .iter()
            .all(|exchange| !exchange.response.is_empty())
            .then(|| master.try_clone().expect("fake reader master clone"));
        let server = thread::spawn(move || serve(master, exchanges));
        let mut transport = Sec1210TransportV2::new(PtyDescriptor(slave), clock);
        let result = client(&mut transport);
        drop(transport);
        drop(master_guard);
        let requests = server.join().expect("fake SEC1210 reader thread");
        (result, requests)
    }

    fn request(message_type: u8, sequence: u8, parameters: [u8; 3], payload: &[u8]) -> Vec<u8> {
        let mut frame = vec![0x03, 0x06, message_type];
        frame.extend_from_slice(&(payload.len() as u32).to_le_bytes());
        frame.extend_from_slice(&[0, sequence]);
        frame.extend_from_slice(&parameters);
        frame.extend_from_slice(payload);
        let checksum = frame.iter().fold(0u8, |value, byte| value ^ byte);
        frame.push(checksum);
        frame
    }

    fn initialization_exchanges() -> Vec<ServerExchange> {
        vec![
            ServerExchange {
                expected: request(0x65, 1, [0, 0, 0], &[]),
                response: response(0x81, 1, 1, 0, 1, &[]),
            },
            ServerExchange {
                expected: request(0x62, 2, [2, 0, 0], &[]),
                response: data(2, &ATR),
            },
            ServerExchange {
                expected: request(0x6c, 3, [0, 0, 0], &[]),
                response: response(0x82, 3, 0, 0, 1, &GET_PARAMETERS),
            },
            ServerExchange {
                expected: request(0x61, 4, [1, 0, 0], &SET_PARAMETERS),
                response: response(0x82, 4, 0, 0, 1, &SET_PARAMETERS),
            },
            ServerExchange {
                expected: request(0x6f, 5, [0, 0, 0], &[0, 0xc1, 1, 0xfe, 0x3e]),
                response: data(5, &IFS_RESPONSE),
            },
        ]
    }

    #[cfg(feature = "normal-process")]
    fn fixture_fields() -> BTreeMap<&'static str, &'static str> {
        QKDV_FIXTURE
            .lines()
            .filter(|line| !line.is_empty() && !line.starts_with('#'))
            .map(|line| line.split_once(": ").expect("QKDV fixture field"))
            .collect()
    }

    #[cfg(feature = "normal-process")]
    fn normal_pairs() -> Vec<(Instruction, Vec<u8>, Vec<u8>)> {
        let fields = fixture_fields();
        [
            (Instruction::Select, "normal_select"),
            (Instruction::OpenSession, "normal_open"),
            (Instruction::GetInfo, "normal_info"),
            (Instruction::ReadDChunk, "normal_read_1_0"),
            (Instruction::ReadDChunk, "normal_read_1_192"),
            (Instruction::ReadDChunk, "normal_read_2_0"),
            (Instruction::ReadDChunk, "normal_read_2_192"),
            (Instruction::ExportA2, "normal_a2"),
        ]
        .into_iter()
        .map(|(instruction, prefix)| {
            let request_name = format!("{prefix}_request_hex");
            let response_name = format!("{prefix}_response_hex");
            (
                instruction,
                hex(fields[request_name.as_str()]),
                hex(fields[response_name.as_str()]),
            )
        })
        .collect()
    }

    #[cfg(feature = "normal-process")]
    fn oracle_pairs() -> Vec<(Vec<u8>, Vec<u8>)> {
        CCID_ORACLE
            .lines()
            .filter(|line| !line.is_empty() && !line.starts_with('#') && !line.starts_with("index"))
            .map(|line| {
                let fields = line.split('\t').collect::<Vec<_>>();
                assert_eq!(fields.len(), 5);
                (hex(fields[3]), hex(fields[4]))
            })
            .collect()
    }

    #[cfg(feature = "normal-process")]
    fn qkdv_body(capability: Capability, kind: MessageKind, sequence: u32, body: &[u8]) -> Vec<u8> {
        let mut encoded = vec![0u8; HEADER_BYTES + body.len()];
        let count = encode_frame(capability, kind, sequence, body, &mut encoded)
            .expect("QKDV fixture frame");
        encoded.truncate(count);
        let parsed = parse_frame(capability, &encoded).expect("QKDV fixture parse");
        match parsed.parsed_body().expect("QKDV fixture body") {
            BodyRef::CardApduRequest(value) | BodyRef::CardApduResponse(value) => value.to_vec(),
            _ => panic!("wrong QKDV card body"),
        }
    }

    #[cfg(feature = "normal-process")]
    #[test]
    fn linux_pty_pass_matches_qkdv_and_registered_ccid_application_boundaries() {
        let normal = normal_pairs();
        let oracle = oracle_pairs();
        assert_eq!(normal.len(), 8);
        assert_eq!(oracle.len(), 8);
        for index in [0usize, 2, 3, 4, 5, 6] {
            assert_eq!(normal[index].1, oracle[index].0, "request {index}");
        }
        for index in [0usize, 1, 3, 4, 5, 6] {
            assert_eq!(normal[index].2, oracle[index].1, "response {index}");
        }
        let mut normal_open = oracle[1].0.clone();
        normal_open[6] = 0x02;
        assert_eq!(normal_open, normal[1].1);
        let mut oracle_info = normal[2].2.clone();
        let info_mask_low = oracle_info.len() - 3;
        oracle_info[info_mask_low] = 0x07;
        assert_eq!(oracle_info, oracle[2].1);
        let mut oracle_a2_request = normal[7].1.clone();
        let purpose = oracle_a2_request.len() - 2;
        oracle_a2_request[purpose] = 0x01;
        assert_eq!(oracle_a2_request, oracle[7].0);
        let mut oracle_a2_response = normal[7].2.clone();
        oracle_a2_response[21] = 0x01;
        assert_eq!(oracle_a2_response, oracle[7].1);

        let mut exchanges = initialization_exchanges();
        for (index, (_, command, reply)) in normal.iter().enumerate() {
            let sequence = 6u8.wrapping_add(index as u8);
            exchanges.push(ServerExchange {
                expected: request(0x6f, sequence, [0, 0, 0], &t1_i((index & 1) as u8, command)),
                response: data(sequence, &t1_i((index & 1) as u8, reply)),
            });
        }
        let (responses, requests) = with_pty(exchanges, InstantClock::new(), |transport| {
            transport.initialize().expect("PTY initialization");
            let mut responses = Vec::new();
            for (index, (_, command, reply)) in normal.iter().enumerate() {
                assert_eq!(
                    qkdv_body(
                        Capability::CardRequest,
                        MessageKind::CardApduRequest,
                        index as u32 + 1,
                        command,
                    ),
                    *command
                );
                let accepted = transport.transmit_apdu(command).expect("PTY APDU");
                assert_eq!(accepted.bytes(), reply);
                assert_eq!(
                    qkdv_body(
                        Capability::CardResponse,
                        MessageKind::CardApduResponse,
                        index as u32 + 1,
                        accepted.bytes(),
                    ),
                    *reply
                );
                responses.push(accepted.bytes().to_vec());
            }
            assert_eq!(transport.controller_command_count(), 13);
            assert_eq!(transport.application_apdu_count(), 8);
            assert_eq!(transport.received_byte_count(), 1_192);
            assert_eq!(transport.event_count(), 0);
            assert_eq!(transport.failure(), None);
            responses
        });
        assert_eq!(requests.len(), 13);

        let info = CardInfoV1::try_from_response(
            parse_response(Instruction::GetInfo, &responses[2]).expect("typed INFO"),
        )
        .expect("owned INFO");
        let mut descriptors = [[0u8; DESCRIPTOR_BYTES]; 2];
        for (instruction, response) in [
            Instruction::ReadDChunk,
            Instruction::ReadDChunk,
            Instruction::ReadDChunk,
            Instruction::ReadDChunk,
        ]
        .into_iter()
        .zip(&responses[3..7])
        {
            let ResponseRef::ReadDChunk {
                selector,
                offset,
                bytes,
                ..
            } = parse_response(instruction, response).expect("typed descriptor")
            else {
                panic!("wrong descriptor response")
            };
            let descriptor = match selector {
                DescriptorSelector::Receive => &mut descriptors[0],
                DescriptorSelector::Change => &mut descriptors[1],
            };
            let start = usize::from(offset);
            descriptor[start..start + bytes.len()].copy_from_slice(bytes);
        }
        let ResponseRef::ExportA2 { a2, .. } =
            parse_response(Instruction::ExportA2, &responses[7]).expect("typed A2")
        else {
            panic!("wrong A2 response")
        };
        let mut a2 = *a2;
        let expected_wallet = info.wallet_id();
        let expected_xpub = fixture_fields()["account_xpub_text"].as_bytes();
        let bound =
            bind_normal_card_v1(NormalProfileV2::SimpleRecovery, info, descriptors, &mut a2)
                .expect("qk-core card facts");
        assert_eq!(bound.wallet_id().as_slice(), expected_wallet);
        assert_eq!(bound.account_xpub().as_slice(), expected_xpub);
        assert_eq!(bound.descriptors(), &descriptors);
        assert!(a2.iter().all(|byte| *byte == 0));
    }

    fn initialization_error(exchanges: Vec<ServerExchange>, expected: CardTransportErrorV2) {
        let (actual, _) = with_pty(exchanges, StepClock::ticking(), |transport| {
            transport.initialize()
        });
        assert_eq!(actual, Err(expected), "{}", expected.name());
    }

    #[test]
    fn linux_pty_wire_event_and_initialization_gate_families_are_named() {
        let mut cases = Vec::new();
        let mut checksum = response(0x81, 1, 1, 0, 1, &[]);
        *checksum.last_mut().expect("checksum") ^= 1;
        cases.push((
            vec![ServerExchange {
                expected: request(0x65, 1, [0, 0, 0], &[]),
                response: checksum,
            }],
            CardTransportErrorV2::Sec1210ChecksumRejected,
        ));
        cases.push((
            vec![ServerExchange {
                expected: request(0x65, 1, [0, 0, 0], &[]),
                response: vec![0x03, 0x15, 0x16],
            }],
            CardTransportErrorV2::Sec1210Nack,
        ));
        cases.push((
            vec![ServerExchange {
                expected: request(0x65, 1, [0, 0, 0], &[]),
                response: vec![0x50, 0x02],
            }],
            CardTransportErrorV2::Sec1210CardRemoved,
        ));

        let mut atr = initialization_exchanges();
        atr.truncate(2);
        atr[1].response = data(2, &[0x3f, 0x00]);
        cases.push((atr, CardTransportErrorV2::Sec1210AtrProfileRejected));
        let mut parameters = initialization_exchanges();
        parameters.truncate(3);
        let mut wrong_ifsc = GET_PARAMETERS;
        wrong_ifsc[5] = 0xff;
        parameters[2].response = response(0x82, 3, 0, 0, 1, &wrong_ifsc);
        cases.push((parameters, CardTransportErrorV2::Sec1210ParametersRejected));
        let mut set = initialization_exchanges();
        set.truncate(4);
        set[3].response = response(0x82, 4, 0, 0, 1, &GET_PARAMETERS);
        cases.push((set, CardTransportErrorV2::Sec1210SetParametersEchoRejected));
        let mut ifs = initialization_exchanges();
        ifs[4].response = data(5, &t1_control(0xe1, &[0xfd]));
        cases.push((ifs, CardTransportErrorV2::T1IfsRejected));

        for (exchanges, expected) in cases {
            initialization_error(exchanges, expected);
        }
    }

    #[test]
    fn linux_pty_t1_wtx_and_time_extension_families_are_named() {
        let mut checksum = t1_i(0, &[0x90, 0x00]);
        *checksum.last_mut().expect("T=1 checksum") ^= 1;
        for (block, expected) in [
            (checksum, CardTransportErrorV2::T1ChecksumRejected),
            (
                t1_control(0x80, &[]),
                CardTransportErrorV2::T1UnexpectedRBlock,
            ),
            (t1_wtx(25), CardTransportErrorV2::T1WtxMultiplierRejected),
            (
                t1_control(0x20, &[0x90, 0]),
                CardTransportErrorV2::T1ChainingRejected,
            ),
        ] {
            let mut exchanges = initialization_exchanges();
            exchanges.push(ServerExchange {
                expected: request(0x6f, 6, [0, 0, 0], &t1_i(0, &[0])),
                response: data(6, &block),
            });
            let (actual, _) = with_pty(exchanges, StepClock::ticking(), |transport| {
                transport.initialize().expect("PTY initialization");
                transport.transmit_apdu(&[0]).map(|_| ())
            });
            assert_eq!(actual, Err(expected), "{}", expected.name());
        }

        let mut exchanges = initialization_exchanges();
        let mut extensions = Vec::new();
        for _ in 0..9 {
            extensions.extend(response(0x80, 6, 0x80, 1, 0, &[]));
        }
        exchanges.push(ServerExchange {
            expected: request(0x6f, 6, [0, 0, 0], &t1_i(0, &[0])),
            response: extensions,
        });
        let (actual, _) = with_pty(exchanges, StepClock::ticking(), |transport| {
            transport.initialize().expect("PTY initialization");
            transport.transmit_apdu(&[0]).map(|_| ())
        });
        assert_eq!(
            actual,
            Err(CardTransportErrorV2::Sec1210TimeExtensionLimitExceeded)
        );
    }

    fn closed_first_exchange() -> Vec<ServerExchange> {
        vec![ServerExchange {
            expected: request(0x65, 1, [0, 0, 0], &[]),
            response: Vec::new(),
        }]
    }

    #[test]
    fn linux_pty_descriptor_and_deterministic_clock_boundaries_fail_closed() {
        for (values, expected) in [
            (
                vec![Ok(0), Ok(0), Ok(0), Ok(4_999)],
                CardTransportErrorV2::Sec1210DescriptorClosed,
            ),
            (
                vec![Ok(0), Ok(0), Ok(0), Ok(5_000)],
                CardTransportErrorV2::Sec1210DeadlineExceeded,
            ),
            (
                vec![Ok(2), Ok(2), Ok(2), Ok(1)],
                CardTransportErrorV2::Sec1210ClockRegression,
            ),
        ] {
            let (actual, requests) = with_pty(
                closed_first_exchange(),
                StepClock::scripted(values),
                |transport| transport.initialize(),
            );
            assert_eq!(actual, Err(expected), "{}", expected.name());
            assert_eq!(requests.len(), 1);
        }

        let (master, slave) = pty_pair();
        drop(master);
        let mut transport = Sec1210TransportV2::new(PtyDescriptor(slave), StepClock::ticking());
        assert_eq!(
            transport.initialize(),
            Err(CardTransportErrorV2::Sec1210DescriptorWriteFailed)
        );
        assert_eq!(
            transport.initialize(),
            Err(CardTransportErrorV2::Sec1210DescriptorWriteFailed),
            "first descriptor failure remains sticky"
        );
    }
}
