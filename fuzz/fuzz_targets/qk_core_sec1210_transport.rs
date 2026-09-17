#![no_main]
// Public synthetic inputs only. This target composes qk-core's production
// descriptor/clock loop with independently assembled SEC1210 and T=1 bytes;
// it opens no descriptor and performs no device, process, or card operation.

use libfuzzer_sys::fuzz_target;
use qk_core::{
    CardTransportErrorV2, Sec1210ClockErrorV2, Sec1210DescriptorErrorV2, Sec1210DescriptorReadV2,
    Sec1210DescriptorV2, Sec1210DescriptorWriteV2, Sec1210MonotonicClockV2, Sec1210TransportV2,
    QK_LIM_APDU_015_MAX_WTX_PER_APDU, QK_LIM_APDU_016_MAX_TIME_EXTENSIONS_PER_APDU,
    QK_LIM_APDU_017_MAX_CONTROLLER_COMMANDS, QK_LIM_APDU_018_MAX_RECEIVED_BYTES,
    QK_LIM_APDU_019_BASE_COMMAND_WAIT_MS,
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
const MAX_APPLICATION_APDUS: usize = 108;
const MAX_APPLICATION_COMMAND_BYTES: usize = 221;
const MAX_APPLICATION_RESPONSE_BYTES: usize = 218;
const MAX_EVENTS: usize = 64;
const BWT_MS: u64 = 1_190;

#[derive(Default)]
struct Trace {
    writes: Vec<Vec<u8>>,
    write_waits: Vec<u64>,
    read_waits: Vec<(usize, u64)>,
}

type SharedTrace = Rc<RefCell<Trace>>;

enum ReadStep {
    Bytes(Vec<u8>),
    TimedOut,
    End,
    Failed,
    Overreported(usize),
}

#[derive(Clone, Copy)]
enum WriteFault {
    None,
    Failed(usize),
    TimedOut(usize),
    Short(usize),
}

struct ScriptDescriptor {
    reads: VecDeque<ReadStep>,
    trace: SharedTrace,
    write_fault: WriteFault,
    write_ordinal: usize,
}

impl ScriptDescriptor {
    fn new(reads: Vec<ReadStep>, trace: SharedTrace, write_fault: WriteFault) -> Self {
        Self {
            reads: reads.into(),
            trace,
            write_fault,
            write_ordinal: 0,
        }
    }
}

impl Sec1210DescriptorV2 for ScriptDescriptor {
    fn write(
        &mut self,
        bytes: &[u8],
        maximum_wait_ms: u64,
    ) -> Result<Sec1210DescriptorWriteV2, Sec1210DescriptorErrorV2> {
        assert_production_request(bytes);
        self.write_ordinal = self.write_ordinal.saturating_add(1);
        {
            let mut trace = self.trace.borrow_mut();
            trace.writes.push(bytes.to_vec());
            trace.write_waits.push(maximum_wait_ms);
        }
        match self.write_fault {
            WriteFault::Failed(at) if at == self.write_ordinal => Err(Sec1210DescriptorErrorV2),
            WriteFault::TimedOut(at) if at == self.write_ordinal => {
                Ok(Sec1210DescriptorWriteV2::TimedOut)
            }
            WriteFault::Short(at) if at == self.write_ordinal => Ok(
                Sec1210DescriptorWriteV2::Bytes(bytes.len().saturating_sub(1)),
            ),
            _ => Ok(Sec1210DescriptorWriteV2::Bytes(bytes.len())),
        }
    }

    fn read(
        &mut self,
        output: &mut [u8],
        maximum_wait_ms: u64,
    ) -> Result<Sec1210DescriptorReadV2, Sec1210DescriptorErrorV2> {
        self.trace
            .borrow_mut()
            .read_waits
            .push((self.write_ordinal, maximum_wait_ms));
        match self.reads.pop_front().unwrap_or(ReadStep::End) {
            ReadStep::Bytes(bytes) => {
                if bytes.len() <= output.len() {
                    output[..bytes.len()].copy_from_slice(&bytes);
                }
                Ok(Sec1210DescriptorReadV2::Bytes(bytes.len()))
            }
            ReadStep::TimedOut => Ok(Sec1210DescriptorReadV2::TimedOut),
            ReadStep::End => Ok(Sec1210DescriptorReadV2::EndOfStream),
            ReadStep::Failed => Err(Sec1210DescriptorErrorV2),
            ReadStep::Overreported(extra) => Ok(Sec1210DescriptorReadV2::Bytes(
                output.len().saturating_add(extra.max(1)),
            )),
        }
    }
}

#[derive(Clone, Copy, Default)]
struct ClockPlan {
    fail_at: usize,
    regress_at: usize,
    jump_at: usize,
    jump_ms: u64,
    tick_ms: u64,
}

struct ScriptClock {
    now: u64,
    calls: usize,
    plan: ClockPlan,
}

impl ScriptClock {
    fn new(plan: ClockPlan) -> Self {
        Self {
            now: 10,
            calls: 0,
            plan,
        }
    }
}

impl Sec1210MonotonicClockV2 for ScriptClock {
    fn now_ms(&mut self) -> Result<u64, Sec1210ClockErrorV2> {
        self.calls = self.calls.saturating_add(1);
        if self.plan.fail_at == self.calls {
            return Err(Sec1210ClockErrorV2);
        }
        if self.plan.jump_at == self.calls {
            self.now = self.now.saturating_add(self.plan.jump_ms);
        }
        if self.plan.regress_at == self.calls {
            let value = self.now.saturating_sub(2);
            self.now = value.saturating_add(self.plan.tick_ms);
            return Ok(value);
        }
        let value = self.now;
        self.now = self.now.saturating_add(self.plan.tick_ms);
        Ok(value)
    }
}

struct Cursor<'a> {
    bytes: &'a [u8],
    at: usize,
}

impl<'a> Cursor<'a> {
    fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, at: 0 }
    }

    fn byte(&mut self) -> u8 {
        let value = self.bytes.get(self.at).copied().unwrap_or(0);
        self.at = self.at.saturating_add(1);
        value
    }

    fn bounded(&mut self, bound: usize) -> usize {
        if bound == 0 {
            return 0;
        }
        usize::from(self.byte()) % bound
    }

    fn remaining(&self) -> &'a [u8] {
        self.bytes.get(self.at..).unwrap_or(&[])
    }
}

fn xor(bytes: &[u8]) -> u8 {
    bytes.iter().fold(0, |value, byte| value ^ byte)
}

// Independent batch builders: no qk-sec1210-wire encoder or qk-t1 block
// constructor is used by this target.
fn ccid_response(
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
    frame.push(xor(&frame));
    frame
}

fn ccid_request(message_type: u8, sequence: u8, parameter: u8, payload: &[u8]) -> Vec<u8> {
    let mut frame = vec![0x03, 0x06, message_type];
    frame.extend_from_slice(&(payload.len() as u32).to_le_bytes());
    frame.extend_from_slice(&[0, sequence, parameter, 0, 0]);
    frame.extend_from_slice(payload);
    frame.push(xor(&frame));
    frame
}

fn data_block(sequence: u8, payload: &[u8]) -> Vec<u8> {
    ccid_response(0x80, sequence, 0, 0, 0, payload)
}

fn t1_block(pcb: u8, payload: &[u8]) -> Vec<u8> {
    let mut block = vec![0, pcb, payload.len() as u8];
    block.extend_from_slice(payload);
    block.push(xor(&block));
    block
}

fn t1_i(sequence: u8, payload: &[u8]) -> Vec<u8> {
    t1_block((sequence & 1) << 6, payload)
}

fn t1_wtx(multiplier: u8) -> Vec<u8> {
    t1_block(0xc3, &[multiplier])
}

fn time_extension(sequence: u8, multiplier: u8) -> Vec<u8> {
    ccid_response(0x80, sequence, 0x80, multiplier, 0, &[])
}

fn fix_checksum(frame: &mut [u8]) {
    if frame.is_empty() {
        return;
    }
    let last = frame.len() - 1;
    frame[last] = xor(&frame[..last]);
}

fn assert_production_request(frame: &[u8]) {
    assert!(frame.len() >= 13);
    assert_eq!(&frame[..2], &[0x03, 0x06]);
    let declared = u32::from_le_bytes(frame[3..7].try_into().expect("fixed request header"));
    let declared = usize::try_from(declared).expect("request length fits usize");
    assert!(declared <= 254);
    assert_eq!(frame.len(), 13usize.saturating_add(declared));
    assert_eq!(frame[7], 0);
    assert!(matches!(frame[2], 0x61 | 0x62 | 0x65 | 0x6c | 0x6f));
    assert_eq!(xor(frame), 0);
}

fn setup_requests() -> Vec<Vec<u8>> {
    vec![
        ccid_request(0x65, 1, 0, &[]),
        ccid_request(0x62, 2, 2, &[]),
        ccid_request(0x6c, 3, 0, &[]),
        ccid_request(0x61, 4, 1, &SET_PARAMETERS),
        ccid_request(0x6f, 5, 0, &[0, 0xc1, 1, 0xfe, 0x3e]),
    ]
}

fn assert_setup_write_prefix(trace: &SharedTrace) {
    let trace = trace.borrow();
    for (actual, expected) in trace.writes.iter().zip(setup_requests()) {
        assert_eq!(actual, &expected);
    }
}

fn assert_exact_setup_writes(trace: &SharedTrace) {
    assert_eq!(trace.borrow().writes, setup_requests());
}

fn assert_tick_one_command_waits(trace: &SharedTrace, ordinal: usize, write_wait_ms: u64) {
    let trace = trace.borrow();
    assert_eq!(trace.write_waits[ordinal - 1], write_wait_ms);
    let waits = trace
        .read_waits
        .iter()
        .filter_map(|(command, wait)| (*command == ordinal).then_some(*wait))
        .collect::<Vec<_>>();
    assert!(!waits.is_empty());
    assert_eq!(waits[0], write_wait_ms - 2);
    for pair in waits.windows(2) {
        assert_eq!(pair[0] - pair[1], 2);
    }
}

fn assert_tick_one_setup_waits(trace: &SharedTrace) {
    for ordinal in 1..=5 {
        let write_wait_ms = if ordinal == 5 {
            QK_LIM_APDU_019_BASE_COMMAND_WAIT_MS - 1
        } else {
            QK_LIM_APDU_019_BASE_COMMAND_WAIT_MS
        };
        assert_tick_one_command_waits(trace, ordinal, write_wait_ms);
    }
}

fn expected_apdu_request(sequence: u8, send_sequence: u8, bwi: u8, command: &[u8]) -> Vec<u8> {
    ccid_request(0x6f, sequence, bwi, &t1_i(send_sequence, command))
}

fn expected_wtx_response(sequence: u8, multiplier: u8) -> Vec<u8> {
    ccid_request(0x6f, sequence, multiplier, &t1_block(0xe3, &[multiplier]))
}

fn setup_frames() -> Vec<Vec<u8>> {
    vec![
        ccid_response(0x81, 1, 1, 0, 1, &[]),
        data_block(2, &ATR),
        ccid_response(0x82, 3, 0, 0, 1, &GET_PARAMETERS),
        ccid_response(0x82, 4, 0, 0, 1, &SET_PARAMETERS),
        data_block(5, &IFS_RESPONSE),
    ]
}

fn push_fragmented(reads: &mut Vec<ReadStep>, frame: &[u8], width: usize) {
    for chunk in frame.chunks(width.max(1)) {
        reads.push(ReadStep::Bytes(chunk.to_vec()));
    }
}

fn setup_reads(width: usize) -> Vec<ReadStep> {
    let mut reads = Vec::new();
    for frame in setup_frames() {
        push_fragmented(&mut reads, &frame, width);
    }
    reads
}

fn make_transport(
    reads: Vec<ReadStep>,
    write_fault: WriteFault,
    clock_plan: ClockPlan,
) -> (
    Sec1210TransportV2<ScriptDescriptor, ScriptClock>,
    SharedTrace,
) {
    let trace = Rc::new(RefCell::new(Trace::default()));
    let descriptor = ScriptDescriptor::new(reads, trace.clone(), write_fault);
    (
        Sec1210TransportV2::new(descriptor, ScriptClock::new(clock_plan)),
        trace,
    )
}

fn audit(
    transport: &mut Sec1210TransportV2<ScriptDescriptor, ScriptClock>,
    trace: &SharedTrace,
    outcome: Result<(), CardTransportErrorV2>,
) {
    assert!(transport.controller_command_count() <= QK_LIM_APDU_017_MAX_CONTROLLER_COMMANDS);
    assert!(transport.received_byte_count() <= QK_LIM_APDU_018_MAX_RECEIVED_BYTES);
    assert!(transport.event_count() <= MAX_EVENTS);
    assert!(transport.application_apdu_count() <= MAX_APPLICATION_APDUS);
    let active_apdus = transport.application_apdu_count().saturating_add(1);
    assert!(transport.wtx_count() <= active_apdus.saturating_mul(QK_LIM_APDU_015_MAX_WTX_PER_APDU));
    assert!(
        transport.reader_time_extension_count()
            <= active_apdus.saturating_mul(QK_LIM_APDU_016_MAX_TIME_EXTENSIONS_PER_APDU)
    );
    for request in &trace.borrow().writes {
        assert_production_request(request);
    }

    match outcome {
        Ok(()) => {
            assert_eq!(transport.failure(), None);
            let writes = trace.borrow().writes.len();
            transport.reset();
            assert_eq!(transport.failure(), None);
            assert_eq!(transport.controller_command_count(), 0);
            assert_eq!(transport.received_byte_count(), 0);
            assert_eq!(transport.event_count(), 0);
            assert_eq!(transport.application_apdu_count(), 0);
            assert_eq!(transport.wtx_count(), 0);
            assert_eq!(transport.reader_time_extension_count(), 0);
            assert_eq!(trace.borrow().writes.len(), writes);
        }
        Err(first) => {
            assert_eq!(transport.failure(), Some(first));
            assert!(first.name().is_ascii());
            assert!(!first.name().contains(':'));
            assert_eq!(format!("{first:?}"), first.name());
            let writes = trace.borrow().writes.len();
            assert_eq!(transport.initialize(), Err(first));
            assert_eq!(transport.transmit_apdu(&[0]).err(), Some(first));
            assert_eq!(trace.borrow().writes.len(), writes);
            transport.reset();
            assert_eq!(transport.failure(), Some(first));
            assert_eq!(transport.controller_command_count(), 0);
            assert_eq!(transport.received_byte_count(), 0);
            assert_eq!(transport.event_count(), 0);
            assert_eq!(transport.application_apdu_count(), 0);
            assert_eq!(transport.initialize(), Err(first));
            assert_eq!(trace.borrow().writes.len(), writes);
        }
    }
}

#[derive(Clone, Copy)]
enum ExpectedOutcome<'a> {
    Success(&'a [u8]),
    Failure(CardTransportErrorV2),
    Unconstrained,
}

fn setup_write_failure(fault: WriteFault) -> Option<(usize, CardTransportErrorV2)> {
    match fault {
        WriteFault::Failed(ordinal) if ordinal <= 5 => {
            Some((ordinal, CardTransportErrorV2::Sec1210DescriptorWriteFailed))
        }
        WriteFault::TimedOut(ordinal) if ordinal <= 5 => {
            Some((ordinal, CardTransportErrorV2::Sec1210DeadlineExceeded))
        }
        WriteFault::Short(ordinal) if ordinal <= 5 => {
            Some((ordinal, CardTransportErrorV2::Sec1210PartialWrite))
        }
        _ => None,
    }
}

fn setup_read_failure(kind: u8, read_at: usize) -> Option<(usize, CardTransportErrorV2)> {
    if read_at >= 5 || kind == 0 {
        return None;
    }
    let error = match kind {
        1 => CardTransportErrorV2::Sec1210DeadlineExceeded,
        2 | 4 => CardTransportErrorV2::Sec1210DescriptorClosed,
        3 | 5 => CardTransportErrorV2::Sec1210DescriptorReadFailed,
        _ => unreachable!("bounded read fault selector"),
    };
    Some((read_at + 1, error))
}

fn first_failure(
    write: Option<(usize, CardTransportErrorV2)>,
    read: Option<(usize, CardTransportErrorV2)>,
) -> Option<(usize, CardTransportErrorV2)> {
    match (write, read) {
        (Some(write), Some(read)) => Some(if write.0 <= read.0 { write } else { read }),
        (Some(write), None) => Some(write),
        (None, Some(read)) => Some(read),
        (None, None) => None,
    }
}

fn assert_expected(outcome: Result<(), CardTransportErrorV2>, expected: ExpectedOutcome<'_>) {
    match expected {
        ExpectedOutcome::Success(_) => assert_eq!(outcome, Ok(())),
        ExpectedOutcome::Failure(error) => assert_eq!(outcome, Err(error)),
        ExpectedOutcome::Unconstrained => {}
    }
}

fn initialize_then_one(
    reads: Vec<ReadStep>,
    write_fault: WriteFault,
    clock_plan: ClockPlan,
    command: &[u8],
    expected: ExpectedOutcome<'_>,
) {
    let (mut transport, trace) = make_transport(reads, write_fault, clock_plan);
    let outcome = match transport.initialize() {
        Err(error) => Err(error),
        Ok(()) => {
            assert_exact_setup_writes(&trace);
            match transport.transmit_apdu(command) {
                Ok(response) => {
                    if let ExpectedOutcome::Success(expected) = expected {
                        assert_eq!(response.bytes(), expected);
                    }
                    Ok(())
                }
                Err(error) => Err(error),
            }
        }
    };
    assert_expected(outcome, expected);
    if trace.borrow().writes.len() > 5 && !command.is_empty() {
        assert_eq!(
            trace.borrow().writes[5],
            expected_apdu_request(6, 0, 0, command)
        );
    }
    if clock_plan.tick_ms == 1
        && clock_plan.fail_at == 0
        && clock_plan.regress_at == 0
        && clock_plan.jump_at == 0
    {
        assert_tick_one_setup_waits(&trace);
        if trace.borrow().writes.len() > 5 {
            assert_tick_one_command_waits(&trace, 6, QK_LIM_APDU_019_BASE_COMMAND_WAIT_MS);
        }
    } else if clock_plan.fail_at == 1 {
        assert!(trace.borrow().write_waits.is_empty());
        assert!(trace.borrow().read_waits.is_empty());
    } else if clock_plan.regress_at == 2 || clock_plan.jump_at == 2 {
        assert_eq!(
            trace.borrow().write_waits,
            [QK_LIM_APDU_019_BASE_COMMAND_WAIT_MS]
        );
        assert!(trace.borrow().read_waits.is_empty());
    }
    audit(&mut transport, &trace, outcome);
}

fn raw_steps(input: &[u8]) -> Vec<ReadStep> {
    let mut cursor = Cursor::new(input);
    let mut reads = Vec::new();
    while cursor.at < input.len() && reads.len() < 512 {
        let tag = cursor.byte();
        match tag {
            0 => reads.push(ReadStep::TimedOut),
            1 => reads.push(ReadStep::End),
            2 => reads.push(ReadStep::Failed),
            3 => reads.push(ReadStep::Bytes(Vec::new())),
            4 => reads.push(ReadStep::Overreported(usize::from(cursor.byte()).max(1))),
            _ => {
                let wanted = 1 + usize::from(tag % 64);
                let available = input.len().saturating_sub(cursor.at);
                let take = wanted.min(available);
                let bytes = input[cursor.at..cursor.at.saturating_add(take)].to_vec();
                cursor.at = cursor.at.saturating_add(take);
                reads.push(ReadStep::Bytes(bytes));
            }
        }
    }
    reads
}

fn raw_lane(input: &[u8]) {
    let mut cursor = Cursor::new(input);
    let fault_kind = cursor.byte() % 4;
    let at = 1 + cursor.bounded(8);
    let write_fault = match fault_kind {
        1 => WriteFault::Failed(at),
        2 => WriteFault::TimedOut(at),
        3 => WriteFault::Short(at),
        _ => WriteFault::None,
    };
    let raw = cursor.remaining();
    let predictable_read_error = match raw.first().copied() {
        None | Some(1 | 3) => Some(CardTransportErrorV2::Sec1210DescriptorClosed),
        Some(0) => Some(CardTransportErrorV2::Sec1210DeadlineExceeded),
        Some(2 | 4) => Some(CardTransportErrorV2::Sec1210DescriptorReadFailed),
        Some(_) if raw.len() == 1 => Some(CardTransportErrorV2::Sec1210DescriptorClosed),
        Some(_) => None,
    };
    let reads = raw_steps(raw);
    let (mut transport, trace) = make_transport(reads, write_fault, ClockPlan::default());
    let outcome = transport.initialize();
    if let Some((_, expected)) =
        setup_write_failure(write_fault).filter(|(ordinal, _)| *ordinal == 1)
    {
        assert_eq!(outcome, Err(expected));
    } else if let Some(expected) = predictable_read_error {
        assert_eq!(outcome, Err(expected));
    }
    audit(&mut transport, &trace, outcome);
}

fn initialization_lane(input: &[u8]) {
    let mut cursor = Cursor::new(input);
    let width = 1 + cursor.bounded(32);
    let mut frames = setup_frames();
    let chosen = cursor.bounded(frames.len());
    let mutation = cursor.byte() % 11;
    let frame = &mut frames[chosen];
    let expected = match mutation {
        0 => ExpectedOutcome::Success(&[]),
        1 => {
            if let Some(last) = frame.last_mut() {
                *last ^= 1;
            }
            ExpectedOutcome::Failure(CardTransportErrorV2::Sec1210ChecksumRejected)
        }
        2 => {
            frame[0] = 4;
            ExpectedOutcome::Failure(CardTransportErrorV2::Sec1210PrefixRejected)
        }
        3 => {
            frame[3..7].copy_from_slice(&u32::MAX.to_le_bytes());
            ExpectedOutcome::Failure(CardTransportErrorV2::Sec1210LengthExceeded)
        }
        4 => {
            frame[7] = 1;
            fix_checksum(frame);
            ExpectedOutcome::Failure(CardTransportErrorV2::Sec1210SlotRejected)
        }
        5 => {
            frame[8] = (chosen as u8).wrapping_add(2);
            fix_checksum(frame);
            ExpectedOutcome::Failure(CardTransportErrorV2::Sec1210SequenceRejected)
        }
        6 => {
            frame[9] = 3;
            fix_checksum(frame);
            ExpectedOutcome::Failure(CardTransportErrorV2::Sec1210StatusReserved)
        }
        7 => {
            frame[10] = 1;
            fix_checksum(frame);
            ExpectedOutcome::Failure(CardTransportErrorV2::Sec1210StatusErrorRejected)
        }
        8 => {
            frame[2] = match frame[2] {
                0x80 => 0x81,
                _ => 0x80,
            };
            fix_checksum(frame);
            ExpectedOutcome::Failure(CardTransportErrorV2::Sec1210ResponseTypeRejected)
        }
        9 => {
            *frame = vec![0x03, 0x15, 0x16];
            ExpectedOutcome::Failure(CardTransportErrorV2::Sec1210Nack)
        }
        _ => {
            frame.pop();
            ExpectedOutcome::Failure(CardTransportErrorV2::Sec1210Truncated)
        }
    };
    let mut reads = Vec::new();
    let frame_count = if mutation == 0 {
        frames.len()
    } else {
        chosen.saturating_add(1)
    };
    for frame in frames.into_iter().take(frame_count) {
        push_fragmented(&mut reads, &frame, width);
    }
    if mutation != 0 {
        reads.push(ReadStep::End);
    }
    let (mut transport, trace) = make_transport(
        reads,
        WriteFault::None,
        ClockPlan {
            tick_ms: 1,
            ..ClockPlan::default()
        },
    );
    let outcome = transport.initialize();
    assert_expected(outcome, expected);
    if outcome.is_ok() {
        assert_exact_setup_writes(&trace);
        assert_tick_one_setup_waits(&trace);
    } else {
        assert_setup_write_prefix(&trace);
    }
    audit(&mut transport, &trace, outcome);
}

fn apdu_lane(input: &[u8]) {
    let mut cursor = Cursor::new(input);
    let width = 1 + cursor.bounded(32);
    let command_mode = cursor.byte() % 5;
    let command_len = match command_mode {
        0 => 0,
        1 => MAX_APPLICATION_COMMAND_BYTES + 1,
        2 => MAX_APPLICATION_COMMAND_BYTES,
        _ => 1 + cursor.bounded(MAX_APPLICATION_COMMAND_BYTES),
    };
    let command = (0..command_len)
        .map(|index| cursor.byte().wrapping_add(index as u8))
        .collect::<Vec<_>>();
    let response_mode = cursor.byte() % 8;
    let response_len = match response_mode {
        0 => 0,
        1 => MAX_APPLICATION_RESPONSE_BYTES + 1,
        2 => MAX_APPLICATION_RESPONSE_BYTES,
        _ => 1 + cursor.bounded(MAX_APPLICATION_RESPONSE_BYTES),
    };
    let response = (0..response_len)
        .map(|index| cursor.byte().wrapping_add(index as u8))
        .collect::<Vec<_>>();
    let mut block = t1_i(0, &response);
    match response_mode {
        3 => *block.last_mut().unwrap_or(&mut 0) ^= 1,
        4 => {
            block[0] = 1;
            fix_checksum(&mut block);
        }
        5 => block = t1_block(0x80, &[]),
        6 => block = t1_block(0x20, &response),
        _ => {}
    }
    let mut reads = setup_reads(width);
    push_fragmented(&mut reads, &data_block(6, &block), width);
    let expected = if command_len == 0 || command_len > MAX_APPLICATION_COMMAND_BYTES {
        ExpectedOutcome::Failure(CardTransportErrorV2::Sec1210ApplicationCommandLengthRejected)
    } else {
        match response_mode {
            1 => ExpectedOutcome::Failure(
                CardTransportErrorV2::Sec1210ApplicationResponseLengthRejected,
            ),
            3 => ExpectedOutcome::Failure(CardTransportErrorV2::T1ChecksumRejected),
            4 => ExpectedOutcome::Failure(CardTransportErrorV2::T1NadRejected),
            5 => ExpectedOutcome::Failure(CardTransportErrorV2::T1UnexpectedRBlock),
            6 => ExpectedOutcome::Failure(CardTransportErrorV2::T1ChainingRejected),
            _ => ExpectedOutcome::Success(response.as_slice()),
        }
    };
    initialize_then_one(
        reads,
        WriteFault::None,
        ClockPlan {
            tick_ms: 1,
            ..ClockPlan::default()
        },
        &command,
        expected,
    );
}

fn control_lane(input: &[u8]) {
    let mut cursor = Cursor::new(input);
    let width = 1 + cursor.bounded(48);
    let extensions = cursor.bounded(10);
    let wtx_count = cursor.bounded(10);
    let malformed_extension = cursor.byte() % 3;
    let mut reads = setup_reads(width);
    let mut sequence = 6u8;
    for ordinal in 0..extensions {
        let extension = if ordinal == 0 && malformed_extension == 1 {
            ccid_response(0x80, sequence, 0x80, cursor.byte(), 0, &[0])
        } else if ordinal == 0 && malformed_extension == 2 {
            ccid_response(0x80, sequence, 0x80, cursor.byte(), 1, &[])
        } else {
            time_extension(sequence, cursor.byte())
        };
        push_fragmented(&mut reads, &extension, width);
    }
    let mut multipliers = Vec::new();
    for ordinal in 0..wtx_count {
        let multiplier = cursor.byte() % 27;
        multipliers.push(multiplier);
        push_fragmented(
            &mut reads,
            &data_block(sequence, &t1_wtx(multiplier)),
            width,
        );
        if multiplier == 0 || multiplier > 24 || ordinal >= 8 {
            break;
        }
        sequence = sequence.wrapping_add(1);
    }
    let response = [cursor.byte(), cursor.byte()];
    push_fragmented(
        &mut reads,
        &data_block(sequence, &t1_i(0, &response)),
        width,
    );
    let expected = if extensions != 0 && malformed_extension != 0 {
        ExpectedOutcome::Failure(CardTransportErrorV2::Sec1210TimeExtensionShapeRejected)
    } else if extensions > QK_LIM_APDU_016_MAX_TIME_EXTENSIONS_PER_APDU {
        ExpectedOutcome::Failure(CardTransportErrorV2::Sec1210TimeExtensionLimitExceeded)
    } else if let Some((ordinal, multiplier)) = multipliers
        .iter()
        .copied()
        .enumerate()
        .find(|(ordinal, multiplier)| !(1..=24).contains(multiplier) || *ordinal >= 8)
    {
        if !(1..=24).contains(&multiplier) {
            ExpectedOutcome::Failure(CardTransportErrorV2::T1WtxMultiplierRejected)
        } else if ordinal >= QK_LIM_APDU_015_MAX_WTX_PER_APDU {
            ExpectedOutcome::Failure(CardTransportErrorV2::T1WtxLimitExceeded)
        } else {
            ExpectedOutcome::Unconstrained
        }
    } else {
        ExpectedOutcome::Success(response.as_slice())
    };
    let (mut transport, trace) = make_transport(
        reads,
        WriteFault::None,
        ClockPlan {
            tick_ms: 1,
            ..ClockPlan::default()
        },
    );
    let outcome = match transport.initialize() {
        Err(error) => Err(error),
        Ok(()) => match transport.transmit_apdu(&[0]) {
            Ok(actual) => {
                if let ExpectedOutcome::Success(expected) = expected {
                    assert_eq!(actual.bytes(), expected);
                }
                Ok(())
            }
            Err(error) => Err(error),
        },
    };
    assert_expected(outcome, expected);
    assert_setup_write_prefix(&trace);
    assert_tick_one_setup_waits(&trace);
    if trace.borrow().writes.len() > 5 {
        assert_eq!(
            trace.borrow().writes[5],
            expected_apdu_request(6, 0, 0, &[0])
        );
        assert_tick_one_command_waits(&trace, 6, QK_LIM_APDU_019_BASE_COMMAND_WAIT_MS);
    }
    let accepted_wtx = if extensions > QK_LIM_APDU_016_MAX_TIME_EXTENSIONS_PER_APDU
        || (extensions != 0 && malformed_extension != 0)
    {
        0
    } else {
        multipliers
            .iter()
            .copied()
            .take(QK_LIM_APDU_015_MAX_WTX_PER_APDU)
            .take_while(|multiplier| (1..=24).contains(multiplier))
            .count()
    };
    let accepted_extensions = if extensions != 0 && malformed_extension != 0 {
        0
    } else {
        extensions.min(QK_LIM_APDU_016_MAX_TIME_EXTENSIONS_PER_APDU)
    };
    assert_eq!(transport.reader_time_extension_count(), accepted_extensions);
    assert_eq!(transport.wtx_count(), accepted_wtx);
    assert_eq!(trace.borrow().writes.len(), 6 + accepted_wtx);
    for (ordinal, multiplier) in multipliers.iter().copied().take(accepted_wtx).enumerate() {
        assert_eq!(
            trace.borrow().writes[6 + ordinal],
            expected_wtx_response(7u8.wrapping_add(ordinal as u8), multiplier)
        );
        assert_eq!(trace.borrow().writes[6 + ordinal][9], multiplier);
        assert_tick_one_command_waits(
            &trace,
            7 + ordinal,
            QK_LIM_APDU_019_BASE_COMMAND_WAIT_MS.max(u64::from(multiplier) * BWT_MS),
        );
    }
    audit(&mut transport, &trace, outcome);
}

fn event_lane(input: &[u8]) {
    let mut cursor = Cursor::new(input);
    let event_kind = cursor.byte() % 5;
    let count = cursor.bounded(66);
    let mut first = Vec::new();
    for ordinal in 0..count {
        match event_kind {
            0 => first.extend_from_slice(&[0x50, 0x03]),
            1 => first.extend_from_slice(&[0x50, 0x02]),
            2 => first.extend_from_slice(&[0x50, 0xf1]),
            3 => first.extend_from_slice(&[0x51, 0, 1, cursor.byte()]),
            _ => first.extend_from_slice(&[0x51, u8::from(ordinal != 0), 1, cursor.byte()]),
        }
    }
    first.extend(ccid_response(0x81, 1, 1, 0, 1, &[]));
    let mut reads = vec![ReadStep::Bytes(first)];
    for frame in setup_frames().into_iter().skip(1) {
        reads.push(ReadStep::Bytes(frame));
    }
    let (mut transport, trace) = make_transport(
        reads,
        WriteFault::None,
        ClockPlan {
            tick_ms: 1,
            ..ClockPlan::default()
        },
    );
    let outcome = transport.initialize();
    let expected = if count == 0 || (event_kind == 0 && count <= MAX_EVENTS) {
        ExpectedOutcome::Success(&[])
    } else {
        ExpectedOutcome::Failure(match event_kind {
            0 => CardTransportErrorV2::Sec1210EventLimitExceeded,
            1 => CardTransportErrorV2::Sec1210CardRemoved,
            2 => CardTransportErrorV2::Sec1210EventBitmapRejected,
            _ => CardTransportErrorV2::Sec1210HardwareError,
        })
    };
    assert_expected(outcome, expected);
    if outcome.is_ok() {
        assert_exact_setup_writes(&trace);
    } else {
        assert_setup_write_prefix(&trace);
    }
    audit(&mut transport, &trace, outcome);
}

fn descriptor_lane(input: &[u8]) {
    let mut cursor = Cursor::new(input);
    let write_kind = cursor.byte() % 4;
    let write_at = 1 + cursor.bounded(6);
    let write_fault = match write_kind {
        1 => WriteFault::Failed(write_at),
        2 => WriteFault::TimedOut(write_at),
        3 => WriteFault::Short(write_at),
        _ => WriteFault::None,
    };
    let mut reads = setup_reads(274);
    let read_at = cursor.bounded(reads.len().saturating_add(1));
    let read_kind = cursor.byte() % 6;
    let read_fault = match read_kind {
        0 => None,
        1 => Some(ReadStep::TimedOut),
        2 => Some(ReadStep::End),
        3 => Some(ReadStep::Failed),
        4 => Some(ReadStep::Bytes(Vec::new())),
        _ => Some(ReadStep::Overreported(1 + cursor.bounded(255))),
    };
    if let Some(fault) = read_fault {
        if read_at < reads.len() {
            reads[read_at] = fault;
        } else {
            reads.push(fault);
        }
    }
    let (mut transport, trace) = make_transport(
        reads,
        write_fault,
        ClockPlan {
            tick_ms: 1,
            ..ClockPlan::default()
        },
    );
    let outcome = transport.initialize();
    let expected = first_failure(
        setup_write_failure(write_fault),
        setup_read_failure(read_kind, read_at),
    );
    match expected {
        Some((ordinal, error)) => {
            assert_eq!(outcome, Err(error));
            assert_eq!(trace.borrow().writes.len(), ordinal);
            assert_setup_write_prefix(&trace);
        }
        None => {
            assert_eq!(outcome, Ok(()));
            assert_exact_setup_writes(&trace);
        }
    }
    audit(&mut transport, &trace, outcome);
}

fn clock_lane(input: &[u8]) {
    let mut cursor = Cursor::new(input);
    let kind = cursor.byte() % 5;
    if kind == 4 {
        absolute_deadline_lane();
        return;
    }
    let response = [0x90, 0x00];
    let (plan, expected) = match kind {
        0 => (
            ClockPlan {
                tick_ms: 1,
                ..ClockPlan::default()
            },
            ExpectedOutcome::Success(&response),
        ),
        1 => (
            ClockPlan {
                fail_at: 1,
                ..ClockPlan::default()
            },
            ExpectedOutcome::Failure(CardTransportErrorV2::Sec1210ClockFailed),
        ),
        2 => (
            ClockPlan {
                regress_at: 2,
                ..ClockPlan::default()
            },
            ExpectedOutcome::Failure(CardTransportErrorV2::Sec1210ClockRegression),
        ),
        _ => (
            ClockPlan {
                jump_at: 2,
                jump_ms: 5_000,
                ..ClockPlan::default()
            },
            ExpectedOutcome::Failure(CardTransportErrorV2::Sec1210DeadlineExceeded),
        ),
    };
    let mut reads = setup_reads(17);
    push_fragmented(&mut reads, &data_block(6, &t1_i(0, &response)), 17);
    initialize_then_one(reads, WriteFault::None, plan, &[cursor.byte()], expected);
}

fn absolute_deadline_lane() {
    let response = [0x90, 0x00];
    let mut reads = setup_reads(274);
    reads.push(ReadStep::Bytes(data_block(6, &t1_wtx(24))));
    reads.push(ReadStep::Bytes(data_block(7, &t1_i(0, &response))));
    let (mut transport, trace) = make_transport(
        reads,
        WriteFault::None,
        ClockPlan {
            jump_at: 29,
            jump_ms: 2_000,
            ..ClockPlan::default()
        },
    );
    assert_eq!(transport.initialize(), Ok(()));
    assert_eq!(
        transport
            .transmit_apdu(&[0])
            .expect("one bounded WTX completes before the absolute deadline")
            .bytes(),
        response
    );
    assert_eq!(transport.wtx_count(), 1);
    assert_eq!(transport.reader_time_extension_count(), 0);
    assert_eq!(
        trace.borrow().write_waits,
        [5_000, 5_000, 5_000, 5_000, 5_000, 5_000, 28_000]
    );
    assert_eq!(
        trace.borrow().read_waits,
        [
            (1, 5_000),
            (2, 5_000),
            (3, 5_000),
            (4, 5_000),
            (5, 5_000),
            (6, 5_000),
            (7, 28_000),
        ]
    );
    assert_eq!(trace.borrow().writes[6], expected_wtx_response(7, 24));
    audit(&mut transport, &trace, Ok(()));
}

fn apdu_count_boundary() {
    let count = MAX_APPLICATION_APDUS;
    let mut reads = setup_reads(274);
    for index in 0..count {
        let sequence = (6usize.saturating_add(index)) as u8;
        reads.push(ReadStep::Bytes(data_block(
            sequence,
            &t1_i((index & 1) as u8, &[0x90, 0]),
        )));
    }
    let (mut transport, trace) = make_transport(
        reads,
        WriteFault::None,
        ClockPlan {
            tick_ms: 1,
            ..ClockPlan::default()
        },
    );
    assert_eq!(transport.initialize(), Ok(()));
    for _ in 0..count {
        let response = transport
            .transmit_apdu(&[0])
            .expect("the exact 108-APDU boundary is accepted");
        assert_eq!(response.bytes(), [0x90, 0]);
    }
    assert_eq!(transport.application_apdu_count(), MAX_APPLICATION_APDUS);
    assert_eq!(
        transport.controller_command_count(),
        5 + MAX_APPLICATION_APDUS
    );
    let mut expected = setup_requests();
    for index in 0..count {
        expected.push(expected_apdu_request(
            6u8.wrapping_add(index as u8),
            (index & 1) as u8,
            0,
            &[0],
        ));
    }
    assert_eq!(trace.borrow().writes.as_slice(), expected.as_slice());
    let outcome = transport.transmit_apdu(&[0]).map(|_| ());
    assert_eq!(
        outcome,
        Err(CardTransportErrorV2::Sec1210ApplicationApduLimitExceeded)
    );
    assert_eq!(trace.borrow().writes.len(), 5 + MAX_APPLICATION_APDUS);
    audit(&mut transport, &trace, outcome);
}

fn command_count_boundary() {
    let mut reads = setup_reads(274);
    let mut controller_sequence = 6u8;
    for application_sequence in 0..MAX_APPLICATION_APDUS {
        for _ in 0..QK_LIM_APDU_015_MAX_WTX_PER_APDU {
            reads.push(ReadStep::Bytes(data_block(controller_sequence, &t1_wtx(1))));
            controller_sequence = controller_sequence.wrapping_add(1);
        }
        reads.push(ReadStep::Bytes(data_block(
            controller_sequence,
            &t1_i((application_sequence & 1) as u8, &[0x90, 0]),
        )));
        controller_sequence = controller_sequence.wrapping_add(1);
    }
    let (mut transport, trace) = make_transport(
        reads,
        WriteFault::None,
        ClockPlan {
            tick_ms: 1,
            ..ClockPlan::default()
        },
    );
    assert_eq!(transport.initialize(), Ok(()));
    for _ in 0..MAX_APPLICATION_APDUS {
        let response = transport
            .transmit_apdu(&[0])
            .expect("the exact 977-command boundary is accepted");
        assert_eq!(response.bytes(), [0x90, 0]);
    }
    assert_eq!(
        transport.controller_command_count(),
        QK_LIM_APDU_017_MAX_CONTROLLER_COMMANDS
    );
    assert_eq!(transport.application_apdu_count(), MAX_APPLICATION_APDUS);
    assert_eq!(
        transport.wtx_count(),
        MAX_APPLICATION_APDUS * QK_LIM_APDU_015_MAX_WTX_PER_APDU
    );
    let mut expected = setup_requests();
    let mut sequence = 6u8;
    for application in 0..MAX_APPLICATION_APDUS {
        expected.push(expected_apdu_request(
            sequence,
            (application & 1) as u8,
            0,
            &[0],
        ));
        sequence = sequence.wrapping_add(1);
        for _ in 0..QK_LIM_APDU_015_MAX_WTX_PER_APDU {
            expected.push(expected_wtx_response(sequence, 1));
            sequence = sequence.wrapping_add(1);
        }
    }
    assert_eq!(trace.borrow().writes.as_slice(), expected.as_slice());
    let outcome = transport.transmit_apdu(&[0]).map(|_| ());
    assert_eq!(
        outcome,
        Err(CardTransportErrorV2::Sec1210SessionCommandLimitExceeded)
    );
    assert_eq!(
        trace.borrow().writes.len(),
        QK_LIM_APDU_017_MAX_CONTROLLER_COMMANDS
    );
    audit(&mut transport, &trace, outcome);
}

fn boundary_lane(input: &[u8]) {
    let mut cursor = Cursor::new(input);
    match cursor.byte() % 8 {
        0 => apdu_count_boundary(),
        1 => command_count_boundary(),
        2 => {
            let mut reads = setup_reads(274);
            reads.push(ReadStep::Bytes(data_block(
                6,
                &t1_i(0, &vec![0x5a; MAX_APPLICATION_RESPONSE_BYTES + 1]),
            )));
            initialize_then_one(
                reads,
                WriteFault::None,
                ClockPlan {
                    tick_ms: 1,
                    ..ClockPlan::default()
                },
                &[0],
                ExpectedOutcome::Failure(
                    CardTransportErrorV2::Sec1210ApplicationResponseLengthRejected,
                ),
            );
        }
        3 => {
            // One reader time extension with a payload is rejected by its
            // production name before any WTX or final response is consumed.
            control_lane(&[0, 1, 0, 1, 1, 0xaa, 0xbb]);
        }
        4 => event_lane(&[0, 64]),
        5 => event_lane(&[0, 65]),
        6 => control_lane(&[0, 0, 8, 0, 1, 1, 1, 1, 1, 1, 1, 1, 0xaa, 0xbb]),
        _ => control_lane(&[0, 0, 9, 0, 1, 1, 1, 1, 1, 1, 1, 1, 1, 0xaa, 0xbb]),
    }
}

fuzz_target!(|input: &[u8]| {
    let lane = input.first().copied().unwrap_or(0) % 8;
    let body = input.get(1..).unwrap_or(&[]);
    match lane {
        0 => raw_lane(body),
        1 => initialization_lane(body),
        2 => apdu_lane(body),
        3 => control_lane(body),
        4 => event_lane(body),
        5 => descriptor_lane(body),
        6 => clock_lane(body),
        _ => boundary_lane(body),
    }
});
