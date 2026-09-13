#![no_main]
// Public-input, in-memory reference checks only. No UART, clocks or subprocesses.
use libfuzzer_sys::fuzz_target;
use qk_sec1210_wire::{Command, Decoder, Error, Exchange, Message, Observation, Phase};
use qk_sec1210_wire::{
    ReadbackError as RE, ReadbackObservation as RO, ReadbackPhase as RP, ReadbackSession,
};

const ATR: [u8; 15] = [
    0x3b, 0xd5, 0x18, 0xff, 0x81, 0x91, 0xfe, 0x1f, 0xc3, 0x80, 0x73, 0xc8, 0x21, 0x10, 0x0a,
];

#[derive(Debug, PartialEq, Eq)]
enum Fact {
    Response(Vec<u8>),
    Bitmap(u8),
    Hardware(u8, u8, u8),
}

// Batch cursor oracle, independently expressed from the streaming codec.
// The only pre-checksum header interpretation is the untrusted bounded length.
fn next(bytes: &[u8]) -> Result<Option<(Fact, usize)>, Error> {
    if bytes.is_empty() {
        return Ok(None);
    }
    match bytes[0] {
        0x50 => Ok(bytes.get(1).map(|b| (Fact::Bitmap(*b), 2))),
        0x51 => Ok((bytes.len() >= 4).then(|| (Fact::Hardware(bytes[1], bytes[2], bytes[3]), 4))),
        3 => {
            if bytes.len() < 2 {
                return Ok(None);
            }
            let size = match bytes[1] {
                0x15 => 3,
                6 => {
                    if bytes.len() < 7 {
                        return Ok(None);
                    }
                    let n = bytes[3] as u64
                        + 256 * bytes[4] as u64
                        + 65536 * bytes[5] as u64
                        + 16777216 * bytes[6] as u64;
                    if n > 261 {
                        return Err(Error::LengthExceeded);
                    }
                    n as usize + 13
                }
                _ => return Err(Error::PrefixRejected),
            };
            if bytes.len() < size {
                return Ok(None);
            }
            let mut checksum = 0;
            for byte in &bytes[..size] {
                checksum ^= byte;
            }
            if checksum != 0 {
                return Err(Error::ChecksumRejected);
            }
            if bytes[1] == 0x15 {
                return Err(Error::Nack);
            }
            Ok(Some((Fact::Response(bytes[2..size - 1].to_vec()), size)))
        }
        _ => Err(Error::PrefixRejected),
    }
}

fn fact(message: Message) -> Fact {
    match message {
        Message::Response(r) => {
            let mut v = vec![r.message_type];
            v.extend_from_slice(&(r.payload().len() as u32).to_le_bytes());
            v.extend_from_slice(&[r.slot, r.sequence, r.status, r.error, r.parameter]);
            v.extend_from_slice(r.payload());
            Fact::Response(v)
        }
        Message::SlotChange { bitmap } => Fact::Bitmap(bitmap),
        Message::HardwareError {
            slot,
            sequence,
            code,
        } => Fact::Hardware(slot, sequence, code),
    }
}

fn decoder_reference(bytes: &[u8]) {
    let mut decoder = Decoder::default();
    let mut start = 0;
    for end in 1..=bytes.len() {
        let expected = next(&bytes[start..end]);
        let got = decoder.push(bytes[end - 1]).map(|m| m.map(fact));
        match expected {
            Ok(Some((value, length))) => {
                assert_eq!(got, Ok(Some(value)));
                assert_eq!(end - start, length);
                start = end;
            }
            Ok(None) => assert_eq!(got, Ok(None)),
            Err(error) => {
                assert_eq!(got, Err(error));
                assert_eq!(decoder.push(0x50), Err(error));
                assert_eq!(decoder.finish(), Err(error));
                return;
            }
        }
        assert_eq!(decoder.pending_bytes(), end - start);
    }
    if start != bytes.len() {
        assert_eq!(decoder.finish(), Err(Error::Truncated));
        assert_eq!(decoder.push(0), Err(Error::Truncated));
    } else {
        assert_eq!(decoder.finish(), Ok(()));
    }
}

fn response(power: bool) -> Vec<u8> {
    // Not built with the product encoder.
    let mut out = vec![
        3,
        6,
        if power { 0x80 } else { 0x81 },
        if power { 15 } else { 0 },
        0,
        0,
        0,
        0,
        if power { 2 } else { 1 },
        if power { 0 } else { 1 },
        0,
        0,
    ];
    if power {
        out.extend_from_slice(&ATR);
    }
    out.push(out.iter().copied().fold(0, |a, b| a ^ b));
    out
}

fn validate(power: bool, r: &[u8]) -> Result<(), Error> {
    if r[5] != 0 {
        return Err(Error::SlotRejected);
    }
    if r[6] != if power { 2 } else { 1 } {
        return Err(Error::SequenceRejected);
    }
    if r[0] != if power { 0x80 } else { 0x81 } {
        return Err(Error::ResponseTypeRejected);
    }
    let command = r[7] / 64;
    let icc = r[7] % 4;
    if r[7] & 60 != 0 || command == 3 || icc == 3 {
        return Err(Error::StatusReserved);
    }
    if command == 1 {
        return Err(Error::CommandFailed);
    }
    if command == 2 {
        return Err(Error::TimeExtensionRejected);
    }
    if r[8] != 0 {
        return Err(Error::StatusErrorRejected);
    }
    if icc == 2 {
        return Err(Error::CardAbsent);
    }
    if !power && icc == 0 {
        return Err(Error::AlreadyActive);
    }
    if power && icc == 1 {
        return Err(Error::IccStatusRejected);
    }
    if !power && r.len() != 10 {
        return Err(Error::PayloadRejected);
    }
    if power && r[9] != 0 {
        return Err(Error::ChainingRejected);
    }
    if power && r[10..] != ATR {
        return Err(Error::AtrRejected);
    }
    Ok(())
}

struct Model {
    phase: Phase,
    pending: Vec<u8>,
    failure: Option<Error>,
    events: usize,
    received: usize,
    requests: usize,
    responses: usize,
    elapsed: u64,
    observations: Vec<Observation>,
}
impl Default for Model {
    fn default() -> Self {
        Self {
            phase: Phase::ReadyStatus,
            pending: Vec::new(),
            failure: None,
            events: 0,
            received: 0,
            requests: 0,
            responses: 0,
            elapsed: 0,
            observations: Vec::new(),
        }
    }
}
impl Model {
    fn reject<T>(&mut self, error: Error) -> Result<T, Error> {
        let first = *self.failure.get_or_insert(error);
        self.phase = Phase::Failed;
        Err(first)
    }
    fn begin(&mut self) -> Result<Command, Error> {
        let c = match self.phase {
            Phase::ReadyStatus => Command::GetSlotStatus,
            Phase::ReadyPower => Command::PowerOn,
            _ => return self.reject(Error::SequenceViolation),
        };
        self.phase = Phase::Writing(c);
        Ok(c)
    }
    fn written(&mut self, n: usize) -> Result<(), Error> {
        if let Phase::Writing(c) = self.phase {
            if n != 13 {
                return self.reject(Error::PartialWrite);
            }
            self.requests += 1;
            self.elapsed = 0;
            self.phase = Phase::Receiving(c);
            Ok(())
        } else {
            self.reject(Error::SequenceViolation)
        }
    }
    fn receive(&mut self, bytes: &[u8], elapsed: u64) -> Result<(), Error> {
        let power = match self.phase {
            Phase::Receiving(c) => c == Command::PowerOn,
            _ => return self.reject(Error::UnsolicitedResponse),
        };
        if elapsed < self.elapsed {
            return self.reject(Error::ClockRegression);
        }
        self.elapsed = elapsed;
        if elapsed >= 5000 {
            return self.reject(if self.pending.is_empty() {
                Error::DeadlineExceeded
            } else {
                Error::PartialFrameDeadline
            });
        }
        if self.received + bytes.len() > 4096 {
            return self.reject(Error::ReceiveLimitExceeded);
        }
        self.received += bytes.len();
        self.pending.extend_from_slice(bytes);
        loop {
            let (value, length) = match next(&self.pending) {
                Ok(Some(v)) => v,
                Ok(None) => return Ok(()),
                Err(e) => return self.reject(e),
            };
            match value {
                Fact::Bitmap(b) => {
                    self.events += 1;
                    if self.events > 64 {
                        return self.reject(Error::EventLimitExceeded);
                    }
                    self.observations.push(Observation::SlotChange {
                        bitmap: b,
                        slot1_bits: (b / 4) % 4,
                    });
                    if b & 240 != 0 {
                        return self.reject(Error::EventBitmapRejected);
                    }
                    if b & 1 == 0 {
                        return self.reject(Error::CardAbsent);
                    }
                }
                Fact::Hardware(slot, seq, code) => {
                    self.events += 1;
                    if self.events > 64 {
                        return self.reject(Error::EventLimitExceeded);
                    }
                    self.observations.push(Observation::HardwareError {
                        slot,
                        sequence: seq,
                        code,
                    });
                    if slot != 0 {
                        return self.reject(Error::SlotRejected);
                    }
                    if seq != if power { 2 } else { 1 } {
                        return self.reject(Error::SequenceRejected);
                    }
                    return self.reject(Error::HardwareError);
                }
                Fact::Response(r) => {
                    if let Err(e) = validate(power, &r) {
                        return self.reject(e);
                    }
                    if length != self.pending.len() {
                        return self.reject(Error::TrailingData);
                    }
                    self.observations.push(if power {
                        Observation::Atr(ATR)
                    } else {
                        Observation::SlotStatus {
                            status: r[7],
                            error: r[8],
                            clock: r[9],
                        }
                    });
                    self.responses += 1;
                    self.phase = if power {
                        Phase::Complete
                    } else {
                        Phase::ReadyPower
                    };
                }
            }
            self.pending.drain(..length);
            if self.pending.is_empty() {
                return Ok(());
            }
        }
    }
}

fn compare(actual: &Exchange, expected: &Model) {
    assert_eq!(actual.phase(), expected.phase);
    assert_eq!(actual.failure(), expected.failure);
    assert_eq!(actual.events(), expected.events);
    assert_eq!(actual.received_bytes(), expected.received);
    assert_eq!(actual.requests(), expected.requests);
    assert_eq!(actual.responses(), expected.responses);
    assert!(actual.observations().len() <= 66);
    assert_eq!(actual.observations(), expected.observations);
}
fn begin(a: &mut Exchange, m: &mut Model) {
    assert_eq!(a.begin(), m.begin());
    compare(a, m);
}
fn written(a: &mut Exchange, m: &mut Model, n: usize) {
    assert_eq!(a.written(n), m.written(n));
    compare(a, m);
}
fn receive(a: &mut Exchange, m: &mut Model, bytes: &[u8], ms: u64) {
    assert_eq!(a.receive(bytes, ms).map(|_| ()), m.receive(bytes, ms));
    compare(a, m);
}
fn ready(power: bool) -> (Exchange, Model) {
    let (mut a, mut m) = (Exchange::default(), Model::default());
    begin(&mut a, &mut m);
    written(&mut a, &mut m, 13);
    if power {
        receive(&mut a, &mut m, &response(false), 1);
        begin(&mut a, &mut m);
        written(&mut a, &mut m, 13);
    }
    (a, m)
}

fn readback_frame(kind: u8, sequence: u8, status: u8, parameter: u8, body: &[u8]) -> Vec<u8> {
    let mut bytes = vec![3, 6, kind];
    bytes.extend_from_slice(&(body.len() as u32).to_le_bytes());
    bytes.extend_from_slice(&[0, sequence, status, 0, parameter]);
    bytes.extend_from_slice(body);
    bytes.push(bytes.iter().copied().fold(0, |sum, byte| sum ^ byte));
    bytes
}

fn readback_ifs_pending() -> ReadbackSession {
    let mut session = ReadbackSession::default();
    for (index, raw) in [
        readback_frame(0x81, 1, 1, 0xff, &[]),
        readback_frame(0x80, 2, 0, 0, &ATR),
        readback_frame(0x82, 3, 0, 1, &[0x18, 0x10, 0xff, 0x4d, 3, 0xfe, 0]),
    ]
    .iter()
    .enumerate()
    {
        let request = session.begin_initial(0).unwrap();
        assert_eq!(request.sequence(), (index + 1) as u8);
        session.written(13, 0).unwrap();
        session.receive(raw, 0).unwrap();
    }
    let request = session
        .begin_transfer(&[0, 0xc1, 1, 0xfe, 0x3e], 0)
        .unwrap();
    assert_eq!(
        request.as_bytes(),
        [3, 6, 0x6f, 5, 0, 0, 0, 0, 4, 0, 0, 0, 0, 0xc1, 1, 0xfe, 0x3e, 0x6b,]
    );
    session.written(18, 0).unwrap();
    session
}

// Independent batch oracle for the sequence-4 transfer. Its body stays opaque:
// only qk-t1 may interpret an IFS response or activate the larger T=1 bound.
#[derive(Default)]
struct IfsWireModel {
    pending: Vec<u8>,
    received: usize,
    events: usize,
    observations: Vec<RO>,
    accepted: Option<Vec<u8>>,
    error: Option<RE>,
    last: u64,
}
impl IfsWireModel {
    fn reject(&mut self, error: Error) -> Result<(), RE> {
        Err(*self.error.get_or_insert(error.into()))
    }
    fn receive(&mut self, raw: &[u8], now: u64) -> Result<(), RE> {
        if let Some(error) = self.error {
            return Err(error);
        }
        if now < self.last {
            return self.reject(Error::ClockRegression);
        }
        self.last = now;
        if self.accepted.is_none() && now >= 5000 {
            return self.reject(if self.pending.is_empty() {
                Error::DeadlineExceeded
            } else {
                Error::PartialFrameDeadline
            });
        }
        if self.accepted.is_some() {
            return self.reject(Error::UnsolicitedResponse);
        }
        if 61 + self.received + raw.len() > 8192 {
            return self.reject(Error::ReceiveLimitExceeded);
        }
        self.received += raw.len();
        self.pending.extend_from_slice(raw);
        loop {
            let (value, length) = match next(&self.pending) {
                Ok(Some(value)) => value,
                Ok(None) => return Ok(()),
                Err(error) => return self.reject(error),
            };
            match value {
                Fact::Bitmap(bitmap) => {
                    self.events += 1;
                    if self.events > 64 {
                        return self.reject(Error::EventLimitExceeded);
                    }
                    self.observations.push(RO::SlotChange {
                        bitmap,
                        slot1_bits: bitmap / 4 % 4,
                    });
                    if bitmap > 15 {
                        return self.reject(Error::EventBitmapRejected);
                    }
                    if bitmap % 2 == 0 {
                        return self.reject(Error::CardAbsent);
                    }
                }
                Fact::Hardware(slot, sequence, code) => {
                    self.events += 1;
                    if self.events > 64 {
                        return self.reject(Error::EventLimitExceeded);
                    }
                    self.observations.push(RO::HardwareError {
                        slot,
                        sequence,
                        code,
                    });
                    return self.reject(if slot != 0 {
                        Error::SlotRejected
                    } else if sequence != 4 {
                        Error::SequenceRejected
                    } else {
                        Error::HardwareError
                    });
                }
                Fact::Response(r) => {
                    let checks = [
                        (r[5] != 0, Error::SlotRejected),
                        (r[6] != 4, Error::SequenceRejected),
                        (
                            r[7] & 60 != 0 || r[7] % 4 == 3 || r[7] / 64 == 3,
                            Error::StatusReserved,
                        ),
                        (r[7] / 64 == 2, Error::TimeExtensionRejected),
                        (r[7] / 64 == 1, Error::CommandFailed),
                        (r[0] != 0x80, Error::ResponseTypeRejected),
                        (r[8] != 0, Error::StatusErrorRejected),
                        (r[7] % 4 == 2, Error::CardAbsent),
                        (r[7] % 4 != 0, Error::IccStatusRejected),
                        (r[9] != 0, Error::ChainingRejected),
                    ];
                    if let Some((_, error)) = checks.into_iter().find(|(bad, _)| *bad) {
                        return self.reject(error);
                    }
                    self.observations.push(RO::Transfer {
                        sequence: 4,
                        payload_bytes: r.len() - 10,
                    });
                    if length != self.pending.len() {
                        return self.reject(Error::TrailingData);
                    }
                    self.accepted = Some(r[10..].to_vec());
                }
            }
            self.pending.drain(..length);
            if self.pending.is_empty() {
                return Ok(());
            }
        }
    }
    fn check(&self, actual: &ReadbackSession) {
        assert_eq!(actual.failure(), self.error);
        let expected_phase = if self.error.is_some() {
            RP::Failed
        } else if self.accepted.is_some() {
            RP::ReadyTransfer
        } else {
            RP::Receiving(qk_sec1210_wire::ReadbackCommand::XfrBlock)
        };
        assert_eq!(actual.phase(), expected_phase);
        assert_eq!(actual.sequence(), 4);
        assert_eq!(actual.requests(), 4);
        assert_eq!(actual.responses(), 3 + usize::from(self.accepted.is_some()));
        assert_eq!(actual.received_bytes(), 61 + self.received);
        assert_eq!(actual.events(), self.events);
        assert_eq!(&actual.observations()[3..], self.observations);
        assert_eq!(
            actual.response().map(|r| r.payload().to_vec()),
            self.accepted
        );
    }
}

fn ifs_wire_case(raw: &[u8], split: usize, now: u64) {
    decoder_reference(raw);
    let (mut actual, mut model) = (readback_ifs_pending(), IfsWireModel::default());
    for (part, time) in [(&raw[..split], 1), (&raw[split..], now), (&[][..], 5000)] {
        assert_eq!(actual.receive(part, time), model.receive(part, time));
        model.check(&actual);
    }
    if let Some(error) = model.error {
        assert_eq!(
            actual.begin_transfer(&[0, 0xc1, 1, 0xfe, 0x3e], 5000),
            Err(error)
        );
        assert_eq!(actual.written(18, 5000), Err(error));
        assert_eq!(actual.tick(u64::MAX), Err(error));
        model.check(&actual);
    }
}

fn hostile_ifs_wire(input: &[u8]) {
    let at = |index| input.get(index).copied().unwrap_or(0);
    let echo = [0, 0xe1, 1, 0xfe, 0x1e];
    let exact = readback_frame(0x80, 4, 0, 0, &echo);
    assert_eq!(
        exact,
        [3, 6, 0x80, 5, 0, 0, 0, 0, 4, 0, 0, 0, 0, 0xe1, 1, 0xfe, 0x1e, 0x84,]
    );
    ifs_wire_case(&exact, usize::from(at(0)) % (exact.len() + 1), 2);
    ifs_wire_case(input, input.len() / 2, 2);

    let length = [5, 36, 37, 258, 259, 261, 262][usize::from(at(1) % 7)];
    let mut body: Vec<_> = (0..length).map(|index| at(index + 2)).collect();
    if length == 5 {
        body.copy_from_slice(&echo);
        body[usize::from(at(2) % 5)] ^= at(3);
    }
    // Repaired outer checksums expose wire semantic precedence while leaving
    // malformed S-block fields and 258/259-byte bodies opaque to the transport.
    let mut raw = readback_frame(0x80, 4, 0, 0, &body);
    if at(4) & 1 != 0 {
        for pair in input.as_chunks::<2>().0.iter().take(8) {
            let index = [2, 7, 8, 9, 10, 11][usize::from(pair[0] % 6)];
            raw[index] ^= pair[1];
        }
        let last = raw.len() - 1;
        raw[last] = raw[..last].iter().copied().fold(0, |a, b| a ^ b);
    }
    if at(5) & 1 != 0 {
        raw.splice(..0, [0x50, 0x0f].repeat(usize::from(at(6) % 67)));
    }
    if at(7) & 1 != 0 {
        raw.extend_from_slice(&exact); // Repeated/coalesced response.
    }
    let split = usize::from(at(8)) % (raw.len() + 1);
    let time = [0, 2, 4999, 5000, u64::MAX][usize::from(at(9) % 5)];
    ifs_wire_case(&raw, split, time);
}

fuzz_target!(|input: &[u8]| {
    if input.len() > 4096 {
        return;
    }
    decoder_reference(input);
    let power = input.first().copied().unwrap_or(0) & 1 != 0;
    let (mut a, mut m) = ready(power);
    // Whole hostile input including oversize, NACK and async event sequences.
    receive(&mut a, &mut m, input, 10);
    receive(&mut a, &mut m, &[], 5000);
    begin(&mut a, &mut m); // First failure is sticky.

    // Repaired-checksum mutations reach semantic gates, in both exchange phases.
    let mut wire = response(power);
    for pair in input.as_chunks::<2>().0.iter().take(32) {
        let index = 2 + pair[0] as usize % (wire.len() - 3);
        wire[index] ^= pair[1];
    }
    let last = wire.len() - 1;
    wire[last] = wire[..last].iter().copied().fold(0, |a, b| a ^ b);
    decoder_reference(&wire);
    let split = input.get(1).copied().unwrap_or(0) as usize % (wire.len() + 1);
    let (mut a, mut m) = ready(power);
    receive(&mut a, &mut m, &wire[..split], 10);
    receive(&mut a, &mut m, &wire[split..], 11);
    receive(&mut a, &mut m, &[], 5000);

    // Operation programs exercise ordering, deadlines, regressions and totals.
    let (mut a, mut m) = (Exchange::default(), Model::default());
    for block in input.chunks(8).take(128) {
        let x = block.first().copied().unwrap_or(0);
        let y = block.get(1).copied().unwrap_or(0);
        match x % 8 {
            0 => begin(&mut a, &mut m),
            1 => written(&mut a, &mut m, if y & 1 == 0 { 13 } else { y as usize }),
            2 => receive(&mut a, &mut m, &response(false), y as u64),
            3 => receive(&mut a, &mut m, &response(true), y as u64),
            4 => receive(&mut a, &mut m, block.get(2..).unwrap_or(&[]), y as u64),
            5 => {
                let ms = [0, 4999, 5000, u64::MAX][y as usize % 4];
                receive(&mut a, &mut m, &[], ms);
            }
            6 => receive(&mut a, &mut m, &[0x50, y], 11),
            _ => receive(&mut a, &mut m, &[0x51, y, x, 1], 12),
        }
    }
    let (mut a, mut m) = ready(false);
    let n = input.first().copied().unwrap_or(0) as usize % 67;
    for _ in 0..n {
        receive(&mut a, &mut m, &[0x50, 15], 20);
    }
    receive(&mut a, &mut m, &response(false), 21);
    begin(&mut a, &mut m);
    written(&mut a, &mut m, 13);
    receive(&mut a, &mut m, &[0x50, 3], 1);
    receive(&mut a, &mut m, &response(true), 2);
    hostile_ifs_wire(input);
});
