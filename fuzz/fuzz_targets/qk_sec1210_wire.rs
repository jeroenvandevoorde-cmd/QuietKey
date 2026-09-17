#![no_main]
// Public-input, in-memory reference checks only. No UART, clocks or subprocesses.
use libfuzzer_sys::fuzz_target;
use qk_sec1210_wire::{
    validate_production_atr, Command, Decoder, Error, Exchange, Message, Observation, Phase,
    ProductionDecoder, ProductionMessage, ProductionMessageKind, ProductionRequest,
    MAX_PRODUCTION_ATR_BYTES,
};
use qk_sec1210_wire::{
    ReadbackError as RE, ReadbackObservation as RO, ReadbackPhase as RP, ReadbackSession,
};

const ATR: [u8; 15] = [
    0x3b, 0xd5, 0x18, 0xff, 0x81, 0x91, 0xfe, 0x1f, 0xc3, 0x80, 0x73, 0xc8, 0x21, 0x10, 0x0a,
];
// Independently pinned reference payload, not the exported product constant.
const FIDI: [u8; 7] = [0x18, 0x10, 0xff, 0x4d, 0, 0xfe, 0];

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

fn production_fact(message: ProductionMessage) -> Fact {
    match message.kind() {
        ProductionMessageKind::Response => {
            let response = message
                .response()
                .expect("response kind carries fixed response storage");
            let mut value = vec![response.message_type()];
            value.extend_from_slice(&(response.payload().len() as u32).to_le_bytes());
            value.extend_from_slice(&[
                response.slot(),
                response.sequence(),
                response.status(),
                response.error(),
                response.parameter(),
            ]);
            value.extend_from_slice(response.payload());
            Fact::Response(value)
        }
        ProductionMessageKind::SlotChange { bitmap } => Fact::Bitmap(bitmap),
        ProductionMessageKind::HardwareError {
            slot,
            sequence,
            code,
        } => Fact::Hardware(slot, sequence, code),
    }
}

fn production_decoder_equivalence(bytes: &[u8]) {
    let mut boxed = Decoder::default();
    let mut fixed = ProductionDecoder::default();
    for byte in bytes {
        assert_eq!(
            boxed.push(*byte).map(|value| value.map(fact)),
            fixed.push(*byte).map(|value| value.map(production_fact))
        );
        assert_eq!(boxed.pending_bytes(), fixed.pending_bytes());
    }
    assert_eq!(boxed.finish(), fixed.finish());
}

fn production_request_frame(
    message_type: u8,
    sequence: u8,
    parameter: u8,
    payload: &[u8],
) -> Vec<u8> {
    let mut frame = vec![3, 6, message_type];
    frame.extend_from_slice(&(payload.len() as u32).to_le_bytes());
    frame.extend_from_slice(&[0, sequence, parameter, 0, 0]);
    frame.extend_from_slice(payload);
    frame.push(frame.iter().copied().fold(0, |sum, byte| sum ^ byte));
    frame
}

fn production_requests(input: &[u8]) {
    let sequence = input.first().copied().unwrap_or(0);
    let expected = [
        (
            ProductionRequest::get_slot_status(sequence),
            production_request_frame(0x65, sequence, 0, &[]),
        ),
        (
            ProductionRequest::power_on_3v(sequence),
            production_request_frame(0x62, sequence, 2, &[]),
        ),
        (
            ProductionRequest::get_parameters(sequence),
            production_request_frame(0x6c, sequence, 0, &[]),
        ),
        (
            ProductionRequest::set_fidi_parameters(sequence),
            production_request_frame(0x61, sequence, 1, &FIDI),
        ),
    ];
    for (request, expected) in expected {
        assert_eq!(request.as_bytes(), expected);
    }

    let bwi = input.get(1).copied().unwrap_or(0);
    let accepted = (4..=258).contains(&input.len())
        && usize::from(input[2]) + 4 == input.len()
        && input.iter().copied().fold(0, |sum, byte| sum ^ byte) == 0;
    let request = ProductionRequest::xfr_block(sequence, bwi, input);
    assert_eq!(request.is_ok(), accepted);
    if let Ok(request) = request {
        assert_eq!(
            request.as_bytes(),
            production_request_frame(0x6f, sequence, bwi, input)
        );
    }

    let mut exact = vec![0, 0, 254];
    exact.extend(std::iter::repeat_n(0xa5, 254));
    exact.push(exact.iter().copied().fold(0, |sum, byte| sum ^ byte));
    let exact_request = ProductionRequest::xfr_block(sequence, bwi, &exact)
        .expect("the exact 258-byte production TPDU bound is accepted");
    assert_eq!(
        exact_request.as_bytes(),
        production_request_frame(0x6f, sequence, bwi, &exact)
    );
    let mut excess = vec![0, 0, 255];
    excess.extend(std::iter::repeat_n(0xa5, 255));
    excess.push(excess.iter().copied().fold(0, |sum, byte| sum ^ byte));
    assert_eq!(
        ProductionRequest::xfr_block(sequence, bwi, &excess).err(),
        Some(Error::PayloadRejected)
    );
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
    readback_pending(false)
}
fn readback_pending(fidi: bool) -> ReadbackSession {
    let mut session = if fidi {
        ReadbackSession::with_fidi()
    } else {
        ReadbackSession::default()
    };
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
    if fidi {
        assert_eq!(qk_sec1210_wire::FIDI_PARAMETERS, FIDI);
        let request = session.begin_initial(0).unwrap();
        assert_eq!(
            request.as_bytes(),
            [3, 6, 0x61, 7, 0, 0, 0, 0, 4, 1, 0, 0, 0x18, 0x10, 0xff, 0x4d, 0, 0xfe, 0, 0x22]
        );
        session.written(20, 0).unwrap();
    } else {
        let request = session
            .begin_transfer(&[0, 0xc1, 1, 0xfe, 0x3e], 0)
            .unwrap();
        assert_eq!(
            request.as_bytes(),
            [3, 6, 0x6f, 5, 0, 0, 0, 0, 4, 0, 0, 0, 0, 0xc1, 1, 0xfe, 0x3e, 0x6b,]
        );
        session.written(18, 0).unwrap();
    }
    session
}

// Independent batch oracle for sequence 4: default transfer or opt-in fixed
// SetParameters. A transfer body stays opaque: only qk-t1 interprets IFS.
#[derive(Default)]
struct IfsWireModel {
    pending: Vec<u8>,
    received: usize,
    events: usize,
    observations: Vec<RO>,
    accepted: Option<Vec<u8>>,
    error: Option<RE>,
    last: u64,
    fidi: bool,
    evidence: Option<Vec<u8>>,
}
impl IfsWireModel {
    fn reject(&mut self, error: impl Into<RE>) -> Result<(), RE> {
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
                    if self.fidi {
                        self.evidence = Some(r.clone());
                    }
                    let checks = [
                        (r[5] != 0, Error::SlotRejected),
                        (r[6] != 4, Error::SequenceRejected),
                        (
                            r[7] & 60 != 0 || r[7] % 4 == 3 || r[7] / 64 == 3,
                            Error::StatusReserved,
                        ),
                        (r[7] / 64 == 2, Error::TimeExtensionRejected),
                        (r[7] / 64 == 1, Error::CommandFailed),
                        (
                            r[0] != if self.fidi { 0x82 } else { 0x80 },
                            Error::ResponseTypeRejected,
                        ),
                        (r[8] != 0, Error::StatusErrorRejected),
                        (r[7] % 4 == 2, Error::CardAbsent),
                        (r[7] % 4 != 0, Error::IccStatusRejected),
                        (!self.fidi && r[9] != 0, Error::ChainingRejected),
                    ];
                    if let Some((_, error)) = checks.into_iter().find(|(bad, _)| *bad) {
                        return self.reject(error);
                    }
                    if self.fidi {
                        if r.len() != 17 {
                            return self.reject(Error::PayloadRejected);
                        }
                        let mut bytes = [0; 7];
                        bytes.copy_from_slice(&r[10..]);
                        self.observations.push(RO::Parameters {
                            protocol: r[9],
                            bytes,
                        });
                        if r[9] != 1 {
                            return self.reject(RE::ProtocolRejected);
                        }
                        if bytes != FIDI {
                            return self.reject(RE::SetParametersEchoRejected);
                        }
                    } else {
                        self.observations.push(RO::Transfer {
                            sequence: 4,
                            payload_bytes: r.len() - 10,
                        });
                    }
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
            RP::Receiving(if self.fidi {
                qk_sec1210_wire::ReadbackCommand::SetParameters
            } else {
                qk_sec1210_wire::ReadbackCommand::XfrBlock
            })
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
        let evidence = actual.set_parameters_reply_evidence().map(|r| {
            let mut v = vec![r.message_type];
            v.extend_from_slice(&(r.payload().len() as u32).to_le_bytes());
            v.extend_from_slice(&[r.slot, r.sequence, r.status, r.error, r.parameter]);
            v.extend_from_slice(r.payload());
            v
        });
        assert_eq!(evidence, self.evidence);
        assert_eq!(
            actual.set_parameters_accepted(),
            self.fidi && self.accepted.is_some()
        );
    }
}

fn ifs_wire_case(raw: &[u8], split: usize, now: u64) {
    readback_case(raw, split, now, false);
}
fn readback_case(raw: &[u8], split: usize, now: u64, fidi: bool) {
    decoder_reference(raw);
    let mut actual = if fidi {
        readback_pending(true)
    } else {
        readback_ifs_pending()
    };
    let mut model = IfsWireModel {
        fidi,
        ..IfsWireModel::default()
    };
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

fn hostile_fidi_wire(input: &[u8]) {
    let at = |index| input.get(index).copied().unwrap_or(0);
    let exact = readback_frame(0x82, 4, 0, 1, &FIDI);
    assert_eq!(
        exact,
        [3, 6, 0x82, 7, 0, 0, 0, 0, 4, 0, 0, 1, 0x18, 0x10, 0xff, 0x4d, 0, 0xfe, 0, 0xc1]
    );
    readback_case(&exact, usize::from(at(0)) % 21, 2, true);
    readback_case(input, input.len() / 2, 2, true);

    let size = [0, 6, 7, 8, 261, 262][usize::from(at(1) % 6)];
    let mut body = vec![0; size];
    for (index, value) in body.iter_mut().enumerate() {
        *value = at(index + 2);
    }
    if size == 7 {
        body.copy_from_slice(&FIDI);
        body[usize::from(at(2) % 7)] ^= at(3);
    }
    let mut raw = readback_frame(0x82, 4, 0, 1, &body);
    // CCID error precedence is tested with independently preserved bError,
    // not by inferring an echo rejection from any nonmatching payload.
    match at(4) % 5 {
        0 => (),
        1 => {
            raw[9] = 0x40;
            raw[10] = at(5);
        }
        2 => {
            raw[2] = 0x81;
            raw[9] = 0x80;
            raw[10] = at(5);
        }
        _ => {
            for pair in input.as_chunks::<2>().0.iter().take(12) {
                let index = [2, 7, 8, 9, 10, 11][usize::from(pair[0] % 6)];
                raw[index] ^= pair[1];
            }
        }
    }
    let last = raw.len() - 1;
    raw[last] = raw[..last].iter().copied().fold(0, |a, b| a ^ b);
    if at(6) & 1 != 0 {
        raw.splice(..0, [0x50, 0x0f].repeat(usize::from(at(7) % 67)));
    }
    if at(8) & 1 != 0 {
        raw.extend_from_slice(&exact);
    }
    let split = usize::from(at(9)) % (raw.len() + 1);
    let now = [0, 2, 4999, 5000, u64::MAX][usize::from(at(10) % 5)];
    readback_case(&raw, split, now, true);
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

fn production_atr_oracle(input: &[u8]) {
    match validate_production_atr(input) {
        Ok(()) => {
            assert!((2..=MAX_PRODUCTION_ATR_BYTES).contains(&input.len()));
            assert_eq!(input[0], 0x3b);
            assert_eq!(
                input[1..].iter().copied().fold(0u8, |sum, byte| sum ^ byte),
                0
            );
        }
        Err(error) => {
            assert_eq!(error.name(), "Sec1210AtrProfileRejected");
            assert_eq!(format!("{error:?}"), error.name());
        }
    }
}

fuzz_target!(|input: &[u8]| {
    if input.len() > 4096 {
        return;
    }
    decoder_reference(input);
    production_decoder_equivalence(input);
    production_atr_oracle(input);
    production_requests(input);
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
    hostile_fidi_wire(input);
    raw_oracle::exercise(input);
});

// SUP-013: sibling raw-response coverage. All preceding oracles remain intact.
mod raw_oracle {
    use super::{next, Fact, ATR, FIDI};
    use qk_sec1210_wire::{
        Error as W, RawCommand as C, RawError as E, RawFrameSpan, RawObservation as O,
        RawPhase as P, RawRequest, RawSession, Response,
    };

    const IFS: [u8; 5] = [0, 0xc1, 1, 254, 0x3e];
    const ECHO: [u8; 5] = [0, 0xe1, 1, 254, 0x1e];
    const BASELINE: [u8; 7] = [0x11, 0x10, 0xff, 0x4d, 0, 254, 0];

    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    enum Stage {
        Initial(u8),
        Ifs,
        Confirm,
        Idle,
        Apdu,
        Write(u8),
        Wait(u8),
        Failed,
    }

    #[derive(Debug, PartialEq, Eq)]
    struct Request {
        command: u8,
        ordinal: usize,
        sequence: u8,
        bwi: u8,
        allowance: u64,
        deadline: u64,
        apdu_deadline: Option<u64>,
        bytes: Vec<u8>,
    }

    enum Op {
        Initial,
        Ifs(Vec<u8>),
        Confirm,
        Start,
        Transfer(Vec<u8>, u8),
        End,
        Written(usize),
        Receive(Vec<u8>),
        Tick,
    }

    // Independent batch state machine: no product decoder, command encoder,
    // session fields or T=1 implementation supplies an expected result.
    struct Model {
        stage: Stage,
        pending: Vec<u8>,
        cursor: usize,
        received: usize,
        writes: usize,
        replies: usize,
        ordinal: usize,
        request_len: usize,
        events: usize,
        extensions: usize,
        apdu_extensions: usize,
        last_clock: Option<u64>,
        allowance: u64,
        command_deadline: u64,
        apdu_deadline: Option<u64>,
        ifs_pending: bool,
        ifs_ok: bool,
        parameters_ok: bool,
        transferred: bool,
        wtx: Option<u8>,
        accepted: Option<Vec<u8>>,
        evidence: Option<Vec<u8>>,
        parameters_evidence: Option<Vec<u8>>,
        span: Option<RawFrameSpan>,
        observations: Vec<O>,
        error: Option<E>,
    }

    fn add(left: u64, right: u64) -> u64 {
        left.saturating_add(right)
    }

    impl Model {
        fn new() -> Self {
            Self {
                stage: Stage::Initial(0),
                pending: Vec::new(),
                cursor: 0,
                received: 0,
                writes: 0,
                replies: 0,
                ordinal: 0,
                request_len: 0,
                events: 0,
                extensions: 0,
                apdu_extensions: 0,
                last_clock: None,
                allowance: 5000,
                command_deadline: 0,
                apdu_deadline: None,
                ifs_pending: false,
                ifs_ok: false,
                parameters_ok: false,
                transferred: false,
                wtx: None,
                accepted: None,
                evidence: None,
                parameters_evidence: None,
                span: None,
                observations: Vec::new(),
                error: None,
            }
        }

        fn fail<T>(&mut self, error: impl Into<E>) -> Result<T, E> {
            let first = *self.error.get_or_insert(error.into());
            self.stage = Stage::Failed;
            Err(first)
        }

        fn clock(&mut self, now: u64) -> Result<(), E> {
            if let Some(error) = self.error {
                return Err(error);
            }
            if self.last_clock.is_some_and(|old| old > now) {
                return self.fail(W::ClockRegression);
            }
            self.last_clock = Some(now);
            if self.apdu_deadline.is_some_and(|end| now >= end) {
                return self.fail(E::ApduDeadlineExceeded);
            }
            if matches!(self.stage, Stage::Write(_) | Stage::Wait(_))
                && now >= self.command_deadline
            {
                return self.fail(if self.pending.is_empty() {
                    W::DeadlineExceeded
                } else {
                    W::PartialFrameDeadline
                });
            }
            Ok(())
        }

        fn claim(&mut self, command: u8, payload: &[u8], bwi: u8, now: u64) -> Result<Request, E> {
            if self.writes >= 512 {
                return self.fail(E::CommandLimitExceeded);
            }
            self.ordinal = self.writes + 1;
            self.allowance = if u64::from(bwi) * 1190 > 5000 {
                u64::from(bwi) * 1190
            } else {
                5000
            };
            self.command_deadline = add(now, self.allowance);
            if let Some(end) = self.apdu_deadline {
                if end < self.command_deadline {
                    self.command_deadline = end;
                }
            }
            let kind = [0x65, 0x62, 0x6c, 0x61, 0x6f][usize::from(command)];
            let parameter = match command {
                1 => 2,
                3 => 1,
                4 => bwi,
                _ => 0,
            };
            let length = payload.len();
            let sequence = (self.ordinal % 256) as u8;
            let mut bytes = vec![
                3,
                6,
                kind,
                (length % 256) as u8,
                (length / 256) as u8,
                0,
                0,
                0,
                sequence,
                parameter,
                0,
                0,
            ];
            bytes.extend_from_slice(payload);
            let mut xor = 0;
            for b in &bytes {
                xor ^= b;
            }
            bytes.push(xor);
            self.request_len = bytes.len();
            self.accepted = None;
            self.evidence = None;
            self.span = None;
            self.stage = Stage::Write(command);
            Ok(Request {
                command,
                ordinal: self.ordinal,
                sequence,
                bwi,
                allowance: self.allowance,
                deadline: self.command_deadline,
                apdu_deadline: self.apdu_deadline,
                bytes,
            })
        }

        fn operation(&mut self, op: &Op, now: u64) -> Result<Option<Request>, E> {
            self.clock(now)?;
            match op {
                Op::Initial => {
                    let Stage::Initial(command) = self.stage else {
                        return self.fail(E::StateRejected);
                    };
                    let payload = if command == 3 { &FIDI[..] } else { &[] };
                    self.claim(command, payload, 0, now).map(Some)
                }
                Op::Ifs(bytes) => {
                    if self.stage != Stage::Ifs {
                        return self.fail(E::StateRejected);
                    }
                    if bytes != &IFS {
                        return self.fail(E::IfsRejected);
                    }
                    self.ifs_pending = true;
                    self.claim(4, bytes, 0, now).map(Some)
                }
                Op::Confirm => {
                    if self.stage != Stage::Confirm {
                        return self.fail(E::StateRejected);
                    }
                    if self.accepted.as_ref().map(|r| &r[10..]) != Some(&ECHO[..]) {
                        return self.fail(E::IfsRejected);
                    }
                    self.ifs_pending = false;
                    self.ifs_ok = true;
                    self.stage = Stage::Idle;
                    Ok(None)
                }
                Op::Start => {
                    if self.stage != Stage::Idle || !self.ifs_ok {
                        return self.fail(E::StateRejected);
                    }
                    self.apdu_deadline = Some(add(now, 30000));
                    self.apdu_extensions = 0;
                    self.transferred = false;
                    self.wtx = None;
                    self.stage = Stage::Apdu;
                    Ok(None)
                }
                Op::Transfer(bytes, bwi) => {
                    if self.stage != Stage::Apdu || self.apdu_deadline.is_none() {
                        return self.fail(E::StateRejected);
                    }
                    let mut xor = 0;
                    for b in bytes {
                        xor ^= b;
                    }
                    if bytes.len() < 4
                        || bytes.len() > 258
                        || usize::from(bytes[2]) != bytes.len() - 4
                        || xor != 0
                    {
                        return self.fail(E::TransferPayloadRejected);
                    }
                    if *bwi > 24 {
                        return self.fail(E::WtxMultiplierRejected);
                    }
                    if *bwi == 0 {
                        if self.wtx.is_some() || self.transferred {
                            return self.fail(E::WtxResponseRejected);
                        }
                    } else if self.wtx != Some(*bwi)
                        || bytes != &[0, 0xe3, 1, *bwi, 0xe3 ^ 1 ^ *bwi]
                    {
                        return self.fail(E::WtxResponseRejected);
                    }
                    self.wtx = None;
                    self.claim(4, bytes, *bwi, now).map(Some)
                }
                Op::End => {
                    if self.stage != Stage::Apdu
                        || self.apdu_deadline.is_none()
                        || !self.transferred
                        || self.wtx.is_some()
                    {
                        return self.fail(E::StateRejected);
                    }
                    self.apdu_deadline = None;
                    self.stage = Stage::Idle;
                    Ok(None)
                }
                Op::Written(count) => {
                    let Stage::Write(command) = self.stage else {
                        return self.fail(E::StateRejected);
                    };
                    if *count != self.request_len {
                        return self.fail(W::PartialWrite);
                    }
                    self.writes += 1;
                    self.stage = Stage::Wait(command);
                    Ok(None)
                }
                Op::Receive(bytes) => self.receive(bytes).map(|_| None),
                Op::Tick => Ok(None),
            }
        }

        fn receive(&mut self, bytes: &[u8]) -> Result<(), E> {
            let Stage::Wait(command) = self.stage else {
                return self.fail(W::UnsolicitedResponse);
            };
            if self.received + bytes.len() > 32768 {
                return self.fail(W::ReceiveLimitExceeded);
            }
            if self.pending.is_empty() {
                self.cursor = self.received;
            }
            self.received += bytes.len();
            self.pending.extend_from_slice(bytes);
            loop {
                let (fact, length) = match next(&self.pending) {
                    Ok(Some(value)) => value,
                    Ok(None) => return Ok(()),
                    Err(error) => return self.fail(error),
                };
                match fact {
                    Fact::Bitmap(bitmap) => {
                        self.events += 1;
                        if self.events > 64 {
                            return self.fail(W::EventLimitExceeded);
                        }
                        self.observations.push(O::SlotChange {
                            bitmap,
                            slot1_bits: bitmap / 4 % 4,
                        });
                        if bitmap > 15 {
                            return self.fail(W::EventBitmapRejected);
                        }
                        if bitmap % 2 == 0 {
                            return self.fail(W::CardAbsent);
                        }
                    }
                    Fact::Hardware(slot, sequence, code) => {
                        self.events += 1;
                        if self.events > 64 {
                            return self.fail(W::EventLimitExceeded);
                        }
                        self.observations.push(O::HardwareError {
                            slot,
                            sequence,
                            code,
                        });
                        return self.fail(if slot != 0 {
                            W::SlotRejected
                        } else if usize::from(sequence) != self.ordinal % 256 {
                            W::SequenceRejected
                        } else {
                            W::HardwareError
                        });
                    }
                    Fact::Response(r) => {
                        self.evidence = Some(r.clone());
                        self.span = Some(RawFrameSpan {
                            start_rx_offset: self.cursor,
                            end_rx_offset: self.cursor + length,
                        });
                        if command == 3 {
                            self.parameters_evidence = Some(r.clone());
                        }
                        let extension = match self.validate(command, &r) {
                            Ok(extension) => extension,
                            Err(error) => return self.fail(error),
                        };
                        if !extension {
                            if length != self.pending.len() {
                                return self.fail(W::TrailingData);
                            }
                            self.replies += 1;
                            if command == 4 && self.apdu_deadline.is_some() {
                                self.transferred = true;
                                let p = &r[10..];
                                let xor = p.iter().copied().reduce(|a, b| a ^ b).unwrap_or(0);
                                self.wtx = if p.len() == 5
                                    && p[0] == 0
                                    && p[1] == 0xc3
                                    && p[2] == 1
                                    && xor == 0
                                {
                                    Some(p[3])
                                } else {
                                    None
                                };
                            }
                            self.accepted = Some(r);
                            self.stage = match command {
                                0..=2 => Stage::Initial(command + 1),
                                3 => {
                                    self.parameters_ok = true;
                                    Stage::Ifs
                                }
                                _ if self.ifs_pending => Stage::Confirm,
                                _ => Stage::Apdu,
                            };
                        }
                    }
                }
                self.pending.drain(..length);
                self.cursor += length;
                if self.pending.is_empty() {
                    return Ok(());
                }
            }
        }

        fn validate(&mut self, command: u8, r: &[u8]) -> Result<bool, E> {
            let status = r[7];
            let icc = status % 4;
            let kind = status / 64;
            let extension = kind == 2;
            let checks = [
                (r[5] != 0, W::SlotRejected),
                (usize::from(r[6]) != self.ordinal % 256, W::SequenceRejected),
                (status & 60 != 0 || icc == 3 || kind == 3, W::StatusReserved),
                (
                    extension && (command != 4 || self.apdu_deadline.is_none()),
                    W::TimeExtensionRejected,
                ),
                (kind == 1, W::CommandFailed),
                (
                    r[0] != [0x81, 0x80, 0x82, 0x82, 0x80][usize::from(command)],
                    W::ResponseTypeRejected,
                ),
                (!extension && r[8] != 0, W::StatusErrorRejected),
                (icc == 2, W::CardAbsent),
                (command == 0 && icc == 0, W::AlreadyActive),
                (command != 0 && icc != 0, W::IccStatusRejected),
            ];
            if let Some((_, error)) = checks.into_iter().find(|(failed, _)| *failed) {
                return Err(error.into());
            }
            if extension {
                if r.len() != 10 || r[9] != 0 {
                    return Err(E::TimeExtensionShapeRejected);
                }
                if self.apdu_extensions >= 8 {
                    return Err(E::TimeExtensionLimitExceeded);
                }
                self.apdu_extensions += 1;
                self.extensions += 1;
                self.observations.push(O::TimeExtension {
                    ordinal: self.ordinal,
                    sequence: (self.ordinal % 256) as u8,
                    multiplier: r[8],
                    apdu_count: self.apdu_extensions,
                    invocation_count: self.extensions,
                    command_deadline_ms: self.command_deadline,
                    apdu_deadline_ms: self.apdu_deadline.unwrap(),
                    span: self.span.unwrap(),
                });
                return Ok(true);
            }
            match command {
                0 => {
                    if r.len() != 10 {
                        return Err(W::PayloadRejected.into());
                    }
                    self.observations.push(O::SlotStatus {
                        status,
                        error: r[8],
                        clock: r[9],
                    });
                }
                1 => {
                    if r[9] != 0 {
                        return Err(W::ChainingRejected.into());
                    }
                    if r[10..] != ATR {
                        return Err(W::AtrRejected.into());
                    }
                    self.observations.push(O::Atr(ATR));
                }
                2 | 3 => {
                    if r.len() != 17 {
                        return Err(W::PayloadRejected.into());
                    }
                    let mut bytes = [0; 7];
                    bytes.copy_from_slice(&r[10..]);
                    self.observations.push(O::Parameters {
                        protocol: r[9],
                        bytes,
                    });
                    if r[9] != 1 {
                        return Err(E::ProtocolRejected);
                    }
                    if command == 3 {
                        if bytes != FIDI {
                            return Err(E::SetParametersEchoRejected);
                        }
                    } else {
                        if bytes[5] != 254 {
                            return Err(E::IfscRejected);
                        }
                        if bytes[1] % 2 != 0 {
                            return Err(E::LrcModeRejected);
                        }
                    }
                }
                _ => {
                    if r[9] != 0 {
                        return Err(W::ChainingRejected.into());
                    }
                    self.observations.push(O::Transfer {
                        ordinal: self.ordinal,
                        sequence: (self.ordinal % 256) as u8,
                        payload_bytes: r.len() - 10,
                    });
                }
            }
            Ok(false)
        }

        fn compare(&self, actual: &RawSession) {
            let phase = match self.stage {
                Stage::Initial(0) => P::ReadyStatus,
                Stage::Initial(1) => P::ReadyPower,
                Stage::Initial(2) => P::ReadyParameters,
                Stage::Initial(3) => P::ReadySetParameters,
                Stage::Ifs => P::ReadyIfs,
                Stage::Confirm => P::AwaitIfsAcceptance,
                Stage::Idle => P::ReadyApdu,
                Stage::Apdu => P::ReadyTransfer,
                Stage::Write(c) => P::Writing(command(c)),
                Stage::Wait(c) => P::Receiving(command(c)),
                Stage::Failed => P::Failed,
                Stage::Initial(_) => unreachable!(),
            };
            assert_eq!(actual.phase(), phase);
            assert_eq!(actual.failure(), self.error);
            assert_eq!(actual.requests(), self.writes);
            assert_eq!(actual.responses(), self.replies);
            assert_eq!(actual.ordinal(), self.ordinal);
            assert_eq!(usize::from(actual.sequence()), self.ordinal % 256);
            assert_eq!(actual.events(), self.events);
            assert_eq!(actual.received_bytes(), self.received);
            assert_eq!(actual.time_extension_count(), self.extensions);
            assert_eq!(actual.apdu_time_extension_count(), self.apdu_extensions);
            assert_eq!(actual.host_allowance_ms(), self.allowance);
            assert_eq!(actual.command_deadline_ms(), self.command_deadline);
            assert_eq!(actual.apdu_deadline_ms(), self.apdu_deadline);
            assert_eq!(actual.ifs_accepted(), self.ifs_ok);
            assert_eq!(actual.set_parameters_accepted(), self.parameters_ok);
            assert_eq!(actual.last_reply_span(), self.span);
            assert_eq!(actual.response().map(reply_fact), self.accepted);
            assert_eq!(actual.reply_evidence().map(reply_fact), self.evidence);
            assert_eq!(
                actual.set_parameters_reply_evidence().map(reply_fact),
                self.parameters_evidence
            );
            assert_eq!(actual.observations(), self.observations);
            assert!(actual.observations().len() <= 32768 / 2 + 4);
        }
    }

    fn command(code: u8) -> C {
        match code {
            0 => C::GetSlotStatus,
            1 => C::PowerOn,
            2 => C::GetParameters,
            3 => C::SetParameters,
            4 => C::XfrBlock,
            _ => unreachable!(),
        }
    }
    fn request_fact(r: RawRequest) -> Request {
        Request {
            command: match r.command() {
                C::GetSlotStatus => 0,
                C::PowerOn => 1,
                C::GetParameters => 2,
                C::SetParameters => 3,
                C::XfrBlock => 4,
            },
            ordinal: r.ordinal(),
            sequence: r.sequence(),
            bwi: r.bwi(),
            allowance: r.host_allowance_ms(),
            deadline: r.deadline_ms(),
            apdu_deadline: r.apdu_deadline_ms(),
            bytes: r.as_bytes().to_vec(),
        }
    }
    fn reply_fact(r: &Response) -> Vec<u8> {
        let n = r.payload().len();
        let mut bytes = vec![
            r.message_type,
            (n % 256) as u8,
            (n / 256) as u8,
            0,
            0,
            r.slot,
            r.sequence,
            r.status,
            r.error,
            r.parameter,
        ];
        bytes.extend_from_slice(r.payload());
        bytes
    }

    struct Pair {
        actual: RawSession,
        model: Model,
    }
    impl Pair {
        fn new() -> Self {
            Self {
                actual: RawSession::new(),
                model: Model::new(),
            }
        }
        fn step(&mut self, op: Op, now: u64) -> Result<(), E> {
            let expected = self.model.operation(&op, now);
            let actual = match &op {
                Op::Initial => self
                    .actual
                    .begin_initial(now)
                    .map(|r| Some(request_fact(r))),
                Op::Ifs(b) => self
                    .actual
                    .begin_ifs_transfer(b, now)
                    .map(|r| Some(request_fact(r))),
                Op::Confirm => self.actual.accept_ifs(now).map(|_| None),
                Op::Start => self.actual.begin_apdu(now).map(|_| None),
                Op::Transfer(b, m) => self
                    .actual
                    .begin_transfer(b, *m, now)
                    .map(|r| Some(request_fact(r))),
                Op::End => self.actual.end_apdu(now).map(|_| None),
                Op::Written(n) => self.actual.written(*n, now).map(|_| None),
                Op::Receive(b) => self.actual.receive(b, now).map(|_| None),
                Op::Tick => self.actual.tick(now).map(|_| None),
            };
            assert_eq!(actual, expected);
            self.model.compare(&self.actual);
            expected.map(|_| ())
        }
        fn exact(&mut self, op: Op, now: u64) {
            self.step(op, now).unwrap();
        }
        fn sticky(&mut self) {
            if self.model.error.is_none() {
                return;
            }
            for op in [
                Op::Initial,
                Op::Ifs(IFS.to_vec()),
                Op::Confirm,
                Op::Start,
                Op::Transfer(vec![0; 259], 255),
                Op::End,
                Op::Written(usize::MAX),
                Op::Receive(vec![3, 6, 0x80]),
                Op::Tick,
            ] {
                let _ = self.step(op, u64::MAX);
            }
        }
        fn initialize(&mut self) {
            for code in 0..4 {
                self.exact(Op::Initial, 0);
                self.exact(Op::Written(self.model.request_len), 0);
                self.exact(Op::Receive(initial_reply(code)), 0);
            }
        }
        fn ready() -> Self {
            let mut p = Self::new();
            p.initialize();
            p.exact(Op::Ifs(IFS.to_vec()), 0);
            p.exact(Op::Written(18), 0);
            p.exact(Op::Receive(frame(0x80, 5, 0, 0, 0, &ECHO)), 0);
            p.exact(Op::Confirm, 0);
            p
        }
        fn pending() -> Self {
            let mut p = Self::ready();
            p.exact(Op::Start, 0);
            p.exact(Op::Transfer(tpdu(0, &[0x55]), 0), 0);
            p.exact(Op::Written(18), 0);
            p
        }
        fn extension(&self, multiplier: u8) -> Vec<u8> {
            frame(
                0x80,
                (self.model.ordinal % 256) as u8,
                0x80,
                multiplier,
                0,
                &[],
            )
        }
        fn transfer_reply(&self, payload: &[u8]) -> Vec<u8> {
            frame(0x80, (self.model.ordinal % 256) as u8, 0, 0, 0, payload)
        }
    }

    fn frame(kind: u8, seq: u8, status: u8, error: u8, parameter: u8, payload: &[u8]) -> Vec<u8> {
        let n = payload.len();
        let mut bytes = vec![
            3,
            6,
            kind,
            (n % 256) as u8,
            (n / 256) as u8,
            0,
            0,
            0,
            seq,
            status,
            error,
            parameter,
        ];
        bytes.extend_from_slice(payload);
        repair(&mut bytes, true);
        bytes
    }
    fn repair(bytes: &mut Vec<u8>, append: bool) {
        if append {
            bytes.push(0);
        }
        let end = bytes.len() - 1;
        let mut xor = 0;
        for b in &bytes[..end] {
            xor ^= b;
        }
        bytes[end] = xor;
    }
    fn tpdu(pcb: u8, payload: &[u8]) -> Vec<u8> {
        let mut bytes = vec![0, pcb, payload.len() as u8];
        bytes.extend_from_slice(payload);
        repair(&mut bytes, true);
        bytes
    }
    fn initial_reply(code: u8) -> Vec<u8> {
        match code {
            0 => frame(0x81, 1, 1, 0, 1, &[]),
            1 => frame(0x80, 2, 0, 0, 0, &ATR),
            2 => frame(0x82, 3, 0, 0, 1, &BASELINE),
            3 => frame(0x82, 4, 0, 0, 1, &FIDI),
            _ => unreachable!(),
        }
    }

    fn byte(input: &[u8], at: usize) -> u8 {
        input.get(at).copied().unwrap_or(0)
    }

    fn checkpoint(code: u8) -> Pair {
        if code % 6 == 5 {
            return Pair::pending();
        }
        let mut p = Pair::new();
        for command in 0..code % 6 {
            p.exact(Op::Initial, 0);
            p.exact(Op::Written(p.model.request_len), 0);
            p.exact(Op::Receive(initial_reply(command)), 0);
        }
        if code % 6 == 4 {
            p.exact(Op::Ifs(IFS.to_vec()), 0);
        } else {
            p.exact(Op::Initial, 0);
        }
        p.exact(Op::Written(p.model.request_len), 0);
        p
    }

    fn matching(p: &Pair) -> Vec<u8> {
        match p.model.stage {
            Stage::Wait(c @ 0..=3) => initial_reply(c),
            _ if p.model.ifs_pending => frame(0x80, 5, 0, 0, 0, &ECHO),
            _ => p.transfer_reply(&tpdu(0, &[0x90, 0])),
        }
    }

    fn fragments(p: &mut Pair, bytes: &[u8], cut: usize, now: u64) {
        let cut = cut.min(bytes.len());
        if p.step(Op::Receive(bytes[..cut].to_vec()), now).is_ok() && cut < bytes.len() {
            let _ = p.step(Op::Receive(bytes[cut..].to_vec()), now);
        }
    }

    // Arbitrary fragments and checksum-repaired mutations meet every fixed
    // initialization checkpoint as well as an ordinary raw application block.
    fn hostile(input: &[u8]) {
        let mut raw = Pair::pending();
        let cut = usize::from(byte(input, 0)) % (input.len() + 1);
        fragments(&mut raw, input, cut, 1);
        let _ = raw.step(Op::Tick, 5000);
        raw.sticky();

        let mut p = checkpoint(byte(input, 0));
        let mut response = matching(&p);
        let mutation = byte(input, 1) % 18;
        let value = byte(input, 2);
        match mutation {
            0 => {}
            1 => response[2] = value,
            2 => response[7] = value,
            3 => response[8] = value,
            4 => response[9] = value,
            5 => response[10] = value,
            6 => response[11] = value,
            7 => {
                let at = usize::from(value) % response.len();
                response[at] ^= byte(input, 3) | 1;
            }
            8 => response[3..7].copy_from_slice(&[value, byte(input, 3), 0, 0]),
            9 => response = p.extension(value),
            10 => {
                let lengths = [0, 4, 5, 36, 37, 258, 259, 261, 262];
                let n = lengths[usize::from(value) % lengths.len()];
                response = p.transfer_reply(&vec![byte(input, 3); n]);
            }
            11 => response = p.transfer_reply(&tpdu(0xc3, &[value])),
            12 => response = vec![3, 0x15, value],
            13 => response = vec![0x51, value, byte(input, 3), byte(input, 4)],
            14 => response = vec![0x50, value],
            15 => response.truncate(usize::from(value) % response.len()),
            16 => {
                response[9] = 0x40;
                response[10] = value;
            }
            _ => {
                response[9] = 0x80;
                response[10] = value;
            }
        }
        if response.len() >= 13 && mutation != 15 && byte(input, 4) & 1 == 0 {
            repair(&mut response, false);
        }
        if byte(input, 4) & 2 != 0 {
            let mut prefix = vec![0x50, 3];
            prefix.extend_from_slice(&response);
            response = prefix;
        }
        if byte(input, 4) & 4 != 0 {
            response.extend_from_slice(&matching(&p));
        }
        let cut = usize::from(byte(input, 5)) % (response.len() + 1);
        fragments(&mut p, &response, cut, 1);
        if p.model.stage == Stage::Confirm {
            let _ = p.step(Op::Confirm, 1);
        }
        let _ = p.step(Op::Tick, 5000);
        p.sticky();
    }

    // Six-byte operations: action, clock selector, argument, payload/control,
    // two operand bytes. Action zero advances a valid path from the model's
    // checkpoint; other actions may violate order, write size or WTX binding.
    fn program(input: &[u8]) {
        let mut p = match byte(input, 0) % 3 {
            0 => Pair::new(),
            1 => Pair::ready(),
            _ => Pair::pending(),
        };
        for word in input.get(1..).unwrap_or_default().chunks(6).take(128) {
            let previous = p.model.last_clock.unwrap_or(0);
            let deadline = p.model.command_deadline;
            let apdu = p.model.apdu_deadline.unwrap_or(30000);
            let now = match byte(word, 1) % 10 {
                0 => previous,
                1 => add(previous, 1),
                2 => previous.saturating_sub(1),
                3 => deadline.saturating_sub(1),
                4 => deadline,
                5 => add(deadline, 1),
                6 => apdu.saturating_sub(1),
                7 => apdu,
                8 => add(apdu, 1),
                _ => u64::MAX,
            };
            let argument = byte(word, 2);
            let payload = [byte(word, 4), byte(word, 5)];
            let op = match byte(word, 0) % 16 {
                0 => match p.model.stage {
                    Stage::Initial(_) => Op::Initial,
                    Stage::Ifs => Op::Ifs(IFS.to_vec()),
                    Stage::Confirm => Op::Confirm,
                    Stage::Idle => Op::Start,
                    Stage::Apdu if p.model.wtx.is_some() => {
                        let m = p.model.wtx.unwrap();
                        Op::Transfer(tpdu(0xe3, &[m]), m)
                    }
                    Stage::Apdu if p.model.transferred => Op::End,
                    Stage::Apdu => Op::Transfer(tpdu(0, &payload), 0),
                    Stage::Write(_) => Op::Written(p.model.request_len),
                    _ => Op::Receive(matching(&p)),
                },
                1 => Op::Initial,
                2 => Op::Ifs(if argument & 1 == 0 {
                    IFS.to_vec()
                } else {
                    tpdu(0xc1, &[argument])
                }),
                3 => Op::Confirm,
                4 => Op::Start,
                5 => Op::Transfer(tpdu(byte(word, 3), &payload), argument),
                6 => Op::End,
                7 => Op::Written(if argument & 1 == 0 {
                    p.model.request_len
                } else {
                    usize::from(argument)
                }),
                8 => Op::Receive(matching(&p)),
                9 => Op::Receive(p.extension(argument)),
                10 => Op::Receive(p.transfer_reply(&tpdu(0xc3, &[argument]))),
                11 => Op::Receive(word.get(2..).unwrap_or_default().to_vec()),
                12 => Op::Receive(Vec::new()),
                13 => Op::Transfer(tpdu(0xe3, &[argument]), argument),
                14 => Op::Receive(vec![0x50, argument]),
                _ => Op::Tick,
            };
            if p.step(op, now).is_err() {
                break;
            }
        }
        p.sticky();
    }

    fn ordinary(p: &mut Pair, payload: &[u8], now: u64) {
        p.exact(Op::Start, now);
        p.exact(Op::Transfer(tpdu(0, &[0x55]), 0), now);
        p.exact(Op::Written(18), now);
        p.exact(Op::Receive(p.transfer_reply(payload)), now);
        p.exact(Op::End, now);
    }

    // One-byte selectors deliberately make the deep limits reachable from
    // minimal public seeds instead of requiring hundreds of lucky mutations.
    fn boundaries(input: &[u8]) {
        match byte(input, 0) {
            0xf0 => {
                let mut p = Pair::ready();
                for _ in 5..512 {
                    ordinary(&mut p, &[0], 0);
                }
                assert_eq!(p.model.ordinal, 512);
                p.exact(Op::Start, 0);
                assert_eq!(
                    p.step(Op::Transfer(tpdu(0, &[0x55]), 0), 0),
                    Err(E::CommandLimitExceeded)
                );
                p.sticky();
            }
            0xf1 => {
                let mut p = Pair::ready();
                assert_eq!(p.model.received, 99);
                for _ in 0..119 {
                    ordinary(&mut p, &[0; 261], 0);
                }
                ordinary(&mut p, &[0; 50], 0);
                assert_eq!(p.model.received, 32768);
                p.exact(Op::Start, 0);
                p.exact(Op::Transfer(tpdu(0, &[0x55]), 0), 0);
                p.exact(Op::Written(18), 0);
                p.exact(Op::Receive(Vec::new()), 0);
                assert_eq!(
                    p.step(Op::Receive(vec![3]), 0),
                    Err(W::ReceiveLimitExceeded.into())
                );
                p.sticky();
            }
            0xf2 => {
                let mut p = Pair::pending();
                p.exact(Op::Receive(p.transfer_reply(&tpdu(0xc3, &[24]))), 1);
                p.exact(Op::Transfer(tpdu(0xe3, &[24]), 24), 100);
                p.exact(Op::Written(18), 100);
                assert_eq!(p.model.allowance, 28560);
                assert_eq!(p.model.command_deadline, 28660);
                p.exact(Op::Receive(p.extension(255)), 6000);
                p.exact(Op::Receive(p.transfer_reply(&tpdu(0xc3, &[2]))), 28000);
                p.exact(Op::Transfer(tpdu(0xe3, &[2]), 2), 28000);
                p.exact(Op::Written(18), 28000);
                assert_eq!(p.model.allowance, 5000);
                assert_eq!(p.model.command_deadline, 30000);
                if byte(input, 1) & 1 == 0 {
                    p.exact(Op::Receive(p.transfer_reply(&tpdu(0, &[0x90, 0]))), 29999);
                    p.exact(Op::End, 29999);
                } else {
                    p.exact(Op::Receive(vec![3]), 29999);
                    assert_eq!(p.step(Op::Tick, 30000), Err(E::ApduDeadlineExceeded));
                }
                p.sticky();
            }
            0xf3 => {
                let mut p = Pair::pending();
                for m in [0, 1, 2, 255] {
                    p.exact(Op::Receive(p.extension(m)), 1);
                }
                p.exact(Op::Receive(p.transfer_reply(&tpdu(0xc3, &[1]))), 1);
                p.exact(Op::Transfer(tpdu(0xe3, &[1]), 1), 2);
                p.exact(Op::Written(18), 2);
                for m in [255, 2, 1, 0] {
                    p.exact(Op::Receive(p.extension(m)), 3);
                }
                assert_eq!(p.model.apdu_extensions, 8);
                if byte(input, 1) & 1 == 0 {
                    assert_eq!(
                        p.step(Op::Receive(p.extension(0)), 3),
                        Err(E::TimeExtensionLimitExceeded)
                    );
                } else {
                    p.exact(Op::Receive(p.transfer_reply(&tpdu(0, &[0x90, 0]))), 3);
                    p.exact(Op::End, 3);
                    p.exact(Op::Start, 4);
                    assert_eq!(p.model.apdu_extensions, 0);
                    assert_eq!(p.model.extensions, 8);
                    p.exact(Op::Transfer(tpdu(0, &[0x55]), 0), 4);
                    p.exact(Op::Written(18), 4);
                    p.exact(Op::Receive(p.extension(255)), 4);
                }
                p.sticky();
            }
            0xf4 => {
                let mut p = Pair::pending();
                let mut bytes = vec![0x50, 0x0f];
                bytes.extend(p.extension(0));
                bytes.extend(p.extension(255));
                bytes.extend(p.transfer_reply(&tpdu(0, &[0x90, 0])));
                let cut = usize::from(byte(input, 1)) % (bytes.len() + 1);
                fragments(&mut p, &bytes, cut, 1);
                assert_eq!(p.model.error, None);
                assert_eq!(
                    p.model.span,
                    Some(RawFrameSpan {
                        start_rx_offset: 127,
                        end_rx_offset: 146
                    })
                );
                p.exact(Op::End, 1);
            }
            0xf5 => {
                let mut p = Pair::pending();
                let m = [0, 1, 2, 24, 25, 255][usize::from(byte(input, 1)) % 6];
                p.exact(Op::Receive(p.transfer_reply(&tpdu(0xc3, &[m]))), 1);
                let op = match byte(input, 2) % 5 {
                    0 => Op::Transfer(tpdu(0xe3, &[m]), m),
                    1 => Op::Transfer(tpdu(0xe3, &[m ^ 1]), m),
                    2 => Op::Transfer(tpdu(0xe3, &[m]), 0),
                    3 => Op::End,
                    _ => Op::Start,
                };
                let _ = p.step(op, 1);
                p.sticky();
            }
            0xf6 => {
                let mut p = Pair::pending();
                let mut events = Vec::new();
                for _ in 0..64 {
                    events.extend_from_slice(&[0x50, 3]);
                }
                p.exact(Op::Receive(events), 1);
                if byte(input, 1) & 1 == 0 {
                    assert_eq!(
                        p.step(Op::Receive(vec![0x50, 3]), 1),
                        Err(W::EventLimitExceeded.into())
                    );
                } else {
                    p.exact(Op::Receive(p.transfer_reply(&[0])), 1);
                    p.exact(Op::End, 1);
                    p.exact(Op::Start, 1);
                    p.exact(Op::Transfer(tpdu(0, &[0]), 0), 1);
                    p.exact(Op::Written(18), 1);
                    assert_eq!(
                        p.step(Op::Receive(vec![0x50, 3]), 1),
                        Err(W::EventLimitExceeded.into())
                    );
                }
                p.sticky();
            }
            0xf7 => {
                let mut p = Pair::ready();
                p.exact(Op::Start, 0);
                let n = if byte(input, 1) & 1 == 0 { 254 } else { 255 };
                let result = p.step(Op::Transfer(tpdu(0, &vec![0x55; n]), 0), 0);
                if n == 254 {
                    assert_eq!(result, Ok(()));
                    p.exact(Op::Written(271), 0);
                    let response =
                        p.transfer_reply(&vec![0; if byte(input, 2) & 1 == 0 { 261 } else { 262 }]);
                    let _ = p.step(Op::Receive(response), 1);
                } else {
                    assert_eq!(result, Err(E::TransferPayloadRejected));
                }
                p.sticky();
            }
            _ => {}
        }
    }

    pub(super) fn exercise(input: &[u8]) {
        hostile(input);
        program(input);
        boundaries(input);
    }
}
