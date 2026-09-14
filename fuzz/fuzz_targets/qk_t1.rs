#![no_main]
// Public synthetic inputs only. Two independently expressed batch/state oracles;
// no bench code, native transport, host clock, signing operation or fixture key.
use libfuzzer_sys::fuzz_target;
use qk_sec1210_wire::{
    Error as W, ReadbackCommand as C, ReadbackError as E, ReadbackObservation as O,
    ReadbackPhase as P, ReadbackSession as Wire,
};
use qk_t1::{Error as T, Phase as Q, Received, Session as T1};

const ATR: [u8; 15] = [
    0x3b, 0xd5, 0x18, 0xff, 0x81, 0x91, 0xfe, 0x1f, 0xc3, 0x80, 0x73, 0xc8, 0x21, 0x10, 0x0a,
];
const PARAMS: [u8; 7] = [0x18, 0x10, 0xff, 0x4d, 3, 0xfe, 0];
// Reference bytes are not imported from the implementation constant.
const FIDI: [u8; 7] = [0x18, 0x10, 0xff, 0x4d, 0, 0xfe, 0];

fn byte(input: &[u8], index: usize) -> u8 {
    input.get(index).copied().unwrap_or(0)
}
fn lrc(bytes: &[u8]) -> u8 {
    bytes.iter().copied().fold(0, |sum, b| sum ^ b)
}
fn tpdu(pcb: u8, body: &[u8]) -> Vec<u8> {
    let mut v = vec![0, pcb, body.len() as u8];
    v.extend_from_slice(body);
    v.push(lrc(&v));
    v
}

#[derive(Debug, PartialEq, Eq)]
enum TFact<'a> {
    I(u8, bool, &'a [u8]),
    R(u8),
    Ifs,
}

// Table-oriented complete-block oracle, not the implementation's PCB decoder.
fn t_decode(bytes: &[u8]) -> Result<TFact<'_>, T> {
    t_decode_bound(bytes, 36, false)
}
fn t_decode_bound(bytes: &[u8], bound: usize, awaiting_ifs: bool) -> Result<TFact<'_>, T> {
    if bytes.len() < 4 || bytes.len() > bound || bytes.len() != usize::from(bytes[2]) + 4 {
        return Err(T::BlockLengthRejected);
    }
    if lrc(bytes) != 0 {
        return Err(T::ChecksumRejected);
    }
    if bytes[0] != 0 {
        return Err(T::NadRejected);
    }
    let payload = &bytes[3..bytes.len() - 1];
    match bytes[1] {
        0 | 0x20 | 0x40 | 0x60 => Ok(TFact::I(
            u8::from(bytes[1] >= 0x40),
            matches!(bytes[1], 0x20 | 0x60),
            payload,
        )),
        0x80 | 0x81 | 0x82 | 0x90 | 0x91 | 0x92 => {
            if !payload.is_empty() {
                Err(T::ControlLengthRejected)
            } else if matches!(bytes[1], 0x81 | 0x82 | 0x91 | 0x92) {
                Err(T::RetransmissionRejected)
            } else {
                Ok(TFact::R(u8::from(bytes[1] == 0x90)))
            }
        }
        0xc0 | 0xe0 | 0xc1 | 0xe1 | 0xc2 | 0xe2 | 0xc3 | 0xe3 => {
            if awaiting_ifs && bytes[1] == 0xe1 && payload == [0xfe] {
                return Ok(TFact::Ifs);
            }
            let (size, error) = match bytes[1] % 4 {
                0 => (0, T::ResynchRejected),
                1 => (1, T::IfsRejected),
                2 => (0, T::AbortRejected),
                _ => (1, T::WtxRejected),
            };
            Err(if payload.len() == size {
                error
            } else {
                T::ControlLengthRejected
            })
        }
        _ => Err(T::PcbRejected),
    }
}
fn check_t_decode(bytes: &[u8]) {
    let actual = qk_t1::decode(bytes).map(|value| match value {
        Received::I {
            sequence,
            more,
            inf,
        } => TFact::I(sequence, more, inf),
        Received::R { sequence } => TFact::R(sequence),
    });
    assert_eq!(actual, t_decode(bytes));
}

#[derive(Default)]
struct TModel {
    // 0 idle, 1 claimable, 2 awaiting write result, 3 awaiting response,
    // 4 complete, 5 terminal. Buffers are independent dynamic reference values.
    stage: u8,
    ns: u8,
    nr: u8,
    acknowledged: bool,
    wanted: Vec<u8>,
    prefix: Vec<u8>,
    outgoing: Vec<u8>,
    exchanges: usize,
    complete: usize,
    start: u64,
    last: Option<u64>,
    error: Option<T>,
    ifs_mode: bool,
    ifs_pending: bool,
    ifs_accepted: bool,
}
impl TModel {
    fn with_ifs() -> Self {
        Self {
            ifs_mode: true,
            ..Self::default()
        }
    }
    fn bound(&self) -> usize {
        if self.ifs_accepted {
            258
        } else {
            36
        }
    }
    fn reject<U>(&mut self, error: T) -> Result<U, T> {
        self.stage = 5;
        Err(*self.error.get_or_insert(error))
    }
    fn clock(&mut self, now: u64) -> Result<(), T> {
        if let Some(error) = self.error {
            return Err(error);
        }
        if self.last.is_some_and(|last| last > now) {
            return self.reject(T::ClockRegression);
        }
        self.last = Some(now);
        let budget = if self.ifs_pending { 5000 } else { 30_000 };
        if (1..=3).contains(&self.stage) && now - self.start >= budget {
            return self.reject(T::DeadlineExceeded);
        }
        Ok(())
    }
    fn begin(&mut self, command: &[u8], wanted: &[u8], now: u64) -> Result<(), T> {
        if self.error.is_some()
            || !matches!(self.stage, 0 | 4)
            || (self.ifs_mode && !self.ifs_accepted)
        {
            return self.reject(T::StateRejected);
        }
        self.clock(now)?;
        if self.complete == 8 {
            return self.reject(T::ApduLimitExceeded);
        }
        if command.is_empty() || command.len() > 30 {
            return self.reject(T::CommandLengthRejected);
        }
        if wanted.is_empty() || wanted.len() > 218 {
            return self.reject(T::ResponseLengthRejected);
        }
        self.wanted = wanted.to_vec();
        self.prefix.clear();
        self.acknowledged = false;
        self.exchanges = 0;
        self.start = now;
        self.outgoing = tpdu(64 * self.ns, command);
        self.stage = 1;
        Ok(())
    }
    fn begin_ifs(&mut self, now: u64) -> Result<(), T> {
        if self.error.is_some()
            || !self.ifs_mode
            || self.ifs_pending
            || self.ifs_accepted
            || self.stage != 0
        {
            return self.reject(T::StateRejected);
        }
        self.clock(now)?;
        self.ifs_pending = true;
        self.start = now;
        self.outgoing = vec![0, 0xc1, 1, 0xfe, 0x3e];
        self.stage = 1;
        Ok(())
    }
    fn next(&mut self, now: u64) -> Result<Vec<u8>, T> {
        self.clock(now)?;
        if self.stage != 1 {
            return self.reject(T::StateRejected);
        }
        if self.exchanges == 16 {
            return self.reject(T::ExchangeLimitExceeded);
        }
        self.stage = 2;
        Ok(self.outgoing.clone())
    }
    fn written(&mut self, count: usize, now: u64) -> Result<(), T> {
        if self.error.is_some() || self.stage != 2 {
            return self.reject(T::StateRejected);
        }
        if count != self.outgoing.len() {
            return self.reject(T::PartialWrite);
        }
        self.exchanges += 1;
        self.clock(now)?;
        self.stage = 3;
        Ok(())
    }
    fn receive(&mut self, bytes: &[u8], now: u64) -> Result<(), T> {
        self.clock(now)?;
        if self.stage != 3 {
            if self.ifs_mode {
                if let Err(error) = t_decode_bound(bytes, self.bound(), false) {
                    return self.reject(error);
                }
            }
            return self.reject(T::StateRejected);
        }
        let decoded = t_decode_bound(bytes, self.bound(), self.ifs_pending);
        if self.ifs_pending {
            match decoded {
                Ok(TFact::Ifs) => {
                    self.ifs_pending = false;
                    self.ifs_accepted = true;
                    self.outgoing.clear();
                    self.stage = 0;
                    return Ok(());
                }
                Ok(TFact::I(..)) => return self.reject(T::IfsRejected),
                Ok(TFact::R(_)) => return self.reject(T::UnexpectedRBlock),
                Err(error) => return self.reject(error),
            }
        }
        let (sequence, more, data) = match decoded {
            Ok(TFact::I(s, m, d)) => (s, m, d),
            Ok(TFact::R(_)) => return self.reject(T::UnexpectedRBlock),
            Ok(TFact::Ifs) => unreachable!("IFS is decoded only while negotiating"),
            Err(error) => return self.reject(error),
        };
        if sequence != self.nr {
            return self.reject(T::SequenceRejected);
        }
        let end = self.prefix.len() + data.len();
        if end > self.wanted.len() {
            return self.reject(T::ResponseLengthRejected);
        }
        if self.wanted[self.prefix.len()..end] != *data {
            return self.reject(T::ResponseMismatch);
        }
        if more == (end == self.wanted.len()) {
            return self.reject(T::ResponseLengthRejected);
        }
        self.prefix.extend_from_slice(data);
        if !self.acknowledged {
            self.ns = 1 - self.ns;
            self.acknowledged = true;
        }
        self.nr = 1 - self.nr;
        if more {
            if self.exchanges == 16 {
                return self.reject(T::ExchangeLimitExceeded);
            }
            self.outgoing = tpdu(0x80 + 16 * self.nr, &[]);
            self.stage = 1;
        } else {
            self.outgoing.clear();
            self.complete += 1;
            self.stage = 4;
        }
        Ok(())
    }
    fn check(&self, actual: &T1) {
        let phase = [
            Q::Idle,
            Q::Ready,
            Q::Writing,
            Q::Receiving,
            Q::Complete,
            Q::Failed,
        ];
        assert_eq!(actual.phase(), phase[self.stage as usize]);
        assert_eq!(actual.failure(), self.error);
        assert_eq!(actual.send_sequence(), self.ns);
        assert_eq!(actual.receive_sequence(), self.nr);
        assert_eq!(actual.exchanges(), self.exchanges);
        assert_eq!(actual.completed_apdus(), self.complete);
        assert_eq!(actual.response_prefix(), self.prefix);
        assert_eq!(actual.ifs_accepted(), self.ifs_accepted);
        assert_eq!(actual.receive_bound(), self.bound());
    }
}

// A batch cursor over complete CCID frames and events. The only pre-checksum
// header interpretation is the untrusted bounded length; semantic validation
// receives header/payload bytes only after this cursor verifies the checksum.
enum WireFact {
    Response(Vec<u8>),
    Bitmap(u8),
    Hardware(u8, u8, u8),
}
fn wire_next(bytes: &[u8]) -> Result<Option<(WireFact, usize)>, W> {
    let Some(first) = bytes.first() else {
        return Ok(None);
    };
    let needed = match first {
        0x50 => 2,
        0x51 => 4,
        3 => match bytes.get(1) {
            None => return Ok(None),
            Some(0x15) => 3,
            Some(6) => {
                if bytes.len() < 7 {
                    return Ok(None);
                }
                let length = bytes[3..7]
                    .iter()
                    .rev()
                    .fold(0u64, |n, b| n * 256 + u64::from(*b));
                if length > 261 {
                    return Err(W::LengthExceeded);
                }
                13 + length as usize
            }
            _ => return Err(W::PrefixRejected),
        },
        _ => return Err(W::PrefixRejected),
    };
    if bytes.len() < needed {
        return Ok(None);
    }
    let fact = match first {
        0x50 => WireFact::Bitmap(bytes[1]),
        0x51 => WireFact::Hardware(bytes[1], bytes[2], bytes[3]),
        _ => {
            if lrc(&bytes[..needed]) != 0 {
                return Err(W::ChecksumRejected);
            }
            if bytes[1] == 0x15 {
                return Err(W::Nack);
            }
            WireFact::Response(bytes[2..needed - 1].to_vec())
        }
    };
    Ok(Some((fact, needed)))
}
fn ccid(kind: u8, seq: u8, status: u8, parameter: u8, payload: &[u8]) -> Vec<u8> {
    let mut v = vec![3, 6, kind];
    v.extend_from_slice(&(payload.len() as u32).to_le_bytes());
    v.extend_from_slice(&[0, seq, status, 0, parameter]);
    v.extend_from_slice(payload);
    v.push(lrc(&v));
    v
}
fn response(command: usize, seq: u8, payload: &[u8]) -> Vec<u8> {
    match command {
        0 => ccid(0x81, seq, 1, 0xff, &[]),
        1 => ccid(0x80, seq, 0, 0, &ATR),
        2 => ccid(0x82, seq, 0, 1, &PARAMS),
        _ => ccid(0x80, seq, 0, 0, payload),
    }
}

#[derive(Default)]
struct WModel {
    // stage is 0 ready, 1 awaiting write result, 2 receiving, 3 terminal;
    // command is the independently advanced initialization index or transfer 3.
    stage: u8,
    command: usize,
    seq: u8,
    request_len: usize,
    requests: usize,
    responses: usize,
    events: usize,
    received: usize,
    pending: Vec<u8>,
    accepted: Option<Vec<u8>>,
    observations: Vec<O>,
    start: u64,
    last: Option<u64>,
    error: Option<E>,
    fidi: bool,
    parameters_evidence: Option<Vec<u8>>,
    parameters_accepted: bool,
}
impl WModel {
    fn with_fidi() -> Self {
        Self {
            fidi: true,
            ..Self::default()
        }
    }
    fn setting_parameters(&self) -> bool {
        self.fidi && self.command == 3
    }
    fn transfer_index(&self) -> usize {
        if self.fidi {
            4
        } else {
            3
        }
    }
    fn reply(&self, payload: &[u8]) -> Vec<u8> {
        if self.setting_parameters() {
            ccid(0x82, self.seq, 0, 1, &FIDI)
        } else {
            response(self.command, self.seq, payload)
        }
    }
    fn reject<U>(&mut self, error: impl Into<E>) -> Result<U, E> {
        self.stage = 3;
        Err(*self.error.get_or_insert(error.into()))
    }
    fn clock(&mut self, now: u64) -> Result<(), E> {
        if let Some(error) = self.error {
            return Err(error);
        }
        if self.last.is_some_and(|last| last > now) {
            return self.reject(W::ClockRegression);
        }
        self.last = Some(now);
        if matches!(self.stage, 1 | 2) && now - self.start >= 5000 {
            return self.reject(if self.pending.is_empty() {
                W::DeadlineExceeded
            } else {
                W::PartialFrameDeadline
            });
        }
        Ok(())
    }
    fn begin(&mut self, payload: Option<&[u8]>, now: u64) -> Result<Vec<u8>, E> {
        self.clock(now)?;
        if self.stage != 0 || payload.is_some() != (self.command == self.transfer_index()) {
            return self.reject(E::StateRejected);
        }
        let body = payload.unwrap_or(if self.setting_parameters() {
            &FIDI
        } else {
            &[]
        });
        if payload.is_some()
            && (body.len() < 4
                || body.len() > 34
                || usize::from(body[2]) + 4 != body.len()
                || lrc(body) != 0)
        {
            return self.reject(E::TransferPayloadRejected);
        }
        if self.requests == 128 {
            return self.reject(E::CommandLimitExceeded);
        }
        self.seq = (self.requests + 1) as u8;
        let value = ccid(
            if self.setting_parameters() {
                0x61
            } else {
                [0x65, 0x62, 0x6c, 0x6f][self.command.min(3)]
            },
            self.seq,
            if self.command == 1 {
                2
            } else {
                u8::from(self.setting_parameters())
            },
            0,
            body,
        );
        self.request_len = value.len();
        self.accepted = None;
        self.start = now;
        self.stage = 1;
        Ok(value)
    }
    fn written(&mut self, count: usize, now: u64) -> Result<(), E> {
        if self.error.is_some() || self.stage != 1 {
            return self.reject(E::StateRejected);
        }
        if count != self.request_len {
            return self.reject(W::PartialWrite);
        }
        self.requests += 1;
        self.clock(now)?;
        self.stage = 2;
        Ok(())
    }
    fn validate(&mut self, r: &[u8]) -> Result<(), E> {
        let errors = [
            (r[5] != 0, W::SlotRejected),
            (r[6] != self.seq, W::SequenceRejected),
            (
                r[7] & 60 != 0 || r[7] % 4 == 3 || r[7] / 64 == 3,
                W::StatusReserved,
            ),
            (r[7] / 64 == 2, W::TimeExtensionRejected),
            (r[7] / 64 == 1, W::CommandFailed),
            (
                r[0] != if self.setting_parameters() {
                    0x82
                } else {
                    [0x81, 0x80, 0x82, 0x80][self.command.min(3)]
                },
                W::ResponseTypeRejected,
            ),
            (r[8] != 0, W::StatusErrorRejected),
            (r[7] % 4 == 2, W::CardAbsent),
            (self.command == 0 && r[7] % 4 == 0, W::AlreadyActive),
            (self.command != 0 && r[7] % 4 != 0, W::IccStatusRejected),
        ];
        if let Some((_, error)) = errors.iter().find(|(failed, _)| *failed) {
            return Err((*error).into());
        }
        match self.command {
            0 => {
                if r.len() != 10 {
                    return Err(W::PayloadRejected.into());
                }
                self.observations.push(O::SlotStatus {
                    status: r[7],
                    error: r[8],
                    clock: r[9],
                });
            }
            c if c == 1 || c == self.transfer_index() => {
                if r[9] != 0 {
                    return Err(W::ChainingRejected.into());
                }
                if self.command == 1 {
                    if r[10..] != ATR {
                        return Err(W::AtrRejected.into());
                    }
                    self.observations.push(O::Atr(ATR));
                } else {
                    self.observations.push(O::Transfer {
                        sequence: r[6],
                        payload_bytes: r.len() - 10,
                    });
                }
            }
            _ => {
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
                if self.setting_parameters() {
                    if bytes != FIDI {
                        return Err(E::SetParametersEchoRejected);
                    }
                    return Ok(());
                }
                if bytes[5] != 254 {
                    return Err(E::IfscRejected);
                }
                if bytes[1] % 2 != 0 {
                    return Err(E::LrcModeRejected);
                }
            }
        }
        Ok(())
    }
    fn receive(&mut self, data: &[u8], now: u64) -> Result<(), E> {
        self.clock(now)?;
        if self.stage != 2 {
            return self.reject(W::UnsolicitedResponse);
        }
        if self.received + data.len() > 8192 {
            return self.reject(W::ReceiveLimitExceeded);
        }
        self.received += data.len();
        self.pending.extend_from_slice(data);
        loop {
            let (fact, length) = match wire_next(&self.pending) {
                Ok(Some(value)) => value,
                Ok(None) => return Ok(()),
                Err(error) => return self.reject(error),
            };
            match fact {
                WireFact::Bitmap(bitmap) => {
                    self.events += 1;
                    if self.events > 64 {
                        return self.reject(W::EventLimitExceeded);
                    }
                    self.observations.push(O::SlotChange {
                        bitmap,
                        slot1_bits: (bitmap / 4) % 4,
                    });
                    if bitmap > 15 {
                        return self.reject(W::EventBitmapRejected);
                    }
                    if bitmap % 2 == 0 {
                        return self.reject(W::CardAbsent);
                    }
                }
                WireFact::Hardware(slot, sequence, code) => {
                    self.events += 1;
                    if self.events > 64 {
                        return self.reject(W::EventLimitExceeded);
                    }
                    self.observations.push(O::HardwareError {
                        slot,
                        sequence,
                        code,
                    });
                    if slot != 0 {
                        return self.reject(W::SlotRejected);
                    }
                    if sequence != self.seq {
                        return self.reject(W::SequenceRejected);
                    }
                    return self.reject(W::HardwareError);
                }
                WireFact::Response(r) => {
                    if self.setting_parameters() {
                        self.parameters_evidence = Some(r.clone());
                    }
                    if let Err(error) = self.validate(&r) {
                        return self.reject(error);
                    }
                    if length != self.pending.len() {
                        return self.reject(W::TrailingData);
                    }
                    self.responses += 1;
                    if self.setting_parameters() {
                        self.parameters_accepted = true;
                    }
                    self.accepted = Some(r);
                    self.command = (self.command + 1).min(self.transfer_index());
                    self.stage = 0;
                }
            }
            self.pending.drain(..length);
            if self.pending.is_empty() {
                return Ok(());
            }
        }
    }
    fn check(&self, actual: &Wire) {
        let c = if self.setting_parameters() {
            C::SetParameters
        } else {
            [C::GetSlotStatus, C::PowerOn, C::GetParameters, C::XfrBlock][self.command.min(3)]
        };
        let phase = match self.stage {
            0 if self.setting_parameters() => P::ReadySetParameters,
            0 => [
                P::ReadyStatus,
                P::ReadyPower,
                P::ReadyParameters,
                P::ReadyTransfer,
            ][self.command.min(3)],
            1 => P::Writing(c),
            2 => P::Receiving(c),
            _ => P::Failed,
        };
        assert_eq!(actual.phase(), phase);
        assert_eq!(actual.failure(), self.error);
        assert_eq!(actual.sequence(), self.seq);
        assert_eq!(actual.requests(), self.requests);
        assert_eq!(actual.responses(), self.responses);
        assert_eq!(actual.events(), self.events);
        assert_eq!(actual.received_bytes(), self.received);
        assert_eq!(actual.observations(), self.observations);
        assert!(actual.observations().len() <= 192);
        let got = actual.response().map(|r| {
            let mut v = vec![r.message_type];
            v.extend_from_slice(&(r.payload().len() as u32).to_le_bytes());
            v.extend_from_slice(&[r.slot, r.sequence, r.status, r.error, r.parameter]);
            v.extend_from_slice(r.payload());
            v
        });
        assert_eq!(got, self.accepted);
        let evidence = actual.set_parameters_reply_evidence().map(|r| {
            let mut v = vec![r.message_type];
            v.extend_from_slice(&(r.payload().len() as u32).to_le_bytes());
            v.extend_from_slice(&[r.slot, r.sequence, r.status, r.error, r.parameter]);
            v.extend_from_slice(r.payload());
            v
        });
        assert_eq!(evidence, self.parameters_evidence);
        assert_eq!(actual.set_parameters_accepted(), self.parameters_accepted);
    }
}

fn w_begin(a: &mut Wire, m: &mut WModel, body: Option<&[u8]>, now: u64) {
    let got = match body {
        Some(b) => a.begin_transfer(b, now),
        None => a.begin_initial(now),
    };
    assert_eq!(got.map(|r| r.as_bytes().to_vec()), m.begin(body, now));
    m.check(a);
}
fn w_written(a: &mut Wire, m: &mut WModel, n: usize, now: u64) {
    assert_eq!(a.written(n, now), m.written(n, now));
    m.check(a);
}
fn w_receive(a: &mut Wire, m: &mut WModel, bytes: &[u8], now: u64) {
    assert_eq!(a.receive(bytes, now), m.receive(bytes, now));
    m.check(a);
}
fn w_ready(command: usize) -> (Wire, WModel) {
    w_ready_mode(command, false)
}
fn w_ready_mode(command: usize, fidi: bool) -> (Wire, WModel) {
    let (mut a, mut m) = if fidi {
        (Wire::with_fidi(), WModel::with_fidi())
    } else {
        (Wire::default(), WModel::default())
    };
    for _ in 0..command {
        w_begin(&mut a, &mut m, None, 0);
        let count = m.request_len;
        w_written(&mut a, &mut m, count, 0);
        let raw = m.reply(&[]);
        w_receive(&mut a, &mut m, &raw, 0);
    }
    (a, m)
}

fn hostile_fidi_wire(input: &[u8]) {
    // The whole hostile input reaches the opt-in Parameters gate, not only
    // default initialization. Repaired-checksum cases expose precedence and
    // preserve the raw bError evidence independently of response acceptance.
    let mut mutated = ccid(0x82, 4, 0, 1, &FIDI);
    for pair in input.as_chunks::<2>().0.iter().take(24) {
        let index = [2, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18][usize::from(pair[0] % 13)];
        mutated[index] ^= pair[1];
    }
    let last = mutated.len() - 1;
    mutated[last] = lrc(&mutated[..last]);
    let mut alternative = match byte(input, 0) % 6 {
        0 => mutated,
        1 => ccid(0x82, 4, 0x40, 1, &[]),
        2 => ccid(0x81, 4, 0x80, 0, &[]),
        3 => ccid(0x82, 4, 0, 1, &input[..input.len().min(261)]),
        4 => ccid(0x82, 4, 0, 1, &FIDI[..usize::from(byte(input, 1) % 7)]),
        _ => ccid(0x82, 4, 0, 1, &FIDI),
    };
    if matches!(byte(input, 0) % 6, 1 | 2) {
        alternative[10] = byte(input, 2);
        let last = alternative.len() - 1;
        alternative[last] = lrc(&alternative[..last]);
    }
    if byte(input, 3) & 1 != 0 {
        alternative.splice(..0, [0x50, 0x0f]);
    }
    if byte(input, 4) & 1 != 0 {
        alternative.extend_from_slice(&ccid(0x82, 4, 0, 1, &FIDI));
    }
    for raw in [input, alternative.as_slice()] {
        let (mut actual, mut model) = w_ready_mode(3, true);
        w_begin(&mut actual, &mut model, None, 0);
        w_written(&mut actual, &mut model, 20, 0);
        let split = usize::from(byte(input, 5)) % (raw.len() + 1);
        w_receive(&mut actual, &mut model, &raw[..split], 1);
        let now = [1, 2, 4999, 5000, u64::MAX][usize::from(byte(input, 6) % 5)];
        w_receive(&mut actual, &mut model, &raw[split..], now);
        w_begin(&mut actual, &mut model, None, now);
        w_receive(&mut actual, &mut model, &[], u64::MAX);
    }

    // Starting before or after baseline initialization gives the operation
    // program both premature and post-ATR SetParameters ordering to attack.
    for start in [0, 3, 4] {
        let (mut actual, mut model) = w_ready_mode(start, true);
        for op in input.chunks(4).take(160) {
            let y = byte(op, 1);
            let now = [0, 1, 4999, 5000, u64::MAX][usize::from(y % 5)];
            match byte(op, 0) % 7 {
                0 => w_begin(&mut actual, &mut model, None, now),
                1 => w_begin(
                    &mut actual,
                    &mut model,
                    Some(&[0, 0xc1, 1, 0xfe, 0x3e]),
                    now,
                ),
                2 => {
                    let n = if y & 1 == 0 {
                        model.request_len
                    } else {
                        usize::from(y)
                    };
                    w_written(&mut actual, &mut model, n, now);
                }
                3 => {
                    let raw = model.reply(&[0, 0xe1, 1, 0xfe, 0x1e]);
                    w_receive(&mut actual, &mut model, &raw, now);
                }
                4 => w_receive(&mut actual, &mut model, &alternative, now),
                5 => w_receive(&mut actual, &mut model, &[0x50, y], now),
                _ => {
                    assert_eq!(actual.tick(now), model.clock(now));
                    model.check(&actual);
                }
            }
        }
    }
}

fn hostile_wire(input: &[u8]) {
    let command = usize::from(byte(input, 0) % 4);
    let payload = tpdu(0, &[0]);
    let body = (command == 3).then_some(payload.as_slice());
    let (mut a, mut m) = w_ready(command);
    w_begin(&mut a, &mut m, body, 0);
    w_written(&mut a, &mut m, 13 + body.map_or(0, <[u8]>::len), 0);
    w_receive(&mut a, &mut m, input, 1);
    w_receive(&mut a, &mut m, &[], 5000);
    w_begin(&mut a, &mut m, None, 0); // First failure remains sticky.

    // Mutations preserve the wire checksum to expose semantic precedence.
    let mut bytes = response(command, command as u8 + 1, &tpdu(0, &[0x90, 0]));
    for pair in input.chunks_exact(2).take(16) {
        let index = match pair[0] % 7 {
            0 => 2,
            1 => 7,
            2 => 8,
            3 => 9,
            4 => 10,
            5 => 11,
            _ => 12 + usize::from(pair[0]) % (bytes.len() - 12),
        };
        bytes[index] ^= pair[1];
    }
    let last = bytes.len() - 1;
    bytes[last] = lrc(&bytes[..last]);
    let (mut a, mut m) = w_ready(command);
    w_begin(&mut a, &mut m, body, 10);
    w_written(&mut a, &mut m, 13 + body.map_or(0, <[u8]>::len), 10);
    let split = usize::from(byte(input, 1)) % (bytes.len() + 1);
    w_receive(&mut a, &mut m, &bytes[..split], 11);
    w_receive(&mut a, &mut m, &bytes[split..], 12);
    w_receive(&mut a, &mut m, &[], 5010);

    // Operation programs include malformed writes, deadline/clock faults,
    // events coalesced before a response and every new initialization state.
    let (mut a, mut m) = (Wire::default(), WModel::default());
    for op in input.chunks(5).take(160) {
        let x = byte(op, 0);
        let y = byte(op, 1);
        let now = [0, 1, 4999, 5000, 30_000, u64::MAX][usize::from(y % 6)];
        match x % 7 {
            0 => w_begin(&mut a, &mut m, None, now),
            1 => w_begin(&mut a, &mut m, Some(&payload), now),
            2 => {
                let count = if y & 1 == 0 {
                    m.request_len
                } else {
                    usize::from(y)
                };
                w_written(&mut a, &mut m, count, now);
            }
            3 => {
                let bytes = response(m.command, m.seq, &tpdu(0, &[0]));
                w_receive(&mut a, &mut m, &bytes, now);
            }
            4 => w_receive(&mut a, &mut m, &op[1..], now),
            5 => w_receive(&mut a, &mut m, &[0x50, y], now),
            _ => {
                assert_eq!(a.tick(now), m.clock(now));
                m.check(&a);
            }
        }
    }

    // Event accounting is invocation-wide, including an event coalesced with
    // the command response; boundary 65 must fail before retaining that event.
    let (mut a, mut m) = w_ready(2);
    w_begin(&mut a, &mut m, None, 0);
    w_written(&mut a, &mut m, 13, 0);
    let events = usize::from(byte(input, 0) % 67);
    let mut bytes = vec![0x50, 0x0f].repeat(events);
    bytes.extend_from_slice(&response(2, 3, &[]));
    w_receive(&mut a, &mut m, &bytes, 1);
}

fn hostile_t1(input: &[u8]) {
    check_t_decode(input);
    let len = usize::from(byte(input, 0) % 33);
    let mut frame = tpdu(
        byte(input, 1),
        &input.iter().copied().cycle().take(len).collect::<Vec<_>>(),
    );
    if !input.is_empty() {
        frame[0] = byte(input, 2);
        let end = frame.len() - 1;
        frame[end] = lrc(&frame[..end]);
    }
    check_t_decode(&frame);
    for (sequence, command) in [
        (byte(input, 0) % 4, &input[..input.len().min(31)]),
        (0, &[0x80, 0xca][..]),
    ] {
        let expected = if command.is_empty() || command.len() > 30 {
            Err(T::CommandLengthRejected)
        } else if sequence > 1 {
            Err(T::SequenceRejected)
        } else {
            Ok(tpdu(64 * sequence, command))
        };
        assert_eq!(
            qk_t1::encode_command(command, sequence).map(|b| b.as_bytes().to_vec()),
            expected
        );
        let ack = if sequence > 1 {
            Err(T::SequenceRejected)
        } else {
            Ok(tpdu(0x80 + 16 * sequence, &[]))
        };
        assert_eq!(
            qk_t1::encode_ack(sequence).map(|b| b.as_bytes().to_vec()),
            ack
        );
    }
    let (mut a, mut m) = (T1::default(), TModel::default());
    for op in input.chunks(5).take(160) {
        let x = byte(op, 0);
        let y = byte(op, 1);
        let now = [0, 1, 29_999, 30_000, u64::MAX][usize::from(y % 5)];
        match x % 6 {
            0 => assert_eq!(
                a.begin(&op[1..], &[0x90, 0], now),
                m.begin(&op[1..], &[0x90, 0], now)
            ),
            1 => assert_eq!(
                a.next_block(now).map(|b| b.as_bytes().to_vec()),
                m.next(now)
            ),
            2 => {
                let size = if y & 1 == 0 {
                    m.outgoing.len()
                } else {
                    usize::from(y)
                };
                assert_eq!(a.written(size, now), m.written(size, now));
            }
            3 => assert_eq!(a.receive(&frame, now), m.receive(&frame, now)),
            4 => assert_eq!(
                a.receive(&tpdu(64 * m.nr, &[0x90, 0]), now),
                m.receive(&tpdu(64 * m.nr, &[0x90, 0]), now)
            ),
            _ => assert_eq!(a.tick(now), m.clock(now)),
        }
        m.check(&a);
    }
}

fn t_ifs_ready() -> (T1, TModel) {
    let (mut actual, mut model) = (T1::with_ifs(), TModel::with_ifs());
    assert_eq!(actual.begin_ifs(0), model.begin_ifs(0));
    model.check(&actual);
    assert_eq!(
        actual.next_block(0).map(|block| block.as_bytes().to_vec()),
        model.next(0)
    );
    model.check(&actual);
    assert_eq!(actual.written(5, 0), model.written(5, 0));
    model.check(&actual);
    (actual, model)
}

fn t_receive(actual: &mut T1, model: &mut TModel, bytes: &[u8], now: u64) {
    assert_eq!(actual.receive(bytes, now), model.receive(bytes, now));
    model.check(actual);
}

fn hostile_ifs(input: &[u8]) {
    // Whole input and field mutations run against a separate negotiation path.
    // The exact echo is the only value that can change the model's bound.
    let (mut actual, mut model) = t_ifs_ready();
    t_receive(&mut actual, &mut model, input, 1);
    assert_eq!(actual.begin_ifs(1), model.begin_ifs(1));
    model.check(&actual);
    t_receive(&mut actual, &mut model, &[0, 0xe1, 1, 0xfe, 0x1e], 5000);

    let mut echo = vec![0, 0xe1, 1, 0xfe, 0x1e];
    for pair in input.as_chunks::<2>().0.iter().take(16) {
        echo[usize::from(pair[0] % 5)] ^= pair[1];
    }
    if byte(input, 2) & 1 == 0 {
        echo[4] = lrc(&echo[..4]);
    }
    let alternative = match byte(input, 0) % 12 {
        0 => echo,
        1 => tpdu(0, &[0xfe]),
        2 => tpdu(0x80, &[]),
        3 => tpdu(0xc3, &[1]),
        4 => tpdu(0xc0, &[]),
        5 => tpdu(0xc2, &[]),
        6 => tpdu(0xc1, &[0xfe]),
        7 => tpdu(0xe1, &[byte(input, 1)]),
        8 => tpdu(0xe1, &[]),
        9 => tpdu(0xe1, &[0xfe, 0]),
        10 => tpdu(0, &[0; 254]), // Complete 258-byte block before activation.
        _ => tpdu(byte(input, 1), &[byte(input, 2)]),
    };
    let (mut actual, mut model) = t_ifs_ready();
    t_receive(&mut actual, &mut model, &alternative, 1);
    if let Some(error) = model.error {
        assert_eq!(actual.next_block(1), Err(error));
        assert_eq!(actual.tick(u64::MAX), Err(error));
        assert_eq!(actual.begin(&[0], &[0], 1), Err(error));
        model.check(&actual);
    }

    let (mut actual, mut model) = t_ifs_ready();
    t_receive(&mut actual, &mut model, &[0, 0xe1, 1, 0xfe, 0x1e], 1);
    assert_eq!(
        actual.begin(&[0], &[0; 218], 1),
        model.begin(&[0], &[0; 218], 1)
    );
    assert_eq!(
        actual.next_block(1).map(|b| b.as_bytes().to_vec()),
        model.next(1)
    );
    assert_eq!(actual.written(5, 1), model.written(5, 1));
    model.check(&actual);
    let size = [32, 33, 218, 219, 254, 255][usize::from(byte(input, 3) % 6)];
    let large = tpdu(0, &vec![0; size]);
    t_receive(&mut actual, &mut model, &large, 2);
    // A valid 258-byte block reaches the narrower expected-response gate;
    // a 259-byte block fails the active receive ceiling first.
    if size == 254 {
        assert_eq!(actual.failure(), Some(T::ResponseLengthRejected));
    } else if size == 255 {
        assert_eq!(actual.failure(), Some(T::BlockLengthRejected));
    }

    // Stateful programs include negotiation before/during/after APDU use,
    // unsolicited/repeated echoes, partial writes and both budget boundaries.
    let (mut actual, mut model) = (T1::with_ifs(), TModel::with_ifs());
    for op in input.chunks(4).take(160) {
        let y = byte(op, 1);
        let now = [0, 1, 4999, 5000, 29_999, 30_000, u64::MAX][usize::from(y % 7)];
        match byte(op, 0) % 9 {
            0 => assert_eq!(actual.begin_ifs(now), model.begin_ifs(now)),
            1 => assert_eq!(actual.begin(&[0], &[0], now), model.begin(&[0], &[0], now)),
            2 => assert_eq!(
                actual.next_block(now).map(|b| b.as_bytes().to_vec()),
                model.next(now)
            ),
            3 => {
                let count = if y & 1 == 0 {
                    model.outgoing.len()
                } else {
                    usize::from(y)
                };
                assert_eq!(actual.written(count, now), model.written(count, now));
            }
            4 => t_receive(&mut actual, &mut model, &[0, 0xe1, 1, 0xfe, 0x1e], now),
            5 => t_receive(&mut actual, &mut model, &alternative, now),
            6 => {
                let card = tpdu(64 * model.nr, &[0]);
                t_receive(&mut actual, &mut model, &card, now);
            }
            7 => t_receive(&mut actual, &mut model, &[0, 0xc1, 1, 0xfe, 0x3e], now),
            _ => assert_eq!(actual.tick(now), model.clock(now)),
        }
        model.check(&actual);
    }
}

// Joint model exercise: up to eight synthetic public APDUs, with persistent
// sequence bits, card chaining and independent CCID sequence/fragment handling.
// It constructs requests itself and compares both models after every action.
fn joint(input: &[u8]) {
    joint_mode(input, false, false);
}
fn joint_mode(input: &[u8], ifs: bool, fidi: bool) {
    let (mut wire, mut wm) = w_ready_mode(if fidi { 4 } else { 3 }, fidi);
    let (mut t1, mut tm) = if ifs {
        (T1::with_ifs(), TModel::with_ifs())
    } else {
        (T1::default(), TModel::default())
    };
    if ifs {
        assert_eq!(t1.begin_ifs(0), tm.begin_ifs(0));
        assert_eq!(t1.next_block(0).map(|b| b.as_bytes().to_vec()), tm.next(0));
        tm.check(&t1);
        let request = [0, 0xc1, 1, 0xfe, 0x3e];
        w_begin(&mut wire, &mut wm, Some(&request), 0);
        w_written(&mut wire, &mut wm, 18, 0);
        assert_eq!(t1.written(5, 0), tm.written(5, 0));
        let reply = ccid(
            0x80,
            if fidi { 5 } else { 4 },
            0,
            0,
            &[0, 0xe1, 1, 0xfe, 0x1e],
        );
        let split = usize::from(byte(input, 6)) % (reply.len() + 1);
        w_receive(&mut wire, &mut wm, &reply[..split], 0);
        if split != reply.len() {
            w_receive(&mut wire, &mut wm, &reply[split..], 0);
        }
        t_receive(&mut t1, &mut tm, wire.response().unwrap().payload(), 0);
        assert_eq!(
            (
                t1.send_sequence(),
                t1.receive_sequence(),
                t1.completed_apdus()
            ),
            (0, 0, 0)
        );
    }
    let width = 1 + usize::from(byte(input, 1) % if ifs { 254 } else { 32 });
    let apdus = if byte(input, 2) == 0 {
        8
    } else {
        1 + usize::from(byte(input, 2) % 8)
    };
    let mut now = 1u64;
    let mut block_index = 0usize;
    let selected = usize::from(byte(input, 3) % 64);
    let fault = byte(input, 4) % 16;
    for apdu in 0..apdus {
        let command = vec![apdu as u8; 1 + usize::from(byte(input, 5 + apdu) % 30)];
        let wanted: Vec<_> = (0..1 + usize::from(byte(input, 13 + apdu) % 218))
            .map(|i| byte(input, 21 + i).wrapping_add(i as u8))
            .collect();
        assert_eq!(
            t1.begin(&command, &wanted, now),
            tm.begin(&command, &wanted, now)
        );
        tm.check(&t1);
        for (piece, data) in wanted.chunks(width).enumerate() {
            let got = t1.next_block(now).map(|b| b.as_bytes().to_vec());
            let predicted = tm.next(now);
            assert_eq!(got, predicted);
            tm.check(&t1);
            let Ok(outgoing) = predicted else { return };
            w_begin(&mut wire, &mut wm, Some(&outgoing), now);
            w_written(&mut wire, &mut wm, 13 + outgoing.len(), now);
            assert_eq!(
                t1.written(outgoing.len(), now),
                tm.written(outgoing.len(), now)
            );
            tm.check(&t1);
            let more = (piece + 1) * width < wanted.len();
            let mut card = tpdu(64 * tm.nr + u8::from(more) * 32, data);
            let hit = block_index == selected;
            if hit {
                match fault {
                    1 => card[1] ^= 0x40, // replay/wrong N(R)
                    2 => card[3] ^= 1,    // wrong GOLDEN prefix
                    3 => card[1] ^= 0x20, // premature final or excess chaining
                    4 => card = tpdu(0xc3, &[1]),
                    5 => card = tpdu(0x81, &[]),
                    6 => card = tpdu(0x80, &[]),
                    7 => card[0] = 1,
                    _ => (),
                }
                let last = card.len() - 1;
                card[last] = lrc(&card[..last]);
                if fault == 8 {
                    card[last] ^= 1;
                }
                if fault == 9 {
                    card.pop();
                }
            }
            let mut framed = ccid(0x80, wm.seq, 0, 0, &card);
            if hit && fault == 10 {
                // A SlotStatus extension outranks the pending DataBlock type
                // and bError. It must never renew either caller deadline.
                framed = ccid(0x81, wm.seq, 0x80, 0, &[]);
                framed[10] = 0xff;
                let last = framed.len() - 1;
                framed[last] = lrc(&framed[..last]);
            }
            if hit && fault == 11 {
                framed.extend_from_slice(&[0x50, 3]);
            }
            if hit && fault == 12 {
                framed.splice(..0, [0x50, 0x0f]);
            }
            if hit && fault == 13 {
                now += 5000;
            }
            if hit && fault == 14 {
                now = now.saturating_sub(1);
            }
            if hit && fault == 15 {
                now += 30_000;
            }
            let fragment = if byte(input, 0) & 1 == 0 {
                framed.len()
            } else {
                1 + usize::from(byte(input, 0) % 13)
            };
            for part in framed.chunks(fragment) {
                w_receive(&mut wire, &mut wm, part, now);
                assert_eq!(t1.tick(now), tm.clock(now));
                tm.check(&t1);
                if wm.error.is_some() || tm.error.is_some() {
                    return;
                }
                now += 1;
            }
            let actual_card = wire
                .response()
                .expect("model accepted a complete response")
                .payload();
            let expected_card = &wm.accepted.as_ref().unwrap()[10..];
            assert_eq!(t1.receive(actual_card, now), tm.receive(expected_card, now));
            tm.check(&t1);
            if tm.error.is_some() {
                assert_eq!(t1.next_block(now), Err(tm.error.unwrap()));
                return;
            }
            block_index += 1;
        }
        assert_eq!(t1.completed_apdus(), apdu + 1);
        assert_eq!(t1.response_prefix(), wanted);
    }
}

fuzz_target!(|input: &[u8]| {
    if input.len() > 8192 {
        return;
    }
    hostile_t1(input);
    hostile_wire(input);
    joint(input);
    hostile_ifs(input);
    joint_mode(input, true, false);
    hostile_fidi_wire(input);
    joint_mode(input, true, true);
    raw_oracle::exercise(input);
});

// SUP-013 additions use an independently expressed table/state oracle. The
// frozen decoders, state models and all their calls above remain unchanged.
mod raw_oracle {
    use super::{byte, ccid, lrc, t_decode_bound, tpdu, wire_next, TFact, WireFact, ATR, FIDI};
    use qk_sec1210_wire::{
        Error as WireError, RawCommand, RawError as WireRawError, RawFrameSpan, RawPhase,
        RawRequest, RawSession as RawWire,
    };
    use qk_t1::{Error, Phase, RawError, RawSession};

    const IFS_ECHO: [u8; 5] = [0, 0xe1, 1, 0xfe, 0x1e];

    #[derive(Default)]
    struct Model {
        // Table states: idle, ready, writing, receiving, complete, failed.
        stage: usize,
        // 0 required, 1 pending, 2 accepted. Separate from the phase table.
        ifs: u8,
        ns: u8,
        nr: u8,
        outgoing: Vec<u8>,
        bwi: u8,
        response: Vec<u8>,
        exchanges: usize,
        complete: usize,
        started: u64,
        last: Option<u64>,
        deadline: Option<u64>,
        wtx: Vec<u8>,
        total_wtx: usize,
        error: Option<RawError>,
    }

    fn add_time(start: u64, duration: u64) -> u64 {
        start.checked_add(duration).unwrap_or(u64::MAX)
    }

    impl Model {
        fn bound(&self) -> usize {
            if self.ifs == 2 {
                258
            } else {
                36
            }
        }

        fn fail<U>(&mut self, error: impl Into<RawError>) -> Result<U, RawError> {
            self.stage = 5;
            Err(*self.error.get_or_insert(error.into()))
        }

        fn clock(&mut self, now: u64) -> Result<(), RawError> {
            if let Some(error) = self.error {
                return Err(error);
            }
            if self.last.is_some_and(|previous| previous > now) {
                return self.fail(Error::ClockRegression);
            }
            self.last = Some(now);
            if (1..=3).contains(&self.stage) {
                let duration = if self.ifs == 1 { 5000 } else { 30_000 };
                if now >= add_time(self.started, duration) {
                    return self.fail(Error::DeadlineExceeded);
                }
            }
            Ok(())
        }

        fn begin_ifs(&mut self, now: u64) -> Result<(), RawError> {
            self.clock(now)?;
            if self.stage != 0 || self.ifs != 0 {
                return self.fail(Error::StateRejected);
            }
            self.ifs = 1;
            self.started = now;
            self.outgoing = vec![0, 0xc1, 1, 0xfe, 0x3e];
            self.bwi = 0;
            self.stage = 1;
            Ok(())
        }

        fn begin(&mut self, command: &[u8], now: u64) -> Result<(), RawError> {
            self.clock(now)?;
            if self.ifs != 2 || !matches!(self.stage, 0 | 4) {
                return self.fail(Error::StateRejected);
            }
            if self.complete == 128 {
                return self.fail(Error::ApduLimitExceeded);
            }
            if command.is_empty() || command.len() > 254 {
                return self.fail(Error::CommandLengthRejected);
            }
            self.response.clear();
            self.exchanges = 0;
            self.wtx.clear();
            self.started = now;
            self.deadline = Some(add_time(now, 30_000));
            self.outgoing = tpdu(64 * self.ns, command);
            self.bwi = 0;
            self.stage = 1;
            Ok(())
        }

        fn next(&mut self, now: u64) -> Result<(Vec<u8>, u8, u64), RawError> {
            self.clock(now)?;
            if self.stage != 1 || self.outgoing.is_empty() {
                return self.fail(Error::StateRejected);
            }
            if self.exchanges == 16 {
                return self.fail(Error::ExchangeLimitExceeded);
            }
            self.stage = 2;
            let allowance = 5000u64.max(u64::from(self.bwi) * 1190);
            Ok((self.outgoing.clone(), self.bwi, allowance))
        }

        fn written(&mut self, count: usize, now: u64) -> Result<(), RawError> {
            self.clock(now)?;
            if self.stage != 2 {
                return self.fail(Error::StateRejected);
            }
            if count != self.outgoing.len() {
                return self.fail(Error::PartialWrite);
            }
            self.exchanges += 1;
            self.stage = 3;
            Ok(())
        }

        fn receive(&mut self, raw: &[u8], now: u64) -> Result<(), RawError> {
            self.clock(now)?;
            if self.stage != 3 {
                match t_decode_bound(raw, self.bound(), false) {
                    Err(Error::IfsRejected) => return self.fail(Error::IfsRejected),
                    Err(Error::WtxRejected) if raw[1] == 0xe3 => {
                        return self.fail(RawError::WtxResponseRejected);
                    }
                    _ => return self.fail(Error::StateRejected),
                }
            }
            if self.ifs == 1 {
                match t_decode_bound(raw, 36, true) {
                    Ok(TFact::Ifs) => {
                        self.ifs = 2;
                        self.stage = 0;
                        self.outgoing.clear();
                        return Ok(());
                    }
                    Ok(TFact::I(..)) => return self.fail(Error::IfsRejected),
                    Ok(TFact::R(_)) => return self.fail(Error::UnexpectedRBlock),
                    Err(error) => return self.fail(error),
                }
            }
            let (sequence, chained, data) = match t_decode_bound(raw, 258, false) {
                Ok(TFact::I(sequence, chained, data)) => (sequence, chained, data),
                Ok(TFact::R(_)) => return self.fail(Error::UnexpectedRBlock),
                Ok(TFact::Ifs) => unreachable!("IFS fact requires negotiation mode"),
                Err(Error::WtxRejected) if raw[1] == 0xc3 => {
                    let multiplier = raw[3];
                    if multiplier == 0 || multiplier > 24 {
                        return self.fail(RawError::WtxMultiplierRejected);
                    }
                    if self.wtx.len() == 8 {
                        return self.fail(RawError::WtxLimitExceeded);
                    }
                    self.wtx.push(multiplier);
                    self.total_wtx += 1;
                    self.outgoing = tpdu(0xe3, &[multiplier]);
                    self.bwi = multiplier;
                    self.stage = 1;
                    return Ok(());
                }
                Err(Error::WtxRejected) => return self.fail(RawError::WtxResponseRejected),
                Err(error) => return self.fail(error),
            };
            if sequence != self.nr {
                return self.fail(Error::SequenceRejected);
            }
            if chained {
                return self.fail(RawError::ChainingRejected);
            }
            if data.len() > 254 {
                return self.fail(Error::ResponseLengthRejected);
            }
            self.response = data.to_vec();
            self.ns = 1 - self.ns;
            self.nr = 1 - self.nr;
            self.outgoing.clear();
            self.complete += 1;
            self.stage = 4;
            Ok(())
        }

        fn check(&self, actual: &RawSession) {
            let phases = [
                Phase::Idle,
                Phase::Ready,
                Phase::Writing,
                Phase::Receiving,
                Phase::Complete,
                Phase::Failed,
            ];
            assert_eq!(actual.phase(), phases[self.stage]);
            assert_eq!(actual.failure(), self.error);
            assert_eq!(actual.ifs_accepted(), self.ifs == 2);
            assert_eq!(actual.receive_bound(), self.bound());
            assert_eq!(actual.send_sequence(), self.ns);
            assert_eq!(actual.receive_sequence(), self.nr);
            assert_eq!(actual.response(), self.response);
            assert_eq!(actual.exchanges(), self.exchanges);
            assert_eq!(actual.completed_apdus(), self.complete);
            assert_eq!(actual.apdu_deadline_ms(), self.deadline);
            assert_eq!(actual.wtx_multipliers(), self.wtx);
            assert_eq!(actual.wtx_count(), self.wtx.len());
            assert_eq!(actual.total_wtx_count(), self.total_wtx);
        }
    }

    fn begin_ifs(actual: &mut RawSession, model: &mut Model, now: u64) {
        assert_eq!(actual.begin_ifs(now), model.begin_ifs(now));
        model.check(actual);
    }

    fn begin(actual: &mut RawSession, model: &mut Model, command: &[u8], now: u64) {
        assert_eq!(actual.begin(command, now), model.begin(command, now));
        model.check(actual);
    }

    fn next(actual: &mut RawSession, model: &mut Model, now: u64) {
        assert_eq!(
            actual.next_block(now).map(|block| (
                block.as_bytes().to_vec(),
                block.bwi(),
                block.command_allowance_ms(),
            )),
            model.next(now)
        );
        model.check(actual);
    }

    fn written(actual: &mut RawSession, model: &mut Model, count: usize, now: u64) {
        assert_eq!(actual.written(count, now), model.written(count, now));
        model.check(actual);
    }

    fn receive(actual: &mut RawSession, model: &mut Model, raw: &[u8], now: u64) {
        assert_eq!(actual.receive(raw, now), model.receive(raw, now));
        model.check(actual);
    }

    fn clock(actual: &mut RawSession, model: &mut Model, now: u64) {
        assert_eq!(actual.tick(now), model.clock(now));
        model.check(actual);
    }

    // Prepared states are reached solely through the public APIs, with model
    // expectations checked at every transition. No private state is seeded.
    fn ready(depth: u8) -> (RawSession, Model) {
        let (mut actual, mut model) = (RawSession::default(), Model::default());
        if depth == 0 {
            return (actual, model);
        }
        begin_ifs(&mut actual, &mut model, 0);
        next(&mut actual, &mut model, 0);
        written(&mut actual, &mut model, 5, 0);
        if depth == 1 {
            return (actual, model);
        }
        receive(&mut actual, &mut model, &IFS_ECHO, 1);
        if depth == 2 {
            return (actual, model);
        }
        begin(&mut actual, &mut model, &[0x80, 0x15], 2);
        next(&mut actual, &mut model, 2);
        written(&mut actual, &mut model, 6, 2);
        if depth == 4 {
            receive(&mut actual, &mut model, &tpdu(0xc3, &[2]), 3);
        }
        (actual, model)
    }

    fn sticky(actual: &mut RawSession, model: &mut Model) {
        if model.error.is_none() {
            return;
        }
        clock(actual, model, u64::MAX);
        begin_ifs(actual, model, 0);
        begin(actual, model, &[], u64::MAX);
        next(actual, model, 0);
        written(actual, model, usize::MAX, 0);
        receive(actual, model, &IFS_ECHO, 0);
    }

    fn constructed(input: &[u8]) -> Vec<u8> {
        let multiplier = byte(input, 1);
        let size = [0, 1, 32, 33, 132, 165, 254, 255][usize::from(byte(input, 2) % 8)];
        let data: Vec<u8> = (0..size).map(|index| byte(input, index + 3)).collect();
        match byte(input, 0) % 16 {
            0 => tpdu(0xc3, &[multiplier]),
            1 => tpdu(0xe3, &[multiplier]),
            2 => tpdu(0, &data),
            3 => tpdu(0x20, &data),
            4 => tpdu(0x40, &data),
            5 => tpdu(0x80, &[]),
            6 => tpdu(0x81, &[]),
            7 => tpdu(0xc0, &[]),
            8 => tpdu(0xc1, &[multiplier]),
            9 => tpdu(0xe1, &[multiplier]),
            10 => tpdu(0xc2, &[]),
            11 => tpdu(0xc3, &data),
            12 => {
                let mut raw = tpdu(0, &data);
                raw[0] = multiplier;
                let last = raw.len() - 1;
                raw[last] = lrc(&raw[..last]);
                raw
            }
            13 => {
                let mut raw = tpdu(0, &data);
                raw[2] ^= multiplier;
                let last = raw.len() - 1;
                raw[last] = lrc(&raw[..last]);
                raw
            }
            14 => {
                let mut raw = tpdu(0, &data);
                let last = raw.len() - 1;
                raw[last] ^= multiplier;
                raw
            }
            _ => tpdu(multiplier, &data),
        }
    }

    fn program(input: &[u8], frame: &[u8]) {
        let (mut actual, mut model) = ready(byte(input, 0) % 5);
        for op in input.chunks(4).take(160) {
            let selector = byte(op, 1);
            let now = match selector % 10 {
                0 => 0,
                1 => model.last.unwrap_or(0),
                2 => add_time(model.last.unwrap_or(0), 1),
                3 => model.last.unwrap_or(0).saturating_sub(1),
                4 => add_time(model.started, 4999),
                5 => add_time(model.started, 5000),
                6 => add_time(model.started, 29_999),
                7 => add_time(model.started, 30_000),
                8 => u64::MAX - 1,
                _ => u64::MAX,
            };
            match byte(op, 0) % 9 {
                0 => begin_ifs(&mut actual, &mut model, now),
                1 => {
                    let len = [0, 1, 132, 254, 255][usize::from(byte(op, 2) % 5)];
                    begin(&mut actual, &mut model, &vec![byte(op, 3); len], now);
                }
                2 => next(&mut actual, &mut model, now),
                3 => {
                    let count = if byte(op, 2) & 1 == 0 {
                        model.outgoing.len()
                    } else {
                        usize::from(byte(op, 3))
                    };
                    written(&mut actual, &mut model, count, now);
                }
                4 => receive(&mut actual, &mut model, frame, now),
                5 => receive(&mut actual, &mut model, &IFS_ECHO, now),
                6 => {
                    let len = [0, 1, 165, 254, 255][usize::from(byte(op, 2) % 5)];
                    let raw = tpdu(64 * model.nr, &vec![byte(op, 3); len]);
                    receive(&mut actual, &mut model, &raw, now);
                }
                7 => receive(&mut actual, &mut model, &tpdu(0xc3, &[byte(op, 2)]), now),
                _ => clock(&mut actual, &mut model, now),
            }
        }
        sticky(&mut actual, &mut model);
    }

    // Compact public seed programs select long traversals. Only one selected
    // branch runs, instead of making all fuzz inputs traverse every ceiling.
    fn boundary(input: &[u8]) {
        if byte(input, 0) != 0xf6 {
            return;
        }
        let (mut actual, mut model) = ready(2);
        match byte(input, 1) % 4 {
            0 => {
                let count = [127, 128, 129][usize::from(byte(input, 2) % 3)];
                let command_len = [1, 132, 254][usize::from(byte(input, 3) % 3)];
                for apdu in 0..count {
                    let now = apdu as u64 + 2;
                    begin(&mut actual, &mut model, &vec![0x5a; command_len], now);
                    if model.error.is_some() {
                        break;
                    }
                    next(&mut actual, &mut model, now);
                    written(&mut actual, &mut model, command_len + 4, now);
                    let raw = tpdu(64 * model.nr, &[0x90, 0]);
                    receive(&mut actual, &mut model, &raw, now);
                }
            }
            1 => {
                let count = [7, 8, 9][usize::from(byte(input, 2) % 3)];
                let multiplier = [0, 1, 2, 24, 25, 255][usize::from(byte(input, 3) % 6)];
                begin(&mut actual, &mut model, &[0x15], 2);
                next(&mut actual, &mut model, 2);
                written(&mut actual, &mut model, 5, 2);
                for _ in 0..count {
                    receive(&mut actual, &mut model, &tpdu(0xc3, &[multiplier]), 3);
                    if model.error.is_some() {
                        break;
                    }
                    next(&mut actual, &mut model, 3);
                    written(&mut actual, &mut model, 5, 3);
                }
                if model.error.is_none() {
                    let raw = tpdu(64 * model.nr, &[0x90, 0]);
                    receive(&mut actual, &mut model, &raw, 4);
                    // New APDU resets only the per-APDU list, not its total.
                    begin(&mut actual, &mut model, &[0], 4);
                }
            }
            2 => {
                let started = if byte(input, 2) & 1 == 0 {
                    2
                } else {
                    u64::MAX - 2
                };
                begin(&mut actual, &mut model, &[0], started);
                next(&mut actual, &mut model, started);
                written(&mut actual, &mut model, 5, started);
                receive(&mut actual, &mut model, &tpdu(0xc3, &[24]), started);
                next(&mut actual, &mut model, started);
                written(&mut actual, &mut model, 5, started);
                let elapsed = [5000, 28_560, 29_999, 30_000][usize::from(byte(input, 3) % 4)];
                let now = add_time(started, elapsed);
                receive(&mut actual, &mut model, &tpdu(0, &[0x90, 0]), now);
                // Completion retains the deadline but no longer times it.
                clock(&mut actual, &mut model, u64::MAX);
            }
            _ => {
                let size = [0, 1, 32, 33, 165, 254, 255][usize::from(byte(input, 2) % 7)];
                begin(&mut actual, &mut model, &[0; 254], 2);
                next(&mut actual, &mut model, 2);
                written(&mut actual, &mut model, 258, 2);
                let raw = tpdu(byte(input, 3), &vec![0xa5; size]);
                receive(&mut actual, &mut model, &raw, 3);
            }
        }
        sticky(&mut actual, &mut model);
    }

    // The joint path has its own counters, framing cursor and timing facts.
    // It never imports the bench engine or uses actual getters as expectations.
    struct Joint {
        wire: RawWire,
        t1: RawSession,
        model: Model,
        now: u64,
        requests: usize,
        responses: usize,
        rx: usize,
        events: usize,
        te_total: usize,
        te_apdu: usize,
        apdu_deadline: Option<u64>,
        command_deadline: u64,
        allowance: u64,
        sequence: u8,
    }

    struct PacketFacts {
        responses: usize,
        extensions: usize,
        events: usize,
        reply: Option<Vec<u8>>,
        span: Option<RawFrameSpan>,
        error: Option<WireRawError>,
    }

    // Independent batch interpretation of the prefix visible after a read.
    // All generated joint frames have fixed valid semantics; corruption is
    // injected into the checksum, while raw hostile semantics live above and
    // in the independent wire target. The cursor still checks complete frames.
    fn packet_facts(raw: &[u8], origin: usize, previous_te: usize) -> PacketFacts {
        let mut facts = PacketFacts {
            responses: 0,
            extensions: 0,
            events: 0,
            reply: None,
            span: None,
            error: None,
        };
        let mut cursor = 0;
        while cursor < raw.len() {
            match wire_next(&raw[cursor..]) {
                Ok(None) => break,
                Err(error) => {
                    facts.error = Some(error.into());
                    break;
                }
                Ok(Some((fact, consumed))) => {
                    let start = cursor;
                    cursor += consumed;
                    match fact {
                        WireFact::Response(response) => {
                            facts.span = Some(RawFrameSpan {
                                start_rx_offset: origin + start,
                                end_rx_offset: origin + cursor,
                            });
                            let extension = response[0] == 0x80 && response[7] == 0x80;
                            facts.reply = Some(response);
                            if extension {
                                if previous_te + facts.extensions == 8 {
                                    facts.error = Some(WireRawError::TimeExtensionLimitExceeded);
                                    break;
                                }
                                facts.extensions += 1;
                            } else {
                                facts.responses += 1;
                                if cursor != raw.len() {
                                    facts.error = Some(WireError::TrailingData.into());
                                }
                                break;
                            }
                        }
                        WireFact::Bitmap(bitmap) => {
                            assert_eq!(bitmap, 3);
                            facts.events += 1;
                        }
                        WireFact::Hardware(..) => unreachable!("not a generated joint event"),
                    }
                }
            }
        }
        facts
    }

    impl Joint {
        fn new() -> Self {
            Self {
                wire: RawWire::new(),
                t1: RawSession::default(),
                model: Model::default(),
                now: 0,
                requests: 0,
                responses: 0,
                rx: 0,
                events: 0,
                te_total: 0,
                te_apdu: 0,
                apdu_deadline: None,
                command_deadline: 0,
                allowance: 0,
                sequence: 0,
            }
        }

        fn counters(&self) {
            assert_eq!(self.wire.requests(), self.requests);
            assert_eq!(self.wire.responses(), self.responses);
            assert_eq!(self.wire.ordinal(), self.requests);
            assert_eq!(self.wire.sequence(), self.sequence);
            assert_eq!(self.wire.received_bytes(), self.rx);
            assert_eq!(self.wire.events(), self.events);
            assert_eq!(self.wire.time_extension_count(), self.te_total);
            assert_eq!(self.wire.apdu_time_extension_count(), self.te_apdu);
            assert_eq!(self.wire.apdu_deadline_ms(), self.apdu_deadline);
            assert_eq!(self.wire.command_deadline_ms(), self.command_deadline);
            assert_eq!(self.wire.host_allowance_ms(), self.allowance);
            self.model.check(&self.t1);
        }

        fn terminal(&mut self, expected: WireRawError) {
            assert_eq!(self.wire.failure(), Some(expected));
            assert_eq!(self.wire.phase(), RawPhase::Failed);
            assert_eq!(self.wire.tick(u64::MAX), Err(expected));
            assert_eq!(self.wire.begin_initial(0), Err(expected));
            assert_eq!(self.wire.begin_ifs_transfer(&[], 0), Err(expected));
            assert_eq!(self.wire.accept_ifs(0), Err(expected));
            assert_eq!(self.wire.begin_apdu(0), Err(expected));
            assert_eq!(self.wire.begin_transfer(&[], 255, 0), Err(expected));
            assert_eq!(self.wire.written(usize::MAX, 0), Err(expected));
            assert_eq!(self.wire.receive(&IFS_ECHO, 0), Err(expected));
            assert_eq!(self.wire.end_apdu(0), Err(expected));
            self.counters();
        }

        fn request(
            &mut self,
            actual: Result<RawRequest, WireRawError>,
            command: RawCommand,
            payload: &[u8],
            bwi: u8,
        ) -> bool {
            if self.requests == 512 {
                assert_eq!(actual, Err(WireRawError::CommandLimitExceeded));
                self.terminal(WireRawError::CommandLimitExceeded);
                return false;
            }
            let actual = actual.expect("model has a valid claim before the ceiling");
            let ordinal = self.requests + 1;
            let sequence = (ordinal % 256) as u8;
            let kind = match command {
                RawCommand::GetSlotStatus => 0x65,
                RawCommand::PowerOn => 0x62,
                RawCommand::GetParameters => 0x6c,
                RawCommand::SetParameters => 0x61,
                RawCommand::XfrBlock => 0x6f,
            };
            let specific = match command {
                RawCommand::PowerOn => 2,
                RawCommand::SetParameters => 1,
                RawCommand::XfrBlock => bwi,
                _ => 0,
            };
            let frame = ccid(kind, sequence, specific, 0, payload);
            let allowance = 5000u64.max(u64::from(bwi) * 1190);
            let unbounded = add_time(self.now, allowance);
            let deadline = self
                .apdu_deadline
                .map_or(unbounded, |cap| cap.min(unbounded));
            assert_eq!(actual.as_bytes(), frame);
            assert_eq!(actual.command(), command);
            assert_eq!(actual.ordinal(), ordinal);
            assert_eq!(actual.sequence(), sequence);
            assert_eq!(actual.bwi(), bwi);
            assert_eq!(actual.host_allowance_ms(), allowance);
            assert_eq!(actual.deadline_ms(), deadline);
            assert_eq!(actual.apdu_deadline_ms(), self.apdu_deadline);
            assert_eq!(self.wire.phase(), RawPhase::Writing(command));
            assert!(self.wire.reply_evidence().is_none());
            assert!(self.wire.last_reply_span().is_none());
            assert_eq!(self.wire.written(frame.len(), self.now), Ok(()));
            self.requests = ordinal;
            self.sequence = sequence;
            self.allowance = allowance;
            self.command_deadline = deadline;
            assert_eq!(self.wire.phase(), RawPhase::Receiving(command));
            self.counters();
            true
        }

        fn deliver(
            &mut self,
            packet: &[u8],
            split: usize,
            command: RawCommand,
            next_phase: RawPhase,
        ) -> bool {
            let base_rx = self.rx;
            let base_responses = self.responses;
            let base_events = self.events;
            let base_te = self.te_total;
            let base_apdu_te = self.te_apdu;
            let mut end = 0;
            for chunk in packet.chunks(split) {
                self.now += 1;
                end += chunk.len();
                let facts = packet_facts(&packet[..end], base_rx, base_apdu_te);
                let expected = facts.error.map_or(Ok(()), Err);
                assert_eq!(self.wire.receive(chunk, self.now), expected);
                self.rx = base_rx + end;
                self.responses = base_responses + facts.responses;
                self.events = base_events + facts.events;
                self.te_total = base_te + facts.extensions;
                self.te_apdu = base_apdu_te + facts.extensions;
                assert_eq!(self.wire.last_reply_span(), facts.span);
                match (self.wire.reply_evidence(), facts.reply.as_ref()) {
                    (None, None) => (),
                    (Some(actual), Some(raw)) => {
                        assert_eq!(actual.message_type, raw[0]);
                        assert_eq!(actual.slot, raw[5]);
                        assert_eq!(actual.sequence, raw[6]);
                        assert_eq!(actual.status, raw[7]);
                        assert_eq!(actual.error, raw[8]);
                        assert_eq!(actual.parameter, raw[9]);
                        assert_eq!(actual.payload(), &raw[10..]);
                    }
                    _ => panic!("independent reply evidence differs"),
                }
                self.counters();
                if let Some(error) = facts.error {
                    self.terminal(error);
                    return false;
                }
                assert_eq!(
                    self.wire.phase(),
                    if facts.responses == 0 {
                        RawPhase::Receiving(command)
                    } else {
                        next_phase
                    }
                );
            }
            assert_eq!(self.responses, base_responses + 1);
            true
        }

        fn initialize(&mut self, split: usize) {
            let steps = [
                (RawCommand::GetSlotStatus, RawPhase::ReadyPower),
                (RawCommand::PowerOn, RawPhase::ReadyParameters),
                (RawCommand::GetParameters, RawPhase::ReadySetParameters),
                (RawCommand::SetParameters, RawPhase::ReadyIfs),
            ];
            for (index, (command, phase)) in steps.into_iter().enumerate() {
                let payload = if index == 3 { FIDI.as_slice() } else { &[] };
                let request = self.wire.begin_initial(self.now);
                assert!(self.request(request, command, payload, 0));
                let seq = (index + 1) as u8;
                let response = match index {
                    0 => ccid(0x81, seq, 1, 1, &[]),
                    1 => ccid(0x80, seq, 0, 0, &ATR),
                    2 => ccid(0x82, seq, 0, 1, &[0x11, 0x10, 0xff, 0x4d, 0, 0xfe, 0]),
                    _ => ccid(0x82, seq, 0, 1, &FIDI),
                };
                assert!(self.deliver(&response, split, command, phase));
            }
            assert!(self.wire.set_parameters_accepted());
            begin_ifs(&mut self.t1, &mut self.model, self.now);
            next(&mut self.t1, &mut self.model, self.now);
            let request = self.wire.begin_ifs_transfer(&self.model.outgoing, self.now);
            let payload = self.model.outgoing.clone();
            assert!(self.request(request, RawCommand::XfrBlock, &payload, 0));
            written(&mut self.t1, &mut self.model, 5, self.now);
            let response = ccid(0x80, 5, 0, 0, &IFS_ECHO);
            assert!(self.deliver(
                &response,
                split,
                RawCommand::XfrBlock,
                RawPhase::AwaitIfsAcceptance,
            ));
            let payload = self.wire.response().unwrap().payload().to_vec();
            receive(&mut self.t1, &mut self.model, &payload, self.now);
            assert_eq!(self.wire.accept_ifs(self.now), Ok(()));
            assert!(self.wire.ifs_accepted());
            self.counters();
        }
    }

    fn joint(input: &[u8]) {
        let deep = byte(input, 0) == 0xf7;
        let scenario = if deep { 0 } else { byte(input, 0) % 14 };
        let split = if deep {
            32
        } else {
            1 + usize::from(byte(input, 3) % 32)
        };
        let mut pair = Joint::new();
        pair.initialize(split);
        let apdus = if deep {
            64
        } else {
            1 + usize::from(byte(input, 1) % 3)
        };
        for _ in 0..apdus {
            pair.now += 1;
            let command_len = if deep {
                1
            } else {
                [1, 132, 254][usize::from(byte(input, 2) % 3)]
            };
            let command = vec![0x5a; command_len];
            begin(&mut pair.t1, &mut pair.model, &command, pair.now);
            assert_eq!(pair.wire.begin_apdu(pair.now), Ok(()));
            pair.apdu_deadline = Some(add_time(pair.now, 30_000));
            pair.te_apdu = 0;
            let wtx_goal = if deep {
                7
            } else {
                match scenario {
                    1..=4 => 1,
                    5 => 9,
                    _ => 0,
                }
            };
            let multiplier = match scenario {
                1 => 1,
                3 => 24,
                4 => 25,
                _ => 2,
            };
            let mut card_wtx = 0;
            loop {
                let expected = pair.model.next(pair.now).unwrap();
                let block = pair.t1.next_block(pair.now).unwrap();
                assert_eq!(block.as_bytes(), expected.0);
                assert_eq!(block.bwi(), expected.1);
                assert_eq!(block.command_allowance_ms(), expected.2);
                pair.model.check(&pair.t1);
                let request = pair
                    .wire
                    .begin_transfer(block.as_bytes(), block.bwi(), pair.now);
                if !pair.request(request, RawCommand::XfrBlock, &expected.0, expected.1) {
                    return;
                }
                written(
                    &mut pair.t1,
                    &mut pair.model,
                    block.as_bytes().len(),
                    pair.now,
                );
                if matches!(scenario, 8 | 9 | 13) {
                    pair.now = match scenario {
                        8 => pair.command_deadline,
                        9 => pair.apdu_deadline.unwrap(),
                        _ => pair.now - 1,
                    };
                    let error = match scenario {
                        8 => WireError::DeadlineExceeded.into(),
                        9 => WireRawError::ApduDeadlineExceeded,
                        _ => WireError::ClockRegression.into(),
                    };
                    assert_eq!(pair.wire.receive(&[3], pair.now), Err(error));
                    pair.terminal(error);
                    return;
                }
                let card = if card_wtx < wtx_goal {
                    card_wtx += 1;
                    tpdu(0xc3, &[multiplier])
                } else {
                    let response_len = if deep {
                        0
                    } else {
                        [0, 165, 254][usize::from(byte(input, 2) % 3)]
                    };
                    let pcb = match scenario {
                        10 => 0x20 + 64 * pair.model.nr,
                        11 => 64 * (1 - pair.model.nr),
                        _ => 64 * pair.model.nr,
                    };
                    tpdu(pcb, &vec![0xa5; response_len])
                };
                let mut packet = Vec::new();
                if !deep && byte(input, 4) & 1 != 0 {
                    packet.extend_from_slice(&[0x50, 3]);
                }
                let extensions = match scenario {
                    6 => 1,
                    7 => 9,
                    _ => 0,
                };
                for _ in 0..extensions {
                    let mut extension = ccid(0x80, pair.sequence, 0x80, 0, &[]);
                    extension[10] = byte(input, 5);
                    let last = extension.len() - 1;
                    extension[last] = lrc(&extension[..last]);
                    packet.extend_from_slice(&extension);
                }
                let mut response = ccid(0x80, pair.sequence, 0, 0, &card);
                if scenario == 12 {
                    let last = response.len() - 1;
                    response[last] ^= 1;
                }
                packet.extend_from_slice(&response);
                if !pair.deliver(
                    &packet,
                    split,
                    RawCommand::XfrBlock,
                    RawPhase::ReadyTransfer,
                ) {
                    return;
                }
                let received = pair.wire.response().unwrap().payload().to_vec();
                assert_eq!(received, card);
                receive(&mut pair.t1, &mut pair.model, &received, pair.now);
                if pair.model.error.is_some() {
                    let sent = pair.requests;
                    sticky(&mut pair.t1, &mut pair.model);
                    assert_eq!(pair.wire.requests(), sent);
                    return;
                }
                if pair.model.stage == 4 {
                    assert_eq!(pair.wire.end_apdu(pair.now), Ok(()));
                    pair.apdu_deadline = None;
                    pair.counters();
                    break;
                }
                assert_eq!(pair.model.stage, 1);
            }
        }
    }

    pub(super) fn exercise(input: &[u8]) {
        // Complete hostile input reaches both pre-IFS and post-IFS boundaries.
        for depth in [1, 3] {
            let (mut actual, mut model) = ready(depth);
            receive(&mut actual, &mut model, input, 4);
            sticky(&mut actual, &mut model);
        }
        let frame = constructed(input);
        for depth in [0, 1, 3] {
            let (mut actual, mut model) = ready(depth);
            receive(&mut actual, &mut model, &frame, 4);
            sticky(&mut actual, &mut model);
        }
        program(input, &frame);
        boundary(input);
        joint(input);
    }
}
