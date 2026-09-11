use crate::{Decoder, Error, Message, Response};

pub const MAX_EVENTS: usize = 64;
pub const MAX_RECEIVED_BYTES: usize = 4096;
pub const RECEIVE_BUDGET_MS: u64 = 5000;
pub const REGISTERED_ATR: [u8; 15] = [
    0x3b, 0xd5, 0x18, 0xff, 0x81, 0x91, 0xfe, 0x1f, 0xc3, 0x80, 0x73, 0xc8, 0x21, 0x10, 0x0a,
];

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Command {
    GetSlotStatus,
    PowerOn,
}

impl Command {
    pub const fn sequence(self) -> u8 {
        match self {
            Self::GetSlotStatus => 1,
            Self::PowerOn => 2,
        }
    }
    pub fn encode(self) -> [u8; 13] {
        let (kind, parameter) = match self {
            Self::GetSlotStatus => (0x65, 0),
            Self::PowerOn => (0x62, 2),
        };
        let mut wire = [
            0x03,
            0x06,
            kind,
            0,
            0,
            0,
            0,
            0,
            self.sequence(),
            parameter,
            0,
            0,
            0,
        ];
        wire[12] = wire[..12].iter().fold(0, |a, b| a ^ b);
        wire
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Phase {
    ReadyStatus,
    Writing(Command),
    Receiving(Command),
    ReadyPower,
    Complete,
    Failed,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Observation {
    SlotChange { bitmap: u8, slot1_bits: u8 },
    HardwareError { slot: u8, sequence: u8, code: u8 },
    SlotStatus { status: u8, error: u8, clock: u8 },
    Atr([u8; 15]),
}

pub struct Exchange {
    phase: Phase,
    decoder: Decoder,
    events: usize,
    received: usize,
    requests: usize,
    responses: usize,
    elapsed: u64,
    failure: Option<Error>,
    observations: Vec<Observation>,
}

impl Default for Exchange {
    fn default() -> Self {
        Self {
            phase: Phase::ReadyStatus,
            decoder: Decoder::default(),
            events: 0,
            received: 0,
            requests: 0,
            responses: 0,
            elapsed: 0,
            failure: None,
            observations: Vec::new(),
        }
    }
}

impl Exchange {
    /// Facts survive a later rejection in the same coalesced read. At most
    /// MAX_EVENTS event records and two accepted response records are stored.
    pub fn observations(&self) -> &[Observation] {
        &self.observations
    }
    pub fn phase(&self) -> Phase {
        self.phase
    }
    pub fn events(&self) -> usize {
        self.events
    }
    pub fn received_bytes(&self) -> usize {
        self.received
    }
    pub fn requests(&self) -> usize {
        self.requests
    }
    pub fn responses(&self) -> usize {
        self.responses
    }
    pub fn failure(&self) -> Option<Error> {
        self.failure
    }

    fn reject<T>(&mut self, error: Error) -> Result<T, Error> {
        let error = *self.failure.get_or_insert(error);
        self.phase = Phase::Failed;
        Err(error)
    }

    pub fn begin(&mut self) -> Result<Command, Error> {
        let command = match self.phase {
            Phase::ReadyStatus => Command::GetSlotStatus,
            Phase::ReadyPower => Command::PowerOn,
            _ => return self.reject(Error::SequenceViolation),
        };
        self.phase = Phase::Writing(command);
        Ok(command)
    }

    /// One write attempt only. The caller starts the receive clock on its return.
    pub fn written(&mut self, bytes: usize) -> Result<(), Error> {
        let Phase::Writing(command) = self.phase else {
            return self.reject(Error::SequenceViolation);
        };
        if bytes != command.encode().len() {
            return self.reject(Error::PartialWrite);
        }
        self.requests += 1;
        self.elapsed = 0;
        self.phase = Phase::Receiving(command);
        Ok(())
    }

    pub fn receive(&mut self, bytes: &[u8], elapsed_ms: u64) -> Result<Vec<Observation>, Error> {
        let Phase::Receiving(command) = self.phase else {
            return self.reject(Error::UnsolicitedResponse);
        };
        if elapsed_ms < self.elapsed {
            return self.reject(Error::ClockRegression);
        }
        self.elapsed = elapsed_ms;
        if elapsed_ms >= RECEIVE_BUDGET_MS {
            return self.reject(if self.decoder.pending_bytes() == 0 {
                Error::DeadlineExceeded
            } else {
                Error::PartialFrameDeadline
            });
        }
        if bytes.len() > MAX_RECEIVED_BYTES - self.received {
            return self.reject(Error::ReceiveLimitExceeded);
        }
        self.received += bytes.len();
        let mut observations = Vec::new();
        for (index, byte) in bytes.iter().enumerate() {
            let message = match self.decoder.push(*byte) {
                Ok(Some(message)) => message,
                Ok(None) => continue,
                Err(error) => return self.reject(error),
            };
            match message {
                Message::SlotChange { bitmap } => {
                    self.events += 1;
                    if self.events > MAX_EVENTS {
                        return self.reject(Error::EventLimitExceeded);
                    }
                    self.observations.push(Observation::SlotChange {
                        bitmap,
                        slot1_bits: (bitmap >> 2) & 3,
                    });
                    if bitmap & 0xf0 != 0 {
                        return self.reject(Error::EventBitmapRejected);
                    }
                    if bitmap & 1 == 0 {
                        return self.reject(Error::CardAbsent);
                    }
                    observations.push(Observation::SlotChange {
                        bitmap,
                        slot1_bits: (bitmap >> 2) & 3,
                    });
                }
                Message::HardwareError {
                    slot,
                    sequence,
                    code,
                } => {
                    self.events += 1;
                    if self.events > MAX_EVENTS {
                        return self.reject(Error::EventLimitExceeded);
                    }
                    self.observations.push(Observation::HardwareError {
                        slot,
                        sequence,
                        code,
                    });
                    if slot != 0 {
                        return self.reject(Error::SlotRejected);
                    }
                    if sequence != command.sequence() {
                        return self.reject(Error::SequenceRejected);
                    }
                    return self.reject(Error::HardwareError);
                }
                Message::Response(response) => {
                    let observation = match validate(command, &response) {
                        Ok(value) => value,
                        Err(error) => return self.reject(error),
                    };
                    // No response may be accepted with any trailing unconsumed data.
                    if index + 1 != bytes.len() {
                        return self.reject(Error::TrailingData);
                    }
                    self.observations.push(observation.clone());
                    observations.push(observation);
                    self.responses += 1;
                    self.phase = match command {
                        Command::GetSlotStatus => Phase::ReadyPower,
                        Command::PowerOn => Phase::Complete,
                    };
                }
            }
        }
        Ok(observations)
    }
}

fn validate(command: Command, response: &Response) -> Result<Observation, Error> {
    if response.slot != 0 {
        return Err(Error::SlotRejected);
    }
    if response.sequence != command.sequence() {
        return Err(Error::SequenceRejected);
    }
    let kind = match command {
        Command::GetSlotStatus => 0x81,
        Command::PowerOn => 0x80,
    };
    if response.message_type != kind {
        return Err(Error::ResponseTypeRejected);
    }
    if response.status & 0x3c != 0 || response.status & 3 == 3 || response.status >> 6 == 3 {
        return Err(Error::StatusReserved);
    }
    match response.status >> 6 {
        1 => return Err(Error::CommandFailed),
        2 => return Err(Error::TimeExtensionRejected),
        _ => (),
    }
    if response.error != 0 {
        return Err(Error::StatusErrorRejected);
    }
    match (command, response.status & 3) {
        (_, 2) => return Err(Error::CardAbsent),
        (Command::GetSlotStatus, 0) => return Err(Error::AlreadyActive),
        (Command::PowerOn, 1) => return Err(Error::IccStatusRejected),
        _ => (),
    }
    match command {
        Command::GetSlotStatus => {
            if !response.payload().is_empty() {
                return Err(Error::PayloadRejected);
            }
            // R3: the raw clock byte is an observation, not an acceptance gate.
            Ok(Observation::SlotStatus {
                status: response.status,
                error: response.error,
                clock: response.parameter,
            })
        }
        Command::PowerOn => {
            if response.parameter != 0 {
                return Err(Error::ChainingRejected);
            }
            if response.payload() != REGISTERED_ATR {
                return Err(Error::AtrRejected);
            }
            Ok(Observation::Atr(REGISTERED_ATR))
        }
    }
}
