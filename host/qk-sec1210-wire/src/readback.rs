//! QK-DEC-167-SUP-003's separate, caller-clocked CCID session.
//! The old status/ATR probe and its limits are not changed by this API.
use crate::{Decoder, Error, Message, Response, REGISTERED_ATR};

pub const READBACK_MAX_COMMANDS: usize = 128;
pub const READBACK_MAX_EVENTS: usize = 64;
pub const READBACK_MAX_RECEIVED_BYTES: usize = 8192;
pub const READBACK_COMMAND_BUDGET_MS: u64 = 5000;
pub const READBACK_MAX_OUTGOING_TPDU_BYTES: usize = 34;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ReadbackError {
    Wire(Error),
    StateRejected,
    CommandLimitExceeded,
    TransferPayloadRejected,
    ProtocolRejected,
    IfscRejected,
    LrcModeRejected,
}

impl ReadbackError {
    pub fn name(self) -> &'static str {
        match self {
            Self::Wire(error) => error.name(),
            Self::StateRejected => "Sec1210ReadbackStateRejected",
            Self::CommandLimitExceeded => "Sec1210ReadbackCommandLimitExceeded",
            Self::TransferPayloadRejected => "Sec1210TransferPayloadRejected",
            Self::ProtocolRejected => "Sec1210ProtocolRejected",
            Self::IfscRejected => "Sec1210IfscRejected",
            Self::LrcModeRejected => "Sec1210LrcModeRejected",
        }
    }
}
impl From<Error> for ReadbackError {
    fn from(error: Error) -> Self {
        Self::Wire(error)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ReadbackCommand {
    GetSlotStatus,
    PowerOn,
    GetParameters,
    XfrBlock,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ReadbackPhase {
    ReadyStatus,
    ReadyPower,
    ReadyParameters,
    ReadyTransfer,
    Writing(ReadbackCommand),
    Receiving(ReadbackCommand),
    Failed,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ReadbackRequest {
    command: ReadbackCommand,
    sequence: u8,
    bytes: [u8; 13 + READBACK_MAX_OUTGOING_TPDU_BYTES],
    len: usize,
}
impl ReadbackRequest {
    pub fn command(&self) -> ReadbackCommand {
        self.command
    }
    pub fn sequence(&self) -> u8 {
        self.sequence
    }
    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes[..self.len]
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ReadbackObservation {
    SlotChange { bitmap: u8, slot1_bits: u8 },
    HardwareError { slot: u8, sequence: u8, code: u8 },
    SlotStatus { status: u8, error: u8, clock: u8 },
    Atr([u8; 15]),
    Parameters { protocol: u8, bytes: [u8; 7] },
    Transfer { sequence: u8, payload_bytes: usize },
}

pub struct ReadbackSession {
    phase: ReadbackPhase,
    decoder: Decoder,
    sequence: u8,
    request_len: usize,
    requests: usize,
    responses: usize,
    events: usize,
    received: usize,
    started: u64,
    last_now: Option<u64>,
    observations: Vec<ReadbackObservation>,
    response: Option<Box<Response>>,
    failure: Option<ReadbackError>,
}
impl Default for ReadbackSession {
    fn default() -> Self {
        Self {
            phase: ReadbackPhase::ReadyStatus,
            decoder: Decoder::default(),
            sequence: 0,
            request_len: 0,
            requests: 0,
            responses: 0,
            events: 0,
            received: 0,
            started: 0,
            last_now: None,
            observations: Vec::new(),
            response: None,
            failure: None,
        }
    }
}

impl ReadbackSession {
    pub fn phase(&self) -> ReadbackPhase {
        self.phase
    }
    pub fn requests(&self) -> usize {
        self.requests
    }
    pub fn responses(&self) -> usize {
        self.responses
    }
    pub fn events(&self) -> usize {
        self.events
    }
    pub fn received_bytes(&self) -> usize {
        self.received
    }
    pub fn sequence(&self) -> u8 {
        self.sequence
    }
    pub fn failure(&self) -> Option<ReadbackError> {
        self.failure
    }
    pub fn observations(&self) -> &[ReadbackObservation] {
        &self.observations
    }
    /// The last accepted response is retained until the next command is claimed.
    pub fn response(&self) -> Option<&Response> {
        self.response.as_deref()
    }

    fn reject<T>(&mut self, error: impl Into<ReadbackError>) -> Result<T, ReadbackError> {
        let error = *self.failure.get_or_insert(error.into());
        self.phase = ReadbackPhase::Failed;
        Err(error)
    }

    pub fn tick(&mut self, now_ms: u64) -> Result<(), ReadbackError> {
        if let Some(error) = self.failure {
            return Err(error);
        }
        if self.last_now.is_some_and(|last| now_ms < last) {
            return self.reject(Error::ClockRegression);
        }
        self.last_now = Some(now_ms);
        if matches!(
            self.phase,
            ReadbackPhase::Writing(_) | ReadbackPhase::Receiving(_)
        ) && now_ms - self.started >= READBACK_COMMAND_BUDGET_MS
        {
            return self.reject(if self.decoder.pending_bytes() == 0 {
                Error::DeadlineExceeded
            } else {
                Error::PartialFrameDeadline
            });
        }
        Ok(())
    }

    pub fn begin_initial(&mut self, now_ms: u64) -> Result<ReadbackRequest, ReadbackError> {
        self.tick(now_ms)?;
        let command = match self.phase {
            ReadbackPhase::ReadyStatus => ReadbackCommand::GetSlotStatus,
            ReadbackPhase::ReadyPower => ReadbackCommand::PowerOn,
            ReadbackPhase::ReadyParameters => ReadbackCommand::GetParameters,
            _ => return self.reject(ReadbackError::StateRejected),
        };
        self.claim(command, &[], now_ms)
    }

    /// Only a complete bounded TPDU may be wrapped. This pure API performs no
    /// transmission and does not provide an application-command interface.
    pub fn begin_transfer(
        &mut self,
        tpdu: &[u8],
        now_ms: u64,
    ) -> Result<ReadbackRequest, ReadbackError> {
        self.tick(now_ms)?;
        if self.phase != ReadbackPhase::ReadyTransfer {
            return self.reject(ReadbackError::StateRejected);
        }
        if !(4..=READBACK_MAX_OUTGOING_TPDU_BYTES).contains(&tpdu.len())
            || usize::from(tpdu[2]) + 4 != tpdu.len()
            || tpdu.iter().fold(0, |a, b| a ^ b) != 0
        {
            return self.reject(ReadbackError::TransferPayloadRejected);
        }
        self.claim(ReadbackCommand::XfrBlock, tpdu, now_ms)
    }

    fn claim(
        &mut self,
        command: ReadbackCommand,
        payload: &[u8],
        now_ms: u64,
    ) -> Result<ReadbackRequest, ReadbackError> {
        if self.requests == READBACK_MAX_COMMANDS {
            return self.reject(ReadbackError::CommandLimitExceeded);
        }
        // The 128-command ceiling is below the sequence-byte wrap point.
        self.sequence = (self.requests + 1) as u8;
        let mut request = ReadbackRequest {
            command,
            sequence: self.sequence,
            bytes: [0; 13 + READBACK_MAX_OUTGOING_TPDU_BYTES],
            len: 13 + payload.len(),
        };
        request.bytes[0] = 3;
        request.bytes[1] = 6;
        request.bytes[2] = match command {
            ReadbackCommand::GetSlotStatus => 0x65,
            ReadbackCommand::PowerOn => 0x62,
            ReadbackCommand::GetParameters => 0x6c,
            ReadbackCommand::XfrBlock => 0x6f,
        };
        request.bytes[3..7].copy_from_slice(&(payload.len() as u32).to_le_bytes());
        request.bytes[8] = self.sequence;
        if command == ReadbackCommand::PowerOn {
            request.bytes[9] = 2;
        }
        request.bytes[12..12 + payload.len()].copy_from_slice(payload);
        request.bytes[request.len - 1] = request.bytes[..request.len - 1]
            .iter()
            .fold(0, |a, b| a ^ b);
        self.request_len = request.len;
        self.response = None;
        self.started = now_ms;
        self.phase = ReadbackPhase::Writing(command);
        Ok(request)
    }

    pub fn written(&mut self, bytes: usize, now_ms: u64) -> Result<(), ReadbackError> {
        if let Some(error) = self.failure {
            return Err(error);
        }
        let ReadbackPhase::Writing(command) = self.phase else {
            return self.reject(ReadbackError::StateRejected);
        };
        if bytes != self.request_len {
            return self.reject(Error::PartialWrite);
        }
        self.requests += 1;
        self.tick(now_ms)?;
        self.phase = ReadbackPhase::Receiving(command);
        Ok(())
    }

    pub fn receive(&mut self, bytes: &[u8], now_ms: u64) -> Result<(), ReadbackError> {
        self.tick(now_ms)?;
        let ReadbackPhase::Receiving(command) = self.phase else {
            return self.reject(Error::UnsolicitedResponse);
        };
        if bytes.len() > READBACK_MAX_RECEIVED_BYTES - self.received {
            return self.reject(Error::ReceiveLimitExceeded);
        }
        self.received += bytes.len();
        for (index, byte) in bytes.iter().enumerate() {
            let message = match self.decoder.push(*byte) {
                Ok(Some(message)) => message,
                Ok(None) => continue,
                Err(error) => return self.reject(error),
            };
            match message {
                Message::SlotChange { bitmap } => {
                    self.events += 1;
                    if self.events > READBACK_MAX_EVENTS {
                        return self.reject(Error::EventLimitExceeded);
                    }
                    self.observations.push(ReadbackObservation::SlotChange {
                        bitmap,
                        slot1_bits: (bitmap >> 2) & 3,
                    });
                    if bitmap & 0xf0 != 0 {
                        return self.reject(Error::EventBitmapRejected);
                    }
                    if bitmap & 1 == 0 {
                        return self.reject(Error::CardAbsent);
                    }
                }
                Message::HardwareError {
                    slot,
                    sequence,
                    code,
                } => {
                    self.events += 1;
                    if self.events > READBACK_MAX_EVENTS {
                        return self.reject(Error::EventLimitExceeded);
                    }
                    self.observations.push(ReadbackObservation::HardwareError {
                        slot,
                        sequence,
                        code,
                    });
                    if slot != 0 {
                        return self.reject(Error::SlotRejected);
                    }
                    if sequence != self.sequence {
                        return self.reject(Error::SequenceRejected);
                    }
                    return self.reject(Error::HardwareError);
                }
                Message::Response(response) => {
                    if let Err(error) = self.validate(command, &response) {
                        return self.reject(error);
                    }
                    if index + 1 != bytes.len() {
                        return self.reject(Error::TrailingData);
                    }
                    self.responses += 1;
                    self.response = Some(response);
                    self.phase = match command {
                        ReadbackCommand::GetSlotStatus => ReadbackPhase::ReadyPower,
                        ReadbackCommand::PowerOn => ReadbackPhase::ReadyParameters,
                        ReadbackCommand::GetParameters | ReadbackCommand::XfrBlock => {
                            ReadbackPhase::ReadyTransfer
                        }
                    };
                }
            }
        }
        Ok(())
    }

    fn validate(
        &mut self,
        command: ReadbackCommand,
        response: &Response,
    ) -> Result<(), ReadbackError> {
        if response.slot != 0 {
            return Err(Error::SlotRejected.into());
        }
        if response.sequence != self.sequence {
            return Err(Error::SequenceRejected.into());
        }
        if response.status & 0x3c != 0 || response.status & 3 == 3 || response.status >> 6 == 3 {
            return Err(Error::StatusReserved.into());
        }
        // Time extension precedes both expected response type and bError. In
        // particular, a SlotStatus extension during XfrBlock is not a retry.
        match response.status >> 6 {
            2 => return Err(Error::TimeExtensionRejected.into()),
            1 => return Err(Error::CommandFailed.into()),
            _ => (),
        }
        let kind = match command {
            ReadbackCommand::GetSlotStatus => 0x81,
            ReadbackCommand::GetParameters => 0x82,
            ReadbackCommand::PowerOn | ReadbackCommand::XfrBlock => 0x80,
        };
        if response.message_type != kind {
            return Err(Error::ResponseTypeRejected.into());
        }
        if response.error != 0 {
            return Err(Error::StatusErrorRejected.into());
        }
        let icc = response.status & 3;
        if icc == 2 {
            return Err(Error::CardAbsent.into());
        }
        if command == ReadbackCommand::GetSlotStatus {
            if icc == 0 {
                return Err(Error::AlreadyActive.into());
            }
        } else if icc != 0 {
            return Err(Error::IccStatusRejected.into());
        }
        let observation = match command {
            ReadbackCommand::GetSlotStatus => {
                if !response.payload().is_empty() {
                    return Err(Error::PayloadRejected.into());
                }
                ReadbackObservation::SlotStatus {
                    status: response.status,
                    error: response.error,
                    clock: response.parameter,
                }
            }
            ReadbackCommand::PowerOn => {
                if response.parameter != 0 {
                    return Err(Error::ChainingRejected.into());
                }
                if response.payload() != REGISTERED_ATR {
                    return Err(Error::AtrRejected.into());
                }
                ReadbackObservation::Atr(REGISTERED_ATR)
            }
            ReadbackCommand::GetParameters => {
                let Ok(bytes) = <[u8; 7]>::try_from(response.payload()) else {
                    return Err(Error::PayloadRejected.into());
                };
                // All seven bytes remain available as evidence even when one
                // of the three parameter gates below rejects the response.
                self.observations.push(ReadbackObservation::Parameters {
                    protocol: response.parameter,
                    bytes,
                });
                if response.parameter != 1 {
                    return Err(ReadbackError::ProtocolRejected);
                }
                if bytes[5] != 0xfe {
                    return Err(ReadbackError::IfscRejected);
                }
                if bytes[1] & 1 != 0 {
                    return Err(ReadbackError::LrcModeRejected);
                }
                return Ok(());
            }
            ReadbackCommand::XfrBlock => {
                if response.parameter != 0 {
                    return Err(Error::ChainingRejected.into());
                }
                ReadbackObservation::Transfer {
                    sequence: response.sequence,
                    payload_bytes: response.payload().len(),
                }
            }
        };
        self.observations.push(observation);
        Ok(())
    }
}
