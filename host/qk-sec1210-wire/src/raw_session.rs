//! SUP-013's fixed-initialization, raw-response sibling session.
//!
//! The caller first validates the IFS reply with its T=1 session, then calls
//! `accept_ifs`. For each APDU it calls `begin_apdu`, wraps each block produced
//! by that T=1 session, and calls `end_apdu` only after T=1 accepts the final
//! I-block. Neither a reader extension nor a WTX exchange resets that boundary.
use crate::{Decoder, Error, Message, Response, FIDI_PARAMETERS, REGISTERED_ATR};

pub const RAW_MAX_COMMANDS: usize = 512;
pub const RAW_MAX_EVENTS: usize = 64;
pub const RAW_MAX_RECEIVED_BYTES: usize = 32_768;
pub const RAW_MAX_OUTGOING_TPDU_BYTES: usize = 258;
pub const RAW_COMMAND_BUDGET_MS: u64 = 5_000;
pub const RAW_APDU_BUDGET_MS: u64 = 30_000;
pub const RAW_BWT_MS: u64 = 1_190;
pub const RAW_MAX_TIME_EXTENSIONS: usize = 8;
pub const RAW_MAX_WTX_MULTIPLIER: u8 = 24;

const IFS_REQUEST: [u8; 5] = [0x00, 0xc1, 0x01, 0xfe, 0x3e];
const IFS_RESPONSE: [u8; 5] = [0x00, 0xe1, 0x01, 0xfe, 0x1e];

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RawError {
    Wire(Error),
    StateRejected,
    CommandLimitExceeded,
    TransferPayloadRejected,
    ProtocolRejected,
    IfscRejected,
    LrcModeRejected,
    SetParametersEchoRejected,
    IfsRejected,
    WtxMultiplierRejected,
    WtxResponseRejected,
    TimeExtensionShapeRejected,
    TimeExtensionLimitExceeded,
    ApduDeadlineExceeded,
}

impl RawError {
    pub fn name(self) -> &'static str {
        match self {
            Self::Wire(error) => error.name(),
            Self::StateRejected => "Sec1210SessionStateRejected",
            Self::CommandLimitExceeded => "Sec1210SessionCommandLimitExceeded",
            Self::TransferPayloadRejected => "Sec1210TransferPayloadRejected",
            Self::ProtocolRejected => "Sec1210ProtocolRejected",
            Self::IfscRejected => "Sec1210IfscRejected",
            Self::LrcModeRejected => "Sec1210LrcModeRejected",
            Self::SetParametersEchoRejected => "Sec1210SetParametersEchoRejected",
            Self::IfsRejected => "T1IfsRejected",
            Self::WtxMultiplierRejected => "T1WtxMultiplierRejected",
            Self::WtxResponseRejected => "T1WtxResponseRejected",
            Self::TimeExtensionShapeRejected => "Sec1210TimeExtensionShapeRejected",
            Self::TimeExtensionLimitExceeded => "Sec1210TimeExtensionLimitExceeded",
            Self::ApduDeadlineExceeded => "T1DeadlineExceeded",
        }
    }
}

impl From<Error> for RawError {
    fn from(error: Error) -> Self {
        Self::Wire(error)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RawCommand {
    GetSlotStatus,
    PowerOn,
    GetParameters,
    SetParameters,
    XfrBlock,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RawPhase {
    ReadyStatus,
    ReadyPower,
    ReadyParameters,
    ReadySetParameters,
    ReadyIfs,
    AwaitIfsAcceptance,
    ReadyApdu,
    ReadyTransfer,
    Writing(RawCommand),
    Receiving(RawCommand),
    Failed,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RawRequest {
    command: RawCommand,
    ordinal: usize,
    sequence: u8,
    bwi: u8,
    host_allowance_ms: u64,
    deadline_ms: u64,
    apdu_deadline_ms: Option<u64>,
    bytes: [u8; 13 + RAW_MAX_OUTGOING_TPDU_BYTES],
    len: usize,
}

impl RawRequest {
    pub fn command(&self) -> RawCommand {
        self.command
    }
    pub fn ordinal(&self) -> usize {
        self.ordinal
    }
    pub fn sequence(&self) -> u8 {
        self.sequence
    }
    pub fn bwi(&self) -> u8 {
        self.bwi
    }
    /// The nominal allowance before clipping to the original APDU deadline.
    pub fn host_allowance_ms(&self) -> u64 {
        self.host_allowance_ms
    }
    pub fn deadline_ms(&self) -> u64 {
        self.deadline_ms
    }
    pub fn apdu_deadline_ms(&self) -> Option<u64> {
        self.apdu_deadline_ms
    }
    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes[..self.len]
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum RawObservation {
    SlotChange {
        bitmap: u8,
        slot1_bits: u8,
    },
    HardwareError {
        slot: u8,
        sequence: u8,
        code: u8,
    },
    SlotStatus {
        status: u8,
        error: u8,
        clock: u8,
    },
    Atr([u8; 15]),
    Parameters {
        protocol: u8,
        bytes: [u8; 7],
    },
    Transfer {
        ordinal: usize,
        sequence: u8,
        payload_bytes: usize,
    },
    TimeExtension {
        ordinal: usize,
        sequence: u8,
        multiplier: u8,
        apdu_count: usize,
        invocation_count: usize,
        command_deadline_ms: u64,
        apdu_deadline_ms: u64,
        span: RawFrameSpan,
    },
}

/// Half-open byte offsets in this invocation's received UART byte stream.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RawFrameSpan {
    pub start_rx_offset: usize,
    pub end_rx_offset: usize,
}

pub struct RawSession {
    phase: RawPhase,
    decoder: Decoder,
    sequence: u8,
    ordinal: usize,
    request_len: usize,
    requests: usize,
    responses: usize,
    events: usize,
    received: usize,
    host_allowance_ms: u64,
    command_deadline: u64,
    apdu_deadline: Option<u64>,
    last_now: Option<u64>,
    observations: Vec<RawObservation>,
    response: Option<Box<Response>>,
    reply_evidence: Option<Box<Response>>,
    frame_start_rx_offset: usize,
    last_reply_span: Option<RawFrameSpan>,
    set_parameters_reply_evidence: Option<Box<Response>>,
    set_parameters_accepted: bool,
    ifs_accepted: bool,
    ifs_pending: bool,
    apdu_has_transfer: bool,
    awaiting_wtx: Option<u8>,
    time_extensions: usize,
    apdu_time_extensions: usize,
    failure: Option<RawError>,
}

impl Default for RawSession {
    fn default() -> Self {
        Self {
            phase: RawPhase::ReadyStatus,
            decoder: Decoder::default(),
            sequence: 0,
            ordinal: 0,
            request_len: 0,
            requests: 0,
            responses: 0,
            events: 0,
            received: 0,
            host_allowance_ms: RAW_COMMAND_BUDGET_MS,
            command_deadline: 0,
            apdu_deadline: None,
            last_now: None,
            observations: Vec::new(),
            response: None,
            reply_evidence: None,
            frame_start_rx_offset: 0,
            last_reply_span: None,
            set_parameters_reply_evidence: None,
            set_parameters_accepted: false,
            ifs_accepted: false,
            ifs_pending: false,
            apdu_has_transfer: false,
            awaiting_wtx: None,
            time_extensions: 0,
            apdu_time_extensions: 0,
            failure: None,
        }
    }
}

impl RawSession {
    pub fn new() -> Self {
        Self::default()
    }
    pub fn phase(&self) -> RawPhase {
        self.phase
    }
    pub fn requests(&self) -> usize {
        self.requests
    }
    /// Final accepted CCID responses only; reader extensions are not final.
    pub fn responses(&self) -> usize {
        self.responses
    }
    pub fn ordinal(&self) -> usize {
        self.ordinal
    }
    pub fn sequence(&self) -> u8 {
        self.sequence
    }
    pub fn events(&self) -> usize {
        self.events
    }
    pub fn received_bytes(&self) -> usize {
        self.received
    }
    pub fn time_extension_count(&self) -> usize {
        self.time_extensions
    }
    pub fn apdu_time_extension_count(&self) -> usize {
        self.apdu_time_extensions
    }
    pub fn host_allowance_ms(&self) -> u64 {
        self.host_allowance_ms
    }
    pub fn command_deadline_ms(&self) -> u64 {
        self.command_deadline
    }
    pub fn apdu_deadline_ms(&self) -> Option<u64> {
        self.apdu_deadline
    }
    pub fn failure(&self) -> Option<RawError> {
        self.failure
    }
    /// Bounded by the received-byte, command and asynchronous-event ceilings.
    pub fn observations(&self) -> &[RawObservation] {
        &self.observations
    }
    pub fn response(&self) -> Option<&Response> {
        self.response.as_deref()
    }
    /// The current command's last complete checksum-verified reply, even if
    /// semantic gates fail. The next claim clears this and its matching span.
    pub fn reply_evidence(&self) -> Option<&Response> {
        self.reply_evidence.as_deref()
    }
    pub fn last_reply_span(&self) -> Option<RawFrameSpan> {
        self.last_reply_span
    }
    pub fn set_parameters_reply_evidence(&self) -> Option<&Response> {
        self.set_parameters_reply_evidence.as_deref()
    }
    pub fn set_parameters_accepted(&self) -> bool {
        self.set_parameters_accepted
    }
    pub fn ifs_accepted(&self) -> bool {
        self.ifs_accepted
    }

    fn reject<T>(&mut self, error: impl Into<RawError>) -> Result<T, RawError> {
        let error = *self.failure.get_or_insert(error.into());
        self.phase = RawPhase::Failed;
        Err(error)
    }

    pub fn tick(&mut self, now_ms: u64) -> Result<(), RawError> {
        if let Some(error) = self.failure {
            return Err(error);
        }
        if self.last_now.is_some_and(|last| now_ms < last) {
            return self.reject(Error::ClockRegression);
        }
        self.last_now = Some(now_ms);
        // The absolute APDU budget has precedence even with a partial frame.
        if self
            .apdu_deadline
            .is_some_and(|deadline| now_ms >= deadline)
        {
            return self.reject(RawError::ApduDeadlineExceeded);
        }
        if matches!(self.phase, RawPhase::Writing(_) | RawPhase::Receiving(_))
            && now_ms >= self.command_deadline
        {
            return self.reject(if self.decoder.pending_bytes() == 0 {
                Error::DeadlineExceeded
            } else {
                Error::PartialFrameDeadline
            });
        }
        Ok(())
    }

    pub fn begin_initial(&mut self, now_ms: u64) -> Result<RawRequest, RawError> {
        self.tick(now_ms)?;
        let command = match self.phase {
            RawPhase::ReadyStatus => RawCommand::GetSlotStatus,
            RawPhase::ReadyPower => RawCommand::PowerOn,
            RawPhase::ReadyParameters => RawCommand::GetParameters,
            RawPhase::ReadySetParameters => RawCommand::SetParameters,
            _ => return self.reject(RawError::StateRejected),
        };
        let payload: &[u8] = if command == RawCommand::SetParameters {
            &FIDI_PARAMETERS
        } else {
            &[]
        };
        self.claim(command, payload, 0, now_ms)
    }

    pub fn begin_ifs_transfer(&mut self, tpdu: &[u8], now_ms: u64) -> Result<RawRequest, RawError> {
        self.tick(now_ms)?;
        if self.phase != RawPhase::ReadyIfs {
            return self.reject(RawError::StateRejected);
        }
        if tpdu != IFS_REQUEST {
            return self.reject(RawError::IfsRejected);
        }
        self.ifs_pending = true;
        self.claim(RawCommand::XfrBlock, tpdu, 0, now_ms)
    }

    /// Called only after the paired T=1 session has validated this same echo.
    /// Its exact-byte check here prevents trusting an unchecked caller flag.
    pub fn accept_ifs(&mut self, now_ms: u64) -> Result<(), RawError> {
        self.tick(now_ms)?;
        if self.phase != RawPhase::AwaitIfsAcceptance {
            return self.reject(RawError::StateRejected);
        }
        if self.response().map(Response::payload) != Some(IFS_RESPONSE.as_slice()) {
            return self.reject(RawError::IfsRejected);
        }
        self.ifs_pending = false;
        self.ifs_accepted = true;
        self.phase = RawPhase::ReadyApdu;
        Ok(())
    }

    pub fn begin_apdu(&mut self, now_ms: u64) -> Result<(), RawError> {
        self.tick(now_ms)?;
        if self.phase != RawPhase::ReadyApdu || !self.ifs_accepted {
            return self.reject(RawError::StateRejected);
        }
        self.apdu_deadline = Some(now_ms.saturating_add(RAW_APDU_BUDGET_MS));
        self.apdu_time_extensions = 0;
        self.apdu_has_transfer = false;
        self.awaiting_wtx = None;
        self.phase = RawPhase::ReadyTransfer;
        Ok(())
    }

    /// Wrap a block accepted for sending by the paired T=1 session. A nonzero
    /// bBWI is additionally tied to the preceding exact card WTX request.
    pub fn begin_transfer(
        &mut self,
        tpdu: &[u8],
        bwi: u8,
        now_ms: u64,
    ) -> Result<RawRequest, RawError> {
        self.tick(now_ms)?;
        if self.phase != RawPhase::ReadyTransfer || self.apdu_deadline.is_none() {
            return self.reject(RawError::StateRejected);
        }
        if !(4..=RAW_MAX_OUTGOING_TPDU_BYTES).contains(&tpdu.len())
            || usize::from(tpdu[2]) + 4 != tpdu.len()
            || tpdu.iter().fold(0, |sum, byte| sum ^ byte) != 0
        {
            return self.reject(RawError::TransferPayloadRejected);
        }
        if bwi > RAW_MAX_WTX_MULTIPLIER {
            return self.reject(RawError::WtxMultiplierRejected);
        }
        if bwi == 0 {
            if self.awaiting_wtx.is_some() || self.apdu_has_transfer {
                return self.reject(RawError::WtxResponseRejected);
            }
        } else if self.awaiting_wtx != Some(bwi) || tpdu != [0, 0xe3, 1, bwi, 0xe2 ^ bwi] {
            return self.reject(RawError::WtxResponseRejected);
        }
        self.awaiting_wtx = None;
        self.claim(RawCommand::XfrBlock, tpdu, bwi, now_ms)
    }

    /// The upper T=1 session must already have accepted the final I-block.
    /// A WTX request is never a valid APDU endpoint in this lower layer either.
    pub fn end_apdu(&mut self, now_ms: u64) -> Result<(), RawError> {
        self.tick(now_ms)?;
        if self.phase != RawPhase::ReadyTransfer
            || self.apdu_deadline.is_none()
            || !self.apdu_has_transfer
            || self.awaiting_wtx.is_some()
        {
            return self.reject(RawError::StateRejected);
        }
        self.apdu_deadline = None;
        self.phase = RawPhase::ReadyApdu;
        Ok(())
    }

    fn claim(
        &mut self,
        command: RawCommand,
        payload: &[u8],
        bwi: u8,
        now_ms: u64,
    ) -> Result<RawRequest, RawError> {
        if self.requests >= RAW_MAX_COMMANDS {
            return self.reject(RawError::CommandLimitExceeded);
        }
        self.ordinal = self.requests + 1;
        self.sequence = self.ordinal as u8;
        self.host_allowance_ms = RAW_COMMAND_BUDGET_MS.max(u64::from(bwi) * RAW_BWT_MS);
        let deadline = now_ms.saturating_add(self.host_allowance_ms);
        self.command_deadline = self
            .apdu_deadline
            .map_or(deadline, |apdu| apdu.min(deadline));
        let mut request = RawRequest {
            command,
            ordinal: self.ordinal,
            sequence: self.sequence,
            bwi,
            host_allowance_ms: self.host_allowance_ms,
            deadline_ms: self.command_deadline,
            apdu_deadline_ms: self.apdu_deadline,
            bytes: [0; 13 + RAW_MAX_OUTGOING_TPDU_BYTES],
            len: 13 + payload.len(),
        };
        request.bytes[..3].copy_from_slice(&[
            3,
            6,
            match command {
                RawCommand::GetSlotStatus => 0x65,
                RawCommand::PowerOn => 0x62,
                RawCommand::GetParameters => 0x6c,
                RawCommand::SetParameters => 0x61,
                RawCommand::XfrBlock => 0x6f,
            },
        ]);
        request.bytes[3..7].copy_from_slice(&(payload.len() as u32).to_le_bytes());
        request.bytes[8] = self.sequence;
        request.bytes[9] = match command {
            RawCommand::PowerOn => 2,
            RawCommand::SetParameters => 1,
            RawCommand::XfrBlock => bwi,
            _ => 0,
        };
        request.bytes[12..12 + payload.len()].copy_from_slice(payload);
        request.bytes[request.len - 1] = request.bytes[..request.len - 1]
            .iter()
            .fold(0, |sum, byte| sum ^ byte);
        self.request_len = request.len;
        self.response = None;
        self.reply_evidence = None;
        self.last_reply_span = None;
        self.phase = RawPhase::Writing(command);
        Ok(request)
    }

    pub fn written(&mut self, bytes: usize, now_ms: u64) -> Result<(), RawError> {
        self.tick(now_ms)?;
        let RawPhase::Writing(command) = self.phase else {
            return self.reject(RawError::StateRejected);
        };
        if bytes != self.request_len {
            return self.reject(Error::PartialWrite);
        }
        self.requests += 1;
        self.phase = RawPhase::Receiving(command);
        Ok(())
    }

    pub fn receive(&mut self, bytes: &[u8], now_ms: u64) -> Result<(), RawError> {
        self.tick(now_ms)?;
        let RawPhase::Receiving(command) = self.phase else {
            return self.reject(Error::UnsolicitedResponse);
        };
        if bytes.len() > RAW_MAX_RECEIVED_BYTES - self.received {
            return self.reject(Error::ReceiveLimitExceeded);
        }
        let fragment_start = self.received;
        self.received += bytes.len();
        for (index, byte) in bytes.iter().enumerate() {
            if self.decoder.pending_bytes() == 0 {
                self.frame_start_rx_offset = fragment_start + index;
            }
            let message = match self.decoder.push(*byte) {
                Ok(Some(message)) => message,
                Ok(None) => continue,
                Err(error) => return self.reject(error),
            };
            match message {
                Message::SlotChange { bitmap } => {
                    self.events += 1;
                    if self.events > RAW_MAX_EVENTS {
                        return self.reject(Error::EventLimitExceeded);
                    }
                    self.observations.push(RawObservation::SlotChange {
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
                    if self.events > RAW_MAX_EVENTS {
                        return self.reject(Error::EventLimitExceeded);
                    }
                    self.observations.push(RawObservation::HardwareError {
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
                    self.reply_evidence = Some(response.clone());
                    self.last_reply_span = Some(RawFrameSpan {
                        start_rx_offset: self.frame_start_rx_offset,
                        end_rx_offset: fragment_start + index + 1,
                    });
                    if command == RawCommand::SetParameters {
                        self.set_parameters_reply_evidence = Some(response.clone());
                    }
                    let extension = match self.validate(command, &response) {
                        Ok(extension) => extension,
                        Err(error) => return self.reject(error),
                    };
                    if extension {
                        continue;
                    }
                    if index + 1 != bytes.len() {
                        return self.reject(Error::TrailingData);
                    }
                    self.responses += 1;
                    if command == RawCommand::XfrBlock && self.apdu_deadline.is_some() {
                        self.apdu_has_transfer = true;
                        self.awaiting_wtx = wtx_multiplier(response.payload());
                    }
                    self.response = Some(response);
                    self.phase = match command {
                        RawCommand::GetSlotStatus => RawPhase::ReadyPower,
                        RawCommand::PowerOn => RawPhase::ReadyParameters,
                        RawCommand::GetParameters => RawPhase::ReadySetParameters,
                        RawCommand::SetParameters => {
                            self.set_parameters_accepted = true;
                            RawPhase::ReadyIfs
                        }
                        RawCommand::XfrBlock if self.ifs_pending => RawPhase::AwaitIfsAcceptance,
                        RawCommand::XfrBlock => RawPhase::ReadyTransfer,
                    };
                }
            }
        }
        Ok(())
    }

    /// Return true only for a nonfinal reader extension. Initialization keeps
    /// the historical status-before-type rejection precedence intact.
    fn validate(&mut self, command: RawCommand, response: &Response) -> Result<bool, RawError> {
        if response.slot != 0 {
            return Err(Error::SlotRejected.into());
        }
        if response.sequence != self.sequence {
            return Err(Error::SequenceRejected.into());
        }
        if response.status & 0x3c != 0 || response.status & 3 == 3 || response.status >> 6 == 3 {
            return Err(Error::StatusReserved.into());
        }
        let extension = response.status >> 6 == 2;
        if extension && (command != RawCommand::XfrBlock || self.apdu_deadline.is_none()) {
            return Err(Error::TimeExtensionRejected.into());
        }
        if response.status >> 6 == 1 {
            return Err(Error::CommandFailed.into());
        }
        let kind = match command {
            RawCommand::GetSlotStatus => 0x81,
            RawCommand::GetParameters | RawCommand::SetParameters => 0x82,
            RawCommand::PowerOn | RawCommand::XfrBlock => 0x80,
        };
        if response.message_type != kind {
            return Err(Error::ResponseTypeRejected.into());
        }
        if !extension && response.error != 0 {
            return Err(Error::StatusErrorRejected.into());
        }
        let icc = response.status & 3;
        if icc == 2 {
            return Err(Error::CardAbsent.into());
        }
        if command == RawCommand::GetSlotStatus {
            if icc == 0 {
                return Err(Error::AlreadyActive.into());
            }
        } else if icc != 0 {
            return Err(Error::IccStatusRejected.into());
        }
        if extension {
            if !response.payload().is_empty() || response.parameter != 0 {
                return Err(RawError::TimeExtensionShapeRejected);
            }
            if self.apdu_time_extensions == RAW_MAX_TIME_EXTENSIONS {
                return Err(RawError::TimeExtensionLimitExceeded);
            }
            self.apdu_time_extensions += 1;
            self.time_extensions += 1;
            self.observations.push(RawObservation::TimeExtension {
                ordinal: self.ordinal,
                sequence: self.sequence,
                multiplier: response.error,
                apdu_count: self.apdu_time_extensions,
                invocation_count: self.time_extensions,
                command_deadline_ms: self.command_deadline,
                apdu_deadline_ms: self.apdu_deadline.expect("active application exchange"),
                span: self
                    .last_reply_span
                    .expect("complete checksum-verified reply"),
            });
            return Ok(true);
        }
        let observation = match command {
            RawCommand::GetSlotStatus => {
                if !response.payload().is_empty() {
                    return Err(Error::PayloadRejected.into());
                }
                RawObservation::SlotStatus {
                    status: response.status,
                    error: response.error,
                    clock: response.parameter,
                }
            }
            RawCommand::PowerOn => {
                if response.parameter != 0 {
                    return Err(Error::ChainingRejected.into());
                }
                if response.payload() != REGISTERED_ATR {
                    return Err(Error::AtrRejected.into());
                }
                RawObservation::Atr(REGISTERED_ATR)
            }
            RawCommand::GetParameters | RawCommand::SetParameters => {
                let Ok(bytes) = <[u8; 7]>::try_from(response.payload()) else {
                    return Err(Error::PayloadRejected.into());
                };
                self.observations.push(RawObservation::Parameters {
                    protocol: response.parameter,
                    bytes,
                });
                if response.parameter != 1 {
                    return Err(RawError::ProtocolRejected);
                }
                if command == RawCommand::SetParameters {
                    if bytes != FIDI_PARAMETERS {
                        return Err(RawError::SetParametersEchoRejected);
                    }
                } else {
                    if bytes[5] != 0xfe {
                        return Err(RawError::IfscRejected);
                    }
                    if bytes[1] & 1 != 0 {
                        return Err(RawError::LrcModeRejected);
                    }
                }
                return Ok(false);
            }
            RawCommand::XfrBlock => {
                if response.parameter != 0 {
                    return Err(Error::ChainingRejected.into());
                }
                RawObservation::Transfer {
                    ordinal: self.ordinal,
                    sequence: response.sequence,
                    payload_bytes: response.payload().len(),
                }
            }
        };
        self.observations.push(observation);
        Ok(false)
    }
}

fn wtx_multiplier(payload: &[u8]) -> Option<u8> {
    (payload.len() == 5
        && payload[..3] == [0, 0xc3, 1]
        && payload.iter().fold(0, |sum, byte| sum ^ byte) == 0)
        .then(|| payload[3])
}
