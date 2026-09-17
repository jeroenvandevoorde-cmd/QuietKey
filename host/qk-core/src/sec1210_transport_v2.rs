//! Production SEC1210 transport foundation.
//!
//! The trusted platform supplies one already-open, already-configured
//! read-write descriptor and a monotonic clock. Reservation of that descriptor
//! is a platform assertion. This module neither opens a path nor controls the
//! apparatus, and it has no alternate runtime transport.

use crate::wipe;
use qk_sec1210_wire::{
    validate_production_atr, Error as WireError, ProductionDecoder, ProductionMessageKind,
    ProductionRequest, ProductionResponse, MAX_PRODUCTION_ATR_BYTES, MAX_WIRE_BYTES,
};
use qk_t1::{Error as T1Error, Phase as T1Phase, RawError as T1RawError, RawSession as T1Session};

/// QK-LIM-APDU-012: fixed T=1 command INF storage.
pub const QK_LIM_APDU_012_COMMAND_INF_BYTES: usize = 254;
/// QK-LIM-APDU-013: fixed T=1 response INF storage.
pub const QK_LIM_APDU_013_RESPONSE_INF_BYTES: usize = 254;
/// QK-LIM-APDU-014: accepted WTX multiplier maximum.
pub const QK_LIM_APDU_014_MAX_WTX_MULTIPLIER: u8 = 24;
/// QK-LIM-APDU-015: accepted WTX requests in one APDU.
pub const QK_LIM_APDU_015_MAX_WTX_PER_APDU: usize = 8;
/// QK-LIM-APDU-016: accepted reader time extensions in one APDU.
pub const QK_LIM_APDU_016_MAX_TIME_EXTENSIONS_PER_APDU: usize = 8;
/// QK-LIM-APDU-017: 5 setup commands plus 108 times 9 APDU commands.
pub const QK_LIM_APDU_017_MAX_CONTROLLER_COMMANDS: usize = 977;
/// QK-LIM-APDU-018: compositional receive envelope plus terminal diagnostics.
pub const QK_LIM_APDU_018_MAX_RECEIVED_BYTES: usize =
    PRE_HEADROOM_RECEIVED_BYTES + TERMINAL_DIAGNOSTIC_BYTES;
/// QK-LIM-APDU-019: base wait for one controller command.
pub const QK_LIM_APDU_019_BASE_COMMAND_WAIT_MS: u64 = 5_000;
/// QK-LIM-APDU-020: absolute deadline for one application APDU.
pub const QK_LIM_APDU_020_APDU_DEADLINE_MS: u64 = 30_000;

const SETUP_COMMANDS: usize = 5;
pub(crate) const MAX_APPLICATION_APDUS: usize = 108;
const MAX_EVENTS: usize = 64;
const MAX_CONTROLLER_COMMANDS_PER_APDU: usize = 1 + QK_LIM_APDU_015_MAX_WTX_PER_APDU;
const MAX_APPLICATION_COMMAND_BYTES: usize = qk_card_protocol::MAX_REQUEST_BYTES;
const MAX_APPLICATION_RESPONSE_BYTES: usize = qk_card_protocol::MAX_RESPONSE_BYTES;
const CONTROLLER_RESPONSE_OVERHEAD_BYTES: usize = 13;
const T1_BLOCK_OVERHEAD_BYTES: usize = 4;
const T1_CONTROL_INF_BYTES: usize = 1;
const SLOT_STATUS_RESPONSE_BYTES: usize = CONTROLLER_RESPONSE_OVERHEAD_BYTES;
const POWER_ON_RESPONSE_BYTES: usize =
    CONTROLLER_RESPONSE_OVERHEAD_BYTES + MAX_PRODUCTION_ATR_BYTES;
const GET_PARAMETERS_RESPONSE_BYTES: usize =
    CONTROLLER_RESPONSE_OVERHEAD_BYTES + FIDI_PARAMETERS.len();
const SET_PARAMETERS_RESPONSE_BYTES: usize =
    CONTROLLER_RESPONSE_OVERHEAD_BYTES + FIDI_PARAMETERS.len();
const IFS_RESPONSE_BYTES: usize =
    CONTROLLER_RESPONSE_OVERHEAD_BYTES + T1_BLOCK_OVERHEAD_BYTES + T1_CONTROL_INF_BYTES;
const SETUP_RECEIVED_BYTES: usize = SLOT_STATUS_RESPONSE_BYTES
    + POWER_ON_RESPONSE_BYTES
    + GET_PARAMETERS_RESPONSE_BYTES
    + SET_PARAMETERS_RESPONSE_BYTES
    + IFS_RESPONSE_BYTES;
const FINAL_APPLICATION_RESPONSE_BYTES: usize =
    CONTROLLER_RESPONSE_OVERHEAD_BYTES + T1_BLOCK_OVERHEAD_BYTES + MAX_APPLICATION_RESPONSE_BYTES;
const WTX_RESPONSE_BYTES: usize =
    CONTROLLER_RESPONSE_OVERHEAD_BYTES + T1_BLOCK_OVERHEAD_BYTES + T1_CONTROL_INF_BYTES;
const TIME_EXTENSION_RESPONSE_BYTES: usize = CONTROLLER_RESPONSE_OVERHEAD_BYTES;
const EVENT_RECORD_BYTES: usize = 4;
const PRE_HEADROOM_RECEIVED_BYTES: usize = SETUP_RECEIVED_BYTES
    + MAX_APPLICATION_APDUS
        * (FINAL_APPLICATION_RESPONSE_BYTES
            + QK_LIM_APDU_015_MAX_WTX_PER_APDU * WTX_RESPONSE_BYTES
            + QK_LIM_APDU_016_MAX_TIME_EXTENSIONS_PER_APDU * TIME_EXTENSION_RESPONSE_BYTES)
    + MAX_EVENTS * EVENT_RECORD_BYTES;
const TERMINAL_DIAGNOSTIC_BYTES: usize = MAX_WIRE_BYTES + EVENT_RECORD_BYTES;
const FIDI_PARAMETERS: [u8; 7] = [0x18, 0x10, 0xff, 0x4d, 0x00, 0xfe, 0x00];

const _: () = assert!(QK_LIM_APDU_012_COMMAND_INF_BYTES == qk_t1::RAW_MAX_COMMAND_BYTES);
const _: () = assert!(QK_LIM_APDU_013_RESPONSE_INF_BYTES == qk_t1::RAW_MAX_RESPONSE_BYTES);
const _: () = assert!(QK_LIM_APDU_014_MAX_WTX_MULTIPLIER == qk_t1::RAW_MAX_WTX_MULTIPLIER);
const _: () = assert!(QK_LIM_APDU_015_MAX_WTX_PER_APDU == qk_t1::RAW_MAX_WTX);
const _: () = assert!(QK_LIM_APDU_019_BASE_COMMAND_WAIT_MS == qk_t1::RAW_BASE_COMMAND_BUDGET_MS);
const _: () = assert!(QK_LIM_APDU_020_APDU_DEADLINE_MS == qk_t1::RAW_APDU_BUDGET_MS);
const _: () = assert!(
    QK_LIM_APDU_017_MAX_CONTROLLER_COMMANDS
        == SETUP_COMMANDS + MAX_APPLICATION_APDUS * MAX_CONTROLLER_COMMANDS_PER_APDU
);
const _: () = assert!(QK_LIM_APDU_018_MAX_RECEIVED_BYTES == 52_815);

/// Fieldless descriptor failure supplied by the trusted platform adapter.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Sec1210DescriptorErrorV2;

/// Fieldless clock failure supplied by the trusted platform adapter.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Sec1210ClockErrorV2;

/// Result of one bounded descriptor read.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Sec1210DescriptorReadV2 {
    Bytes(usize),
    TimedOut,
    EndOfStream,
}

/// Result of one bounded descriptor write.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Sec1210DescriptorWriteV2 {
    Bytes(usize),
    TimedOut,
}

/// Already-open descriptor grant. The platform asserts its reservation.
pub trait Sec1210DescriptorV2 {
    /// The trusted adapter must return within `maximum_wait_ms`.
    fn write(
        &mut self,
        bytes: &[u8],
        maximum_wait_ms: u64,
    ) -> Result<Sec1210DescriptorWriteV2, Sec1210DescriptorErrorV2>;
    /// The trusted adapter must return within `maximum_wait_ms`.
    fn read(
        &mut self,
        bytes: &mut [u8],
        maximum_wait_ms: u64,
    ) -> Result<Sec1210DescriptorReadV2, Sec1210DescriptorErrorV2>;
}

/// Injected monotonic clock used for every controller and APDU deadline.
pub trait Sec1210MonotonicClockV2 {
    fn now_ms(&mut self) -> Result<u64, Sec1210ClockErrorV2>;
}

/// Closed production transport error taxonomy. Every leaf is fieldless.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CardTransportErrorV2 {
    Sec1210DescriptorReadFailed,
    Sec1210DescriptorWriteFailed,
    Sec1210DescriptorClosed,
    Sec1210ClockFailed,
    Sec1210ClockRegression,
    Sec1210StateRejected,
    Sec1210ApplicationCommandLengthRejected,
    Sec1210ApplicationResponseLengthRejected,
    Sec1210ApplicationApduLimitExceeded,
    Sec1210SessionCommandLimitExceeded,
    Sec1210SessionReceiveLimitExceeded,
    Sec1210EventLimitExceeded,
    Sec1210PrefixRejected,
    Sec1210LengthExceeded,
    Sec1210Truncated,
    Sec1210ChecksumRejected,
    Sec1210Nack,
    Sec1210SlotRejected,
    Sec1210SequenceRejected,
    Sec1210ResponseTypeRejected,
    Sec1210StatusReserved,
    Sec1210CommandFailed,
    Sec1210TimeExtensionRejected,
    Sec1210StatusErrorRejected,
    Sec1210AlreadyActive,
    Sec1210CardRemoved,
    Sec1210IccStatusRejected,
    Sec1210PayloadRejected,
    Sec1210ChainingRejected,
    Sec1210AtrProfileRejected,
    Sec1210EventBitmapRejected,
    Sec1210HardwareError,
    Sec1210UnsolicitedResponse,
    Sec1210TrailingData,
    Sec1210SequenceViolation,
    Sec1210PartialWrite,
    Sec1210DeadlineExceeded,
    Sec1210PartialFrameDeadline,
    Sec1210ParametersRejected,
    Sec1210SetParametersEchoRejected,
    Sec1210TimeExtensionShapeRejected,
    Sec1210TimeExtensionLimitExceeded,
    T1BlockLengthRejected,
    T1ChecksumRejected,
    T1NadRejected,
    T1PcbRejected,
    T1ControlLengthRejected,
    T1RetransmissionRejected,
    T1WtxRejected,
    T1IfsRejected,
    T1ResynchRejected,
    T1AbortRejected,
    T1UnexpectedRBlock,
    T1SequenceRejected,
    T1StateRejected,
    T1CommandLengthRejected,
    T1ResponseLengthRejected,
    T1ResponseMismatch,
    T1PartialWrite,
    T1ExchangeLimitExceeded,
    T1ApduLimitExceeded,
    T1DeadlineExceeded,
    T1ClockRegression,
    T1WtxMultiplierRejected,
    T1WtxLimitExceeded,
    T1WtxResponseRejected,
    T1ChainingRejected,
}

impl CardTransportErrorV2 {
    pub const fn name(self) -> &'static str {
        match self {
            Self::Sec1210DescriptorReadFailed => "Sec1210DescriptorReadFailed",
            Self::Sec1210DescriptorWriteFailed => "Sec1210DescriptorWriteFailed",
            Self::Sec1210DescriptorClosed => "Sec1210DescriptorClosed",
            Self::Sec1210ClockFailed => "Sec1210ClockFailed",
            Self::Sec1210ClockRegression => "Sec1210ClockRegression",
            Self::Sec1210StateRejected => "Sec1210StateRejected",
            Self::Sec1210ApplicationCommandLengthRejected => {
                "Sec1210ApplicationCommandLengthRejected"
            }
            Self::Sec1210ApplicationResponseLengthRejected => {
                "Sec1210ApplicationResponseLengthRejected"
            }
            Self::Sec1210ApplicationApduLimitExceeded => "Sec1210ApplicationApduLimitExceeded",
            Self::Sec1210SessionCommandLimitExceeded => "Sec1210SessionCommandLimitExceeded",
            Self::Sec1210SessionReceiveLimitExceeded => "Sec1210SessionReceiveLimitExceeded",
            Self::Sec1210EventLimitExceeded => "Sec1210EventLimitExceeded",
            Self::Sec1210PrefixRejected => "Sec1210PrefixRejected",
            Self::Sec1210LengthExceeded => "Sec1210LengthExceeded",
            Self::Sec1210Truncated => "Sec1210Truncated",
            Self::Sec1210ChecksumRejected => "Sec1210ChecksumRejected",
            Self::Sec1210Nack => "Sec1210Nack",
            Self::Sec1210SlotRejected => "Sec1210SlotRejected",
            Self::Sec1210SequenceRejected => "Sec1210SequenceRejected",
            Self::Sec1210ResponseTypeRejected => "Sec1210ResponseTypeRejected",
            Self::Sec1210StatusReserved => "Sec1210StatusReserved",
            Self::Sec1210CommandFailed => "Sec1210CommandFailed",
            Self::Sec1210TimeExtensionRejected => "Sec1210TimeExtensionRejected",
            Self::Sec1210StatusErrorRejected => "Sec1210StatusErrorRejected",
            Self::Sec1210AlreadyActive => "Sec1210AlreadyActive",
            Self::Sec1210CardRemoved => "Sec1210CardRemoved",
            Self::Sec1210IccStatusRejected => "Sec1210IccStatusRejected",
            Self::Sec1210PayloadRejected => "Sec1210PayloadRejected",
            Self::Sec1210ChainingRejected => "Sec1210ChainingRejected",
            Self::Sec1210AtrProfileRejected => "Sec1210AtrProfileRejected",
            Self::Sec1210EventBitmapRejected => "Sec1210EventBitmapRejected",
            Self::Sec1210HardwareError => "Sec1210HardwareError",
            Self::Sec1210UnsolicitedResponse => "Sec1210UnsolicitedResponse",
            Self::Sec1210TrailingData => "Sec1210TrailingData",
            Self::Sec1210SequenceViolation => "Sec1210SequenceViolation",
            Self::Sec1210PartialWrite => "Sec1210PartialWrite",
            Self::Sec1210DeadlineExceeded => "Sec1210DeadlineExceeded",
            Self::Sec1210PartialFrameDeadline => "Sec1210PartialFrameDeadline",
            Self::Sec1210ParametersRejected => "Sec1210ParametersRejected",
            Self::Sec1210SetParametersEchoRejected => "Sec1210SetParametersEchoRejected",
            Self::Sec1210TimeExtensionShapeRejected => "Sec1210TimeExtensionShapeRejected",
            Self::Sec1210TimeExtensionLimitExceeded => "Sec1210TimeExtensionLimitExceeded",
            Self::T1BlockLengthRejected => "T1BlockLengthRejected",
            Self::T1ChecksumRejected => "T1ChecksumRejected",
            Self::T1NadRejected => "T1NadRejected",
            Self::T1PcbRejected => "T1PcbRejected",
            Self::T1ControlLengthRejected => "T1ControlLengthRejected",
            Self::T1RetransmissionRejected => "T1RetransmissionRejected",
            Self::T1WtxRejected => "T1WtxRejected",
            Self::T1IfsRejected => "T1IfsRejected",
            Self::T1ResynchRejected => "T1ResynchRejected",
            Self::T1AbortRejected => "T1AbortRejected",
            Self::T1UnexpectedRBlock => "T1UnexpectedRBlock",
            Self::T1SequenceRejected => "T1SequenceRejected",
            Self::T1StateRejected => "T1StateRejected",
            Self::T1CommandLengthRejected => "T1CommandLengthRejected",
            Self::T1ResponseLengthRejected => "T1ResponseLengthRejected",
            Self::T1ResponseMismatch => "T1ResponseMismatch",
            Self::T1PartialWrite => "T1PartialWrite",
            Self::T1ExchangeLimitExceeded => "T1ExchangeLimitExceeded",
            Self::T1ApduLimitExceeded => "T1ApduLimitExceeded",
            Self::T1DeadlineExceeded => "T1DeadlineExceeded",
            Self::T1ClockRegression => "T1ClockRegression",
            Self::T1WtxMultiplierRejected => "T1WtxMultiplierRejected",
            Self::T1WtxLimitExceeded => "T1WtxLimitExceeded",
            Self::T1WtxResponseRejected => "T1WtxResponseRejected",
            Self::T1ChainingRejected => "T1ChainingRejected",
        }
    }
}

/// Fixed response owner returned to qk-core application policy.
pub struct CardTransportResponseV2 {
    bytes: [u8; MAX_APPLICATION_RESPONSE_BYTES],
    len: usize,
}

impl CardTransportResponseV2 {
    pub fn bytes(&self) -> &[u8] {
        self.bytes.get(..self.len).unwrap_or(&[])
    }
}

impl Drop for CardTransportResponseV2 {
    fn drop(&mut self) {
        wipe::bytes(&mut self.bytes);
        self.len = 0;
    }
}

#[derive(Clone, Copy, Eq, PartialEq)]
enum ControllerCommand {
    GetSlotStatus,
    PowerOn,
    GetParameters,
    SetParameters,
    XfrBlock,
}

enum ResponseDisposition {
    Final,
    TimeExtension,
}

struct ReceiveBuffer {
    bytes: [u8; MAX_WIRE_BYTES],
}

impl ReceiveBuffer {
    const fn new() -> Self {
        Self {
            bytes: [0; MAX_WIRE_BYTES],
        }
    }
}

impl Drop for ReceiveBuffer {
    fn drop(&mut self) {
        wipe::bytes(&mut self.bytes);
    }
}

struct TpduBuffer {
    bytes: [u8; qk_t1::RAW_MAX_BLOCK_BYTES],
    len: usize,
}

impl TpduBuffer {
    fn copy_from(bytes: &[u8]) -> Result<Self, CardTransportErrorV2> {
        let mut value = Self {
            bytes: [0; qk_t1::RAW_MAX_BLOCK_BYTES],
            len: bytes.len(),
        };
        let Some(destination) = value.bytes.get_mut(..bytes.len()) else {
            return Err(CardTransportErrorV2::T1BlockLengthRejected);
        };
        destination.copy_from_slice(bytes);
        Ok(value)
    }

    fn bytes(&self) -> &[u8] {
        self.bytes.get(..self.len).unwrap_or(&[])
    }
}

impl Drop for TpduBuffer {
    fn drop(&mut self) {
        wipe::bytes(&mut self.bytes);
        self.len = 0;
    }
}

/// Fixed-storage production SEC1210 transport over platform grants.
pub struct Sec1210TransportV2<D, C> {
    descriptor: D,
    clock: C,
    decoder: ProductionDecoder,
    t1: T1Session,
    sequence: u8,
    controller_commands: usize,
    received_bytes: usize,
    events: usize,
    application_apdus: usize,
    wtx: usize,
    time_extensions: usize,
    apdu_time_extensions: usize,
    initialized: bool,
    last_clock_ms: Option<u64>,
    failure: Option<CardTransportErrorV2>,
}

impl<D, C> Sec1210TransportV2<D, C>
where
    D: Sec1210DescriptorV2,
    C: Sec1210MonotonicClockV2,
{
    pub fn new(descriptor: D, clock: C) -> Self {
        Self {
            descriptor,
            clock,
            decoder: ProductionDecoder::default(),
            t1: T1Session::default(),
            sequence: 0,
            controller_commands: 0,
            received_bytes: 0,
            events: 0,
            application_apdus: 0,
            wtx: 0,
            time_extensions: 0,
            apdu_time_extensions: 0,
            initialized: false,
            last_clock_ms: None,
            failure: None,
        }
    }

    pub const fn failure(&self) -> Option<CardTransportErrorV2> {
        self.failure
    }

    pub const fn controller_command_count(&self) -> usize {
        self.controller_commands
    }

    pub const fn received_byte_count(&self) -> usize {
        self.received_bytes
    }

    pub const fn event_count(&self) -> usize {
        self.events
    }

    pub const fn application_apdu_count(&self) -> usize {
        self.application_apdus
    }

    pub const fn reader_time_extension_count(&self) -> usize {
        self.time_extensions
    }

    pub fn wtx_count(&self) -> usize {
        self.wtx
    }

    /// Run the exact five-command production initialization once.
    pub fn initialize(&mut self) -> Result<(), CardTransportErrorV2> {
        self.ensure_live()?;
        if self.initialized || self.controller_commands != 0 {
            return self.reject(CardTransportErrorV2::Sec1210StateRejected);
        }

        let status = self.exchange(
            ControllerCommand::GetSlotStatus,
            &[],
            0,
            QK_LIM_APDU_019_BASE_COMMAND_WAIT_MS,
            None,
            false,
        )?;
        self.validate_slot_status(&status)?;

        let power = self.exchange(
            ControllerCommand::PowerOn,
            &[],
            0,
            QK_LIM_APDU_019_BASE_COMMAND_WAIT_MS,
            None,
            false,
        )?;
        self.validate_power_on(&power)?;

        let parameters = self.exchange(
            ControllerCommand::GetParameters,
            &[],
            0,
            QK_LIM_APDU_019_BASE_COMMAND_WAIT_MS,
            None,
            false,
        )?;
        self.validate_get_parameters(&parameters)?;

        let set = self.exchange(
            ControllerCommand::SetParameters,
            &[],
            0,
            QK_LIM_APDU_019_BASE_COMMAND_WAIT_MS,
            None,
            false,
        )?;
        self.validate_set_parameters(&set)?;

        let now = self.now()?;
        if let Err(error) = self.t1.begin_ifs(now) {
            return self.reject(map_t1_error(error));
        }
        let ifs_deadline = now.saturating_add(QK_LIM_APDU_019_BASE_COMMAND_WAIT_MS);
        let block = match self.t1.next_block(now) {
            Ok(block) => block,
            Err(error) => return self.reject(map_t1_error(error)),
        };
        let command_allowance_ms = block.command_allowance_ms();
        let tpdu = match TpduBuffer::copy_from(block.as_bytes()) {
            Ok(value) => value,
            Err(error) => return self.reject(error),
        };
        let block_len = tpdu.bytes().len();
        if let Err(error) = self.t1.written(block_len, now) {
            return self.reject(map_t1_error(error));
        }
        let response = self.exchange(
            ControllerCommand::XfrBlock,
            tpdu.bytes(),
            0,
            command_allowance_ms,
            Some(ifs_deadline),
            false,
        )?;
        let now = self.now()?;
        let received = self.t1.receive(response.payload(), now);
        self.wtx = self.t1.total_wtx_count();
        if let Err(error) = received {
            return self.reject(map_t1_error(error));
        }
        if !self.t1.ifs_accepted() {
            return self.reject(CardTransportErrorV2::T1IfsRejected);
        }
        self.initialized = true;
        Ok(())
    }

    /// Exchange one bounded application APDU after initialization.
    pub fn transmit_apdu(
        &mut self,
        command: &[u8],
    ) -> Result<CardTransportResponseV2, CardTransportErrorV2> {
        self.ensure_live()?;
        if !self.initialized {
            return self.reject(CardTransportErrorV2::Sec1210StateRejected);
        }
        if self.controller_commands >= QK_LIM_APDU_017_MAX_CONTROLLER_COMMANDS {
            return self.reject(CardTransportErrorV2::Sec1210SessionCommandLimitExceeded);
        }
        if self.application_apdus >= MAX_APPLICATION_APDUS {
            return self.reject(CardTransportErrorV2::Sec1210ApplicationApduLimitExceeded);
        }
        if command.is_empty() || command.len() > MAX_APPLICATION_COMMAND_BYTES {
            return self.reject(CardTransportErrorV2::Sec1210ApplicationCommandLengthRejected);
        }
        self.apdu_time_extensions = 0;
        let now = self.now()?;
        if let Err(error) = self.t1.begin(command, now) {
            return self.reject(map_t1_error(error));
        }

        loop {
            let now = self.now()?;
            let block = match self.t1.next_block(now) {
                Ok(block) => block,
                Err(error) => return self.reject(map_t1_error(error)),
            };
            let bwi = block.bwi();
            let command_allowance_ms = block.command_allowance_ms();
            let tpdu = match TpduBuffer::copy_from(block.as_bytes()) {
                Ok(value) => value,
                Err(error) => return self.reject(error),
            };
            let block_len = tpdu.bytes().len();
            if let Err(error) = self.t1.written(block_len, now) {
                return self.reject(map_t1_error(error));
            }
            let response = self.exchange(
                ControllerCommand::XfrBlock,
                tpdu.bytes(),
                bwi,
                command_allowance_ms,
                self.t1.apdu_deadline_ms(),
                true,
            )?;
            let now = self.now()?;
            let received = self.t1.receive(response.payload(), now);
            self.wtx = self.t1.total_wtx_count();
            if let Err(error) = received {
                return self.reject(map_t1_error(error));
            }
            if self.t1.phase() == T1Phase::Complete {
                let bytes = self.t1.response();
                if bytes.len() > MAX_APPLICATION_RESPONSE_BYTES {
                    return self
                        .reject(CardTransportErrorV2::Sec1210ApplicationResponseLengthRejected);
                }
                let mut output = CardTransportResponseV2 {
                    bytes: [0; MAX_APPLICATION_RESPONSE_BYTES],
                    len: bytes.len(),
                };
                let Some(destination) = output.bytes.get_mut(..bytes.len()) else {
                    return self
                        .reject(CardTransportErrorV2::Sec1210ApplicationResponseLengthRejected);
                };
                destination.copy_from_slice(bytes);
                self.application_apdus = self
                    .application_apdus
                    .checked_add(1)
                    .ok_or(CardTransportErrorV2::Sec1210ApplicationApduLimitExceeded)?;
                return Ok(output);
            }
        }
    }

    /// Clear all contact state without sending a controller command.
    pub fn reset(&mut self) {
        let failure = self.failure;
        self.decoder = ProductionDecoder::default();
        self.t1 = T1Session::default();
        self.sequence = 0;
        self.controller_commands = 0;
        self.received_bytes = 0;
        self.events = 0;
        self.application_apdus = 0;
        self.wtx = 0;
        self.time_extensions = 0;
        self.apdu_time_extensions = 0;
        self.initialized = false;
        self.last_clock_ms = None;
        // A reset wipes contact state but never turns a rejected session into
        // a retry path. The first failure remains sticky for this owner.
        self.failure = failure;
    }

    fn ensure_live(&mut self) -> Result<(), CardTransportErrorV2> {
        match self.failure {
            Some(error) => Err(error),
            None => Ok(()),
        }
    }

    fn reject<T>(&mut self, error: CardTransportErrorV2) -> Result<T, CardTransportErrorV2> {
        if let Some(error) = self.failure {
            return Err(error);
        }
        self.wtx = self.t1.total_wtx_count();
        self.decoder = ProductionDecoder::default();
        self.t1 = T1Session::default();
        self.failure = Some(error);
        Err(error)
    }

    fn now(&mut self) -> Result<u64, CardTransportErrorV2> {
        let now = match self.clock.now_ms() {
            Ok(now) => now,
            Err(_) => return self.reject(CardTransportErrorV2::Sec1210ClockFailed),
        };
        if self.last_clock_ms.is_some_and(|last| now < last) {
            return self.reject(CardTransportErrorV2::Sec1210ClockRegression);
        }
        self.last_clock_ms = Some(now);
        Ok(now)
    }

    fn request(
        command: ControllerCommand,
        sequence: u8,
        bwi: u8,
        payload: &[u8],
    ) -> Result<ProductionRequest, CardTransportErrorV2> {
        match command {
            ControllerCommand::GetSlotStatus => Ok(ProductionRequest::get_slot_status(sequence)),
            ControllerCommand::PowerOn => Ok(ProductionRequest::power_on_3v(sequence)),
            ControllerCommand::GetParameters => Ok(ProductionRequest::get_parameters(sequence)),
            ControllerCommand::SetParameters => {
                Ok(ProductionRequest::set_fidi_parameters(sequence))
            }
            ControllerCommand::XfrBlock => {
                ProductionRequest::xfr_block(sequence, bwi, payload).map_err(map_wire_error)
            }
        }
    }

    fn exchange(
        &mut self,
        command: ControllerCommand,
        payload: &[u8],
        bwi: u8,
        command_allowance_ms: u64,
        absolute_deadline: Option<u64>,
        apdu_active: bool,
    ) -> Result<ProductionResponse, CardTransportErrorV2> {
        self.ensure_live()?;
        if self.controller_commands >= QK_LIM_APDU_017_MAX_CONTROLLER_COMMANDS {
            return self.reject(CardTransportErrorV2::Sec1210SessionCommandLimitExceeded);
        }
        let sequence = self.sequence.wrapping_add(1);
        let request = match Self::request(command, sequence, bwi, payload) {
            Ok(request) => request,
            Err(error) => return self.reject(error),
        };
        let started = self.now()?;
        let command_deadline = started.saturating_add(command_allowance_ms);
        let absolute_limited = absolute_deadline.is_some_and(|value| value <= command_deadline);
        let deadline =
            absolute_deadline.map_or(command_deadline, |value| value.min(command_deadline));
        if started >= deadline {
            return self.reject(self.deadline_error(absolute_limited));
        }
        let write_wait_ms = deadline.saturating_sub(started);
        let write = self.descriptor.write(request.as_bytes(), write_wait_ms);
        let write_finished = self.now()?;
        if write_finished >= deadline {
            return self.reject(self.deadline_error(absolute_limited));
        }
        let written = match write {
            Ok(Sec1210DescriptorWriteV2::Bytes(written)) => written,
            Ok(Sec1210DescriptorWriteV2::TimedOut) => {
                return self.reject(self.deadline_error(absolute_limited));
            }
            Err(_) => return self.reject(CardTransportErrorV2::Sec1210DescriptorWriteFailed),
        };
        if written != request.as_bytes().len() {
            return self.reject(CardTransportErrorV2::Sec1210PartialWrite);
        }
        self.controller_commands = self
            .controller_commands
            .checked_add(1)
            .ok_or(CardTransportErrorV2::Sec1210SessionCommandLimitExceeded)?;
        self.sequence = sequence;

        loop {
            let now = self.now()?;
            if now >= deadline {
                return self.reject(self.deadline_error(absolute_limited));
            }
            let maximum_wait_ms = deadline.saturating_sub(now);
            let mut buffer = ReceiveBuffer::new();
            let read = self.descriptor.read(&mut buffer.bytes, maximum_wait_ms);
            let finished = self.now()?;
            if finished >= deadline {
                return self.reject(self.deadline_error(absolute_limited));
            }
            let count = match read {
                Err(_) => return self.reject(CardTransportErrorV2::Sec1210DescriptorReadFailed),
                Ok(Sec1210DescriptorReadV2::Bytes(0))
                | Ok(Sec1210DescriptorReadV2::EndOfStream) => {
                    if self.decoder.pending_bytes() == 0 {
                        return self.reject(CardTransportErrorV2::Sec1210DescriptorClosed);
                    }
                    let error = match self.decoder.finish() {
                        Ok(()) => CardTransportErrorV2::Sec1210DescriptorClosed,
                        Err(error) => map_wire_error(error),
                    };
                    return self.reject(error);
                }
                Ok(Sec1210DescriptorReadV2::TimedOut) => {
                    return self.reject(self.deadline_error(absolute_limited));
                }
                Ok(Sec1210DescriptorReadV2::Bytes(count)) => count,
            };
            let Some(fragment) = buffer.bytes.get(..count) else {
                return self.reject(CardTransportErrorV2::Sec1210DescriptorReadFailed);
            };
            self.accept_received_bytes(count)?;

            for (index, byte) in fragment.iter().enumerate() {
                let message = match self.decoder.push(*byte) {
                    Ok(Some(message)) => message,
                    Ok(None) => continue,
                    Err(error) => return self.reject(map_wire_error(error)),
                };
                match message.kind() {
                    ProductionMessageKind::SlotChange { bitmap } => {
                        if self.events >= MAX_EVENTS {
                            return self.reject(CardTransportErrorV2::Sec1210EventLimitExceeded);
                        }
                        self.events = self
                            .events
                            .checked_add(1)
                            .ok_or(CardTransportErrorV2::Sec1210EventLimitExceeded)?;
                        if bitmap & 0xf0 != 0 {
                            return self.reject(CardTransportErrorV2::Sec1210EventBitmapRejected);
                        }
                        if bitmap & 1 == 0 {
                            return self.reject(CardTransportErrorV2::Sec1210CardRemoved);
                        }
                    }
                    ProductionMessageKind::HardwareError {
                        slot,
                        sequence: event_sequence,
                        code: _,
                    } => {
                        if self.events >= MAX_EVENTS {
                            return self.reject(CardTransportErrorV2::Sec1210EventLimitExceeded);
                        }
                        self.events = self
                            .events
                            .checked_add(1)
                            .ok_or(CardTransportErrorV2::Sec1210EventLimitExceeded)?;
                        if slot != 0 {
                            return self.reject(CardTransportErrorV2::Sec1210SlotRejected);
                        }
                        if event_sequence != sequence {
                            return self.reject(CardTransportErrorV2::Sec1210SequenceRejected);
                        }
                        return self.reject(CardTransportErrorV2::Sec1210HardwareError);
                    }
                    ProductionMessageKind::Response => {
                        let Some(response) = message.into_response() else {
                            return self.reject(CardTransportErrorV2::Sec1210StateRejected);
                        };
                        let disposition =
                            match self.validate_response(command, sequence, &response, apdu_active)
                            {
                                Ok(disposition) => disposition,
                                Err(error) => return self.reject(error),
                            };
                        if matches!(disposition, ResponseDisposition::TimeExtension) {
                            continue;
                        }
                        if index.saturating_add(1) != fragment.len() {
                            return self.reject(CardTransportErrorV2::Sec1210TrailingData);
                        }
                        return Ok(response);
                    }
                }
            }
        }
    }

    fn deadline_error(&self, absolute_limited: bool) -> CardTransportErrorV2 {
        if absolute_limited {
            return CardTransportErrorV2::T1DeadlineExceeded;
        }
        if self.decoder.pending_bytes() == 0 {
            CardTransportErrorV2::Sec1210DeadlineExceeded
        } else {
            CardTransportErrorV2::Sec1210PartialFrameDeadline
        }
    }

    fn accept_received_bytes(&mut self, count: usize) -> Result<(), CardTransportErrorV2> {
        let remaining = QK_LIM_APDU_018_MAX_RECEIVED_BYTES.saturating_sub(self.received_bytes);
        if count > remaining {
            return self.reject(CardTransportErrorV2::Sec1210SessionReceiveLimitExceeded);
        }
        self.received_bytes = match self.received_bytes.checked_add(count) {
            Some(total) => total,
            None => {
                return self.reject(CardTransportErrorV2::Sec1210SessionReceiveLimitExceeded);
            }
        };
        Ok(())
    }

    fn validate_response(
        &mut self,
        command: ControllerCommand,
        sequence: u8,
        response: &ProductionResponse,
        apdu_active: bool,
    ) -> Result<ResponseDisposition, CardTransportErrorV2> {
        if response.slot() != 0 {
            return Err(CardTransportErrorV2::Sec1210SlotRejected);
        }
        if response.sequence() != sequence {
            return Err(CardTransportErrorV2::Sec1210SequenceRejected);
        }
        let status = response.status();
        if status & 0x3c != 0 || status & 3 == 3 || status >> 6 == 3 {
            return Err(CardTransportErrorV2::Sec1210StatusReserved);
        }
        let extension = status >> 6 == 2;
        if extension
            && (command != ControllerCommand::XfrBlock
                || !apdu_active
                || response.message_type() != 0x80)
        {
            return Err(CardTransportErrorV2::Sec1210TimeExtensionRejected);
        }
        if status >> 6 == 1 {
            return Err(CardTransportErrorV2::Sec1210CommandFailed);
        }
        let expected_type = match command {
            ControllerCommand::GetSlotStatus => 0x81,
            ControllerCommand::GetParameters | ControllerCommand::SetParameters => 0x82,
            ControllerCommand::PowerOn | ControllerCommand::XfrBlock => 0x80,
        };
        if response.message_type() != expected_type {
            return Err(CardTransportErrorV2::Sec1210ResponseTypeRejected);
        }
        if !extension && response.error() != 0 {
            return Err(CardTransportErrorV2::Sec1210StatusErrorRejected);
        }
        let icc = status & 3;
        if icc == 2 {
            return Err(CardTransportErrorV2::Sec1210CardRemoved);
        }
        if command == ControllerCommand::GetSlotStatus {
            if icc == 0 {
                return Err(CardTransportErrorV2::Sec1210AlreadyActive);
            }
        } else if icc != 0 {
            return Err(CardTransportErrorV2::Sec1210IccStatusRejected);
        }
        if extension {
            if !response.payload().is_empty() || response.parameter() != 0 {
                return Err(CardTransportErrorV2::Sec1210TimeExtensionShapeRejected);
            }
            if self.apdu_time_extensions >= QK_LIM_APDU_016_MAX_TIME_EXTENSIONS_PER_APDU {
                return Err(CardTransportErrorV2::Sec1210TimeExtensionLimitExceeded);
            }
            self.apdu_time_extensions = self
                .apdu_time_extensions
                .checked_add(1)
                .ok_or(CardTransportErrorV2::Sec1210TimeExtensionLimitExceeded)?;
            self.time_extensions = self
                .time_extensions
                .checked_add(1)
                .ok_or(CardTransportErrorV2::Sec1210TimeExtensionLimitExceeded)?;
            return Ok(ResponseDisposition::TimeExtension);
        }
        if command == ControllerCommand::XfrBlock && response.parameter() != 0 {
            return Err(CardTransportErrorV2::Sec1210ChainingRejected);
        }
        Ok(ResponseDisposition::Final)
    }

    fn validate_slot_status(
        &mut self,
        response: &ProductionResponse,
    ) -> Result<(), CardTransportErrorV2> {
        if !response.payload().is_empty() {
            return self.reject(CardTransportErrorV2::Sec1210PayloadRejected);
        }
        Ok(())
    }

    fn validate_power_on(
        &mut self,
        response: &ProductionResponse,
    ) -> Result<(), CardTransportErrorV2> {
        if response.parameter() != 0 {
            return self.reject(CardTransportErrorV2::Sec1210ChainingRejected);
        }
        if validate_production_atr(response.payload()).is_err() {
            return self.reject(CardTransportErrorV2::Sec1210AtrProfileRejected);
        }
        Ok(())
    }

    fn validate_get_parameters(
        &mut self,
        response: &ProductionResponse,
    ) -> Result<(), CardTransportErrorV2> {
        let payload = response.payload();
        if response.parameter() != 1 || payload.len() != FIDI_PARAMETERS.len() {
            return self.reject(CardTransportErrorV2::Sec1210ParametersRejected);
        }
        if payload.get(1).is_none_or(|value| value & 1 != 0)
            || payload.get(5).is_none_or(|value| {
                !(MAX_APPLICATION_COMMAND_BYTES..=QK_LIM_APDU_012_COMMAND_INF_BYTES)
                    .contains(&usize::from(*value))
            })
        {
            return self.reject(CardTransportErrorV2::Sec1210ParametersRejected);
        }
        Ok(())
    }

    fn validate_set_parameters(
        &mut self,
        response: &ProductionResponse,
    ) -> Result<(), CardTransportErrorV2> {
        if response.parameter() != 1 || response.payload() != FIDI_PARAMETERS {
            return self.reject(CardTransportErrorV2::Sec1210SetParametersEchoRejected);
        }
        Ok(())
    }
}

fn map_wire_error(error: WireError) -> CardTransportErrorV2 {
    match error {
        WireError::PrefixRejected => CardTransportErrorV2::Sec1210PrefixRejected,
        WireError::LengthExceeded => CardTransportErrorV2::Sec1210LengthExceeded,
        WireError::Truncated => CardTransportErrorV2::Sec1210Truncated,
        WireError::ChecksumRejected => CardTransportErrorV2::Sec1210ChecksumRejected,
        WireError::Nack => CardTransportErrorV2::Sec1210Nack,
        WireError::SlotRejected => CardTransportErrorV2::Sec1210SlotRejected,
        WireError::SequenceRejected => CardTransportErrorV2::Sec1210SequenceRejected,
        WireError::ResponseTypeRejected => CardTransportErrorV2::Sec1210ResponseTypeRejected,
        WireError::StatusReserved => CardTransportErrorV2::Sec1210StatusReserved,
        WireError::CommandFailed => CardTransportErrorV2::Sec1210CommandFailed,
        WireError::TimeExtensionRejected => CardTransportErrorV2::Sec1210TimeExtensionRejected,
        WireError::StatusErrorRejected => CardTransportErrorV2::Sec1210StatusErrorRejected,
        WireError::AlreadyActive => CardTransportErrorV2::Sec1210AlreadyActive,
        WireError::CardAbsent => CardTransportErrorV2::Sec1210CardRemoved,
        WireError::IccStatusRejected => CardTransportErrorV2::Sec1210IccStatusRejected,
        WireError::PayloadRejected => CardTransportErrorV2::Sec1210PayloadRejected,
        WireError::ChainingRejected => CardTransportErrorV2::Sec1210ChainingRejected,
        WireError::AtrRejected => CardTransportErrorV2::Sec1210AtrProfileRejected,
        WireError::EventBitmapRejected => CardTransportErrorV2::Sec1210EventBitmapRejected,
        WireError::HardwareError => CardTransportErrorV2::Sec1210HardwareError,
        WireError::EventLimitExceeded => CardTransportErrorV2::Sec1210EventLimitExceeded,
        WireError::ReceiveLimitExceeded => CardTransportErrorV2::Sec1210SessionReceiveLimitExceeded,
        WireError::UnsolicitedResponse => CardTransportErrorV2::Sec1210UnsolicitedResponse,
        WireError::TrailingData => CardTransportErrorV2::Sec1210TrailingData,
        WireError::SequenceViolation => CardTransportErrorV2::Sec1210SequenceViolation,
        WireError::PartialWrite => CardTransportErrorV2::Sec1210PartialWrite,
        WireError::DeadlineExceeded => CardTransportErrorV2::Sec1210DeadlineExceeded,
        WireError::PartialFrameDeadline => CardTransportErrorV2::Sec1210PartialFrameDeadline,
        WireError::ClockRegression => CardTransportErrorV2::Sec1210ClockRegression,
    }
}

fn map_t1_error(error: T1RawError) -> CardTransportErrorV2 {
    match error {
        T1RawError::T1(error) => map_t1_leaf(error),
        T1RawError::WtxMultiplierRejected => CardTransportErrorV2::T1WtxMultiplierRejected,
        T1RawError::WtxLimitExceeded => CardTransportErrorV2::T1WtxLimitExceeded,
        T1RawError::WtxResponseRejected => CardTransportErrorV2::T1WtxResponseRejected,
        T1RawError::ChainingRejected => CardTransportErrorV2::T1ChainingRejected,
    }
}

fn map_t1_leaf(error: T1Error) -> CardTransportErrorV2 {
    match error {
        T1Error::BlockLengthRejected => CardTransportErrorV2::T1BlockLengthRejected,
        T1Error::ChecksumRejected => CardTransportErrorV2::T1ChecksumRejected,
        T1Error::NadRejected => CardTransportErrorV2::T1NadRejected,
        T1Error::PcbRejected => CardTransportErrorV2::T1PcbRejected,
        T1Error::ControlLengthRejected => CardTransportErrorV2::T1ControlLengthRejected,
        T1Error::RetransmissionRejected => CardTransportErrorV2::T1RetransmissionRejected,
        T1Error::WtxRejected => CardTransportErrorV2::T1WtxRejected,
        T1Error::IfsRejected => CardTransportErrorV2::T1IfsRejected,
        T1Error::ResynchRejected => CardTransportErrorV2::T1ResynchRejected,
        T1Error::AbortRejected => CardTransportErrorV2::T1AbortRejected,
        T1Error::UnexpectedRBlock => CardTransportErrorV2::T1UnexpectedRBlock,
        T1Error::SequenceRejected => CardTransportErrorV2::T1SequenceRejected,
        T1Error::StateRejected => CardTransportErrorV2::T1StateRejected,
        T1Error::CommandLengthRejected => CardTransportErrorV2::T1CommandLengthRejected,
        T1Error::ResponseLengthRejected => CardTransportErrorV2::T1ResponseLengthRejected,
        T1Error::ResponseMismatch => CardTransportErrorV2::T1ResponseMismatch,
        T1Error::PartialWrite => CardTransportErrorV2::T1PartialWrite,
        T1Error::ExchangeLimitExceeded => CardTransportErrorV2::T1ExchangeLimitExceeded,
        T1Error::ApduLimitExceeded => CardTransportErrorV2::T1ApduLimitExceeded,
        T1Error::DeadlineExceeded => CardTransportErrorV2::T1DeadlineExceeded,
        T1Error::ClockRegression => CardTransportErrorV2::T1ClockRegression,
    }
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::panic)]
mod tests {
    use crate::wipe::{reset_wiped_bytes, wiped_bytes};

    use super::{
        map_t1_error, map_t1_leaf, map_wire_error, CardTransportErrorV2, CardTransportResponseV2,
        ReceiveBuffer, Sec1210ClockErrorV2, Sec1210DescriptorErrorV2, Sec1210DescriptorReadV2,
        Sec1210DescriptorV2, Sec1210DescriptorWriteV2, Sec1210MonotonicClockV2, Sec1210TransportV2,
        T1Error, T1RawError, TpduBuffer, WireError, MAX_APPLICATION_RESPONSE_BYTES,
        QK_LIM_APDU_018_MAX_RECEIVED_BYTES,
    };
    use std::panic::{catch_unwind, AssertUnwindSafe};

    struct NoDescriptor;

    impl Sec1210DescriptorV2 for NoDescriptor {
        fn write(
            &mut self,
            _bytes: &[u8],
            _maximum_wait_ms: u64,
        ) -> Result<Sec1210DescriptorWriteV2, Sec1210DescriptorErrorV2> {
            Err(Sec1210DescriptorErrorV2)
        }

        fn read(
            &mut self,
            _bytes: &mut [u8],
            _maximum_wait_ms: u64,
        ) -> Result<Sec1210DescriptorReadV2, Sec1210DescriptorErrorV2> {
            Err(Sec1210DescriptorErrorV2)
        }
    }

    struct NoClock;

    impl Sec1210MonotonicClockV2 for NoClock {
        fn now_ms(&mut self) -> Result<u64, Sec1210ClockErrorV2> {
            Err(Sec1210ClockErrorV2)
        }
    }

    #[test]
    fn receive_limit_accepts_exact_capacity_and_rejects_byte_52816() {
        let mut transport = Sec1210TransportV2::new(NoDescriptor, NoClock);
        transport.received_bytes = QK_LIM_APDU_018_MAX_RECEIVED_BYTES - 1;
        assert_eq!(transport.accept_received_bytes(1), Ok(()));
        assert_eq!(
            transport.accept_received_bytes(1),
            Err(CardTransportErrorV2::Sec1210SessionReceiveLimitExceeded)
        );
        assert_eq!(transport.received_bytes, QK_LIM_APDU_018_MAX_RECEIVED_BYTES);
        assert_eq!(
            transport.failure,
            Some(CardTransportErrorV2::Sec1210SessionReceiveLimitExceeded)
        );
    }

    #[test]
    fn outer_rejection_discards_lower_layer_error_objects() {
        let mut transport = Sec1210TransportV2::new(NoDescriptor, NoClock);
        assert!(transport.decoder.push(0x52).is_err());
        assert_eq!(transport.t1.begin_ifs(0), Ok(()));
        assert!(transport.t1.receive(&[0], 1).is_err());
        assert!(transport.t1.failure().is_some());

        let failure = CardTransportErrorV2::Sec1210ChecksumRejected;
        let rejected: Result<(), _> = transport.reject(failure);
        assert_eq!(rejected, Err(failure));
        assert_eq!(transport.failure(), Some(failure));
        assert_eq!(transport.decoder.finish(), Ok(()));
        assert_eq!(transport.t1.failure(), None);
    }

    #[test]
    fn every_wire_error_has_one_explicit_production_mapping() {
        let cases = [
            (
                WireError::PrefixRejected,
                CardTransportErrorV2::Sec1210PrefixRejected,
            ),
            (
                WireError::LengthExceeded,
                CardTransportErrorV2::Sec1210LengthExceeded,
            ),
            (WireError::Truncated, CardTransportErrorV2::Sec1210Truncated),
            (
                WireError::ChecksumRejected,
                CardTransportErrorV2::Sec1210ChecksumRejected,
            ),
            (WireError::Nack, CardTransportErrorV2::Sec1210Nack),
            (
                WireError::SlotRejected,
                CardTransportErrorV2::Sec1210SlotRejected,
            ),
            (
                WireError::SequenceRejected,
                CardTransportErrorV2::Sec1210SequenceRejected,
            ),
            (
                WireError::ResponseTypeRejected,
                CardTransportErrorV2::Sec1210ResponseTypeRejected,
            ),
            (
                WireError::StatusReserved,
                CardTransportErrorV2::Sec1210StatusReserved,
            ),
            (
                WireError::CommandFailed,
                CardTransportErrorV2::Sec1210CommandFailed,
            ),
            (
                WireError::TimeExtensionRejected,
                CardTransportErrorV2::Sec1210TimeExtensionRejected,
            ),
            (
                WireError::StatusErrorRejected,
                CardTransportErrorV2::Sec1210StatusErrorRejected,
            ),
            (
                WireError::AlreadyActive,
                CardTransportErrorV2::Sec1210AlreadyActive,
            ),
            (
                WireError::CardAbsent,
                CardTransportErrorV2::Sec1210CardRemoved,
            ),
            (
                WireError::IccStatusRejected,
                CardTransportErrorV2::Sec1210IccStatusRejected,
            ),
            (
                WireError::PayloadRejected,
                CardTransportErrorV2::Sec1210PayloadRejected,
            ),
            (
                WireError::ChainingRejected,
                CardTransportErrorV2::Sec1210ChainingRejected,
            ),
            (
                WireError::AtrRejected,
                CardTransportErrorV2::Sec1210AtrProfileRejected,
            ),
            (
                WireError::EventBitmapRejected,
                CardTransportErrorV2::Sec1210EventBitmapRejected,
            ),
            (
                WireError::HardwareError,
                CardTransportErrorV2::Sec1210HardwareError,
            ),
            (
                WireError::EventLimitExceeded,
                CardTransportErrorV2::Sec1210EventLimitExceeded,
            ),
            (
                WireError::ReceiveLimitExceeded,
                CardTransportErrorV2::Sec1210SessionReceiveLimitExceeded,
            ),
            (
                WireError::UnsolicitedResponse,
                CardTransportErrorV2::Sec1210UnsolicitedResponse,
            ),
            (
                WireError::TrailingData,
                CardTransportErrorV2::Sec1210TrailingData,
            ),
            (
                WireError::SequenceViolation,
                CardTransportErrorV2::Sec1210SequenceViolation,
            ),
            (
                WireError::PartialWrite,
                CardTransportErrorV2::Sec1210PartialWrite,
            ),
            (
                WireError::DeadlineExceeded,
                CardTransportErrorV2::Sec1210DeadlineExceeded,
            ),
            (
                WireError::PartialFrameDeadline,
                CardTransportErrorV2::Sec1210PartialFrameDeadline,
            ),
            (
                WireError::ClockRegression,
                CardTransportErrorV2::Sec1210ClockRegression,
            ),
        ];
        for (source, production) in cases {
            assert_eq!(map_wire_error(source), production);
        }
    }

    #[test]
    fn every_t1_error_has_one_explicit_production_mapping() {
        let leaf_cases = [
            (
                T1Error::BlockLengthRejected,
                CardTransportErrorV2::T1BlockLengthRejected,
            ),
            (
                T1Error::ChecksumRejected,
                CardTransportErrorV2::T1ChecksumRejected,
            ),
            (T1Error::NadRejected, CardTransportErrorV2::T1NadRejected),
            (T1Error::PcbRejected, CardTransportErrorV2::T1PcbRejected),
            (
                T1Error::ControlLengthRejected,
                CardTransportErrorV2::T1ControlLengthRejected,
            ),
            (
                T1Error::RetransmissionRejected,
                CardTransportErrorV2::T1RetransmissionRejected,
            ),
            (T1Error::WtxRejected, CardTransportErrorV2::T1WtxRejected),
            (T1Error::IfsRejected, CardTransportErrorV2::T1IfsRejected),
            (
                T1Error::ResynchRejected,
                CardTransportErrorV2::T1ResynchRejected,
            ),
            (
                T1Error::AbortRejected,
                CardTransportErrorV2::T1AbortRejected,
            ),
            (
                T1Error::UnexpectedRBlock,
                CardTransportErrorV2::T1UnexpectedRBlock,
            ),
            (
                T1Error::SequenceRejected,
                CardTransportErrorV2::T1SequenceRejected,
            ),
            (
                T1Error::StateRejected,
                CardTransportErrorV2::T1StateRejected,
            ),
            (
                T1Error::CommandLengthRejected,
                CardTransportErrorV2::T1CommandLengthRejected,
            ),
            (
                T1Error::ResponseLengthRejected,
                CardTransportErrorV2::T1ResponseLengthRejected,
            ),
            (
                T1Error::ResponseMismatch,
                CardTransportErrorV2::T1ResponseMismatch,
            ),
            (T1Error::PartialWrite, CardTransportErrorV2::T1PartialWrite),
            (
                T1Error::ExchangeLimitExceeded,
                CardTransportErrorV2::T1ExchangeLimitExceeded,
            ),
            (
                T1Error::ApduLimitExceeded,
                CardTransportErrorV2::T1ApduLimitExceeded,
            ),
            (
                T1Error::DeadlineExceeded,
                CardTransportErrorV2::T1DeadlineExceeded,
            ),
            (
                T1Error::ClockRegression,
                CardTransportErrorV2::T1ClockRegression,
            ),
        ];
        for (source, production) in leaf_cases {
            assert_eq!(map_t1_leaf(source), production);
            assert_eq!(map_t1_error(T1RawError::T1(source)), production);
        }
        let raw_cases = [
            (
                T1RawError::WtxMultiplierRejected,
                CardTransportErrorV2::T1WtxMultiplierRejected,
            ),
            (
                T1RawError::WtxLimitExceeded,
                CardTransportErrorV2::T1WtxLimitExceeded,
            ),
            (
                T1RawError::WtxResponseRejected,
                CardTransportErrorV2::T1WtxResponseRejected,
            ),
            (
                T1RawError::ChainingRejected,
                CardTransportErrorV2::T1ChainingRejected,
            ),
        ];
        for (source, production) in raw_cases {
            assert_eq!(map_t1_error(source), production);
        }
    }

    #[test]
    fn transport_owned_fixed_storage_wipes_on_drop_and_unwind() {
        let response = CardTransportResponseV2 {
            bytes: [0xa5; MAX_APPLICATION_RESPONSE_BYTES],
            len: MAX_APPLICATION_RESPONSE_BYTES,
        };
        reset_wiped_bytes();
        drop(response);
        assert_eq!(wiped_bytes(), MAX_APPLICATION_RESPONSE_BYTES);

        let receive = ReceiveBuffer::new();
        reset_wiped_bytes();
        drop(receive);
        assert_eq!(wiped_bytes(), qk_sec1210_wire::MAX_WIRE_BYTES);

        let tpdu = TpduBuffer::copy_from(&[0, 0, 1, 0x55, 0x54]).expect("valid T=1 block");
        reset_wiped_bytes();
        drop(tpdu);
        assert_eq!(wiped_bytes(), qk_t1::RAW_MAX_BLOCK_BYTES);

        reset_wiped_bytes();
        let unwind = catch_unwind(AssertUnwindSafe(|| {
            let _response = CardTransportResponseV2 {
                bytes: [0xa5; MAX_APPLICATION_RESPONSE_BYTES],
                len: MAX_APPLICATION_RESPONSE_BYTES,
            };
            panic!("test-only caught unwind");
        }));
        assert!(unwind.is_err());
        assert_eq!(wiped_bytes(), MAX_APPLICATION_RESPONSE_BYTES);
    }
}
