//! SUP-013's caller-clocked, raw-response session. No I/O or response oracle.
use crate::codec::{decode_bounded, validate_ifs_response};
use crate::{Error, Phase, Received, MAX_BLOCK_BYTES};

pub const RAW_MAX_COMMAND_BYTES: usize = 254;
pub const RAW_MAX_RESPONSE_BYTES: usize = 254;
pub const RAW_MAX_BLOCK_BYTES: usize = 258;
pub const RAW_MAX_APDUS: usize = 128;
pub const RAW_MAX_EXCHANGES: usize = 16;
pub const RAW_MAX_WTX: usize = 8;
pub const RAW_MAX_WTX_MULTIPLIER: u8 = 24;
pub const RAW_APDU_BUDGET_MS: u64 = 30_000;
pub const RAW_BASE_COMMAND_BUDGET_MS: u64 = 5_000;
pub const RAW_BWT_MS: u64 = 1_190;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RawError {
    T1(Error),
    WtxMultiplierRejected,
    WtxLimitExceeded,
    WtxResponseRejected,
    ChainingRejected,
}

impl RawError {
    pub const fn name(self) -> &'static str {
        match self {
            Self::T1(error) => error.name(),
            Self::WtxMultiplierRejected => "T1WtxMultiplierRejected",
            Self::WtxLimitExceeded => "T1WtxLimitExceeded",
            Self::WtxResponseRejected => "T1WtxResponseRejected",
            Self::ChainingRejected => "T1ChainingRejected",
        }
    }
}

impl From<Error> for RawError {
    fn from(error: Error) -> Self {
        Self::T1(error)
    }
}

/// The session alone constructs these blocks and their associated bBWI value.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RawBlock {
    bytes: [u8; RAW_MAX_BLOCK_BYTES],
    len: usize,
    bwi: u8,
}

impl RawBlock {
    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes[..self.len]
    }

    pub fn bwi(&self) -> u8 {
        self.bwi
    }

    /// Host allowance; the caller must additionally apply the absolute APDU cap.
    pub fn command_allowance_ms(&self) -> u64 {
        RAW_BASE_COMMAND_BUDGET_MS.max(u64::from(self.bwi) * RAW_BWT_MS)
    }

    fn encode(pcb: u8, inf: &[u8], bwi: u8) -> Self {
        let mut block = Self {
            bytes: [0; RAW_MAX_BLOCK_BYTES],
            len: inf.len() + 4,
            bwi,
        };
        block.bytes[1] = pcb;
        block.bytes[2] = inf.len() as u8;
        block.bytes[3..3 + inf.len()].copy_from_slice(inf);
        block.bytes[block.len - 1] = block.bytes[..block.len - 1]
            .iter()
            .fold(0, |sum, byte| sum ^ byte);
        block
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum IfsState {
    Required,
    Pending,
    Accepted,
}

pub struct RawSession {
    phase: Phase,
    ifs: IfsState,
    send_sequence: u8,
    receive_sequence: u8,
    response: [u8; RAW_MAX_RESPONSE_BYTES],
    response_len: usize,
    pending: Option<RawBlock>,
    exchanges: usize,
    completed: usize,
    started: u64,
    last_now: Option<u64>,
    apdu_deadline: Option<u64>,
    wtx: [u8; RAW_MAX_WTX],
    wtx_len: usize,
    total_wtx: usize,
    failure: Option<RawError>,
}

impl Default for RawSession {
    fn default() -> Self {
        Self {
            phase: Phase::Idle,
            ifs: IfsState::Required,
            send_sequence: 0,
            receive_sequence: 0,
            response: [0; RAW_MAX_RESPONSE_BYTES],
            response_len: 0,
            pending: None,
            exchanges: 0,
            completed: 0,
            started: 0,
            last_now: None,
            apdu_deadline: None,
            wtx: [0; RAW_MAX_WTX],
            wtx_len: 0,
            total_wtx: 0,
            failure: None,
        }
    }
}

impl RawSession {
    pub fn phase(&self) -> Phase {
        self.phase
    }
    pub fn failure(&self) -> Option<RawError> {
        self.failure
    }
    pub fn ifs_accepted(&self) -> bool {
        self.ifs == IfsState::Accepted
    }
    pub fn receive_bound(&self) -> usize {
        if self.ifs_accepted() {
            RAW_MAX_BLOCK_BYTES
        } else {
            MAX_BLOCK_BYTES
        }
    }
    pub fn send_sequence(&self) -> u8 {
        self.send_sequence
    }
    pub fn receive_sequence(&self) -> u8 {
        self.receive_sequence
    }
    pub fn response(&self) -> &[u8] {
        &self.response[..self.response_len]
    }
    pub fn exchanges(&self) -> usize {
        self.exchanges
    }
    pub fn completed_apdus(&self) -> usize {
        self.completed
    }
    /// Retained after completion for evidence; only active APDUs are timed.
    pub fn apdu_deadline_ms(&self) -> Option<u64> {
        self.apdu_deadline
    }
    pub fn wtx_multipliers(&self) -> &[u8] {
        &self.wtx[..self.wtx_len]
    }
    pub fn wtx_count(&self) -> usize {
        self.wtx_len
    }
    pub fn total_wtx_count(&self) -> usize {
        self.total_wtx
    }

    fn reject<T>(&mut self, error: impl Into<RawError>) -> Result<T, RawError> {
        let error = *self.failure.get_or_insert(error.into());
        self.phase = Phase::Failed;
        Err(error)
    }

    /// Includes lower-layer writes, pauses, reads and evidence work.
    pub fn tick(&mut self, now_ms: u64) -> Result<(), RawError> {
        if let Some(error) = self.failure {
            return Err(error);
        }
        if self.last_now.is_some_and(|last| now_ms < last) {
            return self.reject(Error::ClockRegression);
        }
        self.last_now = Some(now_ms);
        if matches!(self.phase, Phase::Ready | Phase::Writing | Phase::Receiving) {
            let budget = if self.ifs == IfsState::Pending {
                RAW_BASE_COMMAND_BUDGET_MS
            } else {
                RAW_APDU_BUDGET_MS
            };
            if now_ms >= self.started.saturating_add(budget) {
                return self.reject(Error::DeadlineExceeded);
            }
        }
        Ok(())
    }

    pub fn begin_ifs(&mut self, now_ms: u64) -> Result<(), RawError> {
        self.tick(now_ms)?;
        if self.ifs != IfsState::Required || self.phase != Phase::Idle {
            return self.reject(Error::StateRejected);
        }
        self.ifs = IfsState::Pending;
        self.started = now_ms;
        self.pending = Some(RawBlock::encode(0xc1, &[0xfe], 0));
        self.phase = Phase::Ready;
        Ok(())
    }

    pub fn begin(&mut self, command: &[u8], now_ms: u64) -> Result<(), RawError> {
        self.tick(now_ms)?;
        if self.ifs != IfsState::Accepted || !matches!(self.phase, Phase::Idle | Phase::Complete) {
            return self.reject(Error::StateRejected);
        }
        if self.completed == RAW_MAX_APDUS {
            return self.reject(Error::ApduLimitExceeded);
        }
        if command.is_empty() || command.len() > RAW_MAX_COMMAND_BYTES {
            return self.reject(Error::CommandLengthRejected);
        }
        self.response_len = 0;
        self.exchanges = 0;
        self.wtx_len = 0;
        self.started = now_ms;
        self.apdu_deadline = Some(now_ms.saturating_add(RAW_APDU_BUDGET_MS));
        self.pending = Some(RawBlock::encode(self.send_sequence << 6, command, 0));
        self.phase = Phase::Ready;
        Ok(())
    }

    pub fn next_block(&mut self, now_ms: u64) -> Result<RawBlock, RawError> {
        self.tick(now_ms)?;
        if self.phase != Phase::Ready {
            return self.reject(Error::StateRejected);
        }
        if self.exchanges == RAW_MAX_EXCHANGES {
            return self.reject(Error::ExchangeLimitExceeded);
        }
        let Some(block) = self.pending.clone() else {
            return self.reject(Error::StateRejected);
        };
        self.phase = Phase::Writing;
        Ok(block)
    }

    pub fn written(&mut self, bytes: usize, now_ms: u64) -> Result<(), RawError> {
        self.tick(now_ms)?;
        if self.phase != Phase::Writing {
            return self.reject(Error::StateRejected);
        }
        if self.pending.as_ref().map(|block| block.as_bytes().len()) != Some(bytes) {
            return self.reject(Error::PartialWrite);
        }
        self.exchanges += 1;
        self.phase = Phase::Receiving;
        Ok(())
    }

    pub fn receive(&mut self, bytes: &[u8], now_ms: u64) -> Result<(), RawError> {
        self.tick(now_ms)?;
        if self.phase != Phase::Receiving {
            match decode_bounded(bytes, self.receive_bound()) {
                Err(Error::IfsRejected) => return self.reject(Error::IfsRejected),
                Err(Error::WtxRejected) if bytes[1] == 0xe3 => {
                    return self.reject(RawError::WtxResponseRejected);
                }
                _ => (),
            }
            return self.reject(Error::StateRejected);
        }
        if self.ifs == IfsState::Pending {
            if let Err(error) = validate_ifs_response(bytes) {
                return self.reject(error);
            }
            self.ifs = IfsState::Accepted;
            self.pending = None;
            self.phase = Phase::Idle;
            return Ok(());
        }
        let block = match decode_bounded(bytes, self.receive_bound()) {
            Ok(block) => block,
            // These indices are used only after the frozen decoder has checked
            // exact LEN, LRC, NAD, PCB and the one-byte control grammar.
            Err(Error::WtxRejected) if bytes[1] == 0xc3 => {
                let multiplier = bytes[3];
                if !(1..=RAW_MAX_WTX_MULTIPLIER).contains(&multiplier) {
                    return self.reject(RawError::WtxMultiplierRejected);
                }
                if self.wtx_len == RAW_MAX_WTX {
                    return self.reject(RawError::WtxLimitExceeded);
                }
                self.wtx[self.wtx_len] = multiplier;
                self.wtx_len += 1;
                self.total_wtx += 1;
                self.pending = Some(RawBlock::encode(0xe3, &[multiplier], multiplier));
                self.phase = Phase::Ready;
                return Ok(());
            }
            Err(Error::WtxRejected) => return self.reject(RawError::WtxResponseRejected),
            Err(error) => return self.reject(error),
        };
        let Received::I {
            sequence,
            more,
            inf,
        } = block
        else {
            return self.reject(Error::UnexpectedRBlock);
        };
        if sequence != self.receive_sequence {
            return self.reject(Error::SequenceRejected);
        }
        if more {
            return self.reject(RawError::ChainingRejected);
        }
        if inf.len() > RAW_MAX_RESPONSE_BYTES {
            return self.reject(Error::ResponseLengthRejected);
        }
        self.response[..inf.len()].copy_from_slice(inf);
        self.response_len = inf.len();
        self.send_sequence ^= 1;
        self.receive_sequence ^= 1;
        self.pending = None;
        self.completed += 1;
        self.phase = Phase::Complete;
        Ok(())
    }
}
