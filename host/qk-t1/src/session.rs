use crate::codec::{
    decode_bounded, encode_ifs_request, validate_ifs_response, IFS_MAX_BLOCK_BYTES,
};
use crate::{
    encode_ack, encode_command, Block, Error, Received, MAX_BLOCK_BYTES, MAX_RESPONSE_BYTES,
};

pub const APDU_BUDGET_MS: u64 = 30_000;
pub const IFS_BUDGET_MS: u64 = 5_000;
pub const MAX_EXCHANGES: usize = 16;
pub const MAX_APDUS: usize = 8;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Phase {
    Idle,
    Ready,
    Writing,
    Receiving,
    Complete,
    Failed,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum IfsState {
    Disabled,
    Required,
    Pending,
    Accepted,
}

pub struct Session {
    phase: Phase,
    ifs: IfsState,
    send_sequence: u8,
    receive_sequence: u8,
    command_acked: bool,
    expected: [u8; MAX_RESPONSE_BYTES],
    expected_len: usize,
    response: [u8; MAX_RESPONSE_BYTES],
    response_len: usize,
    pending: Option<Block>,
    exchanges: usize,
    completed: usize,
    started: u64,
    last_now: Option<u64>,
    failure: Option<Error>,
}

impl Default for Session {
    fn default() -> Self {
        Self {
            phase: Phase::Idle,
            ifs: IfsState::Disabled,
            send_sequence: 0,
            receive_sequence: 0,
            command_acked: false,
            expected: [0; MAX_RESPONSE_BYTES],
            expected_len: 0,
            response: [0; MAX_RESPONSE_BYTES],
            response_len: 0,
            pending: None,
            exchanges: 0,
            completed: 0,
            started: 0,
            last_now: None,
            failure: None,
        }
    }
}

impl Session {
    /// Require the single SUP-007 IFSD 254 negotiation before any APDU.
    /// The default session remains fixed at IFSD 32.
    pub fn with_ifs() -> Self {
        Self {
            ifs: IfsState::Required,
            ..Self::default()
        }
    }

    pub fn ifs_accepted(&self) -> bool {
        self.ifs == IfsState::Accepted
    }

    pub fn receive_bound(&self) -> usize {
        if self.ifs_accepted() {
            IFS_MAX_BLOCK_BYTES
        } else {
            MAX_BLOCK_BYTES
        }
    }

    pub fn phase(&self) -> Phase {
        self.phase
    }
    pub fn failure(&self) -> Option<Error> {
        self.failure
    }
    pub fn exchanges(&self) -> usize {
        self.exchanges
    }
    pub fn completed_apdus(&self) -> usize {
        self.completed
    }
    pub fn send_sequence(&self) -> u8 {
        self.send_sequence
    }
    pub fn receive_sequence(&self) -> u8 {
        self.receive_sequence
    }
    pub fn response_prefix(&self) -> &[u8] {
        &self.response[..self.response_len]
    }

    fn reject<T>(&mut self, error: Error) -> Result<T, Error> {
        let error = *self.failure.get_or_insert(error);
        self.phase = Phase::Failed;
        Err(error)
    }

    /// The caller uses one monotonic clock for the whole invocation, including
    /// trace work and time spent waiting in the lower CCID layer.
    pub fn tick(&mut self, now_ms: u64) -> Result<(), Error> {
        if let Some(error) = self.failure {
            return Err(error);
        }
        if self.last_now.is_some_and(|last| now_ms < last) {
            return self.reject(Error::ClockRegression);
        }
        self.last_now = Some(now_ms);
        let budget = if self.ifs == IfsState::Pending {
            IFS_BUDGET_MS
        } else {
            APDU_BUDGET_MS
        };
        if matches!(self.phase, Phase::Ready | Phase::Writing | Phase::Receiving)
            && now_ms - self.started >= budget
        {
            return self.reject(Error::DeadlineExceeded);
        }
        Ok(())
    }

    /// Queue exactly one terminal-initiated S(IFS request), using the same
    /// claim/write/receive path and caller clock as the APDU exchanges.
    pub fn begin_ifs(&mut self, now_ms: u64) -> Result<(), Error> {
        if let Some(error) = self.failure {
            return Err(error);
        }
        if self.ifs != IfsState::Required || self.phase != Phase::Idle {
            return self.reject(Error::StateRejected);
        }
        self.tick(now_ms)?;
        self.ifs = IfsState::Pending;
        self.started = now_ms;
        self.pending = Some(encode_ifs_request());
        self.phase = Phase::Ready;
        Ok(())
    }

    pub fn begin(&mut self, command: &[u8], expected: &[u8], now_ms: u64) -> Result<(), Error> {
        if let Some(error) = self.failure {
            return Err(error);
        }
        if !matches!(self.phase, Phase::Idle | Phase::Complete)
            || matches!(self.ifs, IfsState::Required | IfsState::Pending)
        {
            return self.reject(Error::StateRejected);
        }
        self.tick(now_ms)?;
        if self.completed == MAX_APDUS {
            return self.reject(Error::ApduLimitExceeded);
        }
        let pending = match encode_command(command, self.send_sequence) {
            Ok(block) => block,
            Err(error) => return self.reject(error),
        };
        if expected.is_empty() || expected.len() > MAX_RESPONSE_BYTES {
            return self.reject(Error::ResponseLengthRejected);
        }
        self.expected[..expected.len()].copy_from_slice(expected);
        self.expected_len = expected.len();
        self.response_len = 0;
        self.command_acked = false;
        self.exchanges = 0;
        self.started = now_ms;
        self.pending = Some(pending);
        self.phase = Phase::Ready;
        Ok(())
    }

    /// Claim exactly one pending block after checking the deadline and budget.
    /// A second claim, write or receive cannot retransmit it.
    pub fn next_block(&mut self, now_ms: u64) -> Result<Block, Error> {
        self.tick(now_ms)?;
        if self.phase != Phase::Ready {
            return self.reject(Error::StateRejected);
        }
        if self.exchanges == MAX_EXCHANGES {
            return self.reject(Error::ExchangeLimitExceeded);
        }
        let Some(block) = self.pending.clone() else {
            return self.reject(Error::StateRejected);
        };
        self.phase = Phase::Writing;
        Ok(block)
    }

    pub fn written(&mut self, bytes: usize, now_ms: u64) -> Result<(), Error> {
        if let Some(error) = self.failure {
            return Err(error);
        }
        if self.phase != Phase::Writing {
            return self.reject(Error::StateRejected);
        }
        if self.pending.as_ref().map(|b| b.as_bytes().len()) != Some(bytes) {
            return self.reject(Error::PartialWrite);
        }
        self.exchanges += 1;
        self.tick(now_ms)?;
        self.phase = Phase::Receiving;
        Ok(())
    }

    pub fn receive(&mut self, bytes: &[u8], now_ms: u64) -> Result<(), Error> {
        self.tick(now_ms)?;
        if self.phase != Phase::Receiving {
            // On the explicit IFS path, unsolicited control blocks retain
            // their named rejection even outside an outstanding exchange.
            // The default session keeps its existing state-first behavior.
            if self.ifs != IfsState::Disabled {
                if let Err(error) = decode_bounded(bytes, self.receive_bound()) {
                    return self.reject(error);
                }
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
        if inf.len() > self.expected_len - self.response_len {
            return self.reject(Error::ResponseLengthRejected);
        }
        let end = self.response_len + inf.len();
        if inf != &self.expected[self.response_len..end] {
            return self.reject(Error::ResponseMismatch);
        }
        if (!more && end != self.expected_len) || (more && end == self.expected_len) {
            return self.reject(Error::ResponseLengthRejected);
        }
        self.response[self.response_len..end].copy_from_slice(inf);
        self.response_len = end;
        if !self.command_acked {
            self.send_sequence ^= 1;
            self.command_acked = true;
        }
        self.receive_sequence ^= 1;
        if more {
            if self.exchanges == MAX_EXCHANGES {
                return self.reject(Error::ExchangeLimitExceeded);
            }
            self.pending = Some(encode_ack(self.receive_sequence).expect("one-bit sequence"));
            self.phase = Phase::Ready;
        } else {
            self.pending = None;
            self.completed += 1;
            self.phase = Phase::Complete;
        }
        Ok(())
    }
}
