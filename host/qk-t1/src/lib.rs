//! QK-DEC-167-SUP-003/007's bounded, fail-first T=1 readback subset.
//! Explicit sessions permit one fixed IFSD negotiation. No I/O,
//! retransmission, or recovery is performed.
#![deny(unsafe_code)]

mod codec;
mod raw_session;
mod session;
#[allow(unsafe_code)]
mod wipe;

pub use codec::{decode, encode_ack, encode_command, Block, Error, Received, MAX_BLOCK_BYTES};
pub use raw_session::{
    RawBlock, RawError, RawSession, RAW_APDU_BUDGET_MS, RAW_BASE_COMMAND_BUDGET_MS, RAW_BWT_MS,
    RAW_MAX_APDUS, RAW_MAX_BLOCK_BYTES, RAW_MAX_COMMAND_BYTES, RAW_MAX_EXCHANGES,
    RAW_MAX_RESPONSE_BYTES, RAW_MAX_WTX, RAW_MAX_WTX_MULTIPLIER,
};
pub use session::{Phase, Session, APDU_BUDGET_MS, IFS_BUDGET_MS, MAX_APDUS, MAX_EXCHANGES};

pub const MAX_COMMAND_BYTES: usize = 30;
pub const MAX_RESPONSE_BYTES: usize = 218;
pub const IFSC: usize = 254;
pub const IFSD: usize = 32;
