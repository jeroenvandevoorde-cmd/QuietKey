//! QK-DEC-167-SUP-003's bounded, fail-first T=1 readback subset.
//! No I/O, protocol negotiation, retransmission, or recovery is performed.
#![forbid(unsafe_code)]

mod codec;
mod session;

pub use codec::{decode, encode_ack, encode_command, Block, Error, Received, MAX_BLOCK_BYTES};
pub use session::{Phase, Session, APDU_BUDGET_MS, MAX_APDUS, MAX_EXCHANGES};

pub const MAX_COMMAND_BYTES: usize = 30;
pub const MAX_RESPONSE_BYTES: usize = 218;
pub const IFSC: usize = 254;
pub const IFSD: usize = 32;
