//! QK-DEC-167: mock-first status/ATR framing, not an APDU transport.
#![forbid(unsafe_code)]

mod codec;
mod exchange;
mod readback;

pub use codec::{Decoder, Error, Message, Response, MAX_CCID_BYTES, MAX_WIRE_BYTES};
pub use exchange::{
    Command, Exchange, Observation, Phase, MAX_EVENTS, MAX_RECEIVED_BYTES, RECEIVE_BUDGET_MS,
    REGISTERED_ATR,
};
pub use readback::{
    ReadbackCommand, ReadbackError, ReadbackObservation, ReadbackPhase, ReadbackRequest,
    ReadbackSession, READBACK_COMMAND_BUDGET_MS, READBACK_MAX_COMMANDS, READBACK_MAX_EVENTS,
    READBACK_MAX_OUTGOING_TPDU_BYTES, READBACK_MAX_RECEIVED_BYTES,
};
