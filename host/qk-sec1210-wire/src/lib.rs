//! QK-DEC-167: mock-first status/ATR framing, not an APDU transport.
#![forbid(unsafe_code)]

mod codec;
mod exchange;

pub use codec::{Decoder, Error, Message, Response, MAX_CCID_BYTES, MAX_WIRE_BYTES};
pub use exchange::{
    Command, Exchange, Observation, Phase, MAX_EVENTS, MAX_RECEIVED_BYTES, RECEIVE_BUDGET_MS,
    REGISTERED_ATR,
};
