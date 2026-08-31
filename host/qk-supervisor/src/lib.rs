//! HOST-only QuietKey supervisor lifecycle and Unix receive-boundary reference.
//!
//! This crate owns no wallet, card, key, share, transaction, or other secret
//! material. It spawns no process and grants no real device. Target process,
//! namespace, device, privilege, and runtime-directory enforcement remain
//! outside this HOST reference.

#![deny(unsafe_code)]

mod lifecycle;
#[allow(unsafe_code)]
mod unix_recv;

pub use lifecycle::{
    Child, Device, MockGrantSet, ProcessRole, Supervisor, SupervisorAction, SupervisorError,
    SupervisorEvent, SupervisorOutcome, SupervisorState,
};
pub use unix_recv::{receive_once, UnixReceiveError, UnixReceiveOutcome};
