//! HOST-only QuietKey trusted-process foundation and non-signing shell.
//!
//! This slice owns one QKIP core endpoint, independently parses the exact
//! qk-io peer grammar, and exposes only typed mock Display, Keypad, and
//! CardSlot capabilities. Transported artifact bytes remain sealed as hostile
//! input. No wallet semantic, approval, signing, export, APDU, real-device,
//! process, socket, persistence, target, production, or Gate claim exists.

#![deny(unsafe_code)]
#![deny(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects
)]

mod capability;
mod error;
mod io_wire;
mod session;
mod session_id;
#[allow(unsafe_code)]
mod wipe;

pub use capability::{
    CardBPublicBindingV2, CardInstanceV2, CardMockErrorV2, CardPresence, CoreDeviceGrants,
    CoreScreen, KeypadKey, MockCardSlot, MockDisplay, MockKeypad,
};
pub use error::{CoreError, Interruption, IoRejection};
pub use io_wire::{Operation, Source};
pub use session::{
    CoreMode, CoreOutbound, CoreReceiveEvent, CoreReceiveOutcome, CoreSession, CoreState,
    HostileIngress,
};

/// Exact QK-DEC-144 inner peer version.
pub const INNER_VERSION: u8 = 1;
/// Exact request/response inner header width.
pub const INNER_HEADER_BYTES: usize = 8;
/// Exact deterministic qk-io transfer chunk ceiling.
pub const MAX_CHUNK_BYTES: usize = 262_144;
/// Exact largest hostile artifact accepted by the HOST shell.
pub const MAX_INGRESS_BYTES: usize = 2_097_152;

const _: () = assert!(MAX_INGRESS_BYTES == qk_ipc::MAX_PAYLOAD_BYTES);

#[cfg(feature = "fuzzing")]
#[doc(hidden)]
pub mod fuzz {
    pub use crate::io_wire::{
        encode_ingress_begin, encode_ingress_read, parse_response, ExpectedResponse, Response,
    };
    pub use crate::session::fuzz_start_session;
    pub use crate::wipe::{reset_wiped_bytes, wiped_bytes};
}
