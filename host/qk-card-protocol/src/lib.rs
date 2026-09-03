//! Bounded QuietKey Key Card B protocol grammar and session accounting.
//!
//! HOST REFERENCE ONLY -- NOT AN APPLET OR DEVICE DRIVER. This crate parses
//! hostile protocol bytes but performs no card I/O, signing, persistence,
//! randomness, logging, or platform operation.

#![deny(unsafe_code)]

mod apdu;
mod record;
mod session;
#[allow(unsafe_code)]
mod wipe;

pub use apdu::{
    encode_abort, encode_begin_provision, encode_commit, encode_export_a2, encode_get_info,
    encode_open_session, encode_read_d_chunk, encode_rejection, encode_select, encode_sign_digest,
    encode_success, encode_write_chunk, instruction_allows_rejection, parse_command,
    parse_response, A2Purpose, CommandRef, DescriptorSelector, EncodeError, EnvelopeRef,
    Instruction, Media, Mode, Profile, ProtocolError, ResponseError, ResponseRef, SignRequest,
    StatusWord,
};
pub use record::{
    parse_record, RecordError, RecordRef, XprvRef, RECORD_A2_OFFSET, RECORD_CHANGE_D_OFFSET,
    RECORD_INSTANCE_ID_OFFSET, RECORD_MAGIC_OFFSET, RECORD_ORIGIN_FINGERPRINT_OFFSET,
    RECORD_PROFILE_OFFSET, RECORD_RECEIVE_D_OFFSET, RECORD_ROLE_OFFSET, RECORD_VERSION_OFFSET,
    RECORD_WALLET_ID_OFFSET, RECORD_XPRV_OFFSET,
};
pub use session::{allowed_operations, Lifecycle, SessionTracker};
#[cfg(feature = "fuzzing")]
#[doc(hidden)]
pub use wipe::{reset_wiped_bytes, wiped_bytes};

/// Exact six-byte development applet AID.
pub const APPLET_AID: [u8; 6] = [0xf0, 0x51, 0x4b, 0x32, 0x42, 0x01];
/// Exact protocol version.
pub const PROTOCOL_VERSION: u8 = 1;
/// Exact immutable record version.
pub const RECORD_VERSION: u8 = 1;
/// Exact Key Card B role byte.
pub const ROLE_KEY_CARD_B: u8 = 2;
/// Exact immutable record length.
pub const RECORD_BYTES: usize = 781;
/// Exact maximum provisioning chunk length.
pub const MAX_WRITE_CHUNK_BYTES: usize = 192;
/// Exact number of provisioning chunks.
pub const WRITE_CHUNK_COUNT: usize = 5;
/// Exact descriptor byte length.
pub const DESCRIPTOR_BYTES: usize = 306;
/// Exact raw extended-public-key length.
pub const RAW_XPUB_BYTES: usize = 78;
/// Exact raw extended-private-key length.
pub const RAW_XPRV_BYTES: usize = 78;
/// Exact non-SELECT exchange cap per volatile session.
pub const MAX_EXCHANGES: u16 = 128;
/// Exact serialized command-and-response byte cap per volatile session.
pub const MAX_AGGREGATE_BYTES: usize = 65_536;
/// Exact per-session signature request cap.
pub const MAX_SIGNATURES: u8 = 100;
/// Exact maximum child index.
pub const MAX_CHILD_INDEX: u32 = 65_535;
/// Exact maximum proprietary APDU request length.
pub const MAX_REQUEST_BYTES: usize = 221;
/// Exact maximum response length, status word included.
pub const MAX_RESPONSE_BYTES: usize = 218;

const _: () = assert!(RECORD_BYTES == 4 + 1 + 1 + 1 + 16 + 32 + 4 + 78 + 32 + 306 + 306);
const _: () = assert!(MAX_REQUEST_BYTES == 4 + 1 + 21 + 2 + 192 + 1);
const _: () = assert!(MAX_RESPONSE_BYTES == 21 + 1 + 2 + 192 + 2);
const _: () = assert!(128 * (MAX_REQUEST_BYTES + MAX_RESPONSE_BYTES) == 56_192);
