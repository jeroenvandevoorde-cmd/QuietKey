//! Immutable 781-byte Key Card B record grammar.

use core::{cmp::Ordering, fmt};

use crate::{
    Profile, DESCRIPTOR_BYTES, RAW_XPRV_BYTES, RECORD_BYTES, RECORD_VERSION, ROLE_KEY_CARD_B,
};

pub const RECORD_MAGIC_OFFSET: usize = 0;
pub const RECORD_VERSION_OFFSET: usize = 4;
pub const RECORD_PROFILE_OFFSET: usize = 5;
pub const RECORD_ROLE_OFFSET: usize = 6;
pub const RECORD_INSTANCE_ID_OFFSET: usize = 7;
pub const RECORD_WALLET_ID_OFFSET: usize = 23;
pub const RECORD_ORIGIN_FINGERPRINT_OFFSET: usize = 55;
pub const RECORD_XPRV_OFFSET: usize = 59;
pub const RECORD_A2_OFFSET: usize = 137;
pub const RECORD_RECEIVE_D_OFFSET: usize = 169;
pub const RECORD_CHANGE_D_OFFSET: usize = 475;

const RECORD_MAGIC: [u8; 4] = *b"QKCB";
const MAINNET_XPRV_VERSION: [u8; 4] = [0x04, 0x88, 0xad, 0xe4];
const ACCOUNT_DEPTH: u8 = 4;
const ACCOUNT_CHILD: [u8; 4] = [0x80, 0x00, 0x00, 0x02];
const SECP256K1_ORDER: [u8; 32] = [
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xfe,
    0xba, 0xae, 0xdc, 0xe6, 0xaf, 0x48, 0xa0, 0x3b, 0xbf, 0xd2, 0x5e, 0x8c, 0xd0, 0x36, 0x41, 0x41,
];

const _: () = assert!(RECORD_CHANGE_D_OFFSET + DESCRIPTOR_BYTES == RECORD_BYTES);
const _: () = assert!(RECORD_XPRV_OFFSET + RAW_XPRV_BYTES == RECORD_A2_OFFSET);

/// Named immutable-record rejection.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RecordError {
    Length,
    Magic,
    Version,
    Profile,
    Role,
    XprvVersion,
    XprvDepth,
    XprvChildNumber,
    XprvKeyPrefix,
    XprvScalar,
}

impl RecordError {
    pub const fn name(self) -> &'static str {
        match self {
            Self::Length => "RecordLength",
            Self::Magic => "RecordMagic",
            Self::Version => "RecordVersion",
            Self::Profile => "RecordProfile",
            Self::Role => "RecordRole",
            Self::XprvVersion => "RecordXprvVersion",
            Self::XprvDepth => "RecordXprvDepth",
            Self::XprvChildNumber => "RecordXprvChildNumber",
            Self::XprvKeyPrefix => "RecordXprvKeyPrefix",
            Self::XprvScalar => "RecordXprvScalar",
        }
    }
}

impl fmt::Display for RecordError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.name())
    }
}

impl std::error::Error for RecordError {}

/// Borrowed, structurally validated raw mainnet account xprv.
#[derive(Clone, Copy, Eq, PartialEq)]
pub struct XprvRef<'a> {
    bytes: &'a [u8; RAW_XPRV_BYTES],
}

impl<'a> XprvRef<'a> {
    pub const fn bytes(self) -> &'a [u8; RAW_XPRV_BYTES] {
        self.bytes
    }

    pub fn parent_fingerprint(self) -> &'a [u8; 4] {
        array_ref(&self.bytes[5..9]).expect("fixed xprv field")
    }

    pub fn chain_code(self) -> &'a [u8; 32] {
        array_ref(&self.bytes[13..45]).expect("fixed xprv field")
    }

    pub fn scalar(self) -> &'a [u8; 32] {
        array_ref(&self.bytes[46..78]).expect("fixed xprv field")
    }
}

impl fmt::Debug for XprvRef<'_> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("XprvRef(REDACTED)")
    }
}

/// Borrowed, fully structurally validated immutable record.
#[derive(Clone, Copy, Eq, PartialEq)]
pub struct RecordRef<'a> {
    bytes: &'a [u8; RECORD_BYTES],
    profile: Profile,
}

impl<'a> RecordRef<'a> {
    pub const fn bytes(self) -> &'a [u8; RECORD_BYTES] {
        self.bytes
    }

    pub const fn profile(self) -> Profile {
        self.profile
    }

    pub fn instance_id(self) -> &'a [u8; 16] {
        array_ref(&self.bytes[RECORD_INSTANCE_ID_OFFSET..RECORD_WALLET_ID_OFFSET])
            .expect("fixed record field")
    }

    pub fn wallet_id(self) -> &'a [u8; 32] {
        array_ref(&self.bytes[RECORD_WALLET_ID_OFFSET..RECORD_ORIGIN_FINGERPRINT_OFFSET])
            .expect("fixed record field")
    }

    pub fn origin_fingerprint(self) -> &'a [u8; 4] {
        array_ref(&self.bytes[RECORD_ORIGIN_FINGERPRINT_OFFSET..RECORD_XPRV_OFFSET])
            .expect("fixed record field")
    }

    pub fn account_xprv(self) -> XprvRef<'a> {
        XprvRef {
            bytes: array_ref(&self.bytes[RECORD_XPRV_OFFSET..RECORD_A2_OFFSET])
                .expect("fixed record field"),
        }
    }

    pub fn a2(self) -> &'a [u8; 32] {
        array_ref(&self.bytes[RECORD_A2_OFFSET..RECORD_RECEIVE_D_OFFSET])
            .expect("fixed record field")
    }

    pub fn receive_descriptor(self) -> &'a [u8; DESCRIPTOR_BYTES] {
        array_ref(&self.bytes[RECORD_RECEIVE_D_OFFSET..RECORD_CHANGE_D_OFFSET])
            .expect("fixed record field")
    }

    pub fn change_descriptor(self) -> &'a [u8; DESCRIPTOR_BYTES] {
        array_ref(&self.bytes[RECORD_CHANGE_D_OFFSET..RECORD_BYTES]).expect("fixed record field")
    }
}

impl fmt::Debug for RecordRef<'_> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("RecordRef(REDACTED)")
    }
}

fn array_ref<const N: usize>(bytes: &[u8]) -> Result<&[u8; N], RecordError> {
    bytes.try_into().map_err(|_| RecordError::Length)
}

fn scalar_is_valid(scalar: &[u8; 32]) -> bool {
    if scalar.iter().all(|byte| *byte == 0) {
        return false;
    }
    scalar.as_slice().cmp(SECP256K1_ORDER.as_slice()) == Ordering::Less
}

/// Parse and structurally validate the exact immutable record.
pub fn parse_record(bytes: &[u8]) -> Result<RecordRef<'_>, RecordError> {
    let fixed = array_ref::<RECORD_BYTES>(bytes)?;
    if fixed[RECORD_MAGIC_OFFSET..RECORD_VERSION_OFFSET] != RECORD_MAGIC {
        return Err(RecordError::Magic);
    }
    if fixed[RECORD_VERSION_OFFSET] != RECORD_VERSION {
        return Err(RecordError::Version);
    }
    let profile = Profile::from_byte(fixed[RECORD_PROFILE_OFFSET]).ok_or(RecordError::Profile)?;
    if fixed[RECORD_ROLE_OFFSET] != ROLE_KEY_CARD_B {
        return Err(RecordError::Role);
    }
    let xprv = &fixed[RECORD_XPRV_OFFSET..RECORD_A2_OFFSET];
    if xprv[0..4] != MAINNET_XPRV_VERSION {
        return Err(RecordError::XprvVersion);
    }
    if xprv[4] != ACCOUNT_DEPTH {
        return Err(RecordError::XprvDepth);
    }
    if xprv[9..13] != ACCOUNT_CHILD {
        return Err(RecordError::XprvChildNumber);
    }
    if xprv[45] != 0 {
        return Err(RecordError::XprvKeyPrefix);
    }
    let scalar = array_ref::<32>(&xprv[46..78])?;
    if !scalar_is_valid(scalar) {
        return Err(RecordError::XprvScalar);
    }
    Ok(RecordRef {
        bytes: fixed,
        profile,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn record() -> [u8; RECORD_BYTES] {
        let mut bytes = [0u8; RECORD_BYTES];
        bytes[0..4].copy_from_slice(b"QKCB");
        bytes[4] = 1;
        bytes[5] = 1;
        bytes[6] = 2;
        bytes[59..63].copy_from_slice(&MAINNET_XPRV_VERSION);
        bytes[63] = 4;
        bytes[68..72].copy_from_slice(&ACCOUNT_CHILD);
        bytes[104] = 0;
        bytes[136] = 1;
        bytes
    }

    #[test]
    fn parses_exact_structure() {
        let bytes = record();
        let parsed = parse_record(&bytes).expect("valid record");
        assert_eq!(parsed.profile(), Profile::SimpleRecovery);
        assert_eq!(parsed.account_xprv().scalar()[31], 1);
    }

    #[test]
    fn rejects_curve_order() {
        let mut bytes = record();
        bytes[105..137].copy_from_slice(&SECP256K1_ORDER);
        assert_eq!(parse_record(&bytes), Err(RecordError::XprvScalar));
    }
}
