//! Stable, explicit rejection categories. Every parse failure carries
//! exactly one category and the byte offset where it was detected.

use core::fmt;

/// Stable rejection category. Categories are explicit and exhaustive;
/// rejection is always fail-closed and never panics.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum RejectCategory {
    /// Input exceeds the byte cap for its declared source.
    InputTooLarge,
    /// Missing or wrong `psbt\xff` magic prefix.
    InvalidMagic,
    /// Input ends before a structurally required byte.
    Truncated,
    /// A CompactSize is not encoded in its minimal form.
    NonMinimalCompactSize,
    /// A key violates structural rules: its CompactSize key type does
    /// not fit inside the key, key data is present where the type
    /// requires none, or key data has an invalid length for its type.
    InvalidKeyStructure,
    /// A value violates the structural rules enforced for its type.
    InvalidValueStructure,
    /// Two records in one map share identical complete raw key bytes.
    DuplicateKey,
    /// A PSBT v2 global field (types 0x02 through 0x06).
    V2GlobalField,
    /// A Taproot field (input 0x13-0x18, output 0x05-0x07).
    TaprootField,
    /// The global map lacks the required unsigned-transaction record.
    MissingUnsignedTx,
    /// The unsigned transaction value is structurally malformed.
    MalformedUnsignedTx,
    /// The unsigned transaction uses witness serialization format.
    UnsignedTxWitnessFormat,
    /// An unsigned-transaction input carries a non-empty scriptSig.
    UnsignedTxScriptSigNotEmpty,
    /// The unsigned transaction declares zero inputs.
    UnsignedTxZeroInputs,
    /// The unsigned transaction declares zero outputs.
    UnsignedTxZeroOutputs,
    /// Input ends at a map boundary before all declared maps appeared.
    InvalidMapCount,
    /// Bytes remain after the final declared output map.
    TrailingBytes,
    /// More unsigned-transaction inputs than `limits::MAX_INPUTS`.
    TooManyInputs,
    /// More unsigned-transaction outputs than `limits::MAX_OUTPUTS`.
    TooManyOutputs,
    /// More signer-bearing records in one map than `limits::MAX_SIGNERS`.
    TooManySigners,
    /// A BIP32 derivation path deeper than `limits::MAX_PATH_DEPTH`.
    PathTooDeep,
    /// The ephemeral duplicate-detection set could not allocate.
    AllocationFailed,
    /// A well-formed global version field declares a version other
    /// than zero.
    UnsupportedPsbtVersion,
    /// A complete raw key (encoded key type plus key data, excluding
    /// the key-length prefix) exceeds the candidate
    /// `limits::MAX_KEY_BYTES`.
    KeyTooLong,
    /// A record value (excluding its length prefix) exceeds the
    /// candidate `limits::MAX_VALUE_BYTES`.
    ValueTooLong,
    /// More records in one map than the candidate
    /// `limits::MAX_RECORDS_PER_MAP`; every non-separator record
    /// counts.
    TooManyRecords,
    /// An unsigned-transaction output scriptPubKey exceeds the
    /// candidate `limits::MAX_TX_OUTPUT_SCRIPT_BYTES`.
    TxOutputScriptTooLong,
}

impl fmt::Display for RejectCategory {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let s = match self {
            Self::InputTooLarge => "input exceeds source byte cap",
            Self::InvalidMagic => "missing or wrong psbt magic",
            Self::Truncated => "input truncated",
            Self::NonMinimalCompactSize => "non-minimal CompactSize",
            Self::InvalidKeyStructure => "invalid key structure",
            Self::InvalidValueStructure => "invalid value structure",
            Self::DuplicateKey => "duplicate complete raw key",
            Self::V2GlobalField => "psbt v2 global field",
            Self::TaprootField => "taproot field",
            Self::MissingUnsignedTx => "missing unsigned transaction",
            Self::MalformedUnsignedTx => "malformed unsigned transaction",
            Self::UnsignedTxWitnessFormat => "unsigned tx in witness format",
            Self::UnsignedTxScriptSigNotEmpty => "unsigned tx scriptSig not empty",
            Self::UnsignedTxZeroInputs => "unsigned tx declares zero inputs",
            Self::UnsignedTxZeroOutputs => "unsigned tx declares zero outputs",
            Self::InvalidMapCount => "invalid map count",
            Self::TrailingBytes => "trailing bytes after final map",
            Self::TooManyInputs => "too many inputs",
            Self::TooManyOutputs => "too many outputs",
            Self::TooManySigners => "too many signer records",
            Self::PathTooDeep => "derivation path too deep",
            Self::AllocationFailed => "duplicate-set allocation failed",
            Self::UnsupportedPsbtVersion => "unsupported psbt version",
            Self::KeyTooLong => "complete raw key too long",
            Self::ValueTooLong => "record value too long",
            Self::TooManyRecords => "too many records in one map",
            Self::TxOutputScriptTooLong => "unsigned tx output script too long",
        };
        f.write_str(s)
    }
}

/// A structural rejection: one stable category plus the byte offset in
/// the input buffer at which the condition was detected.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ParseError {
    /// Stable rejection category.
    pub category: RejectCategory,
    /// Byte offset in the input buffer where detection occurred.
    pub offset: usize,
}

impl ParseError {
    pub(crate) const fn new(category: RejectCategory, offset: usize) -> Self {
        Self { category, offset }
    }
}

impl fmt::Display for ParseError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{} at byte {}", self.category, self.offset)
    }
}

impl std::error::Error for ParseError {}
