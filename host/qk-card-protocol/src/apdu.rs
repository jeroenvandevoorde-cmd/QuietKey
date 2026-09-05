//! Exact APDU grammar, status words, and allocation-free encoders.

use core::fmt;

use crate::{
    APPLET_AID, MAX_CHILD_INDEX, MAX_REQUEST_BYTES, MAX_RESPONSE_BYTES, MAX_WRITE_CHUNK_BYTES,
    PROTOCOL_VERSION,
};

const SELECT_INS: u8 = 0xa4;
const PROPRIETARY_CLA: u8 = 0x80;
const SELECT_CLA: u8 = 0x00;
const ENVELOPE_BYTES: usize = 21;

/// Physical-media fact supplied by the card boundary.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Media {
    /// Contact interface with negotiated T=1.
    ContactT1,
    /// Any contactless transport.
    Contactless,
}

/// OPEN_SESSION mode byte.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum Mode {
    Setup = 0x01,
    Normal = 0x02,
    KitRestore = 0x03,
    Rescue = 0x04,
}

impl Mode {
    pub const fn from_byte(value: u8) -> Option<Self> {
        match value {
            0x01 => Some(Self::Setup),
            0x02 => Some(Self::Normal),
            0x03 => Some(Self::KitRestore),
            0x04 => Some(Self::Rescue),
            _ => None,
        }
    }

    pub const fn byte(self) -> u8 {
        self as u8
    }
}

/// Provisioned wallet profile byte.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum Profile {
    SimpleRecovery = 0x01,
    Inheritance = 0x02,
    QuantumShelter = 0x03,
}

impl Profile {
    pub const fn from_byte(value: u8) -> Option<Self> {
        match value {
            0x01 => Some(Self::SimpleRecovery),
            0x02 => Some(Self::Inheritance),
            0x03 => Some(Self::QuantumShelter),
            _ => None,
        }
    }

    pub const fn byte(self) -> u8 {
        self as u8
    }
}

/// Descriptor selector used by READ_D_CHUNK.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum DescriptorSelector {
    Receive = 0x01,
    Change = 0x02,
}

impl DescriptorSelector {
    pub const fn from_byte(value: u8) -> Option<Self> {
        match value {
            0x01 => Some(Self::Receive),
            0x02 => Some(Self::Change),
            _ => None,
        }
    }

    pub const fn byte(self) -> u8 {
        self as u8
    }
}

/// A2 export purpose byte.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum A2Purpose {
    Setup = 0x01,
    Normal = 0x02,
    Rescue = 0x03,
}

impl A2Purpose {
    pub const fn from_byte(value: u8) -> Option<Self> {
        match value {
            0x01 => Some(Self::Setup),
            0x02 => Some(Self::Normal),
            0x03 => Some(Self::Rescue),
            _ => None,
        }
    }

    pub const fn byte(self) -> u8 {
        self as u8
    }
}

/// Closed command set.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum Instruction {
    Select = SELECT_INS,
    OpenSession = 0x10,
    GetInfo = 0x11,
    ReadDChunk = 0x12,
    ExportA2 = 0x13,
    SignDigest = 0x15,
    BeginProvision = 0x20,
    WriteChunk = 0x21,
    Commit = 0x22,
    Abort = 0x23,
}

impl Instruction {
    pub const fn from_byte(value: u8) -> Option<Self> {
        match value {
            SELECT_INS => Some(Self::Select),
            0x10 => Some(Self::OpenSession),
            0x11 => Some(Self::GetInfo),
            0x12 => Some(Self::ReadDChunk),
            0x13 => Some(Self::ExportA2),
            0x15 => Some(Self::SignDigest),
            0x20 => Some(Self::BeginProvision),
            0x21 => Some(Self::WriteChunk),
            0x22 => Some(Self::Commit),
            0x23 => Some(Self::Abort),
            _ => None,
        }
    }

    pub const fn byte(self) -> u8 {
        self as u8
    }
}

/// Exact status-word vocabulary.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u16)]
pub enum StatusWord {
    Success = 0x9000,
    WrongLength = 0x6700,
    IncorrectP1P2 = 0x6a86,
    InstructionNotSupported = 0x6d00,
    ClassNotSupported = 0x6e00,
    ProtocolVersionMismatch = 0x6f01,
    ContactInterfaceRequired = 0x6f02,
    SessionStateRejected = 0x6f03,
    SessionIdMismatch = 0x6f04,
    SequenceRejected = 0x6f05,
    ModeOrOperationRejected = 0x6f06,
    LifecycleRejected = 0x6f07,
    ProvisioningOrderRejected = 0x6f08,
    RecordRejected = 0x6f09,
    WalletBindingRejected = 0x6f0a,
    DerivationPathRejected = 0x6f0b,
    ChildDerivationRejected = 0x6f0c,
    SigningBindingRejected = 0x6f0d,
    CryptographicOperationRejected = 0x6f0e,
    InternalIntegrityFailure = 0x6f0f,
}

impl StatusWord {
    pub const fn value(self) -> u16 {
        self as u16
    }

    pub const fn bytes(self) -> [u8; 2] {
        self.value().to_be_bytes()
    }

    pub const fn from_value(value: u16) -> Option<Self> {
        match value {
            0x9000 => Some(Self::Success),
            0x6700 => Some(Self::WrongLength),
            0x6a86 => Some(Self::IncorrectP1P2),
            0x6d00 => Some(Self::InstructionNotSupported),
            0x6e00 => Some(Self::ClassNotSupported),
            0x6f01 => Some(Self::ProtocolVersionMismatch),
            0x6f02 => Some(Self::ContactInterfaceRequired),
            0x6f03 => Some(Self::SessionStateRejected),
            0x6f04 => Some(Self::SessionIdMismatch),
            0x6f05 => Some(Self::SequenceRejected),
            0x6f06 => Some(Self::ModeOrOperationRejected),
            0x6f07 => Some(Self::LifecycleRejected),
            0x6f08 => Some(Self::ProvisioningOrderRejected),
            0x6f09 => Some(Self::RecordRejected),
            0x6f0a => Some(Self::WalletBindingRejected),
            0x6f0b => Some(Self::DerivationPathRejected),
            0x6f0c => Some(Self::ChildDerivationRejected),
            0x6f0d => Some(Self::SigningBindingRejected),
            0x6f0e => Some(Self::CryptographicOperationRejected),
            0x6f0f => Some(Self::InternalIntegrityFailure),
            _ => None,
        }
    }
}

/// Named protocol rejection with a fixed status word.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ProtocolError {
    WrongLength,
    IncorrectP1P2,
    InstructionNotSupported,
    ClassNotSupported,
    ProtocolVersionMismatch,
    ContactInterfaceRequired,
    SessionStateRejected,
    SessionIdMismatch,
    SequenceRejected,
    ModeOrOperationRejected,
    LifecycleRejected,
    ProvisioningOrderRejected,
    RecordRejected,
    WalletBindingRejected,
    DerivationPathRejected,
    ChildDerivationRejected,
    SigningBindingRejected,
    CryptographicOperationRejected,
    InternalIntegrityFailure,
}

impl ProtocolError {
    pub const fn name(self) -> &'static str {
        match self {
            Self::WrongLength => "WrongLength",
            Self::IncorrectP1P2 => "IncorrectP1P2",
            Self::InstructionNotSupported => "InstructionNotSupported",
            Self::ClassNotSupported => "ClassNotSupported",
            Self::ProtocolVersionMismatch => "ProtocolVersionMismatch",
            Self::ContactInterfaceRequired => "ContactInterfaceRequired",
            Self::SessionStateRejected => "SessionStateRejected",
            Self::SessionIdMismatch => "SessionIdMismatch",
            Self::SequenceRejected => "SequenceRejected",
            Self::ModeOrOperationRejected => "ModeOrOperationRejected",
            Self::LifecycleRejected => "LifecycleRejected",
            Self::ProvisioningOrderRejected => "ProvisioningOrderRejected",
            Self::RecordRejected => "RecordRejected",
            Self::WalletBindingRejected => "WalletBindingRejected",
            Self::DerivationPathRejected => "DerivationPathRejected",
            Self::ChildDerivationRejected => "ChildDerivationRejected",
            Self::SigningBindingRejected => "SigningBindingRejected",
            Self::CryptographicOperationRejected => "CryptographicOperationRejected",
            Self::InternalIntegrityFailure => "InternalIntegrityFailure",
        }
    }

    pub const fn status_word(self) -> StatusWord {
        match self {
            Self::WrongLength => StatusWord::WrongLength,
            Self::IncorrectP1P2 => StatusWord::IncorrectP1P2,
            Self::InstructionNotSupported => StatusWord::InstructionNotSupported,
            Self::ClassNotSupported => StatusWord::ClassNotSupported,
            Self::ProtocolVersionMismatch => StatusWord::ProtocolVersionMismatch,
            Self::ContactInterfaceRequired => StatusWord::ContactInterfaceRequired,
            Self::SessionStateRejected => StatusWord::SessionStateRejected,
            Self::SessionIdMismatch => StatusWord::SessionIdMismatch,
            Self::SequenceRejected => StatusWord::SequenceRejected,
            Self::ModeOrOperationRejected => StatusWord::ModeOrOperationRejected,
            Self::LifecycleRejected => StatusWord::LifecycleRejected,
            Self::ProvisioningOrderRejected => StatusWord::ProvisioningOrderRejected,
            Self::RecordRejected => StatusWord::RecordRejected,
            Self::WalletBindingRejected => StatusWord::WalletBindingRejected,
            Self::DerivationPathRejected => StatusWord::DerivationPathRejected,
            Self::ChildDerivationRejected => StatusWord::ChildDerivationRejected,
            Self::SigningBindingRejected => StatusWord::SigningBindingRejected,
            Self::CryptographicOperationRejected => StatusWord::CryptographicOperationRejected,
            Self::InternalIntegrityFailure => StatusWord::InternalIntegrityFailure,
        }
    }

    pub const fn from_status_word(status: StatusWord) -> Option<Self> {
        match status {
            StatusWord::Success => None,
            StatusWord::WrongLength => Some(Self::WrongLength),
            StatusWord::IncorrectP1P2 => Some(Self::IncorrectP1P2),
            StatusWord::InstructionNotSupported => Some(Self::InstructionNotSupported),
            StatusWord::ClassNotSupported => Some(Self::ClassNotSupported),
            StatusWord::ProtocolVersionMismatch => Some(Self::ProtocolVersionMismatch),
            StatusWord::ContactInterfaceRequired => Some(Self::ContactInterfaceRequired),
            StatusWord::SessionStateRejected => Some(Self::SessionStateRejected),
            StatusWord::SessionIdMismatch => Some(Self::SessionIdMismatch),
            StatusWord::SequenceRejected => Some(Self::SequenceRejected),
            StatusWord::ModeOrOperationRejected => Some(Self::ModeOrOperationRejected),
            StatusWord::LifecycleRejected => Some(Self::LifecycleRejected),
            StatusWord::ProvisioningOrderRejected => Some(Self::ProvisioningOrderRejected),
            StatusWord::RecordRejected => Some(Self::RecordRejected),
            StatusWord::WalletBindingRejected => Some(Self::WalletBindingRejected),
            StatusWord::DerivationPathRejected => Some(Self::DerivationPathRejected),
            StatusWord::ChildDerivationRejected => Some(Self::ChildDerivationRejected),
            StatusWord::SigningBindingRejected => Some(Self::SigningBindingRejected),
            StatusWord::CryptographicOperationRejected => {
                Some(Self::CryptographicOperationRejected)
            }
            StatusWord::InternalIntegrityFailure => Some(Self::InternalIntegrityFailure),
        }
    }
}

impl fmt::Display for ProtocolError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.name())
    }
}

impl std::error::Error for ProtocolError {}

/// Return whether a named rejection belongs to the command's closed set.
pub const fn instruction_allows_rejection(instruction: Instruction, error: ProtocolError) -> bool {
    use ProtocolError as E;
    let framing = matches!(
        error,
        E::ContactInterfaceRequired
            | E::ClassNotSupported
            | E::InstructionNotSupported
            | E::IncorrectP1P2
            | E::WrongLength
    );
    if framing {
        return true;
    }
    match instruction {
        Instruction::Select => matches!(error, E::ModeOrOperationRejected),
        Instruction::OpenSession => matches!(
            error,
            E::ProtocolVersionMismatch
                | E::SessionStateRejected
                | E::ModeOrOperationRejected
                | E::LifecycleRejected
                | E::InternalIntegrityFailure
        ),
        Instruction::GetInfo => matches!(
            error,
            E::ProtocolVersionMismatch
                | E::SessionStateRejected
                | E::SessionIdMismatch
                | E::SequenceRejected
        ),
        Instruction::ReadDChunk | Instruction::ExportA2 => matches!(
            error,
            E::ProtocolVersionMismatch
                | E::SessionStateRejected
                | E::SessionIdMismatch
                | E::SequenceRejected
                | E::ModeOrOperationRejected
                | E::LifecycleRejected
        ),
        Instruction::SignDigest => matches!(
            error,
            E::ProtocolVersionMismatch
                | E::SessionStateRejected
                | E::SessionIdMismatch
                | E::SequenceRejected
                | E::ModeOrOperationRejected
                | E::LifecycleRejected
                | E::WalletBindingRejected
                | E::DerivationPathRejected
                | E::ChildDerivationRejected
                | E::SigningBindingRejected
                | E::CryptographicOperationRejected
        ),
        Instruction::BeginProvision | Instruction::WriteChunk => matches!(
            error,
            E::ProtocolVersionMismatch
                | E::SessionStateRejected
                | E::SessionIdMismatch
                | E::SequenceRejected
                | E::ModeOrOperationRejected
                | E::LifecycleRejected
                | E::ProvisioningOrderRejected
                | E::InternalIntegrityFailure
        ),
        Instruction::Commit => matches!(
            error,
            E::ProtocolVersionMismatch
                | E::SessionStateRejected
                | E::SessionIdMismatch
                | E::SequenceRejected
                | E::ModeOrOperationRejected
                | E::LifecycleRejected
                | E::ProvisioningOrderRejected
                | E::RecordRejected
                | E::WalletBindingRejected
                | E::CryptographicOperationRejected
                | E::InternalIntegrityFailure
        ),
        Instruction::Abort => matches!(
            error,
            E::ProtocolVersionMismatch
                | E::SessionStateRejected
                | E::SessionIdMismatch
                | E::SequenceRejected
                | E::ModeOrOperationRejected
                | E::LifecycleRejected
                | E::InternalIntegrityFailure
        ),
    }
}

/// Encoding failure before any partial output is authoritative.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum EncodeError {
    OutputBufferTooSmall,
    BodyTooLong,
    ValueOutOfRange,
}

impl EncodeError {
    pub const fn name(self) -> &'static str {
        match self {
            Self::OutputBufferTooSmall => "OutputBufferTooSmall",
            Self::BodyTooLong => "BodyTooLong",
            Self::ValueOutOfRange => "ValueOutOfRange",
        }
    }
}

impl fmt::Display for EncodeError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.name())
    }
}

impl std::error::Error for EncodeError {}

/// Named failure while decoding a hostile card response.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ResponseError {
    Truncated,
    UnknownStatusWord,
    RejectionHasBody,
    RejectionNotAllowed,
    SuccessLength,
    SuccessVersion,
    SuccessEnvelope,
    SuccessField,
}

impl ResponseError {
    pub const fn name(self) -> &'static str {
        match self {
            Self::Truncated => "ResponseTruncated",
            Self::UnknownStatusWord => "ResponseUnknownStatusWord",
            Self::RejectionHasBody => "ResponseRejectionHasBody",
            Self::RejectionNotAllowed => "ResponseRejectionNotAllowed",
            Self::SuccessLength => "ResponseSuccessLength",
            Self::SuccessVersion => "ResponseSuccessVersion",
            Self::SuccessEnvelope => "ResponseSuccessEnvelope",
            Self::SuccessField => "ResponseSuccessField",
        }
    }
}

impl fmt::Display for ResponseError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.name())
    }
}

impl std::error::Error for ResponseError {}

/// Exact post-OPEN session envelope borrowed from hostile input.
#[derive(Clone, Copy, Eq, PartialEq)]
pub struct EnvelopeRef<'a> {
    session_id: &'a [u8; 16],
    sequence: u32,
}

impl<'a> EnvelopeRef<'a> {
    pub const fn new(session_id: &'a [u8; 16], sequence: u32) -> Self {
        Self {
            session_id,
            sequence,
        }
    }

    pub const fn session_id(self) -> &'a [u8; 16] {
        self.session_id
    }

    pub const fn sequence(self) -> u32 {
        self.sequence
    }
}

impl fmt::Debug for EnvelopeRef<'_> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("EnvelopeRef(REDACTED)")
    }
}

/// Allocation-free typed view of an accepted command.
#[derive(Clone, Copy, Eq, PartialEq)]
pub enum CommandRef<'a> {
    Select,
    OpenSession {
        mode: Mode,
        session_id: &'a [u8; 16],
    },
    GetInfo {
        envelope: EnvelopeRef<'a>,
    },
    ReadDChunk {
        envelope: EnvelopeRef<'a>,
        selector: DescriptorSelector,
        offset: u16,
    },
    ExportA2 {
        envelope: EnvelopeRef<'a>,
        purpose: A2Purpose,
    },
    SignDigest {
        envelope: EnvelopeRef<'a>,
        wallet_id: &'a [u8; 32],
        review_hash: &'a [u8; 32],
        input_index: u32,
        branch: u8,
        child_index: u32,
        digest: &'a [u8; 32],
    },
    BeginProvision {
        envelope: EnvelopeRef<'a>,
        ordinal: u8,
        provisioning_nonce: &'a [u8; 12],
    },
    WriteChunk {
        envelope: EnvelopeRef<'a>,
        offset: u16,
        bytes: &'a [u8],
    },
    Commit {
        envelope: EnvelopeRef<'a>,
    },
    Abort {
        envelope: EnvelopeRef<'a>,
    },
}

impl fmt::Debug for CommandRef<'_> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("CommandRef(REDACTED)")
    }
}

/// Structurally valid APDU whose semantic fields remain unclassified.
///
/// This is a test-model seam. Product callers use [`parse_command`], which
/// additionally applies the stateless semantic checks.
#[doc(hidden)]
#[derive(Clone, Copy, Eq, PartialEq)]
pub enum RawCommandRef<'a> {
    Select,
    OpenSession {
        mode: u8,
        session_id: &'a [u8; 16],
    },
    GetInfo {
        envelope: EnvelopeRef<'a>,
    },
    ReadDChunk {
        envelope: EnvelopeRef<'a>,
        selector: u8,
        offset: u16,
    },
    ExportA2 {
        envelope: EnvelopeRef<'a>,
        purpose: u8,
    },
    SignDigest {
        envelope: EnvelopeRef<'a>,
        wallet_id: &'a [u8; 32],
        review_hash: &'a [u8; 32],
        input_index: u32,
        branch: u8,
        child_index: u32,
        digest: &'a [u8; 32],
    },
    BeginProvision {
        envelope: EnvelopeRef<'a>,
        ordinal: u8,
        provisioning_nonce: &'a [u8; 12],
    },
    WriteChunk {
        envelope: EnvelopeRef<'a>,
        offset: u16,
        bytes: &'a [u8],
    },
    Commit {
        envelope: EnvelopeRef<'a>,
    },
    Abort {
        envelope: EnvelopeRef<'a>,
    },
}

impl fmt::Debug for RawCommandRef<'_> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("RawCommandRef(REDACTED)")
    }
}

/// Allocation-free typed view of an accepted response.
#[derive(Clone, Copy, Eq, PartialEq)]
pub enum ResponseRef<'a> {
    Rejected(ProtocolError),
    Select,
    OpenSession {
        envelope: EnvelopeRef<'a>,
    },
    GetInfo {
        envelope: EnvelopeRef<'a>,
        record_version: u8,
        lifecycle: u8,
        profile: u8,
        role: u8,
        instance_id: &'a [u8; 16],
        wallet_id: &'a [u8; 32],
        origin_fingerprint: &'a [u8; 4],
        account_xpub: &'a [u8; 78],
        allowed_operations: u16,
    },
    ReadDChunk {
        envelope: EnvelopeRef<'a>,
        selector: DescriptorSelector,
        offset: u16,
        bytes: &'a [u8],
    },
    ExportA2 {
        envelope: EnvelopeRef<'a>,
        purpose: A2Purpose,
        a2: &'a [u8; 32],
    },
    SignDigest {
        envelope: EnvelopeRef<'a>,
        review_hash: &'a [u8; 32],
        input_index: u32,
        public_key: &'a [u8; 33],
        signature_der: &'a [u8],
    },
    BeginProvision {
        envelope: EnvelopeRef<'a>,
    },
    WriteChunk {
        envelope: EnvelopeRef<'a>,
        next_offset: u16,
    },
    Commit {
        envelope: EnvelopeRef<'a>,
    },
    Abort {
        envelope: EnvelopeRef<'a>,
    },
}

impl fmt::Debug for ResponseRef<'_> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("ResponseRef(REDACTED)")
    }
}

impl<'a> CommandRef<'a> {
    pub const fn instruction(self) -> Instruction {
        match self {
            Self::Select => Instruction::Select,
            Self::OpenSession { .. } => Instruction::OpenSession,
            Self::GetInfo { .. } => Instruction::GetInfo,
            Self::ReadDChunk { .. } => Instruction::ReadDChunk,
            Self::ExportA2 { .. } => Instruction::ExportA2,
            Self::SignDigest { .. } => Instruction::SignDigest,
            Self::BeginProvision { .. } => Instruction::BeginProvision,
            Self::WriteChunk { .. } => Instruction::WriteChunk,
            Self::Commit { .. } => Instruction::Commit,
            Self::Abort { .. } => Instruction::Abort,
        }
    }

    pub const fn envelope(self) -> Option<EnvelopeRef<'a>> {
        match self {
            Self::Select | Self::OpenSession { .. } => None,
            Self::GetInfo { envelope }
            | Self::ReadDChunk { envelope, .. }
            | Self::ExportA2 { envelope, .. }
            | Self::SignDigest { envelope, .. }
            | Self::BeginProvision { envelope, .. }
            | Self::WriteChunk { envelope, .. }
            | Self::Commit { envelope }
            | Self::Abort { envelope } => Some(envelope),
        }
    }
}

impl<'a> RawCommandRef<'a> {
    #[cfg(feature = "model-raw-apdu")]
    pub const fn instruction(self) -> Instruction {
        match self {
            Self::Select => Instruction::Select,
            Self::OpenSession { .. } => Instruction::OpenSession,
            Self::GetInfo { .. } => Instruction::GetInfo,
            Self::ReadDChunk { .. } => Instruction::ReadDChunk,
            Self::ExportA2 { .. } => Instruction::ExportA2,
            Self::SignDigest { .. } => Instruction::SignDigest,
            Self::BeginProvision { .. } => Instruction::BeginProvision,
            Self::WriteChunk { .. } => Instruction::WriteChunk,
            Self::Commit { .. } => Instruction::Commit,
            Self::Abort { .. } => Instruction::Abort,
        }
    }

    pub const fn envelope(self) -> Option<EnvelopeRef<'a>> {
        match self {
            Self::Select | Self::OpenSession { .. } => None,
            Self::GetInfo { envelope }
            | Self::ReadDChunk { envelope, .. }
            | Self::ExportA2 { envelope, .. }
            | Self::SignDigest { envelope, .. }
            | Self::BeginProvision { envelope, .. }
            | Self::WriteChunk { envelope, .. }
            | Self::Commit { envelope }
            | Self::Abort { envelope } => Some(envelope),
        }
    }

    fn validate_semantics(self) -> Result<CommandRef<'a>, ProtocolError> {
        if self
            .envelope()
            .is_some_and(|envelope| envelope.sequence() == 0)
        {
            return Err(ProtocolError::SequenceRejected);
        }
        match self {
            Self::Select => Ok(CommandRef::Select),
            Self::OpenSession { mode, session_id } => Ok(CommandRef::OpenSession {
                mode: Mode::from_byte(mode).ok_or(ProtocolError::ModeOrOperationRejected)?,
                session_id,
            }),
            Self::GetInfo { envelope } => Ok(CommandRef::GetInfo { envelope }),
            Self::ReadDChunk {
                envelope,
                selector,
                offset,
            } => {
                let selector = DescriptorSelector::from_byte(selector)
                    .ok_or(ProtocolError::ModeOrOperationRejected)?;
                if !matches!(offset, 0 | 192) {
                    return Err(ProtocolError::ModeOrOperationRejected);
                }
                Ok(CommandRef::ReadDChunk {
                    envelope,
                    selector,
                    offset,
                })
            }
            Self::ExportA2 { envelope, purpose } => Ok(CommandRef::ExportA2 {
                envelope,
                purpose: A2Purpose::from_byte(purpose)
                    .ok_or(ProtocolError::ModeOrOperationRejected)?,
            }),
            Self::SignDigest {
                envelope,
                wallet_id,
                review_hash,
                input_index,
                branch,
                child_index,
                digest,
            } => {
                if branch > 1 || child_index > MAX_CHILD_INDEX {
                    return Err(ProtocolError::DerivationPathRejected);
                }
                Ok(CommandRef::SignDigest {
                    envelope,
                    wallet_id,
                    review_hash,
                    input_index,
                    branch,
                    child_index,
                    digest,
                })
            }
            Self::BeginProvision {
                envelope,
                ordinal,
                provisioning_nonce,
            } => {
                if !matches!(ordinal, 1..=3) {
                    return Err(ProtocolError::ProvisioningOrderRejected);
                }
                Ok(CommandRef::BeginProvision {
                    envelope,
                    ordinal,
                    provisioning_nonce,
                })
            }
            Self::WriteChunk {
                envelope,
                offset,
                bytes,
            } => {
                if !matches!(
                    (offset, bytes.len()),
                    (0 | 192 | 384 | 576, MAX_WRITE_CHUNK_BYTES) | (768, 13)
                ) {
                    return Err(ProtocolError::ProvisioningOrderRejected);
                }
                Ok(CommandRef::WriteChunk {
                    envelope,
                    offset,
                    bytes,
                })
            }
            Self::Commit { envelope } => Ok(CommandRef::Commit { envelope }),
            Self::Abort { envelope } => Ok(CommandRef::Abort { envelope }),
        }
    }
}

fn array_ref<const N: usize>(bytes: &[u8]) -> Result<&[u8; N], ProtocolError> {
    bytes.try_into().map_err(|_| ProtocolError::WrongLength)
}

fn parse_structural_envelope(data: &[u8]) -> Result<(EnvelopeRef<'_>, &[u8]), ProtocolError> {
    if data.len() < ENVELOPE_BYTES {
        return Err(ProtocolError::WrongLength);
    }
    if data[0] != PROTOCOL_VERSION {
        return Err(ProtocolError::ProtocolVersionMismatch);
    }
    let session_id = array_ref(&data[1..17])?;
    let sequence = u32::from_be_bytes(array_ref::<4>(&data[17..21])?.to_owned());
    Ok((EnvelopeRef::new(session_id, sequence), &data[21..]))
}

fn parse_response_envelope(data: &[u8]) -> Result<(EnvelopeRef<'_>, &[u8]), ResponseError> {
    if data.len() < ENVELOPE_BYTES {
        return Err(ResponseError::SuccessLength);
    }
    if data[0] != PROTOCOL_VERSION {
        return Err(ResponseError::SuccessVersion);
    }
    let session_id = data[1..17]
        .try_into()
        .map_err(|_| ResponseError::SuccessLength)?;
    let sequence = u32::from_be_bytes(
        data[17..21]
            .try_into()
            .map_err(|_| ResponseError::SuccessLength)?,
    );
    if sequence == 0 {
        return Err(ResponseError::SuccessEnvelope);
    }
    Ok((EnvelopeRef::new(session_id, sequence), &data[21..]))
}

/// Parse an exact response for the expected request instruction.
pub fn parse_response(
    expected: Instruction,
    response: &[u8],
) -> Result<ResponseRef<'_>, ResponseError> {
    if response.len() < 2 {
        return Err(ResponseError::Truncated);
    }
    let body_length = response.len() - 2;
    let status = StatusWord::from_value(u16::from_be_bytes([
        response[body_length],
        response[body_length + 1],
    ]))
    .ok_or(ResponseError::UnknownStatusWord)?;
    if status != StatusWord::Success {
        if body_length != 0 {
            return Err(ResponseError::RejectionHasBody);
        }
        let error =
            ProtocolError::from_status_word(status).ok_or(ResponseError::UnknownStatusWord)?;
        if !instruction_allows_rejection(expected, error) {
            return Err(ResponseError::RejectionNotAllowed);
        }
        return Ok(ResponseRef::Rejected(error));
    }
    let body = &response[..body_length];
    if expected == Instruction::Select {
        return if body.is_empty() {
            Ok(ResponseRef::Select)
        } else {
            Err(ResponseError::SuccessLength)
        };
    }
    if expected == Instruction::OpenSession {
        if body.len() != ENVELOPE_BYTES {
            return Err(ResponseError::SuccessLength);
        }
        if body[0] != PROTOCOL_VERSION {
            return Err(ResponseError::SuccessVersion);
        }
        if body[17..21] != [0, 0, 0, 0] {
            return Err(ResponseError::SuccessEnvelope);
        }
        let session_id = body[1..17]
            .try_into()
            .map_err(|_| ResponseError::SuccessLength)?;
        return Ok(ResponseRef::OpenSession {
            envelope: EnvelopeRef::new(session_id, 0),
        });
    }
    let (envelope, tail) = parse_response_envelope(body)?;
    match expected {
        Instruction::GetInfo => parse_info_response(envelope, tail),
        Instruction::ReadDChunk => parse_read_response(envelope, tail),
        Instruction::ExportA2 => parse_a2_response(envelope, tail),
        Instruction::SignDigest => parse_sign_response(envelope, tail),
        Instruction::BeginProvision => {
            require_empty_tail(tail)?;
            Ok(ResponseRef::BeginProvision { envelope })
        }
        Instruction::WriteChunk => {
            if tail.len() != 2 {
                return Err(ResponseError::SuccessLength);
            }
            let next_offset = u16::from_be_bytes([tail[0], tail[1]]);
            if !matches!(next_offset, 192 | 384 | 576 | 768 | 781) {
                return Err(ResponseError::SuccessField);
            }
            Ok(ResponseRef::WriteChunk {
                envelope,
                next_offset,
            })
        }
        Instruction::Commit => {
            require_empty_tail(tail)?;
            Ok(ResponseRef::Commit { envelope })
        }
        Instruction::Abort => {
            require_empty_tail(tail)?;
            Ok(ResponseRef::Abort { envelope })
        }
        Instruction::Select | Instruction::OpenSession => Err(ResponseError::SuccessField),
    }
}

fn require_empty_tail(tail: &[u8]) -> Result<(), ResponseError> {
    if tail.is_empty() {
        Ok(())
    } else {
        Err(ResponseError::SuccessLength)
    }
}

fn parse_info_response<'a>(
    envelope: EnvelopeRef<'a>,
    tail: &'a [u8],
) -> Result<ResponseRef<'a>, ResponseError> {
    if tail.len() != 137 {
        return Err(ResponseError::SuccessLength);
    }
    if tail[0] != PROTOCOL_VERSION {
        return Err(ResponseError::SuccessVersion);
    }
    if tail[1] != crate::RECORD_VERSION {
        return Err(ResponseError::SuccessField);
    }
    let lifecycle = tail[2];
    if !matches!(lifecycle, 0x00 | 0x01 | 0x02 | 0xff) {
        return Err(ResponseError::SuccessField);
    }
    let profile = tail[3];
    if lifecycle == 0x02 {
        if Profile::from_byte(profile).is_none() {
            return Err(ResponseError::SuccessField);
        }
    } else if profile != 0 || tail[5..135].iter().any(|byte| *byte != 0) {
        return Err(ResponseError::SuccessField);
    }
    if tail[4] != crate::ROLE_KEY_CARD_B {
        return Err(ResponseError::SuccessField);
    }
    let operations = u16::from_be_bytes([tail[135], tail[136]]);
    let coherent_operations = match lifecycle {
        0x00 => operations == 0x0011,
        0x01 => matches!(operations, 0x00b1 | 0x00d1),
        0x02 => matches!(operations, 0x0003 | 0x0007 | 0x000f),
        0xff => operations == 0x0001,
        _ => false,
    };
    if !coherent_operations {
        return Err(ResponseError::SuccessField);
    }
    if lifecycle == 0x02 && !raw_account_xpub_is_structural(&tail[57..135]) {
        return Err(ResponseError::SuccessField);
    }
    Ok(ResponseRef::GetInfo {
        envelope,
        record_version: tail[1],
        lifecycle,
        profile,
        role: tail[4],
        instance_id: tail[5..21]
            .try_into()
            .map_err(|_| ResponseError::SuccessLength)?,
        wallet_id: tail[21..53]
            .try_into()
            .map_err(|_| ResponseError::SuccessLength)?,
        origin_fingerprint: tail[53..57]
            .try_into()
            .map_err(|_| ResponseError::SuccessLength)?,
        account_xpub: tail[57..135]
            .try_into()
            .map_err(|_| ResponseError::SuccessLength)?,
        allowed_operations: operations,
    })
}

fn raw_account_xpub_is_structural(bytes: &[u8]) -> bool {
    bytes.len() == crate::RAW_XPUB_BYTES
        && bytes[0..4] == [0x04, 0x88, 0xb2, 0x1e]
        && bytes[4] == 4
        && bytes[9..13] == [0x80, 0x00, 0x00, 0x02]
        && matches!(bytes[45], 0x02 | 0x03)
}

fn parse_read_response<'a>(
    envelope: EnvelopeRef<'a>,
    tail: &'a [u8],
) -> Result<ResponseRef<'a>, ResponseError> {
    if tail.len() < 3 {
        return Err(ResponseError::SuccessLength);
    }
    let selector = DescriptorSelector::from_byte(tail[0]).ok_or(ResponseError::SuccessField)?;
    let offset = u16::from_be_bytes([tail[1], tail[2]]);
    let expected_chunk = match offset {
        0 => 192,
        192 => 114,
        _ => return Err(ResponseError::SuccessField),
    };
    if tail.len() != 3 + expected_chunk {
        return Err(ResponseError::SuccessLength);
    }
    Ok(ResponseRef::ReadDChunk {
        envelope,
        selector,
        offset,
        bytes: &tail[3..],
    })
}

fn parse_a2_response<'a>(
    envelope: EnvelopeRef<'a>,
    tail: &'a [u8],
) -> Result<ResponseRef<'a>, ResponseError> {
    if tail.len() != 33 {
        return Err(ResponseError::SuccessLength);
    }
    let purpose = A2Purpose::from_byte(tail[0]).ok_or(ResponseError::SuccessField)?;
    Ok(ResponseRef::ExportA2 {
        envelope,
        purpose,
        a2: tail[1..33]
            .try_into()
            .map_err(|_| ResponseError::SuccessLength)?,
    })
}

fn parse_sign_response<'a>(
    envelope: EnvelopeRef<'a>,
    tail: &'a [u8],
) -> Result<ResponseRef<'a>, ResponseError> {
    if tail.len() < 32 + 4 + 33 + 1 + 8 {
        return Err(ResponseError::SuccessLength);
    }
    if tail[36] != 0x02 && tail[36] != 0x03 {
        return Err(ResponseError::SuccessField);
    }
    let der_length = usize::from(tail[69]);
    if !(8..=72).contains(&der_length) || tail.len() != 70 + der_length {
        return Err(ResponseError::SuccessLength);
    }
    Ok(ResponseRef::SignDigest {
        envelope,
        review_hash: tail[0..32]
            .try_into()
            .map_err(|_| ResponseError::SuccessLength)?,
        input_index: u32::from_be_bytes(
            tail[32..36]
                .try_into()
                .map_err(|_| ResponseError::SuccessLength)?,
        ),
        public_key: tail[36..69]
            .try_into()
            .map_err(|_| ResponseError::SuccessLength)?,
        signature_der: &tail[70..],
    })
}

fn parse_case4(command: &[u8]) -> Result<&[u8], ProtocolError> {
    if command.len() < 6 {
        return Err(ProtocolError::WrongLength);
    }
    let body_length = usize::from(command[4]);
    let expected = 6usize
        .checked_add(body_length)
        .ok_or(ProtocolError::WrongLength)?;
    if expected != command.len() || command[command.len() - 1] != 0 {
        return Err(ProtocolError::WrongLength);
    }
    Ok(&command[5..5 + body_length])
}

/// Parse one hostile APDU through the structural rejection layers only.
///
/// Semantic fields intentionally remain raw so the stateful HOST model can
/// apply session, identity and sequence checks before later semantic checks.
#[doc(hidden)]
pub fn parse_structural_command(
    media: Media,
    command: &[u8],
) -> Result<RawCommandRef<'_>, ProtocolError> {
    if media != Media::ContactT1 {
        return Err(ProtocolError::ContactInterfaceRequired);
    }
    let cla = *command.first().ok_or(ProtocolError::WrongLength)?;
    if cla != SELECT_CLA && cla != PROPRIETARY_CLA {
        return Err(ProtocolError::ClassNotSupported);
    }
    let instruction_byte = *command.get(1).ok_or(ProtocolError::WrongLength)?;
    let instruction =
        Instruction::from_byte(instruction_byte).ok_or(ProtocolError::InstructionNotSupported)?;
    let required_cla = if instruction == Instruction::Select {
        SELECT_CLA
    } else {
        PROPRIETARY_CLA
    };
    if cla != required_cla {
        return Err(ProtocolError::ClassNotSupported);
    }
    let p1 = *command.get(2).ok_or(ProtocolError::WrongLength)?;
    let p2 = *command.get(3).ok_or(ProtocolError::WrongLength)?;
    let valid_parameters = if instruction == Instruction::Select {
        p1 == 0x04 && p2 == 0x00
    } else {
        p1 == 0 && p2 == 0
    };
    if !valid_parameters {
        return Err(ProtocolError::IncorrectP1P2);
    }
    let data = parse_case4(command)?;
    if instruction == Instruction::Select {
        if data.len() != APPLET_AID.len() {
            return Err(ProtocolError::WrongLength);
        }
        if data != APPLET_AID {
            return Err(ProtocolError::ModeOrOperationRejected);
        }
        return Ok(RawCommandRef::Select);
    }

    match instruction {
        Instruction::OpenSession => {
            if data.len() != 18 {
                return Err(ProtocolError::WrongLength);
            }
            if data[0] != PROTOCOL_VERSION {
                return Err(ProtocolError::ProtocolVersionMismatch);
            }
            Ok(RawCommandRef::OpenSession {
                mode: data[1],
                session_id: array_ref(&data[2..18])?,
            })
        }
        Instruction::GetInfo => {
            if data.len() != ENVELOPE_BYTES {
                return Err(ProtocolError::WrongLength);
            }
            let (envelope, tail) = parse_structural_envelope(data)?;
            debug_assert!(tail.is_empty());
            Ok(RawCommandRef::GetInfo { envelope })
        }
        Instruction::ReadDChunk => {
            if data.len() != ENVELOPE_BYTES + 3 {
                return Err(ProtocolError::WrongLength);
            }
            let (envelope, tail) = parse_structural_envelope(data)?;
            debug_assert_eq!(tail.len(), 3);
            let offset = u16::from_be_bytes(array_ref::<2>(&tail[1..3])?.to_owned());
            Ok(RawCommandRef::ReadDChunk {
                envelope,
                selector: tail[0],
                offset,
            })
        }
        Instruction::ExportA2 => {
            if data.len() != ENVELOPE_BYTES + 1 {
                return Err(ProtocolError::WrongLength);
            }
            let (envelope, tail) = parse_structural_envelope(data)?;
            debug_assert_eq!(tail.len(), 1);
            Ok(RawCommandRef::ExportA2 {
                envelope,
                purpose: tail[0],
            })
        }
        Instruction::SignDigest => {
            if data.len() != ENVELOPE_BYTES + 105 {
                return Err(ProtocolError::WrongLength);
            }
            let (envelope, tail) = parse_structural_envelope(data)?;
            debug_assert_eq!(tail.len(), 105);
            let branch = tail[68];
            let child_index = u32::from_be_bytes(array_ref::<4>(&tail[69..73])?.to_owned());
            Ok(RawCommandRef::SignDigest {
                envelope,
                wallet_id: array_ref(&tail[0..32])?,
                review_hash: array_ref(&tail[32..64])?,
                input_index: u32::from_be_bytes(array_ref::<4>(&tail[64..68])?.to_owned()),
                branch,
                child_index,
                digest: array_ref(&tail[73..105])?,
            })
        }
        Instruction::BeginProvision => {
            if data.len() != ENVELOPE_BYTES + 13 {
                return Err(ProtocolError::WrongLength);
            }
            let (envelope, tail) = parse_structural_envelope(data)?;
            debug_assert_eq!(tail.len(), 13);
            Ok(RawCommandRef::BeginProvision {
                envelope,
                ordinal: tail[0],
                provisioning_nonce: array_ref(&tail[1..13])?,
            })
        }
        Instruction::WriteChunk => {
            if !matches!(data.len(), 36 | 215) {
                return Err(ProtocolError::WrongLength);
            }
            let (envelope, tail) = parse_structural_envelope(data)?;
            debug_assert!(matches!(tail.len(), 15 | 194));
            let offset = u16::from_be_bytes(array_ref::<2>(&tail[0..2])?.to_owned());
            let bytes = &tail[2..];
            Ok(RawCommandRef::WriteChunk {
                envelope,
                offset,
                bytes,
            })
        }
        Instruction::Commit => {
            if data.len() != ENVELOPE_BYTES {
                return Err(ProtocolError::WrongLength);
            }
            let (envelope, tail) = parse_structural_envelope(data)?;
            debug_assert!(tail.is_empty());
            Ok(RawCommandRef::Commit { envelope })
        }
        Instruction::Abort => {
            if data.len() != ENVELOPE_BYTES {
                return Err(ProtocolError::WrongLength);
            }
            let (envelope, tail) = parse_structural_envelope(data)?;
            debug_assert!(tail.is_empty());
            Ok(RawCommandRef::Abort { envelope })
        }
        Instruction::Select => unreachable!("SELECT returned before proprietary dispatch"),
    }
}

/// Parse one hostile APDU according to the ratified stateless semantics.
pub fn parse_command(media: Media, command: &[u8]) -> Result<CommandRef<'_>, ProtocolError> {
    parse_structural_command(media, command)?.validate_semantics()
}

fn encode_case4(
    cla: u8,
    instruction: Instruction,
    p1: u8,
    p2: u8,
    data: &[u8],
    output: &mut [u8],
) -> Result<usize, EncodeError> {
    let length = u8::try_from(data.len()).map_err(|_| EncodeError::BodyTooLong)?;
    let total = data.len().checked_add(6).ok_or(EncodeError::BodyTooLong)?;
    if total > MAX_REQUEST_BYTES && instruction != Instruction::Select {
        return Err(EncodeError::BodyTooLong);
    }
    if output.len() < total {
        return Err(EncodeError::OutputBufferTooSmall);
    }
    output[0] = cla;
    output[1] = instruction.byte();
    output[2] = p1;
    output[3] = p2;
    output[4] = length;
    output[5..5 + data.len()].copy_from_slice(data);
    output[total - 1] = 0;
    Ok(total)
}

fn put_envelope(envelope: EnvelopeRef<'_>, output: &mut [u8]) {
    output[0] = PROTOCOL_VERSION;
    output[1..17].copy_from_slice(envelope.session_id());
    output[17..21].copy_from_slice(&envelope.sequence().to_be_bytes());
}

fn encode_proprietary(
    instruction: Instruction,
    envelope: EnvelopeRef<'_>,
    tail: &[u8],
    output: &mut [u8],
) -> Result<usize, EncodeError> {
    let body_length = ENVELOPE_BYTES
        .checked_add(tail.len())
        .ok_or(EncodeError::BodyTooLong)?;
    if body_length > u8::MAX as usize {
        return Err(EncodeError::BodyTooLong);
    }
    let mut body = crate::wipe::WipingArray::<215>::zeroed();
    if body_length > body.as_slice().len() {
        return Err(EncodeError::BodyTooLong);
    }
    put_envelope(envelope, &mut body.as_mut_slice()[..ENVELOPE_BYTES]);
    body.as_mut_slice()[ENVELOPE_BYTES..body_length].copy_from_slice(tail);
    encode_case4(
        PROPRIETARY_CLA,
        instruction,
        0,
        0,
        &body.as_slice()[..body_length],
        output,
    )
}

/// Encode the exact SELECT command.
pub fn encode_select(output: &mut [u8]) -> Result<usize, EncodeError> {
    encode_case4(
        SELECT_CLA,
        Instruction::Select,
        0x04,
        0,
        &APPLET_AID,
        output,
    )
}

/// Encode OPEN_SESSION.
pub fn encode_open_session(
    mode: Mode,
    session_id: &[u8; 16],
    output: &mut [u8],
) -> Result<usize, EncodeError> {
    let mut body = crate::wipe::WipingArray::<18>::zeroed();
    body.as_mut_slice()[0] = PROTOCOL_VERSION;
    body.as_mut_slice()[1] = mode.byte();
    body.as_mut_slice()[2..18].copy_from_slice(session_id);
    encode_case4(
        PROPRIETARY_CLA,
        Instruction::OpenSession,
        0,
        0,
        body.as_slice(),
        output,
    )
}

pub fn encode_get_info(envelope: EnvelopeRef<'_>, output: &mut [u8]) -> Result<usize, EncodeError> {
    encode_proprietary(Instruction::GetInfo, envelope, &[], output)
}

pub fn encode_read_d_chunk(
    envelope: EnvelopeRef<'_>,
    selector: DescriptorSelector,
    offset: u16,
    output: &mut [u8],
) -> Result<usize, EncodeError> {
    if !matches!(offset, 0 | 192) {
        return Err(EncodeError::ValueOutOfRange);
    }
    let mut tail = crate::wipe::WipingArray::<3>::zeroed();
    tail.as_mut_slice()[0] = selector.byte();
    tail.as_mut_slice()[1..3].copy_from_slice(&offset.to_be_bytes());
    encode_proprietary(Instruction::ReadDChunk, envelope, tail.as_slice(), output)
}

pub fn encode_export_a2(
    envelope: EnvelopeRef<'_>,
    purpose: A2Purpose,
    output: &mut [u8],
) -> Result<usize, EncodeError> {
    encode_proprietary(Instruction::ExportA2, envelope, &[purpose.byte()], output)
}

/// Fields for one SIGN_DIGEST request.
#[derive(Clone, Copy, Eq, PartialEq)]
pub struct SignRequest<'a> {
    pub wallet_id: &'a [u8; 32],
    pub review_hash: &'a [u8; 32],
    pub input_index: u32,
    pub branch: u8,
    pub child_index: u32,
    pub digest: &'a [u8; 32],
}

impl fmt::Debug for SignRequest<'_> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("SignRequest(REDACTED)")
    }
}

pub fn encode_sign_digest(
    envelope: EnvelopeRef<'_>,
    request: SignRequest<'_>,
    output: &mut [u8],
) -> Result<usize, EncodeError> {
    if request.branch > 1 || request.child_index > MAX_CHILD_INDEX {
        return Err(EncodeError::ValueOutOfRange);
    }
    let mut tail = crate::wipe::WipingArray::<105>::zeroed();
    tail.as_mut_slice()[0..32].copy_from_slice(request.wallet_id);
    tail.as_mut_slice()[32..64].copy_from_slice(request.review_hash);
    tail.as_mut_slice()[64..68].copy_from_slice(&request.input_index.to_be_bytes());
    tail.as_mut_slice()[68] = request.branch;
    tail.as_mut_slice()[69..73].copy_from_slice(&request.child_index.to_be_bytes());
    tail.as_mut_slice()[73..105].copy_from_slice(request.digest);
    encode_proprietary(Instruction::SignDigest, envelope, tail.as_slice(), output)
}

pub fn encode_begin_provision(
    envelope: EnvelopeRef<'_>,
    ordinal: u8,
    provisioning_nonce: &[u8; 12],
    output: &mut [u8],
) -> Result<usize, EncodeError> {
    if !matches!(ordinal, 1..=3) {
        return Err(EncodeError::ValueOutOfRange);
    }
    let mut tail = crate::wipe::WipingArray::<13>::zeroed();
    tail.as_mut_slice()[0] = ordinal;
    tail.as_mut_slice()[1..13].copy_from_slice(provisioning_nonce);
    encode_proprietary(
        Instruction::BeginProvision,
        envelope,
        tail.as_slice(),
        output,
    )
}

pub fn encode_write_chunk(
    envelope: EnvelopeRef<'_>,
    offset: u16,
    bytes: &[u8],
    output: &mut [u8],
) -> Result<usize, EncodeError> {
    if !matches!(
        (offset, bytes.len()),
        (0 | 192 | 384 | 576, MAX_WRITE_CHUNK_BYTES) | (768, 13)
    ) {
        return Err(EncodeError::ValueOutOfRange);
    }
    let mut tail = crate::wipe::WipingArray::<{ 2 + MAX_WRITE_CHUNK_BYTES }>::zeroed();
    tail.as_mut_slice()[0..2].copy_from_slice(&offset.to_be_bytes());
    tail.as_mut_slice()[2..2 + bytes.len()].copy_from_slice(bytes);
    encode_proprietary(
        Instruction::WriteChunk,
        envelope,
        &tail.as_slice()[..2 + bytes.len()],
        output,
    )
}

pub fn encode_commit(envelope: EnvelopeRef<'_>, output: &mut [u8]) -> Result<usize, EncodeError> {
    encode_proprietary(Instruction::Commit, envelope, &[], output)
}

pub fn encode_abort(envelope: EnvelopeRef<'_>, output: &mut [u8]) -> Result<usize, EncodeError> {
    encode_proprietary(Instruction::Abort, envelope, &[], output)
}

/// Encode one exact successful response, optionally prepending an envelope.
pub fn encode_success(
    envelope: Option<EnvelopeRef<'_>>,
    tail: &[u8],
    output: &mut [u8],
) -> Result<usize, EncodeError> {
    let envelope_length = if envelope.is_some() {
        ENVELOPE_BYTES
    } else {
        0
    };
    let body_length = envelope_length
        .checked_add(tail.len())
        .ok_or(EncodeError::BodyTooLong)?;
    let total = body_length.checked_add(2).ok_or(EncodeError::BodyTooLong)?;
    if total > MAX_RESPONSE_BYTES {
        return Err(EncodeError::BodyTooLong);
    }
    if output.len() < total {
        return Err(EncodeError::OutputBufferTooSmall);
    }
    if let Some(value) = envelope {
        put_envelope(value, &mut output[..ENVELOPE_BYTES]);
    }
    output[envelope_length..body_length].copy_from_slice(tail);
    output[body_length..total].copy_from_slice(&StatusWord::Success.bytes());
    Ok(total)
}

/// Encode an exact bodyless named rejection.
pub fn encode_rejection(error: ProtocolError, output: &mut [u8]) -> Result<usize, EncodeError> {
    if output.len() < 2 {
        return Err(EncodeError::OutputBufferTooSmall);
    }
    output[..2].copy_from_slice(&error.status_word().bytes());
    Ok(2)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn status_round_trip_is_closed() {
        for value in [
            0x9000, 0x6700, 0x6a86, 0x6d00, 0x6e00, 0x6f01, 0x6f02, 0x6f03, 0x6f04, 0x6f05, 0x6f06,
            0x6f07, 0x6f08, 0x6f09, 0x6f0a, 0x6f0b, 0x6f0c, 0x6f0d, 0x6f0e, 0x6f0f,
        ] {
            let status = StatusWord::from_value(value).expect("registered status");
            assert_eq!(status.value(), value);
        }
        assert_eq!(StatusWord::from_value(0x6f10), None);
    }
}
