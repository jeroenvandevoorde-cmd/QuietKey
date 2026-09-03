//! Exact QKDV header, complete-frame codec, and borrowed body grammars.

use crate::{
    DeviceError, HEADER_BYTES, MAGIC, MAX_BODY_BYTES, MAX_CARD_APDU_REQUEST_BODY_BYTES,
    MAX_CARD_APDU_RESPONSE_BODY_BYTES, MAX_CARD_FACTOR_BODY_BYTES, MAX_CHUNK_BODY_BYTES,
    MAX_DISPLAY_BODY_BYTES, MAX_FILENAME_BYTES, MAX_FRAME_BYTES, MAX_KEYPAD_BODY_BYTES,
    MAX_OUTPUT_BEGIN_BODY_BYTES, VERSION,
};

const MAX_TRANSFER_BYTES: usize = 2_097_152;
const MAX_BBQR_PART_BYTES: u16 = 2_680;
const A1_BYTES: u32 = 67;
const KIT_BYTES: u32 = 142;
const A1_PRINT_BYTES: u32 = 67;
const KIT_PRINT_BYTES: u32 = 829;
#[cfg(feature = "legacy-normal-factor-fixture")]
const MAX_SIGNATURES: usize = 100;
#[cfg(feature = "legacy-normal-factor-fixture")]
const MIN_DER_BYTES: usize = 8;
#[cfg(feature = "legacy-normal-factor-fixture")]
const MAX_DER_BYTES: usize = 72;
const DESCRIPTOR_BYTES: usize = 306;
const WALLET_ID_BYTES: usize = 32;
const ACCOUNT_XPUB_BYTES: usize = 111;
const A2_BYTES: usize = 32;
#[cfg(feature = "legacy-normal-factor-fixture")]
const CARD_FACTOR_PREFIX_BYTES: usize =
    2 * DESCRIPTOR_BYTES + WALLET_ID_BYTES + ACCOUNT_XPUB_BYTES + A2_BYTES + 2;
const FEE_POLICY: &[u8] = b"QK-FEE-POLICY-V2";

/// Exact inherited-descriptor identity.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Capability {
    Display,
    Keypad,
    CardResponse,
    CardRequest,
    CameraInput,
    MediaInput,
    PrintOutput,
    MediaOutput,
}

impl Capability {
    pub const fn wire_value(self) -> u8 {
        match self {
            Self::Display => 0x01,
            Self::Keypad => 0x02,
            Self::CardResponse => 0x03,
            Self::CardRequest => 0x04,
            Self::CameraInput => 0x05,
            Self::MediaInput => 0x06,
            Self::PrintOutput => 0x07,
            Self::MediaOutput => 0x08,
        }
    }

    fn parse(value: u8) -> Result<Self, DeviceError> {
        match value {
            0x01 => Ok(Self::Display),
            0x02 => Ok(Self::Keypad),
            0x03 => Ok(Self::CardResponse),
            0x04 => Ok(Self::CardRequest),
            0x05 => Ok(Self::CameraInput),
            0x06 => Ok(Self::MediaInput),
            0x07 => Ok(Self::PrintOutput),
            0x08 => Ok(Self::MediaOutput),
            _ => Err(DeviceError::CapabilityOutOfRange),
        }
    }
}

/// Capability-bound message kind.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum MessageKind {
    DisplayStage,
    DisplayProfile,
    DisplayReview,
    DisplayResult,
    KeypadEvent,
    CardProfile,
    CardNormalFactor,
    CardApduResponse,
    CardRejected,
    CardReadProfile,
    CardReadNormalFactor,
    CardApduRequest,
    CameraBegin,
    CameraChunk,
    MediaReadBegin,
    MediaReadChunk,
    MediaBeginAccepted,
    MediaChunkAccepted,
    MediaFinished,
    MediaRejected,
    PrintWriteBegin,
    PrintWriteChunk,
    PrintWriteFinish,
    MediaWriteBegin,
    MediaWriteChunk,
    MediaWriteFinish,
}

impl MessageKind {
    pub const fn capability(self) -> Capability {
        match self {
            Self::DisplayStage
            | Self::DisplayProfile
            | Self::DisplayReview
            | Self::DisplayResult => Capability::Display,
            Self::KeypadEvent => Capability::Keypad,
            Self::CardProfile
            | Self::CardNormalFactor
            | Self::CardApduResponse
            | Self::CardRejected => Capability::CardResponse,
            Self::CardReadProfile | Self::CardReadNormalFactor | Self::CardApduRequest => {
                Capability::CardRequest
            }
            Self::CameraBegin | Self::CameraChunk => Capability::CameraInput,
            Self::MediaReadBegin
            | Self::MediaReadChunk
            | Self::MediaBeginAccepted
            | Self::MediaChunkAccepted
            | Self::MediaFinished
            | Self::MediaRejected => Capability::MediaInput,
            Self::PrintWriteBegin | Self::PrintWriteChunk | Self::PrintWriteFinish => {
                Capability::PrintOutput
            }
            Self::MediaWriteBegin | Self::MediaWriteChunk | Self::MediaWriteFinish => {
                Capability::MediaOutput
            }
        }
    }

    pub const fn wire_value(self) -> u8 {
        match self {
            Self::DisplayStage
            | Self::KeypadEvent
            | Self::CardReadProfile
            | Self::CameraBegin
            | Self::MediaReadBegin
            | Self::PrintWriteBegin
            | Self::MediaWriteBegin => 0x01,
            Self::DisplayProfile
            | Self::CardReadNormalFactor
            | Self::CameraChunk
            | Self::MediaReadChunk
            | Self::PrintWriteChunk
            | Self::MediaWriteChunk => 0x02,
            Self::DisplayReview
            | Self::CardApduRequest
            | Self::PrintWriteFinish
            | Self::MediaWriteFinish => 0x03,
            Self::DisplayResult => 0x04,
            Self::CardProfile | Self::MediaBeginAccepted => 0x81,
            Self::CardNormalFactor | Self::MediaChunkAccepted => 0x82,
            Self::CardApduResponse | Self::MediaFinished => 0x83,
            Self::CardRejected | Self::MediaRejected => 0xff,
        }
    }

    pub const fn body_cap(self) -> usize {
        match self {
            Self::DisplayStage | Self::DisplayProfile => 1,
            Self::DisplayReview | Self::DisplayResult => MAX_DISPLAY_BODY_BYTES,
            Self::KeypadEvent => MAX_KEYPAD_BODY_BYTES,
            Self::CardProfile => 1,
            Self::CardNormalFactor => MAX_CARD_FACTOR_BODY_BYTES,
            Self::CardApduResponse => MAX_CARD_APDU_RESPONSE_BODY_BYTES,
            Self::CardRejected | Self::MediaRejected => 3,
            Self::CardReadProfile | Self::CardReadNormalFactor => 0,
            Self::CardApduRequest => MAX_CARD_APDU_REQUEST_BODY_BYTES,
            Self::CameraBegin => 5,
            Self::MediaReadBegin => 71,
            Self::CameraChunk | Self::MediaReadChunk => MAX_CHUNK_BODY_BYTES,
            Self::MediaBeginAccepted | Self::MediaFinished => 5,
            Self::MediaChunkAccepted => 4,
            Self::PrintWriteBegin | Self::MediaWriteBegin => MAX_OUTPUT_BEGIN_BODY_BYTES,
            Self::PrintWriteChunk | Self::MediaWriteChunk => MAX_CHUNK_BODY_BYTES,
            Self::PrintWriteFinish | Self::MediaWriteFinish => 5,
        }
    }

    fn parse(capability: Capability, value: u8) -> Result<Self, DeviceError> {
        if !matches!(value, 0x01 | 0x02 | 0x03 | 0x04 | 0x81 | 0x82 | 0x83 | 0xff) {
            return Err(DeviceError::KindOutOfRange);
        }
        match (capability, value) {
            (Capability::Display, 0x01) => Ok(Self::DisplayStage),
            (Capability::Display, 0x02) => Ok(Self::DisplayProfile),
            (Capability::Display, 0x03) => Ok(Self::DisplayReview),
            (Capability::Display, 0x04) => Ok(Self::DisplayResult),
            (Capability::Keypad, 0x01) => Ok(Self::KeypadEvent),
            (Capability::CardResponse, 0x81) => Ok(Self::CardProfile),
            (Capability::CardResponse, 0x82) => Ok(Self::CardNormalFactor),
            (Capability::CardResponse, 0x83) => Ok(Self::CardApduResponse),
            (Capability::CardResponse, 0xff) => Ok(Self::CardRejected),
            (Capability::CardRequest, 0x01) => Ok(Self::CardReadProfile),
            (Capability::CardRequest, 0x02) => Ok(Self::CardReadNormalFactor),
            (Capability::CardRequest, 0x03) => Ok(Self::CardApduRequest),
            (Capability::CameraInput, 0x01) => Ok(Self::CameraBegin),
            (Capability::CameraInput, 0x02) => Ok(Self::CameraChunk),
            (Capability::MediaInput, 0x01) => Ok(Self::MediaReadBegin),
            (Capability::MediaInput, 0x02) => Ok(Self::MediaReadChunk),
            (Capability::MediaInput, 0x81) => Ok(Self::MediaBeginAccepted),
            (Capability::MediaInput, 0x82) => Ok(Self::MediaChunkAccepted),
            (Capability::MediaInput, 0x83) => Ok(Self::MediaFinished),
            (Capability::MediaInput, 0xff) => Ok(Self::MediaRejected),
            (Capability::PrintOutput, 0x01) => Ok(Self::PrintWriteBegin),
            (Capability::PrintOutput, 0x02) => Ok(Self::PrintWriteChunk),
            (Capability::PrintOutput, 0x03) => Ok(Self::PrintWriteFinish),
            (Capability::MediaOutput, 0x01) => Ok(Self::MediaWriteBegin),
            (Capability::MediaOutput, 0x02) => Ok(Self::MediaWriteChunk),
            (Capability::MediaOutput, 0x03) => Ok(Self::MediaWriteFinish),
            _ => Err(DeviceError::CapabilityKindMismatch),
        }
    }
}

/// Parsed immutable header facts.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct FrameHeader {
    capability: Capability,
    kind: MessageKind,
    sequence: u32,
    body_len: u32,
}

impl FrameHeader {
    pub const fn capability(&self) -> Capability {
        self.capability
    }

    pub const fn kind(&self) -> MessageKind {
        self.kind
    }

    pub const fn sequence(&self) -> u32 {
        self.sequence
    }

    pub const fn body_len(&self) -> u32 {
        self.body_len
    }
}

/// One borrowed, completely parsed frame.
#[derive(Clone, Copy, Eq, PartialEq)]
pub struct FrameRef<'a> {
    header: FrameHeader,
    body: &'a [u8],
}

impl<'a> FrameRef<'a> {
    pub(crate) const fn from_parts(header: FrameHeader, body: &'a [u8]) -> Self {
        Self { header, body }
    }

    pub const fn header(&self) -> &FrameHeader {
        &self.header
    }

    pub const fn body(&self) -> &'a [u8] {
        self.body
    }

    pub fn parsed_body(&self) -> Result<BodyRef<'a>, DeviceError> {
        parse_body(self)
    }
}

pub(crate) fn parse_header(
    expected_capability: Capability,
    bytes: &[u8; HEADER_BYTES],
) -> Result<FrameHeader, DeviceError> {
    if bytes[0..4] != MAGIC {
        return Err(DeviceError::MagicMismatch);
    }
    if bytes[4] != VERSION {
        return Err(DeviceError::VersionMismatch);
    }
    let capability = Capability::parse(bytes[5])?;
    if capability != expected_capability {
        return Err(DeviceError::CapabilityMismatch);
    }
    let kind = MessageKind::parse(capability, bytes[6])?;
    if bytes[7] != 0 {
        return Err(DeviceError::ReservedNonZero);
    }
    let sequence = read_u32(&bytes[8..12]);
    if sequence == 0 {
        return Err(DeviceError::SequenceZero);
    }
    let body_len = read_u32(&bytes[12..16]);
    if body_len as usize > kind.body_cap() || body_len as usize > MAX_BODY_BYTES {
        return Err(DeviceError::BodyLengthExceeded);
    }
    Ok(FrameHeader {
        capability,
        kind,
        sequence,
        body_len,
    })
}

/// Parse one complete frame with no trailing byte and validate its body.
pub fn parse_frame(
    expected_capability: Capability,
    bytes: &[u8],
) -> Result<FrameRef<'_>, DeviceError> {
    let header_bytes: &[u8; HEADER_BYTES] = bytes
        .get(..HEADER_BYTES)
        .ok_or(DeviceError::HeaderTruncated)?
        .try_into()
        .map_err(|_| DeviceError::HeaderTruncated)?;
    let header = parse_header(expected_capability, header_bytes)?;
    let frame_len = HEADER_BYTES
        .checked_add(header.body_len as usize)
        .ok_or(DeviceError::BodyLengthExceeded)?;
    if bytes.len() < frame_len {
        return Err(DeviceError::BodyTruncated);
    }
    if bytes.len() > frame_len {
        return Err(DeviceError::TrailingByte);
    }
    let body = bytes
        .get(HEADER_BYTES..frame_len)
        .ok_or(DeviceError::BodyTruncated)?;
    let frame = FrameRef { header, body };
    parse_body(&frame)?;
    Ok(frame)
}

/// Encode one exact, body-valid frame into a caller-owned output prefix.
///
/// The output remains unchanged on rejection. Bytes after the returned prefix
/// remain untouched on success.
pub fn encode_frame(
    capability: Capability,
    kind: MessageKind,
    sequence: u32,
    body: &[u8],
    output: &mut [u8],
) -> Result<usize, DeviceError> {
    if kind.capability() != capability {
        return Err(DeviceError::CapabilityKindMismatch);
    }
    if sequence == 0 {
        return Err(DeviceError::SequenceZero);
    }
    if body.len() > kind.body_cap() || body.len() > MAX_BODY_BYTES {
        return Err(DeviceError::BodyLengthExceeded);
    }
    let header = FrameHeader {
        capability,
        kind,
        sequence,
        body_len: u32::try_from(body.len()).map_err(|_| DeviceError::BodyLengthExceeded)?,
    };
    parse_body(&FrameRef { header, body })?;
    let frame_len = HEADER_BYTES
        .checked_add(body.len())
        .ok_or(DeviceError::BodyLengthExceeded)?;
    if frame_len > MAX_FRAME_BYTES || output.len() < frame_len {
        return Err(DeviceError::OutputBufferTooSmall);
    }
    let mut header_bytes = [0u8; HEADER_BYTES];
    header_bytes[0..4].copy_from_slice(&MAGIC);
    header_bytes[4] = VERSION;
    header_bytes[5] = capability.wire_value();
    header_bytes[6] = kind.wire_value();
    header_bytes[7] = 0;
    header_bytes[8..12].copy_from_slice(&sequence.to_le_bytes());
    header_bytes[12..16].copy_from_slice(&(body.len() as u32).to_le_bytes());
    output[..HEADER_BYTES].copy_from_slice(&header_bytes);
    output[HEADER_BYTES..frame_len].copy_from_slice(body);
    Ok(frame_len)
}

/// Exact immutable Normal profile.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Profile {
    SimpleRecovery,
    Inheritance,
    QuantumShelter,
}

impl Profile {
    pub const fn wire_value(self) -> u8 {
        match self {
            Self::SimpleRecovery => 0x01,
            Self::Inheritance => 0x02,
            Self::QuantumShelter => 0x03,
        }
    }

    fn parse(value: u8) -> Result<Self, DeviceError> {
        match value {
            0x01 => Ok(Self::SimpleRecovery),
            0x02 => Ok(Self::Inheritance),
            0x03 => Ok(Self::QuantumShelter),
            _ => Err(DeviceError::ValueOutOfRange),
        }
    }
}

/// Exact Normal stage value.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum NormalStage {
    NormalStart,
    ProfileBinding,
    Transport,
    PsbtIntake,
    FactorB,
    A1Intake,
    FactorA1,
    Validation,
    Review,
    FinalApproval,
    ApprovalHeld,
    Revalidation,
    TerminalASigning,
    CardBSigning,
    Finalization,
    AwaitingExportAction,
    TransactionResult,
    CompletedWiped,
}

impl NormalStage {
    pub const fn wire_value(self) -> u8 {
        match self {
            Self::NormalStart => 0x01,
            Self::ProfileBinding => 0x02,
            Self::Transport => 0x03,
            Self::PsbtIntake => 0x04,
            Self::FactorB => 0x05,
            Self::A1Intake => 0x06,
            Self::FactorA1 => 0x07,
            Self::Validation => 0x08,
            Self::Review => 0x09,
            Self::FinalApproval => 0x0a,
            Self::ApprovalHeld => 0x0b,
            Self::Revalidation => 0x0c,
            Self::TerminalASigning => 0x0d,
            Self::CardBSigning => 0x0e,
            Self::Finalization => 0x0f,
            Self::AwaitingExportAction => 0x10,
            Self::TransactionResult => 0x11,
            Self::CompletedWiped => 0x12,
        }
    }

    fn parse(value: u8) -> Result<Self, DeviceError> {
        match value {
            0x01 => Ok(Self::NormalStart),
            0x02 => Ok(Self::ProfileBinding),
            0x03 => Ok(Self::Transport),
            0x04 => Ok(Self::PsbtIntake),
            0x05 => Ok(Self::FactorB),
            0x06 => Ok(Self::A1Intake),
            0x07 => Ok(Self::FactorA1),
            0x08 => Ok(Self::Validation),
            0x09 => Ok(Self::Review),
            0x0a => Ok(Self::FinalApproval),
            0x0b => Ok(Self::ApprovalHeld),
            0x0c => Ok(Self::Revalidation),
            0x0d => Ok(Self::TerminalASigning),
            0x0e => Ok(Self::CardBSigning),
            0x0f => Ok(Self::Finalization),
            0x10 => Ok(Self::AwaitingExportAction),
            0x11 => Ok(Self::TransactionResult),
            0x12 => Ok(Self::CompletedWiped),
            _ => Err(DeviceError::ValueOutOfRange),
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Network {
    BitcoinMainnet,
}

impl Network {
    fn parse(value: u8) -> Result<Self, DeviceError> {
        match value {
            0x01 => Ok(Self::BitcoinMainnet),
            _ => Err(DeviceError::ValueOutOfRange),
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DirectRbf {
    NotSignaled,
    Signaled,
}

impl DirectRbf {
    fn parse(value: u8) -> Result<Self, DeviceError> {
        match value {
            0x00 => Ok(Self::NotSignaled),
            0x01 => Ok(Self::Signaled),
            _ => Err(DeviceError::ValueOutOfRange),
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Warning {
    FeeRateLow,
    FeeRateHigh,
    FeeShareHigh,
    FeeAbsoluteHigh,
}

impl Warning {
    fn parse(value: u8) -> Result<Self, DeviceError> {
        match value {
            0x01 => Ok(Self::FeeRateLow),
            0x02 => Ok(Self::FeeRateHigh),
            0x03 => Ok(Self::FeeShareHigh),
            0x04 => Ok(Self::FeeAbsoluteHigh),
            _ => Err(DeviceError::ValueOutOfRange),
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RecipientType {
    P2wpkh,
    P2wsh,
    P2tr,
    P2pkh,
    P2sh,
    OpReturn,
}

impl RecipientType {
    fn parse(value: u8) -> Result<Self, DeviceError> {
        match value {
            0x01 => Ok(Self::P2wpkh),
            0x02 => Ok(Self::P2wsh),
            0x03 => Ok(Self::P2tr),
            0x04 => Ok(Self::P2pkh),
            0x05 => Ok(Self::P2sh),
            0x06 => Ok(Self::OpReturn),
            _ => Err(DeviceError::ValueOutOfRange),
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Route {
    Sd,
    Bbqr,
}

impl Route {
    fn parse(value: u8) -> Result<Self, DeviceError> {
        match value {
            0x01 => Ok(Self::Sd),
            0x02 => Ok(Self::Bbqr),
            _ => Err(DeviceError::ValueOutOfRange),
        }
    }
}

/// Exact qk-io source value.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Source {
    CameraA1Candidate,
    CameraKitCandidate,
    CameraBbqrPsbt,
    MediaPsbt,
}

impl Source {
    pub const fn wire_value(self) -> u8 {
        match self {
            Self::CameraA1Candidate => 0x01,
            Self::CameraKitCandidate => 0x02,
            Self::CameraBbqrPsbt => 0x03,
            Self::MediaPsbt => 0x04,
        }
    }

    fn parse(value: u8) -> Result<Self, DeviceError> {
        match value {
            0x01 => Ok(Self::CameraA1Candidate),
            0x02 => Ok(Self::CameraKitCandidate),
            0x03 => Ok(Self::CameraBbqrPsbt),
            0x04 => Ok(Self::MediaPsbt),
            _ => Err(DeviceError::ValueOutOfRange),
        }
    }
}

/// Exact qk-io artifact value.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Artifact {
    FinalizedPsbt,
    RawTransaction,
    WatchOnlyBsms,
    A1PrintArtifact,
    KitPrintArtifact,
}

impl Artifact {
    pub const fn wire_value(self) -> u8 {
        match self {
            Self::FinalizedPsbt => 0x01,
            Self::RawTransaction => 0x02,
            Self::WatchOnlyBsms => 0x03,
            Self::A1PrintArtifact => 0x04,
            Self::KitPrintArtifact => 0x05,
        }
    }

    fn parse(value: u8) -> Result<Self, DeviceError> {
        match value {
            0x01 => Ok(Self::FinalizedPsbt),
            0x02 => Ok(Self::RawTransaction),
            0x03 => Ok(Self::WatchOnlyBsms),
            0x04 => Ok(Self::A1PrintArtifact),
            0x05 => Ok(Self::KitPrintArtifact),
            _ => Err(DeviceError::ValueOutOfRange),
        }
    }
}

/// Exact nineteen-key logical P0.1 vocabulary.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum LogicalKey {
    Seven,
    EightUp,
    Nine,
    CeDelete,
    CancelBack,
    FourLeft,
    Five,
    SixRight,
    Multiply,
    Divide,
    One,
    TwoDown,
    Three,
    Minus,
    Percent,
    Zero,
    Decimal,
    Plus,
    EqualsConfirmEnter,
}

impl LogicalKey {
    pub const fn wire_value(self) -> u8 {
        self as u8 + 1
    }

    fn parse(value: u8) -> Result<Self, DeviceError> {
        match value {
            0x01 => Ok(Self::Seven),
            0x02 => Ok(Self::EightUp),
            0x03 => Ok(Self::Nine),
            0x04 => Ok(Self::CeDelete),
            0x05 => Ok(Self::CancelBack),
            0x06 => Ok(Self::FourLeft),
            0x07 => Ok(Self::Five),
            0x08 => Ok(Self::SixRight),
            0x09 => Ok(Self::Multiply),
            0x0a => Ok(Self::Divide),
            0x0b => Ok(Self::One),
            0x0c => Ok(Self::TwoDown),
            0x0d => Ok(Self::Three),
            0x0e => Ok(Self::Minus),
            0x0f => Ok(Self::Percent),
            0x10 => Ok(Self::Zero),
            0x11 => Ok(Self::Decimal),
            0x12 => Ok(Self::Plus),
            0x13 => Ok(Self::EqualsConfirmEnter),
            _ => Err(DeviceError::ValueOutOfRange),
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DeviceRejection {
    Absent,
    AccessRejected,
    Unavailable,
}

impl DeviceRejection {
    fn parse(value: u16) -> Result<Self, DeviceError> {
        match value {
            0x0001 => Ok(Self::Absent),
            0x0002 => Ok(Self::AccessRejected),
            0x0003 => Ok(Self::Unavailable),
            _ => Err(DeviceError::ValueOutOfRange),
        }
    }
}

/// Parsed display body.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DisplayBody<'a> {
    Stage(NormalStage),
    Profile(Profile),
    Review(ReviewBody<'a>),
    Result(ResultBody<'a>),
}

/// Exact selected review facts.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ReviewBody<'a> {
    Overview {
        profile: Profile,
        network: Network,
        wallet_id: &'a [u8; 32],
        input_count: u32,
        total_input: u64,
    },
    Arithmetic {
        total_input: u64,
        total_output: u64,
        fee: u64,
    },
    Recipient {
        output_index: u32,
        amount: u64,
        script: &'a [u8],
        ownership: RecipientOwnership<'a>,
    },
    Change {
        output_index: u32,
        amount: u64,
        script: &'a [u8],
        child_index: u32,
    },
    OpReturn {
        output_index: u32,
        amount: u64,
        script: &'a [u8],
        payload: &'a [u8],
    },
    Locktime {
        locktime: u32,
    },
    Sequence {
        input_index: u32,
        sequence: u32,
        direct_rbf: DirectRbf,
    },
    FeePolicy,
    FeeFacts {
        fee: u64,
        estimated_vsize: u32,
        fee_rate_msat_per_vbyte: u64,
    },
    Warning(Warning),
    FinalApproval {
        profile: Profile,
        review_hash: &'a [u8; 32],
    },
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RecipientOwnership<'a> {
    External {
        recipient_type: RecipientType,
        data: &'a [u8],
    },
    SelfTransfer {
        child_index: u32,
        witness_program: &'a [u8],
    },
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ArtifactFactRef<'a> {
    kind: Artifact,
    serialized_len: u32,
    sha256: &'a [u8; 32],
}

impl<'a> ArtifactFactRef<'a> {
    pub const fn kind(self) -> Artifact {
        self.kind
    }

    pub const fn serialized_len(self) -> u32 {
        self.serialized_len
    }

    pub const fn sha256(self) -> &'a [u8; 32] {
        self.sha256
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ReceiptFact {
    kind: Artifact,
    total_len: u32,
}

impl ReceiptFact {
    pub const fn kind(self) -> Artifact {
        self.kind
    }

    pub const fn total_len(self) -> u32 {
        self.total_len
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ResultBody<'a> {
    profile: Profile,
    route: Route,
    presence_bitmap: u8,
    finalized_psbt: Option<ArtifactFactRef<'a>>,
    raw_transaction: Option<ArtifactFactRef<'a>>,
    finalized_psbt_receipt: Option<ReceiptFact>,
    raw_transaction_receipt: Option<ReceiptFact>,
    txid: &'a [u8; 32],
    wtxid: &'a [u8; 32],
}

impl<'a> ResultBody<'a> {
    pub const fn profile(self) -> Profile {
        self.profile
    }

    pub const fn route(self) -> Route {
        self.route
    }

    pub const fn presence_bitmap(self) -> u8 {
        self.presence_bitmap
    }

    pub const fn finalized_psbt(self) -> Option<ArtifactFactRef<'a>> {
        self.finalized_psbt
    }

    pub const fn raw_transaction(self) -> Option<ArtifactFactRef<'a>> {
        self.raw_transaction
    }

    pub const fn finalized_psbt_receipt(self) -> Option<ReceiptFact> {
        self.finalized_psbt_receipt
    }

    pub const fn raw_transaction_receipt(self) -> Option<ReceiptFact> {
        self.raw_transaction_receipt
    }

    pub const fn txid(self) -> &'a [u8; 32] {
        self.txid
    }

    pub const fn wtxid(self) -> &'a [u8; 32] {
        self.wtxid
    }
}

/// Parsed semantic event arriving on the keypad descriptor.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum KeypadBody {
    LogicalKey(LogicalKey),
    SelectPsbtSource(Source),
    HoldCompleted,
    SelectSd { caller_nonce: [u8; 16] },
    SelectBbqr { non_final_part_len: u16 },
    CardRemoved,
    SessionTimeout,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CardRequestBody {
    ReadProfile,
    ReadNormalFactor,
}

#[derive(Clone, Copy, Eq, PartialEq)]
pub enum CardResponseBody<'a> {
    Profile(Profile),
    NormalFactor(NormalFactorRef<'a>),
    Rejected {
        request_kind: MessageKind,
        error: DeviceRejection,
    },
}

/// Borrowed validated NormalFactor body.
#[derive(Clone, Copy, Eq, PartialEq)]
pub struct NormalFactorRef<'a> {
    receive_descriptor: &'a [u8; DESCRIPTOR_BYTES],
    change_descriptor: &'a [u8; DESCRIPTOR_BYTES],
    wallet_id: &'a [u8; WALLET_ID_BYTES],
    role_b_account_xpub: &'a [u8; ACCOUNT_XPUB_BYTES],
    a2: &'a [u8; A2_BYTES],
    signature_count: u16,
    signature_bytes: &'a [u8],
}

impl<'a> NormalFactorRef<'a> {
    pub const fn receive_descriptor(self) -> &'a [u8; DESCRIPTOR_BYTES] {
        self.receive_descriptor
    }

    pub const fn change_descriptor(self) -> &'a [u8; DESCRIPTOR_BYTES] {
        self.change_descriptor
    }

    pub const fn wallet_id(self) -> &'a [u8; WALLET_ID_BYTES] {
        self.wallet_id
    }

    pub const fn role_b_account_xpub(self) -> &'a [u8; ACCOUNT_XPUB_BYTES] {
        self.role_b_account_xpub
    }

    pub const fn a2(self) -> &'a [u8; A2_BYTES] {
        self.a2
    }

    pub const fn signature_count(self) -> u16 {
        self.signature_count
    }

    pub const fn signatures(self) -> SignatureIter<'a> {
        SignatureIter {
            remaining: self.signature_bytes,
            count: self.signature_count,
        }
    }
}

#[derive(Clone, Copy, Eq, PartialEq)]
pub struct SignatureRecordRef<'a> {
    input_index: u32,
    role_b_pubkey: &'a [u8; 33],
    der: &'a [u8],
}

impl<'a> SignatureRecordRef<'a> {
    pub const fn input_index(self) -> u32 {
        self.input_index
    }

    pub const fn role_b_pubkey(self) -> &'a [u8; 33] {
        self.role_b_pubkey
    }

    pub const fn der(self) -> &'a [u8] {
        self.der
    }
}

#[derive(Clone, Copy)]
pub struct SignatureIter<'a> {
    remaining: &'a [u8],
    count: u16,
}

impl<'a> Iterator for SignatureIter<'a> {
    type Item = SignatureRecordRef<'a>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.count == 0 {
            return None;
        }
        let input_index = read_u32(self.remaining.get(..4)?);
        let role_b_pubkey: &[u8; 33] = self.remaining.get(4..37)?.try_into().ok()?;
        let der_len = usize::from(*self.remaining.get(37)?);
        let der = self.remaining.get(38..38 + der_len)?;
        self.remaining = self.remaining.get(38 + der_len..)?;
        self.count -= 1;
        Some(SignatureRecordRef {
            input_index,
            role_b_pubkey,
            der,
        })
    }

    fn size_hint(&self) -> (usize, Option<usize>) {
        let count = usize::from(self.count);
        (count, Some(count))
    }
}

impl ExactSizeIterator for SignatureIter<'_> {}

#[derive(Clone, Copy, Eq, PartialEq)]
pub enum InputBody<'a> {
    Begin {
        source: Source,
        total_len: u32,
        filename: Option<&'a [u8]>,
    },
    Chunk {
        offset: u32,
        final_chunk: bool,
        chunk: &'a [u8],
    },
}

#[derive(Clone, Copy, Eq, PartialEq)]
pub enum OutputBody<'a> {
    WriteBegin {
        artifact: Artifact,
        total_len: u32,
        filename: &'a [u8],
    },
    WriteChunk {
        offset: u32,
        chunk: &'a [u8],
    },
    WriteFinish {
        artifact: Artifact,
        total_len: u32,
    },
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum OutputReplyBody {
    BeginAccepted { artifact: Artifact, total_len: u32 },
    ChunkAccepted { next_offset: u32 },
    Finished { artifact: Artifact, total_len: u32 },
    Rejected { request_kind: u8, status: u16 },
}

/// One borrowed body selected by the capability-bound kind.
#[derive(Clone, Copy, Eq, PartialEq)]
pub enum BodyRef<'a> {
    Display(DisplayBody<'a>),
    Keypad(KeypadBody),
    CardRequest(CardRequestBody),
    CardResponse(CardResponseBody<'a>),
    CardApduRequest(&'a [u8]),
    CardApduResponse(&'a [u8]),
    CameraInput(InputBody<'a>),
    MediaInput(InputBody<'a>),
    OutputReply(OutputReplyBody),
    PrintOutput(OutputBody<'a>),
    MediaOutput(OutputBody<'a>),
}

/// Parse the exact capability-bound body grammar of one framed message.
pub fn parse_body<'a>(frame: &FrameRef<'a>) -> Result<BodyRef<'a>, DeviceError> {
    let body = frame.body;
    match frame.header.kind {
        MessageKind::DisplayStage => {
            exact_length(body, 1)?;
            Ok(BodyRef::Display(DisplayBody::Stage(NormalStage::parse(
                body[0],
            )?)))
        }
        MessageKind::DisplayProfile => {
            exact_length(body, 1)?;
            Ok(BodyRef::Display(DisplayBody::Profile(Profile::parse(
                body[0],
            )?)))
        }
        MessageKind::DisplayReview => {
            Ok(BodyRef::Display(DisplayBody::Review(parse_review(body)?)))
        }
        MessageKind::DisplayResult => {
            Ok(BodyRef::Display(DisplayBody::Result(parse_result(body)?)))
        }
        MessageKind::KeypadEvent => Ok(BodyRef::Keypad(parse_keypad(body)?)),
        MessageKind::CardReadProfile => {
            exact_length(body, 0)?;
            Ok(BodyRef::CardRequest(CardRequestBody::ReadProfile))
        }
        MessageKind::CardReadNormalFactor => {
            #[cfg(not(feature = "legacy-normal-factor-fixture"))]
            return Err(DeviceError::LegacyNormalFactorRejected);
            #[cfg(feature = "legacy-normal-factor-fixture")]
            exact_length(body, 0)?;
            #[cfg(feature = "legacy-normal-factor-fixture")]
            Ok(BodyRef::CardRequest(CardRequestBody::ReadNormalFactor))
        }
        MessageKind::CardApduRequest => Ok(BodyRef::CardApduRequest(body)),
        MessageKind::CardProfile => {
            exact_length(body, 1)?;
            Ok(BodyRef::CardResponse(CardResponseBody::Profile(
                Profile::parse(body[0])?,
            )))
        }
        MessageKind::CardNormalFactor => {
            #[cfg(not(feature = "legacy-normal-factor-fixture"))]
            return Err(DeviceError::LegacyNormalFactorRejected);
            #[cfg(feature = "legacy-normal-factor-fixture")]
            Ok(BodyRef::CardResponse(CardResponseBody::NormalFactor(
                parse_normal_factor(body)?,
            )))
        }
        MessageKind::CardApduResponse => Ok(BodyRef::CardApduResponse(body)),
        MessageKind::CardRejected => Ok(BodyRef::CardResponse(parse_card_rejection(body)?)),
        MessageKind::CameraBegin => Ok(BodyRef::CameraInput(parse_camera_begin(body)?)),
        MessageKind::CameraChunk => Ok(BodyRef::CameraInput(parse_input_chunk(body)?)),
        MessageKind::MediaReadBegin => Ok(BodyRef::MediaInput(parse_media_begin(body)?)),
        MessageKind::MediaReadChunk => Ok(BodyRef::MediaInput(parse_input_chunk(body)?)),
        MessageKind::MediaBeginAccepted
        | MessageKind::MediaChunkAccepted
        | MessageKind::MediaFinished
        | MessageKind::MediaRejected => Ok(BodyRef::OutputReply(parse_output_reply(
            frame.header.kind,
            body,
        )?)),
        MessageKind::PrintWriteBegin
        | MessageKind::PrintWriteChunk
        | MessageKind::PrintWriteFinish => Ok(BodyRef::PrintOutput(parse_output(
            Capability::PrintOutput,
            frame.header.kind,
            body,
        )?)),
        MessageKind::MediaWriteBegin
        | MessageKind::MediaWriteChunk
        | MessageKind::MediaWriteFinish => Ok(BodyRef::MediaOutput(parse_output(
            Capability::MediaOutput,
            frame.header.kind,
            body,
        )?)),
    }
}

fn parse_review(body: &[u8]) -> Result<ReviewBody<'_>, DeviceError> {
    let (&subtype, rest) = body.split_first().ok_or(DeviceError::BodyLengthMismatch)?;
    match subtype {
        0x01 => {
            exact_length(rest, 46)?;
            Ok(ReviewBody::Overview {
                profile: Profile::parse(rest[0])?,
                network: Network::parse(rest[1])?,
                wallet_id: rest[2..34]
                    .try_into()
                    .map_err(|_| DeviceError::BodyLengthMismatch)?,
                input_count: read_u32(&rest[34..38]),
                total_input: read_u64(&rest[38..46]),
            })
        }
        0x02 => {
            exact_length(rest, 24)?;
            Ok(ReviewBody::Arithmetic {
                total_input: read_u64(&rest[0..8]),
                total_output: read_u64(&rest[8..16]),
                fee: read_u64(&rest[16..24]),
            })
        }
        0x03 => parse_recipient(rest),
        0x04 => parse_change(rest),
        0x05 => parse_op_return(rest),
        0x06 => {
            exact_length(rest, 4)?;
            Ok(ReviewBody::Locktime {
                locktime: read_u32(rest),
            })
        }
        0x07 => {
            exact_length(rest, 9)?;
            Ok(ReviewBody::Sequence {
                input_index: read_u32(&rest[0..4]),
                sequence: read_u32(&rest[4..8]),
                direct_rbf: DirectRbf::parse(rest[8])?,
            })
        }
        0x08 => {
            if rest != FEE_POLICY {
                return Err(DeviceError::BodyLengthMismatch);
            }
            Ok(ReviewBody::FeePolicy)
        }
        0x09 => {
            exact_length(rest, 20)?;
            Ok(ReviewBody::FeeFacts {
                fee: read_u64(&rest[0..8]),
                estimated_vsize: read_u32(&rest[8..12]),
                fee_rate_msat_per_vbyte: read_u64(&rest[12..20]),
            })
        }
        0x0a => {
            exact_length(rest, 1)?;
            Ok(ReviewBody::Warning(Warning::parse(rest[0])?))
        }
        0x0b => {
            exact_length(rest, 33)?;
            Ok(ReviewBody::FinalApproval {
                profile: Profile::parse(rest[0])?,
                review_hash: rest[1..33]
                    .try_into()
                    .map_err(|_| DeviceError::BodyLengthMismatch)?,
            })
        }
        _ => Err(DeviceError::ValueOutOfRange),
    }
}

fn parse_recipient(rest: &[u8]) -> Result<ReviewBody<'_>, DeviceError> {
    if rest.len() < 15 {
        return Err(DeviceError::NestedLengthMismatch);
    }
    let output_index = read_u32(&rest[0..4]);
    let amount = read_u64(&rest[4..12]);
    let script_len = usize::from(read_u16(&rest[12..14]));
    if script_len > 83 {
        return Err(DeviceError::ValueOutOfRange);
    }
    let ownership_offset = 14usize
        .checked_add(script_len)
        .ok_or(DeviceError::NestedLengthMismatch)?;
    let script = rest
        .get(14..ownership_offset)
        .ok_or(DeviceError::NestedLengthMismatch)?;
    let ownership_tag = *rest
        .get(ownership_offset)
        .ok_or(DeviceError::NestedLengthMismatch)?;
    let ownership = match ownership_tag {
        0x01 => {
            let recipient_type = RecipientType::parse(
                *rest
                    .get(ownership_offset + 1)
                    .ok_or(DeviceError::NestedLengthMismatch)?,
            )?;
            let data_len = usize::from(read_u16(
                rest.get(ownership_offset + 2..ownership_offset + 4)
                    .ok_or(DeviceError::NestedLengthMismatch)?,
            ));
            let data_start = ownership_offset + 4;
            let data_end = data_start
                .checked_add(data_len)
                .ok_or(DeviceError::NestedLengthMismatch)?;
            if data_end != rest.len() {
                return Err(DeviceError::NestedLengthMismatch);
            }
            validate_recipient_data_len(recipient_type, data_len)?;
            RecipientOwnership::External {
                recipient_type,
                data: &rest[data_start..data_end],
            }
        }
        0x02 => {
            let child_index = read_u32(
                rest.get(ownership_offset + 1..ownership_offset + 5)
                    .ok_or(DeviceError::NestedLengthMismatch)?,
            );
            let program_len = usize::from(read_u16(
                rest.get(ownership_offset + 5..ownership_offset + 7)
                    .ok_or(DeviceError::NestedLengthMismatch)?,
            ));
            if program_len != 32 {
                return Err(DeviceError::ValueOutOfRange);
            }
            let program_start = ownership_offset + 7;
            let program_end = program_start
                .checked_add(program_len)
                .ok_or(DeviceError::NestedLengthMismatch)?;
            if program_end != rest.len() {
                return Err(DeviceError::NestedLengthMismatch);
            }
            RecipientOwnership::SelfTransfer {
                child_index,
                witness_program: &rest[program_start..program_end],
            }
        }
        _ => return Err(DeviceError::ValueOutOfRange),
    };
    Ok(ReviewBody::Recipient {
        output_index,
        amount,
        script,
        ownership,
    })
}

fn validate_recipient_data_len(
    recipient_type: RecipientType,
    data_len: usize,
) -> Result<(), DeviceError> {
    let valid = match recipient_type {
        RecipientType::P2wpkh | RecipientType::P2pkh | RecipientType::P2sh => data_len == 20,
        RecipientType::P2wsh | RecipientType::P2tr => data_len == 32,
        RecipientType::OpReturn => data_len <= 80,
    };
    if valid {
        Ok(())
    } else {
        Err(DeviceError::ValueOutOfRange)
    }
}

fn parse_change(rest: &[u8]) -> Result<ReviewBody<'_>, DeviceError> {
    if rest.len() < 18 {
        return Err(DeviceError::NestedLengthMismatch);
    }
    let script_len = usize::from(read_u16(&rest[12..14]));
    if script_len != 34 {
        return Err(DeviceError::ValueOutOfRange);
    }
    let script_end = 14 + script_len;
    if rest.len() != script_end + 4 {
        return Err(DeviceError::NestedLengthMismatch);
    }
    Ok(ReviewBody::Change {
        output_index: read_u32(&rest[0..4]),
        amount: read_u64(&rest[4..12]),
        script: &rest[14..script_end],
        child_index: read_u32(&rest[script_end..]),
    })
}

fn parse_op_return(rest: &[u8]) -> Result<ReviewBody<'_>, DeviceError> {
    if rest.len() < 16 {
        return Err(DeviceError::NestedLengthMismatch);
    }
    let script_len = usize::from(read_u16(&rest[12..14]));
    if script_len == 0 || script_len > 83 {
        return Err(DeviceError::ValueOutOfRange);
    }
    let script_end = 14usize
        .checked_add(script_len)
        .ok_or(DeviceError::NestedLengthMismatch)?;
    let payload_len_end = script_end
        .checked_add(2)
        .ok_or(DeviceError::NestedLengthMismatch)?;
    let payload_len = usize::from(read_u16(
        rest.get(script_end..payload_len_end)
            .ok_or(DeviceError::NestedLengthMismatch)?,
    ));
    if payload_len > 80 {
        return Err(DeviceError::ValueOutOfRange);
    }
    let payload_end = payload_len_end
        .checked_add(payload_len)
        .ok_or(DeviceError::NestedLengthMismatch)?;
    if payload_end != rest.len() {
        return Err(DeviceError::NestedLengthMismatch);
    }
    Ok(ReviewBody::OpReturn {
        output_index: read_u32(&rest[0..4]),
        amount: read_u64(&rest[4..12]),
        script: &rest[14..script_end],
        payload: &rest[payload_len_end..payload_end],
    })
}

fn parse_result(body: &[u8]) -> Result<ResultBody<'_>, DeviceError> {
    if body.len() < 67 {
        return Err(DeviceError::BodyLengthMismatch);
    }
    let profile = Profile::parse(body[0])?;
    let route = Route::parse(body[1])?;
    let presence_bitmap = body[2];
    let valid_bitmap = match (profile, route) {
        (Profile::SimpleRecovery | Profile::Inheritance, Route::Sd) => 0x0f,
        (Profile::SimpleRecovery | Profile::Inheritance, Route::Bbqr) => 0x01,
        (Profile::QuantumShelter, Route::Sd) => 0x0a,
        (Profile::QuantumShelter, Route::Bbqr) => 0x02,
    };
    if presence_bitmap != valid_bitmap {
        return Err(DeviceError::ValueOutOfRange);
    }

    let mut cursor = Cursor::new(&body[3..]);
    let finalized_psbt = if presence_bitmap & 0x01 != 0 {
        Some(parse_artifact_fact(&mut cursor, Artifact::FinalizedPsbt)?)
    } else {
        None
    };
    let raw_transaction = if presence_bitmap & 0x02 != 0 {
        Some(parse_artifact_fact(&mut cursor, Artifact::RawTransaction)?)
    } else {
        None
    };
    let finalized_psbt_receipt = if presence_bitmap & 0x04 != 0 {
        Some(parse_receipt_fact(&mut cursor, Artifact::FinalizedPsbt)?)
    } else {
        None
    };
    let raw_transaction_receipt = if presence_bitmap & 0x08 != 0 {
        Some(parse_receipt_fact(&mut cursor, Artifact::RawTransaction)?)
    } else {
        None
    };
    let txid = cursor.array::<32>()?;
    let wtxid = cursor.array::<32>()?;
    cursor.finish()?;
    Ok(ResultBody {
        profile,
        route,
        presence_bitmap,
        finalized_psbt,
        raw_transaction,
        finalized_psbt_receipt,
        raw_transaction_receipt,
        txid,
        wtxid,
    })
}

fn parse_artifact_fact<'a>(
    cursor: &mut Cursor<'a>,
    expected: Artifact,
) -> Result<ArtifactFactRef<'a>, DeviceError> {
    let kind = Artifact::parse(cursor.byte()?)?;
    if kind != expected {
        return Err(DeviceError::ArtifactMismatch);
    }
    let serialized_len = cursor.u32()?;
    if serialized_len == 0 {
        return Err(DeviceError::ValueOutOfRange);
    }
    let sha256 = cursor.array::<32>()?;
    Ok(ArtifactFactRef {
        kind,
        serialized_len,
        sha256,
    })
}

fn parse_receipt_fact(
    cursor: &mut Cursor<'_>,
    expected: Artifact,
) -> Result<ReceiptFact, DeviceError> {
    let kind = Artifact::parse(cursor.byte()?)?;
    if kind != expected {
        return Err(DeviceError::ArtifactMismatch);
    }
    let total_len = cursor.u32()?;
    if total_len == 0 {
        return Err(DeviceError::ValueOutOfRange);
    }
    Ok(ReceiptFact { kind, total_len })
}

fn parse_keypad(body: &[u8]) -> Result<KeypadBody, DeviceError> {
    let (&event, data) = body.split_first().ok_or(DeviceError::BodyLengthMismatch)?;
    match event {
        0x01 => {
            exact_length(data, 1)?;
            Ok(KeypadBody::LogicalKey(LogicalKey::parse(data[0])?))
        }
        0x02 => {
            exact_length(data, 1)?;
            let source = Source::parse(data[0])?;
            if !matches!(source, Source::CameraBbqrPsbt | Source::MediaPsbt) {
                return Err(DeviceError::SourceMismatch);
            }
            Ok(KeypadBody::SelectPsbtSource(source))
        }
        0x03 => {
            exact_length(data, 0)?;
            Ok(KeypadBody::HoldCompleted)
        }
        0x04 => {
            exact_length(data, 16)?;
            let mut caller_nonce = [0u8; 16];
            caller_nonce.copy_from_slice(data);
            Ok(KeypadBody::SelectSd { caller_nonce })
        }
        0x05 => {
            exact_length(data, 2)?;
            let non_final_part_len = read_u16(data);
            if !(5..=MAX_BBQR_PART_BYTES).contains(&non_final_part_len)
                || !non_final_part_len.is_multiple_of(5)
            {
                return Err(DeviceError::ValueOutOfRange);
            }
            Ok(KeypadBody::SelectBbqr { non_final_part_len })
        }
        0x06 => {
            exact_length(data, 0)?;
            Ok(KeypadBody::CardRemoved)
        }
        0x07 => {
            exact_length(data, 0)?;
            Ok(KeypadBody::SessionTimeout)
        }
        _ => Err(DeviceError::ValueOutOfRange),
    }
}

fn parse_card_rejection(body: &[u8]) -> Result<CardResponseBody<'_>, DeviceError> {
    exact_length(body, 3)?;
    let request_kind = match body[0] {
        0x01 => MessageKind::CardReadProfile,
        0x02 => MessageKind::CardReadNormalFactor,
        _ => return Err(DeviceError::ValueOutOfRange),
    };
    let error = DeviceRejection::parse(read_u16(&body[1..3]))?;
    Ok(CardResponseBody::Rejected {
        request_kind,
        error,
    })
}

#[cfg(feature = "legacy-normal-factor-fixture")]
fn parse_normal_factor(body: &[u8]) -> Result<NormalFactorRef<'_>, DeviceError> {
    if body.len() < CARD_FACTOR_PREFIX_BYTES {
        return Err(DeviceError::BodyLengthMismatch);
    }
    let receive_descriptor = body[0..306]
        .try_into()
        .map_err(|_| DeviceError::BodyLengthMismatch)?;
    let change_descriptor = body[306..612]
        .try_into()
        .map_err(|_| DeviceError::BodyLengthMismatch)?;
    let wallet_id = body[612..644]
        .try_into()
        .map_err(|_| DeviceError::BodyLengthMismatch)?;
    let role_b_account_xpub = body[644..755]
        .try_into()
        .map_err(|_| DeviceError::BodyLengthMismatch)?;
    let a2 = body[755..787]
        .try_into()
        .map_err(|_| DeviceError::BodyLengthMismatch)?;
    let signature_count = read_u16(&body[787..789]);
    if usize::from(signature_count) > MAX_SIGNATURES {
        return Err(DeviceError::CountExceeded);
    }
    let signature_bytes = &body[CARD_FACTOR_PREFIX_BYTES..];
    let mut cursor = Cursor::new(signature_bytes);
    let mut previous = None;
    for _ in 0..signature_count {
        let input_index = cursor.u32()?;
        if previous.is_some_and(|value| input_index <= value) {
            return Err(DeviceError::IndexOrderMismatch);
        }
        previous = Some(input_index);
        cursor.array::<33>()?;
        let der_len = usize::from(cursor.byte()?);
        if !(MIN_DER_BYTES..=MAX_DER_BYTES).contains(&der_len) {
            return Err(DeviceError::ValueOutOfRange);
        }
        cursor.take(der_len)?;
    }
    cursor.finish()?;
    Ok(NormalFactorRef {
        receive_descriptor,
        change_descriptor,
        wallet_id,
        role_b_account_xpub,
        a2,
        signature_count,
        signature_bytes,
    })
}

fn parse_camera_begin(body: &[u8]) -> Result<InputBody<'_>, DeviceError> {
    exact_length(body, 5)?;
    let source = Source::parse(body[0])?;
    let total_len = read_u32(&body[1..5]);
    let valid = match source {
        Source::CameraA1Candidate => total_len == A1_BYTES,
        Source::CameraKitCandidate => total_len == KIT_BYTES,
        Source::CameraBbqrPsbt => (1..=MAX_TRANSFER_BYTES as u32).contains(&total_len),
        Source::MediaPsbt => false,
    };
    if !valid {
        return Err(DeviceError::SourceMismatch);
    }
    Ok(InputBody::Begin {
        source,
        total_len,
        filename: None,
    })
}

fn parse_media_begin(body: &[u8]) -> Result<InputBody<'_>, DeviceError> {
    if body.len() < 7 {
        return Err(DeviceError::BodyLengthMismatch);
    }
    let source = Source::parse(body[0])?;
    if source != Source::MediaPsbt {
        return Err(DeviceError::SourceMismatch);
    }
    let total_len = read_u32(&body[1..5]);
    if total_len == 0 || total_len as usize > MAX_TRANSFER_BYTES {
        return Err(DeviceError::ValueOutOfRange);
    }
    let name_len = usize::from(read_u16(&body[5..7]));
    if name_len == 0 || name_len > MAX_FILENAME_BYTES {
        return Err(DeviceError::FilenameRejected);
    }
    let end = 7usize
        .checked_add(name_len)
        .ok_or(DeviceError::NestedLengthMismatch)?;
    if end != body.len() {
        return Err(DeviceError::NestedLengthMismatch);
    }
    let filename = &body[7..end];
    if !valid_input_filename(filename) {
        return Err(DeviceError::FilenameRejected);
    }
    Ok(InputBody::Begin {
        source,
        total_len,
        filename: Some(filename),
    })
}

fn parse_input_chunk(body: &[u8]) -> Result<InputBody<'_>, DeviceError> {
    if body.len() < 9 {
        return Err(DeviceError::BodyLengthMismatch);
    }
    let offset = read_u32(&body[0..4]);
    let chunk_len = read_u32(&body[4..8]) as usize;
    if chunk_len == 0 {
        return Err(DeviceError::ChunkLengthZero);
    }
    if chunk_len > crate::MAX_CHUNK_BYTES {
        return Err(DeviceError::ChunkLengthExceeded);
    }
    let final_chunk = match body[8] {
        0 => false,
        1 => true,
        _ => return Err(DeviceError::FinalFlagOutOfRange),
    };
    let end = 9usize
        .checked_add(chunk_len)
        .ok_or(DeviceError::NestedLengthMismatch)?;
    if end != body.len() {
        return Err(DeviceError::NestedLengthMismatch);
    }
    Ok(InputBody::Chunk {
        offset,
        final_chunk,
        chunk: &body[9..end],
    })
}

pub(crate) fn parse_output(
    capability: Capability,
    kind: MessageKind,
    body: &[u8],
) -> Result<OutputBody<'_>, DeviceError> {
    match kind {
        MessageKind::PrintWriteBegin | MessageKind::MediaWriteBegin => {
            parse_output_begin(capability, body)
        }
        MessageKind::PrintWriteChunk | MessageKind::MediaWriteChunk => parse_output_chunk(body),
        MessageKind::PrintWriteFinish | MessageKind::MediaWriteFinish => {
            parse_output_finish(capability, body)
        }
        _ => Err(DeviceError::CapabilityKindMismatch),
    }
}

fn parse_output_begin(capability: Capability, body: &[u8]) -> Result<OutputBody<'_>, DeviceError> {
    if body.len() < 7 {
        return Err(DeviceError::BodyLengthMismatch);
    }
    let artifact = Artifact::parse(body[0])?;
    let total_len = read_u32(&body[1..5]);
    if total_len == 0 || total_len as usize > MAX_TRANSFER_BYTES {
        return Err(DeviceError::ValueOutOfRange);
    }
    let name_len = usize::from(read_u16(&body[5..7]));
    if name_len > MAX_FILENAME_BYTES {
        return Err(DeviceError::FilenameRejected);
    }
    let end = 7usize
        .checked_add(name_len)
        .ok_or(DeviceError::NestedLengthMismatch)?;
    if end != body.len() {
        return Err(DeviceError::NestedLengthMismatch);
    }
    let filename = &body[7..end];
    match capability {
        Capability::PrintOutput => {
            let valid = matches!(
                (artifact, total_len),
                (Artifact::A1PrintArtifact, A1_PRINT_BYTES)
                    | (Artifact::KitPrintArtifact, KIT_PRINT_BYTES)
            );
            if !valid {
                return Err(DeviceError::ArtifactMismatch);
            }
            if !filename.is_empty() {
                return Err(DeviceError::FilenameRejected);
            }
        }
        Capability::MediaOutput => {
            if !matches!(artifact, Artifact::FinalizedPsbt | Artifact::RawTransaction) {
                return Err(DeviceError::ArtifactMismatch);
            }
            if !valid_output_filename(artifact, filename) {
                return Err(DeviceError::FilenameRejected);
            }
        }
        _ => return Err(DeviceError::CapabilityMismatch),
    }
    Ok(OutputBody::WriteBegin {
        artifact,
        total_len,
        filename,
    })
}

fn parse_output_chunk(body: &[u8]) -> Result<OutputBody<'_>, DeviceError> {
    if body.len() < 8 {
        return Err(DeviceError::BodyLengthMismatch);
    }
    let offset = read_u32(&body[0..4]);
    let chunk_len = read_u32(&body[4..8]) as usize;
    if chunk_len == 0 {
        return Err(DeviceError::ChunkLengthZero);
    }
    if chunk_len > crate::MAX_CHUNK_BYTES {
        return Err(DeviceError::ChunkLengthExceeded);
    }
    let end = 8usize
        .checked_add(chunk_len)
        .ok_or(DeviceError::NestedLengthMismatch)?;
    if end != body.len() {
        return Err(DeviceError::NestedLengthMismatch);
    }
    Ok(OutputBody::WriteChunk {
        offset,
        chunk: &body[8..end],
    })
}

fn parse_output_finish(capability: Capability, body: &[u8]) -> Result<OutputBody<'_>, DeviceError> {
    exact_length(body, 5)?;
    let artifact = Artifact::parse(body[0])?;
    let valid = match capability {
        Capability::PrintOutput => {
            matches!(
                artifact,
                Artifact::A1PrintArtifact | Artifact::KitPrintArtifact
            )
        }
        Capability::MediaOutput => {
            matches!(artifact, Artifact::FinalizedPsbt | Artifact::RawTransaction)
        }
        _ => false,
    };
    if !valid {
        return Err(DeviceError::ArtifactMismatch);
    }
    let total_len = read_u32(&body[1..5]);
    if total_len == 0 || total_len as usize > MAX_TRANSFER_BYTES {
        return Err(DeviceError::ValueOutOfRange);
    }
    Ok(OutputBody::WriteFinish {
        artifact,
        total_len,
    })
}

fn parse_output_reply(kind: MessageKind, body: &[u8]) -> Result<OutputReplyBody, DeviceError> {
    match kind {
        MessageKind::MediaBeginAccepted => {
            exact_length(body, 5)?;
            let artifact = parse_output_reply_artifact(body[0])?;
            let total_len = read_u32(&body[1..5]);
            if !(1..=MAX_TRANSFER_BYTES as u32).contains(&total_len) {
                return Err(DeviceError::ValueOutOfRange);
            }
            Ok(OutputReplyBody::BeginAccepted {
                artifact,
                total_len,
            })
        }
        MessageKind::MediaChunkAccepted => {
            exact_length(body, 4)?;
            let next_offset = read_u32(body);
            if !(1..=MAX_TRANSFER_BYTES as u32).contains(&next_offset) {
                return Err(DeviceError::ValueOutOfRange);
            }
            Ok(OutputReplyBody::ChunkAccepted { next_offset })
        }
        MessageKind::MediaFinished => {
            exact_length(body, 5)?;
            let artifact = parse_output_reply_artifact(body[0])?;
            let total_len = read_u32(&body[1..5]);
            if !(1..=MAX_TRANSFER_BYTES as u32).contains(&total_len) {
                return Err(DeviceError::ValueOutOfRange);
            }
            Ok(OutputReplyBody::Finished {
                artifact,
                total_len,
            })
        }
        MessageKind::MediaRejected => {
            exact_length(body, 3)?;
            let request_kind = body[0];
            if !matches!(request_kind, 0x01..=0x03) {
                return Err(DeviceError::ValueOutOfRange);
            }
            let status = read_u16(&body[1..3]);
            if !valid_io_status(status) {
                return Err(DeviceError::ValueOutOfRange);
            }
            Ok(OutputReplyBody::Rejected {
                request_kind,
                status,
            })
        }
        _ => Err(DeviceError::CapabilityKindMismatch),
    }
}

fn valid_io_status(status: u16) -> bool {
    matches!(status, 0x0001..=0x0029 | 0x0101..=0x011e)
}

fn parse_output_reply_artifact(value: u8) -> Result<Artifact, DeviceError> {
    let artifact = Artifact::parse(value)?;
    if artifact == Artifact::WatchOnlyBsms {
        Err(DeviceError::ArtifactMismatch)
    } else {
        Ok(artifact)
    }
}

fn valid_input_filename(name: &[u8]) -> bool {
    name.ends_with(b".psbt")
        && name.iter().all(|byte| {
            byte.is_ascii_lowercase() || byte.is_ascii_digit() || matches!(byte, b'.' | b'_' | b'-')
        })
        && !name.contains(&b'/')
        && !name.contains(&b'\\')
}

fn valid_output_filename(artifact: Artifact, name: &[u8]) -> bool {
    let suffix: &[u8] = match artifact {
        Artifact::FinalizedPsbt => b"-final.psbt",
        Artifact::RawTransaction => b"-final.tx",
        _ => return false,
    };
    let expected_len = 3 + 32 + suffix.len();
    name.len() == expected_len
        && &name[..3] == b"qk-"
        && name[3..35]
            .iter()
            .all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f'))
        && &name[35..] == suffix
}

pub(crate) fn validate_output_body(
    capability: Capability,
    body: OutputBody<'_>,
) -> Result<(), DeviceError> {
    match body {
        OutputBody::WriteBegin {
            artifact,
            total_len,
            filename,
        } => {
            if total_len == 0 || total_len as usize > MAX_TRANSFER_BYTES {
                return Err(DeviceError::ValueOutOfRange);
            }
            if filename.len() > MAX_FILENAME_BYTES {
                return Err(DeviceError::FilenameRejected);
            }
            match capability {
                Capability::PrintOutput => {
                    if !matches!(
                        (artifact, total_len),
                        (Artifact::A1PrintArtifact, A1_PRINT_BYTES)
                            | (Artifact::KitPrintArtifact, KIT_PRINT_BYTES)
                    ) {
                        return Err(DeviceError::ArtifactMismatch);
                    }
                    if !filename.is_empty() {
                        return Err(DeviceError::FilenameRejected);
                    }
                }
                Capability::MediaOutput => {
                    if !matches!(artifact, Artifact::FinalizedPsbt | Artifact::RawTransaction) {
                        return Err(DeviceError::ArtifactMismatch);
                    }
                    if !valid_output_filename(artifact, filename) {
                        return Err(DeviceError::FilenameRejected);
                    }
                }
                _ => return Err(DeviceError::CapabilityMismatch),
            }
        }
        OutputBody::WriteChunk { offset, chunk } => {
            if chunk.is_empty() {
                return Err(DeviceError::ChunkLengthZero);
            }
            if chunk.len() > crate::MAX_CHUNK_BYTES {
                return Err(DeviceError::ChunkLengthExceeded);
            }
            let chunk_len =
                u32::try_from(chunk.len()).map_err(|_| DeviceError::TransferLengthExceeded)?;
            offset
                .checked_add(chunk_len)
                .filter(|end| *end <= MAX_TRANSFER_BYTES as u32)
                .ok_or(DeviceError::TransferLengthExceeded)?;
            if !matches!(
                capability,
                Capability::PrintOutput | Capability::MediaOutput
            ) {
                return Err(DeviceError::CapabilityMismatch);
            }
        }
        OutputBody::WriteFinish {
            artifact,
            total_len,
        } => {
            if total_len == 0 || total_len as usize > MAX_TRANSFER_BYTES {
                return Err(DeviceError::ValueOutOfRange);
            }
            let valid = match capability {
                Capability::PrintOutput => matches!(
                    artifact,
                    Artifact::A1PrintArtifact | Artifact::KitPrintArtifact
                ),
                Capability::MediaOutput => {
                    matches!(artifact, Artifact::FinalizedPsbt | Artifact::RawTransaction)
                }
                _ => return Err(DeviceError::CapabilityMismatch),
            };
            if !valid {
                return Err(DeviceError::ArtifactMismatch);
            }
        }
    }
    Ok(())
}

pub(crate) fn validate_input_begin(
    capability: Capability,
    body: InputBody<'_>,
) -> Result<(), DeviceError> {
    let InputBody::Begin {
        source,
        total_len,
        filename,
    } = body
    else {
        return Err(DeviceError::UnexpectedFrame);
    };
    match capability {
        Capability::CameraInput => {
            if filename.is_some() {
                return Err(DeviceError::FilenameRejected);
            }
            let valid = match source {
                Source::CameraA1Candidate => total_len == A1_BYTES,
                Source::CameraKitCandidate => total_len == KIT_BYTES,
                Source::CameraBbqrPsbt => (1..=MAX_TRANSFER_BYTES as u32).contains(&total_len),
                Source::MediaPsbt => false,
            };
            if !valid {
                return Err(DeviceError::SourceMismatch);
            }
        }
        Capability::MediaInput => {
            if source != Source::MediaPsbt {
                return Err(DeviceError::SourceMismatch);
            }
            if !(1..=MAX_TRANSFER_BYTES as u32).contains(&total_len) {
                return Err(DeviceError::ValueOutOfRange);
            }
            let Some(filename) = filename else {
                return Err(DeviceError::FilenameRejected);
            };
            if filename.is_empty()
                || filename.len() > MAX_FILENAME_BYTES
                || !valid_input_filename(filename)
            {
                return Err(DeviceError::FilenameRejected);
            }
        }
        _ => return Err(DeviceError::CapabilityMismatch),
    }
    Ok(())
}

fn exact_length(bytes: &[u8], expected: usize) -> Result<(), DeviceError> {
    if bytes.len() == expected {
        Ok(())
    } else {
        Err(DeviceError::BodyLengthMismatch)
    }
}

fn read_u16(bytes: &[u8]) -> u16 {
    u16::from_le_bytes([bytes[0], bytes[1]])
}

fn read_u32(bytes: &[u8]) -> u32 {
    u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]])
}

fn read_u64(bytes: &[u8]) -> u64 {
    u64::from_le_bytes([
        bytes[0], bytes[1], bytes[2], bytes[3], bytes[4], bytes[5], bytes[6], bytes[7],
    ])
}

struct Cursor<'a> {
    bytes: &'a [u8],
    offset: usize,
}

impl<'a> Cursor<'a> {
    const fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, offset: 0 }
    }

    fn take(&mut self, length: usize) -> Result<&'a [u8], DeviceError> {
        let end = self
            .offset
            .checked_add(length)
            .ok_or(DeviceError::NestedLengthMismatch)?;
        let value = self
            .bytes
            .get(self.offset..end)
            .ok_or(DeviceError::NestedLengthMismatch)?;
        self.offset = end;
        Ok(value)
    }

    fn array<const N: usize>(&mut self) -> Result<&'a [u8; N], DeviceError> {
        self.take(N)?
            .try_into()
            .map_err(|_| DeviceError::NestedLengthMismatch)
    }

    fn byte(&mut self) -> Result<u8, DeviceError> {
        Ok(self.take(1)?[0])
    }

    fn u32(&mut self) -> Result<u32, DeviceError> {
        Ok(read_u32(self.take(4)?))
    }

    fn finish(self) -> Result<(), DeviceError> {
        if self.offset == self.bytes.len() {
            Ok(())
        } else {
            Err(DeviceError::NestedLengthMismatch)
        }
    }
}
