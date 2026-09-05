#![no_main]

use libfuzzer_sys::fuzz_target;
use qk_card_protocol::{
    parse_response, A2Purpose, DescriptorSelector, Instruction, ResponseRef, DESCRIPTOR_BYTES,
};
use qk_core::{
    bind_normal_card_v1, CardInfoV1, CardProcessErrorV1, CoreOutbound, Interruption, KeypadKey,
    NormalErrorV2, NormalProcessControllerV2, NormalProcessErrorV2, NormalProcessEventV2,
    NormalProcessStageV2, NormalProfileV2, NormalStageV2, Source as CoreSource,
};
use qk_device_wire::{
    parse_frame as parse_device_frame, BodyRef, Capability, DeviceError, KeypadBody, LogicalKey,
    MessageKind as DeviceKind, Source as DeviceSource, HEADER_BYTES as DEVICE_HEADER_BYTES,
};
use qk_ipc::{
    encode_frame as encode_ipc_frame, parse_frame as parse_ipc_frame, Direction,
    MessageKind as IpcKind, HEADER_BYTES as IPC_HEADER_BYTES,
};

const SIGNING: &str = include_str!("../../host/qk-psbt/tests/fixtures/signing_finalization_v2.txt");
const PROVISIONING: &str =
    include_str!("../../host/qk-provisioning/tests/fixtures/provisioning_v2.txt");
const CARD: &str = include_str!("../../host/qk-card-protocol/tests/fixtures/card_protocol_v1.txt");

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum SignatureMutation {
    None,
    WrongBinding,
    WrongKey,
    MalformedDer,
    InvalidSignature,
}

#[derive(Clone, Debug, Eq, PartialEq)]
enum FuzzFact {
    DeviceRejected(&'static str),
    CardBindingRejected(&'static str),
    NormalRejected {
        name: &'static str,
        stage: NormalProcessStageV2,
    },
    Accepted {
        profile: NormalProfileV2,
        stages: Vec<NormalProcessStageV2>,
        outbound_lengths: Vec<usize>,
    },
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct Model {
    stage: NormalProcessStageV2,
    terminal_name: Option<&'static str>,
    last_normal_stage: Option<NormalStageV2>,
    mutation: SignatureMutation,
    review_advances: u8,
}

impl Model {
    const fn new(mutation: SignatureMutation) -> Self {
        Self {
            stage: NormalProcessStageV2::AwaitingProfile,
            terminal_name: None,
            last_normal_stage: None,
            mutation,
            review_advances: 0,
        }
    }

    #[allow(clippy::too_many_lines)]
    fn apply(&mut self, command: ModelCommand) -> Option<&'static str> {
        assert!(self.terminal_name.is_none());
        let next = match (self.stage, command) {
            (NormalProcessStageV2::AwaitingProfile, ModelCommand::BindProfile) => {
                NormalProcessStageV2::AwaitingNormalFactor
            }
            (NormalProcessStageV2::AwaitingNormalFactor, ModelCommand::AcceptFactor) => {
                NormalProcessStageV2::Normal(NormalStageV2::NormalStart)
            }
            (
                NormalProcessStageV2::Normal(NormalStageV2::NormalStart),
                ModelCommand::SessionReady,
            ) => NormalProcessStageV2::Normal(NormalStageV2::ProfileBinding),
            (
                NormalProcessStageV2::Normal(NormalStageV2::ProfileBinding),
                ModelCommand::ConfirmProfile,
            ) => NormalProcessStageV2::Normal(NormalStageV2::Transport),
            (NormalProcessStageV2::Normal(NormalStageV2::Transport), ModelCommand::SelectPsbt) => {
                NormalProcessStageV2::Normal(NormalStageV2::PsbtIntake)
            }
            (
                NormalProcessStageV2::Normal(NormalStageV2::PsbtIntake),
                ModelCommand::IngressBegan,
            ) => NormalProcessStageV2::Normal(NormalStageV2::PsbtIntake),
            (
                NormalProcessStageV2::Normal(NormalStageV2::PsbtIntake),
                ModelCommand::IngressFinished,
            ) => NormalProcessStageV2::Normal(NormalStageV2::FactorB),
            (NormalProcessStageV2::Normal(NormalStageV2::FactorB), ModelCommand::AcceptFactorB)
            | (NormalProcessStageV2::Normal(NormalStageV2::A1Intake), ModelCommand::IngressBegan) => {
                NormalProcessStageV2::Normal(NormalStageV2::A1Intake)
            }
            (
                NormalProcessStageV2::Normal(NormalStageV2::A1Intake),
                ModelCommand::IngressFinished,
            ) => NormalProcessStageV2::Normal(NormalStageV2::FactorA1),
            (NormalProcessStageV2::Normal(NormalStageV2::FactorA1), ModelCommand::Validate) => {
                NormalProcessStageV2::Normal(NormalStageV2::Review)
            }
            (NormalProcessStageV2::Normal(NormalStageV2::Review), ModelCommand::AdvanceReview) => {
                self.review_advances = self.review_advances.saturating_add(1);
                if self.review_advances == 12 {
                    NormalProcessStageV2::Normal(NormalStageV2::FinalApproval)
                } else {
                    assert!(self.review_advances < 12);
                    NormalProcessStageV2::Normal(NormalStageV2::Review)
                }
            }
            (
                NormalProcessStageV2::Normal(NormalStageV2::FinalApproval),
                ModelCommand::CompleteHold,
            ) => NormalProcessStageV2::Normal(NormalStageV2::CardBSigning),
            (
                NormalProcessStageV2::Normal(NormalStageV2::CardBSigning),
                ModelCommand::AcceptSignature,
            ) => match self.mutation {
                SignatureMutation::WrongBinding => {
                    return Some(self.reject(
                        "CardSignatureBindingMismatch",
                        Some(NormalStageV2::CardBSigning),
                    ));
                }
                SignatureMutation::WrongKey => {
                    return Some(self.reject(
                        "CardSignatureKeyMismatch",
                        Some(NormalStageV2::CardBSigning),
                    ));
                }
                SignatureMutation::MalformedDer => {
                    return Some(
                        self.reject("CardSignatureMalformed", Some(NormalStageV2::CardBSigning)),
                    );
                }
                SignatureMutation::InvalidSignature => {
                    return Some(
                        self.reject("CardSignatureInvalid", Some(NormalStageV2::CardBSigning)),
                    );
                }
                SignatureMutation::None => {
                    NormalProcessStageV2::Normal(NormalStageV2::AwaitingExportAction)
                }
            },
            (
                NormalProcessStageV2::Normal(NormalStageV2::AwaitingExportAction),
                ModelCommand::SelectSd | ModelCommand::ExportContinues,
            ) => NormalProcessStageV2::Normal(NormalStageV2::AwaitingExportAction),
            (
                NormalProcessStageV2::Normal(NormalStageV2::AwaitingExportAction),
                ModelCommand::ExportFinished,
            )
            | (
                NormalProcessStageV2::Normal(NormalStageV2::TransactionResult),
                ModelCommand::ConfirmResult,
            ) => NormalProcessStageV2::Normal(NormalStageV2::TransactionResult),
            (
                NormalProcessStageV2::Normal(NormalStageV2::TransactionResult),
                ModelCommand::SessionClosed,
            ) => NormalProcessStageV2::Normal(NormalStageV2::CompletedWiped),
            (_, ModelCommand::Reject { name, last_stage }) => {
                return Some(self.reject(name, last_stage));
            }
            _ => panic!("model command is invalid for its current stage"),
        };
        self.stage = next;
        if let NormalProcessStageV2::Normal(normal) = next {
            self.last_normal_stage = Some(normal);
        }
        None
    }

    fn reject(
        &mut self,
        name: &'static str,
        last_normal_stage: Option<NormalStageV2>,
    ) -> &'static str {
        self.stage = NormalProcessStageV2::Terminated;
        self.terminal_name = Some(name);
        self.last_normal_stage = last_normal_stage;
        name
    }

    fn assert_actual(&self, actual: &NormalProcessControllerV2) {
        assert_eq!(actual.stage(), self.stage);
        assert_eq!(actual.fuzz_last_normal_stage(), self.last_normal_stage);
        match (self.terminal_name, actual.terminal_error()) {
            (None, None) => {}
            (Some(expected), Some(error)) => assert_eq!(normal_error_name(error), expected),
            _ => panic!("model and controller terminal facts diverged"),
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum ModelCommand {
    BindProfile,
    AcceptFactor,
    SessionReady,
    ConfirmProfile,
    SelectPsbt,
    IngressBegan,
    IngressFinished,
    AcceptFactorB,
    Validate,
    AdvanceReview,
    CompleteHold,
    AcceptSignature,
    SelectSd,
    ExportContinues,
    ExportFinished,
    ConfirmResult,
    SessionClosed,
    Reject {
        name: &'static str,
        last_stage: Option<NormalStageV2>,
    },
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Checkpoint {
    Ingress,
    Review,
    FinalApproval,
    Export,
    Result,
}

impl Checkpoint {
    const ALL: [Self; 5] = [
        Self::Ingress,
        Self::Review,
        Self::FinalApproval,
        Self::Export,
        Self::Result,
    ];
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Attack {
    HostileQkip,
    InvalidEvent,
    WrongRoute,
    Interruption,
}

impl Attack {
    const fn from_byte(value: u8) -> Self {
        match value % 4 {
            0 => Self::HostileQkip,
            1 => Self::InvalidEvent,
            2 => Self::WrongRoute,
            3 => Self::Interruption,
            _ => unreachable!(),
        }
    }
}

struct Cursor<'a> {
    bytes: &'a [u8],
    offset: usize,
}

impl<'a> Cursor<'a> {
    const fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, offset: 0 }
    }

    fn byte(&mut self) -> u8 {
        let value = self.bytes.get(self.offset).copied().unwrap_or(0);
        self.offset = self.offset.saturating_add(1);
        value
    }

    fn array<const N: usize>(&mut self) -> [u8; N] {
        core::array::from_fn(|_| self.byte())
    }
}

fn field<'a>(source: &'a str, name: &str) -> &'a str {
    source
        .lines()
        .find_map(|line| line.strip_prefix(name)?.strip_prefix(": "))
        .expect("registered public fixture field")
}

#[allow(clippy::chunks_exact_to_as_chunks)]
fn hex_vec(text: &str) -> Vec<u8> {
    assert!(text.len().is_multiple_of(2));
    text.as_bytes()
        .chunks_exact(2)
        .map(|pair| {
            u8::from_str_radix(core::str::from_utf8(pair).expect("ASCII hex"), 16)
                .expect("fixture hex")
        })
        .collect()
}

fn normal_leaf_error_name(error: NormalErrorV2) -> &'static str {
    let name = match error {
        NormalErrorV2::ProfileMissing => "ProfileMissing",
        NormalErrorV2::ProfileUnknown => "ProfileUnknown",
        NormalErrorV2::ProfileMalformed => "ProfileMalformed",
        NormalErrorV2::InvalidTransition => "InvalidTransition",
        NormalErrorV2::WrongIngressSource => "WrongIngressSource",
        NormalErrorV2::CardAbsent => "CardAbsent",
        NormalErrorV2::CardBindingMismatch => "CardBindingMismatch",
        NormalErrorV2::CardDataRejected => "CardDataRejected",
        NormalErrorV2::A1Rejected => "A1Rejected",
        NormalErrorV2::RecoveredWalletMismatch => "RecoveredWalletMismatch",
        NormalErrorV2::ReviewRejected => "ReviewRejected",
        NormalErrorV2::ReviewIncomplete => "ReviewIncomplete",
        NormalErrorV2::ReviewIdentityMismatch => "ReviewIdentityMismatch",
        NormalErrorV2::ApprovalUnavailable => "ApprovalUnavailable",
        NormalErrorV2::PostApprovalYield => "PostApprovalYield",
        NormalErrorV2::RevalidationMismatch => "RevalidationMismatch",
        NormalErrorV2::SigningRejected => "SigningRejected",
        NormalErrorV2::InvalidMockSignature => "InvalidMockSignature",
        NormalErrorV2::FinalizationRejected => "FinalizationRejected",
        NormalErrorV2::ExportRouteUnavailable => "ExportRouteUnavailable",
        NormalErrorV2::ExportArtifactInvariant => "ExportArtifactInvariant",
        NormalErrorV2::ExportReceiptMismatch => "ExportReceiptMismatch",
        NormalErrorV2::BbqrVerificationMismatch => "BbqrVerificationMismatch",
        NormalErrorV2::PartialSdCompletion => "PartialSdCompletion",
        NormalErrorV2::Finished => "Finished",
        NormalErrorV2::Interrupted(reason) => interruption_name(reason),
        NormalErrorV2::Core(_) => "Core",
    };
    assert_eq!(error.name(), name);
    assert_eq!(error.to_string(), name);
    name
}

fn normal_error_name(error: NormalProcessErrorV2) -> &'static str {
    let name = match error {
        NormalProcessErrorV2::CardProfileMismatch => "CardProfileMismatch",
        NormalProcessErrorV2::CardSignatureBindingMismatch => "CardSignatureBindingMismatch",
        NormalProcessErrorV2::CardSignatureKeyMismatch => "CardSignatureKeyMismatch",
        NormalProcessErrorV2::CardSignatureMalformed => "CardSignatureMalformed",
        NormalProcessErrorV2::CardSignatureHighS => "CardSignatureHighS",
        NormalProcessErrorV2::CardSignatureInvalid => "CardSignatureInvalid",
        NormalProcessErrorV2::Normal(error) => normal_leaf_error_name(error),
    };
    assert_eq!(error.name(), name);
    assert_eq!(error.to_string(), name);
    name
}

fn interruption_name(reason: Interruption) -> &'static str {
    let name = match reason {
        Interruption::Cancelled => "Cancelled",
        Interruption::OperationFailed => "OperationFailed",
        Interruption::MediaRemoved => "MediaRemoved",
        Interruption::CardRemoved => "CardRemoved",
        Interruption::SessionTimeout => "SessionTimeout",
        Interruption::Shutdown => "Shutdown",
        Interruption::Restart => "Restart",
        Interruption::PowerLoss => "PowerLoss",
        Interruption::PeerLost => "PeerLost",
        Interruption::CapabilityFailed => "CapabilityFailed",
    };
    assert_eq!(reason.name(), name);
    name
}

fn device_error_name(error: DeviceError) -> &'static str {
    let name = match error {
        DeviceError::DecoderTerminated => "DecoderTerminated",
        DeviceError::HeaderTruncated => "HeaderTruncated",
        DeviceError::MagicMismatch => "MagicMismatch",
        DeviceError::VersionMismatch => "VersionMismatch",
        DeviceError::CapabilityOutOfRange => "CapabilityOutOfRange",
        DeviceError::CapabilityMismatch => "CapabilityMismatch",
        DeviceError::KindOutOfRange => "KindOutOfRange",
        DeviceError::CapabilityKindMismatch => "CapabilityKindMismatch",
        DeviceError::ReservedNonZero => "ReservedNonZero",
        DeviceError::SequenceZero => "SequenceZero",
        DeviceError::SequenceReplay => "SequenceReplay",
        DeviceError::SequenceRegression => "SequenceRegression",
        DeviceError::SequenceSkipped => "SequenceSkipped",
        DeviceError::SequenceExhausted => "SequenceExhausted",
        DeviceError::OutstandingExchange => "OutstandingExchange",
        DeviceError::NoOutstandingExchange => "NoOutstandingExchange",
        DeviceError::ResponseSequenceMismatch => "ResponseSequenceMismatch",
        DeviceError::ResponseKindMismatch => "ResponseKindMismatch",
        DeviceError::BodyLengthExceeded => "BodyLengthExceeded",
        DeviceError::BodyTruncated => "BodyTruncated",
        DeviceError::TrailingByte => "TrailingByte",
        DeviceError::UnexpectedFrame => "UnexpectedFrame",
        DeviceError::ConnectionClosedMidFrame => "ConnectionClosedMidFrame",
        DeviceError::PeerLost => "PeerLost",
        DeviceError::OutputBufferTooSmall => "OutputBufferTooSmall",
        DeviceError::AllocationFailed => "AllocationFailed",
        DeviceError::BodyLengthMismatch => "BodyLengthMismatch",
        DeviceError::ValueOutOfRange => "ValueOutOfRange",
        DeviceError::NestedLengthMismatch => "NestedLengthMismatch",
        DeviceError::CountExceeded => "CountExceeded",
        DeviceError::IndexOrderMismatch => "IndexOrderMismatch",
        DeviceError::OffsetMismatch => "OffsetMismatch",
        DeviceError::ChunkLengthZero => "ChunkLengthZero",
        DeviceError::ChunkLengthExceeded => "ChunkLengthExceeded",
        DeviceError::FinalFlagOutOfRange => "FinalFlagOutOfRange",
        DeviceError::FinalFlagMismatch => "FinalFlagMismatch",
        DeviceError::TransferLengthExceeded => "TransferLengthExceeded",
        DeviceError::TransferIncomplete => "TransferIncomplete",
        DeviceError::SourceMismatch => "SourceMismatch",
        DeviceError::FilenameRejected => "FilenameRejected",
        DeviceError::ArtifactMismatch => "ArtifactMismatch",
        DeviceError::DeviceRejected => "DeviceRejected",
        DeviceError::LegacyNormalFactorRejected => "LegacyNormalFactorRejected",
    };
    assert_eq!(error.name(), name);
    assert_eq!(error.to_string(), name);
    name
}

fn card_binding_error_name(error: CardProcessErrorV1) -> &'static str {
    let name = match error {
        CardProcessErrorV1::UnexpectedResponse => "CardUnexpectedResponse",
        CardProcessErrorV1::RecordRejected => "CardRecordRejected",
        CardProcessErrorV1::InfoRecordVersionMismatch => "CardInfoRecordVersionMismatch",
        CardProcessErrorV1::InfoLifecycleMismatch => "CardInfoLifecycleMismatch",
        CardProcessErrorV1::InfoProfileMismatch => "CardInfoProfileMismatch",
        CardProcessErrorV1::InfoRoleMismatch => "CardInfoRoleMismatch",
        CardProcessErrorV1::InfoOperationMaskMismatch => "CardInfoOperationMaskMismatch",
        CardProcessErrorV1::DescriptorRejected => "CardDescriptorRejected",
        CardProcessErrorV1::DescriptorByteMismatch => "CardDescriptorByteMismatch",
        CardProcessErrorV1::WalletBindingMismatch => "CardWalletBindingMismatch",
        CardProcessErrorV1::OriginFingerprintMismatch => "CardOriginFingerprintMismatch",
        CardProcessErrorV1::AccountXpubMismatch => "CardAccountXpubMismatch",
        CardProcessErrorV1::CardDataRejected => "CardDataRejected",
    };
    assert_eq!(error.name(), name);
    assert_eq!(error.to_string(), name);
    name
}

fn profile(selector: u8) -> (&'static [u8; 2], u8, NormalProfileV2) {
    match selector % 3 {
        0 => (b"01", 1, NormalProfileV2::SimpleRecovery),
        1 => (b"02", 2, NormalProfileV2::Inheritance),
        2 => (b"03", 3, NormalProfileV2::QuantumShelter),
        _ => unreachable!("modulo three is exhaustive"),
    }
}

fn descriptors() -> [[u8; DESCRIPTOR_BYTES]; 2] {
    let mut descriptors = [[0u8; DESCRIPTOR_BYTES]; 2];
    for (field_name, expected_selector, expected_offset, target, start) in [
        (
            "normal_read_1_0_response_hex",
            DescriptorSelector::Receive,
            0u16,
            0usize,
            0usize,
        ),
        (
            "normal_read_1_192_response_hex",
            DescriptorSelector::Receive,
            192,
            0,
            192,
        ),
        (
            "normal_read_2_0_response_hex",
            DescriptorSelector::Change,
            0,
            1,
            0,
        ),
        (
            "normal_read_2_192_response_hex",
            DescriptorSelector::Change,
            192,
            1,
            192,
        ),
    ] {
        let response = hex_vec(field(CARD, field_name));
        let ResponseRef::ReadDChunk {
            selector,
            offset,
            bytes,
            ..
        } = parse_response(Instruction::ReadDChunk, &response).expect("registered READ_D response")
        else {
            panic!("registered READ_D response kind");
        };
        assert_eq!(selector, expected_selector);
        assert_eq!(offset, expected_offset);
        let end = start
            .checked_add(bytes.len())
            .expect("registered descriptor chunk bound");
        descriptors[target][start..end].copy_from_slice(bytes);
    }
    assert_eq!(
        descriptors[0].as_slice(),
        field(CARD, "receive_descriptor").as_bytes()
    );
    assert_eq!(
        descriptors[1].as_slice(),
        field(CARD, "change_descriptor").as_bytes()
    );
    descriptors
}

fn a2() -> [u8; 32] {
    let response = hex_vec(field(CARD, "normal_a2_response_hex"));
    let ResponseRef::ExportA2 {
        purpose: A2Purpose::Normal,
        a2,
        ..
    } = parse_response(Instruction::ExportA2, &response).expect("registered EXPORT_A2 response")
    else {
        panic!("registered EXPORT_A2 response kind");
    };
    assert_eq!(a2.as_slice(), hex_vec(field(CARD, "a2_hex")));
    *a2
}

fn bound_card(
    selected_profile: NormalProfileV2,
) -> Result<qk_core::NormalCardBDataV2, CardProcessErrorV1> {
    let mut response = hex_vec(field(CARD, "normal_info_response_hex"));
    assert_eq!(response.len(), 160);
    response[24] = match selected_profile {
        NormalProfileV2::SimpleRecovery => 1,
        NormalProfileV2::Inheritance => 2,
        NormalProfileV2::QuantumShelter => 3,
    };
    let info = CardInfoV1::try_from_response(
        parse_response(Instruction::GetInfo, &response).expect("registered INFO response"),
    )?;
    let mut a2 = a2();
    let result = bind_normal_card_v1(selected_profile, info, descriptors(), &mut a2);
    assert!(a2.iter().all(|byte| *byte == 0));
    result
}

fn signature_reply(
    mutation: SignatureMutation,
    expected_review_hash: [u8; 32],
) -> ([u8; 32], u32, [u8; 33], Vec<u8>) {
    let response = hex_vec(field(CARD, "normal_sign_0_response_hex"));
    let ResponseRef::SignDigest {
        review_hash,
        input_index,
        public_key,
        signature_der,
        ..
    } = parse_response(Instruction::SignDigest, &response).expect("registered SIGN response")
    else {
        panic!("registered SIGN response kind");
    };
    assert_eq!(
        review_hash.as_slice(),
        hex_vec(field(CARD, "review_hash_hex"))
    );
    let mut review_hash = expected_review_hash;
    let mut public_key = *public_key;
    let mut signature_der = signature_der.to_vec();
    match mutation {
        SignatureMutation::None => {}
        SignatureMutation::WrongBinding => review_hash[0] ^= 1,
        SignatureMutation::WrongKey => public_key[32] ^= 1,
        SignatureMutation::MalformedDer => {
            signature_der = vec![0x30; 7];
        }
        SignatureMutation::InvalidSignature => {
            signature_der[10] ^= 1;
        }
    }
    (review_hash, input_index, public_key, signature_der)
}

fn raw_device_frame(capability: Capability, kind: DeviceKind, body: &[u8]) -> Vec<u8> {
    let mut frame = Vec::with_capacity(DEVICE_HEADER_BYTES + body.len());
    frame.extend_from_slice(b"QKDV");
    frame.extend_from_slice(&[1, capability.wire_value(), kind.wire_value(), 0]);
    frame.extend_from_slice(&1u32.to_le_bytes());
    frame.extend_from_slice(
        &u32::try_from(body.len())
            .expect("bounded device body")
            .to_le_bytes(),
    );
    frame.extend_from_slice(body);
    frame
}

struct OuterOracle {
    session_id: [u8; 16],
    last_exchange_id: u32,
}

impl OuterOracle {
    fn open(outbound: &CoreOutbound) -> Self {
        let frame = parse_ipc_frame(outbound.frame_bytes())
            .expect("qk-core emitted one complete opening QKIP frame");
        assert_eq!(frame.header().direction(), Direction::CoreToIo);
        assert_eq!(frame.header().kind(), IpcKind::SessionOpen);
        assert_eq!(frame.header().exchange_id(), 1);
        assert_eq!(frame.header().payload_len(), 0);
        assert!(frame.payload().is_empty());
        assert_eq!(outbound.frame_bytes().len(), IPC_HEADER_BYTES);
        Self {
            session_id: *frame.header().session_id(),
            last_exchange_id: 1,
        }
    }

    fn assert_request(&mut self, outbound: &CoreOutbound, kind: IpcKind, payload: &[u8]) {
        let frame = parse_ipc_frame(outbound.frame_bytes())
            .expect("qk-core emitted one complete QKIP request");
        assert_eq!(frame.header().direction(), Direction::CoreToIo);
        assert_eq!(frame.header().kind(), kind);
        assert_eq!(frame.header().session_id(), &self.session_id);
        let expected_exchange = self
            .last_exchange_id
            .checked_add(1)
            .expect("bounded model exchange count");
        assert_eq!(frame.header().exchange_id(), expected_exchange);
        assert_eq!(
            usize::try_from(frame.header().payload_len()).expect("HOST usize"),
            payload.len()
        );
        assert_eq!(frame.payload(), payload);
        assert_eq!(
            outbound.frame_bytes().len(),
            IPC_HEADER_BYTES + payload.len()
        );
        self.last_exchange_id = expected_exchange;
    }
}

fn inner_request(opcode: u8, body: &[u8]) -> Vec<u8> {
    let mut request = Vec::with_capacity(8 + body.len());
    request.extend_from_slice(&[1, opcode, 0, 0]);
    request.extend_from_slice(
        &u32::try_from(body.len())
            .expect("bounded inner body")
            .to_le_bytes(),
    );
    request.extend_from_slice(body);
    request
}

fn expected_ingress_begin(source: CoreSource) -> Vec<u8> {
    inner_request(1, &[source.wire_value(), 0, 0])
}

fn expected_ingress_read(offset: u32) -> Vec<u8> {
    inner_request(2, &offset.to_le_bytes())
}

fn sd_filename(caller_nonce: &[u8; 16], artifact: u8) -> Vec<u8> {
    const LOWER_HEX: &[u8; 16] = b"0123456789abcdef";
    let suffix: &[u8] = match artifact {
        1 => b"-final.psbt",
        2 => b"-final.tx",
        _ => panic!("closed artifact byte"),
    };
    let mut filename = Vec::with_capacity(35 + suffix.len());
    filename.extend_from_slice(b"qk-");
    for byte in caller_nonce {
        filename.push(LOWER_HEX[usize::from(byte >> 4)]);
        filename.push(LOWER_HEX[usize::from(byte & 0x0f)]);
    }
    filename.extend_from_slice(suffix);
    filename
}

fn expected_sd_begin(artifact: u8, total: u32, caller_nonce: &[u8; 16]) -> Vec<u8> {
    let filename = sd_filename(caller_nonce, artifact);
    let mut body = Vec::with_capacity(9 + filename.len());
    body.extend_from_slice(&[1, artifact]);
    body.extend_from_slice(&total.to_le_bytes());
    body.extend_from_slice(
        &u16::try_from(1usize + filename.len())
            .expect("bounded filename auxiliary data")
            .to_le_bytes(),
    );
    body.push(u8::try_from(filename.len()).expect("bounded filename"));
    body.extend_from_slice(&filename);
    inner_request(3, &body)
}

fn expected_egress_write(offset: u32, bytes: &[u8]) -> Vec<u8> {
    let mut body = Vec::with_capacity(8 + bytes.len());
    body.extend_from_slice(&offset.to_le_bytes());
    body.extend_from_slice(
        &u32::try_from(bytes.len())
            .expect("bounded egress chunk")
            .to_le_bytes(),
    );
    body.extend_from_slice(bytes);
    inner_request(4, &body)
}

fn expected_egress_finish() -> Vec<u8> {
    inner_request(5, &[])
}

fn outer_payload(outbound: &CoreOutbound) -> &[u8] {
    parse_ipc_frame(outbound.frame_bytes())
        .expect("qk-core emitted canonical QKIP")
        .payload()
}

fn outer_response(request: &CoreOutbound, kind: IpcKind, payload: &[u8]) -> Vec<u8> {
    let request = parse_ipc_frame(request.frame_bytes()).expect("qk-core emitted canonical QKIP");
    let mut output = vec![0u8; IPC_HEADER_BYTES + payload.len()];
    let written = encode_ipc_frame(
        Direction::IoToCore,
        kind,
        *request.header().session_id(),
        request.header().exchange_id(),
        payload,
        &mut output,
    )
    .expect("bounded canonical response");
    assert_eq!(written, output.len());
    output
}

fn inner_success(opcode: u8, body: &[u8]) -> Vec<u8> {
    let mut payload = Vec::with_capacity(8 + body.len());
    payload.extend_from_slice(&[1, opcode, 0, 0]);
    payload.extend_from_slice(
        &u32::try_from(body.len())
            .expect("bounded response body")
            .to_le_bytes(),
    );
    payload.extend_from_slice(body);
    payload
}

fn operation_response(request: &CoreOutbound, opcode: u8, body: &[u8]) -> Vec<u8> {
    outer_response(
        request,
        IpcKind::OperationResponse,
        &inner_success(opcode, body),
    )
}

fn drive_ingress(
    controller: &mut NormalProcessControllerV2,
    model: &mut Model,
    outer: &mut OuterOracle,
    begin: &CoreOutbound,
    source: CoreSource,
    bytes: &[u8],
    lengths: &mut Vec<usize>,
) -> Result<(), FuzzFact> {
    lengths.push(begin.frame_bytes().len());
    let mut began_body = Vec::with_capacity(5);
    began_body.push(source.wire_value());
    began_body.extend_from_slice(
        &u32::try_from(bytes.len())
            .expect("bounded ingress fixture")
            .to_le_bytes(),
    );
    let begin_response = operation_response(begin, 1, &began_body);
    let received = controller.receive_qkip(&begin_response, false);
    let read = checked(controller, model, ModelCommand::IngressBegan, received)?
        .expect("ingress begin must produce the first read request");
    outer.assert_request(&read, IpcKind::OperationRequest, &expected_ingress_read(0));
    lengths.push(read.frame_bytes().len());
    let mut chunk_body = Vec::with_capacity(9 + bytes.len());
    chunk_body.extend_from_slice(&0u32.to_le_bytes());
    chunk_body.extend_from_slice(
        &u32::try_from(bytes.len())
            .expect("bounded ingress fixture")
            .to_le_bytes(),
    );
    chunk_body.push(1);
    chunk_body.extend_from_slice(bytes);
    let chunk = operation_response(&read, 2, &chunk_body);
    let received = controller.receive_qkip(&chunk, false);
    assert!(checked(controller, model, ModelCommand::IngressFinished, received)?.is_none());
    Ok(())
}

#[allow(clippy::too_many_lines)]
fn drive_sd_export(
    controller: &mut NormalProcessControllerV2,
    model: &mut Model,
    outer: &mut OuterOracle,
    mut outbound: CoreOutbound,
    selected_profile: NormalProfileV2,
    lengths: &mut Vec<usize>,
) -> Result<(), FuzzFact> {
    let mut artifact = None;
    let expected_finish_count = match selected_profile {
        NormalProfileV2::SimpleRecovery | NormalProfileV2::Inheritance => 2,
        NormalProfileV2::QuantumShelter => 1,
    };
    let finalized_psbt = hex_vec(field(SIGNING, "finalized_psbt_hex"));
    let raw_transaction = hex_vec(field(SIGNING, "raw_transaction_hex"));
    let expected_artifacts = match selected_profile {
        NormalProfileV2::SimpleRecovery | NormalProfileV2::Inheritance => {
            vec![(1u8, finalized_psbt), (2u8, raw_transaction)]
        }
        NormalProfileV2::QuantumShelter => vec![(2u8, raw_transaction)],
    };
    let mut finish_count = 0usize;
    for _ in 0..16 {
        lengths.push(outbound.frame_bytes().len());
        let payload = outer_payload(&outbound);
        assert!(
            payload.len() >= 8,
            "modelled export request omitted its fixed header"
        );
        let opcode = payload[1];
        let response_body = match opcode {
            3 => {
                assert!(
                    payload.len() >= 14 && payload[8] == 1,
                    "modelled export begin body diverged"
                );
                let (expected_kind, expected_bytes) = expected_artifacts
                    .get(finish_count)
                    .expect("one registered artifact per export begin");
                let expected_total =
                    u32::try_from(expected_bytes.len()).expect("bounded fixture artifact");
                outer.assert_request(
                    &outbound,
                    IpcKind::OperationRequest,
                    &expected_sd_begin(*expected_kind, expected_total, &[0x51; 16]),
                );
                assert!(artifact.is_none());
                artifact = Some((
                    payload[9],
                    u32::from_le_bytes(payload[10..14].try_into().expect("total")),
                ));
                Vec::new()
            }
            4 => {
                assert!(payload.len() >= 16, "modelled export write body diverged");
                let (_, expected_bytes) = expected_artifacts
                    .get(finish_count)
                    .expect("one registered artifact per export write");
                outer.assert_request(
                    &outbound,
                    IpcKind::OperationRequest,
                    &expected_egress_write(0, expected_bytes),
                );
                let offset = u32::from_le_bytes(payload[8..12].try_into().expect("offset"));
                let length = usize::try_from(u32::from_le_bytes(
                    payload[12..16].try_into().expect("length"),
                ))
                .expect("HOST usize");
                let next = usize::try_from(offset)
                    .expect("HOST usize")
                    .checked_add(length)
                    .expect("bounded fixture transfer");
                assert_eq!(
                    payload.len(),
                    16 + length,
                    "modelled export chunk length diverged"
                );
                u32::try_from(next)
                    .expect("bounded export offset")
                    .to_le_bytes()
                    .to_vec()
            }
            5 => {
                outer.assert_request(
                    &outbound,
                    IpcKind::OperationRequest,
                    &expected_egress_finish(),
                );
                let (kind, total) = artifact.take().expect("finish follows export begin");
                let (expected_kind, expected_bytes) = expected_artifacts
                    .get(finish_count)
                    .expect("one registered artifact per export finish");
                assert_eq!(kind, *expected_kind);
                assert_eq!(
                    usize::try_from(total).expect("HOST usize"),
                    expected_bytes.len()
                );
                let mut receipt = vec![1, kind];
                receipt.extend_from_slice(&total.to_le_bytes());
                receipt
            }
            _ => panic!("modelled export opcode is closed"),
        };
        let response = operation_response(&outbound, opcode, &response_body);
        let received = controller.receive_qkip(&response, false);
        let completes = opcode == 5 && finish_count.saturating_add(1) == expected_finish_count;
        let command = if completes {
            ModelCommand::ExportFinished
        } else {
            ModelCommand::ExportContinues
        };
        match checked(controller, model, command, received)? {
            Some(next) => {
                if opcode == 5 {
                    finish_count = finish_count.saturating_add(1);
                }
                outbound = next;
            }
            None if matches!(
                controller.stage(),
                NormalProcessStageV2::Normal(NormalStageV2::TransactionResult)
            ) =>
            {
                assert_eq!(opcode, 5);
                finish_count = finish_count.saturating_add(1);
                assert_eq!(finish_count, expected_finish_count);
                return Ok(());
            }
            None => panic!("modelled export stopped before its final receipt"),
        }
    }
    panic!("modelled export exceeded its bounded request count")
}

fn controller(
    profile_ascii: &[u8],
    cursor: &mut Cursor<'_>,
) -> Result<NormalProcessControllerV2, NormalProcessErrorV2> {
    let namespace = cursor.array::<12>();
    let last_counter = u32::from_le_bytes(cursor.array::<4>()).min(u32::MAX - 1);
    NormalProcessControllerV2::fuzz_start(profile_ascii, namespace, last_counter)
}

fn normal_rejection(
    controller: &mut NormalProcessControllerV2,
    error: NormalProcessErrorV2,
) -> FuzzFact {
    let name = normal_error_name(error);
    let stage = controller.stage();
    assert_eq!(stage, NormalProcessStageV2::Terminated);
    assert_eq!(controller.terminal_error(), Some(error));
    let Err(repeated) = controller.handle_event(NormalProcessEventV2::SessionTimeout) else {
        panic!("terminal controller accepted a later event");
    };
    assert_eq!(repeated, error);
    assert_eq!(controller.stage(), stage);
    assert_eq!(controller.terminal_error(), Some(error));
    FuzzFact::NormalRejected { name, stage }
}

fn checked<T>(
    controller: &mut NormalProcessControllerV2,
    model: &mut Model,
    command: ModelCommand,
    result: Result<T, NormalProcessErrorV2>,
) -> Result<T, FuzzFact> {
    let expected_error = model.apply(command);
    match (expected_error, result) {
        (None, Ok(value)) => {
            model.assert_actual(controller);
            Ok(value)
        }
        (Some(expected), Err(error)) => {
            assert_eq!(normal_error_name(error), expected);
            model.assert_actual(controller);
            let stage = controller.stage();
            let Err(repeated) = controller.handle_event(NormalProcessEventV2::SessionTimeout)
            else {
                panic!("terminated controller accepted a later command");
            };
            assert_eq!(repeated, error);
            model.assert_actual(controller);
            Err(FuzzFact::NormalRejected {
                name: expected,
                stage,
            })
        }
        (None, Err(error)) => panic!("model expected success but implementation returned {error}"),
        (Some(expected), Ok(_)) => {
            panic!("model expected terminating rejection {expected} but command succeeded")
        }
    }
}

fn setup_controller(
    data: &[u8],
    mutation: SignatureMutation,
) -> Result<
    (
        NormalProcessControllerV2,
        CoreOutbound,
        NormalProfileV2,
        Model,
    ),
    FuzzFact,
> {
    let mut cursor = Cursor::new(data);
    let _selector = cursor.byte();
    let _mutation_selector = cursor.byte();
    let (profile_ascii, profile_wire, selected_profile) = profile(cursor.byte());
    let mut controller =
        controller(profile_ascii, &mut cursor).map_err(|error| FuzzFact::NormalRejected {
            name: normal_error_name(error),
            stage: NormalProcessStageV2::Terminated,
        })?;
    let mut model = Model::new(mutation);
    model.assert_actual(&controller);
    let accepted = controller.accept_profile(profile_wire);
    checked(
        &mut controller,
        &mut model,
        ModelCommand::BindProfile,
        accepted,
    )?;
    let card = bound_card(selected_profile).expect("registered APDU facts bind");
    let accepted = controller.fuzz_accept_bound_card(card);
    let opening = checked(
        &mut controller,
        &mut model,
        ModelCommand::AcceptFactor,
        accepted,
    )?;
    Ok((controller, opening, selected_profile, model))
}

#[allow(clippy::too_many_lines)]
fn run_scenario(
    data: &[u8],
    mutation: SignatureMutation,
    injection: Option<(Checkpoint, Attack)>,
) -> FuzzFact {
    let (mut controller, opening, selected_profile, mut model) =
        match setup_controller(data, mutation) {
            Ok(value) => value,
            Err(fact) => return fact,
        };
    let mut outer = OuterOracle::open(&opening);
    let mut stages = vec![controller.stage()];
    let mut outbound_lengths = vec![opening.frame_bytes().len()];
    let ready = outer_response(&opening, IpcKind::SessionReady, &[]);
    let received = controller.receive_qkip(&ready, false);
    if let Err(fact) = checked(
        &mut controller,
        &mut model,
        ModelCommand::SessionReady,
        received,
    ) {
        return fact;
    }
    stages.push(controller.stage());
    let confirmed = controller.handle_event(NormalProcessEventV2::LogicalKey(
        KeypadKey::EqualsConfirmEnter,
    ));
    if let Err(fact) = checked(
        &mut controller,
        &mut model,
        ModelCommand::ConfirmProfile,
        confirmed,
    ) {
        return fact;
    }
    stages.push(controller.stage());

    let source = if data.get(3).copied().unwrap_or(0) & 1 == 0 {
        CoreSource::MediaPsbt
    } else {
        CoreSource::CameraBbqrPsbt
    };
    let selected = controller.handle_event(NormalProcessEventV2::SelectPsbtSource(source));
    let begin = match checked(
        &mut controller,
        &mut model,
        ModelCommand::SelectPsbt,
        selected,
    ) {
        Ok(Some(value)) => value,
        Ok(None) => panic!("PSBT source selection omitted its ingress request"),
        Err(fact) => return fact,
    };
    outer.assert_request(
        &begin,
        IpcKind::OperationRequest,
        &expected_ingress_begin(source),
    );
    if let Some((Checkpoint::Ingress, attack)) = injection {
        return inject(&mut controller, &mut model, Checkpoint::Ingress, attack);
    }
    let psbt = hex_vec(field(SIGNING, "s0_hex"));
    if let Err(fact) = drive_ingress(
        &mut controller,
        &mut model,
        &mut outer,
        &begin,
        source,
        &psbt,
        &mut outbound_lengths,
    ) {
        return fact;
    }
    stages.push(controller.stage());
    let advanced = controller.advance_automatic();
    let a1_begin = match checked(
        &mut controller,
        &mut model,
        ModelCommand::AcceptFactorB,
        advanced,
    ) {
        Ok(Some(value)) => value,
        Ok(None) => panic!("accepted factor did not open A1 ingress"),
        Err(fact) => return fact,
    };
    stages.push(controller.stage());
    outer.assert_request(
        &a1_begin,
        IpcKind::OperationRequest,
        &expected_ingress_begin(CoreSource::CameraA1Candidate),
    );
    let a1 = hex_vec(field(PROVISIONING, "a1_capsule_hex"));
    if let Err(fact) = drive_ingress(
        &mut controller,
        &mut model,
        &mut outer,
        &a1_begin,
        CoreSource::CameraA1Candidate,
        &a1,
        &mut outbound_lengths,
    ) {
        return fact;
    }
    stages.push(controller.stage());
    let validated = controller.advance_automatic();
    if let Err(fact) = checked(
        &mut controller,
        &mut model,
        ModelCommand::Validate,
        validated,
    ) {
        return fact;
    }
    stages.push(controller.stage());
    if let Some((Checkpoint::Review, attack)) = injection {
        return inject(&mut controller, &mut model, Checkpoint::Review, attack);
    }

    for _ in 0..12 {
        let advanced = controller.handle_event(NormalProcessEventV2::LogicalKey(
            KeypadKey::EqualsConfirmEnter,
        ));
        if let Err(fact) = checked(
            &mut controller,
            &mut model,
            ModelCommand::AdvanceReview,
            advanced,
        ) {
            return fact;
        }
        stages.push(controller.stage());
    }
    assert_eq!(
        controller.stage(),
        NormalProcessStageV2::Normal(NormalStageV2::FinalApproval)
    );
    if let Some((Checkpoint::FinalApproval, attack)) = injection {
        return inject(
            &mut controller,
            &mut model,
            Checkpoint::FinalApproval,
            attack,
        );
    }
    let before_hold = drain_display_stages(&mut controller);
    assert!(!before_hold.contains(&NormalStageV2::Revalidation));
    assert!(!before_hold.contains(&NormalStageV2::CardBSigning));
    let held = controller.handle_event(NormalProcessEventV2::HoldCompleted);
    if let Err(fact) = checked(
        &mut controller,
        &mut model,
        ModelCommand::CompleteHold,
        held,
    ) {
        return fact;
    }
    assert_eq!(
        drain_display_stages(&mut controller),
        [
            NormalStageV2::ApprovalHeld,
            NormalStageV2::Revalidation,
            NormalStageV2::TerminalASigning,
            NormalStageV2::CardBSigning,
        ]
    );
    let request = controller
        .card_b_signing_request()
        .expect("CardBSigning exposes one immutable request");
    assert_eq!(request.input_index(), 0);
    assert_eq!(
        request.role_b_pubkey().as_slice(),
        hex_vec(field(CARD, "route_public_key_hex"))
    );
    assert_eq!(
        request.digest().as_slice(),
        hex_vec(field(CARD, "digest_hex"))
    );
    let expected_review_hash = *request.review_hash();
    drop(request);
    let (review_hash, input_index, public_key, mut signature) =
        signature_reply(mutation, expected_review_hash);
    let accepted =
        controller.accept_card_b_signature(review_hash, input_index, public_key, &mut signature);
    let signature_outcome = checked(
        &mut controller,
        &mut model,
        ModelCommand::AcceptSignature,
        accepted,
    );
    assert!(signature.iter().all(|byte| *byte == 0));
    match signature_outcome {
        Ok(None) => {}
        Ok(Some(_)) => panic!("card signature unexpectedly yielded transport"),
        Err(fact) => return fact,
    }
    stages.push(controller.stage());

    let selected = controller.handle_event(NormalProcessEventV2::SelectSd {
        caller_nonce: [0x51; 16],
    });
    let begin = match checked(
        &mut controller,
        &mut model,
        ModelCommand::SelectSd,
        selected,
    ) {
        Ok(Some(value)) => value,
        Ok(None) => panic!("SD selection omitted its first write request"),
        Err(fact) => return fact,
    };
    if let Some((Checkpoint::Export, attack)) = injection {
        let first_kind = if selected_profile == NormalProfileV2::QuantumShelter {
            2
        } else {
            1
        };
        let first_bytes = if first_kind == 1 {
            hex_vec(field(SIGNING, "finalized_psbt_hex"))
        } else {
            hex_vec(field(SIGNING, "raw_transaction_hex"))
        };
        outer.assert_request(
            &begin,
            IpcKind::OperationRequest,
            &expected_sd_begin(
                first_kind,
                u32::try_from(first_bytes.len()).expect("bounded fixture artifact"),
                &[0x51; 16],
            ),
        );
        return inject(&mut controller, &mut model, Checkpoint::Export, attack);
    }
    if let Err(fact) = drive_sd_export(
        &mut controller,
        &mut model,
        &mut outer,
        begin,
        selected_profile,
        &mut outbound_lengths,
    ) {
        return fact;
    }
    stages.push(controller.stage());
    if let Some((Checkpoint::Result, attack)) = injection {
        return inject(&mut controller, &mut model, Checkpoint::Result, attack);
    }
    let confirmed = controller.handle_event(NormalProcessEventV2::LogicalKey(
        KeypadKey::EqualsConfirmEnter,
    ));
    let close = match checked(
        &mut controller,
        &mut model,
        ModelCommand::ConfirmResult,
        confirmed,
    ) {
        Ok(Some(value)) => value,
        Ok(None) => panic!("result confirmation omitted close request"),
        Err(fact) => return fact,
    };
    outer.assert_request(&close, IpcKind::SessionClose, &[]);
    outbound_lengths.push(close.frame_bytes().len());
    let closed = outer_response(&close, IpcKind::SessionClosed, &[]);
    let received = controller.receive_qkip(&closed, false);
    if let Err(fact) = checked(
        &mut controller,
        &mut model,
        ModelCommand::SessionClosed,
        received,
    ) {
        return fact;
    }
    stages.push(controller.stage());
    assert_eq!(
        controller.stage(),
        NormalProcessStageV2::Normal(NormalStageV2::CompletedWiped)
    );
    FuzzFact::Accepted {
        profile: selected_profile,
        stages,
        outbound_lengths,
    }
}

fn run_complete(data: &[u8], mutation: SignatureMutation) -> FuzzFact {
    run_scenario(data, mutation, None)
}

fn inject(
    controller: &mut NormalProcessControllerV2,
    model: &mut Model,
    checkpoint: Checkpoint,
    attack: Attack,
) -> FuzzFact {
    let last_stage = match model.stage {
        NormalProcessStageV2::Normal(stage) => Some(stage),
        _ => panic!("checkpoint injection requires an active Normal owner"),
    };
    let (expected, result) = match attack {
        Attack::HostileQkip => {
            let expected = if checkpoint == Checkpoint::Result {
                "PostApprovalYield"
            } else {
                "Core"
            };
            (expected, controller.receive_qkip(&[], true).map(|_| ()))
        }
        Attack::InvalidEvent => (
            "InvalidTransition",
            controller
                .handle_event(NormalProcessEventV2::LogicalKey(KeypadKey::Seven))
                .map(|_| ()),
        ),
        Attack::WrongRoute => {
            let expected = if checkpoint == Checkpoint::Export {
                "PostApprovalYield"
            } else {
                "InvalidTransition"
            };
            (
                expected,
                controller
                    .handle_event(NormalProcessEventV2::SelectBbqr {
                        non_final_part_len: 5,
                    })
                    .map(|_| ()),
            )
        }
        Attack::Interruption => {
            let event = if matches!(checkpoint, Checkpoint::FinalApproval | Checkpoint::Result) {
                NormalProcessEventV2::SessionTimeout
            } else {
                NormalProcessEventV2::CardRemoved
            };
            let expected = if matches!(event, NormalProcessEventV2::SessionTimeout) {
                "SessionTimeout"
            } else {
                "CardRemoved"
            };
            (expected, controller.handle_event(event).map(|_| ()))
        }
    };
    let command = ModelCommand::Reject {
        name: expected,
        last_stage,
    };
    match checked(controller, model, command, result) {
        Ok(()) => panic!("hostile checkpoint injection was accepted"),
        Err(fact) => fact,
    }
}

fn drain_display_stages(controller: &mut NormalProcessControllerV2) -> Vec<NormalStageV2> {
    let mut stages = Vec::new();
    while let Some(stage) = controller.fuzz_take_display_stage() {
        stages.push(stage);
    }
    stages
}

fn map_key(key: LogicalKey) -> KeypadKey {
    match key {
        LogicalKey::Seven => KeypadKey::Seven,
        LogicalKey::EightUp => KeypadKey::EightUp,
        LogicalKey::Nine => KeypadKey::Nine,
        LogicalKey::CeDelete => KeypadKey::CeDelete,
        LogicalKey::CancelBack => KeypadKey::CancelBack,
        LogicalKey::FourLeft => KeypadKey::FourLeft,
        LogicalKey::Five => KeypadKey::Five,
        LogicalKey::SixRight => KeypadKey::SixRight,
        LogicalKey::Multiply => KeypadKey::Multiply,
        LogicalKey::Divide => KeypadKey::Divide,
        LogicalKey::One => KeypadKey::One,
        LogicalKey::TwoDown => KeypadKey::TwoDown,
        LogicalKey::Three => KeypadKey::Three,
        LogicalKey::Minus => KeypadKey::Minus,
        LogicalKey::Percent => KeypadKey::Percent,
        LogicalKey::Zero => KeypadKey::Zero,
        LogicalKey::Decimal => KeypadKey::Decimal,
        LogicalKey::Plus => KeypadKey::Plus,
        LogicalKey::EqualsConfirmEnter => KeypadKey::EqualsConfirmEnter,
    }
}

fn map_source(source: DeviceSource) -> CoreSource {
    match source {
        DeviceSource::CameraA1Candidate => CoreSource::CameraA1Candidate,
        DeviceSource::CameraKitCandidate => CoreSource::CameraKitCandidate,
        DeviceSource::CameraBbqrPsbt => CoreSource::CameraBbqrPsbt,
        DeviceSource::MediaPsbt => CoreSource::MediaPsbt,
    }
}

fn map_event(body: KeypadBody) -> NormalProcessEventV2 {
    match body {
        KeypadBody::LogicalKey(key) => NormalProcessEventV2::LogicalKey(map_key(key)),
        KeypadBody::SelectPsbtSource(source) => {
            NormalProcessEventV2::SelectPsbtSource(map_source(source))
        }
        KeypadBody::HoldCompleted => NormalProcessEventV2::HoldCompleted,
        KeypadBody::SelectSd { caller_nonce } => NormalProcessEventV2::SelectSd { caller_nonce },
        KeypadBody::SelectBbqr { non_final_part_len } => {
            NormalProcessEventV2::SelectBbqr { non_final_part_len }
        }
        KeypadBody::CardRemoved => NormalProcessEventV2::CardRemoved,
        KeypadBody::SessionTimeout => NormalProcessEventV2::SessionTimeout,
    }
}

fn fuzz_keypad(data: &[u8]) -> FuzzFact {
    let body = data.get(1..).unwrap_or_default();
    let raw = raw_device_frame(Capability::Keypad, DeviceKind::KeypadEvent, body);
    let frame = match parse_device_frame(Capability::Keypad, &raw) {
        Ok(value) => value,
        Err(error) => return FuzzFact::DeviceRejected(device_error_name(error)),
    };
    let event = match frame.parsed_body() {
        Ok(BodyRef::Keypad(body)) => map_event(body),
        Ok(_) => return FuzzFact::DeviceRejected("UnexpectedFrame"),
        Err(error) => return FuzzFact::DeviceRejected(device_error_name(error)),
    };
    let (mut controller, opening, selected_profile, _model) =
        match setup_controller(data, SignatureMutation::None) {
            Ok(value) => value,
            Err(fact) => return fact,
        };
    let _outer = OuterOracle::open(&opening);
    let ready = outer_response(&opening, IpcKind::SessionReady, &[]);
    if let Err(error) = controller.receive_qkip(&ready, false) {
        return normal_rejection(&mut controller, error);
    }
    match controller.handle_event(event) {
        Ok(outbound) => FuzzFact::Accepted {
            profile: selected_profile,
            stages: vec![controller.stage()],
            outbound_lengths: outbound
                .as_ref()
                .map(|value| vec![value.frame_bytes().len()])
                .unwrap_or_default(),
        },
        Err(error) => normal_rejection(&mut controller, error),
    }
}

fn fuzz_profile(data: &[u8]) -> FuzzFact {
    let mut cursor = Cursor::new(data);
    let profile_ascii = data.get(1..).unwrap_or_default();
    match controller(profile_ascii, &mut cursor) {
        Ok(controller) => FuzzFact::Accepted {
            profile: controller.selected_profile(),
            stages: vec![controller.stage()],
            outbound_lengths: Vec::new(),
        },
        Err(error) => FuzzFact::NormalRejected {
            name: normal_error_name(error),
            stage: NormalProcessStageV2::Terminated,
        },
    }
}

fn fuzz_card_binding(data: &[u8]) -> FuzzFact {
    let (_, profile_wire, selected_profile) = profile(data.first().copied().unwrap_or(0));
    let mut response = hex_vec(field(CARD, "normal_info_response_hex"));
    response[24] = profile_wire;
    let mut descriptor_pair = descriptors();
    let mutation = data.get(1).copied().unwrap_or(0) % 8;
    let expected = match mutation {
        0 => None,
        1 => {
            response[23] = 0;
            response[24] = 0;
            response[26..156].fill(0);
            response[156..158].copy_from_slice(&0x0011u16.to_be_bytes());
            Some("CardInfoLifecycleMismatch")
        }
        2 => {
            response[24] = if profile_wire == 3 {
                1
            } else {
                profile_wire + 1
            };
            Some("CardInfoProfileMismatch")
        }
        3 => {
            response[156..158].copy_from_slice(&0x0007u16.to_be_bytes());
            Some("CardInfoOperationMaskMismatch")
        }
        4 => {
            response[42] ^= 1;
            Some("CardWalletBindingMismatch")
        }
        5 => {
            response[74] ^= 1;
            Some("CardOriginFingerprintMismatch")
        }
        6 => {
            response[155] ^= 1;
            Some("CardAccountXpubMismatch")
        }
        7 => {
            descriptor_pair[0][0] ^= 1;
            Some("CardDescriptorRejected")
        }
        _ => unreachable!("modulo eight is exhaustive"),
    };
    let parsed = parse_response(Instruction::GetInfo, &response)
        .expect("mutated response remains byte-grammatical");
    let info = CardInfoV1::try_from_response(parsed).expect("owned INFO response");
    let mut a2 = a2();
    let result = bind_normal_card_v1(selected_profile, info, descriptor_pair, &mut a2);
    assert!(a2.iter().all(|byte| *byte == 0));
    match (expected, result) {
        (None, Ok(_)) => FuzzFact::Accepted {
            profile: selected_profile,
            stages: vec![NormalProcessStageV2::AwaitingNormalFactor],
            outbound_lengths: Vec::new(),
        },
        (Some(name), Err(error)) => {
            assert_eq!(card_binding_error_name(error), name);
            FuzzFact::CardBindingRejected(name)
        }
        (None, Err(error)) => panic!("registered binding rejected: {error}"),
        (Some(name), Ok(_)) => panic!("mutated card binding accepted instead of {name}"),
    }
}

fn fuzz_qkip(data: &[u8]) -> FuzzFact {
    let (mut controller, opening, selected_profile, _model) =
        match setup_controller(data, SignatureMutation::None) {
            Ok(value) => value,
            Err(fact) => return fact,
        };
    match controller.receive_qkip(
        data.get(2..).unwrap_or_default(),
        data.get(1).copied().unwrap_or(0) & 1 != 0,
    ) {
        Ok(outbound) => FuzzFact::Accepted {
            profile: selected_profile,
            stages: vec![controller.stage()],
            outbound_lengths: core::iter::once(opening.frame_bytes().len())
                .chain(outbound.as_ref().map(|value| value.frame_bytes().len()))
                .collect(),
        },
        Err(error) => normal_rejection(&mut controller, error),
    }
}

fn fuzz_legacy_factor(data: &[u8]) -> FuzzFact {
    let request = data.get(1).copied().unwrap_or(0) & 1 == 0;
    let (capability, kind) = if request {
        (Capability::CardRequest, DeviceKind::CardReadNormalFactor)
    } else {
        (Capability::CardResponse, DeviceKind::CardNormalFactor)
    };
    let raw = raw_device_frame(capability, kind, data.get(2..).unwrap_or_default());
    let frame = match parse_device_frame(capability, &raw) {
        Ok(value) => value,
        Err(error) => return FuzzFact::DeviceRejected(device_error_name(error)),
    };
    match frame.parsed_body() {
        Err(error) => FuzzFact::DeviceRejected(device_error_name(error)),
        Ok(_) => panic!("active decoder accepted legacy NormalFactor"),
    }
}

fn admitted(data: &[u8]) -> bool {
    data.iter()
        .fold(0x9du8, |state, byte| state.wrapping_mul(33) ^ byte)
        == 0
}

fn assert_signature_outcome(mutation: SignatureMutation, fact: &FuzzFact) {
    let expected_rejection = match mutation {
        SignatureMutation::None => None,
        SignatureMutation::WrongBinding => Some("CardSignatureBindingMismatch"),
        SignatureMutation::WrongKey => Some("CardSignatureKeyMismatch"),
        SignatureMutation::MalformedDer => Some("CardSignatureMalformed"),
        SignatureMutation::InvalidSignature => Some("CardSignatureInvalid"),
    };
    match (expected_rejection, fact) {
        (None, FuzzFact::Accepted { .. }) => {}
        (Some(expected), FuzzFact::NormalRejected { name, .. }) => assert_eq!(name, &expected),
        _ => panic!("signature mutation produced the wrong closed outcome"),
    }
}

fuzz_target!(|data: &[u8]| {
    let selector = data.first().copied().unwrap_or(0);
    let fact = if selector == b'V' && admitted(data) {
        let mutation = match data.get(1).copied().unwrap_or(0) % 5 {
            0 => SignatureMutation::None,
            1 => SignatureMutation::WrongBinding,
            2 => SignatureMutation::WrongKey,
            3 => SignatureMutation::MalformedDer,
            4 => SignatureMutation::InvalidSignature,
            _ => unreachable!("modulo five is exhaustive"),
        };
        let fact = run_complete(data, mutation);
        assert_signature_outcome(mutation, &fact);
        for (index, checkpoint) in Checkpoint::ALL.into_iter().enumerate() {
            let attack = Attack::from_byte(
                data.get(index.saturating_add(2))
                    .copied()
                    .unwrap_or(u8::try_from(index).expect("five bounded checkpoints")),
            );
            assert!(matches!(
                run_scenario(data, SignatureMutation::None, Some((checkpoint, attack))),
                FuzzFact::NormalRejected { .. }
            ));
        }
        fact
    } else {
        let exercise = || match selector % 5 {
            0 => fuzz_profile(data),
            1 => fuzz_card_binding(data),
            2 => fuzz_keypad(data),
            3 => fuzz_qkip(data),
            4 => fuzz_legacy_factor(data),
            _ => unreachable!("modulo five is exhaustive"),
        };
        exercise()
    };
    match fact {
        FuzzFact::DeviceRejected(name)
        | FuzzFact::CardBindingRejected(name)
        | FuzzFact::NormalRejected { name, .. } => {
            assert!(!name.is_empty());
        }
        FuzzFact::Accepted { .. } => {}
    }
});
