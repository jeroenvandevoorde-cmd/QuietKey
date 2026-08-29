//! Deterministic v2 slice-5 HOST-only screen-flow topology.
//!
//! This parallel machine selects already-bound public facts and models only
//! event order, logical wiping, and the explicitly deferred Kit boundaries.
//! It has no renderer, signer, card, scanner, exporter, or approval authority.

use crate::screen_flow::KeypadKey;
use crate::{ExportArtifacts, ReviewReadyV3, SdArtifactMetadata, TierArtifacts};
use qk_provisioning::ProvisioningArtifactsV2;
use qk_psbt::{
    DirectRbf, FeePolicyV2Facts, FeeWarning, RecipientType, ReviewNetwork, ReviewV3, ReviewV3Hash,
    ReviewV3Output, ReviewV3OutputOwnership,
};
use std::sync::atomic::{AtomicU64, Ordering};

static NEXT_SCREEN_FLOW_V2_PROVENANCE: AtomicU64 = AtomicU64::new(0);

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum FlowKindV2 {
    Setup,
    A1B,
    Kit,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ScreenKindV2 {
    SetupStart,
    TierSelection,
    EntropyModeSelection,
    CeremonyInput,
    CeremonyEcho,
    CeremonyConfirm,
    CeremonyCommitment,
    DerivationExplanation,
    ProvisioningResult,
    ProvisionB,
    VerifyB,
    SpareBSelection,
    ProvisionSpareB,
    VerifySpareB,
    CreateA1,
    ScanBackA1,
    CoordinatorMaterial,
    CreateTwoKits,
    VerifyTwoKits,
    Rehearsal,
    SetupReady,
    NormalStart,
    Transport,
    Intake,
    FactorB,
    FactorA1,
    Validation,
    ReviewOverview,
    ReviewArithmetic,
    ReviewRecipient,
    ReviewChange,
    ReviewOpReturn,
    ReviewLocktime,
    ReviewSequence,
    ReviewFeePolicy,
    FinalApproval,
    AwaitingSigning,
    Export,
    TransactionResult,
    KitStart,
    KitDoorSelection,
    KitDoorConfirmation,
    ScanKitShareOne,
    ScanKitShareTwo,
    CombineKitShares,
    KitSpendTransaction,
    KitSpendValidation,
    KitSpendCompleteness,
    KitSpendDeferred,
    KitRestoreActionSelection,
    CardRemainsConfirmation,
    KitRestoreDeferred,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CeremonyPurposeV2 {
    SeedA,
    SignerB,
    KitR,
    A2,
}

impl CeremonyPurposeV2 {
    const fn next(self) -> Option<Self> {
        match self {
            Self::SeedA => Some(Self::SignerB),
            Self::SignerB => Some(Self::KitR),
            Self::KitR => Some(Self::A2),
            Self::A2 => None,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum EntropyInputModeV2 {
    DiceGrid,
    ManualKeypad,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum KitDoorV2 {
    KitSpend,
    KitRestore,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SpareBChoiceV2 {
    NoSpare,
    ProvisionSpare,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum KitRestoreActionV2 {
    ReplacementB,
    A1Reprint,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CardRemainsStatementV2 {
    InHand,
    Missing,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DeferredBoundaryV2 {
    KitSpendSlice11,
    KitRestoreSlice10,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum WipingReasonV2 {
    InvalidTransition,
    Cancelled,
    OperationFailed,
    MediaRemoved,
    CardRemoved,
    SessionTimeout,
    Shutdown,
    Restart,
    PowerLoss,
    DoorSwitchAttempt,
    KitScannerModeMismatch,
    ReviewIncomplete,
    ReviewIdentityMismatch,
    PostApprovalYield,
    RestoreSigningProhibited,
    MissingCardRequiresKitSpend,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum StatePreservingRejectionV2 {
    DiceGridUnavailable,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum FlowTerminalV2 {
    CompletedWiped,
    DeferredWiped(DeferredBoundaryV2),
    FailedWiped(WipingReasonV2),
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct FlowFinishedV2;

#[derive(Clone, Copy, Eq, PartialEq)]
pub struct ApprovalTokenV2 {
    provenance: u64,
    cycle: u64,
}

#[derive(Clone, Copy, Eq, PartialEq)]
pub struct ApprovalIdentityV2 {
    token: ApprovalTokenV2,
    review_hash: ReviewV3Hash,
}

impl ApprovalIdentityV2 {
    #[must_use]
    pub const fn token(self) -> ApprovalTokenV2 {
        self.token
    }

    #[must_use]
    pub const fn review_hash(self) -> ReviewV3Hash {
        self.review_hash
    }
}

#[derive(Clone, Copy)]
pub enum CompletedOperationV2<'a> {
    Plain,
    Provisioning(&'a ProvisioningArtifactsV2),
    Review(&'a ReviewReadyV3),
    Export(&'a ExportArtifacts),
}

#[derive(Clone, Copy)]
pub enum FlowEventV2<'a> {
    Key(KeypadKey),
    OperationCompleted(CompletedOperationV2<'a>),
    OperationFailed,
    CeremonyCommitmentReady([u8; 32]),
    SelectSpareB(SpareBChoiceV2),
    TransportPresented,
    CameraPresented,
    IntakePresented,
    PsbtPresented,
    A1Presented,
    BbqrTransactionPresented,
    CoordinatorPresented,
    MediaRemoved,
    ApprovalHoldStarted,
    ApprovalHoldCompleted(ApprovalTokenV2),
    SigningOutcome { identity: ApprovalIdentityV2 },
    SelectKitDoor(KitDoorV2),
    ConfirmKitDoor(KitDoorV2),
    KitShareAccepted,
    KitSpendTransactionPresented,
    KitSpendValidated,
    CoordinatorUtxoCompletenessConfirmed,
    SelectKitRestoreAction(KitRestoreActionV2),
    CardRemainsStatement(CardRemainsStatementV2),
    CardRemoved,
    SessionTimeout,
    Shutdown,
    Restart,
    PowerLoss,
}

#[derive(Clone, Copy)]
pub struct CeremonyCommitmentV2View<'a> {
    commitment: &'a [u8; 32],
}

impl<'a> CeremonyCommitmentV2View<'a> {
    #[must_use]
    pub const fn bytes(self) -> &'a [u8; 32] {
        self.commitment
    }
}

#[derive(Clone, Copy)]
pub struct ProvisioningResultV2View<'a> {
    facts: &'a ProvisioningArtifactsV2,
}

impl ProvisioningResultV2View<'_> {
    #[must_use]
    pub const fn wallet_id(&self) -> [u8; 32] {
        self.facts.wallet_id
    }
}

#[derive(Clone, Copy)]
pub struct ReviewOverviewV2View {
    network: ReviewNetwork,
    wallet_id: [u8; 32],
    input_count: usize,
    total_input_amount: u64,
}

impl ReviewOverviewV2View {
    #[must_use]
    pub const fn network(&self) -> ReviewNetwork {
        self.network
    }

    #[must_use]
    pub const fn wallet_id(&self) -> [u8; 32] {
        self.wallet_id
    }

    #[must_use]
    pub const fn input_count(&self) -> usize {
        self.input_count
    }

    #[must_use]
    pub const fn total_input_amount(&self) -> u64 {
        self.total_input_amount
    }
}

#[derive(Clone, Copy)]
pub struct ReviewArithmeticV2View {
    total_input_amount: u64,
    total_output_amount: u64,
    fee: u64,
}

impl ReviewArithmeticV2View {
    #[must_use]
    pub const fn total_input_amount(&self) -> u64 {
        self.total_input_amount
    }

    #[must_use]
    pub const fn total_output_amount(&self) -> u64 {
        self.total_output_amount
    }

    #[must_use]
    pub const fn fee(&self) -> u64 {
        self.fee
    }
}

#[derive(Clone, Copy)]
pub enum RecipientFactV2View<'a> {
    External {
        recipient_type: RecipientType,
        data: &'a [u8],
    },
    SelfTransfer {
        child_index: u32,
        witness_program: &'a [u8],
    },
}

#[derive(Clone, Copy)]
pub struct ReviewRecipientV2View<'a> {
    index: u32,
    amount: u64,
    script_pubkey: &'a [u8],
    recipient: RecipientFactV2View<'a>,
}

impl<'a> ReviewRecipientV2View<'a> {
    #[must_use]
    pub const fn index(&self) -> u32 {
        self.index
    }

    #[must_use]
    pub const fn amount(&self) -> u64 {
        self.amount
    }

    #[must_use]
    pub const fn script_pubkey(&self) -> &'a [u8] {
        self.script_pubkey
    }

    #[must_use]
    pub const fn recipient(&self) -> RecipientFactV2View<'a> {
        self.recipient
    }
}

#[derive(Clone, Copy)]
pub struct ReviewChangeV2View<'a> {
    index: u32,
    amount: u64,
    script_pubkey: &'a [u8],
    child_index: u32,
}

impl<'a> ReviewChangeV2View<'a> {
    #[must_use]
    pub const fn index(&self) -> u32 {
        self.index
    }

    #[must_use]
    pub const fn amount(&self) -> u64 {
        self.amount
    }

    #[must_use]
    pub const fn script_pubkey(&self) -> &'a [u8] {
        self.script_pubkey
    }

    #[must_use]
    pub const fn child_index(&self) -> u32 {
        self.child_index
    }
}

#[derive(Clone, Copy)]
pub struct ReviewOpReturnV2View<'a> {
    index: u32,
    amount: u64,
    script_pubkey: &'a [u8],
    payload: &'a [u8],
}

impl<'a> ReviewOpReturnV2View<'a> {
    #[must_use]
    pub const fn index(&self) -> u32 {
        self.index
    }

    #[must_use]
    pub const fn amount(&self) -> u64 {
        self.amount
    }

    #[must_use]
    pub const fn script_pubkey(&self) -> &'a [u8] {
        self.script_pubkey
    }

    #[must_use]
    pub const fn payload(&self) -> &'a [u8] {
        self.payload
    }
}

#[derive(Clone, Copy)]
pub struct ReviewLocktimeV2View {
    locktime: u32,
}

impl ReviewLocktimeV2View {
    #[must_use]
    pub const fn locktime(self) -> u32 {
        self.locktime
    }
}

#[derive(Clone, Copy)]
pub struct ReviewSequenceV2View {
    input_index: u32,
    sequence: u32,
    direct_rbf: DirectRbf,
}

impl ReviewSequenceV2View {
    #[must_use]
    pub const fn input_index(&self) -> u32 {
        self.input_index
    }

    #[must_use]
    pub const fn sequence(&self) -> u32 {
        self.sequence
    }

    #[must_use]
    pub const fn direct_rbf(&self) -> DirectRbf {
        self.direct_rbf
    }
}

#[derive(Clone, Copy)]
pub struct ReviewFeePolicyV2View {
    identifier: &'static [u8],
    fee: u64,
    fee_policy: FeePolicyV2Facts,
}

impl ReviewFeePolicyV2View {
    #[must_use]
    pub const fn identifier(&self) -> &'static [u8] {
        self.identifier
    }

    #[must_use]
    pub const fn fee(&self) -> u64 {
        self.fee
    }

    #[must_use]
    pub const fn estimated_vsize(&self) -> u32 {
        self.fee_policy.estimated_vsize()
    }

    #[must_use]
    pub const fn fee_rate_msat_per_vbyte(&self) -> u64 {
        self.fee_policy.fee_rate_msat_per_vbyte()
    }

    pub fn warnings(&self) -> impl Iterator<Item = FeeWarning> {
        self.fee_policy.warnings()
    }
}

#[derive(Clone, Copy)]
pub struct FinalApprovalV2View {
    review_hash: ReviewV3Hash,
}

impl FinalApprovalV2View {
    #[must_use]
    pub const fn review_hash(self) -> ReviewV3Hash {
        self.review_hash
    }
}

#[derive(Clone, Copy)]
pub struct TransactionResultV2View {
    finalized_psbt: Option<SdArtifactMetadata>,
    raw_transaction: SdArtifactMetadata,
}

impl TransactionResultV2View {
    #[must_use]
    pub const fn finalized_psbt(self) -> Option<SdArtifactMetadata> {
        self.finalized_psbt
    }

    #[must_use]
    pub const fn raw_transaction(self) -> SdArtifactMetadata {
        self.raw_transaction
    }
}

#[derive(Clone, Copy)]
pub enum ScreenV2<'a> {
    SetupStart,
    TierSelection,
    EntropyModeSelection {
        selected: EntropyInputModeV2,
    },
    CeremonyInput {
        purpose: CeremonyPurposeV2,
        mode: EntropyInputModeV2,
    },
    CeremonyEcho {
        purpose: CeremonyPurposeV2,
        mode: EntropyInputModeV2,
    },
    CeremonyConfirm {
        purpose: CeremonyPurposeV2,
        mode: EntropyInputModeV2,
    },
    CeremonyCommitment {
        purpose: CeremonyPurposeV2,
        mode: EntropyInputModeV2,
        commitment: CeremonyCommitmentV2View<'a>,
    },
    DerivationExplanation,
    ProvisioningResult(ProvisioningResultV2View<'a>),
    ProvisionB,
    VerifyB,
    SpareBSelection,
    ProvisionSpareB,
    VerifySpareB,
    CreateA1,
    ScanBackA1,
    CoordinatorMaterial,
    CreateTwoKits,
    VerifyTwoKits,
    Rehearsal,
    SetupReady,
    NormalStart,
    Transport,
    Intake,
    FactorB,
    FactorA1,
    Validation,
    ReviewOverview(ReviewOverviewV2View),
    ReviewArithmetic(ReviewArithmeticV2View),
    ReviewRecipient(ReviewRecipientV2View<'a>),
    ReviewChange(ReviewChangeV2View<'a>),
    ReviewOpReturn(ReviewOpReturnV2View<'a>),
    ReviewLocktime(ReviewLocktimeV2View),
    ReviewSequence(ReviewSequenceV2View),
    ReviewFeePolicy(ReviewFeePolicyV2View),
    FinalApproval(FinalApprovalV2View),
    AwaitingSigning,
    Export,
    TransactionResult(TransactionResultV2View),
    KitStart,
    KitDoorSelection,
    KitDoorConfirmation {
        door: KitDoorV2,
    },
    ScanKitShareOne {
        door: KitDoorV2,
    },
    ScanKitShareTwo {
        door: KitDoorV2,
    },
    CombineKitShares {
        door: KitDoorV2,
    },
    KitSpendTransaction,
    KitSpendValidation,
    KitSpendCompleteness,
    KitSpendDeferred,
    KitRestoreActionSelection,
    CardRemainsConfirmation,
    KitRestoreDeferred {
        action: KitRestoreActionV2,
    },
}

impl ScreenV2<'_> {
    #[must_use]
    pub const fn kind(&self) -> ScreenKindV2 {
        match self {
            Self::SetupStart => ScreenKindV2::SetupStart,
            Self::TierSelection => ScreenKindV2::TierSelection,
            Self::EntropyModeSelection { .. } => ScreenKindV2::EntropyModeSelection,
            Self::CeremonyInput { .. } => ScreenKindV2::CeremonyInput,
            Self::CeremonyEcho { .. } => ScreenKindV2::CeremonyEcho,
            Self::CeremonyConfirm { .. } => ScreenKindV2::CeremonyConfirm,
            Self::CeremonyCommitment { .. } => ScreenKindV2::CeremonyCommitment,
            Self::DerivationExplanation => ScreenKindV2::DerivationExplanation,
            Self::ProvisioningResult(_) => ScreenKindV2::ProvisioningResult,
            Self::ProvisionB => ScreenKindV2::ProvisionB,
            Self::VerifyB => ScreenKindV2::VerifyB,
            Self::SpareBSelection => ScreenKindV2::SpareBSelection,
            Self::ProvisionSpareB => ScreenKindV2::ProvisionSpareB,
            Self::VerifySpareB => ScreenKindV2::VerifySpareB,
            Self::CreateA1 => ScreenKindV2::CreateA1,
            Self::ScanBackA1 => ScreenKindV2::ScanBackA1,
            Self::CoordinatorMaterial => ScreenKindV2::CoordinatorMaterial,
            Self::CreateTwoKits => ScreenKindV2::CreateTwoKits,
            Self::VerifyTwoKits => ScreenKindV2::VerifyTwoKits,
            Self::Rehearsal => ScreenKindV2::Rehearsal,
            Self::SetupReady => ScreenKindV2::SetupReady,
            Self::NormalStart => ScreenKindV2::NormalStart,
            Self::Transport => ScreenKindV2::Transport,
            Self::Intake => ScreenKindV2::Intake,
            Self::FactorB => ScreenKindV2::FactorB,
            Self::FactorA1 => ScreenKindV2::FactorA1,
            Self::Validation => ScreenKindV2::Validation,
            Self::ReviewOverview(_) => ScreenKindV2::ReviewOverview,
            Self::ReviewArithmetic(_) => ScreenKindV2::ReviewArithmetic,
            Self::ReviewRecipient(_) => ScreenKindV2::ReviewRecipient,
            Self::ReviewChange(_) => ScreenKindV2::ReviewChange,
            Self::ReviewOpReturn(_) => ScreenKindV2::ReviewOpReturn,
            Self::ReviewLocktime(_) => ScreenKindV2::ReviewLocktime,
            Self::ReviewSequence(_) => ScreenKindV2::ReviewSequence,
            Self::ReviewFeePolicy(_) => ScreenKindV2::ReviewFeePolicy,
            Self::FinalApproval(_) => ScreenKindV2::FinalApproval,
            Self::AwaitingSigning => ScreenKindV2::AwaitingSigning,
            Self::Export => ScreenKindV2::Export,
            Self::TransactionResult(_) => ScreenKindV2::TransactionResult,
            Self::KitStart => ScreenKindV2::KitStart,
            Self::KitDoorSelection => ScreenKindV2::KitDoorSelection,
            Self::KitDoorConfirmation { .. } => ScreenKindV2::KitDoorConfirmation,
            Self::ScanKitShareOne { .. } => ScreenKindV2::ScanKitShareOne,
            Self::ScanKitShareTwo { .. } => ScreenKindV2::ScanKitShareTwo,
            Self::CombineKitShares { .. } => ScreenKindV2::CombineKitShares,
            Self::KitSpendTransaction => ScreenKindV2::KitSpendTransaction,
            Self::KitSpendValidation => ScreenKindV2::KitSpendValidation,
            Self::KitSpendCompleteness => ScreenKindV2::KitSpendCompleteness,
            Self::KitSpendDeferred => ScreenKindV2::KitSpendDeferred,
            Self::KitRestoreActionSelection => ScreenKindV2::KitRestoreActionSelection,
            Self::CardRemainsConfirmation => ScreenKindV2::CardRemainsConfirmation,
            Self::KitRestoreDeferred { .. } => ScreenKindV2::KitRestoreDeferred,
        }
    }
}

#[derive(Clone, Copy)]
enum MachineStateV2 {
    Screen(ScreenKindV2),
    Terminal(FlowTerminalV2),
}

#[derive(Clone, Copy, Eq, PartialEq)]
enum ReviewCursorV2 {
    Overview,
    Arithmetic,
    Recipient(usize),
    Change(usize),
    OpReturn(usize),
    Locktime,
    Sequence(usize),
    FeePolicy,
    FinalApproval,
}

pub struct ScreenFlowV2 {
    flow: FlowKindV2,
    state: MachineStateV2,
    entropy_mode: EntropyInputModeV2,
    ceremony_purpose: CeremonyPurposeV2,
    ceremony_confirmed: bool,
    ceremony_commitment: Option<[u8; 32]>,
    door: Option<KitDoorV2>,
    restore_action: Option<KitRestoreActionV2>,
    provenance: Option<u64>,
    next_cycle: u64,
    approval: Option<ApprovalIdentityV2>,
}

#[must_use]
pub struct ProvisioningResultSessionV2<'flow, 'facts> {
    flow: &'flow mut ScreenFlowV2,
    facts: &'facts ProvisioningArtifactsV2,
    active: bool,
}

#[must_use]
pub struct ReviewSessionV2<'flow, 'facts> {
    flow: &'flow mut ScreenFlowV2,
    ready: &'facts ReviewReadyV3,
    cursor: ReviewCursorV2,
    review_complete: bool,
    pending_hold: Option<ApprovalTokenV2>,
    active: bool,
}

#[must_use]
pub struct TransactionResultSessionV2<'flow, 'facts> {
    flow: &'flow mut ScreenFlowV2,
    _export: &'facts ExportArtifacts,
    view: TransactionResultV2View,
    active: bool,
}

pub enum FlowApplyOutcomeV2<'flow, 'facts> {
    Continue(ScreenKindV2),
    Rejected(StatePreservingRejectionV2),
    ProvisioningResult(ProvisioningResultSessionV2<'flow, 'facts>),
    Review(ReviewSessionV2<'flow, 'facts>),
    TransactionResult(TransactionResultSessionV2<'flow, 'facts>),
    CompletedWiped,
    DeferredWiped(DeferredBoundaryV2),
    FailedWiped(WipingReasonV2),
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ScopedApplyOutcomeV2 {
    Continue(ScreenKindV2),
    Released(ScreenKindV2),
    CompletedWiped,
    DeferredWiped(DeferredBoundaryV2),
    FailedWiped(WipingReasonV2),
}

pub enum ReviewSessionOutcomeV2<'flow, 'facts> {
    Continue(ReviewSessionV2<'flow, 'facts>),
    Released(ScopedApplyOutcomeV2),
}

impl ScreenFlowV2 {
    #[must_use]
    pub fn new(flow: FlowKindV2) -> Self {
        let provenance = NEXT_SCREEN_FLOW_V2_PROVENANCE
            .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |value| {
                value.checked_add(1)
            })
            .ok();
        let state = match provenance {
            Some(_) => MachineStateV2::Screen(match flow {
                FlowKindV2::Setup => ScreenKindV2::SetupStart,
                FlowKindV2::A1B => ScreenKindV2::NormalStart,
                FlowKindV2::Kit => ScreenKindV2::KitStart,
            }),
            None => MachineStateV2::Terminal(FlowTerminalV2::FailedWiped(
                WipingReasonV2::OperationFailed,
            )),
        };
        Self {
            flow,
            state,
            entropy_mode: EntropyInputModeV2::DiceGrid,
            ceremony_purpose: CeremonyPurposeV2::SeedA,
            ceremony_confirmed: false,
            ceremony_commitment: None,
            door: None,
            restore_action: None,
            provenance,
            next_cycle: 0,
            approval: None,
        }
    }

    #[must_use]
    pub const fn flow_kind(&self) -> FlowKindV2 {
        self.flow
    }

    #[must_use]
    pub const fn screen_kind(&self) -> Option<ScreenKindV2> {
        match self.state {
            MachineStateV2::Screen(kind) => Some(kind),
            MachineStateV2::Terminal(_) => None,
        }
    }

    #[must_use]
    pub const fn terminal(&self) -> Option<FlowTerminalV2> {
        match self.state {
            MachineStateV2::Screen(_) => None,
            MachineStateV2::Terminal(terminal) => Some(terminal),
        }
    }

    #[must_use]
    pub const fn is_finished(&self) -> bool {
        matches!(self.state, MachineStateV2::Terminal(_))
    }

    #[must_use]
    pub const fn approval_identity(&self) -> Option<ApprovalIdentityV2> {
        self.approval
    }

    #[must_use]
    pub const fn selected_kit_door(&self) -> Option<KitDoorV2> {
        self.door
    }

    #[must_use]
    pub fn screen(&self) -> Option<ScreenV2<'_>> {
        Some(match self.screen_kind()? {
            ScreenKindV2::SetupStart => ScreenV2::SetupStart,
            ScreenKindV2::TierSelection => ScreenV2::TierSelection,
            ScreenKindV2::EntropyModeSelection => ScreenV2::EntropyModeSelection {
                selected: self.entropy_mode,
            },
            ScreenKindV2::CeremonyInput => ScreenV2::CeremonyInput {
                purpose: self.ceremony_purpose,
                mode: self.entropy_mode,
            },
            ScreenKindV2::CeremonyEcho => ScreenV2::CeremonyEcho {
                purpose: self.ceremony_purpose,
                mode: self.entropy_mode,
            },
            ScreenKindV2::CeremonyConfirm => ScreenV2::CeremonyConfirm {
                purpose: self.ceremony_purpose,
                mode: self.entropy_mode,
            },
            ScreenKindV2::CeremonyCommitment => ScreenV2::CeremonyCommitment {
                purpose: self.ceremony_purpose,
                mode: self.entropy_mode,
                commitment: CeremonyCommitmentV2View {
                    commitment: self.ceremony_commitment.as_ref()?,
                },
            },
            ScreenKindV2::DerivationExplanation => ScreenV2::DerivationExplanation,
            ScreenKindV2::ProvisionB => ScreenV2::ProvisionB,
            ScreenKindV2::VerifyB => ScreenV2::VerifyB,
            ScreenKindV2::SpareBSelection => ScreenV2::SpareBSelection,
            ScreenKindV2::ProvisionSpareB => ScreenV2::ProvisionSpareB,
            ScreenKindV2::VerifySpareB => ScreenV2::VerifySpareB,
            ScreenKindV2::CreateA1 => ScreenV2::CreateA1,
            ScreenKindV2::ScanBackA1 => ScreenV2::ScanBackA1,
            ScreenKindV2::CoordinatorMaterial => ScreenV2::CoordinatorMaterial,
            ScreenKindV2::CreateTwoKits => ScreenV2::CreateTwoKits,
            ScreenKindV2::VerifyTwoKits => ScreenV2::VerifyTwoKits,
            ScreenKindV2::Rehearsal => ScreenV2::Rehearsal,
            ScreenKindV2::SetupReady => ScreenV2::SetupReady,
            ScreenKindV2::NormalStart => ScreenV2::NormalStart,
            ScreenKindV2::Transport => ScreenV2::Transport,
            ScreenKindV2::Intake => ScreenV2::Intake,
            ScreenKindV2::FactorB => ScreenV2::FactorB,
            ScreenKindV2::FactorA1 => ScreenV2::FactorA1,
            ScreenKindV2::Validation => ScreenV2::Validation,
            ScreenKindV2::AwaitingSigning => ScreenV2::AwaitingSigning,
            ScreenKindV2::Export => ScreenV2::Export,
            ScreenKindV2::KitStart => ScreenV2::KitStart,
            ScreenKindV2::KitDoorSelection => ScreenV2::KitDoorSelection,
            ScreenKindV2::KitDoorConfirmation => ScreenV2::KitDoorConfirmation { door: self.door? },
            ScreenKindV2::ScanKitShareOne => ScreenV2::ScanKitShareOne { door: self.door? },
            ScreenKindV2::ScanKitShareTwo => ScreenV2::ScanKitShareTwo { door: self.door? },
            ScreenKindV2::CombineKitShares => ScreenV2::CombineKitShares { door: self.door? },
            ScreenKindV2::KitSpendTransaction => ScreenV2::KitSpendTransaction,
            ScreenKindV2::KitSpendValidation => ScreenV2::KitSpendValidation,
            ScreenKindV2::KitSpendCompleteness => ScreenV2::KitSpendCompleteness,
            ScreenKindV2::KitSpendDeferred => ScreenV2::KitSpendDeferred,
            ScreenKindV2::KitRestoreActionSelection => ScreenV2::KitRestoreActionSelection,
            ScreenKindV2::CardRemainsConfirmation => ScreenV2::CardRemainsConfirmation,
            ScreenKindV2::KitRestoreDeferred => ScreenV2::KitRestoreDeferred {
                action: self.restore_action?,
            },
            ScreenKindV2::ProvisioningResult
            | ScreenKindV2::ReviewOverview
            | ScreenKindV2::ReviewArithmetic
            | ScreenKindV2::ReviewRecipient
            | ScreenKindV2::ReviewChange
            | ScreenKindV2::ReviewOpReturn
            | ScreenKindV2::ReviewLocktime
            | ScreenKindV2::ReviewSequence
            | ScreenKindV2::ReviewFeePolicy
            | ScreenKindV2::FinalApproval
            | ScreenKindV2::TransactionResult => return None,
        })
    }

    pub fn apply<'flow, 'facts>(
        &'flow mut self,
        event: FlowEventV2<'facts>,
    ) -> Result<FlowApplyOutcomeV2<'flow, 'facts>, FlowFinishedV2> {
        if self.is_finished() {
            return Err(FlowFinishedV2);
        }
        if let Some(outcome) = self.universal(&event) {
            return Ok(Self::lift(outcome));
        }
        if self.is_door_switch(&event) {
            let outcome = self.fail(WipingReasonV2::DoorSwitchAttempt);
            return Ok(Self::lift(outcome));
        }
        if self.is_kit_scan_screen() && Self::is_scanner_mismatch(&event) {
            let outcome = self.fail(WipingReasonV2::KitScannerModeMismatch);
            return Ok(Self::lift(outcome));
        }
        if self.is_restore_signing_attempt(&event) {
            let outcome = self.fail(WipingReasonV2::RestoreSigningProhibited);
            return Ok(Self::lift(outcome));
        }

        match (self.screen_kind(), event) {
            (
                Some(ScreenKindV2::DerivationExplanation),
                FlowEventV2::OperationCompleted(CompletedOperationV2::Provisioning(facts)),
            ) if self.flow == FlowKindV2::Setup => {
                self.state = MachineStateV2::Screen(ScreenKindV2::ProvisioningResult);
                return Ok(FlowApplyOutcomeV2::ProvisioningResult(
                    ProvisioningResultSessionV2 {
                        flow: self,
                        facts,
                        active: true,
                    },
                ));
            }
            (
                Some(ScreenKindV2::Validation),
                FlowEventV2::OperationCompleted(CompletedOperationV2::Review(ready)),
            ) if self.flow == FlowKindV2::A1B => {
                self.state = MachineStateV2::Screen(ScreenKindV2::ReviewOverview);
                return Ok(FlowApplyOutcomeV2::Review(ReviewSessionV2 {
                    flow: self,
                    ready,
                    cursor: ReviewCursorV2::Overview,
                    review_complete: false,
                    pending_hold: None,
                    active: true,
                }));
            }
            (
                Some(ScreenKindV2::Export),
                FlowEventV2::OperationCompleted(CompletedOperationV2::Export(export)),
            ) if self.flow == FlowKindV2::A1B => {
                let view = Self::result_view(export);
                self.state = MachineStateV2::Screen(ScreenKindV2::TransactionResult);
                return Ok(FlowApplyOutcomeV2::TransactionResult(
                    TransactionResultSessionV2 {
                        flow: self,
                        _export: export,
                        view,
                        active: true,
                    },
                ));
            }
            _ => {}
        }

        let outcome = match self.flow {
            FlowKindV2::Setup => self.apply_setup(event),
            FlowKindV2::A1B => self.apply_normal(event),
            FlowKindV2::Kit => self.apply_kit(event),
        };
        Ok(outcome)
    }

    fn apply_setup<'flow, 'facts>(
        &'flow mut self,
        event: FlowEventV2<'facts>,
    ) -> FlowApplyOutcomeV2<'flow, 'facts> {
        let Some(kind) = self.screen_kind() else {
            return Self::lift(self.fail(WipingReasonV2::InvalidTransition));
        };
        if kind == ScreenKindV2::EntropyModeSelection
            && self.entropy_mode == EntropyInputModeV2::DiceGrid
            && matches!(
                event,
                FlowEventV2::Key(KeypadKey::EqualsConfirmEnter) | FlowEventV2::CameraPresented
            )
        {
            return FlowApplyOutcomeV2::Rejected(StatePreservingRejectionV2::DiceGridUnavailable);
        }
        let outcome = match (kind, event) {
            (ScreenKindV2::SetupStart, FlowEventV2::Key(KeypadKey::EqualsConfirmEnter)) => {
                self.continue_to(ScreenKindV2::TierSelection)
            }
            (ScreenKindV2::TierSelection, FlowEventV2::Key(KeypadKey::EqualsConfirmEnter)) => {
                self.continue_to(ScreenKindV2::EntropyModeSelection)
            }
            (ScreenKindV2::EntropyModeSelection, FlowEventV2::Key(KeypadKey::FourLeft)) => {
                self.entropy_mode = EntropyInputModeV2::DiceGrid;
                self.continue_to(ScreenKindV2::EntropyModeSelection)
            }
            (ScreenKindV2::EntropyModeSelection, FlowEventV2::Key(KeypadKey::SixRight)) => {
                self.entropy_mode = EntropyInputModeV2::ManualKeypad;
                self.continue_to(ScreenKindV2::EntropyModeSelection)
            }
            (
                ScreenKindV2::EntropyModeSelection,
                FlowEventV2::Key(KeypadKey::EqualsConfirmEnter),
            ) if self.entropy_mode == EntropyInputModeV2::ManualKeypad => {
                self.continue_to(ScreenKindV2::CeremonyInput)
            }
            (ScreenKindV2::CeremonyConfirm, FlowEventV2::CeremonyCommitmentReady(commitment))
                if self.ceremony_confirmed =>
            {
                self.ceremony_confirmed = false;
                self.ceremony_commitment = Some(commitment);
                self.continue_to(ScreenKindV2::CeremonyCommitment)
            }
            (ScreenKindV2::CeremonyCommitment, FlowEventV2::Key(KeypadKey::EqualsConfirmEnter)) => {
                self.ceremony_commitment = None;
                match self.ceremony_purpose.next() {
                    Some(next) => {
                        self.ceremony_purpose = next;
                        self.continue_to(ScreenKindV2::CeremonyInput)
                    }
                    None => self.continue_to(ScreenKindV2::DerivationExplanation),
                }
            }
            (
                ScreenKindV2::ProvisionB,
                FlowEventV2::OperationCompleted(CompletedOperationV2::Plain),
            ) => self.continue_to(ScreenKindV2::VerifyB),
            (
                ScreenKindV2::VerifyB,
                FlowEventV2::OperationCompleted(CompletedOperationV2::Plain),
            ) => self.continue_to(ScreenKindV2::SpareBSelection),
            (ScreenKindV2::SpareBSelection, FlowEventV2::SelectSpareB(SpareBChoiceV2::NoSpare)) => {
                self.continue_to(ScreenKindV2::CreateA1)
            }
            (
                ScreenKindV2::SpareBSelection,
                FlowEventV2::SelectSpareB(SpareBChoiceV2::ProvisionSpare),
            ) => self.continue_to(ScreenKindV2::ProvisionSpareB),
            (
                ScreenKindV2::ProvisionSpareB,
                FlowEventV2::OperationCompleted(CompletedOperationV2::Plain),
            ) => self.continue_to(ScreenKindV2::VerifySpareB),
            (
                ScreenKindV2::VerifySpareB,
                FlowEventV2::OperationCompleted(CompletedOperationV2::Plain),
            ) => self.continue_to(ScreenKindV2::CreateA1),
            (
                ScreenKindV2::CreateA1,
                FlowEventV2::OperationCompleted(CompletedOperationV2::Plain),
            ) => self.continue_to(ScreenKindV2::ScanBackA1),
            (
                ScreenKindV2::ScanBackA1,
                FlowEventV2::OperationCompleted(CompletedOperationV2::Plain),
            ) => self.continue_to(ScreenKindV2::CoordinatorMaterial),
            (
                ScreenKindV2::CoordinatorMaterial,
                FlowEventV2::OperationCompleted(CompletedOperationV2::Plain),
            ) => self.continue_to(ScreenKindV2::CreateTwoKits),
            (
                ScreenKindV2::CreateTwoKits,
                FlowEventV2::OperationCompleted(CompletedOperationV2::Plain),
            ) => self.continue_to(ScreenKindV2::VerifyTwoKits),
            (
                ScreenKindV2::VerifyTwoKits,
                FlowEventV2::OperationCompleted(CompletedOperationV2::Plain),
            ) => self.continue_to(ScreenKindV2::Rehearsal),
            (
                ScreenKindV2::Rehearsal,
                FlowEventV2::OperationCompleted(CompletedOperationV2::Plain),
            ) => self.continue_to(ScreenKindV2::SetupReady),
            (ScreenKindV2::SetupReady, FlowEventV2::Key(KeypadKey::EqualsConfirmEnter)) => {
                self.complete()
            }
            _ => self.fail(WipingReasonV2::InvalidTransition),
        };
        Self::lift(outcome)
    }

    fn apply_normal<'flow, 'facts>(
        &'flow mut self,
        event: FlowEventV2<'facts>,
    ) -> FlowApplyOutcomeV2<'flow, 'facts> {
        let Some(kind) = self.screen_kind() else {
            return Self::lift(self.fail(WipingReasonV2::InvalidTransition));
        };
        if matches!(
            event,
            FlowEventV2::ApprovalHoldStarted | FlowEventV2::ApprovalHoldCompleted(_)
        ) {
            return Self::lift(self.fail(WipingReasonV2::ReviewIncomplete));
        }
        let outcome = match (kind, event) {
            (ScreenKindV2::NormalStart, FlowEventV2::Key(KeypadKey::EqualsConfirmEnter)) => {
                self.continue_to(ScreenKindV2::Transport)
            }
            (
                ScreenKindV2::Transport,
                FlowEventV2::TransportPresented | FlowEventV2::CameraPresented,
            ) => self.continue_to(ScreenKindV2::Intake),
            (ScreenKindV2::Intake, FlowEventV2::IntakePresented) => {
                self.continue_to(ScreenKindV2::FactorB)
            }
            (
                ScreenKindV2::FactorB,
                FlowEventV2::OperationCompleted(CompletedOperationV2::Plain),
            ) => self.continue_to(ScreenKindV2::FactorA1),
            (
                ScreenKindV2::FactorA1,
                FlowEventV2::OperationCompleted(CompletedOperationV2::Plain),
            ) => self.continue_to(ScreenKindV2::Validation),
            (ScreenKindV2::AwaitingSigning, FlowEventV2::SigningOutcome { identity }) => {
                if self.approval == Some(identity) {
                    self.approval = None;
                    self.continue_to(ScreenKindV2::Export)
                } else {
                    self.fail(WipingReasonV2::ReviewIdentityMismatch)
                }
            }
            _ => self.fail(WipingReasonV2::InvalidTransition),
        };
        Self::lift(outcome)
    }

    fn apply_kit<'flow, 'facts>(
        &'flow mut self,
        event: FlowEventV2<'facts>,
    ) -> FlowApplyOutcomeV2<'flow, 'facts> {
        let Some(kind) = self.screen_kind() else {
            return Self::lift(self.fail(WipingReasonV2::InvalidTransition));
        };
        let outcome = match (kind, event) {
            (ScreenKindV2::KitStart, FlowEventV2::Key(KeypadKey::EqualsConfirmEnter)) => {
                self.continue_to(ScreenKindV2::KitDoorSelection)
            }
            (ScreenKindV2::KitDoorSelection, FlowEventV2::SelectKitDoor(door)) => {
                self.door = Some(door);
                self.continue_to(ScreenKindV2::KitDoorConfirmation)
            }
            (ScreenKindV2::KitDoorConfirmation, FlowEventV2::ConfirmKitDoor(door))
                if self.door == Some(door) =>
            {
                self.continue_to(ScreenKindV2::ScanKitShareOne)
            }
            (ScreenKindV2::ScanKitShareOne, FlowEventV2::KitShareAccepted) => {
                self.continue_to(ScreenKindV2::ScanKitShareTwo)
            }
            (ScreenKindV2::ScanKitShareTwo, FlowEventV2::KitShareAccepted) => {
                self.continue_to(ScreenKindV2::CombineKitShares)
            }
            (
                ScreenKindV2::CombineKitShares,
                FlowEventV2::OperationCompleted(CompletedOperationV2::Plain),
            ) => match self.door {
                Some(KitDoorV2::KitSpend) => self.continue_to(ScreenKindV2::KitSpendTransaction),
                Some(KitDoorV2::KitRestore) => {
                    self.continue_to(ScreenKindV2::KitRestoreActionSelection)
                }
                None => self.fail(WipingReasonV2::InvalidTransition),
            },
            (ScreenKindV2::KitSpendTransaction, FlowEventV2::KitSpendTransactionPresented)
                if self.door == Some(KitDoorV2::KitSpend) =>
            {
                self.continue_to(ScreenKindV2::KitSpendValidation)
            }
            (ScreenKindV2::KitSpendValidation, FlowEventV2::KitSpendValidated)
                if self.door == Some(KitDoorV2::KitSpend) =>
            {
                self.continue_to(ScreenKindV2::KitSpendCompleteness)
            }
            (
                ScreenKindV2::KitSpendCompleteness,
                FlowEventV2::CoordinatorUtxoCompletenessConfirmed,
            ) if self.door == Some(KitDoorV2::KitSpend) => {
                self.continue_to(ScreenKindV2::KitSpendDeferred)
            }
            (ScreenKindV2::KitSpendDeferred, FlowEventV2::Key(KeypadKey::EqualsConfirmEnter))
                if self.door == Some(KitDoorV2::KitSpend) =>
            {
                self.defer(DeferredBoundaryV2::KitSpendSlice11)
            }
            (
                ScreenKindV2::KitRestoreActionSelection,
                FlowEventV2::SelectKitRestoreAction(action),
            ) if self.door == Some(KitDoorV2::KitRestore) => {
                self.restore_action = Some(action);
                match action {
                    KitRestoreActionV2::ReplacementB => {
                        self.continue_to(ScreenKindV2::CardRemainsConfirmation)
                    }
                    KitRestoreActionV2::A1Reprint => {
                        self.continue_to(ScreenKindV2::KitRestoreDeferred)
                    }
                }
            }
            (
                ScreenKindV2::CardRemainsConfirmation,
                FlowEventV2::CardRemainsStatement(CardRemainsStatementV2::InHand),
            ) if self.restore_action == Some(KitRestoreActionV2::ReplacementB) => {
                self.continue_to(ScreenKindV2::KitRestoreDeferred)
            }
            (
                ScreenKindV2::CardRemainsConfirmation,
                FlowEventV2::CardRemainsStatement(CardRemainsStatementV2::Missing),
            ) => self.fail(WipingReasonV2::MissingCardRequiresKitSpend),
            (ScreenKindV2::KitRestoreDeferred, FlowEventV2::Key(KeypadKey::EqualsConfirmEnter))
                if self.door == Some(KitDoorV2::KitRestore) =>
            {
                self.defer(DeferredBoundaryV2::KitRestoreSlice10)
            }
            _ => self.fail(WipingReasonV2::InvalidTransition),
        };
        Self::lift(outcome)
    }

    fn universal(&mut self, event: &FlowEventV2<'_>) -> Option<ScopedApplyOutcomeV2> {
        Some(match event {
            FlowEventV2::Key(KeypadKey::CancelBack) => self.fail(WipingReasonV2::Cancelled),
            FlowEventV2::OperationFailed => self.fail(WipingReasonV2::OperationFailed),
            FlowEventV2::MediaRemoved => self.fail(WipingReasonV2::MediaRemoved),
            FlowEventV2::CardRemoved => self.fail(WipingReasonV2::CardRemoved),
            FlowEventV2::SessionTimeout => self.fail(WipingReasonV2::SessionTimeout),
            FlowEventV2::Shutdown => self.fail(WipingReasonV2::Shutdown),
            FlowEventV2::Restart => self.fail(WipingReasonV2::Restart),
            FlowEventV2::PowerLoss => self.fail(WipingReasonV2::PowerLoss),
            FlowEventV2::TransportPresented
            | FlowEventV2::CameraPresented
            | FlowEventV2::IntakePresented
            | FlowEventV2::PsbtPresented
            | FlowEventV2::A1Presented
            | FlowEventV2::BbqrTransactionPresented
            | FlowEventV2::CoordinatorPresented
                if self.approval.is_some() =>
            {
                self.fail(WipingReasonV2::PostApprovalYield)
            }
            _ => return None,
        })
    }

    fn is_door_switch(&self, event: &FlowEventV2<'_>) -> bool {
        if self.flow != FlowKindV2::Kit || self.door.is_none() {
            return false;
        }
        match event {
            FlowEventV2::SelectKitDoor(_) => true,
            FlowEventV2::ConfirmKitDoor(candidate) => {
                self.screen_kind() != Some(ScreenKindV2::KitDoorConfirmation)
                    || self.door != Some(*candidate)
            }
            _ => false,
        }
    }

    fn is_kit_scan_screen(&self) -> bool {
        matches!(
            self.screen_kind(),
            Some(ScreenKindV2::ScanKitShareOne | ScreenKindV2::ScanKitShareTwo)
        )
    }

    const fn is_scanner_mismatch(event: &FlowEventV2<'_>) -> bool {
        matches!(
            event,
            FlowEventV2::PsbtPresented
                | FlowEventV2::A1Presented
                | FlowEventV2::BbqrTransactionPresented
                | FlowEventV2::CoordinatorPresented
                | FlowEventV2::CameraPresented
                | FlowEventV2::TransportPresented
                | FlowEventV2::IntakePresented
        )
    }

    fn is_restore_signing_attempt(&self, event: &FlowEventV2<'_>) -> bool {
        if self.flow != FlowKindV2::Kit
            || self.door != Some(KitDoorV2::KitRestore)
            || self.is_kit_scan_screen()
        {
            return false;
        }
        matches!(
            event,
            FlowEventV2::TransportPresented
                | FlowEventV2::CameraPresented
                | FlowEventV2::IntakePresented
                | FlowEventV2::PsbtPresented
                | FlowEventV2::BbqrTransactionPresented
                | FlowEventV2::CoordinatorPresented
                | FlowEventV2::KitSpendTransactionPresented
                | FlowEventV2::KitSpendValidated
                | FlowEventV2::CoordinatorUtxoCompletenessConfirmed
                | FlowEventV2::ApprovalHoldStarted
                | FlowEventV2::ApprovalHoldCompleted(_)
                | FlowEventV2::SigningOutcome { .. }
                | FlowEventV2::OperationCompleted(
                    CompletedOperationV2::Review(_) | CompletedOperationV2::Export(_)
                )
        )
    }

    fn mint_hold_token(&mut self) -> Option<ApprovalTokenV2> {
        let provenance = self.provenance?;
        let next = self.next_cycle.checked_add(1)?;
        let token = ApprovalTokenV2 {
            provenance,
            cycle: self.next_cycle,
        };
        self.next_cycle = next;
        Some(token)
    }

    fn bind_completed_hold(
        &mut self,
        pending: Option<ApprovalTokenV2>,
        presented: ApprovalTokenV2,
        review_hash: ReviewV3Hash,
    ) -> Result<ApprovalIdentityV2, ScopedApplyOutcomeV2> {
        if pending != Some(presented) {
            return Err(self.fail(WipingReasonV2::ReviewIdentityMismatch));
        }
        let identity = ApprovalIdentityV2 {
            token: presented,
            review_hash,
        };
        self.approval = Some(identity);
        Ok(identity)
    }

    fn result_view(export: &ExportArtifacts) -> TransactionResultV2View {
        match export.artifacts() {
            TierArtifacts::SimpleRecovery {
                finalized_psbt,
                raw_transaction,
            }
            | TierArtifacts::Inheritance {
                finalized_psbt,
                raw_transaction,
            } => TransactionResultV2View {
                finalized_psbt: Some(finalized_psbt.metadata()),
                raw_transaction: raw_transaction.metadata(),
            },
            TierArtifacts::QuantumShelter { raw_transaction } => TransactionResultV2View {
                finalized_psbt: None,
                raw_transaction: raw_transaction.metadata(),
            },
        }
    }

    fn continue_to(&mut self, kind: ScreenKindV2) -> ScopedApplyOutcomeV2 {
        self.state = MachineStateV2::Screen(kind);
        ScopedApplyOutcomeV2::Continue(kind)
    }

    fn release_to(&mut self, kind: ScreenKindV2) -> ScopedApplyOutcomeV2 {
        self.state = MachineStateV2::Screen(kind);
        ScopedApplyOutcomeV2::Released(kind)
    }

    fn complete(&mut self) -> ScopedApplyOutcomeV2 {
        self.wipe(FlowTerminalV2::CompletedWiped);
        ScopedApplyOutcomeV2::CompletedWiped
    }

    fn defer(&mut self, boundary: DeferredBoundaryV2) -> ScopedApplyOutcomeV2 {
        self.wipe(FlowTerminalV2::DeferredWiped(boundary));
        ScopedApplyOutcomeV2::DeferredWiped(boundary)
    }

    fn fail(&mut self, reason: WipingReasonV2) -> ScopedApplyOutcomeV2 {
        self.wipe(FlowTerminalV2::FailedWiped(reason));
        ScopedApplyOutcomeV2::FailedWiped(reason)
    }

    fn wipe(&mut self, terminal: FlowTerminalV2) {
        self.entropy_mode = EntropyInputModeV2::DiceGrid;
        self.ceremony_purpose = CeremonyPurposeV2::SeedA;
        self.ceremony_confirmed = false;
        self.ceremony_commitment = None;
        self.door = None;
        self.restore_action = None;
        self.provenance = None;
        self.next_cycle = 0;
        self.approval = None;
        self.state = MachineStateV2::Terminal(terminal);
    }

    pub(crate) fn terminate_manual_keypad(&mut self, reason: WipingReasonV2) {
        if !self.is_finished() {
            self.wipe(FlowTerminalV2::FailedWiped(reason));
        }
    }

    pub(crate) fn terminate_kit_intake(&mut self, reason: WipingReasonV2) {
        if !self.is_finished() {
            self.wipe(FlowTerminalV2::FailedWiped(reason));
        }
    }

    pub(crate) fn terminate_kit_restore(&mut self, reason: WipingReasonV2) {
        if !self.is_finished() {
            self.wipe(FlowTerminalV2::FailedWiped(reason));
        }
    }

    pub(crate) fn accept_kit_intake_share(&mut self) -> bool {
        if self.flow != FlowKindV2::Kit {
            return false;
        }
        self.state = match self.screen_kind() {
            Some(ScreenKindV2::ScanKitShareOne) => {
                MachineStateV2::Screen(ScreenKindV2::ScanKitShareTwo)
            }
            Some(ScreenKindV2::ScanKitShareTwo) => {
                MachineStateV2::Screen(ScreenKindV2::CombineKitShares)
            }
            _ => return false,
        };
        true
    }

    pub(crate) fn complete_kit_intake(&mut self) -> bool {
        if self.flow != FlowKindV2::Kit
            || self.screen_kind() != Some(ScreenKindV2::CombineKitShares)
        {
            return false;
        }
        self.state = MachineStateV2::Screen(match self.door {
            Some(KitDoorV2::KitSpend) => ScreenKindV2::KitSpendTransaction,
            Some(KitDoorV2::KitRestore) => ScreenKindV2::KitRestoreActionSelection,
            None => return false,
        });
        true
    }

    pub(crate) fn select_kit_restore_action_semantic(
        &mut self,
        action: KitRestoreActionV2,
    ) -> bool {
        if self.flow != FlowKindV2::Kit
            || self.door != Some(KitDoorV2::KitRestore)
            || self.screen_kind() != Some(ScreenKindV2::KitRestoreActionSelection)
            || self.restore_action.is_some()
        {
            return false;
        }
        self.restore_action = Some(action);
        self.state = MachineStateV2::Screen(match action {
            KitRestoreActionV2::ReplacementB => ScreenKindV2::CardRemainsConfirmation,
            KitRestoreActionV2::A1Reprint => ScreenKindV2::KitRestoreDeferred,
        });
        true
    }

    pub(crate) fn confirm_kit_restore_card_remains_semantic(
        &mut self,
        statement: CardRemainsStatementV2,
    ) -> bool {
        if self.flow != FlowKindV2::Kit
            || self.door != Some(KitDoorV2::KitRestore)
            || self.restore_action != Some(KitRestoreActionV2::ReplacementB)
            || self.screen_kind() != Some(ScreenKindV2::CardRemainsConfirmation)
        {
            return false;
        }
        match statement {
            CardRemainsStatementV2::InHand => {
                self.state = MachineStateV2::Screen(ScreenKindV2::KitRestoreDeferred);
            }
            CardRemainsStatementV2::Missing => {
                self.wipe(FlowTerminalV2::FailedWiped(
                    WipingReasonV2::MissingCardRequiresKitSpend,
                ));
            }
        }
        true
    }

    pub(crate) fn complete_kit_restore_semantic(&mut self) -> bool {
        if self.flow != FlowKindV2::Kit
            || self.door != Some(KitDoorV2::KitRestore)
            || self.restore_action.is_none()
            || self.screen_kind() != Some(ScreenKindV2::KitRestoreDeferred)
        {
            return false;
        }
        self.wipe(FlowTerminalV2::CompletedWiped);
        true
    }

    pub(crate) fn begin_manual_keypad_echo(&mut self) -> bool {
        if self.flow != FlowKindV2::Setup
            || self.screen_kind() != Some(ScreenKindV2::CeremonyInput)
            || self.entropy_mode != EntropyInputModeV2::ManualKeypad
        {
            return false;
        }
        self.state = MachineStateV2::Screen(ScreenKindV2::CeremonyEcho);
        true
    }

    pub(crate) fn confirm_manual_keypad_echo(&mut self) -> bool {
        if self.screen_kind() != Some(ScreenKindV2::CeremonyEcho) {
            return false;
        }
        self.state = MachineStateV2::Screen(ScreenKindV2::CeremonyConfirm);
        true
    }

    pub(crate) fn complete_manual_keypad_confirmation(&mut self) -> bool {
        if self.screen_kind() != Some(ScreenKindV2::CeremonyConfirm) {
            return false;
        }
        self.ceremony_confirmed = true;
        true
    }

    fn lift<'flow, 'facts>(outcome: ScopedApplyOutcomeV2) -> FlowApplyOutcomeV2<'flow, 'facts> {
        match outcome {
            ScopedApplyOutcomeV2::Continue(kind) | ScopedApplyOutcomeV2::Released(kind) => {
                FlowApplyOutcomeV2::Continue(kind)
            }
            ScopedApplyOutcomeV2::CompletedWiped => FlowApplyOutcomeV2::CompletedWiped,
            ScopedApplyOutcomeV2::DeferredWiped(boundary) => {
                FlowApplyOutcomeV2::DeferredWiped(boundary)
            }
            ScopedApplyOutcomeV2::FailedWiped(reason) => FlowApplyOutcomeV2::FailedWiped(reason),
        }
    }
}

impl<'flow, 'facts> ProvisioningResultSessionV2<'flow, 'facts> {
    #[must_use]
    pub const fn screen(&self) -> ScreenV2<'facts> {
        ScreenV2::ProvisioningResult(ProvisioningResultV2View { facts: self.facts })
    }

    pub fn apply(mut self, event: FlowEventV2<'_>) -> Result<ScopedApplyOutcomeV2, FlowFinishedV2> {
        if !self.active || self.flow.is_finished() {
            self.active = false;
            return Err(FlowFinishedV2);
        }
        if let Some(outcome) = self.flow.universal(&event) {
            self.active = false;
            return Ok(outcome);
        }
        let outcome = match event {
            FlowEventV2::Key(KeypadKey::EqualsConfirmEnter) => {
                self.flow.release_to(ScreenKindV2::ProvisionB)
            }
            _ => self.flow.fail(WipingReasonV2::InvalidTransition),
        };
        self.active = false;
        Ok(outcome)
    }
}

impl Drop for ProvisioningResultSessionV2<'_, '_> {
    fn drop(&mut self) {
        if self.active && !self.flow.is_finished() {
            let _ = self.flow.fail(WipingReasonV2::Cancelled);
        }
    }
}

impl<'flow, 'facts> TransactionResultSessionV2<'flow, 'facts> {
    #[must_use]
    pub const fn screen(&self) -> ScreenV2<'facts> {
        ScreenV2::TransactionResult(self.view)
    }

    pub fn apply(mut self, event: FlowEventV2<'_>) -> Result<ScopedApplyOutcomeV2, FlowFinishedV2> {
        if !self.active || self.flow.is_finished() {
            self.active = false;
            return Err(FlowFinishedV2);
        }
        if let Some(outcome) = self.flow.universal(&event) {
            self.active = false;
            return Ok(outcome);
        }
        let outcome = match event {
            FlowEventV2::Key(KeypadKey::EqualsConfirmEnter) => self.flow.complete(),
            _ => self.flow.fail(WipingReasonV2::InvalidTransition),
        };
        self.active = false;
        Ok(outcome)
    }
}

impl Drop for TransactionResultSessionV2<'_, '_> {
    fn drop(&mut self) {
        if self.active && !self.flow.is_finished() {
            let _ = self.flow.fail(WipingReasonV2::Cancelled);
        }
    }
}

impl<'flow, 'facts> ReviewSessionV2<'flow, 'facts> {
    fn review(&self) -> &'facts ReviewV3 {
        self.ready.review()
    }

    #[must_use]
    pub const fn pending_hold_token(&self) -> Option<ApprovalTokenV2> {
        self.pending_hold
    }

    #[must_use]
    pub fn screen(&self) -> Option<ScreenV2<'facts>> {
        let review = self.review();
        Some(match self.cursor {
            ReviewCursorV2::Overview => ScreenV2::ReviewOverview(ReviewOverviewV2View {
                network: review.context().network,
                wallet_id: review.wallet_id(),
                input_count: review.input_count(),
                total_input_amount: review.total_input_amount(),
            }),
            ReviewCursorV2::Arithmetic => ScreenV2::ReviewArithmetic(ReviewArithmeticV2View {
                total_input_amount: review.total_input_amount(),
                total_output_amount: review.total_output_amount(),
                fee: review.fee(),
            }),
            ReviewCursorV2::Recipient(index) => {
                ScreenV2::ReviewRecipient(Self::recipient_view(review.outputs().get(index)?)?)
            }
            ReviewCursorV2::Change(index) => {
                ScreenV2::ReviewChange(Self::change_view(review.outputs().get(index)?)?)
            }
            ReviewCursorV2::OpReturn(index) => {
                ScreenV2::ReviewOpReturn(Self::op_return_view(review.outputs().get(index)?)?)
            }
            ReviewCursorV2::Locktime => ScreenV2::ReviewLocktime(ReviewLocktimeV2View {
                locktime: review.locktime(),
            }),
            ReviewCursorV2::Sequence(index) => {
                let input = review.inputs().get(index)?;
                ScreenV2::ReviewSequence(ReviewSequenceV2View {
                    input_index: input.index(),
                    sequence: input.sequence(),
                    direct_rbf: input.direct_rbf(),
                })
            }
            ReviewCursorV2::FeePolicy => ScreenV2::ReviewFeePolicy(ReviewFeePolicyV2View {
                identifier: review.fee_policy_identifier(),
                fee: review.fee(),
                fee_policy: review.fee_policy(),
            }),
            ReviewCursorV2::FinalApproval => ScreenV2::FinalApproval(FinalApprovalV2View {
                review_hash: self.ready.review_hash(),
            }),
        })
    }

    pub fn apply(
        mut self,
        event: FlowEventV2<'_>,
    ) -> Result<ReviewSessionOutcomeV2<'flow, 'facts>, FlowFinishedV2> {
        if !self.active || self.flow.is_finished() {
            self.active = false;
            return Err(FlowFinishedV2);
        }
        if let Some(outcome) = self.flow.universal(&event) {
            self.active = false;
            return Ok(ReviewSessionOutcomeV2::Released(outcome));
        }
        if matches!(
            event,
            FlowEventV2::ApprovalHoldStarted | FlowEventV2::ApprovalHoldCompleted(_)
        ) && self.cursor != ReviewCursorV2::FinalApproval
        {
            self.active = false;
            return Ok(ReviewSessionOutcomeV2::Released(
                self.flow.fail(WipingReasonV2::ReviewIncomplete),
            ));
        }
        match event {
            FlowEventV2::Key(
                KeypadKey::EqualsConfirmEnter | KeypadKey::SixRight | KeypadKey::TwoDown,
            ) if self.cursor != ReviewCursorV2::FinalApproval && self.pending_hold.is_none() => {
                let Some(next) = self.next_cursor() else {
                    self.active = false;
                    return Ok(ReviewSessionOutcomeV2::Released(
                        self.flow.fail(WipingReasonV2::InvalidTransition),
                    ));
                };
                if next == ReviewCursorV2::FinalApproval {
                    self.review_complete = true;
                }
                self.cursor = next;
                self.flow.state = MachineStateV2::Screen(Self::cursor_kind(next));
                Ok(ReviewSessionOutcomeV2::Continue(self))
            }
            FlowEventV2::Key(KeypadKey::FourLeft | KeypadKey::EightUp)
                if self.cursor != ReviewCursorV2::Overview && self.pending_hold.is_none() =>
            {
                let Some(previous) = self.previous_cursor() else {
                    self.active = false;
                    return Ok(ReviewSessionOutcomeV2::Released(
                        self.flow.fail(WipingReasonV2::InvalidTransition),
                    ));
                };
                self.cursor = previous;
                self.flow.state = MachineStateV2::Screen(Self::cursor_kind(previous));
                Ok(ReviewSessionOutcomeV2::Continue(self))
            }
            FlowEventV2::ApprovalHoldStarted
                if self.cursor == ReviewCursorV2::FinalApproval
                    && self.review_complete
                    && self.pending_hold.is_none() =>
            {
                let Some(token) = self.flow.mint_hold_token() else {
                    self.active = false;
                    return Ok(ReviewSessionOutcomeV2::Released(
                        self.flow.fail(WipingReasonV2::OperationFailed),
                    ));
                };
                self.pending_hold = Some(token);
                Ok(ReviewSessionOutcomeV2::Continue(self))
            }
            FlowEventV2::ApprovalHoldCompleted(token)
                if self.cursor == ReviewCursorV2::FinalApproval && self.review_complete =>
            {
                if let Err(outcome) = self.flow.bind_completed_hold(
                    self.pending_hold,
                    token,
                    self.ready.review_hash(),
                ) {
                    self.active = false;
                    return Ok(ReviewSessionOutcomeV2::Released(outcome));
                }
                self.pending_hold = None;
                self.active = false;
                Ok(ReviewSessionOutcomeV2::Released(
                    self.flow.release_to(ScreenKindV2::AwaitingSigning),
                ))
            }
            FlowEventV2::ApprovalHoldStarted if self.cursor == ReviewCursorV2::FinalApproval => {
                self.active = false;
                Ok(ReviewSessionOutcomeV2::Released(
                    self.flow.fail(WipingReasonV2::ReviewIdentityMismatch),
                ))
            }
            _ => {
                self.active = false;
                Ok(ReviewSessionOutcomeV2::Released(
                    self.flow.fail(WipingReasonV2::InvalidTransition),
                ))
            }
        }
    }

    fn recipient_view(output: &'facts ReviewV3Output) -> Option<ReviewRecipientV2View<'facts>> {
        let recipient = match output.ownership() {
            ReviewV3OutputOwnership::NotOwned {
                recipient_type,
                data,
            } if *recipient_type != RecipientType::OpReturn => RecipientFactV2View::External {
                recipient_type: *recipient_type,
                data,
            },
            ReviewV3OutputOwnership::ProvenSelfTransfer {
                child_index,
                witness_program,
            } => RecipientFactV2View::SelfTransfer {
                child_index: *child_index,
                witness_program,
            },
            _ => return None,
        };
        Some(ReviewRecipientV2View {
            index: output.index(),
            amount: output.amount(),
            script_pubkey: output.script_pubkey(),
            recipient,
        })
    }

    fn change_view(output: &'facts ReviewV3Output) -> Option<ReviewChangeV2View<'facts>> {
        let ReviewV3OutputOwnership::ProvenChange { child_index } = output.ownership() else {
            return None;
        };
        Some(ReviewChangeV2View {
            index: output.index(),
            amount: output.amount(),
            script_pubkey: output.script_pubkey(),
            child_index: *child_index,
        })
    }

    fn op_return_view(output: &'facts ReviewV3Output) -> Option<ReviewOpReturnV2View<'facts>> {
        let ReviewV3OutputOwnership::NotOwned {
            recipient_type: RecipientType::OpReturn,
            data,
        } = output.ownership()
        else {
            return None;
        };
        Some(ReviewOpReturnV2View {
            index: output.index(),
            amount: output.amount(),
            script_pubkey: output.script_pubkey(),
            payload: data,
        })
    }

    fn next_cursor(&self) -> Option<ReviewCursorV2> {
        Some(match self.cursor {
            ReviewCursorV2::Overview => ReviewCursorV2::Arithmetic,
            ReviewCursorV2::Arithmetic => self
                .first_recipient_after(None)
                .map(ReviewCursorV2::Recipient)
                .or_else(|| self.first_change_after(None).map(ReviewCursorV2::Change))
                .or_else(|| {
                    self.first_op_return_after(None)
                        .map(ReviewCursorV2::OpReturn)
                })
                .unwrap_or(ReviewCursorV2::Locktime),
            ReviewCursorV2::Recipient(index) => self
                .first_recipient_after(Some(index))
                .map(ReviewCursorV2::Recipient)
                .or_else(|| self.first_change_after(None).map(ReviewCursorV2::Change))
                .or_else(|| {
                    self.first_op_return_after(None)
                        .map(ReviewCursorV2::OpReturn)
                })
                .unwrap_or(ReviewCursorV2::Locktime),
            ReviewCursorV2::Change(index) => self
                .first_change_after(Some(index))
                .map(ReviewCursorV2::Change)
                .or_else(|| {
                    self.first_op_return_after(None)
                        .map(ReviewCursorV2::OpReturn)
                })
                .unwrap_or(ReviewCursorV2::Locktime),
            ReviewCursorV2::OpReturn(index) => self
                .first_op_return_after(Some(index))
                .map(ReviewCursorV2::OpReturn)
                .unwrap_or(ReviewCursorV2::Locktime),
            ReviewCursorV2::Locktime => {
                if self.review().inputs().is_empty() {
                    ReviewCursorV2::FeePolicy
                } else {
                    ReviewCursorV2::Sequence(0)
                }
            }
            ReviewCursorV2::Sequence(index) => match index.checked_add(1) {
                Some(next) if next < self.review().inputs().len() => ReviewCursorV2::Sequence(next),
                _ => ReviewCursorV2::FeePolicy,
            },
            ReviewCursorV2::FeePolicy => ReviewCursorV2::FinalApproval,
            ReviewCursorV2::FinalApproval => return None,
        })
    }

    fn previous_cursor(&self) -> Option<ReviewCursorV2> {
        Some(match self.cursor {
            ReviewCursorV2::Overview => return None,
            ReviewCursorV2::Arithmetic => ReviewCursorV2::Overview,
            ReviewCursorV2::Recipient(index) => self
                .last_recipient_before(index)
                .map(ReviewCursorV2::Recipient)
                .unwrap_or(ReviewCursorV2::Arithmetic),
            ReviewCursorV2::Change(index) => self
                .last_change_before(index)
                .map(ReviewCursorV2::Change)
                .or_else(|| self.last_recipient().map(ReviewCursorV2::Recipient))
                .unwrap_or(ReviewCursorV2::Arithmetic),
            ReviewCursorV2::OpReturn(index) => self
                .last_op_return_before(index)
                .map(ReviewCursorV2::OpReturn)
                .or_else(|| self.last_change().map(ReviewCursorV2::Change))
                .or_else(|| self.last_recipient().map(ReviewCursorV2::Recipient))
                .unwrap_or(ReviewCursorV2::Arithmetic),
            ReviewCursorV2::Locktime => self
                .last_op_return()
                .map(ReviewCursorV2::OpReturn)
                .or_else(|| self.last_change().map(ReviewCursorV2::Change))
                .or_else(|| self.last_recipient().map(ReviewCursorV2::Recipient))
                .unwrap_or(ReviewCursorV2::Arithmetic),
            ReviewCursorV2::Sequence(0) => ReviewCursorV2::Locktime,
            ReviewCursorV2::Sequence(index) => ReviewCursorV2::Sequence(index - 1),
            ReviewCursorV2::FeePolicy => match self.review().inputs().len().checked_sub(1) {
                Some(last) => ReviewCursorV2::Sequence(last),
                None => ReviewCursorV2::Locktime,
            },
            ReviewCursorV2::FinalApproval => ReviewCursorV2::FeePolicy,
        })
    }

    const fn cursor_kind(cursor: ReviewCursorV2) -> ScreenKindV2 {
        match cursor {
            ReviewCursorV2::Overview => ScreenKindV2::ReviewOverview,
            ReviewCursorV2::Arithmetic => ScreenKindV2::ReviewArithmetic,
            ReviewCursorV2::Recipient(_) => ScreenKindV2::ReviewRecipient,
            ReviewCursorV2::Change(_) => ScreenKindV2::ReviewChange,
            ReviewCursorV2::OpReturn(_) => ScreenKindV2::ReviewOpReturn,
            ReviewCursorV2::Locktime => ScreenKindV2::ReviewLocktime,
            ReviewCursorV2::Sequence(_) => ScreenKindV2::ReviewSequence,
            ReviewCursorV2::FeePolicy => ScreenKindV2::ReviewFeePolicy,
            ReviewCursorV2::FinalApproval => ScreenKindV2::FinalApproval,
        }
    }

    fn first_recipient_after(&self, after: Option<usize>) -> Option<usize> {
        self.review()
            .outputs()
            .iter()
            .enumerate()
            .find_map(|(index, output)| {
                (after.is_none_or(|after| index > after) && Self::is_recipient(output))
                    .then_some(index)
            })
    }

    fn first_change_after(&self, after: Option<usize>) -> Option<usize> {
        self.review()
            .outputs()
            .iter()
            .enumerate()
            .find_map(|(index, output)| {
                (after.is_none_or(|after| index > after) && Self::is_change(output))
                    .then_some(index)
            })
    }

    fn first_op_return_after(&self, after: Option<usize>) -> Option<usize> {
        self.review()
            .outputs()
            .iter()
            .enumerate()
            .find_map(|(index, output)| {
                (after.is_none_or(|after| index > after) && Self::is_op_return(output))
                    .then_some(index)
            })
    }

    fn last_recipient(&self) -> Option<usize> {
        self.last_recipient_before(usize::MAX)
    }

    fn last_change(&self) -> Option<usize> {
        self.last_change_before(usize::MAX)
    }

    fn last_op_return(&self) -> Option<usize> {
        self.last_op_return_before(usize::MAX)
    }

    fn last_recipient_before(&self, before: usize) -> Option<usize> {
        self.review()
            .outputs()
            .iter()
            .enumerate()
            .rev()
            .find_map(|(index, output)| {
                (index < before && Self::is_recipient(output)).then_some(index)
            })
    }

    fn last_change_before(&self, before: usize) -> Option<usize> {
        self.review()
            .outputs()
            .iter()
            .enumerate()
            .rev()
            .find_map(|(index, output)| {
                (index < before && Self::is_change(output)).then_some(index)
            })
    }

    fn last_op_return_before(&self, before: usize) -> Option<usize> {
        self.review()
            .outputs()
            .iter()
            .enumerate()
            .rev()
            .find_map(|(index, output)| {
                (index < before && Self::is_op_return(output)).then_some(index)
            })
    }

    fn is_recipient(output: &ReviewV3Output) -> bool {
        matches!(
            output.ownership(),
            ReviewV3OutputOwnership::NotOwned {
                recipient_type: RecipientType::P2wpkh
                    | RecipientType::P2wsh
                    | RecipientType::P2tr
                    | RecipientType::P2pkh
                    | RecipientType::P2sh,
                ..
            } | ReviewV3OutputOwnership::ProvenSelfTransfer { .. }
        )
    }

    fn is_change(output: &ReviewV3Output) -> bool {
        matches!(
            output.ownership(),
            ReviewV3OutputOwnership::ProvenChange { .. }
        )
    }

    fn is_op_return(output: &ReviewV3Output) -> bool {
        matches!(
            output.ownership(),
            ReviewV3OutputOwnership::NotOwned {
                recipient_type: RecipientType::OpReturn,
                ..
            }
        )
    }
}

impl Drop for ReviewSessionV2<'_, '_> {
    fn drop(&mut self) {
        if self.active && !self.flow.is_finished() {
            let _ = self.flow.fail(WipingReasonV2::Cancelled);
        }
    }
}
