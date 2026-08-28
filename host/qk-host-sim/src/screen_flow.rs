//! Deterministic M27 HOST-only wallet-mode screen-flow state machine.
//!
//! The lifetime-free root retains no borrowed fact or ceremony material.
//! Exact caller borrows exist only inside scoped sessions and end before the
//! root flow advances beyond their semantic boundary. This is not an approval
//! authority and has no signer, renderer, card, camera, or target integration.

use crate::{ExportArtifacts, ReviewReady, SdArtifactMetadata, TierArtifacts};
use qk_provisioning::ProvisioningArtifacts;
use qk_psbt::{
    DirectRbf, FeePolicyFacts, FeeWarning, RecipientType, ReviewNetwork, ReviewV2, ReviewV2Hash,
    ReviewV2Output, ReviewV2OutputOwnership,
};
use std::sync::atomic::{AtomicU64, Ordering};

static NEXT_SCREEN_FLOW_PROVENANCE: AtomicU64 = AtomicU64::new(0);

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum FlowKind {
    Provisioning,
    SigningA1B,
    RecoveryA1C,
    RecoveryBC,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ScreenKind {
    ProvisioningStart,
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
    ProvisionC,
    VerifyC,
    CreateA1,
    ScanBackA1,
    CoordinatorMaterial,
    Rehearsal,
    KitReady,
    FlowStart,
    Route,
    Transport,
    Intake,
    Factor,
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
    PostApprovalFactor,
    AwaitingSigning,
    Export,
    TransactionResult,
    RecoveryRotation,
}

/// Exact nineteen-key logical P0.1 map. Both physical zero switches
/// normalize to the single [`Self::Zero`] value before submission.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum KeypadKey {
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

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CeremonyPurpose {
    SeedA,
    SignerB,
    SignerC,
    A2,
}

/// Ceremony-wide v1 dice input choice. This typed selection does not
/// implement transcript capture, length validation, or camera behavior.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum EntropyInputMode {
    DiceGrid,
    ManualKeypad,
}

impl CeremonyPurpose {
    const fn next(self) -> Option<Self> {
        match self {
            Self::SeedA => Some(Self::SignerB),
            Self::SignerB => Some(Self::SignerC),
            Self::SignerC => Some(Self::A2),
            Self::A2 => None,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum FactorRole {
    A1,
    SignerB,
    SignerC,
    EmergencySignerC,
}

/// Opaque process-provenance and monotonic-cycle hold token.
#[derive(Clone, Copy, Eq, PartialEq)]
pub struct ApprovalToken {
    provenance: u64,
    cycle: u64,
}

/// Inseparable token and exact approved review hash.
#[derive(Clone, Copy, Eq, PartialEq)]
pub struct ApprovalIdentity {
    token: ApprovalToken,
    review_hash: ReviewV2Hash,
}

impl ApprovalIdentity {
    #[must_use]
    pub const fn token(self) -> ApprovalToken {
        self.token
    }

    #[must_use]
    pub const fn review_hash(self) -> ReviewV2Hash {
        self.review_hash
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum WipingReason {
    InvalidTransition,
    Cancelled,
    OperationFailed,
    MediaRemoved,
    CardRemoved,
    SessionTimeout,
    Shutdown,
    Restart,
    PowerLoss,
    ReviewIncomplete,
    ReviewIdentityMismatch,
    PostApprovalYield,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum FlowTerminal {
    CompletedWiped,
    FailedWiped(WipingReason),
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ScopedApplyOutcome {
    Continue(ScreenKind),
    Released(ScreenKind),
    CompletedWiped,
    FailedWiped(WipingReason),
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct FlowFinished;

#[derive(Clone, Copy)]
pub enum CompletedOperation<'a> {
    Plain,
    Provisioning(&'a ProvisioningArtifacts),
    Review(&'a ReviewReady),
    Export(&'a ExportArtifacts),
}

#[derive(Clone, Copy)]
pub enum FlowEvent<'a> {
    Key(KeypadKey),
    OperationCompleted(CompletedOperation<'a>),
    OperationFailed,
    CeremonyEchoReady(&'a [u8]),
    CeremonyCommitmentReady([u8; 32]),
    TransportPresented,
    CameraPresented,
    IntakePresented,
    MediaRemoved,
    ApprovalHoldStarted,
    ApprovalHoldCompleted(ApprovalToken),
    SigningOutcome { identity: ApprovalIdentity },
    CardRemoved,
    SessionTimeout,
    Shutdown,
    Restart,
    PowerLoss,
}

/// Exact transient ceremony unit. It has no formatting or ownership method.
#[derive(Clone, Copy)]
pub struct CeremonyUnitView<'a> {
    unit: &'a [u8],
}

impl<'a> CeremonyUnitView<'a> {
    #[must_use]
    pub const fn bytes(self) -> &'a [u8] {
        self.unit
    }
}

#[derive(Clone, Copy)]
pub struct CeremonyCommitmentView<'a> {
    commitment: &'a [u8; 32],
}

impl<'a> CeremonyCommitmentView<'a> {
    #[must_use]
    pub const fn bytes(self) -> &'a [u8; 32] {
        self.commitment
    }
}

/// Narrow provisioning-result view. No owning provisioning object escapes.
#[derive(Clone, Copy)]
pub struct ProvisioningResultView<'a> {
    facts: &'a ProvisioningArtifacts,
}

impl ProvisioningResultView<'_> {
    #[must_use]
    pub const fn wallet_id(&self) -> [u8; 32] {
        self.facts.wallet_id
    }
}

#[derive(Clone, Copy)]
pub struct ReviewOverviewView {
    network: ReviewNetwork,
    wallet_id: [u8; 32],
    input_count: usize,
    total_input_amount: u64,
}

impl ReviewOverviewView {
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
pub struct ReviewArithmeticView {
    total_input_amount: u64,
    total_output_amount: u64,
    fee: u64,
}

impl ReviewArithmeticView {
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
pub enum RecipientFactView<'a> {
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
pub struct ReviewRecipientView<'a> {
    index: u32,
    amount: u64,
    script_pubkey: &'a [u8],
    recipient: RecipientFactView<'a>,
}

impl<'a> ReviewRecipientView<'a> {
    #[must_use]
    pub const fn index(&self) -> u32 {
        self.index
    }

    #[must_use]
    pub const fn amount(&self) -> u64 {
        self.amount
    }

    #[must_use]
    pub fn script_pubkey(&self) -> &'a [u8] {
        self.script_pubkey
    }

    #[must_use]
    pub const fn recipient(&self) -> RecipientFactView<'a> {
        self.recipient
    }
}

#[derive(Clone, Copy)]
pub struct ReviewChangeView<'a> {
    index: u32,
    amount: u64,
    script_pubkey: &'a [u8],
    child_index: u32,
}

impl<'a> ReviewChangeView<'a> {
    #[must_use]
    pub const fn index(&self) -> u32 {
        self.index
    }

    #[must_use]
    pub const fn amount(&self) -> u64 {
        self.amount
    }

    #[must_use]
    pub fn script_pubkey(&self) -> &'a [u8] {
        self.script_pubkey
    }

    #[must_use]
    pub const fn child_index(&self) -> u32 {
        self.child_index
    }
}

#[derive(Clone, Copy)]
pub struct ReviewOpReturnView<'a> {
    index: u32,
    amount: u64,
    script_pubkey: &'a [u8],
    payload: &'a [u8],
}

impl<'a> ReviewOpReturnView<'a> {
    #[must_use]
    pub const fn index(&self) -> u32 {
        self.index
    }

    #[must_use]
    pub const fn amount(&self) -> u64 {
        self.amount
    }

    #[must_use]
    pub fn script_pubkey(&self) -> &'a [u8] {
        self.script_pubkey
    }

    #[must_use]
    pub const fn payload(&self) -> &'a [u8] {
        self.payload
    }
}

#[derive(Clone, Copy)]
pub struct ReviewLocktimeView {
    locktime: u32,
}

impl ReviewLocktimeView {
    #[must_use]
    pub const fn locktime(self) -> u32 {
        self.locktime
    }
}

#[derive(Clone, Copy)]
pub struct ReviewSequenceView {
    input_index: u32,
    sequence: u32,
    direct_rbf: DirectRbf,
}

impl ReviewSequenceView {
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
pub struct ReviewFeePolicyView {
    identifier: &'static [u8],
    fee: u64,
    fee_policy: FeePolicyFacts,
}

impl ReviewFeePolicyView {
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

    pub fn warnings(&self) -> impl Iterator<Item = FeeWarning> + '_ {
        self.fee_policy.warnings()
    }
}

#[derive(Clone, Copy)]
pub struct FinalApprovalView {
    review_hash: ReviewV2Hash,
}

impl FinalApprovalView {
    #[must_use]
    pub const fn review_hash(self) -> ReviewV2Hash {
        self.review_hash
    }
}

/// Narrow M25 result view. The owning export capability never escapes.
#[derive(Clone, Copy)]
pub struct TransactionResultView {
    finalized_psbt: Option<SdArtifactMetadata>,
    raw_transaction: SdArtifactMetadata,
}

impl TransactionResultView {
    #[must_use]
    pub const fn finalized_psbt(self) -> Option<SdArtifactMetadata> {
        self.finalized_psbt
    }

    #[must_use]
    pub const fn raw_transaction(self) -> SdArtifactMetadata {
        self.raw_transaction
    }
}

/// Narrow typed screen vocabulary. Fact-owner references are private inside
/// the view wrappers and cannot be recovered through this surface.
#[derive(Clone, Copy)]
pub enum Screen<'a> {
    ProvisioningStart,
    TierSelection,
    EntropyModeSelection {
        selected: EntropyInputMode,
    },
    CeremonyInput {
        purpose: CeremonyPurpose,
        mode: EntropyInputMode,
    },
    CeremonyEcho {
        purpose: CeremonyPurpose,
        mode: EntropyInputMode,
        unit: CeremonyUnitView<'a>,
    },
    CeremonyConfirm {
        purpose: CeremonyPurpose,
        mode: EntropyInputMode,
        unit: Option<CeremonyUnitView<'a>>,
    },
    CeremonyCommitment {
        purpose: CeremonyPurpose,
        mode: EntropyInputMode,
        commitment: CeremonyCommitmentView<'a>,
    },
    DerivationExplanation,
    ProvisioningResult(ProvisioningResultView<'a>),
    ProvisionB,
    VerifyB,
    ProvisionC,
    VerifyC,
    CreateA1,
    ScanBackA1,
    CoordinatorMaterial,
    Rehearsal,
    KitReady,
    FlowStart {
        flow: FlowKind,
    },
    Route {
        flow: FlowKind,
    },
    Transport {
        flow: FlowKind,
    },
    Intake {
        flow: FlowKind,
    },
    Factor {
        flow: FlowKind,
        role: FactorRole,
    },
    Validation,
    ReviewOverview(ReviewOverviewView),
    ReviewArithmetic(ReviewArithmeticView),
    ReviewRecipient(ReviewRecipientView<'a>),
    ReviewChange(ReviewChangeView<'a>),
    ReviewOpReturn(ReviewOpReturnView<'a>),
    ReviewLocktime(ReviewLocktimeView),
    ReviewSequence(ReviewSequenceView),
    ReviewFeePolicy(ReviewFeePolicyView),
    FinalApproval(FinalApprovalView),
    PostApprovalFactor {
        role: FactorRole,
    },
    AwaitingSigning,
    Export,
    TransactionResult(TransactionResultView),
    RecoveryRotation,
}

impl Screen<'_> {
    #[must_use]
    pub const fn kind(&self) -> ScreenKind {
        match self {
            Self::ProvisioningStart => ScreenKind::ProvisioningStart,
            Self::TierSelection => ScreenKind::TierSelection,
            Self::EntropyModeSelection { .. } => ScreenKind::EntropyModeSelection,
            Self::CeremonyInput { .. } => ScreenKind::CeremonyInput,
            Self::CeremonyEcho { .. } => ScreenKind::CeremonyEcho,
            Self::CeremonyConfirm { .. } => ScreenKind::CeremonyConfirm,
            Self::CeremonyCommitment { .. } => ScreenKind::CeremonyCommitment,
            Self::DerivationExplanation => ScreenKind::DerivationExplanation,
            Self::ProvisioningResult(_) => ScreenKind::ProvisioningResult,
            Self::ProvisionB => ScreenKind::ProvisionB,
            Self::VerifyB => ScreenKind::VerifyB,
            Self::ProvisionC => ScreenKind::ProvisionC,
            Self::VerifyC => ScreenKind::VerifyC,
            Self::CreateA1 => ScreenKind::CreateA1,
            Self::ScanBackA1 => ScreenKind::ScanBackA1,
            Self::CoordinatorMaterial => ScreenKind::CoordinatorMaterial,
            Self::Rehearsal => ScreenKind::Rehearsal,
            Self::KitReady => ScreenKind::KitReady,
            Self::FlowStart { .. } => ScreenKind::FlowStart,
            Self::Route { .. } => ScreenKind::Route,
            Self::Transport { .. } => ScreenKind::Transport,
            Self::Intake { .. } => ScreenKind::Intake,
            Self::Factor { .. } => ScreenKind::Factor,
            Self::Validation => ScreenKind::Validation,
            Self::ReviewOverview(_) => ScreenKind::ReviewOverview,
            Self::ReviewArithmetic(_) => ScreenKind::ReviewArithmetic,
            Self::ReviewRecipient(_) => ScreenKind::ReviewRecipient,
            Self::ReviewChange(_) => ScreenKind::ReviewChange,
            Self::ReviewOpReturn(_) => ScreenKind::ReviewOpReturn,
            Self::ReviewLocktime(_) => ScreenKind::ReviewLocktime,
            Self::ReviewSequence(_) => ScreenKind::ReviewSequence,
            Self::ReviewFeePolicy(_) => ScreenKind::ReviewFeePolicy,
            Self::FinalApproval(_) => ScreenKind::FinalApproval,
            Self::PostApprovalFactor { .. } => ScreenKind::PostApprovalFactor,
            Self::AwaitingSigning => ScreenKind::AwaitingSigning,
            Self::Export => ScreenKind::Export,
            Self::TransactionResult(_) => ScreenKind::TransactionResult,
            Self::RecoveryRotation => ScreenKind::RecoveryRotation,
        }
    }
}

#[derive(Clone, Copy)]
enum MachineState {
    Screen(ScreenKind),
    Terminal(FlowTerminal),
}

/// Lifetime-free root screen flow. It owns no fact or ceremony borrow.
pub struct ScreenFlow {
    flow: FlowKind,
    state: MachineState,
    entropy_mode: EntropyInputMode,
    ceremony_purpose: CeremonyPurpose,
    ceremony_confirmed: bool,
    ceremony_commitment: Option<[u8; 32]>,
    factor_step: u8,
    provenance: Option<u64>,
    next_cycle: u64,
    approval: Option<ApprovalIdentity>,
}

#[derive(Clone, Copy, Eq, PartialEq)]
enum ReviewCursor {
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

#[derive(Clone, Copy, Eq, PartialEq)]
enum CeremonySessionStage {
    Echo,
    Confirm,
}

#[must_use]
pub struct CeremonySession<'flow, 'unit> {
    flow: &'flow mut ScreenFlow,
    unit: &'unit [u8],
    stage: CeremonySessionStage,
    active: bool,
}

#[must_use]
pub struct ProvisioningResultSession<'flow, 'facts> {
    flow: &'flow mut ScreenFlow,
    facts: &'facts ProvisioningArtifacts,
    active: bool,
}

#[must_use]
pub struct ReviewSession<'flow, 'facts> {
    flow: &'flow mut ScreenFlow,
    ready: &'facts ReviewReady,
    cursor: ReviewCursor,
    review_complete: bool,
    pending_hold: Option<ApprovalToken>,
    active: bool,
}

#[must_use]
pub struct TransactionResultSession<'flow, 'facts> {
    flow: &'flow mut ScreenFlow,
    _export: &'facts ExportArtifacts,
    view: TransactionResultView,
    active: bool,
}

/// General transition outcome. Scoped variants borrow the root flow until
/// their explicit release boundary or fail-closed Drop.
pub enum FlowApplyOutcome<'flow, 'facts> {
    Continue(ScreenKind),
    Ceremony(CeremonySession<'flow, 'facts>),
    ProvisioningResult(ProvisioningResultSession<'flow, 'facts>),
    Review(ReviewSession<'flow, 'facts>),
    TransactionResult(TransactionResultSession<'flow, 'facts>),
    CompletedWiped,
    FailedWiped(WipingReason),
}

pub enum CeremonySessionOutcome<'flow, 'unit> {
    Continue(CeremonySession<'flow, 'unit>),
    Released(ScopedApplyOutcome),
}

pub enum ReviewSessionOutcome<'flow, 'facts> {
    Continue(ReviewSession<'flow, 'facts>),
    Released(ScopedApplyOutcome),
}

impl ScreenFlow {
    #[must_use]
    pub fn new(flow: FlowKind) -> Self {
        let provenance = NEXT_SCREEN_FLOW_PROVENANCE
            .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |value| {
                value.checked_add(1)
            })
            .ok();
        let state = match provenance {
            Some(_) if flow == FlowKind::Provisioning => {
                MachineState::Screen(ScreenKind::ProvisioningStart)
            }
            Some(_) => MachineState::Screen(ScreenKind::FlowStart),
            None => {
                MachineState::Terminal(FlowTerminal::FailedWiped(WipingReason::OperationFailed))
            }
        };
        Self {
            flow,
            state,
            entropy_mode: EntropyInputMode::DiceGrid,
            ceremony_purpose: CeremonyPurpose::SeedA,
            ceremony_confirmed: false,
            ceremony_commitment: None,
            factor_step: 0,
            provenance,
            next_cycle: 0,
            approval: None,
        }
    }

    #[must_use]
    pub const fn flow_kind(&self) -> FlowKind {
        self.flow
    }

    #[must_use]
    pub const fn screen_kind(&self) -> Option<ScreenKind> {
        match self.state {
            MachineState::Screen(kind) => Some(kind),
            MachineState::Terminal(_) => None,
        }
    }

    #[must_use]
    pub const fn terminal(&self) -> Option<FlowTerminal> {
        match self.state {
            MachineState::Screen(_) => None,
            MachineState::Terminal(terminal) => Some(terminal),
        }
    }

    #[must_use]
    pub const fn is_finished(&self) -> bool {
        matches!(self.state, MachineState::Terminal(_))
    }

    #[must_use]
    pub const fn approval_identity(&self) -> Option<ApprovalIdentity> {
        self.approval
    }

    /// Current fact-free or root-owned-value screen. Scoped fact screens are
    /// available only through their corresponding session.
    #[must_use]
    pub fn screen(&self) -> Option<Screen<'_>> {
        Some(match self.screen_kind()? {
            ScreenKind::ProvisioningStart => Screen::ProvisioningStart,
            ScreenKind::TierSelection => Screen::TierSelection,
            ScreenKind::EntropyModeSelection => Screen::EntropyModeSelection {
                selected: self.entropy_mode,
            },
            ScreenKind::CeremonyInput => Screen::CeremonyInput {
                purpose: self.ceremony_purpose,
                mode: self.entropy_mode,
            },
            ScreenKind::CeremonyConfirm if self.ceremony_confirmed => Screen::CeremonyConfirm {
                purpose: self.ceremony_purpose,
                mode: self.entropy_mode,
                unit: None,
            },
            ScreenKind::CeremonyCommitment => Screen::CeremonyCommitment {
                purpose: self.ceremony_purpose,
                mode: self.entropy_mode,
                commitment: CeremonyCommitmentView {
                    commitment: self.ceremony_commitment.as_ref()?,
                },
            },
            ScreenKind::DerivationExplanation => Screen::DerivationExplanation,
            ScreenKind::ProvisionB => Screen::ProvisionB,
            ScreenKind::VerifyB => Screen::VerifyB,
            ScreenKind::ProvisionC => Screen::ProvisionC,
            ScreenKind::VerifyC => Screen::VerifyC,
            ScreenKind::CreateA1 => Screen::CreateA1,
            ScreenKind::ScanBackA1 => Screen::ScanBackA1,
            ScreenKind::CoordinatorMaterial => Screen::CoordinatorMaterial,
            ScreenKind::Rehearsal => Screen::Rehearsal,
            ScreenKind::KitReady => Screen::KitReady,
            ScreenKind::FlowStart => Screen::FlowStart { flow: self.flow },
            ScreenKind::Route => Screen::Route { flow: self.flow },
            ScreenKind::Transport => Screen::Transport { flow: self.flow },
            ScreenKind::Intake => Screen::Intake { flow: self.flow },
            ScreenKind::Factor => Screen::Factor {
                flow: self.flow,
                role: self.factor_role(self.factor_step)?,
            },
            ScreenKind::Validation => Screen::Validation,
            ScreenKind::PostApprovalFactor => Screen::PostApprovalFactor {
                role: self.factor_role(self.factor_step)?,
            },
            ScreenKind::AwaitingSigning => Screen::AwaitingSigning,
            ScreenKind::Export => Screen::Export,
            ScreenKind::RecoveryRotation => Screen::RecoveryRotation,
            ScreenKind::CeremonyEcho
            | ScreenKind::CeremonyConfirm
            | ScreenKind::ProvisioningResult
            | ScreenKind::ReviewOverview
            | ScreenKind::ReviewArithmetic
            | ScreenKind::ReviewRecipient
            | ScreenKind::ReviewChange
            | ScreenKind::ReviewOpReturn
            | ScreenKind::ReviewLocktime
            | ScreenKind::ReviewSequence
            | ScreenKind::ReviewFeePolicy
            | ScreenKind::FinalApproval
            | ScreenKind::TransactionResult => return None,
        })
    }

    pub fn apply<'flow, 'facts>(
        &'flow mut self,
        event: FlowEvent<'facts>,
    ) -> Result<FlowApplyOutcome<'flow, 'facts>, FlowFinished> {
        if self.is_finished() {
            return Err(FlowFinished);
        }
        if let Some(outcome) = self.universal(&event) {
            return Ok(Self::lift(outcome));
        }

        match (self.screen_kind(), event) {
            (Some(ScreenKind::CeremonyInput), FlowEvent::CeremonyEchoReady(unit))
                if self.flow == FlowKind::Provisioning =>
            {
                self.state = MachineState::Screen(ScreenKind::CeremonyEcho);
                return Ok(FlowApplyOutcome::Ceremony(CeremonySession {
                    flow: self,
                    unit,
                    stage: CeremonySessionStage::Echo,
                    active: true,
                }));
            }
            (
                Some(ScreenKind::DerivationExplanation),
                FlowEvent::OperationCompleted(CompletedOperation::Provisioning(facts)),
            ) if self.flow == FlowKind::Provisioning => {
                self.state = MachineState::Screen(ScreenKind::ProvisioningResult);
                return Ok(FlowApplyOutcome::ProvisioningResult(
                    ProvisioningResultSession {
                        flow: self,
                        facts,
                        active: true,
                    },
                ));
            }
            (
                Some(ScreenKind::Validation),
                FlowEvent::OperationCompleted(CompletedOperation::Review(ready)),
            ) if self.flow != FlowKind::Provisioning => {
                self.state = MachineState::Screen(ScreenKind::ReviewOverview);
                return Ok(FlowApplyOutcome::Review(ReviewSession {
                    flow: self,
                    ready,
                    cursor: ReviewCursor::Overview,
                    review_complete: false,
                    pending_hold: None,
                    active: true,
                }));
            }
            (
                Some(ScreenKind::Export),
                FlowEvent::OperationCompleted(CompletedOperation::Export(export)),
            ) if self.flow != FlowKind::Provisioning => {
                let view = Self::result_view(export);
                self.state = MachineState::Screen(ScreenKind::TransactionResult);
                return Ok(FlowApplyOutcome::TransactionResult(
                    TransactionResultSession {
                        flow: self,
                        _export: export,
                        view,
                        active: true,
                    },
                ));
            }
            _ => {}
        }

        let outcome = if self.flow == FlowKind::Provisioning {
            self.apply_provisioning_root(event)
        } else {
            self.apply_transaction_root(event)
        };
        Ok(Self::lift(outcome))
    }

    fn apply_provisioning_root(&mut self, event: FlowEvent<'_>) -> ScopedApplyOutcome {
        let Some(kind) = self.screen_kind() else {
            return self.fail(WipingReason::InvalidTransition);
        };
        match (kind, event) {
            (ScreenKind::ProvisioningStart, FlowEvent::Key(KeypadKey::EqualsConfirmEnter)) => {
                self.continue_to(ScreenKind::TierSelection)
            }
            (ScreenKind::TierSelection, FlowEvent::Key(KeypadKey::EqualsConfirmEnter)) => {
                self.continue_to(ScreenKind::EntropyModeSelection)
            }
            (ScreenKind::TierSelection, FlowEvent::Key(KeypadKey::CancelBack)) => {
                self.continue_to(ScreenKind::ProvisioningStart)
            }
            (ScreenKind::EntropyModeSelection, FlowEvent::Key(KeypadKey::EqualsConfirmEnter)) => {
                self.continue_to(ScreenKind::CeremonyInput)
            }
            (ScreenKind::EntropyModeSelection, FlowEvent::Key(KeypadKey::FourLeft)) => {
                self.entropy_mode = EntropyInputMode::DiceGrid;
                self.continue_to(ScreenKind::EntropyModeSelection)
            }
            (ScreenKind::EntropyModeSelection, FlowEvent::Key(KeypadKey::SixRight)) => {
                self.entropy_mode = EntropyInputMode::ManualKeypad;
                self.continue_to(ScreenKind::EntropyModeSelection)
            }
            (ScreenKind::EntropyModeSelection, FlowEvent::Key(KeypadKey::CancelBack)) => {
                self.continue_to(ScreenKind::TierSelection)
            }
            (
                ScreenKind::CeremonyInput,
                FlowEvent::Key(
                    KeypadKey::One
                    | KeypadKey::TwoDown
                    | KeypadKey::Three
                    | KeypadKey::FourLeft
                    | KeypadKey::Five
                    | KeypadKey::SixRight
                    | KeypadKey::CeDelete,
                ),
            ) => self.continue_to(ScreenKind::CeremonyInput),
            (ScreenKind::CeremonyInput, FlowEvent::Key(KeypadKey::CancelBack))
                if self.ceremony_purpose == CeremonyPurpose::SeedA =>
            {
                self.continue_to(ScreenKind::EntropyModeSelection)
            }
            (ScreenKind::CeremonyConfirm, FlowEvent::CeremonyCommitmentReady(commitment))
                if self.ceremony_confirmed =>
            {
                self.ceremony_confirmed = false;
                self.ceremony_commitment = Some(commitment);
                self.continue_to(ScreenKind::CeremonyCommitment)
            }
            (ScreenKind::CeremonyCommitment, FlowEvent::Key(KeypadKey::EqualsConfirmEnter)) => {
                self.ceremony_commitment = None;
                match self.ceremony_purpose.next() {
                    Some(next) => {
                        self.ceremony_purpose = next;
                        self.continue_to(ScreenKind::CeremonyInput)
                    }
                    None => self.continue_to(ScreenKind::DerivationExplanation),
                }
            }
            (ScreenKind::ProvisionB, FlowEvent::OperationCompleted(CompletedOperation::Plain)) => {
                self.continue_to(ScreenKind::VerifyB)
            }
            (ScreenKind::VerifyB, FlowEvent::OperationCompleted(CompletedOperation::Plain)) => {
                self.continue_to(ScreenKind::ProvisionC)
            }
            (ScreenKind::ProvisionC, FlowEvent::OperationCompleted(CompletedOperation::Plain)) => {
                self.continue_to(ScreenKind::VerifyC)
            }
            (ScreenKind::VerifyC, FlowEvent::OperationCompleted(CompletedOperation::Plain)) => {
                self.continue_to(ScreenKind::CreateA1)
            }
            (ScreenKind::CreateA1, FlowEvent::OperationCompleted(CompletedOperation::Plain)) => {
                self.continue_to(ScreenKind::ScanBackA1)
            }
            (ScreenKind::ScanBackA1, FlowEvent::OperationCompleted(CompletedOperation::Plain)) => {
                self.continue_to(ScreenKind::CoordinatorMaterial)
            }
            (
                ScreenKind::CoordinatorMaterial,
                FlowEvent::OperationCompleted(CompletedOperation::Plain),
            ) => self.continue_to(ScreenKind::Rehearsal),
            (ScreenKind::Rehearsal, FlowEvent::OperationCompleted(CompletedOperation::Plain)) => {
                self.continue_to(ScreenKind::KitReady)
            }
            (ScreenKind::KitReady, FlowEvent::Key(KeypadKey::EqualsConfirmEnter)) => {
                self.complete()
            }
            (_, FlowEvent::Key(KeypadKey::CancelBack)) => self.fail(WipingReason::Cancelled),
            _ => self.fail(WipingReason::InvalidTransition),
        }
    }

    fn apply_transaction_root(&mut self, event: FlowEvent<'_>) -> ScopedApplyOutcome {
        let Some(kind) = self.screen_kind() else {
            return self.fail(WipingReason::InvalidTransition);
        };
        if matches!(
            event,
            FlowEvent::ApprovalHoldStarted | FlowEvent::ApprovalHoldCompleted(_)
        ) {
            return self.fail(WipingReason::ReviewIncomplete);
        }
        match (kind, event) {
            (ScreenKind::FlowStart, FlowEvent::Key(KeypadKey::EqualsConfirmEnter)) => {
                self.continue_to(ScreenKind::Route)
            }
            (ScreenKind::Route, FlowEvent::Key(KeypadKey::EqualsConfirmEnter)) => {
                self.continue_to(ScreenKind::Transport)
            }
            (ScreenKind::Transport, FlowEvent::TransportPresented | FlowEvent::CameraPresented) => {
                self.continue_to(ScreenKind::Intake)
            }
            (ScreenKind::Intake, FlowEvent::IntakePresented) => {
                self.factor_step = 0;
                self.continue_to(ScreenKind::Factor)
            }
            (ScreenKind::Factor, FlowEvent::OperationCompleted(CompletedOperation::Plain)) => {
                self.factor_step = match self.factor_step.checked_add(1) {
                    Some(step) => step,
                    None => return self.fail(WipingReason::OperationFailed),
                };
                if self.factor_step == 2 {
                    self.continue_to(ScreenKind::Validation)
                } else {
                    self.continue_to(ScreenKind::Factor)
                }
            }
            (
                ScreenKind::PostApprovalFactor,
                FlowEvent::OperationCompleted(CompletedOperation::Plain),
            ) => {
                self.factor_step = match self.factor_step.checked_add(1) {
                    Some(step) => step,
                    None => return self.fail(WipingReason::OperationFailed),
                };
                if self.factor_step == 2 {
                    self.continue_to(ScreenKind::AwaitingSigning)
                } else {
                    self.continue_to(ScreenKind::PostApprovalFactor)
                }
            }
            (ScreenKind::AwaitingSigning, FlowEvent::SigningOutcome { identity }) => {
                if self.approval != Some(identity) {
                    self.fail(WipingReason::ReviewIdentityMismatch)
                } else {
                    self.approval = None;
                    self.continue_to(ScreenKind::Export)
                }
            }
            (ScreenKind::RecoveryRotation, FlowEvent::Key(KeypadKey::EqualsConfirmEnter)) => {
                self.complete()
            }
            (_, FlowEvent::Key(KeypadKey::CancelBack)) => self.fail(WipingReason::Cancelled),
            _ => self.fail(WipingReason::InvalidTransition),
        }
    }

    fn universal(&mut self, event: &FlowEvent<'_>) -> Option<ScopedApplyOutcome> {
        Some(match event {
            FlowEvent::CardRemoved => self.fail(WipingReason::CardRemoved),
            FlowEvent::SessionTimeout => self.fail(WipingReason::SessionTimeout),
            FlowEvent::OperationFailed => self.fail(WipingReason::OperationFailed),
            FlowEvent::MediaRemoved => self.fail(WipingReason::MediaRemoved),
            FlowEvent::Shutdown => self.fail(WipingReason::Shutdown),
            FlowEvent::Restart => self.fail(WipingReason::Restart),
            FlowEvent::PowerLoss => self.fail(WipingReason::PowerLoss),
            FlowEvent::TransportPresented
            | FlowEvent::CameraPresented
            | FlowEvent::IntakePresented
                if self.approval.is_some() =>
            {
                self.fail(WipingReason::PostApprovalYield)
            }
            _ => return None,
        })
    }

    fn mint_hold_token(&mut self) -> Option<ApprovalToken> {
        let provenance = self.provenance?;
        let next = self.next_cycle.checked_add(1)?;
        let token = ApprovalToken {
            provenance,
            cycle: self.next_cycle,
        };
        self.next_cycle = next;
        Some(token)
    }

    fn bind_completed_hold(
        &mut self,
        pending: Option<ApprovalToken>,
        presented: ApprovalToken,
        review_hash: ReviewV2Hash,
    ) -> Result<ApprovalIdentity, ScopedApplyOutcome> {
        if pending != Some(presented) {
            return Err(self.fail(WipingReason::ReviewIdentityMismatch));
        }
        let identity = ApprovalIdentity {
            token: presented,
            review_hash,
        };
        self.approval = Some(identity);
        Ok(identity)
    }

    const fn factor_role(&self, step: u8) -> Option<FactorRole> {
        match (self.flow, step) {
            (FlowKind::SigningA1B, 0) | (FlowKind::RecoveryBC, 0) => Some(FactorRole::SignerB),
            (FlowKind::RecoveryA1C, 0) => Some(FactorRole::EmergencySignerC),
            (FlowKind::SigningA1B | FlowKind::RecoveryA1C, 1) => Some(FactorRole::A1),
            (FlowKind::RecoveryBC, 1) => Some(FactorRole::SignerC),
            _ => None,
        }
    }

    fn result_view(export: &ExportArtifacts) -> TransactionResultView {
        match export.artifacts() {
            TierArtifacts::SimpleRecovery {
                finalized_psbt,
                raw_transaction,
            }
            | TierArtifacts::Inheritance {
                finalized_psbt,
                raw_transaction,
            } => TransactionResultView {
                finalized_psbt: Some(finalized_psbt.metadata()),
                raw_transaction: raw_transaction.metadata(),
            },
            TierArtifacts::QuantumShelter { raw_transaction } => TransactionResultView {
                finalized_psbt: None,
                raw_transaction: raw_transaction.metadata(),
            },
        }
    }

    fn continue_to(&mut self, kind: ScreenKind) -> ScopedApplyOutcome {
        self.state = MachineState::Screen(kind);
        ScopedApplyOutcome::Continue(kind)
    }

    fn release_to(&mut self, kind: ScreenKind) -> ScopedApplyOutcome {
        self.state = MachineState::Screen(kind);
        ScopedApplyOutcome::Released(kind)
    }

    fn complete(&mut self) -> ScopedApplyOutcome {
        self.wipe(FlowTerminal::CompletedWiped);
        ScopedApplyOutcome::CompletedWiped
    }

    fn fail(&mut self, reason: WipingReason) -> ScopedApplyOutcome {
        self.wipe(FlowTerminal::FailedWiped(reason));
        ScopedApplyOutcome::FailedWiped(reason)
    }

    fn wipe(&mut self, terminal: FlowTerminal) {
        self.entropy_mode = EntropyInputMode::DiceGrid;
        self.ceremony_purpose = CeremonyPurpose::SeedA;
        self.ceremony_confirmed = false;
        self.ceremony_commitment = None;
        self.factor_step = 0;
        self.provenance = None;
        self.next_cycle = 0;
        self.approval = None;
        self.state = MachineState::Terminal(terminal);
    }

    /// Crate-internal M29 bridge for an owning manual-keypad scope. The
    /// existing root transition table deliberately treats red C on the first
    /// ceremony input as reversible navigation; M29 instead owns transcript
    /// bytes and therefore requires every scoped cancellation or failure to
    /// terminate after wiping those bytes.
    pub(crate) fn terminate_manual_keypad(&mut self, reason: WipingReason) {
        if !self.is_finished() {
            self.wipe(FlowTerminal::FailedWiped(reason));
        }
    }

    /// Enter M27's exact echo state without storing the owning M29 unit.
    pub(crate) fn begin_manual_keypad_echo(&mut self) -> bool {
        if self.flow != FlowKind::Provisioning
            || self.screen_kind() != Some(ScreenKind::CeremonyInput)
            || self.entropy_mode != EntropyInputMode::ManualKeypad
        {
            return false;
        }
        self.state = MachineState::Screen(ScreenKind::CeremonyEcho);
        true
    }

    /// Record the separate echo acknowledgement and enter confirmation.
    pub(crate) fn confirm_manual_keypad_echo(&mut self) -> bool {
        if self.screen_kind() != Some(ScreenKind::CeremonyEcho) {
            return false;
        }
        self.state = MachineState::Screen(ScreenKind::CeremonyConfirm);
        true
    }

    /// Record explicit confirmation while retaining no transcript reference.
    pub(crate) fn complete_manual_keypad_confirmation(&mut self) -> bool {
        if self.screen_kind() != Some(ScreenKind::CeremonyConfirm) {
            return false;
        }
        self.ceremony_confirmed = true;
        true
    }

    fn lift<'flow, 'facts>(outcome: ScopedApplyOutcome) -> FlowApplyOutcome<'flow, 'facts> {
        match outcome {
            ScopedApplyOutcome::Continue(kind) | ScopedApplyOutcome::Released(kind) => {
                FlowApplyOutcome::Continue(kind)
            }
            ScopedApplyOutcome::CompletedWiped => FlowApplyOutcome::CompletedWiped,
            ScopedApplyOutcome::FailedWiped(reason) => FlowApplyOutcome::FailedWiped(reason),
        }
    }
}

impl<'flow, 'unit> CeremonySession<'flow, 'unit> {
    #[must_use]
    pub fn screen(&self) -> Screen<'unit> {
        let unit = CeremonyUnitView { unit: self.unit };
        match self.stage {
            CeremonySessionStage::Echo => Screen::CeremonyEcho {
                purpose: self.flow.ceremony_purpose,
                mode: self.flow.entropy_mode,
                unit,
            },
            CeremonySessionStage::Confirm => Screen::CeremonyConfirm {
                purpose: self.flow.ceremony_purpose,
                mode: self.flow.entropy_mode,
                unit: Some(unit),
            },
        }
    }

    pub fn apply(
        mut self,
        event: FlowEvent<'_>,
    ) -> Result<CeremonySessionOutcome<'flow, 'unit>, FlowFinished> {
        if !self.active || self.flow.is_finished() {
            self.active = false;
            return Err(FlowFinished);
        }
        if let Some(outcome) = self.flow.universal(&event) {
            self.active = false;
            return Ok(CeremonySessionOutcome::Released(outcome));
        }
        match (self.stage, event) {
            (CeremonySessionStage::Echo, FlowEvent::Key(KeypadKey::EqualsConfirmEnter)) => {
                self.stage = CeremonySessionStage::Confirm;
                self.flow.state = MachineState::Screen(ScreenKind::CeremonyConfirm);
                Ok(CeremonySessionOutcome::Continue(self))
            }
            (CeremonySessionStage::Confirm, FlowEvent::Key(KeypadKey::EqualsConfirmEnter)) => {
                self.flow.ceremony_confirmed = true;
                self.active = false;
                let outcome = self.flow.release_to(ScreenKind::CeremonyConfirm);
                Ok(CeremonySessionOutcome::Released(outcome))
            }
            (_, FlowEvent::Key(KeypadKey::CancelBack)) => {
                self.active = false;
                let outcome = self.flow.fail(WipingReason::Cancelled);
                Ok(CeremonySessionOutcome::Released(outcome))
            }
            _ => {
                self.active = false;
                let outcome = self.flow.fail(WipingReason::InvalidTransition);
                Ok(CeremonySessionOutcome::Released(outcome))
            }
        }
    }
}

impl Drop for CeremonySession<'_, '_> {
    fn drop(&mut self) {
        if self.active && !self.flow.is_finished() {
            let _ = self.flow.fail(WipingReason::Cancelled);
        }
    }
}

impl<'flow, 'facts> ProvisioningResultSession<'flow, 'facts> {
    #[must_use]
    pub const fn screen(&self) -> Screen<'facts> {
        Screen::ProvisioningResult(ProvisioningResultView { facts: self.facts })
    }

    pub fn apply(mut self, event: FlowEvent<'_>) -> Result<ScopedApplyOutcome, FlowFinished> {
        if !self.active || self.flow.is_finished() {
            self.active = false;
            return Err(FlowFinished);
        }
        if let Some(outcome) = self.flow.universal(&event) {
            self.active = false;
            return Ok(outcome);
        }
        let outcome = match event {
            FlowEvent::Key(KeypadKey::EqualsConfirmEnter) => {
                self.flow.release_to(ScreenKind::ProvisionB)
            }
            FlowEvent::Key(KeypadKey::CancelBack) => self.flow.fail(WipingReason::Cancelled),
            _ => self.flow.fail(WipingReason::InvalidTransition),
        };
        self.active = false;
        Ok(outcome)
    }
}

impl Drop for ProvisioningResultSession<'_, '_> {
    fn drop(&mut self) {
        if self.active && !self.flow.is_finished() {
            let _ = self.flow.fail(WipingReason::Cancelled);
        }
    }
}

impl<'flow, 'facts> TransactionResultSession<'flow, 'facts> {
    #[must_use]
    pub const fn screen(&self) -> Screen<'facts> {
        Screen::TransactionResult(self.view)
    }

    pub fn apply(mut self, event: FlowEvent<'_>) -> Result<ScopedApplyOutcome, FlowFinished> {
        if !self.active || self.flow.is_finished() {
            self.active = false;
            return Err(FlowFinished);
        }
        if let Some(outcome) = self.flow.universal(&event) {
            self.active = false;
            return Ok(outcome);
        }
        let outcome = match event {
            FlowEvent::Key(KeypadKey::EqualsConfirmEnter)
                if self.flow.flow == FlowKind::SigningA1B =>
            {
                self.flow.complete()
            }
            FlowEvent::Key(KeypadKey::EqualsConfirmEnter) => {
                self.flow.release_to(ScreenKind::RecoveryRotation)
            }
            FlowEvent::Key(KeypadKey::CancelBack) => self.flow.fail(WipingReason::Cancelled),
            _ => self.flow.fail(WipingReason::InvalidTransition),
        };
        self.active = false;
        Ok(outcome)
    }
}

impl Drop for TransactionResultSession<'_, '_> {
    fn drop(&mut self) {
        if self.active && !self.flow.is_finished() {
            let _ = self.flow.fail(WipingReason::Cancelled);
        }
    }
}

impl<'flow, 'facts> ReviewSession<'flow, 'facts> {
    fn review(&self) -> &'facts ReviewV2 {
        self.ready.review()
    }

    #[must_use]
    pub const fn pending_hold_token(&self) -> Option<ApprovalToken> {
        self.pending_hold
    }

    #[must_use]
    pub fn screen(&self) -> Option<Screen<'facts>> {
        let review = self.review();
        Some(match self.cursor {
            ReviewCursor::Overview => Screen::ReviewOverview(ReviewOverviewView {
                network: review.context().network,
                wallet_id: review.wallet_id(),
                input_count: review.input_count(),
                total_input_amount: review.total_input_amount(),
            }),
            ReviewCursor::Arithmetic => Screen::ReviewArithmetic(ReviewArithmeticView {
                total_input_amount: review.total_input_amount(),
                total_output_amount: review.total_output_amount(),
                fee: review.fee(),
            }),
            ReviewCursor::Recipient(index) => {
                Screen::ReviewRecipient(Self::recipient_view(review.outputs().get(index)?)?)
            }
            ReviewCursor::Change(index) => {
                Screen::ReviewChange(Self::change_view(review.outputs().get(index)?)?)
            }
            ReviewCursor::OpReturn(index) => {
                Screen::ReviewOpReturn(Self::op_return_view(review.outputs().get(index)?)?)
            }
            ReviewCursor::Locktime => Screen::ReviewLocktime(ReviewLocktimeView {
                locktime: review.locktime(),
            }),
            ReviewCursor::Sequence(index) => {
                let input = review.inputs().get(index)?;
                Screen::ReviewSequence(ReviewSequenceView {
                    input_index: input.index(),
                    sequence: input.sequence(),
                    direct_rbf: input.direct_rbf(),
                })
            }
            ReviewCursor::FeePolicy => Screen::ReviewFeePolicy(ReviewFeePolicyView {
                identifier: review.fee_policy_identifier(),
                fee: review.fee(),
                fee_policy: review.fee_policy(),
            }),
            ReviewCursor::FinalApproval => Screen::FinalApproval(FinalApprovalView {
                review_hash: self.ready.review_hash(),
            }),
        })
    }

    pub fn apply(
        mut self,
        event: FlowEvent<'_>,
    ) -> Result<ReviewSessionOutcome<'flow, 'facts>, FlowFinished> {
        if !self.active || self.flow.is_finished() {
            self.active = false;
            return Err(FlowFinished);
        }
        if let Some(outcome) = self.flow.universal(&event) {
            self.active = false;
            return Ok(ReviewSessionOutcome::Released(outcome));
        }
        if matches!(
            event,
            FlowEvent::ApprovalHoldStarted | FlowEvent::ApprovalHoldCompleted(_)
        ) && self.cursor != ReviewCursor::FinalApproval
        {
            self.active = false;
            let outcome = self.flow.fail(WipingReason::ReviewIncomplete);
            return Ok(ReviewSessionOutcome::Released(outcome));
        }

        match event {
            FlowEvent::Key(
                KeypadKey::EqualsConfirmEnter | KeypadKey::SixRight | KeypadKey::TwoDown,
            ) if self.cursor != ReviewCursor::FinalApproval && self.pending_hold.is_none() => {
                let Some(next) = self.next_cursor() else {
                    self.active = false;
                    let outcome = self.flow.fail(WipingReason::InvalidTransition);
                    return Ok(ReviewSessionOutcome::Released(outcome));
                };
                if next == ReviewCursor::FinalApproval {
                    self.review_complete = true;
                }
                self.cursor = next;
                self.flow.state = MachineState::Screen(Self::cursor_kind(next));
                Ok(ReviewSessionOutcome::Continue(self))
            }
            FlowEvent::Key(KeypadKey::FourLeft | KeypadKey::EightUp | KeypadKey::CancelBack)
                if self.cursor != ReviewCursor::Overview && self.pending_hold.is_none() =>
            {
                let Some(previous) = self.previous_cursor() else {
                    self.active = false;
                    let outcome = self.flow.fail(WipingReason::InvalidTransition);
                    return Ok(ReviewSessionOutcome::Released(outcome));
                };
                self.cursor = previous;
                self.flow.state = MachineState::Screen(Self::cursor_kind(previous));
                Ok(ReviewSessionOutcome::Continue(self))
            }
            FlowEvent::ApprovalHoldStarted
                if self.cursor == ReviewCursor::FinalApproval
                    && self.review_complete
                    && self.pending_hold.is_none() =>
            {
                let Some(token) = self.flow.mint_hold_token() else {
                    self.active = false;
                    let outcome = self.flow.fail(WipingReason::OperationFailed);
                    return Ok(ReviewSessionOutcome::Released(outcome));
                };
                self.pending_hold = Some(token);
                Ok(ReviewSessionOutcome::Continue(self))
            }
            FlowEvent::ApprovalHoldCompleted(token)
                if self.cursor == ReviewCursor::FinalApproval && self.review_complete =>
            {
                if let Err(outcome) = self.flow.bind_completed_hold(
                    self.pending_hold,
                    token,
                    self.ready.review_hash(),
                ) {
                    self.active = false;
                    return Ok(ReviewSessionOutcome::Released(outcome));
                }
                self.pending_hold = None;
                self.active = false;
                let next = if self.flow.flow == FlowKind::RecoveryBC {
                    self.flow.factor_step = 0;
                    ScreenKind::PostApprovalFactor
                } else {
                    ScreenKind::AwaitingSigning
                };
                let outcome = self.flow.release_to(next);
                Ok(ReviewSessionOutcome::Released(outcome))
            }
            FlowEvent::ApprovalHoldStarted if self.cursor == ReviewCursor::FinalApproval => {
                self.active = false;
                let outcome = self.flow.fail(WipingReason::ReviewIdentityMismatch);
                Ok(ReviewSessionOutcome::Released(outcome))
            }
            FlowEvent::Key(KeypadKey::CancelBack) => {
                self.active = false;
                let outcome = self.flow.fail(WipingReason::Cancelled);
                Ok(ReviewSessionOutcome::Released(outcome))
            }
            _ => {
                self.active = false;
                let outcome = self.flow.fail(WipingReason::InvalidTransition);
                Ok(ReviewSessionOutcome::Released(outcome))
            }
        }
    }

    fn recipient_view(output: &'facts ReviewV2Output) -> Option<ReviewRecipientView<'facts>> {
        let recipient = match output.ownership() {
            ReviewV2OutputOwnership::NotOwned {
                recipient_type,
                data,
            } if *recipient_type != RecipientType::OpReturn => RecipientFactView::External {
                recipient_type: *recipient_type,
                data,
            },
            ReviewV2OutputOwnership::ProvenSelfTransfer {
                child_index,
                witness_program,
            } => RecipientFactView::SelfTransfer {
                child_index: *child_index,
                witness_program,
            },
            _ => return None,
        };
        Some(ReviewRecipientView {
            index: output.index(),
            amount: output.amount(),
            script_pubkey: output.script_pubkey(),
            recipient,
        })
    }

    fn change_view(output: &'facts ReviewV2Output) -> Option<ReviewChangeView<'facts>> {
        let ReviewV2OutputOwnership::ProvenChange { child_index } = output.ownership() else {
            return None;
        };
        Some(ReviewChangeView {
            index: output.index(),
            amount: output.amount(),
            script_pubkey: output.script_pubkey(),
            child_index: *child_index,
        })
    }

    fn op_return_view(output: &'facts ReviewV2Output) -> Option<ReviewOpReturnView<'facts>> {
        let ReviewV2OutputOwnership::NotOwned {
            recipient_type: RecipientType::OpReturn,
            data,
        } = output.ownership()
        else {
            return None;
        };
        Some(ReviewOpReturnView {
            index: output.index(),
            amount: output.amount(),
            script_pubkey: output.script_pubkey(),
            payload: data,
        })
    }

    fn next_cursor(&self) -> Option<ReviewCursor> {
        Some(match self.cursor {
            ReviewCursor::Overview => ReviewCursor::Arithmetic,
            ReviewCursor::Arithmetic => self
                .first_recipient_after(None)
                .map(ReviewCursor::Recipient)
                .or_else(|| self.first_change_after(None).map(ReviewCursor::Change))
                .or_else(|| self.first_op_return_after(None).map(ReviewCursor::OpReturn))
                .unwrap_or(ReviewCursor::Locktime),
            ReviewCursor::Recipient(index) => self
                .first_recipient_after(Some(index))
                .map(ReviewCursor::Recipient)
                .or_else(|| self.first_change_after(None).map(ReviewCursor::Change))
                .or_else(|| self.first_op_return_after(None).map(ReviewCursor::OpReturn))
                .unwrap_or(ReviewCursor::Locktime),
            ReviewCursor::Change(index) => self
                .first_change_after(Some(index))
                .map(ReviewCursor::Change)
                .or_else(|| self.first_op_return_after(None).map(ReviewCursor::OpReturn))
                .unwrap_or(ReviewCursor::Locktime),
            ReviewCursor::OpReturn(index) => self
                .first_op_return_after(Some(index))
                .map(ReviewCursor::OpReturn)
                .unwrap_or(ReviewCursor::Locktime),
            ReviewCursor::Locktime => {
                if self.review().inputs().is_empty() {
                    ReviewCursor::FeePolicy
                } else {
                    ReviewCursor::Sequence(0)
                }
            }
            ReviewCursor::Sequence(index) => match index.checked_add(1) {
                Some(next) if next < self.review().inputs().len() => ReviewCursor::Sequence(next),
                _ => ReviewCursor::FeePolicy,
            },
            ReviewCursor::FeePolicy => ReviewCursor::FinalApproval,
            ReviewCursor::FinalApproval => return None,
        })
    }

    fn previous_cursor(&self) -> Option<ReviewCursor> {
        Some(match self.cursor {
            ReviewCursor::Overview => return None,
            ReviewCursor::Arithmetic => ReviewCursor::Overview,
            ReviewCursor::Recipient(index) => self
                .last_recipient_before(index)
                .map(ReviewCursor::Recipient)
                .unwrap_or(ReviewCursor::Arithmetic),
            ReviewCursor::Change(index) => self
                .last_change_before(index)
                .map(ReviewCursor::Change)
                .or_else(|| self.last_recipient().map(ReviewCursor::Recipient))
                .unwrap_or(ReviewCursor::Arithmetic),
            ReviewCursor::OpReturn(index) => self
                .last_op_return_before(index)
                .map(ReviewCursor::OpReturn)
                .or_else(|| self.last_change().map(ReviewCursor::Change))
                .or_else(|| self.last_recipient().map(ReviewCursor::Recipient))
                .unwrap_or(ReviewCursor::Arithmetic),
            ReviewCursor::Locktime => self
                .last_op_return()
                .map(ReviewCursor::OpReturn)
                .or_else(|| self.last_change().map(ReviewCursor::Change))
                .or_else(|| self.last_recipient().map(ReviewCursor::Recipient))
                .unwrap_or(ReviewCursor::Arithmetic),
            ReviewCursor::Sequence(0) => ReviewCursor::Locktime,
            ReviewCursor::Sequence(index) => match index.checked_sub(1) {
                Some(previous) => ReviewCursor::Sequence(previous),
                None => ReviewCursor::Locktime,
            },
            ReviewCursor::FeePolicy => match self.review().inputs().len().checked_sub(1) {
                Some(last) => ReviewCursor::Sequence(last),
                None => ReviewCursor::Locktime,
            },
            ReviewCursor::FinalApproval => ReviewCursor::FeePolicy,
        })
    }

    const fn cursor_kind(cursor: ReviewCursor) -> ScreenKind {
        match cursor {
            ReviewCursor::Overview => ScreenKind::ReviewOverview,
            ReviewCursor::Arithmetic => ScreenKind::ReviewArithmetic,
            ReviewCursor::Recipient(_) => ScreenKind::ReviewRecipient,
            ReviewCursor::Change(_) => ScreenKind::ReviewChange,
            ReviewCursor::OpReturn(_) => ScreenKind::ReviewOpReturn,
            ReviewCursor::Locktime => ScreenKind::ReviewLocktime,
            ReviewCursor::Sequence(_) => ScreenKind::ReviewSequence,
            ReviewCursor::FeePolicy => ScreenKind::ReviewFeePolicy,
            ReviewCursor::FinalApproval => ScreenKind::FinalApproval,
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

    fn is_recipient(output: &ReviewV2Output) -> bool {
        matches!(
            output.ownership(),
            ReviewV2OutputOwnership::NotOwned {
                recipient_type: RecipientType::P2wpkh
                    | RecipientType::P2wsh
                    | RecipientType::P2tr
                    | RecipientType::P2pkh
                    | RecipientType::P2sh,
                ..
            } | ReviewV2OutputOwnership::ProvenSelfTransfer { .. }
        )
    }

    fn is_change(output: &ReviewV2Output) -> bool {
        matches!(
            output.ownership(),
            ReviewV2OutputOwnership::ProvenChange { .. }
        )
    }

    fn is_op_return(output: &ReviewV2Output) -> bool {
        matches!(
            output.ownership(),
            ReviewV2OutputOwnership::NotOwned {
                recipient_type: RecipientType::OpReturn,
                ..
            }
        )
    }
}

impl Drop for ReviewSession<'_, '_> {
    fn drop(&mut self) {
        if self.active && !self.flow.is_finished() {
            let _ = self.flow.fail(WipingReason::Cancelled);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn same_provenance_stale_hold_completion_wipes() {
        let mut flow = ScreenFlow::new(FlowKind::SigningA1B);
        flow.state = MachineState::Screen(ScreenKind::FinalApproval);
        let provenance = flow.provenance.expect("live provenance");
        let pending = ApprovalToken {
            provenance,
            cycle: 9,
        };
        let stale = ApprovalToken {
            provenance,
            cycle: 8,
        };
        let review_hash = [0x5a; 32];

        assert!(matches!(
            flow.bind_completed_hold(Some(pending), stale, review_hash),
            Err(ScopedApplyOutcome::FailedWiped(
                WipingReason::ReviewIdentityMismatch
            ))
        ));
        assert_eq!(
            flow.terminal(),
            Some(FlowTerminal::FailedWiped(
                WipingReason::ReviewIdentityMismatch
            ))
        );
        assert!(flow.approval_identity().is_none());
    }
}
