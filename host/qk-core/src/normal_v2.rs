//! QK-DEC-149 HOST-only normal A1+B orchestration.
//!
//! This owner is the sole product-process path from hostile PSBT and A1 bytes
//! through authenticated card facts, immutable schema-v3 review, one approval
//! hold, purpose-bound A/B signing, fresh finalization verification and one
//! explicit export route. It exposes no byte accessor for retained ingress,
//! A2, Seed-A, signer state, or finalized artifacts.

#[cfg(feature = "normal-process")]
use crate::capability::NormalCardBSignatureV2;
use crate::capability::{
    CoreDeviceGrants, CoreScreen, KeypadKey, NormalCardBDataV2, NormalCardMockErrorV2,
};
use crate::error::{CoreError, Interruption, IoRejection};
use crate::io_wire::Source;
use crate::normal_artifact_v2::{
    NormalArtifactErrorV2, NormalExportActionV2, NormalExportArtifactsV2, NormalExportProgressV2,
    NormalExportResultV2, NormalExportTransferV2, NormalProfileV2,
};
use crate::session::{CoreMode, CoreOutbound, CoreReceiveEvent, CoreSession};
#[cfg(feature = "normal-process")]
use crate::wipe;
use crate::wipe::{WipingArray, WipingValueVec};
use core::fmt;
use qk_descriptor::parse_descriptor_pair_v2;
#[cfg(feature = "normal-process")]
use qk_psbt::ValidatedNormalV3Parts;
use qk_psbt::{
    build_validated_normal_v3, finalize_validated_normal_v3, DirectRbf, FeeWarning, InputSource,
    NormalFinalizationErrorV3, NormalSubmittedSignatureV3, OwnedS0, RecipientType, ReviewNetwork,
    ReviewV3, ReviewV3Hash, ReviewV3Output, ReviewV3OutputOwnership, ValidatedNormalV3,
};
use qk_wallet_v2::{
    sign_validated_normal_role_a_v3, validate_normal_role_a_binding_v3, NormalRoleASigningErrorV3,
};

const ROLE_B_XPUB_START: usize = 180;
const ROLE_B_XPUB_END: usize = 291;
const A1_CAPSULE_BYTES: usize = 67;
#[cfg(feature = "normal-process")]
const HALF_CURVE_ORDER: [u8; 32] = [
    0x7f, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0x5d, 0x57, 0x6e, 0x73, 0x57, 0xa4, 0x50, 0x1d, 0xdf, 0xe9, 0x2f, 0x46, 0x68, 0x1b, 0x20, 0xa0,
];

/// Exact normal-flow state order visible to the HOST screen owner.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum NormalStageV2 {
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

#[cfg(feature = "normal-process")]
const PROCESS_STAGE_TRACE_CAPACITY: usize = 8;

/// Fixed process-only trace of stages traversed inside one leaf call.
#[cfg(feature = "normal-process")]
struct ProcessStageTraceV2 {
    stages: [Option<NormalStageV2>; PROCESS_STAGE_TRACE_CAPACITY],
    len: usize,
}

#[cfg(feature = "normal-process")]
impl ProcessStageTraceV2 {
    const fn starting() -> Self {
        let mut value = Self {
            stages: [None; PROCESS_STAGE_TRACE_CAPACITY],
            len: 0,
        };
        value.stages[0] = Some(NormalStageV2::NormalStart);
        value.len = 1;
        value
    }

    fn record(&mut self, stage: NormalStageV2) {
        if let Some(slot) = self.stages.get_mut(self.len) {
            *slot = Some(stage);
            self.len = self.len.saturating_add(1);
        }
    }

    fn take(&mut self) -> [Option<NormalStageV2>; PROCESS_STAGE_TRACE_CAPACITY] {
        let stages = self.stages;
        self.stages = [None; PROCESS_STAGE_TRACE_CAPACITY];
        self.len = 0;
        stages
    }
}

#[cfg(feature = "normal-process")]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum ProcessSignatureRejectionV2 {
    Malformed,
    HighS,
    RepeatedR,
    BindingMismatch,
    KeyMismatch,
    Invalid,
}

/// Exact review cursor. Output and input positions are transaction-order
/// indices; warning positions are canonical QK-FEE-POLICY-V2 indices.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum NormalReviewPositionV2 {
    Overview,
    Arithmetic,
    Recipient(usize),
    Change(usize),
    OpReturn(usize),
    Locktime,
    Sequence(usize),
    FeePolicy,
    FeeFacts,
    Warning(usize),
    FinalApproval,
}

/// Profile and transaction-summary facts for the overview screen.
#[derive(Clone, Copy)]
pub struct NormalOverviewViewV2 {
    profile: NormalProfileV2,
    network: ReviewNetwork,
    wallet_id: [u8; 32],
    input_count: usize,
    total_input_amount: u64,
}

impl NormalOverviewViewV2 {
    pub const fn profile(&self) -> NormalProfileV2 {
        self.profile
    }

    pub const fn network(&self) -> ReviewNetwork {
        self.network
    }

    pub const fn wallet_id(&self) -> [u8; 32] {
        self.wallet_id
    }

    pub const fn input_count(&self) -> usize {
        self.input_count
    }

    pub const fn total_input_amount(&self) -> u64 {
        self.total_input_amount
    }
}

/// Checked arithmetic facts for the arithmetic screen.
#[derive(Clone, Copy)]
pub struct NormalArithmeticViewV2 {
    total_input_amount: u64,
    total_output_amount: u64,
    fee: u64,
}

impl NormalArithmeticViewV2 {
    pub const fn total_input_amount(&self) -> u64 {
        self.total_input_amount
    }

    pub const fn total_output_amount(&self) -> u64 {
        self.total_output_amount
    }

    pub const fn fee(&self) -> u64 {
        self.fee
    }
}

/// Exact recipient classification selected by one recipient screen.
#[derive(Clone, Copy)]
pub enum NormalRecipientFactV2<'a> {
    External {
        recipient_type: RecipientType,
        data: &'a [u8],
    },
    SelfTransfer {
        child_index: u32,
        witness_program: &'a [u8],
    },
}

/// Exact facts for one non-change destination in transaction order.
#[derive(Clone, Copy)]
pub struct NormalRecipientViewV2<'a> {
    index: u32,
    amount: u64,
    script_pubkey: &'a [u8],
    recipient: NormalRecipientFactV2<'a>,
}

impl<'a> NormalRecipientViewV2<'a> {
    pub const fn index(&self) -> u32 {
        self.index
    }

    pub const fn amount(&self) -> u64 {
        self.amount
    }

    pub const fn script_pubkey(&self) -> &'a [u8] {
        self.script_pubkey
    }

    pub const fn recipient(&self) -> NormalRecipientFactV2<'a> {
        self.recipient
    }
}

/// Exact descriptor-proven change facts for one output.
#[derive(Clone, Copy)]
pub struct NormalChangeViewV2<'a> {
    index: u32,
    amount: u64,
    script_pubkey: &'a [u8],
    child_index: u32,
}

impl<'a> NormalChangeViewV2<'a> {
    pub const fn index(&self) -> u32 {
        self.index
    }

    pub const fn amount(&self) -> u64 {
        self.amount
    }

    pub const fn script_pubkey(&self) -> &'a [u8] {
        self.script_pubkey
    }

    pub const fn child_index(&self) -> u32 {
        self.child_index
    }
}

/// Exact canonical OP_RETURN facts for one output.
#[derive(Clone, Copy)]
pub struct NormalOpReturnViewV2<'a> {
    index: u32,
    amount: u64,
    script_pubkey: &'a [u8],
    payload: &'a [u8],
}

impl<'a> NormalOpReturnViewV2<'a> {
    pub const fn index(&self) -> u32 {
        self.index
    }

    pub const fn amount(&self) -> u64 {
        self.amount
    }

    pub const fn script_pubkey(&self) -> &'a [u8] {
        self.script_pubkey
    }

    pub const fn payload(&self) -> &'a [u8] {
        self.payload
    }
}

/// Exact locktime fact selected by the locktime screen.
#[derive(Clone, Copy)]
pub struct NormalLocktimeViewV2 {
    locktime: u32,
}

impl NormalLocktimeViewV2 {
    pub const fn locktime(self) -> u32 {
        self.locktime
    }
}

/// Exact sequence and direct-RBF facts for one input.
#[derive(Clone, Copy)]
pub struct NormalSequenceViewV2 {
    input_index: u32,
    sequence: u32,
    direct_rbf: DirectRbf,
}

impl NormalSequenceViewV2 {
    pub const fn input_index(&self) -> u32 {
        self.input_index
    }

    pub const fn sequence(&self) -> u32 {
        self.sequence
    }

    pub const fn direct_rbf(&self) -> DirectRbf {
        self.direct_rbf
    }
}

/// Exact versioned policy identifier, separated from its fee facts.
#[derive(Clone, Copy)]
pub struct NormalFeePolicyViewV2 {
    identifier: &'static [u8],
}

impl NormalFeePolicyViewV2 {
    pub const fn identifier(&self) -> &'static [u8] {
        self.identifier
    }
}

/// Exact fee facts already computed and bound by schema v3.
#[derive(Clone, Copy)]
pub struct NormalFeeFactsViewV2 {
    fee: u64,
    estimated_vsize: u32,
    fee_rate_msat_per_vbyte: u64,
}

impl NormalFeeFactsViewV2 {
    pub const fn fee(&self) -> u64 {
        self.fee
    }

    pub const fn estimated_vsize(&self) -> u32 {
        self.estimated_vsize
    }

    pub const fn fee_rate_msat_per_vbyte(&self) -> u64 {
        self.fee_rate_msat_per_vbyte
    }
}

/// One canonical warning selected without exposing sibling review facts.
#[derive(Clone, Copy)]
pub struct NormalWarningViewV2 {
    warning: FeeWarning,
}

impl NormalWarningViewV2 {
    pub const fn warning(self) -> FeeWarning {
        self.warning
    }
}

/// Exact profile/hash identity on the final approval screen.
#[derive(Clone, Copy)]
pub struct NormalFinalApprovalViewV2 {
    profile: NormalProfileV2,
    review_hash: ReviewV3Hash,
}

impl NormalFinalApprovalViewV2 {
    pub const fn profile(self) -> NormalProfileV2 {
        self.profile
    }

    pub const fn review_hash(self) -> ReviewV3Hash {
        self.review_hash
    }
}

/// Borrow-only result-screen wrapper over already-bound export facts.
#[derive(Clone, Copy)]
pub struct NormalTransactionResultViewV2<'a> {
    result: &'a NormalExportResultV2,
}

impl<'a> NormalTransactionResultViewV2<'a> {
    pub const fn result(self) -> &'a NormalExportResultV2 {
        self.result
    }
}

/// Narrow screen facts selected verbatim from the immutable profile,
/// schema-v3 review, finalization facts, or export result. No review screen
/// can borrow the whole review object or inspect a sibling screen's facts.
pub enum NormalScreenV2<'a> {
    Stage(NormalStageV2),
    ProfileBinding { profile: NormalProfileV2 },
    ReviewOverview(NormalOverviewViewV2),
    ReviewArithmetic(NormalArithmeticViewV2),
    ReviewRecipient(NormalRecipientViewV2<'a>),
    ReviewChange(NormalChangeViewV2<'a>),
    ReviewOpReturn(NormalOpReturnViewV2<'a>),
    ReviewLocktime(NormalLocktimeViewV2),
    ReviewSequence(NormalSequenceViewV2),
    ReviewFeePolicy(NormalFeePolicyViewV2),
    ReviewFeeFacts(NormalFeeFactsViewV2),
    ReviewWarning(NormalWarningViewV2),
    FinalApproval(NormalFinalApprovalViewV2),
    TransactionResult(NormalTransactionResultViewV2<'a>),
}

/// Opaque hold-cycle token minted by this one normal session.
#[derive(Clone, Copy, Eq, PartialEq)]
pub struct NormalApprovalTokenV2 {
    session_identity: [u8; 16],
    cycle: u64,
}

impl NormalApprovalTokenV2 {
    pub const fn cycle(self) -> u64 {
        self.cycle
    }
}

/// The exact profile, review and current cycle authorized by one hold.
#[derive(Clone, Copy, Eq, PartialEq)]
pub struct NormalApprovalIdentityV2 {
    token: NormalApprovalTokenV2,
    profile: NormalProfileV2,
    review_hash: ReviewV3Hash,
}

impl NormalApprovalIdentityV2 {
    pub const fn token(self) -> NormalApprovalTokenV2 {
        self.token
    }

    pub const fn profile(self) -> NormalProfileV2 {
        self.profile
    }

    pub const fn review_hash(self) -> ReviewV3Hash {
        self.review_hash
    }

    pub const fn cycle(self) -> u64 {
        self.token.cycle
    }
}

/// Closed local normal-flow rejection vocabulary.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum NormalErrorV2 {
    ProfileMissing,
    ProfileUnknown,
    ProfileMalformed,
    InvalidTransition,
    WrongIngressSource,
    CardAbsent,
    CardBindingMismatch,
    CardDataRejected,
    A1Rejected,
    RecoveredWalletMismatch,
    ReviewRejected,
    ReviewIncomplete,
    ReviewIdentityMismatch,
    ApprovalUnavailable,
    PostApprovalYield,
    RevalidationMismatch,
    SigningRejected,
    InvalidMockSignature,
    FinalizationRejected,
    ExportRouteUnavailable,
    ExportArtifactInvariant,
    ExportReceiptMismatch,
    BbqrVerificationMismatch,
    PartialSdCompletion,
    Finished,
    Interrupted(Interruption),
    Core(CoreError),
}

impl NormalErrorV2 {
    pub const fn name(self) -> &'static str {
        match self {
            Self::ProfileMissing => "ProfileMissing",
            Self::ProfileUnknown => "ProfileUnknown",
            Self::ProfileMalformed => "ProfileMalformed",
            Self::InvalidTransition => "InvalidTransition",
            Self::WrongIngressSource => "WrongIngressSource",
            Self::CardAbsent => "CardAbsent",
            Self::CardBindingMismatch => "CardBindingMismatch",
            Self::CardDataRejected => "CardDataRejected",
            Self::A1Rejected => "A1Rejected",
            Self::RecoveredWalletMismatch => "RecoveredWalletMismatch",
            Self::ReviewRejected => "ReviewRejected",
            Self::ReviewIncomplete => "ReviewIncomplete",
            Self::ReviewIdentityMismatch => "ReviewIdentityMismatch",
            Self::ApprovalUnavailable => "ApprovalUnavailable",
            Self::PostApprovalYield => "PostApprovalYield",
            Self::RevalidationMismatch => "RevalidationMismatch",
            Self::SigningRejected => "SigningRejected",
            Self::InvalidMockSignature => "InvalidMockSignature",
            Self::FinalizationRejected => "FinalizationRejected",
            Self::ExportRouteUnavailable => "ExportRouteUnavailable",
            Self::ExportArtifactInvariant => "ExportArtifactInvariant",
            Self::ExportReceiptMismatch => "ExportReceiptMismatch",
            Self::BbqrVerificationMismatch => "BbqrVerificationMismatch",
            Self::PartialSdCompletion => "PartialSdCompletion",
            Self::Finished => "Finished",
            Self::Interrupted(reason) => reason.name(),
            Self::Core(_) => "Core",
        }
    }
}

impl fmt::Display for NormalErrorV2 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.name())
    }
}

impl std::error::Error for NormalErrorV2 {}

/// One normal-flow transition and its optional complete QKIP request.
pub struct NormalProgressV2 {
    stage: NormalStageV2,
    outbound: Option<CoreOutbound>,
}

impl NormalProgressV2 {
    pub const fn stage(&self) -> NormalStageV2 {
        self.stage
    }

    pub const fn outbound(&self) -> Option<&CoreOutbound> {
        self.outbound.as_ref()
    }

    pub fn into_outbound(self) -> Option<CoreOutbound> {
        self.outbound
    }
}

/// Stream consumption plus the next automatically chained request, if any.
pub struct NormalReceiveOutcomeV2 {
    consumed: usize,
    progress: NormalProgressV2,
}

/// Immutable facts for exactly one role-B card signing request.
///
/// This process-only value contains no scalar, A2, Seed-A, or signature. Its
/// fields are copied only from the post-hold, freshly revalidated signing plan.
#[cfg(feature = "normal-process")]
pub struct NormalCardBSigningRequestV2 {
    wallet_id: [u8; 32],
    review_hash: ReviewV3Hash,
    input_index: u32,
    branch: u32,
    child_index: u32,
    digest: [u8; 32],
    role_b_pubkey: [u8; 33],
}

#[cfg(feature = "normal-process")]
impl NormalCardBSigningRequestV2 {
    pub const fn wallet_id(&self) -> &[u8; 32] {
        &self.wallet_id
    }

    pub const fn review_hash(&self) -> &ReviewV3Hash {
        &self.review_hash
    }

    pub const fn input_index(&self) -> u32 {
        self.input_index
    }

    pub const fn branch(&self) -> u32 {
        self.branch
    }

    pub const fn child_index(&self) -> u32 {
        self.child_index
    }

    pub const fn digest(&self) -> &[u8; 32] {
        &self.digest
    }

    pub const fn role_b_pubkey(&self) -> &[u8; 33] {
        &self.role_b_pubkey
    }
}

#[cfg(feature = "normal-process")]
impl Drop for NormalCardBSigningRequestV2 {
    fn drop(&mut self) {
        wipe::bytes(&mut self.wallet_id);
        wipe::bytes(&mut self.review_hash);
        wipe::words32(core::slice::from_mut(&mut self.input_index));
        wipe::words32(core::slice::from_mut(&mut self.branch));
        wipe::words32(core::slice::from_mut(&mut self.child_index));
        wipe::bytes(&mut self.digest);
        wipe::bytes(&mut self.role_b_pubkey);
    }
}

/// One low-S role-B signature that passed exact request binding and
/// libsecp256k1 verification before it became retained finalization input.
#[cfg(feature = "normal-process")]
struct NormalVerifiedCardBSignatureV2 {
    input_index: u32,
    der: WipingArray<72>,
    len: usize,
    r: WipingArray<32>,
}

#[cfg(feature = "normal-process")]
impl NormalVerifiedCardBSignatureV2 {
    fn der(&self) -> &[u8] {
        self.der.as_array().get(..self.len).unwrap_or_default()
    }
}

/// Move-only post-hold owner retained while qk-core requests role-B
/// signatures one at a time.
#[cfg(feature = "normal-process")]
struct NormalProcessSigningStateV2 {
    parts: ValidatedNormalV3Parts,
    role_a: qk_wallet_v2::WalletNormalRoleASignaturesV3,
    role_b: WipingValueVec<NormalVerifiedCardBSignatureV2>,
    cursor: usize,
}

impl NormalReceiveOutcomeV2 {
    pub const fn consumed(&self) -> usize {
        self.consumed
    }

    pub const fn stage(&self) -> NormalStageV2 {
        self.progress.stage
    }

    pub const fn outbound(&self) -> Option<&CoreOutbound> {
        self.progress.outbound.as_ref()
    }

    pub fn into_outbound(self) -> Option<CoreOutbound> {
        self.progress.outbound
    }
}

/// One complete normal A1+B HOST session.
///
/// This type deliberately implements no Clone, Copy, Debug, Display,
/// serializer, logger or byte-export trait.
pub struct NormalSessionV2 {
    core: CoreSession,
    profile: NormalProfileV2,
    stage: NormalStageV2,
    pending_source: Option<Source>,
    s0: Option<OwnedS0>,
    card: Option<NormalCardBDataV2>,
    seed_a: Option<WipingArray<32>>,
    proof: Option<ValidatedNormalV3>,
    review_position: Option<NormalReviewPositionV2>,
    next_cycle: u64,
    pending_hold: Option<NormalApprovalTokenV2>,
    approval: Option<NormalApprovalIdentityV2>,
    artifacts: Option<NormalExportArtifactsV2>,
    transfer: Option<NormalExportTransferV2>,
    result: Option<NormalExportResultV2>,
    close_pending: bool,
    terminal_error: Option<NormalErrorV2>,
    #[cfg(feature = "normal-process")]
    process_stage_trace: ProcessStageTraceV2,
    #[cfg(feature = "normal-process")]
    process_signature_rejection: Option<ProcessSignatureRejectionV2>,
    #[cfg(feature = "normal-process")]
    process_signing: Option<NormalProcessSigningStateV2>,
}

impl NormalSessionV2 {
    /// Parse and bind exactly one profile byte, then mint the QKIP session.
    pub fn start(
        profile_bytes: &[u8],
        grants: CoreDeviceGrants,
    ) -> Result<(Self, CoreOutbound), NormalErrorV2> {
        let profile = NormalProfileV2::parse(profile_bytes).map_err(map_artifact_error)?;
        let (core, outbound) =
            CoreSession::start(CoreMode::A1B, grants).map_err(NormalErrorV2::Core)?;
        Ok((Self::from_core(core, profile), outbound))
    }

    /// Deterministic public-data constructor for unit and fuzz builds.
    #[cfg(any(test, feature = "fuzzing"))]
    #[doc(hidden)]
    pub fn fuzz_start(
        namespace: [u8; 12],
        last_counter: u32,
        profile_bytes: &[u8],
        grants: CoreDeviceGrants,
    ) -> Result<(Self, CoreOutbound), NormalErrorV2> {
        let profile = NormalProfileV2::parse(profile_bytes).map_err(map_artifact_error)?;
        let (core, outbound) =
            crate::session::fuzz_start_session(namespace, last_counter, CoreMode::A1B, grants)
                .map_err(NormalErrorV2::Core)?;
        Ok((Self::from_core(core, profile), outbound))
    }

    fn from_core(core: CoreSession, profile: NormalProfileV2) -> Self {
        Self {
            core,
            profile,
            stage: NormalStageV2::NormalStart,
            pending_source: None,
            s0: None,
            card: None,
            seed_a: None,
            proof: None,
            review_position: None,
            next_cycle: 1,
            pending_hold: None,
            approval: None,
            artifacts: None,
            transfer: None,
            result: None,
            close_pending: false,
            terminal_error: None,
            #[cfg(feature = "normal-process")]
            process_stage_trace: ProcessStageTraceV2::starting(),
            #[cfg(feature = "normal-process")]
            process_signature_rejection: None,
            #[cfg(feature = "normal-process")]
            process_signing: None,
        }
    }

    pub const fn profile(&self) -> NormalProfileV2 {
        self.profile
    }

    pub const fn stage(&self) -> NormalStageV2 {
        self.stage
    }

    pub const fn review_position(&self) -> Option<NormalReviewPositionV2> {
        self.review_position
    }

    pub const fn approval_identity(&self) -> Option<NormalApprovalIdentityV2> {
        self.approval
    }

    pub const fn result(&self) -> Option<&NormalExportResultV2> {
        self.result.as_ref()
    }

    pub const fn terminal_error(&self) -> Option<NormalErrorV2> {
        self.terminal_error
    }

    pub fn is_terminal(&self) -> bool {
        self.terminal_error.is_some() || self.stage == NormalStageV2::CompletedWiped
    }

    pub fn screen(&self) -> Option<NormalScreenV2<'_>> {
        if self.is_terminal() && self.stage != NormalStageV2::CompletedWiped {
            return None;
        }
        let screen = match self.stage {
            NormalStageV2::ProfileBinding => NormalScreenV2::ProfileBinding {
                profile: self.profile,
            },
            NormalStageV2::Review | NormalStageV2::FinalApproval => self.review_screen()?,
            NormalStageV2::TransactionResult => {
                NormalScreenV2::TransactionResult(NormalTransactionResultViewV2 {
                    result: self.result.as_ref()?,
                })
            }
            stage => NormalScreenV2::Stage(stage),
        };
        Some(screen)
    }

    #[cfg(feature = "normal-process")]
    pub(crate) fn take_process_stage_trace(
        &mut self,
    ) -> [Option<NormalStageV2>; PROCESS_STAGE_TRACE_CAPACITY] {
        self.process_stage_trace.take()
    }

    #[cfg(feature = "normal-process")]
    pub(crate) fn take_process_signature_rejection(
        &mut self,
    ) -> Option<ProcessSignatureRejectionV2> {
        self.process_signature_rejection.take()
    }

    /// Consume one QKIP frame and automatically request only the next exact
    /// ingress chunk or selected export step.
    pub fn receive(
        &mut self,
        input: &[u8],
        ancillary_present: bool,
    ) -> Result<NormalReceiveOutcomeV2, NormalErrorV2> {
        self.require_active()?;
        if self.transfer.is_some() {
            return self.receive_export(input, ancillary_present);
        }
        if self.approval.is_some() && !self.close_pending {
            return Err(self.fail(
                NormalErrorV2::PostApprovalYield,
                Interruption::OperationFailed,
            ));
        }
        let received = match self.core.receive(input, ancillary_present) {
            Ok(value) => value,
            Err(error) => {
                let mapped = match (self.stage, error) {
                    (
                        NormalStageV2::A1Intake,
                        CoreError::IoRejected(IoRejection::SourceKindMismatch),
                    )
                    | (NormalStageV2::A1Intake, CoreError::ResponseSourceMismatch) => {
                        NormalErrorV2::WrongIngressSource
                    }
                    (
                        NormalStageV2::A1Intake,
                        CoreError::IoRejected(IoRejection::SourceLengthMismatch),
                    )
                    | (NormalStageV2::A1Intake, CoreError::ResponseTotalLengthMismatch) => {
                        NormalErrorV2::A1Rejected
                    }
                    (_, error) => NormalErrorV2::Core(error),
                };
                return Err(self.fail(mapped, Interruption::OperationFailed));
            }
        };
        let consumed = received.consumed();
        let progress = match received.event() {
            CoreReceiveEvent::NeedMore => self.progress(None),
            CoreReceiveEvent::SessionReady if self.stage == NormalStageV2::NormalStart => {
                self.advance(NormalStageV2::ProfileBinding, None)?
            }
            CoreReceiveEvent::IngressBegan { source, .. }
                if self.pending_source == Some(source)
                    && matches!(
                        self.stage,
                        NormalStageV2::PsbtIntake | NormalStageV2::A1Intake
                    ) =>
            {
                let outbound = self.core.request_next_chunk().map_err(|error| {
                    self.fail(NormalErrorV2::Core(error), Interruption::OperationFailed)
                })?;
                self.progress(Some(outbound))
            }
            CoreReceiveEvent::IngressChunk { final_chunk, .. }
                if matches!(
                    self.stage,
                    NormalStageV2::PsbtIntake | NormalStageV2::A1Intake
                ) =>
            {
                if final_chunk {
                    self.finish_ingress()?
                } else {
                    let outbound = self.core.request_next_chunk().map_err(|error| {
                        self.fail(NormalErrorV2::Core(error), Interruption::OperationFailed)
                    })?;
                    self.progress(Some(outbound))
                }
            }
            CoreReceiveEvent::SessionClosed if self.close_pending => {
                self.close_pending = false;
                self.cleanup_owned();
                self.stage = NormalStageV2::CompletedWiped;
                #[cfg(feature = "normal-process")]
                self.process_stage_trace.record(self.stage);
                NormalProgressV2 {
                    stage: self.stage,
                    outbound: None,
                }
            }
            CoreReceiveEvent::SessionReady
            | CoreReceiveEvent::IngressBegan { .. }
            | CoreReceiveEvent::IngressChunk { .. }
            | CoreReceiveEvent::A1PrintBegan
            | CoreReceiveEvent::KitPrintBegan
            | CoreReceiveEvent::A1PrintWritten { .. }
            | CoreReceiveEvent::KitPrintWritten { .. }
            | CoreReceiveEvent::A1PrintFinished { .. }
            | CoreReceiveEvent::KitPrintFinished { .. }
            | CoreReceiveEvent::SessionClosed => {
                return Err(self.fail(
                    NormalErrorV2::InvalidTransition,
                    Interruption::OperationFailed,
                ))
            }
        };
        Ok(NormalReceiveOutcomeV2 { consumed, progress })
    }

    /// Confirm the immutable displayed profile and enter transport.
    pub fn confirm_profile(&mut self) -> Result<NormalProgressV2, NormalErrorV2> {
        self.require_preapproval()?;
        if self.stage != NormalStageV2::ProfileBinding {
            return Err(self.fail(
                NormalErrorV2::InvalidTransition,
                Interruption::OperationFailed,
            ));
        }
        let key = self
            .core
            .normal_read_key(KeypadKey::EqualsConfirmEnter)
            .map_err(|error| {
                self.fail(NormalErrorV2::Core(error), Interruption::CapabilityFailed)
            })?;
        if key != KeypadKey::EqualsConfirmEnter {
            return Err(self.fail(
                NormalErrorV2::InvalidTransition,
                Interruption::OperationFailed,
            ));
        }
        self.advance(NormalStageV2::Transport, None)
    }

    /// Begin the sole normal PSBT intake from an exact ratified source.
    pub fn begin_psbt_intake(&mut self, source: Source) -> Result<NormalProgressV2, NormalErrorV2> {
        self.require_preapproval()?;
        if self.stage != NormalStageV2::Transport {
            return Err(self.fail(
                NormalErrorV2::InvalidTransition,
                Interruption::OperationFailed,
            ));
        }
        if !matches!(source, Source::CameraBbqrPsbt | Source::MediaPsbt) {
            return Err(self.fail(
                NormalErrorV2::WrongIngressSource,
                Interruption::OperationFailed,
            ));
        }
        let outbound = self.core.begin_ingress(source).map_err(|error| {
            self.fail(NormalErrorV2::Core(error), Interruption::OperationFailed)
        })?;
        self.pending_source = Some(source);
        self.advance(NormalStageV2::PsbtIntake, Some(outbound))
    }

    /// Consume the sole authenticated mock card-B factor.
    pub fn accept_card_b(&mut self) -> Result<NormalProgressV2, NormalErrorV2> {
        self.require_preapproval()?;
        if self.stage != NormalStageV2::FactorB || self.card.is_some() {
            return Err(self.fail(
                NormalErrorV2::InvalidTransition,
                Interruption::OperationFailed,
            ));
        }
        let card = match self.core.take_normal_card_data() {
            Ok(value) => value,
            Err(NormalCardMockErrorV2::CardAbsent) => {
                return Err(self.fail(NormalErrorV2::CardAbsent, Interruption::CardRemoved))
            }
            Err(_) => {
                return Err(self.fail(
                    NormalErrorV2::CardDataRejected,
                    Interruption::OperationFailed,
                ))
            }
        };
        match card_binding_matches(&card) {
            Ok(true) => {}
            Ok(false) => {
                drop(card);
                return Err(self.fail(
                    NormalErrorV2::CardBindingMismatch,
                    Interruption::OperationFailed,
                ));
            }
            Err(()) => {
                drop(card);
                return Err(self.fail(
                    NormalErrorV2::CardDataRejected,
                    Interruption::OperationFailed,
                ));
            }
        }
        self.card = Some(card);
        self.advance(NormalStageV2::A1Intake, None)
    }

    /// Begin exact 67-byte camera A1 intake after factor B.
    pub fn begin_a1_intake(&mut self) -> Result<NormalProgressV2, NormalErrorV2> {
        self.require_preapproval()?;
        if self.stage != NormalStageV2::A1Intake || self.card.is_none() {
            return Err(self.fail(
                NormalErrorV2::InvalidTransition,
                Interruption::OperationFailed,
            ));
        }
        let outbound = self
            .core
            .begin_ingress(Source::CameraA1Candidate)
            .map_err(|error| {
                self.fail(NormalErrorV2::Core(error), Interruption::OperationFailed)
            })?;
        self.pending_source = Some(Source::CameraA1Candidate);
        Ok(self.progress(Some(outbound)))
    }

    /// Prove the A binding before constructing the immutable transaction
    /// review, then consume S0 into the normal signing capability.
    pub fn validate(&mut self) -> Result<NormalProgressV2, NormalErrorV2> {
        self.require_preapproval()?;
        if self.stage != NormalStageV2::FactorA1 || self.proof.is_some() {
            return Err(self.fail(
                NormalErrorV2::InvalidTransition,
                Interruption::OperationFailed,
            ));
        }
        self.advance(NormalStageV2::Validation, None)?;
        let (Some(seed_a), Some(card), Some(s0)) =
            (self.seed_a.as_ref(), self.card.as_ref(), self.s0.take())
        else {
            return Err(self.fail(
                NormalErrorV2::InvalidTransition,
                Interruption::OperationFailed,
            ));
        };
        let descriptor =
            match parse_descriptor_pair_v2(&card.descriptors()[0], &card.descriptors()[1]) {
                Ok(value) => value,
                Err(_) => {
                    return Err(self.fail(
                        NormalErrorV2::CardDataRejected,
                        Interruption::OperationFailed,
                    ))
                }
            };
        let proof = match build_validated_normal_v3(s0, descriptor) {
            Ok(value) => value,
            Err(_) => {
                return Err(self.fail(NormalErrorV2::ReviewRejected, Interruption::OperationFailed))
            }
        };
        if proof.wallet_id() != card.wallet_id() {
            drop(proof);
            return Err(self.fail(
                NormalErrorV2::CardBindingMismatch,
                Interruption::OperationFailed,
            ));
        }
        if validate_normal_role_a_binding_v3(
            seed_a.as_array(),
            card.descriptors(),
            &card.wallet_id(),
            &proof,
        )
        .is_err()
        {
            drop(proof);
            return Err(self.fail(
                NormalErrorV2::RecoveredWalletMismatch,
                Interruption::OperationFailed,
            ));
        }
        self.proof = Some(proof);
        self.review_position = Some(NormalReviewPositionV2::Overview);
        self.advance(NormalStageV2::Review, None)
    }

    /// Visit the exact next review item. There is no index-selecting or skip
    /// API, and completion stops at FinalApproval.
    pub fn advance_review(&mut self) -> Result<NormalProgressV2, NormalErrorV2> {
        self.require_preapproval()?;
        if self.stage != NormalStageV2::Review {
            return Err(self.fail(
                NormalErrorV2::ReviewIncomplete,
                Interruption::OperationFailed,
            ));
        }
        let key = self
            .core
            .normal_read_key(KeypadKey::EqualsConfirmEnter)
            .map_err(|error| {
                self.fail(NormalErrorV2::Core(error), Interruption::CapabilityFailed)
            })?;
        if key != KeypadKey::EqualsConfirmEnter {
            return Err(self.fail(
                NormalErrorV2::InvalidTransition,
                Interruption::OperationFailed,
            ));
        }
        let next = self.next_review_position().ok_or_else(|| {
            self.fail(
                NormalErrorV2::ReviewIncomplete,
                Interruption::OperationFailed,
            )
        })?;
        self.review_position = Some(next);
        if next == NormalReviewPositionV2::FinalApproval {
            self.advance(NormalStageV2::FinalApproval, None)
        } else {
            self.show_review_position()?;
            Ok(self.progress(None))
        }
    }

    /// Start the hold only from the final review position and mint the one
    /// current monotonic cycle token.
    pub fn begin_approval_hold(&mut self) -> Result<NormalApprovalTokenV2, NormalErrorV2> {
        self.require_preapproval()?;
        if self.stage != NormalStageV2::FinalApproval
            || self.review_position != Some(NormalReviewPositionV2::FinalApproval)
            || self.pending_hold.is_some()
        {
            return Err(self.fail(
                NormalErrorV2::ApprovalUnavailable,
                Interruption::OperationFailed,
            ));
        }
        let session_identity = match self.core.normal_session_identity() {
            Ok(identity) => *identity,
            Err(error) => {
                return Err(self.fail(NormalErrorV2::Core(error), Interruption::OperationFailed))
            }
        };
        let token = NormalApprovalTokenV2 {
            session_identity,
            cycle: self.next_cycle,
        };
        self.next_cycle = self.next_cycle.checked_add(1).ok_or_else(|| {
            self.fail(
                NormalErrorV2::ApprovalUnavailable,
                Interruption::OperationFailed,
            )
        })?;
        self.pending_hold = Some(token);
        Ok(token)
    }

    /// Complete the hold, bind its exact identity, reparse and revalidate,
    /// sign A, verify mock B, finalize, freshly verify, and release only the
    /// route-selection capability.
    pub fn complete_approval_hold(
        &mut self,
        token: NormalApprovalTokenV2,
    ) -> Result<NormalProgressV2, NormalErrorV2> {
        let review_hash = self.complete_hold_and_revalidate(token)?;
        self.sign_and_finalize(review_hash)
    }

    /// Complete the process-path hold and pause after role-A signing so the
    /// caller can request each role-B signature from the card one at a time.
    /// The default non-process completion API remains all-in-one.
    #[cfg(feature = "normal-process")]
    pub(crate) fn complete_process_approval_hold(
        &mut self,
        token: NormalApprovalTokenV2,
    ) -> Result<NormalProgressV2, NormalErrorV2> {
        let review_hash = self.complete_hold_and_revalidate(token)?;
        self.begin_process_signing(review_hash)
    }

    /// Return only the current post-revalidation role-B request. No request is
    /// observable before CardBSigning or after its response is consumed.
    #[cfg(feature = "normal-process")]
    pub(crate) fn process_card_b_signing_request(&self) -> Option<NormalCardBSigningRequestV2> {
        if self.stage != NormalStageV2::CardBSigning {
            return None;
        }
        let state = self.process_signing.as_ref()?;
        let plan = state.parts.input_signing_plans().get(state.cursor)?;
        if plan
            .existing_role_signatures()
            .get(1)
            .copied()
            .unwrap_or(true)
        {
            return None;
        }
        Some(NormalCardBSigningRequestV2 {
            wallet_id: state.parts.wallet_id(),
            review_hash: state.parts.review_hash(),
            input_index: plan.input_index(),
            branch: plan.branch(),
            child_index: plan.child_index(),
            digest: *plan.digest(),
            role_b_pubkey: *plan.role_public_keys().get(1)?,
        })
    }

    /// Test-only seam for placing one already-verified public fixture record
    /// in the bounded retained-response owner without advancing its cursor.
    #[cfg(all(feature = "normal-process", any(test, feature = "fuzzing")))]
    pub(crate) fn fuzz_preseed_retained_card_signature(
        &mut self,
        der_signature: &mut [u8],
    ) -> bool {
        let input = ProcessSignatureInputGuard(der_signature);
        let Some(request) = self.process_card_b_signing_request() else {
            return false;
        };
        let verified = verify_process_card_b_signature(
            &request,
            *request.review_hash(),
            request.input_index(),
            *request.role_b_pubkey(),
            input.as_slice(),
            &[],
        );
        drop(request);
        drop(input);
        let Ok(verified) = verified else {
            return false;
        };
        let Some(state) = self.process_signing.as_mut() else {
            return false;
        };
        if !state.role_b.as_slice().is_empty() {
            return false;
        }
        state.role_b.try_push(verified).is_ok()
    }

    /// Bind, normalize, and verify one exact card reply before retaining its
    /// low-S DER owner. The caller's response buffer is cleared on every path.
    #[cfg(feature = "normal-process")]
    pub(crate) fn accept_process_card_b_signature(
        &mut self,
        review_hash: ReviewV3Hash,
        input_index: u32,
        role_b_pubkey: [u8; 33],
        der_signature: &mut [u8],
    ) -> Result<NormalProgressV2, NormalErrorV2> {
        let input = ProcessSignatureInputGuard(der_signature);
        self.require_active()?;
        let Some(request) = self.process_card_b_signing_request() else {
            return Err(self.fail(
                NormalErrorV2::InvalidTransition,
                Interruption::OperationFailed,
            ));
        };
        let verified = verify_process_card_b_signature(
            &request,
            review_hash,
            input_index,
            role_b_pubkey,
            input.as_slice(),
            match self.process_signing.as_ref() {
                Some(state) => state.role_b.as_slice(),
                None => &[],
            },
        );
        drop(request);
        drop(input);
        let verified = match verified {
            Ok(value) => value,
            Err(rejection) => {
                let error = self.fail(
                    NormalErrorV2::InvalidMockSignature,
                    Interruption::OperationFailed,
                );
                self.process_signature_rejection = Some(rejection);
                return Err(error);
            }
        };
        let Some(state) = self.process_signing.as_mut() else {
            drop(verified);
            return Err(self.fail(
                NormalErrorV2::InvalidTransition,
                Interruption::OperationFailed,
            ));
        };
        if state.role_b.try_push(verified).is_err() {
            return Err(self.fail(
                NormalErrorV2::SigningRejected,
                Interruption::OperationFailed,
            ));
        }
        state.cursor = state.cursor.saturating_add(1);
        advance_process_signing_cursor(state);
        if self.process_card_b_signing_request().is_some() {
            Ok(self.progress(None))
        } else {
            self.finish_process_signing()
        }
    }

    fn complete_hold_and_revalidate(
        &mut self,
        token: NormalApprovalTokenV2,
    ) -> Result<ReviewV3Hash, NormalErrorV2> {
        self.require_active()?;
        if self.stage != NormalStageV2::FinalApproval {
            let error = if self.approval.is_some() {
                NormalErrorV2::PostApprovalYield
            } else {
                NormalErrorV2::ApprovalUnavailable
            };
            return Err(self.fail(error, Interruption::OperationFailed));
        }
        let Some(expected) = self.pending_hold else {
            return Err(self.fail(
                NormalErrorV2::ApprovalUnavailable,
                Interruption::OperationFailed,
            ));
        };
        if expected != token {
            self.pending_hold = None;
            return Err(self.fail(
                NormalErrorV2::ReviewIdentityMismatch,
                Interruption::OperationFailed,
            ));
        }
        self.pending_hold = None;
        let review_hash = self
            .proof
            .as_ref()
            .map(ValidatedNormalV3::review_hash)
            .ok_or_else(|| {
                self.fail(
                    NormalErrorV2::ApprovalUnavailable,
                    Interruption::OperationFailed,
                )
            })?;
        self.approval = Some(NormalApprovalIdentityV2 {
            token,
            profile: self.profile,
            review_hash,
        });
        self.advance(NormalStageV2::ApprovalHeld, None)?;
        self.advance(NormalStageV2::Revalidation, None)?;
        let Some(proof) = self.proof.as_ref() else {
            return Err(self.fail(
                NormalErrorV2::RevalidationMismatch,
                Interruption::OperationFailed,
            ));
        };
        if proof.revalidate().is_err() {
            return Err(self.fail(
                NormalErrorV2::RevalidationMismatch,
                Interruption::OperationFailed,
            ));
        }
        Ok(review_hash)
    }

    /// Select exactly one post-finalization carrier. No second route, retry,
    /// or fallback remains reachable in this session.
    pub fn choose_export(
        &mut self,
        action: NormalExportActionV2,
    ) -> Result<NormalProgressV2, NormalErrorV2> {
        self.require_active()?;
        if self.stage != NormalStageV2::AwaitingExportAction
            || self.transfer.is_some()
            || self.result.is_some()
        {
            let error = if self.approval.is_some() {
                NormalErrorV2::PostApprovalYield
            } else {
                NormalErrorV2::InvalidTransition
            };
            return Err(self.fail(error, Interruption::OperationFailed));
        }
        let artifacts = self.artifacts.take().ok_or_else(|| {
            self.fail(
                NormalErrorV2::ExportArtifactInvariant,
                Interruption::OperationFailed,
            )
        })?;
        let mut transfer = artifacts
            .select(action)
            .map_err(|error| self.fail(map_artifact_error(error), Interruption::OperationFailed))?;
        let request = transfer
            .next_request()
            .map_err(|error| self.fail(map_artifact_error(error), Interruption::OperationFailed))?;
        let outbound = match self.core.begin_normal_egress(request.bytes()) {
            Ok(value) => value,
            Err(error) => {
                let error = transfer.normalize_outer_error(NormalArtifactErrorV2::Core(error));
                return Err(self.fail(map_artifact_error(error), Interruption::OperationFailed));
            }
        };
        drop(request);
        self.transfer = Some(transfer);
        self.advance(NormalStageV2::AwaitingExportAction, Some(outbound))
    }

    /// Acknowledge the bound result facts and begin the sole graceful close.
    pub fn complete_result(&mut self) -> Result<NormalProgressV2, NormalErrorV2> {
        self.require_active()?;
        if self.stage != NormalStageV2::TransactionResult || self.result.is_none() {
            let error = if self.approval.is_some() {
                NormalErrorV2::PostApprovalYield
            } else {
                NormalErrorV2::InvalidTransition
            };
            return Err(self.fail(error, Interruption::OperationFailed));
        }
        let outbound = self.core.begin_close().map_err(|error| {
            self.fail(NormalErrorV2::Core(error), Interruption::OperationFailed)
        })?;
        self.close_pending = true;
        Ok(self.progress(Some(outbound)))
    }

    /// Apply one closed interruption with its existing named reason in every
    /// nonterminal state, except that an already-final first SD artifact makes
    /// the logical two-file delivery partially complete.
    pub fn interrupt(&mut self, reason: Interruption) -> Result<(), NormalErrorV2> {
        self.require_active()?;
        Err(self.fail(NormalErrorV2::Interrupted(reason), reason))
    }

    fn finish_ingress(&mut self) -> Result<NormalProgressV2, NormalErrorV2> {
        let ingress = self.core.take_normal_ingress().map_err(|error| {
            self.fail(NormalErrorV2::Core(error), Interruption::OperationFailed)
        })?;
        let (source, bytes) = ingress.into_normal_parts();
        if self.pending_source.take() != Some(source) {
            drop(bytes);
            return Err(self.fail(
                NormalErrorV2::WrongIngressSource,
                Interruption::OperationFailed,
            ));
        }
        match self.stage {
            NormalStageV2::PsbtIntake => {
                let input_source = match source {
                    Source::CameraBbqrPsbt => InputSource::Qr,
                    Source::MediaPsbt => InputSource::MicroSd,
                    _ => {
                        drop(bytes);
                        return Err(self.fail(
                            NormalErrorV2::WrongIngressSource,
                            Interruption::OperationFailed,
                        ));
                    }
                };
                let s0 = OwnedS0::new(bytes.as_slice(), input_source).map_err(|_| {
                    self.fail(NormalErrorV2::ReviewRejected, Interruption::OperationFailed)
                })?;
                drop(bytes);
                self.s0 = Some(s0);
                self.advance(NormalStageV2::FactorB, None)
            }
            NormalStageV2::A1Intake => {
                if let Err(error) = validate_a1_candidate(source, bytes.len()) {
                    drop(bytes);
                    return Err(self.fail(error, Interruption::OperationFailed));
                }
                let Some(card) = self.card.as_ref() else {
                    drop(bytes);
                    return Err(self.fail(
                        NormalErrorV2::CardDataRejected,
                        Interruption::OperationFailed,
                    ));
                };
                let mut seed = WipingArray::<32>::zeroed();
                if qk_a1::decrypt(
                    card.a2(),
                    &card.wallet_id(),
                    bytes.as_slice(),
                    seed.as_mut_array(),
                )
                .is_err()
                {
                    drop(bytes);
                    return Err(self.fail(NormalErrorV2::A1Rejected, Interruption::OperationFailed));
                }
                drop(bytes);
                self.seed_a = Some(seed);
                self.advance(NormalStageV2::FactorA1, None)
            }
            _ => {
                drop(bytes);
                Err(self.fail(
                    NormalErrorV2::InvalidTransition,
                    Interruption::OperationFailed,
                ))
            }
        }
    }

    #[cfg(feature = "normal-process")]
    fn begin_process_signing(
        &mut self,
        approved_review_hash: ReviewV3Hash,
    ) -> Result<NormalProgressV2, NormalErrorV2> {
        self.advance(NormalStageV2::TerminalASigning, None)?;
        let Some(proof) = self.proof.take() else {
            return Err(self.fail(
                NormalErrorV2::SigningRejected,
                Interruption::OperationFailed,
            ));
        };
        let (Some(seed_a), Some(card)) = (self.seed_a.take(), self.card.take()) else {
            drop(proof);
            return Err(self.fail(
                NormalErrorV2::SigningRejected,
                Interruption::OperationFailed,
            ));
        };
        let signed = match sign_validated_normal_role_a_v3(
            seed_a.as_array(),
            card.descriptors(),
            &card.wallet_id(),
            proof,
        ) {
            Ok(value) => value,
            Err(NormalRoleASigningErrorV3::RecoveredWalletMismatch) => {
                drop(seed_a);
                drop(card);
                return Err(self.fail(
                    NormalErrorV2::RecoveredWalletMismatch,
                    Interruption::OperationFailed,
                ));
            }
            Err(_) => {
                drop(seed_a);
                drop(card);
                return Err(self.fail(
                    NormalErrorV2::SigningRejected,
                    Interruption::OperationFailed,
                ));
            }
        };
        drop(seed_a);
        drop(card);
        self.advance(NormalStageV2::CardBSigning, None)?;
        let (parts, role_a) = signed.into_finalization_parts();
        if parts.review_hash() != approved_review_hash {
            drop(parts);
            drop(role_a);
            return Err(self.fail(
                NormalErrorV2::ReviewIdentityMismatch,
                Interruption::OperationFailed,
            ));
        }
        let role_b = WipingValueVec::try_with_capacity(parts.input_count()).map_err(|_| {
            self.fail(
                NormalErrorV2::SigningRejected,
                Interruption::OperationFailed,
            )
        })?;
        let mut state = NormalProcessSigningStateV2 {
            parts,
            role_a,
            role_b,
            cursor: 0,
        };
        advance_process_signing_cursor(&mut state);
        self.process_signing = Some(state);
        if self.process_card_b_signing_request().is_some() {
            Ok(self.progress(None))
        } else {
            self.finish_process_signing()
        }
    }

    #[cfg(feature = "normal-process")]
    fn finish_process_signing(&mut self) -> Result<NormalProgressV2, NormalErrorV2> {
        let Some(state) = self.process_signing.take() else {
            return Err(self.fail(
                NormalErrorV2::SigningRejected,
                Interruption::OperationFailed,
            ));
        };
        let NormalProcessSigningStateV2 {
            parts,
            role_a,
            role_b,
            cursor: _,
        } = state;
        let approved_review_hash = parts.review_hash();
        let mut submitted_a =
            WipingValueVec::try_with_capacity(role_a.inputs().len()).map_err(|_| {
                self.fail(
                    NormalErrorV2::SigningRejected,
                    Interruption::OperationFailed,
                )
            })?;
        for input in role_a.inputs() {
            if let Some(signature) = input.role_a() {
                submitted_a
                    .try_push(NormalSubmittedSignatureV3::new(
                        input.input_index(),
                        signature.der(),
                    ))
                    .map_err(|_| {
                        self.fail(
                            NormalErrorV2::SigningRejected,
                            Interruption::OperationFailed,
                        )
                    })?;
            }
        }
        let mut submitted_b = WipingValueVec::try_with_capacity(role_b.len()).map_err(|_| {
            self.fail(
                NormalErrorV2::SigningRejected,
                Interruption::OperationFailed,
            )
        })?;
        for signature in role_b.as_slice() {
            submitted_b
                .try_push(NormalSubmittedSignatureV3::new(
                    signature.input_index,
                    signature.der(),
                ))
                .map_err(|_| {
                    self.fail(
                        NormalErrorV2::SigningRejected,
                        Interruption::OperationFailed,
                    )
                })?;
        }
        self.advance(NormalStageV2::Finalization, None)?;
        let finalized = match finalize_validated_normal_v3(
            parts,
            submitted_a.as_slice(),
            submitted_b.as_slice(),
        ) {
            Ok(value) => value,
            Err(NormalFinalizationErrorV3::InvalidMockSignature) => {
                drop(submitted_a);
                drop(submitted_b);
                drop(role_a);
                drop(role_b);
                return Err(self.fail(
                    NormalErrorV2::InvalidMockSignature,
                    Interruption::OperationFailed,
                ));
            }
            Err(_) => {
                drop(submitted_a);
                drop(submitted_b);
                drop(role_a);
                drop(role_b);
                return Err(self.fail(
                    NormalErrorV2::FinalizationRejected,
                    Interruption::OperationFailed,
                ));
            }
        };
        drop(submitted_a);
        drop(submitted_b);
        drop(role_a);
        drop(role_b);
        if finalized.review_hash() != approved_review_hash {
            drop(finalized);
            return Err(self.fail(
                NormalErrorV2::ReviewIdentityMismatch,
                Interruption::OperationFailed,
            ));
        }
        let artifacts = NormalExportArtifactsV2::bind_finalized(self.profile, &finalized)
            .map_err(|error| self.fail(map_artifact_error(error), Interruption::OperationFailed))?;
        drop(finalized);
        self.artifacts = Some(artifacts);
        self.advance(NormalStageV2::AwaitingExportAction, None)
    }

    fn sign_and_finalize(
        &mut self,
        approved_review_hash: ReviewV3Hash,
    ) -> Result<NormalProgressV2, NormalErrorV2> {
        self.advance(NormalStageV2::TerminalASigning, None)?;
        let Some(proof) = self.proof.take() else {
            return Err(self.fail(
                NormalErrorV2::SigningRejected,
                Interruption::OperationFailed,
            ));
        };
        let (Some(seed_a), Some(card)) = (self.seed_a.take(), self.card.take()) else {
            drop(proof);
            return Err(self.fail(
                NormalErrorV2::SigningRejected,
                Interruption::OperationFailed,
            ));
        };
        let signed = match sign_validated_normal_role_a_v3(
            seed_a.as_array(),
            card.descriptors(),
            &card.wallet_id(),
            proof,
        ) {
            Ok(value) => value,
            Err(NormalRoleASigningErrorV3::RecoveredWalletMismatch) => {
                drop(seed_a);
                drop(card);
                return Err(self.fail(
                    NormalErrorV2::RecoveredWalletMismatch,
                    Interruption::OperationFailed,
                ));
            }
            Err(_) => {
                drop(seed_a);
                drop(card);
                return Err(self.fail(
                    NormalErrorV2::SigningRejected,
                    Interruption::OperationFailed,
                ));
            }
        };
        drop(seed_a);
        self.advance(NormalStageV2::CardBSigning, None)?;
        let (parts, role_a_owner) = signed.into_finalization_parts();
        #[cfg(feature = "normal-process")]
        if let Err(process_rejection) = validate_bound_card_signature_records(&parts, &card) {
            drop(parts);
            drop(role_a_owner);
            drop(card);
            let error = self.fail(
                NormalErrorV2::CardDataRejected,
                Interruption::OperationFailed,
            );
            self.process_signature_rejection = Some(process_rejection);
            return Err(error);
        }
        let mut role_a =
            WipingValueVec::try_with_capacity(role_a_owner.inputs().len()).map_err(|_| {
                self.fail(
                    NormalErrorV2::SigningRejected,
                    Interruption::OperationFailed,
                )
            })?;
        for input in role_a_owner.inputs() {
            if let Some(signature) = input.role_a() {
                role_a
                    .try_push(NormalSubmittedSignatureV3::new(
                        input.input_index(),
                        signature.der(),
                    ))
                    .map_err(|_| {
                        self.fail(
                            NormalErrorV2::SigningRejected,
                            Interruption::OperationFailed,
                        )
                    })?;
            }
        }
        let mut role_b =
            WipingValueVec::try_with_capacity(card.signatures().len()).map_err(|_| {
                self.fail(
                    NormalErrorV2::SigningRejected,
                    Interruption::OperationFailed,
                )
            })?;
        for signature in card.signatures() {
            role_b
                .try_push(NormalSubmittedSignatureV3::new(
                    signature.input_index(),
                    signature.der_signature(),
                ))
                .map_err(|_| {
                    self.fail(
                        NormalErrorV2::SigningRejected,
                        Interruption::OperationFailed,
                    )
                })?;
        }
        self.advance(NormalStageV2::Finalization, None)?;
        let finalized =
            match finalize_validated_normal_v3(parts, role_a.as_slice(), role_b.as_slice()) {
                Ok(value) => value,
                Err(NormalFinalizationErrorV3::InvalidMockSignature) => {
                    drop(role_a);
                    drop(role_b);
                    drop(role_a_owner);
                    drop(card);
                    return Err(self.fail(
                        NormalErrorV2::InvalidMockSignature,
                        Interruption::OperationFailed,
                    ));
                }
                Err(_) => {
                    drop(role_a);
                    drop(role_b);
                    drop(role_a_owner);
                    drop(card);
                    return Err(self.fail(
                        NormalErrorV2::FinalizationRejected,
                        Interruption::OperationFailed,
                    ));
                }
            };
        drop(role_a);
        drop(role_b);
        drop(role_a_owner);
        drop(card);
        if finalized.review_hash() != approved_review_hash {
            drop(finalized);
            return Err(self.fail(
                NormalErrorV2::ReviewIdentityMismatch,
                Interruption::OperationFailed,
            ));
        }
        let artifacts = NormalExportArtifactsV2::bind_finalized(self.profile, &finalized)
            .map_err(|error| self.fail(map_artifact_error(error), Interruption::OperationFailed))?;
        drop(finalized);
        self.artifacts = Some(artifacts);
        self.advance(NormalStageV2::AwaitingExportAction, None)
    }

    fn receive_export(
        &mut self,
        input: &[u8],
        ancillary_present: bool,
    ) -> Result<NormalReceiveOutcomeV2, NormalErrorV2> {
        let outcome = match self.core.receive_normal_egress(input, ancillary_present) {
            Ok(value) => value,
            Err(error) => {
                return Err(self.fail_outer_export(error));
            }
        };
        if !outcome.response_ready {
            return Ok(NormalReceiveOutcomeV2 {
                consumed: outcome.consumed,
                progress: self.progress(None),
            });
        }
        let response = match self.core.take_normal_egress_response() {
            Ok(value) => value,
            Err(error) => return Err(self.fail_outer_export(error)),
        };
        let Some(transfer) = self.transfer.as_mut() else {
            drop(response);
            return Err(self.fail(
                NormalErrorV2::ExportArtifactInvariant,
                Interruption::OperationFailed,
            ));
        };
        let progress = match transfer.accept_response(response.as_slice()) {
            Ok(value) => value,
            Err(error) => {
                drop(response);
                return Err(self.fail(map_artifact_error(error), Interruption::OperationFailed));
            }
        };
        drop(response);
        let next = match progress {
            NormalExportProgressV2::Continue => {
                let Some(transfer) = self.transfer.as_mut() else {
                    return Err(self.fail(
                        NormalErrorV2::ExportArtifactInvariant,
                        Interruption::OperationFailed,
                    ));
                };
                let request = match transfer.next_request() {
                    Ok(value) => value,
                    Err(error) => {
                        return Err(
                            self.fail(map_artifact_error(error), Interruption::OperationFailed)
                        );
                    }
                };
                let outbound = match self.core.begin_normal_egress(request.bytes()) {
                    Ok(value) => value,
                    Err(error) => {
                        let error =
                            transfer.normalize_outer_error(NormalArtifactErrorV2::Core(error));
                        return Err(
                            self.fail(map_artifact_error(error), Interruption::OperationFailed)
                        );
                    }
                };
                drop(request);
                self.progress(Some(outbound))
            }
            NormalExportProgressV2::Complete(result) => {
                drop(self.transfer.take());
                self.result = Some(result);
                self.advance(NormalStageV2::TransactionResult, None)?
            }
        };
        Ok(NormalReceiveOutcomeV2 {
            consumed: outcome.consumed,
            progress: next,
        })
    }

    fn review(&self) -> Option<&ReviewV3> {
        self.proof.as_ref().map(ValidatedNormalV3::review)
    }

    fn review_screen(&self) -> Option<NormalScreenV2<'_>> {
        let review = self.review()?;
        Some(match self.review_position? {
            NormalReviewPositionV2::Overview => {
                NormalScreenV2::ReviewOverview(NormalOverviewViewV2 {
                    profile: self.profile,
                    network: review.context().network,
                    wallet_id: review.wallet_id(),
                    input_count: review.input_count(),
                    total_input_amount: review.total_input_amount(),
                })
            }
            NormalReviewPositionV2::Arithmetic => {
                NormalScreenV2::ReviewArithmetic(NormalArithmeticViewV2 {
                    total_input_amount: review.total_input_amount(),
                    total_output_amount: review.total_output_amount(),
                    fee: review.fee(),
                })
            }
            NormalReviewPositionV2::Recipient(index) => {
                let output = review.outputs().get(index)?;
                let recipient = match output.ownership() {
                    ReviewV3OutputOwnership::NotOwned {
                        recipient_type,
                        data,
                    } => NormalRecipientFactV2::External {
                        recipient_type: *recipient_type,
                        data: data.as_slice(),
                    },
                    ReviewV3OutputOwnership::ProvenSelfTransfer {
                        child_index,
                        witness_program,
                    } => NormalRecipientFactV2::SelfTransfer {
                        child_index: *child_index,
                        witness_program: witness_program.as_slice(),
                    },
                    ReviewV3OutputOwnership::ProvenChange { .. } => return None,
                };
                NormalScreenV2::ReviewRecipient(NormalRecipientViewV2 {
                    index: output.index(),
                    amount: output.amount(),
                    script_pubkey: output.script_pubkey(),
                    recipient,
                })
            }
            NormalReviewPositionV2::Change(index) => {
                let output = review.outputs().get(index)?;
                let ReviewV3OutputOwnership::ProvenChange { child_index } = output.ownership()
                else {
                    return None;
                };
                NormalScreenV2::ReviewChange(NormalChangeViewV2 {
                    index: output.index(),
                    amount: output.amount(),
                    script_pubkey: output.script_pubkey(),
                    child_index: *child_index,
                })
            }
            NormalReviewPositionV2::OpReturn(index) => {
                let output = review.outputs().get(index)?;
                let ReviewV3OutputOwnership::NotOwned {
                    recipient_type: RecipientType::OpReturn,
                    data,
                } = output.ownership()
                else {
                    return None;
                };
                NormalScreenV2::ReviewOpReturn(NormalOpReturnViewV2 {
                    index: output.index(),
                    amount: output.amount(),
                    script_pubkey: output.script_pubkey(),
                    payload: data.as_slice(),
                })
            }
            NormalReviewPositionV2::Locktime => {
                NormalScreenV2::ReviewLocktime(NormalLocktimeViewV2 {
                    locktime: review.locktime(),
                })
            }
            NormalReviewPositionV2::Sequence(input_index) => {
                let input = review.inputs().get(input_index)?;
                NormalScreenV2::ReviewSequence(NormalSequenceViewV2 {
                    input_index: input.index(),
                    sequence: input.sequence(),
                    direct_rbf: input.direct_rbf(),
                })
            }
            NormalReviewPositionV2::FeePolicy => {
                NormalScreenV2::ReviewFeePolicy(NormalFeePolicyViewV2 {
                    identifier: review.fee_policy_identifier(),
                })
            }
            NormalReviewPositionV2::FeeFacts => {
                NormalScreenV2::ReviewFeeFacts(NormalFeeFactsViewV2 {
                    fee: review.fee(),
                    estimated_vsize: review.estimated_vsize(),
                    fee_rate_msat_per_vbyte: review.fee_rate_msat_per_vbyte(),
                })
            }
            NormalReviewPositionV2::Warning(index) => {
                NormalScreenV2::ReviewWarning(NormalWarningViewV2 {
                    warning: review.fee_warnings().nth(index)?,
                })
            }
            NormalReviewPositionV2::FinalApproval => {
                NormalScreenV2::FinalApproval(NormalFinalApprovalViewV2 {
                    profile: self.profile,
                    review_hash: self.proof.as_ref()?.review_hash(),
                })
            }
        })
    }

    fn next_review_position(&self) -> Option<NormalReviewPositionV2> {
        let review = self.review()?;
        Some(match self.review_position? {
            NormalReviewPositionV2::Overview => NormalReviewPositionV2::Arithmetic,
            NormalReviewPositionV2::Arithmetic => first_recipient(review, None)
                .map(NormalReviewPositionV2::Recipient)
                .or_else(|| first_change(review, None).map(NormalReviewPositionV2::Change))
                .or_else(|| first_op_return(review, None).map(NormalReviewPositionV2::OpReturn))
                .unwrap_or(NormalReviewPositionV2::Locktime),
            NormalReviewPositionV2::Recipient(index) => first_recipient(review, Some(index))
                .map(NormalReviewPositionV2::Recipient)
                .or_else(|| first_change(review, None).map(NormalReviewPositionV2::Change))
                .or_else(|| first_op_return(review, None).map(NormalReviewPositionV2::OpReturn))
                .unwrap_or(NormalReviewPositionV2::Locktime),
            NormalReviewPositionV2::Change(index) => first_change(review, Some(index))
                .map(NormalReviewPositionV2::Change)
                .or_else(|| first_op_return(review, None).map(NormalReviewPositionV2::OpReturn))
                .unwrap_or(NormalReviewPositionV2::Locktime),
            NormalReviewPositionV2::OpReturn(index) => first_op_return(review, Some(index))
                .map(NormalReviewPositionV2::OpReturn)
                .unwrap_or(NormalReviewPositionV2::Locktime),
            NormalReviewPositionV2::Locktime => {
                if review.inputs().is_empty() {
                    NormalReviewPositionV2::FeePolicy
                } else {
                    NormalReviewPositionV2::Sequence(0)
                }
            }
            NormalReviewPositionV2::Sequence(index) => match index.checked_add(1) {
                Some(next) if next < review.inputs().len() => {
                    NormalReviewPositionV2::Sequence(next)
                }
                _ => NormalReviewPositionV2::FeePolicy,
            },
            NormalReviewPositionV2::FeePolicy => NormalReviewPositionV2::FeeFacts,
            NormalReviewPositionV2::FeeFacts => {
                if review.fee_policy().warning_count() == 0 {
                    NormalReviewPositionV2::FinalApproval
                } else {
                    NormalReviewPositionV2::Warning(0)
                }
            }
            NormalReviewPositionV2::Warning(index) => match index.checked_add(1) {
                Some(next) if next < review.fee_policy().warning_count() => {
                    NormalReviewPositionV2::Warning(next)
                }
                _ => NormalReviewPositionV2::FinalApproval,
            },
            NormalReviewPositionV2::FinalApproval => return None,
        })
    }

    fn show_review_position(&mut self) -> Result<(), NormalErrorV2> {
        let screen = match self.review_position {
            Some(NormalReviewPositionV2::Overview) => CoreScreen::ReviewOverview,
            Some(NormalReviewPositionV2::Arithmetic) => CoreScreen::ReviewArithmetic,
            Some(NormalReviewPositionV2::Recipient(_)) => CoreScreen::ReviewRecipient,
            Some(NormalReviewPositionV2::Change(_)) => CoreScreen::ReviewChange,
            Some(NormalReviewPositionV2::OpReturn(_)) => CoreScreen::ReviewOpReturn,
            Some(NormalReviewPositionV2::Locktime) => CoreScreen::ReviewLocktime,
            Some(NormalReviewPositionV2::Sequence(_)) => CoreScreen::ReviewSequence,
            Some(NormalReviewPositionV2::FeePolicy) => CoreScreen::ReviewFeePolicy,
            Some(NormalReviewPositionV2::FeeFacts) => CoreScreen::ReviewFeeFacts,
            Some(NormalReviewPositionV2::Warning(_)) => CoreScreen::ReviewWarning,
            Some(NormalReviewPositionV2::FinalApproval) => CoreScreen::FinalApproval,
            None => {
                return Err(self.fail(
                    NormalErrorV2::ReviewIncomplete,
                    Interruption::OperationFailed,
                ))
            }
        };
        self.core
            .normal_show(screen)
            .map_err(|error| self.fail(NormalErrorV2::Core(error), Interruption::CapabilityFailed))
    }

    fn advance(
        &mut self,
        stage: NormalStageV2,
        outbound: Option<CoreOutbound>,
    ) -> Result<NormalProgressV2, NormalErrorV2> {
        self.stage = stage;
        if stage == NormalStageV2::Review || stage == NormalStageV2::FinalApproval {
            self.show_review_position()?;
        } else {
            self.core
                .normal_show(stage_screen(stage))
                .map_err(|error| {
                    self.fail(NormalErrorV2::Core(error), Interruption::CapabilityFailed)
                })?;
        }
        #[cfg(feature = "normal-process")]
        self.process_stage_trace.record(stage);
        Ok(self.progress(outbound))
    }

    fn progress(&self, outbound: Option<CoreOutbound>) -> NormalProgressV2 {
        NormalProgressV2 {
            stage: self.stage,
            outbound,
        }
    }

    fn require_active(&self) -> Result<(), NormalErrorV2> {
        if self.is_terminal() {
            Err(NormalErrorV2::Finished)
        } else {
            Ok(())
        }
    }

    fn require_preapproval(&mut self) -> Result<(), NormalErrorV2> {
        self.require_active()?;
        if self.approval.is_some() {
            Err(self.fail(
                NormalErrorV2::PostApprovalYield,
                Interruption::OperationFailed,
            ))
        } else if self.pending_hold.is_some() {
            Err(self.fail(
                NormalErrorV2::ApprovalUnavailable,
                Interruption::OperationFailed,
            ))
        } else {
            Ok(())
        }
    }

    fn fail_outer_export(&mut self, error: CoreError) -> NormalErrorV2 {
        let artifact_error = match self.transfer.as_mut() {
            Some(transfer) => transfer.normalize_outer_error(NormalArtifactErrorV2::Core(error)),
            None => NormalArtifactErrorV2::Core(error),
        };
        self.fail(
            map_artifact_error(artifact_error),
            Interruption::OperationFailed,
        )
    }

    fn fail(&mut self, error: NormalErrorV2, reason: Interruption) -> NormalErrorV2 {
        let error = if self
            .transfer
            .as_ref()
            .is_some_and(NormalExportTransferV2::has_partial_sd_completion)
        {
            NormalErrorV2::PartialSdCompletion
        } else {
            error
        };
        if self.terminal_error.is_none() {
            self.cleanup_owned();
            self.core.terminate_normal(reason);
            self.terminal_error = Some(error);
        }
        error
    }

    fn cleanup_owned(&mut self) {
        self.pending_source = None;
        drop(self.s0.take());
        drop(self.card.take());
        drop(self.seed_a.take());
        drop(self.proof.take());
        #[cfg(feature = "normal-process")]
        drop(self.process_signing.take());
        self.review_position = None;
        self.pending_hold = None;
        self.approval = None;
        drop(self.artifacts.take());
        drop(self.transfer.take());
        self.result = None;
    }
}

impl Drop for NormalSessionV2 {
    fn drop(&mut self) {
        self.cleanup_owned();
        if !self.is_terminal() {
            self.core.terminate_normal(Interruption::OperationFailed);
        }
    }
}

#[cfg(feature = "normal-process")]
fn advance_process_signing_cursor(state: &mut NormalProcessSigningStateV2) {
    while let Some(plan) = state.parts.input_signing_plans().get(state.cursor) {
        if !plan
            .existing_role_signatures()
            .get(1)
            .copied()
            .unwrap_or(true)
        {
            break;
        }
        state.cursor = state.cursor.saturating_add(1);
    }
}

#[cfg(feature = "normal-process")]
struct ProcessSignatureInputGuard<'a>(&'a mut [u8]);

#[cfg(feature = "normal-process")]
impl ProcessSignatureInputGuard<'_> {
    fn as_slice(&self) -> &[u8] {
        self.0
    }
}

#[cfg(feature = "normal-process")]
impl Drop for ProcessSignatureInputGuard<'_> {
    fn drop(&mut self) {
        wipe::bytes(self.0);
    }
}

#[cfg(feature = "normal-process")]
fn verify_process_card_b_signature(
    request: &NormalCardBSigningRequestV2,
    review_hash: ReviewV3Hash,
    input_index: u32,
    role_b_pubkey: [u8; 33],
    der_signature: &[u8],
    retained: &[NormalVerifiedCardBSignatureV2],
) -> Result<NormalVerifiedCardBSignatureV2, ProcessSignatureRejectionV2> {
    if review_hash != *request.review_hash() || input_index != request.input_index() {
        return Err(ProcessSignatureRejectionV2::BindingMismatch);
    }
    if role_b_pubkey != *request.role_b_pubkey() {
        return Err(ProcessSignatureRejectionV2::KeyMismatch);
    }
    let mut normalized = WipingArray::<72>::zeroed();
    let len = match qk_secp::normalize_card_signature_der(der_signature, normalized.as_mut_array())
    {
        Ok(len) => len,
        Err(qk_secp::SecpError::DerLengthOutOfBounds)
        | Err(qk_secp::SecpError::SignatureParseFailed) => {
            return Err(ProcessSignatureRejectionV2::Malformed)
        }
        Err(_) => return Err(ProcessSignatureRejectionV2::Invalid),
    };
    let r = normalized_card_signature_r(
        normalized
            .as_array()
            .get(..len)
            .ok_or(ProcessSignatureRejectionV2::Invalid)?,
    )
    .ok_or(ProcessSignatureRejectionV2::Invalid)?;
    if retained
        .iter()
        .any(|prior| prior.r.as_array() == r.as_array())
    {
        return Err(ProcessSignatureRejectionV2::RepeatedR);
    }
    let signature = qk_secp::signature_parse_der(
        normalized
            .as_array()
            .get(..len)
            .ok_or(ProcessSignatureRejectionV2::Invalid)?,
    )
    .map_err(|_| ProcessSignatureRejectionV2::Invalid)?;
    let public_key = qk_secp::pubkey_parse_compressed(request.role_b_pubkey())
        .map_err(|_| ProcessSignatureRejectionV2::Invalid)?;
    qk_secp::ecdsa_verify(&signature, request.digest(), &public_key)
        .map_err(|_| ProcessSignatureRejectionV2::Invalid)?;
    Ok(NormalVerifiedCardBSignatureV2 {
        input_index,
        der: normalized,
        len,
        r,
    })
}

fn card_binding_matches(card: &NormalCardBDataV2) -> Result<bool, ()> {
    let descriptors = card.descriptors();
    let parsed = parse_descriptor_pair_v2(&descriptors[0], &descriptors[1]).map_err(|_| ())?;
    if parsed.wallet_id() != card.wallet_id() {
        return Ok(false);
    }
    Ok(descriptors.iter().all(|descriptor| {
        descriptor.get(ROLE_B_XPUB_START..ROLE_B_XPUB_END) == Some(card.account_xpub().as_slice())
    }))
}

#[cfg(feature = "normal-process")]
fn validate_bound_card_signature_records(
    proof: &ValidatedNormalV3Parts,
    card: &NormalCardBDataV2,
) -> Result<(), ProcessSignatureRejectionV2> {
    let plans = proof.input_signing_plans();
    let mut prior = None;
    for (record_index, signature) in card.signatures().iter().enumerate() {
        let Some(claimed_key) = signature.role_b_pubkey() else {
            // The frozen typed HOST tests predate the process-wire binding.
            // Every QKDV NormalFactor record uses the bound constructor.
            continue;
        };
        match classify_card_signature_der(signature.der_signature()) {
            CardSignatureDerClassV2::Malformed => {
                return Err(ProcessSignatureRejectionV2::Malformed)
            }
            CardSignatureDerClassV2::HighS => return Err(ProcessSignatureRejectionV2::HighS),
            CardSignatureDerClassV2::LowS => {}
        }
        if prior.is_some_and(|prior| signature.input_index() <= prior) {
            return Err(ProcessSignatureRejectionV2::Malformed);
        }
        prior = Some(signature.input_index());
        let position = usize::try_from(signature.input_index())
            .map_err(|_| ProcessSignatureRejectionV2::Malformed)?;
        let plan = plans
            .get(position)
            .filter(|plan| plan.input_index() == signature.input_index())
            .ok_or(ProcessSignatureRejectionV2::Malformed)?;
        let role_b = plan
            .role_public_keys()
            .get(1)
            .ok_or(ProcessSignatureRejectionV2::Malformed)?;
        if role_b != &claimed_key {
            return Err(ProcessSignatureRejectionV2::KeyMismatch);
        }
        reject_repeated_bound_card_r(
            signature,
            card.signatures().get(..record_index).unwrap_or_default(),
        )?;
    }
    Ok(())
}

#[cfg(feature = "normal-process")]
fn reject_repeated_bound_card_r(
    current: &NormalCardBSignatureV2,
    prior_records: &[NormalCardBSignatureV2],
) -> Result<(), ProcessSignatureRejectionV2> {
    for prior in prior_records {
        if prior.role_b_pubkey().is_some()
            && card_signatures_repeat_r(prior.der_signature(), current.der_signature())?
        {
            return Err(ProcessSignatureRejectionV2::RepeatedR);
        }
    }
    Ok(())
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[cfg(feature = "normal-process")]
pub(crate) enum CardSignatureDerClassV2 {
    Malformed,
    LowS,
    HighS,
}

#[cfg(feature = "normal-process")]
pub(crate) fn classify_card_signature_der(der: &[u8]) -> CardSignatureDerClassV2 {
    let Some((&0x30, rest)) = der.split_first() else {
        return CardSignatureDerClassV2::Malformed;
    };
    let Some((&sequence_len, sequence)) = rest.split_first() else {
        return CardSignatureDerClassV2::Malformed;
    };
    if usize::from(sequence_len) != sequence.len() {
        return CardSignatureDerClassV2::Malformed;
    }
    let Some((r, after_r)) = parse_card_der_integer(sequence) else {
        return CardSignatureDerClassV2::Malformed;
    };
    if r.is_empty() {
        return CardSignatureDerClassV2::Malformed;
    }
    let Some((s, trailing)) = parse_card_der_integer(after_r) else {
        return CardSignatureDerClassV2::Malformed;
    };
    if !trailing.is_empty() {
        return CardSignatureDerClassV2::Malformed;
    }
    let magnitude = s.strip_prefix(&[0]).unwrap_or(s);
    if magnitude.len() > HALF_CURVE_ORDER.len() {
        return CardSignatureDerClassV2::HighS;
    }
    if magnitude.len() < HALF_CURVE_ORDER.len() {
        return CardSignatureDerClassV2::LowS;
    }
    if magnitude > HALF_CURVE_ORDER.as_slice() {
        CardSignatureDerClassV2::HighS
    } else {
        CardSignatureDerClassV2::LowS
    }
}

#[cfg(feature = "normal-process")]
fn parse_card_der_integer(bytes: &[u8]) -> Option<(&[u8], &[u8])> {
    let (&0x02, rest) = bytes.split_first()? else {
        return None;
    };
    let (&length, rest) = rest.split_first()?;
    let length = usize::from(length);
    if length == 0 || rest.len() < length {
        return None;
    }
    let (value, trailing) = rest.split_at(length);
    let first = *value.first()?;
    if first & 0x80 != 0 {
        return None;
    }
    if first == 0 && value.get(1).is_some_and(|next| next & 0x80 == 0) {
        return None;
    }
    Some((value, trailing))
}

#[cfg(feature = "normal-process")]
fn normalized_card_signature_r(der: &[u8]) -> Option<WipingArray<32>> {
    let magnitude = card_signature_r_magnitude(der)?;
    if magnitude.len() > 32 {
        return None;
    }
    let mut normalized = WipingArray::<32>::zeroed();
    let offset = 32usize.checked_sub(magnitude.len())?;
    normalized
        .as_mut_array()
        .get_mut(offset..)?
        .copy_from_slice(magnitude);
    Some(normalized)
}

#[cfg(feature = "normal-process")]
fn card_signature_r_magnitude(der: &[u8]) -> Option<&[u8]> {
    let (&0x30, rest) = der.split_first()? else {
        return None;
    };
    let (&sequence_len, sequence) = rest.split_first()?;
    if usize::from(sequence_len) != sequence.len() {
        return None;
    }
    let (r, after_r) = parse_card_der_integer(sequence)?;
    let (_, trailing) = parse_card_der_integer(after_r)?;
    if !trailing.is_empty() {
        return None;
    }
    Some(r.strip_prefix(&[0]).unwrap_or(r))
}

#[cfg(feature = "normal-process")]
fn card_signatures_repeat_r(
    first_der: &[u8],
    second_der: &[u8],
) -> Result<bool, ProcessSignatureRejectionV2> {
    let first =
        card_signature_r_magnitude(first_der).ok_or(ProcessSignatureRejectionV2::Malformed)?;
    let second =
        card_signature_r_magnitude(second_der).ok_or(ProcessSignatureRejectionV2::Malformed)?;
    Ok(first == second)
}

const fn validate_a1_candidate(source: Source, length: usize) -> Result<(), NormalErrorV2> {
    if !matches!(source, Source::CameraA1Candidate) {
        Err(NormalErrorV2::WrongIngressSource)
    } else if length != A1_CAPSULE_BYTES {
        Err(NormalErrorV2::A1Rejected)
    } else {
        Ok(())
    }
}

fn first_recipient(review: &ReviewV3, after: Option<usize>) -> Option<usize> {
    review
        .outputs()
        .iter()
        .enumerate()
        .find_map(|(index, output)| {
            (after.is_none_or(|prior| index > prior) && is_recipient(output)).then_some(index)
        })
}

fn first_change(review: &ReviewV3, after: Option<usize>) -> Option<usize> {
    review
        .outputs()
        .iter()
        .enumerate()
        .find_map(|(index, output)| {
            (after.is_none_or(|prior| index > prior)
                && matches!(
                    output.ownership(),
                    ReviewV3OutputOwnership::ProvenChange { .. }
                ))
            .then_some(index)
        })
}

fn first_op_return(review: &ReviewV3, after: Option<usize>) -> Option<usize> {
    review
        .outputs()
        .iter()
        .enumerate()
        .find_map(|(index, output)| {
            (after.is_none_or(|prior| index > prior)
                && matches!(
                    output.ownership(),
                    ReviewV3OutputOwnership::NotOwned {
                        recipient_type: RecipientType::OpReturn,
                        ..
                    }
                ))
            .then_some(index)
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

const fn stage_screen(stage: NormalStageV2) -> CoreScreen {
    match stage {
        NormalStageV2::NormalStart => CoreScreen::NormalStart,
        NormalStageV2::ProfileBinding => CoreScreen::ProfileBinding,
        NormalStageV2::Transport => CoreScreen::NormalTransport,
        NormalStageV2::PsbtIntake => CoreScreen::PsbtIntake,
        NormalStageV2::FactorB => CoreScreen::FactorB,
        NormalStageV2::A1Intake => CoreScreen::A1Intake,
        NormalStageV2::FactorA1 => CoreScreen::FactorA1,
        NormalStageV2::Validation => CoreScreen::NormalValidation,
        NormalStageV2::Review => CoreScreen::ReviewOverview,
        NormalStageV2::FinalApproval => CoreScreen::FinalApproval,
        NormalStageV2::ApprovalHeld => CoreScreen::ApprovalHeld,
        NormalStageV2::Revalidation => CoreScreen::Revalidation,
        NormalStageV2::TerminalASigning => CoreScreen::TerminalASigning,
        NormalStageV2::CardBSigning => CoreScreen::CardBSigning,
        NormalStageV2::Finalization => CoreScreen::Finalization,
        NormalStageV2::AwaitingExportAction => CoreScreen::AwaitingExportAction,
        NormalStageV2::TransactionResult => CoreScreen::TransactionResult,
        NormalStageV2::CompletedWiped => CoreScreen::CompletedWiped,
    }
}

const fn map_artifact_error(error: NormalArtifactErrorV2) -> NormalErrorV2 {
    match error {
        NormalArtifactErrorV2::ProfileMissing => NormalErrorV2::ProfileMissing,
        NormalArtifactErrorV2::ProfileUnknown => NormalErrorV2::ProfileUnknown,
        NormalArtifactErrorV2::ProfileMalformed => NormalErrorV2::ProfileMalformed,
        NormalArtifactErrorV2::InvalidTransition => NormalErrorV2::InvalidTransition,
        NormalArtifactErrorV2::ExportRouteUnavailable => NormalErrorV2::ExportRouteUnavailable,
        NormalArtifactErrorV2::ExportArtifactInvariant => NormalErrorV2::ExportArtifactInvariant,
        NormalArtifactErrorV2::ExportReceiptMismatch => NormalErrorV2::ExportReceiptMismatch,
        NormalArtifactErrorV2::BbqrVerificationMismatch => NormalErrorV2::BbqrVerificationMismatch,
        NormalArtifactErrorV2::PartialSdCompletion => NormalErrorV2::PartialSdCompletion,
        NormalArtifactErrorV2::Finished => NormalErrorV2::Finished,
        NormalArtifactErrorV2::Core(error) => NormalErrorV2::Core(error),
    }
}

#[cfg(test)]
mod tests {
    use super::{validate_a1_candidate, NormalErrorV2, Source, A1_CAPSULE_BYTES};

    #[cfg(feature = "normal-process")]
    use super::{
        card_signatures_repeat_r, normalized_card_signature_r, reject_repeated_bound_card_r,
        ProcessSignatureRejectionV2,
    };

    #[cfg(feature = "normal-process")]
    use crate::NormalCardBSignatureV2;

    #[test]
    fn a1_candidate_source_and_length_have_distinct_precedence() {
        assert_eq!(
            validate_a1_candidate(Source::MediaPsbt, A1_CAPSULE_BYTES - 1),
            Err(NormalErrorV2::WrongIngressSource)
        );
        assert_eq!(
            validate_a1_candidate(Source::CameraA1Candidate, A1_CAPSULE_BYTES - 1),
            Err(NormalErrorV2::A1Rejected)
        );
        assert_eq!(
            validate_a1_candidate(Source::CameraA1Candidate, A1_CAPSULE_BYTES),
            Ok(())
        );
    }

    #[cfg(feature = "normal-process")]
    #[test]
    fn numeric_r_normalization_ignores_der_pad_and_s_representation() {
        let decode = |text: &str| {
            text.as_bytes()
                .chunks_exact(2)
                .map(|pair| {
                    u8::from_str_radix(core::str::from_utf8(pair).expect("ASCII hex"), 16)
                        .expect("fixture hex")
                })
                .collect::<Vec<_>>()
        };
        let low = decode("3045022100ccbfad55e5be35282e8927ef2694257e694a7738513c3fc3e3964952278097690220409e03b542e5870605c983ff59bbda660bef439a0eefe106d72b16d385ec9437");
        let mut different_s = low.clone();
        *different_s.last_mut().expect("nonempty DER") ^= 1;
        let high = decode("3046022100ccbfad55e5be35282e8927ef2694257e694a7738513c3fc3e396495227809769022100bf61fc4abd1a78f9fa367c00a6442598aebf994ca058bf34e8a747b94a49ad0a");
        let mut normalized_high = [0u8; 72];
        let normalized_high_len =
            qk_secp::normalize_card_signature_der(&high, &mut normalized_high)
                .expect("registered high-S twin normalizes");

        let low_r = normalized_card_signature_r(&low).expect("strict low-S DER");
        let different_s_r =
            normalized_card_signature_r(&different_s).expect("strict distinct-S DER");
        let high_r = normalized_card_signature_r(
            normalized_high
                .get(..normalized_high_len)
                .expect("bounded normalized DER"),
        )
        .expect("strict normalized high-S DER");
        assert_eq!(low_r.as_array(), different_s_r.as_array());
        assert_eq!(low_r.as_array(), high_r.as_array());
        assert_eq!(low_r.as_array()[0], 0xcc);
        assert_eq!(low_r.as_array()[31], 0x69);
        assert_eq!(card_signatures_repeat_r(&low, &different_s), Ok(true));
        assert_eq!(
            card_signatures_repeat_r(
                &low,
                normalized_high
                    .get(..normalized_high_len)
                    .expect("bounded normalized DER"),
            ),
            Ok(true)
        );

        let short =
            normalized_card_signature_r(&[0x30, 6, 2, 1, 1, 2, 1, 1]).expect("strict one-byte r");
        assert!(short.as_array()[..31].iter().all(|byte| *byte == 0));
        assert_eq!(short.as_array()[31], 1);

        let mut oversized_first = vec![0x30, 0x26, 0x02, 0x21];
        oversized_first.extend_from_slice(&[1; 33]);
        oversized_first.extend_from_slice(&[0x02, 0x01, 0x01]);
        let mut oversized_second = oversized_first.clone();
        *oversized_second.last_mut().expect("nonempty DER") = 2;
        assert_eq!(
            card_signatures_repeat_r(&oversized_first, &oversized_second),
            Ok(true)
        );
    }

    #[cfg(feature = "normal-process")]
    #[test]
    fn batch_repeat_detector_uses_numeric_r_and_skips_unbound_legacy_records() {
        fn bound(input_index: u32, mut der: Vec<u8>) -> NormalCardBSignatureV2 {
            NormalCardBSignatureV2::try_new_bound(input_index, [0x02; 33], &mut der)
                .expect("bounded public DER")
        }

        fn unbound(input_index: u32, mut der: Vec<u8>) -> NormalCardBSignatureV2 {
            NormalCardBSignatureV2::try_new(input_index, &mut der).expect("bounded public DER")
        }

        let text = "3045022100ccbfad55e5be35282e8927ef2694257e694a7738513c3fc3e3964952278097690220409e03b542e5870605c983ff59bbda660bef439a0eefe106d72b16d385ec9437";
        let low = text
            .as_bytes()
            .chunks_exact(2)
            .map(|pair| {
                u8::from_str_radix(core::str::from_utf8(pair).expect("ASCII hex"), 16)
                    .expect("fixture hex")
            })
            .collect::<Vec<_>>();
        let mut same_r_different_s = low.clone();
        *same_r_different_s.last_mut().expect("nonempty DER") ^= 1;
        let mut distinct_r = same_r_different_s.clone();
        *distinct_r.get_mut(36).expect("32-byte padded r") ^= 1;

        let current = bound(1, same_r_different_s);
        assert_eq!(
            reject_repeated_bound_card_r(&current, &[bound(0, low.clone())]),
            Err(ProcessSignatureRejectionV2::RepeatedR)
        );
        assert_eq!(
            reject_repeated_bound_card_r(&bound(1, distinct_r), &[bound(0, low.clone())]),
            Ok(())
        );
        assert_eq!(
            reject_repeated_bound_card_r(&current, &[unbound(0, low)]),
            Ok(())
        );
    }
}
