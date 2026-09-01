//! QK-DEC-151 HOST-only, purpose-bound Kit-Spend orchestration.
//!
//! This owner accepts only one `KitSpend` intake capability. It strictly
//! rebinds old D, proves one sweep to distinct authenticated D-prime, exposes
//! the complete schema-v3 review in fixed order, and consumes the recovered
//! authority only after the coordinator statement and screen-named digit.
//! The finalized PSBT is never exposed as an export artifact by this module.

use crate::capability::{CoreScreen, KeypadKey};
use crate::error::Interruption;
use crate::io_wire::Source;
use crate::kit_artifact_v2::{KitArtifactErrorV2, KitExportArtifactsV2};
use crate::kit_intake_v2::{KitDoorV2, KitFrameIdentityV2, KitInputModeV2, KitIntakeReadyV2};
use crate::normal_artifact_v2::{NormalArtifactErrorV2, NormalProfileV2};
use crate::session::{CoreSession, HostileIngress};
use crate::wipe;
use core::fmt;
use qk_descriptor::parse_descriptor_pair_v2;
use qk_kit::{BoundKitSpendV2, KitSpendMathErrorV3};
use qk_psbt::{
    build_validated_kit_sweep_v3, DirectRbf, FeeWarning, FinalizedNormalV3, InputSource,
    IntakeError, KitSweepV3Error, NormalFinalizationErrorV3, OwnedS0, RecipientType,
    ReplacementReceiveIndexV2, ReviewNetwork, ReviewV3, ReviewV3Hash, ReviewV3Output,
    ReviewV3OutputOwnership, ValidatedKitSweepV3,
};

/// The coordinator's external factual statement. It is not transaction data.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CoordinatorCompletenessStatementV2 {
    AllFundsIncluded,
}

/// One already-ratified public assertion digit.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct KitSpendAssertionDigitV2(u8);

impl KitSpendAssertionDigitV2 {
    pub fn new(digit: u8) -> Result<Self, KitSpendErrorV2> {
        (digit <= 9)
            .then_some(Self(digit))
            .ok_or(KitSpendErrorV2::InvalidHumanAssertionDigit)
    }

    #[must_use]
    pub const fn value(self) -> u8 {
        self.0
    }

    fn matches(self, key: KeypadKey) -> bool {
        numeric_key(key) == Some(self.0)
    }
}

/// One monotonic approval cycle bound to the process session identity.
#[derive(Clone, Copy, Eq, PartialEq)]
pub struct KitSpendCycleTokenV2 {
    session_identity: [u8; 16],
    cycle: u64,
}

impl KitSpendCycleTokenV2 {
    #[must_use]
    pub const fn cycle(self) -> u64 {
        self.cycle
    }
}

/// Exact one-use identity displayed on the assertion screen.
#[derive(Clone, Copy, Eq, PartialEq)]
pub struct KitSpendApprovalIdentityV2 {
    token: KitSpendCycleTokenV2,
    review_hash: ReviewV3Hash,
    assertion_digit: KitSpendAssertionDigitV2,
}

impl KitSpendApprovalIdentityV2 {
    #[must_use]
    pub const fn token(self) -> KitSpendCycleTokenV2 {
        self.token
    }

    #[must_use]
    pub const fn review_hash(self) -> ReviewV3Hash {
        self.review_hash
    }

    #[must_use]
    pub const fn assertion_digit(self) -> KitSpendAssertionDigitV2 {
        self.assertion_digit
    }
}

/// Exact Kit-Spend state order before the finalized owner is returned.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum KitSpendStageV2 {
    TransactionIntake,
    Review,
    CompletenessStatement,
    HumanAssertion,
    Signing,
    Finalization,
}

/// Complete schema-v3 review order. Transaction positions are zero-based.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum KitSpendReviewPositionV2 {
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
}

/// One already-bound recipient fact selected by the review cursor.
#[derive(Clone, Copy)]
pub enum KitSpendRecipientFactV2<'a> {
    External {
        recipient_type: RecipientType,
        data: &'a [u8],
    },
    SelfTransfer {
        child_index: u32,
        witness_program: &'a [u8],
    },
}

/// Borrow-only display facts selected from the immutable proof.
pub enum KitSpendScreenV2<'a> {
    TransactionIntake {
        profile: NormalProfileV2,
        old_wallet_id: [u8; 32],
        input_mode: KitInputModeV2,
    },
    ReviewOverview {
        profile: NormalProfileV2,
        network: ReviewNetwork,
        wallet_id: [u8; 32],
        input_count: usize,
        total_input_amount: u64,
    },
    ReviewArithmetic {
        total_input_amount: u64,
        total_output_amount: u64,
        fee: u64,
    },
    ReviewRecipient {
        index: u32,
        amount: u64,
        script_pubkey: &'a [u8],
        recipient: KitSpendRecipientFactV2<'a>,
    },
    ReviewChange {
        index: u32,
        amount: u64,
        script_pubkey: &'a [u8],
        child_index: u32,
    },
    ReviewOpReturn {
        index: u32,
        amount: u64,
        script_pubkey: &'a [u8],
        payload: &'a [u8],
    },
    ReviewLocktime {
        locktime: u32,
    },
    ReviewSequence {
        input_index: u32,
        sequence: u32,
        direct_rbf: DirectRbf,
    },
    ReviewFeePolicy {
        identifier: &'static [u8],
    },
    ReviewFeeFacts {
        fee: u64,
        estimated_vsize: u32,
        fee_rate_msat_per_vbyte: u64,
    },
    ReviewWarning {
        warning: FeeWarning,
    },
    CompletenessStatement {
        review_hash: ReviewV3Hash,
    },
    HumanAssertion {
        approval: KitSpendApprovalIdentityV2,
    },
}

/// Operations that cannot enter this purpose-bound session.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum KitSpendForeignOperationV2 {
    Signing,
    Transaction,
    Review,
    Approval,
    Export,
    Intake,
    NormalWallet,
    Restore,
    KitGeneration,
    KitRegeneration,
    DoorSwitch,
    Transport,
    Capability,
    ScreenYield,
}

/// Closed named Kit-Spend rejection surface; no variant carries hostile bytes.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum KitSpendErrorV2 {
    ProfileMissing,
    ProfileUnknown,
    ProfileMalformed,
    InvalidHumanAssertionDigit,
    WrongDoor,
    InvalidStart,
    InvalidTransition,
    WrongIngressSource,
    RecoveredWalletMismatch,
    ReplacementDescriptorInvalid,
    ReplacementWalletUnchanged,
    Intake(IntakeError),
    Sweep(KitSweepV3Error),
    ReviewIncomplete,
    ReviewIdentityMismatch,
    CompletenessStatementMissing,
    HumanAssertionMismatch,
    PostApprovalYield,
    SigningOutsideSweep,
    TransactionOutsideSweep,
    ReviewOutsideSweep,
    ApprovalProhibited,
    ExportProhibited,
    ForeignInputProhibited,
    NormalWalletOperationProhibited,
    RestoreProhibited,
    KitGenerationProhibited,
    KitRegenerationProhibited,
    DoorSwitchAttempt,
    SigningRejected(KitSpendMathErrorV3),
    FinalizationRejected(NormalFinalizationErrorV3),
    Interrupted(Interruption),
    Finished,
}

impl KitSpendErrorV2 {
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::ProfileMissing => "ProfileMissing",
            Self::ProfileUnknown => "ProfileUnknown",
            Self::ProfileMalformed => "ProfileMalformed",
            Self::InvalidHumanAssertionDigit => "InvalidHumanAssertionDigit",
            Self::WrongDoor => "WrongDoor",
            Self::InvalidStart => "InvalidStart",
            Self::InvalidTransition => "InvalidTransition",
            Self::WrongIngressSource => "WrongIngressSource",
            Self::RecoveredWalletMismatch => "RecoveredWalletMismatch",
            Self::ReplacementDescriptorInvalid => "ReplacementDescriptorInvalid",
            Self::ReplacementWalletUnchanged => "ReplacementWalletUnchanged",
            Self::Intake(error) => match error {
                IntakeError::TooLarge => "TransactionTooLarge",
                IntakeError::AllocationFailed => "TransactionAllocationFailed",
                IntakeError::HashFailure => "TransactionHashFailure",
            },
            Self::Sweep(error) => error.name(),
            Self::ReviewIncomplete => "ReviewIncomplete",
            Self::ReviewIdentityMismatch => "ReviewIdentityMismatch",
            Self::CompletenessStatementMissing => "CompletenessStatementMissing",
            Self::HumanAssertionMismatch => "HumanAssertionMismatch",
            Self::PostApprovalYield => "PostApprovalYield",
            Self::SigningOutsideSweep => "SigningOutsideSweep",
            Self::TransactionOutsideSweep => "TransactionOutsideSweep",
            Self::ReviewOutsideSweep => "ReviewOutsideSweep",
            Self::ApprovalProhibited => "ApprovalProhibited",
            Self::ExportProhibited => "ExportProhibited",
            Self::ForeignInputProhibited => "ForeignInputProhibited",
            Self::NormalWalletOperationProhibited => "NormalWalletOperationProhibited",
            Self::RestoreProhibited => "RestoreProhibited",
            Self::KitGenerationProhibited => "KitGenerationProhibited",
            Self::KitRegenerationProhibited => "KitRegenerationProhibited",
            Self::DoorSwitchAttempt => "DoorSwitchAttempt",
            Self::SigningRejected(error) => error.name(),
            Self::FinalizationRejected(error) => error.name(),
            Self::Interrupted(interruption) => interruption.name(),
            Self::Finished => "Finished",
        }
    }
}

impl fmt::Display for KitSpendErrorV2 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.name())
    }
}

impl std::error::Error for KitSpendErrorV2 {}

/// Non-secret facts bound to one fully verified finalized sweep.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct KitSpendFinalizedFactsV2 {
    profile: NormalProfileV2,
    old_wallet_id: [u8; 32],
    replacement_wallet_id: [u8; 32],
    destination_index: u32,
    review_hash: ReviewV3Hash,
    raw_transaction_len: u32,
    raw_transaction_sha256: [u8; 32],
    txid: [u8; 32],
    wtxid: [u8; 32],
}

impl KitSpendFinalizedFactsV2 {
    pub const fn profile(self) -> NormalProfileV2 {
        self.profile
    }

    pub const fn old_wallet_id(self) -> [u8; 32] {
        self.old_wallet_id
    }

    pub const fn replacement_wallet_id(self) -> [u8; 32] {
        self.replacement_wallet_id
    }

    pub const fn destination_index(self) -> u32 {
        self.destination_index
    }

    pub const fn review_hash(self) -> ReviewV3Hash {
        self.review_hash
    }

    pub const fn raw_transaction_len(self) -> u32 {
        self.raw_transaction_len
    }

    pub const fn raw_transaction_sha256(self) -> [u8; 32] {
        self.raw_transaction_sha256
    }

    pub const fn txid(self) -> [u8; 32] {
        self.txid
    }

    pub const fn wtxid(self) -> [u8; 32] {
        self.wtxid
    }
}

/// One finalized raw-transaction owner. Its bytes stay crate-private.
pub struct KitSpendOutcomeV2 {
    finalized: FinalizedNormalV3,
    facts: KitSpendFinalizedFactsV2,
    completeness: CoordinatorCompletenessStatementV2,
}

impl KitSpendOutcomeV2 {
    #[must_use]
    pub const fn facts(&self) -> KitSpendFinalizedFactsV2 {
        self.facts
    }

    #[must_use]
    pub const fn completeness(&self) -> CoordinatorCompletenessStatementV2 {
        self.completeness
    }

    pub(crate) fn into_export_artifacts(self) -> Result<KitExportArtifactsV2, KitArtifactErrorV2> {
        KitExportArtifactsV2::bind_finalized(self.facts.profile, &self.finalized)
    }
}

struct CallerPsbtGuard<'a> {
    bytes: &'a mut [u8],
}

impl CallerPsbtGuard<'_> {
    fn as_slice(&self) -> &[u8] {
        self.bytes
    }
}

impl Drop for CallerPsbtGuard<'_> {
    fn drop(&mut self) {
        wipe::bytes(self.bytes);
    }
}

/// One non-clonable Kit-Spend process owner and no general signing session.
pub struct KitSpendSessionV2 {
    profile: NormalProfileV2,
    mode: KitInputModeV2,
    identities: [KitFrameIdentityV2; 2],
    old_descriptors: [[u8; 306]; 2],
    old_wallet_id: [u8; 32],
    payload: Option<BoundKitSpendV2>,
    proof: Option<ValidatedKitSweepV3>,
    replacement_wallet_id: Option<[u8; 32]>,
    destination_index: Option<u32>,
    assertion_digit: KitSpendAssertionDigitV2,
    session_identity: [u8; 16],
    next_cycle: u64,
    approval: Option<KitSpendApprovalIdentityV2>,
    completeness: Option<CoordinatorCompletenessStatementV2>,
    review_position: Option<KitSpendReviewPositionV2>,
    stage: KitSpendStageV2,
    terminal_error: Option<KitSpendErrorV2>,
}

impl KitSpendSessionV2 {
    /// Consume one `KitSpend` readiness capability and bind exact old D.
    pub fn begin(
        core: &mut CoreSession,
        profile_bytes: &[u8],
        ready: KitIntakeReadyV2,
        old_descriptors: &[[u8; 306]; 2],
        assertion_digit: KitSpendAssertionDigitV2,
    ) -> Result<Self, KitSpendErrorV2> {
        let session_identity = match core.kit_session_identity() {
            Ok(identity) => *identity,
            Err(_) => {
                return Err(KitSpendErrorV2::Interrupted(
                    core.terminal_reason()
                        .unwrap_or(Interruption::OperationFailed),
                ))
            }
        };
        let mut session = match Self::begin_bound(
            profile_bytes,
            ready,
            old_descriptors,
            assertion_digit,
            session_identity,
        ) {
            Ok(session) => session,
            Err(error) => {
                core.terminate_kit(Interruption::OperationFailed);
                return Err(error);
            }
        };
        if core.kit_show(CoreScreen::KitSpendTransaction).is_err() {
            return Err(session.fail(KitSpendErrorV2::Interrupted(
                core.terminal_reason()
                    .unwrap_or(Interruption::CapabilityFailed),
            )));
        }
        Ok(session)
    }

    /// Deterministic explicit-identity constructor reserved for ring-fenced
    /// fuzzing; the product constructor always takes identity from qk-core.
    #[cfg(feature = "fuzzing")]
    #[doc(hidden)]
    pub fn fuzz_begin(
        profile_bytes: &[u8],
        ready: KitIntakeReadyV2,
        old_descriptors: &[[u8; 306]; 2],
        assertion_digit: KitSpendAssertionDigitV2,
        session_identity: [u8; 16],
    ) -> Result<Self, KitSpendErrorV2> {
        Self::begin_bound(
            profile_bytes,
            ready,
            old_descriptors,
            assertion_digit,
            session_identity,
        )
    }

    fn begin_bound(
        profile_bytes: &[u8],
        ready: KitIntakeReadyV2,
        old_descriptors: &[[u8; 306]; 2],
        assertion_digit: KitSpendAssertionDigitV2,
        session_identity: [u8; 16],
    ) -> Result<Self, KitSpendErrorV2> {
        let profile = parse_profile(profile_bytes)?;
        let parts = ready.into_spend_parts();
        if parts.door != KitDoorV2::KitSpend {
            return Err(KitSpendErrorV2::WrongDoor);
        }
        let [receive, change] = old_descriptors;
        let descriptor = parse_descriptor_pair_v2(receive, change)
            .map_err(|_| KitSpendErrorV2::RecoveredWalletMismatch)?;
        if descriptor.wallet_id() != parts.wallet_id {
            return Err(KitSpendErrorV2::RecoveredWalletMismatch);
        }
        let payload = parts
            .payload
            .bind_spend_v2(old_descriptors, &parts.wallet_id)
            .map_err(|_| KitSpendErrorV2::RecoveredWalletMismatch)?;
        if payload.wallet_id() != parts.wallet_id {
            return Err(KitSpendErrorV2::RecoveredWalletMismatch);
        }
        Ok(Self {
            profile,
            mode: parts.mode,
            identities: parts.identities,
            old_descriptors: *old_descriptors,
            old_wallet_id: parts.wallet_id,
            payload: Some(payload),
            proof: None,
            replacement_wallet_id: None,
            destination_index: None,
            assertion_digit,
            session_identity,
            next_cycle: 1,
            approval: None,
            completeness: None,
            review_position: None,
            stage: KitSpendStageV2::TransactionIntake,
            terminal_error: None,
        })
    }

    #[must_use]
    pub const fn profile(&self) -> NormalProfileV2 {
        self.profile
    }

    #[must_use]
    pub const fn stage(&self) -> KitSpendStageV2 {
        self.stage
    }

    #[must_use]
    pub const fn review_position(&self) -> Option<KitSpendReviewPositionV2> {
        self.review_position
    }

    #[must_use]
    pub const fn frame_identities(&self) -> [KitFrameIdentityV2; 2] {
        self.identities
    }

    #[must_use]
    pub const fn failure(&self) -> Option<KitSpendErrorV2> {
        self.terminal_error
    }

    #[must_use]
    pub fn screen(&self) -> Option<KitSpendScreenV2<'_>> {
        if self.terminal_error.is_some() {
            return None;
        }
        match self.stage {
            KitSpendStageV2::TransactionIntake => Some(KitSpendScreenV2::TransactionIntake {
                profile: self.profile,
                old_wallet_id: self.old_wallet_id,
                input_mode: self.mode,
            }),
            KitSpendStageV2::Review => self.review_screen(),
            KitSpendStageV2::CompletenessStatement => {
                Some(KitSpendScreenV2::CompletenessStatement {
                    review_hash: self.proof.as_ref()?.review_hash(),
                })
            }
            KitSpendStageV2::HumanAssertion => Some(KitSpendScreenV2::HumanAssertion {
                approval: self.approval?,
            }),
            KitSpendStageV2::Signing | KitSpendStageV2::Finalization => None,
        }
    }

    /// Copy one hostile PSBT, clear the caller buffer, and prove exact sweep
    /// semantics before any review screen becomes reachable.
    pub fn submit_sweep(
        &mut self,
        source: Source,
        caller_psbt: &mut [u8],
        replacement_descriptors: &[[u8; 306]; 2],
        destination_index: ReplacementReceiveIndexV2,
    ) -> Result<KitSpendScreenV2<'_>, KitSpendErrorV2> {
        let guard = CallerPsbtGuard { bytes: caller_psbt };
        self.require_active()?;
        self.reject_if_post_review_yield()?;
        if self.stage != KitSpendStageV2::TransactionIntake || self.proof.is_some() {
            return Err(self.fail(KitSpendErrorV2::TransactionOutsideSweep));
        }
        let input_source = match source {
            Source::CameraBbqrPsbt => InputSource::Qr,
            Source::MediaPsbt => InputSource::MicroSd,
            _ => return Err(self.fail(KitSpendErrorV2::WrongIngressSource)),
        };
        let [replacement_receive, replacement_change] = replacement_descriptors;
        let replacement = parse_descriptor_pair_v2(replacement_receive, replacement_change)
            .map_err(|_| self.fail(KitSpendErrorV2::ReplacementDescriptorInvalid))?;
        let replacement_wallet_id = replacement.wallet_id();
        if replacement_wallet_id == self.old_wallet_id {
            return Err(self.fail(KitSpendErrorV2::ReplacementWalletUnchanged));
        }
        let s0 = OwnedS0::new(guard.as_slice(), input_source)
            .map_err(|error| self.fail(KitSpendErrorV2::Intake(error)))?;
        let [old_receive, old_change] = &self.old_descriptors;
        let old = parse_descriptor_pair_v2(old_receive, old_change)
            .map_err(|_| self.fail(KitSpendErrorV2::RecoveredWalletMismatch))?;
        if old.wallet_id() != self.old_wallet_id {
            return Err(self.fail(KitSpendErrorV2::RecoveredWalletMismatch));
        }
        let proof = build_validated_kit_sweep_v3(s0, old, replacement, destination_index)
            .map_err(|error| self.fail(map_sweep_error(error)))?;
        if proof.wallet_id() != self.old_wallet_id
            || proof.replacement_wallet_id() != replacement_wallet_id
            || self
                .payload
                .as_ref()
                .is_none_or(|payload| payload.wallet_id() != proof.wallet_id())
        {
            return Err(self.fail(KitSpendErrorV2::RecoveredWalletMismatch));
        }
        self.destination_index = Some(proof.destination_index());
        self.replacement_wallet_id = Some(replacement_wallet_id);
        self.proof = Some(proof);
        self.review_position = Some(KitSpendReviewPositionV2::Overview);
        self.stage = KitSpendStageV2::Review;
        match self.screen() {
            Some(screen) => Ok(screen),
            None => Err(KitSpendErrorV2::ReviewIncomplete),
        }
    }

    /// Consume one purpose-bound hostile PSBT owner and delegate to the exact
    /// sweep path. The existing source gate admits only camera-BBQr PSBT or
    /// media PSBT, while the transport allocation is cleared on every exit.
    pub fn submit_sweep_ingress(
        &mut self,
        ingress: HostileIngress,
        replacement_descriptors: &[[u8; 306]; 2],
        destination_index: ReplacementReceiveIndexV2,
    ) -> Result<KitSpendScreenV2<'_>, KitSpendErrorV2> {
        let (source, mut bytes) = ingress.into_kit_parts();
        self.submit_sweep(
            source,
            bytes.as_mut_slice(),
            replacement_descriptors,
            destination_index,
        )
    }

    /// Consume the completed source-03/source-04 owner retained by qk-core,
    /// prove the sweep, and select the first immutable review screen.
    pub fn submit_sweep_from_core(
        &mut self,
        core: &mut CoreSession,
        replacement_descriptors: &[[u8; 306]; 2],
        destination_index: ReplacementReceiveIndexV2,
    ) -> Result<KitSpendScreenV2<'_>, KitSpendErrorV2> {
        let ingress = match core.take_kit_ingress() {
            Ok(ingress) => ingress,
            Err(_) => {
                return Err(self.fail(KitSpendErrorV2::Interrupted(
                    core.terminal_reason()
                        .unwrap_or(Interruption::OperationFailed),
                )))
            }
        };
        if let Err(error) =
            self.submit_sweep_ingress(ingress, replacement_descriptors, destination_index)
        {
            core.terminate_kit(Interruption::OperationFailed);
            return Err(error);
        }
        self.show_review_in_core(core)?;
        self.screen().ok_or(KitSpendErrorV2::ReviewIncomplete)
    }

    /// Visit the next immutable review fact, or enter the completeness screen
    /// only after the final fee warning (if any) has been visited.
    pub fn advance_review(&mut self) -> Result<KitSpendScreenV2<'_>, KitSpendErrorV2> {
        self.require_active()?;
        self.reject_if_post_review_yield()?;
        if self.stage != KitSpendStageV2::Review {
            return Err(self.fail(KitSpendErrorV2::ReviewIncomplete));
        }
        match self.next_review_position() {
            Some(next) => {
                self.review_position = Some(next);
            }
            None => {
                self.review_position = None;
                self.stage = KitSpendStageV2::CompletenessStatement;
            }
        }
        match self.screen() {
            Some(screen) => Ok(screen),
            None => Err(KitSpendErrorV2::ReviewIncomplete),
        }
    }

    /// Advance one and only one bound review position and select its existing
    /// typed screen through qk-core's display capability.
    pub fn advance_review_in_core(
        &mut self,
        core: &mut CoreSession,
    ) -> Result<KitSpendScreenV2<'_>, KitSpendErrorV2> {
        if let Err(error) = self.advance_review() {
            core.terminate_kit(Interruption::OperationFailed);
            return Err(error);
        }
        if self.stage == KitSpendStageV2::CompletenessStatement {
            self.show_in_core(core, CoreScreen::KitSpendCompleteness)?;
        } else {
            self.show_review_in_core(core)?;
        }
        self.screen().ok_or(KitSpendErrorV2::ReviewIncomplete)
    }

    /// Record the sole external completeness statement and mint one approval
    /// identity bound to the exact review hash, session, cycle, and digit.
    pub fn confirm_all_funds(
        &mut self,
        statement: CoordinatorCompletenessStatementV2,
    ) -> Result<KitSpendScreenV2<'_>, KitSpendErrorV2> {
        self.require_active()?;
        if self.stage == KitSpendStageV2::HumanAssertion {
            return Err(self.fail(KitSpendErrorV2::PostApprovalYield));
        }
        if self.stage != KitSpendStageV2::CompletenessStatement
            || self.review_position.is_some()
            || self.completeness.is_some()
        {
            return Err(self.fail(KitSpendErrorV2::CompletenessStatementMissing));
        }
        let review_hash = self
            .proof
            .as_ref()
            .map(ValidatedKitSweepV3::review_hash)
            .ok_or_else(|| self.fail(KitSpendErrorV2::ReviewIncomplete))?;
        let token = KitSpendCycleTokenV2 {
            session_identity: self.session_identity,
            cycle: self.next_cycle,
        };
        self.next_cycle = self
            .next_cycle
            .checked_add(1)
            .ok_or_else(|| self.fail(KitSpendErrorV2::ReviewIdentityMismatch))?;
        self.completeness = Some(statement);
        self.approval = Some(KitSpendApprovalIdentityV2 {
            token,
            review_hash,
            assertion_digit: self.assertion_digit,
        });
        self.stage = KitSpendStageV2::HumanAssertion;
        match self.screen() {
            Some(screen) => Ok(screen),
            None => Err(KitSpendErrorV2::ReviewIdentityMismatch),
        }
    }

    /// Bind the external completeness statement and move directly to the
    /// screen-named assertion digit without permitting another yield.
    pub fn confirm_all_funds_in_core(
        &mut self,
        core: &mut CoreSession,
        statement: CoordinatorCompletenessStatementV2,
    ) -> Result<KitSpendScreenV2<'_>, KitSpendErrorV2> {
        if let Err(error) = self.confirm_all_funds(statement) {
            core.terminate_kit(Interruption::OperationFailed);
            return Err(error);
        }
        self.show_in_core(core, CoreScreen::KitSpendHumanAssertion)?;
        self.screen().ok_or(KitSpendErrorV2::ReviewIdentityMismatch)
    }

    /// Read the one asserted digit and, without yielding, consume the proof
    /// through signing and the single normal-v3 finalization engine.
    pub fn execute(
        mut self,
        approval: KitSpendApprovalIdentityV2,
        key: KeypadKey,
    ) -> Result<KitSpendOutcomeV2, KitSpendErrorV2> {
        self.require_active()?;
        if self.stage != KitSpendStageV2::HumanAssertion || self.completeness.is_none() {
            return Err(self.fail(KitSpendErrorV2::CompletenessStatementMissing));
        }
        let expected = self
            .approval
            .take()
            .ok_or_else(|| self.fail(KitSpendErrorV2::ReviewIdentityMismatch))?;
        if approval != expected {
            return Err(self.fail(KitSpendErrorV2::ReviewIdentityMismatch));
        }
        if key == KeypadKey::CancelBack {
            return Err(self.fail(KitSpendErrorV2::Interrupted(Interruption::Cancelled)));
        }
        if !self.assertion_digit.matches(key) {
            return Err(self.fail(KitSpendErrorV2::HumanAssertionMismatch));
        }
        let proof = self
            .proof
            .take()
            .ok_or_else(|| self.fail(KitSpendErrorV2::ReviewIncomplete))?;
        if proof.review_hash() != expected.review_hash {
            return Err(self.fail(KitSpendErrorV2::ReviewIdentityMismatch));
        }
        let payload = self
            .payload
            .take()
            .ok_or_else(|| self.fail(KitSpendErrorV2::SigningOutsideSweep))?;
        self.stage = KitSpendStageV2::Signing;
        let signed = payload
            .sign_validated_sweep_v3(proof)
            .map_err(|error| self.fail(KitSpendErrorV2::SigningRejected(error)))?;
        self.stage = KitSpendStageV2::Finalization;
        let finalized = signed
            .finalize_v3()
            .map_err(|error| self.fail(KitSpendErrorV2::FinalizationRejected(error)))?;
        let replacement_wallet_id = self
            .replacement_wallet_id
            .ok_or_else(|| self.fail(KitSpendErrorV2::InvalidTransition))?;
        let destination_index = self
            .destination_index
            .ok_or_else(|| self.fail(KitSpendErrorV2::InvalidTransition))?;
        if finalized.wallet_id() != self.old_wallet_id
            || finalized.review_hash() != expected.review_hash
        {
            return Err(self.fail(KitSpendErrorV2::ReviewIdentityMismatch));
        }
        let raw_transaction_len = u32::try_from(finalized.raw_transaction().len())
            .map_err(|_| self.fail(KitSpendErrorV2::InvalidTransition))?;
        let facts = KitSpendFinalizedFactsV2 {
            profile: self.profile,
            old_wallet_id: self.old_wallet_id,
            replacement_wallet_id,
            destination_index,
            review_hash: expected.review_hash,
            raw_transaction_len,
            raw_transaction_sha256: finalized.raw_transaction_sha256(),
            txid: finalized.txid(),
            wtxid: finalized.wtxid(),
        };
        let completeness = self
            .completeness
            .take()
            .ok_or(KitSpendErrorV2::CompletenessStatementMissing)?;
        wipe::bytes(&mut self.session_identity);
        self.terminal_error = Some(KitSpendErrorV2::Finished);
        Ok(KitSpendOutcomeV2 {
            finalized,
            facts,
            completeness,
        })
    }

    /// Read the one digit through qk-core and immediately consume the bound
    /// approval identity through signing and finalization. There is no
    /// transport, capability, or screen operation between the read and sign.
    pub fn execute_in_core(
        mut self,
        core: &mut CoreSession,
        key: KeypadKey,
    ) -> Result<KitSpendOutcomeV2, KitSpendErrorV2> {
        let approval = match self.approval {
            Some(approval) => approval,
            None => return Err(self.fail(KitSpendErrorV2::ReviewIdentityMismatch)),
        };
        let key = match core.kit_read_key(key) {
            Ok(key) => key,
            Err(_) => {
                return Err(self.fail(KitSpendErrorV2::Interrupted(
                    core.terminal_reason()
                        .unwrap_or(Interruption::CapabilityFailed),
                )))
            }
        };
        match self.execute(approval, key) {
            Ok(outcome) => Ok(outcome),
            Err(error) => {
                core.terminate_kit(match error {
                    KitSpendErrorV2::Interrupted(reason) => reason,
                    _ => Interruption::OperationFailed,
                });
                Err(error)
            }
        }
    }

    /// Reject every foreign operation. Once review is complete, any such
    /// call is the no-yield violation regardless of its earlier-stage name.
    pub fn reject_foreign_operation(
        &mut self,
        operation: KitSpendForeignOperationV2,
    ) -> Result<(), KitSpendErrorV2> {
        self.require_active()?;
        if matches!(
            self.stage,
            KitSpendStageV2::CompletenessStatement | KitSpendStageV2::HumanAssertion
        ) {
            return Err(self.fail(KitSpendErrorV2::PostApprovalYield));
        }
        let error = match operation {
            KitSpendForeignOperationV2::Signing => KitSpendErrorV2::SigningOutsideSweep,
            KitSpendForeignOperationV2::Transaction => KitSpendErrorV2::TransactionOutsideSweep,
            KitSpendForeignOperationV2::Review => KitSpendErrorV2::ReviewOutsideSweep,
            KitSpendForeignOperationV2::Approval => KitSpendErrorV2::ApprovalProhibited,
            KitSpendForeignOperationV2::Export => KitSpendErrorV2::ExportProhibited,
            KitSpendForeignOperationV2::Intake => KitSpendErrorV2::ForeignInputProhibited,
            KitSpendForeignOperationV2::NormalWallet => {
                KitSpendErrorV2::NormalWalletOperationProhibited
            }
            KitSpendForeignOperationV2::Restore => KitSpendErrorV2::RestoreProhibited,
            KitSpendForeignOperationV2::KitGeneration => KitSpendErrorV2::KitGenerationProhibited,
            KitSpendForeignOperationV2::KitRegeneration => {
                KitSpendErrorV2::KitRegenerationProhibited
            }
            KitSpendForeignOperationV2::DoorSwitch => KitSpendErrorV2::DoorSwitchAttempt,
            KitSpendForeignOperationV2::Transport
            | KitSpendForeignOperationV2::Capability
            | KitSpendForeignOperationV2::ScreenYield => KitSpendErrorV2::InvalidTransition,
        };
        Err(self.fail(error))
    }

    /// Every closed interruption terminates and clears every retained owner.
    pub fn interrupt(&mut self, reason: Interruption) -> Result<(), KitSpendErrorV2> {
        self.require_active()?;
        Err(self.fail(KitSpendErrorV2::Interrupted(reason)))
    }

    fn review(&self) -> Option<&ReviewV3> {
        self.proof.as_ref().map(ValidatedKitSweepV3::review)
    }

    fn show_review_in_core(&mut self, core: &mut CoreSession) -> Result<(), KitSpendErrorV2> {
        let screen = match self.review_position {
            Some(KitSpendReviewPositionV2::Overview) => CoreScreen::ReviewOverview,
            Some(KitSpendReviewPositionV2::Arithmetic) => CoreScreen::ReviewArithmetic,
            Some(KitSpendReviewPositionV2::Recipient(_)) => CoreScreen::ReviewRecipient,
            Some(KitSpendReviewPositionV2::Change(_)) => CoreScreen::ReviewChange,
            Some(KitSpendReviewPositionV2::OpReturn(_)) => CoreScreen::ReviewOpReturn,
            Some(KitSpendReviewPositionV2::Locktime) => CoreScreen::ReviewLocktime,
            Some(KitSpendReviewPositionV2::Sequence(_)) => CoreScreen::ReviewSequence,
            Some(KitSpendReviewPositionV2::FeePolicy) => CoreScreen::ReviewFeePolicy,
            Some(KitSpendReviewPositionV2::FeeFacts) => CoreScreen::ReviewFeeFacts,
            Some(KitSpendReviewPositionV2::Warning(_)) => CoreScreen::ReviewWarning,
            None => return Err(self.fail(KitSpendErrorV2::ReviewIncomplete)),
        };
        self.show_in_core(core, screen)
    }

    fn show_in_core(
        &mut self,
        core: &mut CoreSession,
        screen: CoreScreen,
    ) -> Result<(), KitSpendErrorV2> {
        if core.kit_show(screen).is_err() {
            return Err(self.fail(KitSpendErrorV2::Interrupted(
                core.terminal_reason()
                    .unwrap_or(Interruption::CapabilityFailed),
            )));
        }
        Ok(())
    }

    fn review_screen(&self) -> Option<KitSpendScreenV2<'_>> {
        let review = self.review()?;
        Some(match self.review_position? {
            KitSpendReviewPositionV2::Overview => KitSpendScreenV2::ReviewOverview {
                profile: self.profile,
                network: review.context().network,
                wallet_id: review.wallet_id(),
                input_count: review.input_count(),
                total_input_amount: review.total_input_amount(),
            },
            KitSpendReviewPositionV2::Arithmetic => KitSpendScreenV2::ReviewArithmetic {
                total_input_amount: review.total_input_amount(),
                total_output_amount: review.total_output_amount(),
                fee: review.fee(),
            },
            KitSpendReviewPositionV2::Recipient(index) => {
                let output = review.outputs().get(index)?;
                let recipient = match output.ownership() {
                    ReviewV3OutputOwnership::NotOwned {
                        recipient_type,
                        data,
                    } => KitSpendRecipientFactV2::External {
                        recipient_type: *recipient_type,
                        data: data.as_slice(),
                    },
                    ReviewV3OutputOwnership::ProvenSelfTransfer {
                        child_index,
                        witness_program,
                    } => KitSpendRecipientFactV2::SelfTransfer {
                        child_index: *child_index,
                        witness_program: witness_program.as_slice(),
                    },
                    ReviewV3OutputOwnership::ProvenChange { .. } => return None,
                };
                KitSpendScreenV2::ReviewRecipient {
                    index: output.index(),
                    amount: output.amount(),
                    script_pubkey: output.script_pubkey(),
                    recipient,
                }
            }
            KitSpendReviewPositionV2::Change(index) => {
                let output = review.outputs().get(index)?;
                let ReviewV3OutputOwnership::ProvenChange { child_index } = output.ownership()
                else {
                    return None;
                };
                KitSpendScreenV2::ReviewChange {
                    index: output.index(),
                    amount: output.amount(),
                    script_pubkey: output.script_pubkey(),
                    child_index: *child_index,
                }
            }
            KitSpendReviewPositionV2::OpReturn(index) => {
                let output = review.outputs().get(index)?;
                let ReviewV3OutputOwnership::NotOwned {
                    recipient_type: RecipientType::OpReturn,
                    data,
                } = output.ownership()
                else {
                    return None;
                };
                KitSpendScreenV2::ReviewOpReturn {
                    index: output.index(),
                    amount: output.amount(),
                    script_pubkey: output.script_pubkey(),
                    payload: data.as_slice(),
                }
            }
            KitSpendReviewPositionV2::Locktime => KitSpendScreenV2::ReviewLocktime {
                locktime: review.locktime(),
            },
            KitSpendReviewPositionV2::Sequence(index) => {
                let input = review.inputs().get(index)?;
                KitSpendScreenV2::ReviewSequence {
                    input_index: input.index(),
                    sequence: input.sequence(),
                    direct_rbf: input.direct_rbf(),
                }
            }
            KitSpendReviewPositionV2::FeePolicy => KitSpendScreenV2::ReviewFeePolicy {
                identifier: review.fee_policy_identifier(),
            },
            KitSpendReviewPositionV2::FeeFacts => KitSpendScreenV2::ReviewFeeFacts {
                fee: review.fee(),
                estimated_vsize: review.estimated_vsize(),
                fee_rate_msat_per_vbyte: review.fee_rate_msat_per_vbyte(),
            },
            KitSpendReviewPositionV2::Warning(index) => KitSpendScreenV2::ReviewWarning {
                warning: review.fee_warnings().nth(index)?,
            },
        })
    }

    fn next_review_position(&self) -> Option<KitSpendReviewPositionV2> {
        let review = self.review()?;
        Some(match self.review_position? {
            KitSpendReviewPositionV2::Overview => KitSpendReviewPositionV2::Arithmetic,
            KitSpendReviewPositionV2::Arithmetic => first_recipient(review, None)
                .map(KitSpendReviewPositionV2::Recipient)
                .or_else(|| first_change(review, None).map(KitSpendReviewPositionV2::Change))
                .or_else(|| first_op_return(review, None).map(KitSpendReviewPositionV2::OpReturn))
                .unwrap_or(KitSpendReviewPositionV2::Locktime),
            KitSpendReviewPositionV2::Recipient(index) => first_recipient(review, Some(index))
                .map(KitSpendReviewPositionV2::Recipient)
                .or_else(|| first_change(review, None).map(KitSpendReviewPositionV2::Change))
                .or_else(|| first_op_return(review, None).map(KitSpendReviewPositionV2::OpReturn))
                .unwrap_or(KitSpendReviewPositionV2::Locktime),
            KitSpendReviewPositionV2::Change(index) => first_change(review, Some(index))
                .map(KitSpendReviewPositionV2::Change)
                .or_else(|| first_op_return(review, None).map(KitSpendReviewPositionV2::OpReturn))
                .unwrap_or(KitSpendReviewPositionV2::Locktime),
            KitSpendReviewPositionV2::OpReturn(index) => first_op_return(review, Some(index))
                .map(KitSpendReviewPositionV2::OpReturn)
                .unwrap_or(KitSpendReviewPositionV2::Locktime),
            KitSpendReviewPositionV2::Locktime => {
                if review.inputs().is_empty() {
                    KitSpendReviewPositionV2::FeePolicy
                } else {
                    KitSpendReviewPositionV2::Sequence(0)
                }
            }
            KitSpendReviewPositionV2::Sequence(index) => match index.checked_add(1) {
                Some(next) if next < review.inputs().len() => {
                    KitSpendReviewPositionV2::Sequence(next)
                }
                _ => KitSpendReviewPositionV2::FeePolicy,
            },
            KitSpendReviewPositionV2::FeePolicy => KitSpendReviewPositionV2::FeeFacts,
            KitSpendReviewPositionV2::FeeFacts => {
                if review.fee_policy().warning_count() == 0 {
                    return None;
                }
                KitSpendReviewPositionV2::Warning(0)
            }
            KitSpendReviewPositionV2::Warning(index) => match index.checked_add(1) {
                Some(next) if next < review.fee_policy().warning_count() => {
                    KitSpendReviewPositionV2::Warning(next)
                }
                _ => return None,
            },
        })
    }

    fn require_active(&self) -> Result<(), KitSpendErrorV2> {
        if self.terminal_error.is_some() {
            Err(KitSpendErrorV2::Finished)
        } else {
            Ok(())
        }
    }

    fn reject_if_post_review_yield(&mut self) -> Result<(), KitSpendErrorV2> {
        if matches!(
            self.stage,
            KitSpendStageV2::CompletenessStatement | KitSpendStageV2::HumanAssertion
        ) {
            Err(self.fail(KitSpendErrorV2::PostApprovalYield))
        } else {
            Ok(())
        }
    }

    fn fail(&mut self, error: KitSpendErrorV2) -> KitSpendErrorV2 {
        if self.terminal_error.is_none() {
            drop(self.payload.take());
            drop(self.proof.take());
            self.replacement_wallet_id = None;
            self.destination_index = None;
            self.approval = None;
            self.completeness = None;
            self.review_position = None;
            wipe::bytes(&mut self.session_identity);
            self.terminal_error = Some(error);
        }
        error
    }
}

impl Drop for KitSpendSessionV2 {
    fn drop(&mut self) {
        drop(self.payload.take());
        drop(self.proof.take());
        self.approval = None;
        self.completeness = None;
        self.review_position = None;
        wipe::bytes(&mut self.session_identity);
    }
}

fn parse_profile(bytes: &[u8]) -> Result<NormalProfileV2, KitSpendErrorV2> {
    NormalProfileV2::parse(bytes).map_err(|error| match error {
        NormalArtifactErrorV2::ProfileMissing => KitSpendErrorV2::ProfileMissing,
        NormalArtifactErrorV2::ProfileUnknown => KitSpendErrorV2::ProfileUnknown,
        NormalArtifactErrorV2::ProfileMalformed => KitSpendErrorV2::ProfileMalformed,
        _ => KitSpendErrorV2::InvalidStart,
    })
}

const fn map_sweep_error(error: KitSweepV3Error) -> KitSpendErrorV2 {
    match error {
        KitSweepV3Error::ReplacementWalletUnchanged => KitSpendErrorV2::ReplacementWalletUnchanged,
        _ => KitSpendErrorV2::Sweep(error),
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

const fn numeric_key(key: KeypadKey) -> Option<u8> {
    Some(match key {
        KeypadKey::Zero => 0,
        KeypadKey::One => 1,
        KeypadKey::TwoDown => 2,
        KeypadKey::Three => 3,
        KeypadKey::FourLeft => 4,
        KeypadKey::Five => 5,
        KeypadKey::SixRight => 6,
        KeypadKey::Seven => 7,
        KeypadKey::EightUp => 8,
        KeypadKey::Nine => 9,
        _ => return None,
    })
}
