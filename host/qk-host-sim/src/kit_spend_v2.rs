//! V2 slice-11 HOST-only one-sweep Kit-Spend continuation.

use crate::finalization::FinalizedTransaction;
use crate::kit_intake_v2::{KitFrameIdentityV2, KitInputModeV2, KitIntakeReadyV2};
use crate::screen_flow::KeypadKey;
use crate::screen_flow_v2::{
    FlowTerminalV2, KitDoorV2, ScreenFlowV2, ScreenKindV2, WipingReasonV2,
};
use crate::signing_v2::{finalize_signed_kit_sweep_v3, SigningV2Error};
use crate::transaction_wipe_v2::wipe_bytes;
use core::fmt;
use qk_kit::{BoundKitSpendV2, KitSpendMathErrorV3};
use qk_psbt::{
    build_validated_kit_sweep_v3, InputSource, IntakeError, KitSweepV3Error, OwnedS0, ReviewV3Hash,
    ValidatedKitSweepV3,
};

/// The coordinator's factual statement; HOST does not derive this fact.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CoordinatorCompletenessStatementV2 {
    AllFundsIncluded,
}

/// One public decimal digit named by the Kit-Spend assertion screen.
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

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum KitSpendStageV2 {
    TransactionIntake,
    CompletenessStatement,
    HumanAssertion,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct KitSpendScreenV2 {
    stage: KitSpendStageV2,
    old_wallet_id: [u8; 32],
    replacement_wallet_id: Option<[u8; 32]>,
    destination_index: Option<u32>,
    review_hash: Option<ReviewV3Hash>,
    input_mode: KitInputModeV2,
    assertion_digit: Option<KitSpendAssertionDigitV2>,
}

impl KitSpendScreenV2 {
    #[must_use]
    pub const fn stage(self) -> KitSpendStageV2 {
        self.stage
    }

    #[must_use]
    pub const fn old_wallet_id(self) -> [u8; 32] {
        self.old_wallet_id
    }

    #[must_use]
    pub const fn replacement_wallet_id(self) -> Option<[u8; 32]> {
        self.replacement_wallet_id
    }

    #[must_use]
    pub const fn destination_index(self) -> Option<u32> {
        self.destination_index
    }

    #[must_use]
    pub const fn review_hash(self) -> Option<ReviewV3Hash> {
        self.review_hash
    }

    #[must_use]
    pub const fn input_mode(self) -> KitInputModeV2 {
        self.input_mode
    }

    #[must_use]
    pub const fn assertion_digit(self) -> Option<KitSpendAssertionDigitV2> {
        self.assertion_digit
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum KitSpendInterruptionV2 {
    Cancelled,
    OperationFailed,
    MediaRemoved,
    CardRemoved,
    SessionTimeout,
    Shutdown,
    Restart,
    PowerLoss,
}

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
}

/// Stable named HOST rejection surface; no variant carries transaction bytes.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum KitSpendErrorV2 {
    InvalidHumanAssertionDigit,
    WrongDoor,
    InvalidStart,
    RecoveredWalletMismatch,
    InvalidTransition,
    ReplacementDescriptorInvalid,
    Intake(IntakeError),
    Sweep(KitSweepV3Error),
    CompletenessStatementMissing,
    HumanAssertionMismatch,
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
    Signing(KitSpendMathErrorV3),
    Finalization(SigningV2Error),
    Cancelled,
    OperationFailed,
    MediaRemoved,
    CardRemoved,
    SessionTimeout,
    Shutdown,
    Restart,
    PowerLoss,
    Finished,
}

impl KitSpendErrorV2 {
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::InvalidHumanAssertionDigit => "InvalidHumanAssertionDigit",
            Self::WrongDoor => "WrongDoor",
            Self::InvalidStart => "InvalidStart",
            Self::RecoveredWalletMismatch => "RecoveredWalletMismatch",
            Self::InvalidTransition => "InvalidTransition",
            Self::ReplacementDescriptorInvalid => "ReplacementDescriptorInvalid",
            Self::Intake(error) => match error {
                IntakeError::TooLarge => "TransactionTooLarge",
                IntakeError::AllocationFailed => "TransactionAllocationFailed",
                IntakeError::HashFailure => "TransactionHashFailure",
            },
            Self::Sweep(error) => error.name(),
            Self::CompletenessStatementMissing => "CompletenessStatementMissing",
            Self::HumanAssertionMismatch => "HumanAssertionMismatch",
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
            Self::Signing(error) => error.name(),
            Self::Finalization(_) => "SweepFinalizationFailed",
            Self::Cancelled => "Cancelled",
            Self::OperationFailed => "OperationFailed",
            Self::MediaRemoved => "MediaRemoved",
            Self::CardRemoved => "CardRemoved",
            Self::SessionTimeout => "SessionTimeout",
            Self::Shutdown => "Shutdown",
            Self::Restart => "Restart",
            Self::PowerLoss => "PowerLoss",
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

/// One consuming Kit-Spend result; dropping it clears both transaction owners.
pub struct KitSpendOutcomeV2 {
    finalized: FinalizedTransaction,
    old_wallet_id: [u8; 32],
    replacement_wallet_id: [u8; 32],
    destination_index: u32,
    review_hash: ReviewV3Hash,
    completeness: CoordinatorCompletenessStatementV2,
}

impl KitSpendOutcomeV2 {
    #[must_use]
    pub const fn finalized(&self) -> &FinalizedTransaction {
        &self.finalized
    }

    #[must_use]
    pub const fn old_wallet_id(&self) -> [u8; 32] {
        self.old_wallet_id
    }

    #[must_use]
    pub const fn replacement_wallet_id(&self) -> [u8; 32] {
        self.replacement_wallet_id
    }

    #[must_use]
    pub const fn destination_index(&self) -> u32 {
        self.destination_index
    }

    #[must_use]
    pub const fn review_hash(&self) -> ReviewV3Hash {
        self.review_hash
    }

    #[must_use]
    pub const fn completeness(&self) -> CoordinatorCompletenessStatementV2 {
        self.completeness
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
        wipe_bytes(self.bytes);
    }
}

/// One non-clonable Kit-Spend continuation and no general signing session.
pub struct KitSpendSessionV2 {
    flow: Option<ScreenFlowV2>,
    payload: Option<BoundKitSpendV2>,
    proof: Option<ValidatedKitSweepV3>,
    old_descriptors: [[u8; 306]; 2],
    old_wallet_id: [u8; 32],
    mode: KitInputModeV2,
    identities: [KitFrameIdentityV2; 2],
    assertion_digit: KitSpendAssertionDigitV2,
    completeness: Option<CoordinatorCompletenessStatementV2>,
    stage: KitSpendStageV2,
    failed: Option<KitSpendErrorV2>,
    active: bool,
}

impl KitSpendSessionV2 {
    pub fn begin(
        ready: KitIntakeReadyV2,
        old_descriptors: &[[u8; 306]; 2],
        assertion_digit: KitSpendAssertionDigitV2,
    ) -> Result<Self, KitSpendErrorV2> {
        let mut parts = ready.into_spend_parts();
        if parts.door != KitDoorV2::KitSpend {
            parts
                .flow
                .terminate_kit_spend(WipingReasonV2::DoorSwitchAttempt);
            return Err(KitSpendErrorV2::WrongDoor);
        }
        if parts.next_screen != ScreenKindV2::KitSpendTransaction
            || parts.flow.screen_kind() != Some(ScreenKindV2::KitSpendTransaction)
        {
            parts
                .flow
                .terminate_kit_spend(WipingReasonV2::InvalidTransition);
            return Err(KitSpendErrorV2::InvalidStart);
        }
        let payload = parts
            .payload
            .bind_spend_v2(old_descriptors, &parts.wallet_id)
            .map_err(|_| {
                parts
                    .flow
                    .terminate_kit_spend(WipingReasonV2::OperationFailed);
                KitSpendErrorV2::RecoveredWalletMismatch
            })?;
        Ok(Self {
            flow: Some(parts.flow),
            payload: Some(payload),
            proof: None,
            old_descriptors: *old_descriptors,
            old_wallet_id: parts.wallet_id,
            mode: parts.mode,
            identities: parts.identities,
            assertion_digit,
            completeness: None,
            stage: KitSpendStageV2::TransactionIntake,
            failed: None,
            active: true,
        })
    }

    #[must_use]
    pub fn screen(&self) -> Option<KitSpendScreenV2> {
        if !self.active {
            return None;
        }
        Some(KitSpendScreenV2 {
            stage: self.stage,
            old_wallet_id: self.old_wallet_id,
            replacement_wallet_id: self
                .proof
                .as_ref()
                .map(ValidatedKitSweepV3::replacement_wallet_id),
            destination_index: self
                .proof
                .as_ref()
                .map(ValidatedKitSweepV3::destination_index),
            review_hash: self.proof.as_ref().map(ValidatedKitSweepV3::review_hash),
            input_mode: self.mode,
            assertion_digit: (self.stage == KitSpendStageV2::HumanAssertion)
                .then_some(self.assertion_digit),
        })
    }

    #[must_use]
    pub const fn frame_identities(&self) -> [KitFrameIdentityV2; 2] {
        self.identities
    }

    #[must_use]
    pub fn terminal(&self) -> Option<FlowTerminalV2> {
        self.flow.as_ref().and_then(ScreenFlowV2::terminal)
    }

    #[must_use]
    pub const fn failure(&self) -> Option<KitSpendErrorV2> {
        self.failed
    }

    /// Copy one bounded hostile PSBT, clear the caller buffer, and prove the
    /// exact old-wallet-to-replacement-wallet sweep before exposing the
    /// completeness screen.
    pub fn submit_sweep(
        &mut self,
        caller_psbt: &mut [u8],
        source: InputSource,
        replacement_descriptors: &[[u8; 306]; 2],
        destination_index: u32,
    ) -> Result<KitSpendScreenV2, KitSpendErrorV2> {
        let guard = CallerPsbtGuard { bytes: caller_psbt };
        if !self.active {
            return Err(KitSpendErrorV2::Finished);
        }
        if self.stage != KitSpendStageV2::TransactionIntake || self.proof.is_some() {
            return Err(self.fail(
                KitSpendErrorV2::TransactionOutsideSweep,
                WipingReasonV2::OperationFailed,
            ));
        }
        if !self
            .flow
            .as_mut()
            .is_some_and(ScreenFlowV2::accept_kit_spend_transaction_semantic)
        {
            return Err(self.fail(
                KitSpendErrorV2::InvalidTransition,
                WipingReasonV2::InvalidTransition,
            ));
        }
        let old_descriptor = qk_descriptor::parse_descriptor_pair_v2(
            &self.old_descriptors[0],
            &self.old_descriptors[1],
        )
        .map_err(|_| {
            self.fail(
                KitSpendErrorV2::RecoveredWalletMismatch,
                WipingReasonV2::OperationFailed,
            )
        })?;
        let replacement_descriptor = qk_descriptor::parse_descriptor_pair_v2(
            &replacement_descriptors[0],
            &replacement_descriptors[1],
        )
        .map_err(|_| {
            self.fail(
                KitSpendErrorV2::ReplacementDescriptorInvalid,
                WipingReasonV2::OperationFailed,
            )
        })?;
        let s0 = OwnedS0::new(guard.as_slice(), source).map_err(|error| {
            self.fail(
                KitSpendErrorV2::Intake(error),
                WipingReasonV2::OperationFailed,
            )
        })?;
        let proof = build_validated_kit_sweep_v3(
            s0,
            old_descriptor,
            replacement_descriptor,
            destination_index,
        )
        .map_err(|error| {
            self.fail(
                KitSpendErrorV2::Sweep(error),
                WipingReasonV2::OperationFailed,
            )
        })?;
        if proof.wallet_id() != self.old_wallet_id
            || self
                .payload
                .as_ref()
                .is_none_or(|payload| payload.wallet_id() != proof.wallet_id())
        {
            return Err(self.fail(
                KitSpendErrorV2::RecoveredWalletMismatch,
                WipingReasonV2::OperationFailed,
            ));
        }
        if !self
            .flow
            .as_mut()
            .is_some_and(ScreenFlowV2::accept_kit_spend_validation_semantic)
        {
            return Err(self.fail(
                KitSpendErrorV2::InvalidTransition,
                WipingReasonV2::InvalidTransition,
            ));
        }
        self.proof = Some(proof);
        self.stage = KitSpendStageV2::CompletenessStatement;
        self.screen().ok_or(KitSpendErrorV2::InvalidTransition)
    }

    pub fn confirm_completeness(
        &mut self,
        statement: CoordinatorCompletenessStatementV2,
    ) -> Result<KitSpendScreenV2, KitSpendErrorV2> {
        if !self.active {
            return Err(KitSpendErrorV2::Finished);
        }
        if self.stage != KitSpendStageV2::CompletenessStatement {
            let error = if self.completeness.is_some() {
                KitSpendErrorV2::InvalidTransition
            } else {
                KitSpendErrorV2::CompletenessStatementMissing
            };
            let reason = if error == KitSpendErrorV2::InvalidTransition {
                WipingReasonV2::InvalidTransition
            } else {
                WipingReasonV2::OperationFailed
            };
            return Err(self.fail(error, reason));
        }
        if self.proof.is_none() {
            return Err(self.fail(
                KitSpendErrorV2::CompletenessStatementMissing,
                WipingReasonV2::OperationFailed,
            ));
        }
        if !self
            .flow
            .as_mut()
            .is_some_and(ScreenFlowV2::accept_kit_spend_completeness_semantic)
        {
            return Err(self.fail(
                KitSpendErrorV2::InvalidTransition,
                WipingReasonV2::InvalidTransition,
            ));
        }
        self.completeness = Some(statement);
        self.stage = KitSpendStageV2::HumanAssertion;
        self.screen().ok_or(KitSpendErrorV2::InvalidTransition)
    }

    pub fn execute(mut self, key: KeypadKey) -> Result<KitSpendOutcomeV2, KitSpendErrorV2> {
        if !self.active {
            return Err(KitSpendErrorV2::Finished);
        }
        if self.stage != KitSpendStageV2::HumanAssertion || self.completeness.is_none() {
            return Err(self.fail(
                KitSpendErrorV2::CompletenessStatementMissing,
                WipingReasonV2::OperationFailed,
            ));
        }
        if key == KeypadKey::CancelBack {
            return Err(self.fail(KitSpendErrorV2::Cancelled, WipingReasonV2::Cancelled));
        }
        if !self.assertion_digit.matches(key) {
            return Err(self.fail(
                KitSpendErrorV2::HumanAssertionMismatch,
                WipingReasonV2::OperationFailed,
            ));
        }
        let proof = self.proof.take().ok_or_else(|| {
            self.fail(
                KitSpendErrorV2::InvalidTransition,
                WipingReasonV2::InvalidTransition,
            )
        })?;
        let replacement_wallet_id = proof.replacement_wallet_id();
        let destination_index = proof.destination_index();
        let review_hash = proof.review_hash();
        let payload = self.payload.take().ok_or_else(|| {
            self.fail(
                KitSpendErrorV2::InvalidTransition,
                WipingReasonV2::InvalidTransition,
            )
        })?;
        let signed = payload.sign_validated_sweep_v3(proof).map_err(|error| {
            self.fail(
                KitSpendErrorV2::Signing(error),
                WipingReasonV2::OperationFailed,
            )
        })?;
        let finalized = finalize_signed_kit_sweep_v3(signed).map_err(|error| {
            self.fail(
                KitSpendErrorV2::Finalization(error),
                WipingReasonV2::OperationFailed,
            )
        })?;
        if !self
            .flow
            .as_mut()
            .is_some_and(ScreenFlowV2::complete_kit_spend_semantic)
        {
            return Err(self.fail(
                KitSpendErrorV2::InvalidTransition,
                WipingReasonV2::InvalidTransition,
            ));
        }
        self.active = false;
        Ok(KitSpendOutcomeV2 {
            finalized,
            old_wallet_id: self.old_wallet_id,
            replacement_wallet_id,
            destination_index,
            review_hash,
            completeness: self
                .completeness
                .take()
                .ok_or(KitSpendErrorV2::CompletenessStatementMissing)?,
        })
    }

    pub fn reject_foreign_operation(
        &mut self,
        operation: KitSpendForeignOperationV2,
    ) -> Result<KitSpendScreenV2, KitSpendErrorV2> {
        if !self.active {
            return Err(KitSpendErrorV2::Finished);
        }
        let (error, reason) = match operation {
            KitSpendForeignOperationV2::Signing => (
                KitSpendErrorV2::SigningOutsideSweep,
                WipingReasonV2::OperationFailed,
            ),
            KitSpendForeignOperationV2::Transaction => (
                KitSpendErrorV2::TransactionOutsideSweep,
                WipingReasonV2::OperationFailed,
            ),
            KitSpendForeignOperationV2::Review => (
                KitSpendErrorV2::ReviewOutsideSweep,
                WipingReasonV2::OperationFailed,
            ),
            KitSpendForeignOperationV2::Approval => (
                KitSpendErrorV2::ApprovalProhibited,
                WipingReasonV2::OperationFailed,
            ),
            KitSpendForeignOperationV2::Export => (
                KitSpendErrorV2::ExportProhibited,
                WipingReasonV2::OperationFailed,
            ),
            KitSpendForeignOperationV2::Intake => (
                KitSpendErrorV2::ForeignInputProhibited,
                WipingReasonV2::KitScannerModeMismatch,
            ),
            KitSpendForeignOperationV2::NormalWallet => (
                KitSpendErrorV2::NormalWalletOperationProhibited,
                WipingReasonV2::OperationFailed,
            ),
            KitSpendForeignOperationV2::Restore => (
                KitSpendErrorV2::RestoreProhibited,
                WipingReasonV2::OperationFailed,
            ),
            KitSpendForeignOperationV2::KitGeneration => (
                KitSpendErrorV2::KitGenerationProhibited,
                WipingReasonV2::OperationFailed,
            ),
            KitSpendForeignOperationV2::KitRegeneration => (
                KitSpendErrorV2::KitRegenerationProhibited,
                WipingReasonV2::OperationFailed,
            ),
            KitSpendForeignOperationV2::DoorSwitch => (
                KitSpendErrorV2::DoorSwitchAttempt,
                WipingReasonV2::DoorSwitchAttempt,
            ),
        };
        Err(self.fail(error, reason))
    }

    pub fn interrupt(
        &mut self,
        interruption: KitSpendInterruptionV2,
    ) -> Result<KitSpendScreenV2, KitSpendErrorV2> {
        if !self.active {
            return Err(KitSpendErrorV2::Finished);
        }
        let (error, reason) = match interruption {
            KitSpendInterruptionV2::Cancelled => {
                (KitSpendErrorV2::Cancelled, WipingReasonV2::Cancelled)
            }
            KitSpendInterruptionV2::OperationFailed => (
                KitSpendErrorV2::OperationFailed,
                WipingReasonV2::OperationFailed,
            ),
            KitSpendInterruptionV2::MediaRemoved => {
                (KitSpendErrorV2::MediaRemoved, WipingReasonV2::MediaRemoved)
            }
            KitSpendInterruptionV2::CardRemoved => {
                (KitSpendErrorV2::CardRemoved, WipingReasonV2::CardRemoved)
            }
            KitSpendInterruptionV2::SessionTimeout => (
                KitSpendErrorV2::SessionTimeout,
                WipingReasonV2::SessionTimeout,
            ),
            KitSpendInterruptionV2::Shutdown => {
                (KitSpendErrorV2::Shutdown, WipingReasonV2::Shutdown)
            }
            KitSpendInterruptionV2::Restart => (KitSpendErrorV2::Restart, WipingReasonV2::Restart),
            KitSpendInterruptionV2::PowerLoss => {
                (KitSpendErrorV2::PowerLoss, WipingReasonV2::PowerLoss)
            }
        };
        Err(self.fail(error, reason))
    }

    fn fail(&mut self, error: KitSpendErrorV2, reason: WipingReasonV2) -> KitSpendErrorV2 {
        self.payload.take();
        self.proof.take();
        self.completeness = None;
        if let Some(flow) = self.flow.as_mut() {
            flow.terminate_kit_spend(reason);
        }
        self.failed = Some(error);
        self.active = false;
        error
    }
}

impl Drop for KitSpendSessionV2 {
    fn drop(&mut self) {
        self.payload.take();
        self.proof.take();
        self.completeness = None;
        if self.active {
            if let Some(flow) = self.flow.as_mut() {
                flow.terminate_kit_spend(WipingReasonV2::Cancelled);
            }
            self.active = false;
        }
    }
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
