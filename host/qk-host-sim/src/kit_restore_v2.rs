//! V2 slice-10 HOST-only Kit-Restore semantic continuation.
//!
//! This owner accepts only the opaque QK-DEC-131 KitRestore capability,
//! rebinds it to exact D, fixes one non-signing action, requires the named
//! human digit, and terminates with mandatory fresh-wallet migration.

#![deny(unsafe_op_in_unsafe_fn)]

use crate::kit_intake_v2::{KitFrameIdentityV2, KitInputModeV2, KitIntakeReadyV2};
use crate::screen_flow::KeypadKey;
use crate::screen_flow_v2::{
    CardRemainsStatementV2, FlowTerminalV2, KitDoorV2, KitRestoreActionV2, ScreenFlowV2,
    ScreenKindV2, WipingReasonV2,
};
use core::fmt;
use core::ptr;
use core::sync::atomic::{compiler_fence, Ordering};
use qk_kit::{
    A1ReprintDispositionV2, A1ReprintReceiptV2, A1ReprintViewV2, BoundKitRestoreV2,
    KitRestoreDispositionV2, KitRestoreErrorV2 as KitMathErrorV2, PreparedA1ReprintV2,
    PreparedReplacementBV2, ReplacementBReceiptV2, ReplacementBViewV2, SurvivingBFactorV2,
};

const A1_CAPSULE_BYTES: usize = 67;

#[allow(unsafe_code)]
#[inline(never)]
fn wipe(bytes: &mut [u8]) {
    for byte in bytes {
        // SAFETY: the byte is live and uniquely borrowed for the write.
        unsafe { ptr::write_volatile(byte, 0) };
    }
    compiler_fence(Ordering::SeqCst);
}

struct CallerBufferGuard<'a, const N: usize> {
    bytes: &'a mut [u8; N],
}

impl<const N: usize> CallerBufferGuard<'_, N> {
    fn as_array(&self) -> &[u8; N] {
        self.bytes
    }
}

impl<const N: usize> Drop for CallerBufferGuard<'_, N> {
    fn drop(&mut self) {
        wipe(self.bytes);
    }
}

/// One public decimal digit named by the restore assertion screen.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct HumanAssertionDigitV2(u8);

impl HumanAssertionDigitV2 {
    pub fn new(digit: u8) -> Result<Self, KitRestoreErrorV2> {
        (digit <= 9)
            .then_some(Self(digit))
            .ok_or(KitRestoreErrorV2::InvalidHumanAssertionDigit)
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
pub enum KitRestoreStageV2 {
    ActionSelection,
    CardRemainsConfirmation,
    BranchPreparation,
    HumanAssertion,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct KitRestoreScreenV2 {
    stage: KitRestoreStageV2,
    wallet_id: [u8; 32],
    input_mode: KitInputModeV2,
    action: Option<KitRestoreActionV2>,
    assertion_digit: Option<HumanAssertionDigitV2>,
}

impl KitRestoreScreenV2 {
    #[must_use]
    pub const fn stage(self) -> KitRestoreStageV2 {
        self.stage
    }

    #[must_use]
    pub const fn wallet_id(self) -> [u8; 32] {
        self.wallet_id
    }

    #[must_use]
    pub const fn input_mode(self) -> KitInputModeV2 {
        self.input_mode
    }

    #[must_use]
    pub const fn action(self) -> Option<KitRestoreActionV2> {
        self.action
    }

    #[must_use]
    pub const fn assertion_digit(self) -> Option<HumanAssertionDigitV2> {
        self.assertion_digit
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum KitRestoreInterruptionV2 {
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
pub enum KitRestoreForeignOperationV2 {
    Signing,
    Transaction,
    Review,
    Approval,
    Export,
    Intake,
    GenericWalletOutput,
    KitGeneration,
    KitRegeneration,
    DoorSwitch,
}

/// Exact named HOST rejection surface in precedence order.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum KitRestoreErrorV2 {
    InvalidHumanAssertionDigit,
    WrongDoor,
    InvalidStart,
    RecoveredWalletMismatch,
    InvalidTransition,
    ActionSwitchAttempt,
    DoorSwitchAttempt,
    RestoreModeMismatch,
    TransactionProhibited,
    ReviewProhibited,
    ApprovalProhibited,
    ExportProhibited,
    ForeignInputProhibited,
    GenericWalletOutputProhibited,
    KitGenerationProhibited,
    MissingCardRequiresKitSpend,
    HumanAssertionMismatch,
    SurvivingA1Mismatch,
    SurvivingBFactorMismatch,
    A1PrintRejected,
    A1VerificationMismatch,
    ReplacementBRejected,
    SigningProhibited,
    KitRegenerationProhibited,
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

impl KitRestoreErrorV2 {
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::InvalidHumanAssertionDigit => "InvalidHumanAssertionDigit",
            Self::WrongDoor => "WrongDoor",
            Self::InvalidStart => "InvalidStart",
            Self::RecoveredWalletMismatch => "RecoveredWalletMismatch",
            Self::InvalidTransition => "InvalidTransition",
            Self::ActionSwitchAttempt => "ActionSwitchAttempt",
            Self::DoorSwitchAttempt => "DoorSwitchAttempt",
            Self::RestoreModeMismatch => "RestoreModeMismatch",
            Self::TransactionProhibited => "TransactionProhibited",
            Self::ReviewProhibited => "ReviewProhibited",
            Self::ApprovalProhibited => "ApprovalProhibited",
            Self::ExportProhibited => "ExportProhibited",
            Self::ForeignInputProhibited => "ForeignInputProhibited",
            Self::GenericWalletOutputProhibited => "GenericWalletOutputProhibited",
            Self::KitGenerationProhibited => "KitGenerationProhibited",
            Self::MissingCardRequiresKitSpend => "MissingCardRequiresKitSpend",
            Self::HumanAssertionMismatch => "HumanAssertionMismatch",
            Self::SurvivingA1Mismatch => "SurvivingA1Mismatch",
            Self::SurvivingBFactorMismatch => "SurvivingBFactorMismatch",
            Self::A1PrintRejected => "A1PrintRejected",
            Self::A1VerificationMismatch => "A1VerificationMismatch",
            Self::ReplacementBRejected => "ReplacementBRejected",
            Self::SigningProhibited => "SigningProhibited",
            Self::KitRegenerationProhibited => "KitRegenerationProhibited",
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

impl fmt::Display for KitRestoreErrorV2 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.name())
    }
}

impl std::error::Error for KitRestoreErrorV2 {}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum MandatoryFreshWalletMigrationV2 {
    Required,
}

pub enum KitRestoreArtifactV2 {
    ReplacementB(ReplacementBReceiptV2),
    A1Reprint(A1ReprintReceiptV2),
}

pub struct KitRestoreOutcomeV2 {
    artifact: KitRestoreArtifactV2,
    posture: MandatoryFreshWalletMigrationV2,
}

impl KitRestoreOutcomeV2 {
    #[must_use]
    pub const fn artifact(&self) -> &KitRestoreArtifactV2 {
        &self.artifact
    }

    #[must_use]
    pub const fn posture(&self) -> MandatoryFreshWalletMigrationV2 {
        self.posture
    }
}

/// One non-clonable restore continuation with a fixed digit and action.
pub struct KitRestoreSessionV2 {
    flow: Option<ScreenFlowV2>,
    payload: Option<BoundKitRestoreV2>,
    prepared_replacement: Option<PreparedReplacementBV2>,
    prepared_a1: Option<PreparedA1ReprintV2>,
    mode: KitInputModeV2,
    wallet_id: [u8; 32],
    identities: [KitFrameIdentityV2; 2],
    assertion_digit: HumanAssertionDigitV2,
    action: Option<KitRestoreActionV2>,
    stage: KitRestoreStageV2,
    failed: Option<KitRestoreErrorV2>,
    active: bool,
}

impl KitRestoreSessionV2 {
    pub fn begin(
        ready: KitIntakeReadyV2,
        descriptors: &[[u8; 306]; 2],
        assertion_digit: HumanAssertionDigitV2,
    ) -> Result<Self, KitRestoreErrorV2> {
        let mut parts = ready.into_restore_parts();
        if parts.door != KitDoorV2::KitRestore {
            parts
                .flow
                .terminate_kit_restore(WipingReasonV2::DoorSwitchAttempt);
            return Err(KitRestoreErrorV2::WrongDoor);
        }
        if parts.next_screen != ScreenKindV2::KitRestoreActionSelection
            || parts.flow.screen_kind() != Some(ScreenKindV2::KitRestoreActionSelection)
        {
            parts
                .flow
                .terminate_kit_restore(WipingReasonV2::InvalidTransition);
            return Err(KitRestoreErrorV2::InvalidStart);
        }
        let payload = parts
            .payload
            .bind_restore_v2(descriptors, &parts.wallet_id)
            .map_err(|_| {
                parts
                    .flow
                    .terminate_kit_restore(WipingReasonV2::OperationFailed);
                KitRestoreErrorV2::RecoveredWalletMismatch
            })?;
        Ok(Self {
            flow: Some(parts.flow),
            payload: Some(payload),
            prepared_replacement: None,
            prepared_a1: None,
            mode: parts.mode,
            wallet_id: parts.wallet_id,
            identities: parts.identities,
            assertion_digit,
            action: None,
            stage: KitRestoreStageV2::ActionSelection,
            failed: None,
            active: true,
        })
    }

    #[must_use]
    pub fn screen(&self) -> Option<KitRestoreScreenV2> {
        self.active.then_some(KitRestoreScreenV2 {
            stage: self.stage,
            wallet_id: self.wallet_id,
            input_mode: self.mode,
            action: self.action,
            assertion_digit: (self.stage == KitRestoreStageV2::HumanAssertion)
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
    pub const fn failure(&self) -> Option<KitRestoreErrorV2> {
        self.failed
    }

    pub fn select_action(
        &mut self,
        action: KitRestoreActionV2,
    ) -> Result<KitRestoreScreenV2, KitRestoreErrorV2> {
        if !self.active {
            return Err(KitRestoreErrorV2::Finished);
        }
        if self.action.is_some() || self.stage != KitRestoreStageV2::ActionSelection {
            return Err(self.fail(
                KitRestoreErrorV2::ActionSwitchAttempt,
                WipingReasonV2::DoorSwitchAttempt,
            ));
        }
        if !self
            .flow
            .as_mut()
            .is_some_and(|flow| flow.select_kit_restore_action_semantic(action))
        {
            return Err(self.fail(
                KitRestoreErrorV2::InvalidTransition,
                WipingReasonV2::InvalidTransition,
            ));
        }
        self.action = Some(action);
        self.stage = match action {
            KitRestoreActionV2::ReplacementB => KitRestoreStageV2::CardRemainsConfirmation,
            KitRestoreActionV2::A1Reprint => KitRestoreStageV2::BranchPreparation,
        };
        self.screen().ok_or(KitRestoreErrorV2::InvalidTransition)
    }

    pub fn confirm_card_remains(
        &mut self,
        statement: CardRemainsStatementV2,
    ) -> Result<KitRestoreScreenV2, KitRestoreErrorV2> {
        if !self.active {
            return Err(KitRestoreErrorV2::Finished);
        }
        if self.stage != KitRestoreStageV2::CardRemainsConfirmation
            || self.action != Some(KitRestoreActionV2::ReplacementB)
        {
            return Err(self.fail(
                KitRestoreErrorV2::RestoreModeMismatch,
                WipingReasonV2::InvalidTransition,
            ));
        }
        if !self
            .flow
            .as_mut()
            .is_some_and(|flow| flow.confirm_kit_restore_card_remains_semantic(statement))
        {
            return Err(self.fail(
                KitRestoreErrorV2::InvalidTransition,
                WipingReasonV2::InvalidTransition,
            ));
        }
        if statement == CardRemainsStatementV2::Missing {
            self.payload.take();
            self.failed = Some(KitRestoreErrorV2::MissingCardRequiresKitSpend);
            self.active = false;
            return Err(KitRestoreErrorV2::MissingCardRequiresKitSpend);
        }
        self.stage = KitRestoreStageV2::BranchPreparation;
        self.screen().ok_or(KitRestoreErrorV2::InvalidTransition)
    }

    /// Authenticate the surviving old A1 before exposing the assertion digit.
    pub fn prepare_replacement_b(
        &mut self,
        surviving_a1: &mut [u8; A1_CAPSULE_BYTES],
    ) -> Result<KitRestoreScreenV2, KitRestoreErrorV2> {
        let guard = CallerBufferGuard {
            bytes: surviving_a1,
        };
        self.require_preparation(KitRestoreActionV2::ReplacementB)?;
        let payload = self.take_payload()?;
        let prepared = match payload.prepare_replacement_b(guard.as_array()) {
            Ok(prepared) => prepared,
            Err(error) => return Err(self.fail_math(error)),
        };
        self.prepared_replacement = Some(prepared);
        self.stage = KitRestoreStageV2::HumanAssertion;
        self.screen().ok_or(KitRestoreErrorV2::InvalidTransition)
    }

    /// Bind the surviving B factor and caller nonce before exposing the digit.
    pub fn prepare_a1_reprint(
        &mut self,
        surviving_b: SurvivingBFactorV2,
        nonce: &[u8; 12],
    ) -> Result<KitRestoreScreenV2, KitRestoreErrorV2> {
        self.require_preparation(KitRestoreActionV2::A1Reprint)?;
        let payload = self.take_payload()?;
        let prepared = match payload.prepare_a1_reprint(surviving_b, nonce) {
            Ok(prepared) => prepared,
            Err(error) => return Err(self.fail_math(error)),
        };
        self.prepared_a1 = Some(prepared);
        self.stage = KitRestoreStageV2::HumanAssertion;
        self.screen().ok_or(KitRestoreErrorV2::InvalidTransition)
    }

    pub fn execute_replacement_b<F>(
        mut self,
        key: KeypadKey,
        sink: F,
    ) -> Result<KitRestoreOutcomeV2, KitRestoreErrorV2>
    where
        F: for<'view> FnOnce(ReplacementBViewV2<'view>) -> KitRestoreDispositionV2,
    {
        self.require_action(KitRestoreActionV2::ReplacementB)?;
        self.authorize_digit(key)?;
        let prepared = self.prepared_replacement.take().ok_or_else(|| {
            self.fail(
                KitRestoreErrorV2::InvalidTransition,
                WipingReasonV2::InvalidTransition,
            )
        })?;
        let receipt = match prepared.complete(sink) {
            Ok(receipt) => receipt,
            Err(error) => return Err(self.fail_math(error)),
        };
        self.finish()?;
        Ok(KitRestoreOutcomeV2 {
            artifact: KitRestoreArtifactV2::ReplacementB(receipt),
            posture: MandatoryFreshWalletMigrationV2::Required,
        })
    }

    pub fn execute_a1_reprint<F>(
        mut self,
        key: KeypadKey,
        sink: F,
    ) -> Result<KitRestoreOutcomeV2, KitRestoreErrorV2>
    where
        F: for<'view> FnOnce(
            A1ReprintViewV2<'view>,
            &'view mut [u8; A1_CAPSULE_BYTES],
        ) -> A1ReprintDispositionV2,
    {
        self.require_action(KitRestoreActionV2::A1Reprint)?;
        self.authorize_digit(key)?;
        let prepared = self.prepared_a1.take().ok_or_else(|| {
            self.fail(
                KitRestoreErrorV2::InvalidTransition,
                WipingReasonV2::InvalidTransition,
            )
        })?;
        let receipt = match prepared.complete(sink) {
            Ok(receipt) => receipt,
            Err(error) => return Err(self.fail_math(error)),
        };
        self.finish()?;
        Ok(KitRestoreOutcomeV2 {
            artifact: KitRestoreArtifactV2::A1Reprint(receipt),
            posture: MandatoryFreshWalletMigrationV2::Required,
        })
    }

    pub fn reject_foreign_operation(
        &mut self,
        operation: KitRestoreForeignOperationV2,
    ) -> Result<KitRestoreScreenV2, KitRestoreErrorV2> {
        if !self.active {
            return Err(KitRestoreErrorV2::Finished);
        }
        let (error, reason) = match operation {
            KitRestoreForeignOperationV2::Signing => (
                KitRestoreErrorV2::SigningProhibited,
                WipingReasonV2::RestoreSigningProhibited,
            ),
            KitRestoreForeignOperationV2::Transaction => (
                KitRestoreErrorV2::TransactionProhibited,
                WipingReasonV2::OperationFailed,
            ),
            KitRestoreForeignOperationV2::Review => (
                KitRestoreErrorV2::ReviewProhibited,
                WipingReasonV2::OperationFailed,
            ),
            KitRestoreForeignOperationV2::Approval => (
                KitRestoreErrorV2::ApprovalProhibited,
                WipingReasonV2::OperationFailed,
            ),
            KitRestoreForeignOperationV2::Export => (
                KitRestoreErrorV2::ExportProhibited,
                WipingReasonV2::OperationFailed,
            ),
            KitRestoreForeignOperationV2::Intake => (
                KitRestoreErrorV2::ForeignInputProhibited,
                WipingReasonV2::KitScannerModeMismatch,
            ),
            KitRestoreForeignOperationV2::GenericWalletOutput => (
                KitRestoreErrorV2::GenericWalletOutputProhibited,
                WipingReasonV2::OperationFailed,
            ),
            KitRestoreForeignOperationV2::KitGeneration => (
                KitRestoreErrorV2::KitGenerationProhibited,
                WipingReasonV2::OperationFailed,
            ),
            KitRestoreForeignOperationV2::KitRegeneration => (
                KitRestoreErrorV2::KitRegenerationProhibited,
                WipingReasonV2::OperationFailed,
            ),
            KitRestoreForeignOperationV2::DoorSwitch => (
                KitRestoreErrorV2::DoorSwitchAttempt,
                WipingReasonV2::DoorSwitchAttempt,
            ),
        };
        Err(self.fail(error, reason))
    }

    pub fn interrupt(
        &mut self,
        interruption: KitRestoreInterruptionV2,
    ) -> Result<KitRestoreScreenV2, KitRestoreErrorV2> {
        if !self.active {
            return Err(KitRestoreErrorV2::Finished);
        }
        let (error, reason) = match interruption {
            KitRestoreInterruptionV2::Cancelled => {
                (KitRestoreErrorV2::Cancelled, WipingReasonV2::Cancelled)
            }
            KitRestoreInterruptionV2::OperationFailed => (
                KitRestoreErrorV2::OperationFailed,
                WipingReasonV2::OperationFailed,
            ),
            KitRestoreInterruptionV2::MediaRemoved => (
                KitRestoreErrorV2::MediaRemoved,
                WipingReasonV2::MediaRemoved,
            ),
            KitRestoreInterruptionV2::CardRemoved => {
                (KitRestoreErrorV2::CardRemoved, WipingReasonV2::CardRemoved)
            }
            KitRestoreInterruptionV2::SessionTimeout => (
                KitRestoreErrorV2::SessionTimeout,
                WipingReasonV2::SessionTimeout,
            ),
            KitRestoreInterruptionV2::Shutdown => {
                (KitRestoreErrorV2::Shutdown, WipingReasonV2::Shutdown)
            }
            KitRestoreInterruptionV2::Restart => {
                (KitRestoreErrorV2::Restart, WipingReasonV2::Restart)
            }
            KitRestoreInterruptionV2::PowerLoss => {
                (KitRestoreErrorV2::PowerLoss, WipingReasonV2::PowerLoss)
            }
        };
        Err(self.fail(error, reason))
    }

    fn require_action(&mut self, expected: KitRestoreActionV2) -> Result<(), KitRestoreErrorV2> {
        if !self.active {
            return Err(KitRestoreErrorV2::Finished);
        }
        if self.stage != KitRestoreStageV2::HumanAssertion || self.action != Some(expected) {
            return Err(self.fail(
                KitRestoreErrorV2::RestoreModeMismatch,
                WipingReasonV2::InvalidTransition,
            ));
        }
        Ok(())
    }

    fn require_preparation(
        &mut self,
        expected: KitRestoreActionV2,
    ) -> Result<(), KitRestoreErrorV2> {
        if !self.active {
            return Err(KitRestoreErrorV2::Finished);
        }
        if self.stage != KitRestoreStageV2::BranchPreparation
            || self.action != Some(expected)
            || self.prepared_replacement.is_some()
            || self.prepared_a1.is_some()
        {
            return Err(self.fail(
                KitRestoreErrorV2::RestoreModeMismatch,
                WipingReasonV2::InvalidTransition,
            ));
        }
        Ok(())
    }

    fn authorize_digit(&mut self, key: KeypadKey) -> Result<(), KitRestoreErrorV2> {
        if key == KeypadKey::CancelBack {
            return Err(self.fail(KitRestoreErrorV2::Cancelled, WipingReasonV2::Cancelled));
        }
        if !self.assertion_digit.matches(key) {
            return Err(self.fail(
                KitRestoreErrorV2::HumanAssertionMismatch,
                WipingReasonV2::OperationFailed,
            ));
        }
        Ok(())
    }

    fn take_payload(&mut self) -> Result<BoundKitRestoreV2, KitRestoreErrorV2> {
        self.payload.take().ok_or_else(|| {
            self.fail(
                KitRestoreErrorV2::InvalidTransition,
                WipingReasonV2::InvalidTransition,
            )
        })
    }

    fn fail_math(&mut self, error: KitMathErrorV2) -> KitRestoreErrorV2 {
        let mapped = match error {
            KitMathErrorV2::RecoveredWalletMismatch => KitRestoreErrorV2::RecoveredWalletMismatch,
            KitMathErrorV2::SurvivingA1Mismatch => KitRestoreErrorV2::SurvivingA1Mismatch,
            KitMathErrorV2::SurvivingBFactorMismatch => KitRestoreErrorV2::SurvivingBFactorMismatch,
            KitMathErrorV2::A1PrintRejected => KitRestoreErrorV2::A1PrintRejected,
            KitMathErrorV2::A1VerificationMismatch => KitRestoreErrorV2::A1VerificationMismatch,
            KitMathErrorV2::ReplacementBRejected => KitRestoreErrorV2::ReplacementBRejected,
        };
        self.fail(mapped, WipingReasonV2::OperationFailed)
    }

    fn finish(&mut self) -> Result<(), KitRestoreErrorV2> {
        if !self
            .flow
            .as_mut()
            .is_some_and(ScreenFlowV2::complete_kit_restore_semantic)
        {
            return Err(self.fail(
                KitRestoreErrorV2::InvalidTransition,
                WipingReasonV2::InvalidTransition,
            ));
        }
        self.active = false;
        Ok(())
    }

    fn fail(&mut self, error: KitRestoreErrorV2, reason: WipingReasonV2) -> KitRestoreErrorV2 {
        self.payload.take();
        self.prepared_replacement.take();
        self.prepared_a1.take();
        if let Some(flow) = self.flow.as_mut() {
            flow.terminate_kit_restore(reason);
        }
        self.failed = Some(error);
        self.active = false;
        error
    }
}

impl Drop for KitRestoreSessionV2 {
    fn drop(&mut self) {
        self.payload.take();
        self.prepared_replacement.take();
        self.prepared_a1.take();
        if self.active {
            if let Some(flow) = self.flow.as_mut() {
                flow.terminate_kit_restore(WipingReasonV2::Cancelled);
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
