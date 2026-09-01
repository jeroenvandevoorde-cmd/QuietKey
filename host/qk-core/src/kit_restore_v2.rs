//! QK-DEC-151 HOST-only Kit-Restore product continuation.
//!
//! This purpose-bound owner consumes only an opaque Kit-Restore intake
//! capability, rebinds the recovered authority to exact caller-authenticated
//! D, admits one non-signing restore action behind the ratified public digit,
//! and ends in mandatory fresh-wallet migration. It contains no transport,
//! general signing, Kit generation, or normal-wallet operation.

use crate::capability::{CoreScreen, KeypadKey};
use crate::error::Interruption;
use crate::io_wire::Source;
use crate::kit_intake_v2::{KitFrameIdentityV2, KitInputModeV2, KitIntakeReadyV2};
use crate::session::{CoreSession, HostileIngress};
use crate::wipe::WipingArray;
use core::fmt;
use qk_descriptor::parse_descriptor_pair_v2;
use qk_kit::{
    A1ReprintReceiptV2, BoundKitRestoreV2, KitRestoreDispositionV2,
    KitRestoreErrorV2 as KitMathErrorV2, PreparedA1ReprintV2, PreparedReplacementBV2,
    ReplacementBReceiptV2, ReplacementBViewV2, StagedA1ReprintV2, SurvivingBFactorV2,
};

const A1_CAPSULE_BYTES: usize = 67;

/// One public decimal digit named by the existing assertion screen.
///
/// The digit is supplied by the caller's already-ratified deterministic
/// construction. Qk-core introduces no randomness and treats the digit as a
/// deliberate human gesture, not authentication entropy.
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

/// Exact one-use restore action.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum KitRestoreActionV2 {
    ReplacementB,
    A1Reprint,
}

/// Exact old-card physical-remains statement.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CardRemainsStatementV2 {
    InHand,
    Missing,
}

/// Exact product-process restore stage order.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum KitRestoreStageV2 {
    ActionSelection,
    CardRemainsConfirmation,
    BranchPreparation,
    HumanAssertion,
}

/// Borrow-free public facts selected by an already-ratified Kit screen.
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

/// Operations that can never be admitted by the restore owner.
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

/// Exact terminating restore rejection vocabulary.
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
    Interrupted(Interruption),
    Finished,
}

impl KitRestoreErrorV2 {
    /// Stable name carrying no hostile or secret bytes.
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
            Self::Interrupted(reason) => reason.name(),
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

/// Exact post-Kit-opening product posture.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum MandatoryFreshWalletMigrationV2 {
    Required,
}

/// One completed, non-secret restore artifact.
pub enum KitRestoreArtifactV2 {
    ReplacementB(ReplacementBReceiptV2),
    A1Reprint(A1ReprintReceiptV2),
}

/// One completed restore result. No normal-wallet capability is returned.
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

/// One non-clonable restore continuation with one fixed action and digit.
pub struct KitRestoreSessionV2 {
    payload: Option<BoundKitRestoreV2>,
    prepared_replacement: Option<PreparedReplacementBV2>,
    prepared_a1: Option<PreparedA1ReprintV2>,
    mode: KitInputModeV2,
    wallet_id: [u8; 32],
    identities: [KitFrameIdentityV2; 2],
    assertion_digit: HumanAssertionDigitV2,
    action: Option<KitRestoreActionV2>,
    stage: KitRestoreStageV2,
    terminal_error: Option<KitRestoreErrorV2>,
    active: bool,
}

impl KitRestoreSessionV2 {
    /// Consume exact Kit-Restore readiness and rebind it to authenticated D.
    pub fn begin(
        core: &mut CoreSession,
        ready: KitIntakeReadyV2,
        descriptors: &[[u8; 306]; 2],
        assertion_digit: HumanAssertionDigitV2,
    ) -> Result<Self, KitRestoreErrorV2> {
        let mut session = match Self::begin_bound(ready, descriptors, assertion_digit) {
            Ok(session) => session,
            Err(error) => {
                core.terminate_kit(Interruption::OperationFailed);
                return Err(error);
            }
        };
        if core
            .kit_show(CoreScreen::KitRestoreActionSelection)
            .is_err()
        {
            return Err(session.fail(KitRestoreErrorV2::Interrupted(
                core.terminal_reason()
                    .unwrap_or(Interruption::CapabilityFailed),
            )));
        }
        Ok(session)
    }

    /// Deterministic semantic constructor reserved for ring-fenced fuzzing.
    #[cfg(feature = "fuzzing")]
    #[doc(hidden)]
    pub fn fuzz_begin(
        ready: KitIntakeReadyV2,
        descriptors: &[[u8; 306]; 2],
        assertion_digit: HumanAssertionDigitV2,
    ) -> Result<Self, KitRestoreErrorV2> {
        Self::begin_bound(ready, descriptors, assertion_digit)
    }

    fn begin_bound(
        ready: KitIntakeReadyV2,
        descriptors: &[[u8; 306]; 2],
        assertion_digit: HumanAssertionDigitV2,
    ) -> Result<Self, KitRestoreErrorV2> {
        let parts = ready.into_restore_parts();
        if parts.door != crate::kit_intake_v2::KitDoorV2::KitRestore {
            return Err(KitRestoreErrorV2::WrongDoor);
        }
        let expected = parse_descriptor_pair_v2(&descriptors[0], &descriptors[1])
            .map_err(|_| KitRestoreErrorV2::RecoveredWalletMismatch)?;
        if expected.wallet_id() != parts.wallet_id {
            return Err(KitRestoreErrorV2::RecoveredWalletMismatch);
        }
        let payload = parts
            .payload
            .bind_restore_v2(descriptors, &parts.wallet_id)
            .map_err(|_| KitRestoreErrorV2::RecoveredWalletMismatch)?;
        Ok(Self {
            payload: Some(payload),
            prepared_replacement: None,
            prepared_a1: None,
            mode: parts.mode,
            wallet_id: parts.wallet_id,
            identities: parts.identities,
            assertion_digit,
            action: None,
            stage: KitRestoreStageV2::ActionSelection,
            terminal_error: None,
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
    pub const fn terminal_error(&self) -> Option<KitRestoreErrorV2> {
        self.terminal_error
    }

    #[must_use]
    pub const fn is_terminal(&self) -> bool {
        !self.active
    }

    /// Fix exactly one restore action.
    pub fn select_action(
        &mut self,
        action: KitRestoreActionV2,
    ) -> Result<KitRestoreScreenV2, KitRestoreErrorV2> {
        self.require_active()?;
        if self.action.is_some() || self.stage != KitRestoreStageV2::ActionSelection {
            return Err(self.fail(KitRestoreErrorV2::ActionSwitchAttempt));
        }
        self.action = Some(action);
        self.stage = match action {
            KitRestoreActionV2::ReplacementB => KitRestoreStageV2::CardRemainsConfirmation,
            KitRestoreActionV2::A1Reprint => KitRestoreStageV2::BranchPreparation,
        };
        self.screen().ok_or(KitRestoreErrorV2::InvalidTransition)
    }

    /// Fix the restore action and select only its ratified typed screen.
    pub fn select_action_in_core(
        &mut self,
        core: &mut CoreSession,
        action: KitRestoreActionV2,
    ) -> Result<KitRestoreScreenV2, KitRestoreErrorV2> {
        let screen = match self.select_action(action) {
            Ok(screen) => screen,
            Err(error) => {
                core.terminate_kit(Interruption::OperationFailed);
                return Err(error);
            }
        };
        let target = match screen.stage() {
            KitRestoreStageV2::CardRemainsConfirmation => CoreScreen::CardRemainsConfirmation,
            KitRestoreStageV2::BranchPreparation => CoreScreen::KitRestorePreparation,
            _ => CoreScreen::KitRestoreActionSelection,
        };
        self.show_in_core(core, target)?;
        Ok(screen)
    }

    /// Record whether the old role-B physical remains are in hand.
    pub fn confirm_card_remains(
        &mut self,
        statement: CardRemainsStatementV2,
    ) -> Result<KitRestoreScreenV2, KitRestoreErrorV2> {
        self.require_active()?;
        if self.stage != KitRestoreStageV2::CardRemainsConfirmation
            || self.action != Some(KitRestoreActionV2::ReplacementB)
        {
            return Err(self.fail(KitRestoreErrorV2::RestoreModeMismatch));
        }
        if statement == CardRemainsStatementV2::Missing {
            return Err(self.fail(KitRestoreErrorV2::MissingCardRequiresKitSpend));
        }
        self.stage = KitRestoreStageV2::BranchPreparation;
        self.screen().ok_or(KitRestoreErrorV2::InvalidTransition)
    }

    /// Read the old-card remains choice through the typed restore process and
    /// expose no card capability or secret material.
    pub fn confirm_card_remains_in_core(
        &mut self,
        core: &mut CoreSession,
        statement: CardRemainsStatementV2,
    ) -> Result<KitRestoreScreenV2, KitRestoreErrorV2> {
        let screen = match self.confirm_card_remains(statement) {
            Ok(screen) => screen,
            Err(error) => {
                core.terminate_kit(Interruption::OperationFailed);
                return Err(error);
            }
        };
        self.show_in_core(core, CoreScreen::KitRestorePreparation)?;
        Ok(screen)
    }

    /// Authenticate surviving A1 before the assertion digit is exposed.
    ///
    /// The caller's capsule is taken into a fixed owner and cleared even when
    /// the session is in the wrong state or the leaf rejects it.
    pub fn prepare_replacement_b(
        &mut self,
        surviving_a1: &mut [u8; A1_CAPSULE_BYTES],
    ) -> Result<KitRestoreScreenV2, KitRestoreErrorV2> {
        let surviving_a1 = WipingArray::take(surviving_a1);
        self.require_preparation(KitRestoreActionV2::ReplacementB)?;
        let payload = self.take_payload()?;
        let prepared = match payload.prepare_replacement_b(surviving_a1.as_array()) {
            Ok(prepared) => prepared,
            Err(error) => return Err(self.fail_math(error)),
        };
        self.prepared_replacement = Some(prepared);
        self.stage = KitRestoreStageV2::HumanAssertion;
        self.screen().ok_or(KitRestoreErrorV2::InvalidTransition)
    }

    /// Consume one exact surviving-A1 camera ingress before replacement-B
    /// preparation. Foreign sources and non-canonical widths terminate the
    /// purpose owner, and every transport or scratch byte is cleared.
    pub fn prepare_replacement_b_ingress(
        &mut self,
        ingress: HostileIngress,
    ) -> Result<KitRestoreScreenV2, KitRestoreErrorV2> {
        let (source, bytes) = ingress.into_kit_parts();
        if source != Source::CameraA1Candidate {
            drop(bytes);
            return Err(self.fail(KitRestoreErrorV2::ForeignInputProhibited));
        }
        if bytes.len() != A1_CAPSULE_BYTES {
            drop(bytes);
            return Err(self.fail(KitRestoreErrorV2::SurvivingA1Mismatch));
        }
        let mut capsule = WipingArray::<A1_CAPSULE_BYTES>::zeroed();
        capsule.as_mut_array().copy_from_slice(bytes.as_slice());
        drop(bytes);
        self.prepare_replacement_b(capsule.as_mut_array())
    }

    /// Consume one completed surviving-A1 transfer retained by qk-core and
    /// advance directly to the existing human-assertion screen.
    pub fn prepare_replacement_b_from_core(
        &mut self,
        core: &mut CoreSession,
    ) -> Result<KitRestoreScreenV2, KitRestoreErrorV2> {
        let ingress = match core.take_kit_ingress() {
            Ok(ingress) => ingress,
            Err(_) => {
                return Err(self.fail(KitRestoreErrorV2::Interrupted(
                    core.terminal_reason()
                        .unwrap_or(Interruption::OperationFailed),
                )))
            }
        };
        let screen = match self.prepare_replacement_b_ingress(ingress) {
            Ok(screen) => screen,
            Err(error) => {
                core.terminate_kit(Interruption::OperationFailed);
                return Err(error);
            }
        };
        self.show_in_core(core, CoreScreen::KitRestoreHumanAssertion)?;
        Ok(screen)
    }

    /// Authenticate surviving B and bind the fresh caller nonce before the
    /// assertion digit is exposed.
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

    /// Stage the A1 reprint branch and select the existing assertion screen.
    pub fn prepare_a1_reprint_in_core(
        &mut self,
        core: &mut CoreSession,
        surviving_b: SurvivingBFactorV2,
        nonce: &[u8; 12],
    ) -> Result<KitRestoreScreenV2, KitRestoreErrorV2> {
        let screen = match self.prepare_a1_reprint(surviving_b, nonce) {
            Ok(screen) => screen,
            Err(error) => {
                core.terminate_kit(Interruption::OperationFailed);
                return Err(error);
            }
        };
        self.show_in_core(core, CoreScreen::KitRestoreHumanAssertion)?;
        Ok(screen)
    }

    /// Authorize and consume exactly one public-facts-only replacement call.
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
        let prepared = self
            .prepared_replacement
            .take()
            .ok_or_else(|| self.fail(KitRestoreErrorV2::InvalidTransition))?;
        let receipt = match prepared.complete(sink) {
            Ok(receipt) => receipt,
            Err(error) => return Err(self.fail_math(error)),
        };
        self.active = false;
        Ok(KitRestoreOutcomeV2 {
            artifact: KitRestoreArtifactV2::ReplacementB(receipt),
            posture: MandatoryFreshWalletMigrationV2::Required,
        })
    }

    /// Read the assertion digit through qk-core and invoke exactly its one-use
    /// public-facts-only replacement-B mock boundary.
    pub fn execute_replacement_b_in_core(
        mut self,
        core: &mut CoreSession,
        key: KeypadKey,
    ) -> Result<KitRestoreOutcomeV2, KitRestoreErrorV2> {
        let key = match core.kit_read_key(key) {
            Ok(key) => key,
            Err(_) => {
                return Err(self.fail(KitRestoreErrorV2::Interrupted(
                    core.terminal_reason()
                        .unwrap_or(Interruption::CapabilityFailed),
                )))
            }
        };
        let outcome = match self.execute_replacement_b(key, |view| core.kit_replace_b(view)) {
            Ok(outcome) => outcome,
            Err(error) => {
                core.terminate_kit(match error {
                    KitRestoreErrorV2::Interrupted(reason) => reason,
                    _ => Interruption::OperationFailed,
                });
                return Err(error);
            }
        };
        if core
            .kit_show(CoreScreen::MandatoryFreshWalletMigration)
            .is_err()
        {
            return Err(KitRestoreErrorV2::Interrupted(
                core.terminal_reason()
                    .unwrap_or(Interruption::CapabilityFailed),
            ));
        }
        Ok(outcome)
    }

    /// Authorize the exact staged A1 print boundary.
    ///
    /// The returned owner lends the capsule only for the frozen process print
    /// transport and consumes one exact hostile scan-back. No retry or second
    /// action remains after this consuming transition.
    pub fn begin_a1_reprint(
        mut self,
        key: KeypadKey,
    ) -> Result<AuthorizedA1ReprintV2, KitRestoreErrorV2> {
        self.require_action(KitRestoreActionV2::A1Reprint)?;
        self.authorize_digit(key)?;
        let prepared = self
            .prepared_a1
            .take()
            .ok_or_else(|| self.fail(KitRestoreErrorV2::InvalidTransition))?;
        self.active = false;
        Ok(AuthorizedA1ReprintV2 {
            staged: Some(prepared.into_staged()),
        })
    }

    /// Read the assertion digit through qk-core and stage the sole A1 reprint
    /// without exposing the keypad capability.
    pub fn begin_a1_reprint_in_core(
        mut self,
        core: &mut CoreSession,
        key: KeypadKey,
    ) -> Result<AuthorizedA1ReprintV2, KitRestoreErrorV2> {
        let key = match core.kit_read_key(key) {
            Ok(key) => key,
            Err(_) => {
                return Err(self.fail(KitRestoreErrorV2::Interrupted(
                    core.terminal_reason()
                        .unwrap_or(Interruption::CapabilityFailed),
                )))
            }
        };
        let staged = match self.begin_a1_reprint(key) {
            Ok(staged) => staged,
            Err(error) => {
                core.terminate_kit(match error {
                    KitRestoreErrorV2::Interrupted(reason) => reason,
                    _ => Interruption::OperationFailed,
                });
                return Err(error);
            }
        };
        if core.kit_show(CoreScreen::A1Reprint).is_err() {
            return Err(KitRestoreErrorV2::Interrupted(
                core.terminal_reason()
                    .unwrap_or(Interruption::CapabilityFailed),
            ));
        }
        Ok(staged)
    }

    /// Terminate on an operation outside the one fixed restore action.
    pub fn reject_foreign_operation(
        &mut self,
        operation: KitRestoreForeignOperationV2,
    ) -> Result<KitRestoreScreenV2, KitRestoreErrorV2> {
        self.require_active()?;
        let error = match operation {
            KitRestoreForeignOperationV2::Signing => KitRestoreErrorV2::SigningProhibited,
            KitRestoreForeignOperationV2::Transaction => KitRestoreErrorV2::TransactionProhibited,
            KitRestoreForeignOperationV2::Review => KitRestoreErrorV2::ReviewProhibited,
            KitRestoreForeignOperationV2::Approval => KitRestoreErrorV2::ApprovalProhibited,
            KitRestoreForeignOperationV2::Export => KitRestoreErrorV2::ExportProhibited,
            KitRestoreForeignOperationV2::Intake => KitRestoreErrorV2::ForeignInputProhibited,
            KitRestoreForeignOperationV2::GenericWalletOutput => {
                KitRestoreErrorV2::GenericWalletOutputProhibited
            }
            KitRestoreForeignOperationV2::KitGeneration => {
                KitRestoreErrorV2::KitGenerationProhibited
            }
            KitRestoreForeignOperationV2::KitRegeneration => {
                KitRestoreErrorV2::KitRegenerationProhibited
            }
            KitRestoreForeignOperationV2::DoorSwitch => KitRestoreErrorV2::DoorSwitchAttempt,
        };
        Err(self.fail(error))
    }

    /// Route one closed shell interruption into the absorbing terminal state.
    pub fn interrupt(
        &mut self,
        reason: Interruption,
    ) -> Result<KitRestoreScreenV2, KitRestoreErrorV2> {
        self.require_active()?;
        Err(self.fail(KitRestoreErrorV2::Interrupted(reason)))
    }

    fn require_active(&self) -> Result<(), KitRestoreErrorV2> {
        self.active.then_some(()).ok_or(KitRestoreErrorV2::Finished)
    }

    fn show_in_core(
        &mut self,
        core: &mut CoreSession,
        screen: CoreScreen,
    ) -> Result<(), KitRestoreErrorV2> {
        if core.kit_show(screen).is_err() {
            return Err(self.fail(KitRestoreErrorV2::Interrupted(
                core.terminal_reason()
                    .unwrap_or(Interruption::CapabilityFailed),
            )));
        }
        Ok(())
    }

    fn require_action(&mut self, expected: KitRestoreActionV2) -> Result<(), KitRestoreErrorV2> {
        self.require_active()?;
        if self.stage != KitRestoreStageV2::HumanAssertion || self.action != Some(expected) {
            return Err(self.fail(KitRestoreErrorV2::RestoreModeMismatch));
        }
        Ok(())
    }

    fn require_preparation(
        &mut self,
        expected: KitRestoreActionV2,
    ) -> Result<(), KitRestoreErrorV2> {
        self.require_active()?;
        if self.stage != KitRestoreStageV2::BranchPreparation
            || self.action != Some(expected)
            || self.prepared_replacement.is_some()
            || self.prepared_a1.is_some()
        {
            return Err(self.fail(KitRestoreErrorV2::RestoreModeMismatch));
        }
        Ok(())
    }

    fn authorize_digit(&mut self, key: KeypadKey) -> Result<(), KitRestoreErrorV2> {
        if key == KeypadKey::CancelBack {
            return Err(self.fail(KitRestoreErrorV2::Interrupted(Interruption::Cancelled)));
        }
        if !self.assertion_digit.matches(key) {
            return Err(self.fail(KitRestoreErrorV2::HumanAssertionMismatch));
        }
        Ok(())
    }

    fn take_payload(&mut self) -> Result<BoundKitRestoreV2, KitRestoreErrorV2> {
        self.payload
            .take()
            .ok_or_else(|| self.fail(KitRestoreErrorV2::InvalidTransition))
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
        self.fail(mapped)
    }

    fn fail(&mut self, error: KitRestoreErrorV2) -> KitRestoreErrorV2 {
        self.payload.take();
        self.prepared_replacement.take();
        self.prepared_a1.take();
        self.terminal_error = Some(error);
        self.active = false;
        error
    }
}

impl Drop for KitRestoreSessionV2 {
    fn drop(&mut self) {
        self.payload.take();
        self.prepared_replacement.take();
        self.prepared_a1.take();
        self.active = false;
    }
}

/// One authorized, one-use process adapter for A1 print and scan-back.
pub struct AuthorizedA1ReprintV2 {
    staged: Option<StagedA1ReprintV2>,
}

impl AuthorizedA1ReprintV2 {
    /// Borrow the exact 67-byte capsule for the frozen print artifact.
    #[must_use]
    pub fn capsule(&self) -> Option<&[u8; A1_CAPSULE_BYTES]> {
        self.staged.as_ref().map(StagedA1ReprintV2::capsule)
    }

    /// Consume one exact scan-back through byte equality and A1 authentication.
    pub fn complete_scan_back(
        mut self,
        scan_back: &mut [u8; A1_CAPSULE_BYTES],
    ) -> Result<KitRestoreOutcomeV2, KitRestoreErrorV2> {
        let staged = self.staged.take().ok_or(KitRestoreErrorV2::Finished)?;
        let receipt = staged
            .complete_scan_back(scan_back)
            .map_err(map_math_error)?;
        Ok(KitRestoreOutcomeV2 {
            artifact: KitRestoreArtifactV2::A1Reprint(receipt),
            posture: MandatoryFreshWalletMigrationV2::Required,
        })
    }

    /// Consume one exact A1-camera scan-back without exposing transport bytes.
    /// A foreign source or non-canonical width consumes the staged owner and
    /// returns its closest ratified named rejection.
    pub fn complete_scan_back_ingress(
        self,
        ingress: HostileIngress,
    ) -> Result<KitRestoreOutcomeV2, KitRestoreErrorV2> {
        let (source, bytes) = ingress.into_kit_parts();
        if source != Source::CameraA1Candidate {
            drop(bytes);
            return Err(KitRestoreErrorV2::ForeignInputProhibited);
        }
        if bytes.len() != A1_CAPSULE_BYTES {
            drop(bytes);
            return Err(KitRestoreErrorV2::A1VerificationMismatch);
        }
        let mut scan_back = WipingArray::<A1_CAPSULE_BYTES>::zeroed();
        scan_back.as_mut_array().copy_from_slice(bytes.as_slice());
        drop(bytes);
        self.complete_scan_back(scan_back.as_mut_array())
    }

    /// Consume and clear the staged owner after a named print-boundary failure.
    pub fn reject_print(mut self) -> KitRestoreErrorV2 {
        self.staged.take();
        KitRestoreErrorV2::A1PrintRejected
    }
}

fn map_math_error(error: KitMathErrorV2) -> KitRestoreErrorV2 {
    match error {
        KitMathErrorV2::RecoveredWalletMismatch => KitRestoreErrorV2::RecoveredWalletMismatch,
        KitMathErrorV2::SurvivingA1Mismatch => KitRestoreErrorV2::SurvivingA1Mismatch,
        KitMathErrorV2::SurvivingBFactorMismatch => KitRestoreErrorV2::SurvivingBFactorMismatch,
        KitMathErrorV2::A1PrintRejected => KitRestoreErrorV2::A1PrintRejected,
        KitMathErrorV2::A1VerificationMismatch => KitRestoreErrorV2::A1VerificationMismatch,
        KitMathErrorV2::ReplacementBRejected => KitRestoreErrorV2::ReplacementBRejected,
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
