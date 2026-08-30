//! V2 public-surface and migration fences through slice 11.

use qk_host_sim::{
    ApprovalIdentityV2, CardRemainsStatementV2, CeremonyPurposeV2, DeferredBoundaryV2,
    EntropyInputModeV2, FlowEventV2, FlowKindV2, FlowTerminalV2, HumanAssertionDigitV2, KitDoorV2,
    KitFallbackProgressV2, KitForeignInputV2, KitFrameIdentityV2, KitInputModeV2, KitIntakeErrorV2,
    KitIntakeInterruptionV2, KitIntakeOutcomeV2, KitIntakeReadyV2, KitIntakeScreenV2,
    KitIntakeSessionV2, KitRestoreActionV2, KitRestoreArtifactV2, KitRestoreErrorV2,
    KitRestoreForeignOperationV2, KitRestoreInterruptionV2, KitRestoreOutcomeV2,
    KitRestoreScreenV2, KitRestoreSessionV2, KitRestoreStageV2, KitShareOrdinalV2,
    KitSpendAssertionDigitV2, KitSpendErrorV2, KitSpendForeignOperationV2, KitSpendInterruptionV2,
    KitSpendOutcomeV2, KitSpendScreenV2, KitSpendSessionV2, KitSpendStageV2,
    MandatoryFreshWalletMigrationV2, ManualKeypadErrorV2, ManualKeypadEventV2,
    ManualKeypadOutcomeV2, ManualKeypadScreenV2, ManualKeypadSessionV2, ScreenFlowV2, ScreenKindV2,
    ScreenV2, SpareBChoiceV2, StatePreservingRejectionV2, WipingReasonV2,
};

const LIB: &str = include_str!("../src/lib.rs");
const SCREEN: &str = include_str!("../src/screen_flow_v2.rs");
const MANUAL: &str = include_str!("../src/manual_keypad_v2.rs");
const KIT_INTAKE: &str = include_str!("../src/kit_intake_v2.rs");
const KIT_RESTORE: &str = include_str!("../src/kit_restore_v2.rs");
const KIT_SPEND: &str = include_str!("../src/kit_spend_v2.rs");

#[test]
fn v2_surface_is_parallel_and_contains_no_third_role_or_v1_fixture() {
    assert!(LIB.contains("pub mod screen_flow_v2;"));
    assert!(LIB.contains("mod manual_keypad_v2;"));
    for forbidden in [
        "SignerC",
        "Signer C",
        "CardC",
        "Card C",
        "RecoveryA1C",
        "RecoveryBC",
        "ProvisionC",
        "VerifyC",
        "m25_export.txt",
    ] {
        assert!(!SCREEN.contains(forbidden), "screen fence: {forbidden}");
        assert!(!MANUAL.contains(forbidden), "manual fence: {forbidden}");
    }
    assert!(!SCREEN.contains("include_str!("));
    assert!(!MANUAL.contains("include_str!("));
}

#[test]
fn exact_closed_screen_vocabulary_is_exhaustively_named() {
    let screens = [
        ScreenKindV2::SetupStart,
        ScreenKindV2::TierSelection,
        ScreenKindV2::EntropyModeSelection,
        ScreenKindV2::CeremonyInput,
        ScreenKindV2::CeremonyEcho,
        ScreenKindV2::CeremonyConfirm,
        ScreenKindV2::CeremonyCommitment,
        ScreenKindV2::DerivationExplanation,
        ScreenKindV2::ProvisioningResult,
        ScreenKindV2::ProvisionB,
        ScreenKindV2::VerifyB,
        ScreenKindV2::SpareBSelection,
        ScreenKindV2::ProvisionSpareB,
        ScreenKindV2::VerifySpareB,
        ScreenKindV2::CreateA1,
        ScreenKindV2::ScanBackA1,
        ScreenKindV2::CoordinatorMaterial,
        ScreenKindV2::CreateTwoKits,
        ScreenKindV2::VerifyTwoKits,
        ScreenKindV2::Rehearsal,
        ScreenKindV2::SetupReady,
        ScreenKindV2::NormalStart,
        ScreenKindV2::Transport,
        ScreenKindV2::Intake,
        ScreenKindV2::FactorB,
        ScreenKindV2::FactorA1,
        ScreenKindV2::Validation,
        ScreenKindV2::ReviewOverview,
        ScreenKindV2::ReviewArithmetic,
        ScreenKindV2::ReviewRecipient,
        ScreenKindV2::ReviewChange,
        ScreenKindV2::ReviewOpReturn,
        ScreenKindV2::ReviewLocktime,
        ScreenKindV2::ReviewSequence,
        ScreenKindV2::ReviewFeePolicy,
        ScreenKindV2::FinalApproval,
        ScreenKindV2::AwaitingSigning,
        ScreenKindV2::Export,
        ScreenKindV2::TransactionResult,
        ScreenKindV2::KitStart,
        ScreenKindV2::KitDoorSelection,
        ScreenKindV2::KitDoorConfirmation,
        ScreenKindV2::ScanKitShareOne,
        ScreenKindV2::ScanKitShareTwo,
        ScreenKindV2::CombineKitShares,
        ScreenKindV2::KitSpendTransaction,
        ScreenKindV2::KitSpendValidation,
        ScreenKindV2::KitSpendCompleteness,
        ScreenKindV2::KitSpendDeferred,
        ScreenKindV2::KitRestoreActionSelection,
        ScreenKindV2::CardRemainsConfirmation,
        ScreenKindV2::KitRestoreDeferred,
    ];
    assert_eq!(screens.len(), 52);
    for (index, left) in screens.iter().enumerate() {
        assert!(!screens[..index].contains(left), "duplicate screen kind");
    }
}

#[test]
fn secret_and_approval_owners_expose_no_clone_debug_or_owned_fact_escape() {
    for forbidden in [
        "derive(Clone)\npub struct ScreenFlowV2",
        "derive(Debug)\npub struct ScreenFlowV2",
        "derive(Clone)\npub struct ManualKeypadSessionV2",
        "derive(Debug)\npub struct ManualKeypadSessionV2",
        "derive(Clone)\npub struct KitIntakeSessionV2",
        "derive(Debug)\npub struct KitIntakeSessionV2",
        "derive(Clone)\npub struct KitIntakeReadyV2",
        "derive(Debug)\npub struct KitIntakeReadyV2",
        "derive(Clone)\npub struct KitRestoreSessionV2",
        "derive(Debug)\npub struct KitRestoreSessionV2",
        "derive(Clone)\npub struct KitSpendSessionV2",
        "derive(Debug)\npub struct KitSpendSessionV2",
        "pub fn transcript(",
        "pub fn transcripts(",
        "pub fn secret(",
        "pub fn signing_key(",
        "pub fn review(&self)",
        "pub fn export(&self)",
        "pub fn payload(",
        "pub fn recovered(",
        "pub fn frame(&self)",
        "pub fn flow(&self)",
    ] {
        assert!(!SCREEN.contains(forbidden), "screen escape: {forbidden}");
        assert!(!MANUAL.contains(forbidden), "manual escape: {forbidden}");
        assert!(!KIT_INTAKE.contains(forbidden), "Kit escape: {forbidden}");
        assert!(
            !KIT_RESTORE.contains(forbidden),
            "Kit-Restore escape: {forbidden}"
        );
        assert!(
            !KIT_SPEND.contains(forbidden),
            "Kit-Spend escape: {forbidden}"
        );
    }
    assert!(SCREEN.contains("facts: &'facts ProvisioningArtifactsV2"));
    assert!(SCREEN.contains("ready: &'facts ReviewReadyV3"));
    assert!(SCREEN.contains("_export: &'facts ExportArtifacts"));
}

#[test]
fn intended_public_types_are_available_without_new_capability_types() {
    let _: Option<ScreenFlowV2> = None;
    let _: Option<ScreenV2<'_>> = None;
    let _: Option<FlowEventV2<'_>> = None;
    let _: Option<FlowKindV2> = None;
    let _: Option<FlowTerminalV2> = None;
    let _: Option<ApprovalIdentityV2> = None;
    let _: Option<CeremonyPurposeV2> = None;
    let _: Option<EntropyInputModeV2> = None;
    let _: Option<KitDoorV2> = None;
    let _: Option<KitRestoreActionV2> = None;
    let _: Option<CardRemainsStatementV2> = None;
    let _: Option<SpareBChoiceV2> = None;
    let _: Option<DeferredBoundaryV2> = None;
    let _: Option<StatePreservingRejectionV2> = None;
    let _: Option<WipingReasonV2> = None;
    let _: Option<ManualKeypadSessionV2> = None;
    let _: Option<ManualKeypadEventV2> = None;
    let _: Option<ManualKeypadScreenV2<'_>> = None;
    let _: Option<ManualKeypadOutcomeV2> = None;
    let _: Option<ManualKeypadErrorV2> = None;
    let _: Option<KitInputModeV2> = None;
    let _: Option<KitShareOrdinalV2> = None;
    let _: Option<KitForeignInputV2> = None;
    let _: Option<KitIntakeInterruptionV2> = None;
    let _: Option<KitIntakeErrorV2> = None;
    let _: Option<KitFrameIdentityV2> = None;
    let _: Option<KitFallbackProgressV2> = None;
    let _: Option<KitIntakeScreenV2> = None;
    let _: Option<KitIntakeSessionV2> = None;
    let _: Option<KitIntakeOutcomeV2> = None;
    let _: Option<KitIntakeReadyV2> = None;
    let _: Option<HumanAssertionDigitV2> = None;
    let _: Option<KitRestoreArtifactV2> = None;
    let _: Option<KitRestoreErrorV2> = None;
    let _: Option<KitRestoreForeignOperationV2> = None;
    let _: Option<KitRestoreInterruptionV2> = None;
    let _: Option<KitRestoreOutcomeV2> = None;
    let _: Option<KitRestoreScreenV2> = None;
    let _: Option<KitRestoreSessionV2> = None;
    let _: Option<KitRestoreStageV2> = None;
    let _: Option<MandatoryFreshWalletMigrationV2> = None;
    let _: Option<KitSpendAssertionDigitV2> = None;
    let _: Option<KitSpendErrorV2> = None;
    let _: Option<KitSpendForeignOperationV2> = None;
    let _: Option<KitSpendInterruptionV2> = None;
    let _: Option<KitSpendOutcomeV2> = None;
    let _: Option<KitSpendScreenV2> = None;
    let _: Option<KitSpendSessionV2> = None;
    let _: Option<KitSpendStageV2> = None;
}

#[test]
fn kit_intake_has_one_private_wipe_boundary_and_no_dynamic_storage() {
    assert!(LIB.contains("#![deny(unsafe_code)]"));
    assert!(!LIB.contains("#[allow(unsafe_code)]\nmod kit_intake_v2;"));
    assert!(KIT_INTAKE.contains("#![deny(unsafe_op_in_unsafe_fn)]"));
    assert!(KIT_INTAKE.contains("#[allow(unsafe_code)]\n#[inline(never)]\nfn wipe("));
    assert_eq!(KIT_INTAKE.matches("unsafe {").count(), 1);
    for forbidden in [
        "Box<",
        "Vec<",
        "String",
        "to_vec(",
        "to_owned(",
        "format!(",
        "println!(",
        "eprintln!(",
    ] {
        assert!(
            !KIT_INTAKE.contains(forbidden),
            "fixed-memory fence: {forbidden}"
        );
    }
    assert!(KIT_INTAKE.contains("RecoveredKitPayload"));
    assert!(KIT_INTAKE.contains("_payload: RecoveredKitPayload"));
    assert!(!KIT_INTAKE.contains("&RecoveredKitPayload"));
    assert!(!KIT_INTAKE.contains("[u8; 96]"));
}

#[test]
fn kit_restore_accepts_only_the_opaque_ready_capability_and_stays_non_signing() {
    assert!(LIB.contains("mod kit_restore_v2;"));
    assert!(KIT_RESTORE.contains("ready: KitIntakeReadyV2"));
    assert!(KIT_RESTORE.contains("ready.into_restore_parts()"));
    assert!(KIT_RESTORE.contains("parts.door != KitDoorV2::KitRestore"));
    for forbidden in [
        "RecoveredKitPayload",
        "[u8; 96]",
        "pub fn sign",
        "pub fn approve",
        "pub fn finalize",
        "pub fn export",
        "pub fn regenerate",
        "qk_psbt",
        "RawTransaction",
        "pub fn transaction",
    ] {
        assert!(
            !KIT_RESTORE.contains(forbidden),
            "restore capability fence: {forbidden}"
        );
    }
    assert!(KIT_RESTORE.contains("SigningProhibited"));
    assert!(KIT_RESTORE.contains("MandatoryFreshWalletMigrationV2::Required"));
}

#[test]
fn kit_spend_accepts_only_ready_plus_exact_sweep_and_exposes_no_general_signer() {
    assert!(LIB.contains("mod kit_spend_v2;"));
    assert!(KIT_SPEND.contains("ready: KitIntakeReadyV2"));
    assert!(KIT_SPEND.contains("ready.into_spend_parts()"));
    assert!(KIT_SPEND.contains("parts.door != KitDoorV2::KitSpend"));
    assert!(KIT_SPEND.contains("build_validated_kit_sweep_v3("));
    assert!(KIT_SPEND.contains("payload.sign_validated_sweep_v3(proof)"));
    assert!(KIT_SPEND.contains("finalize_signed_kit_sweep_v3(signed)"));
    for forbidden in [
        "RecoveredKitPayload",
        "[u8; 96]",
        "pub fn sign(",
        "pub fn approve(",
        "pub fn export(",
        "pub fn regenerate(",
        "pub fn payload(",
        "pub fn secret(",
        "pub fn scalar(",
        "pub fn digest(",
    ] {
        assert!(
            !KIT_SPEND.contains(forbidden),
            "Kit-Spend capability fence: {forbidden}"
        );
    }
    assert!(KIT_SPEND.contains("SigningOutsideSweep"));
    assert!(KIT_SPEND.contains("KitRegenerationProhibited"));
    assert!(KIT_SPEND.contains("pub enum CoordinatorCompletenessStatementV2"));
    assert!(KIT_SPEND.contains("AllFundsIncluded"));
}

#[test]
fn kit_restore_uses_fixed_memory_and_wipes_each_caller_secret_boundary() {
    assert!(KIT_RESTORE.contains("#![deny(unsafe_op_in_unsafe_fn)]"));
    assert!(KIT_RESTORE.contains("#[allow(unsafe_code)]\n#[inline(never)]\nfn wipe("));
    assert_eq!(KIT_RESTORE.matches("unsafe {").count(), 1);
    assert!(KIT_RESTORE.contains("impl<const N: usize> Drop for CallerBufferGuard<'_, N>"));
    assert!(KIT_RESTORE.contains("wipe(self.bytes);"));
    assert!(KIT_RESTORE.contains("self.payload.take();"));
    assert!(KIT_RESTORE.contains("self.prepared_replacement.take();"));
    assert!(KIT_RESTORE.contains("self.prepared_a1.take();"));
    for forbidden in [
        "Box<",
        "Vec<",
        "String",
        "to_vec(",
        "to_owned(",
        "format!(",
        "println!(",
        "eprintln!(",
    ] {
        assert!(
            !KIT_RESTORE.contains(forbidden),
            "fixed-memory restore fence: {forbidden}"
        );
    }
}

#[test]
fn kit_restore_digit_is_exposed_only_after_branch_preconditions() {
    assert!(KIT_RESTORE.contains("KitRestoreStageV2::HumanAssertion"));
    assert!(
        KIT_RESTORE.contains("assertion_digit: (self.stage == KitRestoreStageV2::HumanAssertion)")
    );
    assert!(KIT_RESTORE.contains("self.prepared_replacement = Some(prepared);\n        self.stage = KitRestoreStageV2::HumanAssertion;"));
    assert!(KIT_RESTORE.contains("self.prepared_a1 = Some(prepared);\n        self.stage = KitRestoreStageV2::HumanAssertion;"));
    assert!(KIT_RESTORE.contains("self.authorize_digit(key)?;"));
}
