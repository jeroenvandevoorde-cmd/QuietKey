//! V2 slice-10 Kit-Restore semantic behavior over the registered public lineage.

use qk_host_sim::{
    A1ReprintDispositionV2, CardRemainsStatementV2, FlowApplyOutcomeV2, FlowEventV2, FlowKindV2,
    FlowTerminalV2, HumanAssertionDigitV2, KeypadKey, KitDoorV2, KitInputModeV2,
    KitIntakeOutcomeV2, KitIntakeSessionV2, KitRestoreActionV2, KitRestoreArtifactV2,
    KitRestoreDispositionV2, KitRestoreErrorV2, KitRestoreForeignOperationV2,
    KitRestoreInterruptionV2, KitRestoreSessionV2, KitRestoreStageV2,
    MandatoryFreshWalletMigrationV2, ScreenFlowV2, ScreenKindV2, SurvivingBFactorV2,
    WipingReasonV2, KIT_FALLBACK_TABLE_V2,
};
use std::panic::{catch_unwind, AssertUnwindSafe};

const PROVISIONING: &str = include_str!("../../qk-provisioning/tests/fixtures/provisioning_v2.txt");
const KIT_SHARES: &str = include_str!("../../qk-kit/tests/fixtures/kit_share_v2.txt");
const FRESH_NONCE: [u8; 12] = *b"QKV2S10NEW01";

fn field<'a>(fixture: &'a str, name: &str) -> &'a str {
    fixture
        .lines()
        .find_map(|line| line.strip_prefix(name)?.strip_prefix(": "))
        .unwrap_or_else(|| panic!("missing registered field {name}"))
}

fn nibble(value: u8) -> u8 {
    match value {
        b'0'..=b'9' => value - b'0',
        b'a'..=b'f' => value - b'a' + 10,
        _ => panic!("registered lowercase hex"),
    }
}

fn hex_array<const N: usize>(value: &str) -> [u8; N] {
    assert_eq!(value.len(), N * 2);
    let mut output = [0u8; N];
    for (slot, pair) in output.iter_mut().zip(value.as_bytes().chunks_exact(2)) {
        *slot = (nibble(pair[0]) << 4) | nibble(pair[1]);
    }
    output
}

fn descriptors() -> [[u8; 306]; 2] {
    [
        field(PROVISIONING, "receive_descriptor")
            .as_bytes()
            .try_into()
            .unwrap(),
        field(PROVISIONING, "change_descriptor")
            .as_bytes()
            .try_into()
            .unwrap(),
    ]
}

fn wallet_id() -> [u8; 32] {
    hex_array(field(PROVISIONING, "wallet_id"))
}

fn account_xpub_b() -> [u8; 111] {
    field(PROVISIONING, "role_b_account_xpub")
        .as_bytes()
        .try_into()
        .unwrap()
}

fn fingerprint_b() -> [u8; 4] {
    hex_array(field(PROVISIONING, "role_b_origin_fingerprint"))
}

fn frame(number: u8) -> [u8; 142] {
    match number {
        1 => hex_array(field(KIT_SHARES, "frame_1_hex")),
        2 => hex_array(field(KIT_SHARES, "frame_2_hex")),
        _ => panic!("registered share index"),
    }
}

fn fallback(number: u8) -> [u8; 228] {
    match number {
        1 => field(KIT_SHARES, "fallback_1_ascii"),
        2 => field(KIT_SHARES, "fallback_2_ascii"),
        _ => panic!("registered share index"),
    }
    .as_bytes()
    .try_into()
    .unwrap()
}

fn numeric_key(number: u8) -> KeypadKey {
    match number {
        0 => KeypadKey::Zero,
        1 => KeypadKey::One,
        2 => KeypadKey::TwoDown,
        3 => KeypadKey::Three,
        4 => KeypadKey::FourLeft,
        5 => KeypadKey::Five,
        6 => KeypadKey::SixRight,
        7 => KeypadKey::Seven,
        8 => KeypadKey::EightUp,
        9 => KeypadKey::Nine,
        _ => panic!("decimal key"),
    }
}

fn root_continue(flow: &mut ScreenFlowV2, event: FlowEventV2<'_>, expected: ScreenKindV2) {
    assert!(matches!(
        flow.apply(event).unwrap(),
        FlowApplyOutcomeV2::Continue(actual) if actual == expected
    ));
}

fn flow_at_share_one(door: KitDoorV2) -> ScreenFlowV2 {
    let mut flow = ScreenFlowV2::new(FlowKindV2::Kit);
    root_continue(
        &mut flow,
        FlowEventV2::Key(KeypadKey::EqualsConfirmEnter),
        ScreenKindV2::KitDoorSelection,
    );
    root_continue(
        &mut flow,
        FlowEventV2::SelectKitDoor(door),
        ScreenKindV2::KitDoorConfirmation,
    );
    root_continue(
        &mut flow,
        FlowEventV2::ConfirmKitDoor(door),
        ScreenKindV2::ScanKitShareOne,
    );
    flow
}

fn submit_fallback(session: &mut KitIntakeSessionV2, symbols: &[u8; 228]) {
    for symbol in symbols {
        let position = KIT_FALLBACK_TABLE_V2
            .iter()
            .flatten()
            .position(|candidate| candidate == symbol)
            .expect("registered fallback symbol");
        let row = numeric_key((position / 8 + 1) as u8);
        let column = numeric_key((position % 8 + 1) as u8);
        assert!(matches!(
            session.apply_fallback_key(row).unwrap(),
            KitIntakeOutcomeV2::Continue(_)
        ));
        assert!(matches!(
            session.apply_fallback_key(column).unwrap(),
            KitIntakeOutcomeV2::Continue(_)
        ));
    }
}

fn ready(door: KitDoorV2, mode: KitInputModeV2, order: [u8; 2]) -> qk_host_sim::KitIntakeReadyV2 {
    let mut intake = KitIntakeSessionV2::begin(flow_at_share_one(door), mode).unwrap();
    match mode {
        KitInputModeV2::Scanner => {
            let mut first = frame(order[0]);
            assert!(matches!(
                intake.submit_scanner_frame(&mut first).unwrap(),
                KitIntakeOutcomeV2::FirstShareAccepted(_)
            ));
            assert_eq!(first, [0u8; 142]);
            let mut second = frame(order[1]);
            let KitIntakeOutcomeV2::Ready(ready) =
                intake.submit_scanner_frame(&mut second).unwrap()
            else {
                panic!("registered pair releases readiness");
            };
            assert_eq!(second, [0u8; 142]);
            ready
        }
        KitInputModeV2::Fallback => {
            submit_fallback(&mut intake, &fallback(order[0]));
            assert!(matches!(
                intake
                    .apply_fallback_key(KeypadKey::EqualsConfirmEnter)
                    .unwrap(),
                KitIntakeOutcomeV2::FirstShareAccepted(_)
            ));
            submit_fallback(&mut intake, &fallback(order[1]));
            let KitIntakeOutcomeV2::Ready(ready) = intake
                .apply_fallback_key(KeypadKey::EqualsConfirmEnter)
                .unwrap()
            else {
                panic!("registered fallback pair releases readiness");
            };
            ready
        }
    }
}

fn session(digit: u8) -> KitRestoreSessionV2 {
    KitRestoreSessionV2::begin(
        ready(KitDoorV2::KitRestore, KitInputModeV2::Scanner, [1, 2]),
        &descriptors(),
        HumanAssertionDigitV2::new(digit).unwrap(),
    )
    .unwrap()
}

fn surviving_b() -> SurvivingBFactorV2 {
    let mut a2 = hex_array(field(PROVISIONING, "a2_transcript_sha256"));
    let factor = SurvivingBFactorV2::take(wallet_id(), account_xpub_b(), fingerprint_b(), &mut a2);
    assert_eq!(a2, [0u8; 32]);
    factor
}

fn prepare_replacement(session: &mut KitRestoreSessionV2) {
    assert_eq!(
        session
            .select_action(KitRestoreActionV2::ReplacementB)
            .unwrap()
            .stage(),
        KitRestoreStageV2::CardRemainsConfirmation
    );
    assert_eq!(
        session
            .confirm_card_remains(CardRemainsStatementV2::InHand)
            .unwrap()
            .stage(),
        KitRestoreStageV2::BranchPreparation
    );
    let mut capsule = hex_array(field(PROVISIONING, "a1_capsule_hex"));
    let screen = session.prepare_replacement_b(&mut capsule).unwrap();
    assert_eq!(capsule, [0u8; 67]);
    assert_eq!(screen.stage(), KitRestoreStageV2::HumanAssertion);
}

#[test]
fn only_exact_kit_restore_readiness_and_exact_d_can_begin() {
    assert!(matches!(
        KitRestoreSessionV2::begin(
            ready(KitDoorV2::KitSpend, KitInputModeV2::Scanner, [1, 2]),
            &descriptors(),
            HumanAssertionDigitV2::new(0).unwrap(),
        ),
        Err(KitRestoreErrorV2::WrongDoor)
    ));

    let mut wrong_d = descriptors();
    wrong_d[0][0] ^= 1;
    assert!(matches!(
        KitRestoreSessionV2::begin(
            ready(KitDoorV2::KitRestore, KitInputModeV2::Scanner, [1, 2]),
            &wrong_d,
            HumanAssertionDigitV2::new(0).unwrap(),
        ),
        Err(KitRestoreErrorV2::RecoveredWalletMismatch)
    ));
    assert_eq!(
        HumanAssertionDigitV2::new(10).err(),
        Some(KitRestoreErrorV2::InvalidHumanAssertionDigit)
    );

    for (mode, order) in [
        (KitInputModeV2::Scanner, [1, 2]),
        (KitInputModeV2::Scanner, [2, 1]),
        (KitInputModeV2::Fallback, [1, 2]),
        (KitInputModeV2::Fallback, [2, 1]),
    ] {
        let session = KitRestoreSessionV2::begin(
            ready(KitDoorV2::KitRestore, mode, order),
            &descriptors(),
            HumanAssertionDigitV2::new(4).unwrap(),
        )
        .unwrap();
        let screen = session.screen().unwrap();
        assert_eq!(screen.stage(), KitRestoreStageV2::ActionSelection);
        assert_eq!(screen.wallet_id(), wallet_id());
        assert_eq!(screen.input_mode(), mode);
        assert_eq!(screen.assertion_digit(), None);
        assert_eq!(
            session
                .frame_identities()
                .map(|identity| identity.share_index().as_u8()),
            order
        );
    }
}

#[test]
fn replacement_b_preconditions_precede_digit_and_sink() {
    let mut session = session(7);
    let first = session
        .select_action(KitRestoreActionV2::ReplacementB)
        .unwrap();
    assert_eq!(first.assertion_digit(), None);
    let second = session
        .confirm_card_remains(CardRemainsStatementV2::InHand)
        .unwrap();
    assert_eq!(second.stage(), KitRestoreStageV2::BranchPreparation);
    assert_eq!(second.assertion_digit(), None);

    let mut capsule = hex_array(field(PROVISIONING, "a1_capsule_hex"));
    let assertion = session.prepare_replacement_b(&mut capsule).unwrap();
    assert_eq!(capsule, [0u8; 67]);
    assert_eq!(assertion.assertion_digit().unwrap().value(), 7);

    let mut calls = 0usize;
    let outcome = session
        .execute_replacement_b(KeypadKey::Seven, |view| {
            calls += 1;
            assert_eq!(view.wallet_id(), &wallet_id());
            assert_eq!(view.account_xpub(), &account_xpub_b());
            assert_eq!(view.origin_fingerprint(), &fingerprint_b());
            KitRestoreDispositionV2::Accepted
        })
        .unwrap();
    assert_eq!(calls, 1);
    assert_eq!(outcome.posture(), MandatoryFreshWalletMigrationV2::Required);
    let KitRestoreArtifactV2::ReplacementB(receipt) = outcome.artifact() else {
        panic!("replacement receipt only");
    };
    assert_eq!(receipt.wallet_id(), wallet_id());
    assert_eq!(receipt.account_xpub(), account_xpub_b());
    assert_eq!(receipt.origin_fingerprint(), fingerprint_b());
}

#[test]
fn a1_reprint_preconditions_precede_digit_and_fresh_capsule_sink() {
    let mut session = session(2);
    let selected = session
        .select_action(KitRestoreActionV2::A1Reprint)
        .unwrap();
    assert_eq!(selected.stage(), KitRestoreStageV2::BranchPreparation);
    assert_eq!(selected.assertion_digit(), None);
    let assertion = session
        .prepare_a1_reprint(surviving_b(), &FRESH_NONCE)
        .unwrap();
    assert_eq!(assertion.assertion_digit().unwrap().value(), 2);

    let old = hex_array::<67>(field(PROVISIONING, "a1_capsule_hex"));
    let mut printed = [0u8; 67];
    let outcome = session
        .execute_a1_reprint(KeypadKey::TwoDown, |view, scan_back| {
            printed.copy_from_slice(view.capsule());
            scan_back.copy_from_slice(view.capsule());
            A1ReprintDispositionV2::Accepted
        })
        .unwrap();
    assert_ne!(printed, old);
    assert_eq!(&printed[..7], b"QKA1\x01\x01\x01");
    assert_eq!(&printed[7..19], &FRESH_NONCE);
    assert_eq!(outcome.posture(), MandatoryFreshWalletMigrationV2::Required);
    let KitRestoreArtifactV2::A1Reprint(receipt) = outcome.artifact() else {
        panic!("A1 receipt only");
    };
    assert_eq!(receipt.wallet_id(), wallet_id());
    assert_eq!(receipt.nonce(), FRESH_NONCE);
    assert_eq!(
        receipt.capsule_sha256(),
        hex_array("ea4aed0ce7a38dab3cb95f1887d0b0d3268fa54f277c458017136a7dc69b927c")
    );
}

#[test]
fn every_screen_named_digit_is_exact_and_wrong_keys_never_reach_a_sink() {
    for digit in 0..=9 {
        let mut session = session(digit);
        prepare_replacement(&mut session);
        let mut calls = 0usize;
        session
            .execute_replacement_b(numeric_key(digit), |_| {
                calls += 1;
                KitRestoreDispositionV2::Accepted
            })
            .unwrap();
        assert_eq!(calls, 1);
    }

    for (key, expected) in [
        (KeypadKey::Plus, KitRestoreErrorV2::HumanAssertionMismatch),
        (KeypadKey::CancelBack, KitRestoreErrorV2::Cancelled),
    ] {
        let mut session = session(6);
        prepare_replacement(&mut session);
        let mut called = false;
        assert_eq!(
            session
                .execute_replacement_b(key, |_| {
                    called = true;
                    KitRestoreDispositionV2::Accepted
                })
                .err(),
            Some(expected)
        );
        assert!(!called);
    }
}

#[test]
fn missing_card_action_switch_and_factor_mismatches_fail_before_sinks() {
    let mut missing = session(1);
    missing
        .select_action(KitRestoreActionV2::ReplacementB)
        .unwrap();
    assert_eq!(
        missing
            .confirm_card_remains(CardRemainsStatementV2::Missing)
            .err(),
        Some(KitRestoreErrorV2::MissingCardRequiresKitSpend)
    );
    assert_eq!(
        missing.terminal(),
        Some(FlowTerminalV2::FailedWiped(
            WipingReasonV2::MissingCardRequiresKitSpend
        ))
    );
    assert_eq!(
        missing.select_action(KitRestoreActionV2::A1Reprint).err(),
        Some(KitRestoreErrorV2::Finished)
    );

    let mut switched = session(1);
    switched
        .select_action(KitRestoreActionV2::A1Reprint)
        .unwrap();
    assert_eq!(
        switched
            .select_action(KitRestoreActionV2::ReplacementB)
            .err(),
        Some(KitRestoreErrorV2::ActionSwitchAttempt)
    );

    let mut bad_a1 = session(1);
    bad_a1
        .select_action(KitRestoreActionV2::ReplacementB)
        .unwrap();
    bad_a1
        .confirm_card_remains(CardRemainsStatementV2::InHand)
        .unwrap();
    let mut capsule = hex_array::<67>(field(PROVISIONING, "a1_capsule_hex"));
    capsule[31] ^= 1;
    assert_eq!(
        bad_a1.prepare_replacement_b(&mut capsule).err(),
        Some(KitRestoreErrorV2::SurvivingA1Mismatch)
    );
    assert_eq!(capsule, [0u8; 67]);

    let mut bad_b = session(1);
    bad_b.select_action(KitRestoreActionV2::A1Reprint).unwrap();
    let mut a2 = hex_array::<32>(field(PROVISIONING, "a2_transcript_sha256"));
    a2[0] ^= 1;
    let factor = SurvivingBFactorV2::take(wallet_id(), account_xpub_b(), fingerprint_b(), &mut a2);
    assert_eq!(a2, [0u8; 32]);
    assert_eq!(
        bad_b.prepare_a1_reprint(factor, &FRESH_NONCE).err(),
        Some(KitRestoreErrorV2::SurvivingBFactorMismatch)
    );
}

#[test]
fn each_foreign_operation_has_its_distinct_named_rejection() {
    let cases = [
        (
            KitRestoreForeignOperationV2::Signing,
            KitRestoreErrorV2::SigningProhibited,
            WipingReasonV2::RestoreSigningProhibited,
        ),
        (
            KitRestoreForeignOperationV2::Transaction,
            KitRestoreErrorV2::TransactionProhibited,
            WipingReasonV2::OperationFailed,
        ),
        (
            KitRestoreForeignOperationV2::Review,
            KitRestoreErrorV2::ReviewProhibited,
            WipingReasonV2::OperationFailed,
        ),
        (
            KitRestoreForeignOperationV2::Approval,
            KitRestoreErrorV2::ApprovalProhibited,
            WipingReasonV2::OperationFailed,
        ),
        (
            KitRestoreForeignOperationV2::Export,
            KitRestoreErrorV2::ExportProhibited,
            WipingReasonV2::OperationFailed,
        ),
        (
            KitRestoreForeignOperationV2::Intake,
            KitRestoreErrorV2::ForeignInputProhibited,
            WipingReasonV2::KitScannerModeMismatch,
        ),
        (
            KitRestoreForeignOperationV2::GenericWalletOutput,
            KitRestoreErrorV2::GenericWalletOutputProhibited,
            WipingReasonV2::OperationFailed,
        ),
        (
            KitRestoreForeignOperationV2::KitGeneration,
            KitRestoreErrorV2::KitGenerationProhibited,
            WipingReasonV2::OperationFailed,
        ),
        (
            KitRestoreForeignOperationV2::KitRegeneration,
            KitRestoreErrorV2::KitRegenerationProhibited,
            WipingReasonV2::OperationFailed,
        ),
        (
            KitRestoreForeignOperationV2::DoorSwitch,
            KitRestoreErrorV2::DoorSwitchAttempt,
            WipingReasonV2::DoorSwitchAttempt,
        ),
    ];
    for (operation, error, reason) in cases {
        let mut session = session(0);
        assert_eq!(
            session.reject_foreign_operation(operation).err(),
            Some(error)
        );
        assert_eq!(error.to_string(), error.name());
        assert_eq!(
            session.terminal(),
            Some(FlowTerminalV2::FailedWiped(reason))
        );
        assert_eq!(
            session.reject_foreign_operation(operation).err(),
            Some(KitRestoreErrorV2::Finished)
        );
    }
}

#[test]
fn every_interruption_wipes_from_every_reachable_stage() {
    let cases = [
        (
            KitRestoreInterruptionV2::Cancelled,
            KitRestoreErrorV2::Cancelled,
            WipingReasonV2::Cancelled,
        ),
        (
            KitRestoreInterruptionV2::OperationFailed,
            KitRestoreErrorV2::OperationFailed,
            WipingReasonV2::OperationFailed,
        ),
        (
            KitRestoreInterruptionV2::MediaRemoved,
            KitRestoreErrorV2::MediaRemoved,
            WipingReasonV2::MediaRemoved,
        ),
        (
            KitRestoreInterruptionV2::CardRemoved,
            KitRestoreErrorV2::CardRemoved,
            WipingReasonV2::CardRemoved,
        ),
        (
            KitRestoreInterruptionV2::SessionTimeout,
            KitRestoreErrorV2::SessionTimeout,
            WipingReasonV2::SessionTimeout,
        ),
        (
            KitRestoreInterruptionV2::Shutdown,
            KitRestoreErrorV2::Shutdown,
            WipingReasonV2::Shutdown,
        ),
        (
            KitRestoreInterruptionV2::Restart,
            KitRestoreErrorV2::Restart,
            WipingReasonV2::Restart,
        ),
        (
            KitRestoreInterruptionV2::PowerLoss,
            KitRestoreErrorV2::PowerLoss,
            WipingReasonV2::PowerLoss,
        ),
    ];
    for stage in 0..4 {
        for (event, expected, reason) in cases {
            let mut session = session(8);
            match stage {
                0 => {}
                1 => {
                    session
                        .select_action(KitRestoreActionV2::A1Reprint)
                        .unwrap();
                }
                2 => {
                    session
                        .select_action(KitRestoreActionV2::ReplacementB)
                        .unwrap();
                }
                3 => prepare_replacement(&mut session),
                _ => unreachable!(),
            }
            assert_eq!(session.interrupt(event).err(), Some(expected));
            assert_eq!(
                session.terminal(),
                Some(FlowTerminalV2::FailedWiped(reason))
            );
            assert_eq!(
                session.interrupt(event).err(),
                Some(KitRestoreErrorV2::Finished)
            );
        }
    }
}

#[test]
fn sink_rejections_and_unwinds_release_no_receipt() {
    let mut replacement = session(3);
    prepare_replacement(&mut replacement);
    assert_eq!(
        replacement
            .execute_replacement_b(KeypadKey::Three, |_| KitRestoreDispositionV2::Rejected)
            .err(),
        Some(KitRestoreErrorV2::ReplacementBRejected)
    );

    let mut reprint = session(3);
    reprint
        .select_action(KitRestoreActionV2::A1Reprint)
        .unwrap();
    reprint
        .prepare_a1_reprint(surviving_b(), &FRESH_NONCE)
        .unwrap();
    assert_eq!(
        reprint
            .execute_a1_reprint(KeypadKey::Three, |_, _| {
                A1ReprintDispositionV2::Rejected
            })
            .err(),
        Some(KitRestoreErrorV2::A1PrintRejected)
    );

    let mut unwind = session(3);
    prepare_replacement(&mut unwind);
    assert!(catch_unwind(AssertUnwindSafe(|| {
        let _ = unwind.execute_replacement_b(KeypadKey::Three, |_| panic!("test unwind"));
    }))
    .is_err());
}
