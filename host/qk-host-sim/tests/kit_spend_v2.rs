//! V2 slice-11 one-sweep Kit-Spend behavior over the registered public lineage.

use qk_host_sim::{
    CoordinatorCompletenessStatementV2, FlowApplyOutcomeV2, FlowEventV2, FlowKindV2,
    FlowTerminalV2, KeypadKey, KitDoorV2, KitInputModeV2, KitIntakeOutcomeV2, KitIntakeSessionV2,
    KitSpendAssertionDigitV2, KitSpendErrorV2, KitSpendForeignOperationV2, KitSpendInterruptionV2,
    KitSpendSessionV2, KitSpendStageV2, ScreenFlowV2, ScreenKindV2, SigningV2Error, WipingReasonV2,
    KIT_FALLBACK_TABLE_V2,
};

#[test]
fn signing_failures_retain_their_named_category_at_the_kit_boundary() {
    for (error, expected) in [
        (SigningV2Error::DuplicateSignature, "DuplicateSignature"),
        (
            SigningV2Error::InvalidRecoveredSignature,
            "InvalidRecoveredSignature",
        ),
        (SigningV2Error::ThresholdIncomplete, "ThresholdIncomplete"),
    ] {
        assert_eq!(error.name(), expected);
        assert_eq!(KitSpendErrorV2::Finalization(error).name(), expected);
    }
}
use qk_psbt::{InputSource, ReplacementReceiveIndexV2};
use std::panic::{catch_unwind, AssertUnwindSafe};

#[cfg(feature = "fuzzing")]
use qk_host_sim::{kit_spend_execution_trace_v2, reset_kit_spend_execution_trace_v2};

const KIT_SHARES: &str = include_str!("../../qk-kit/tests/fixtures/kit_share_v2.txt");
const SPEND: &str = include_str!("fixtures/kit_spend_v2.txt");

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

fn hex(value: &str) -> Vec<u8> {
    assert!(value.len().is_multiple_of(2));
    value
        .as_bytes()
        .chunks_exact(2)
        .map(|pair| (nibble(pair[0]) << 4) | nibble(pair[1]))
        .collect()
}

fn hex_array<const N: usize>(value: &str) -> [u8; N] {
    hex(value).try_into().expect("registered fixed width")
}

fn old_descriptors() -> [[u8; 306]; 2] {
    [
        field(SPEND, "old_receive_descriptor")
            .as_bytes()
            .try_into()
            .unwrap(),
        field(SPEND, "old_change_descriptor")
            .as_bytes()
            .try_into()
            .unwrap(),
    ]
}

fn replacement_descriptors() -> [[u8; 306]; 2] {
    [
        field(SPEND, "replacement_receive_descriptor")
            .as_bytes()
            .try_into()
            .unwrap(),
        field(SPEND, "replacement_change_descriptor")
            .as_bytes()
            .try_into()
            .unwrap(),
    ]
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

fn continue_to(flow: &mut ScreenFlowV2, event: FlowEventV2<'_>, expected: ScreenKindV2) {
    assert!(matches!(
        flow.apply(event).unwrap(),
        FlowApplyOutcomeV2::Continue(actual) if actual == expected
    ));
}

fn flow_at_share_one(door: KitDoorV2) -> ScreenFlowV2 {
    let mut flow = ScreenFlowV2::new(FlowKindV2::Kit);
    continue_to(
        &mut flow,
        FlowEventV2::Key(KeypadKey::EqualsConfirmEnter),
        ScreenKindV2::KitDoorSelection,
    );
    continue_to(
        &mut flow,
        FlowEventV2::SelectKitDoor(door),
        ScreenKindV2::KitDoorConfirmation,
    );
    continue_to(
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
        session
            .apply_fallback_key(numeric_key((position / 8 + 1) as u8))
            .unwrap();
        session
            .apply_fallback_key(numeric_key((position % 8 + 1) as u8))
            .unwrap();
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
            assert_eq!(first, [0; 142]);
            let mut second = frame(order[1]);
            let KitIntakeOutcomeV2::Ready(ready) =
                intake.submit_scanner_frame(&mut second).unwrap()
            else {
                panic!("registered pair releases readiness");
            };
            assert_eq!(second, [0; 142]);
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
                panic!("registered pair releases readiness");
            };
            ready
        }
    }
}

fn session_for(mode: KitInputModeV2, order: [u8; 2], digit: u8) -> KitSpendSessionV2 {
    KitSpendSessionV2::begin(
        ready(KitDoorV2::KitSpend, mode, order),
        &old_descriptors(),
        KitSpendAssertionDigitV2::new(digit).unwrap(),
    )
    .unwrap()
}

fn session(digit: u8) -> KitSpendSessionV2 {
    session_for(KitInputModeV2::Scanner, [1, 2], digit)
}

fn submit_registered(session: &mut KitSpendSessionV2) {
    let mut s0 = hex(field(SPEND, "s0_hex"));
    let screen = session
        .submit_sweep(
            &mut s0,
            InputSource::MicroSd,
            &replacement_descriptors(),
            ReplacementReceiveIndexV2::from_untrusted(0),
        )
        .unwrap();
    assert!(s0.iter().all(|byte| *byte == 0));
    assert_eq!(screen.stage(), KitSpendStageV2::CompletenessStatement);
    assert_eq!(
        screen.old_wallet_id(),
        hex_array(field(SPEND, "old_wallet_id_hex"))
    );
    assert_eq!(
        screen.replacement_wallet_id(),
        Some(hex_array(field(SPEND, "replacement_wallet_id_hex")))
    );
    assert_eq!(screen.destination_index(), Some(0));
    assert_eq!(
        screen.review_hash(),
        Some(hex_array(field(SPEND, "review_hash_hex")))
    );
}

#[cfg(feature = "fuzzing")]
#[test]
fn fuzz_trace_observes_actual_sign_finalize_and_terminal_edges() {
    reset_kit_spend_execution_trace_v2();
    let mut success = session(0);
    submit_registered(&mut success);
    success
        .confirm_completeness(CoordinatorCompletenessStatementV2::AllFundsIncluded)
        .unwrap();
    success.execute(KeypadKey::Zero).unwrap();
    let trace = kit_spend_execution_trace_v2();
    assert_eq!(trace.callback_count, 0);
    assert_eq!(trace.sign_count, 1);
    assert_eq!(trace.finalize_count, 1);
    assert_eq!(trace.terminal, Some(FlowTerminalV2::CompletedWiped));

    reset_kit_spend_execution_trace_v2();
    let mut rejected = session(0);
    rejected
        .interrupt(KitSpendInterruptionV2::SessionTimeout)
        .unwrap_err();
    let trace = kit_spend_execution_trace_v2();
    assert_eq!(trace.callback_count, 0);
    assert_eq!(trace.sign_count, 0);
    assert_eq!(trace.finalize_count, 0);
    assert_eq!(
        trace.terminal,
        Some(FlowTerminalV2::FailedWiped(WipingReasonV2::SessionTimeout))
    );
}

fn execute_registered(mut session: KitSpendSessionV2, digit: u8) -> qk_host_sim::KitSpendOutcomeV2 {
    submit_registered(&mut session);
    let screen = session
        .confirm_completeness(CoordinatorCompletenessStatementV2::AllFundsIncluded)
        .unwrap();
    assert_eq!(screen.stage(), KitSpendStageV2::HumanAssertion);
    assert_eq!(screen.assertion_digit().unwrap().value(), digit);
    session.execute(numeric_key(digit)).unwrap()
}

#[test]
fn exact_sweep_rebinds_signs_finalizes_and_matches_every_registered_artifact() {
    let outcome = execute_registered(session(4), 4);
    assert_eq!(
        outcome.old_wallet_id(),
        hex_array(field(SPEND, "old_wallet_id_hex"))
    );
    assert_eq!(
        outcome.replacement_wallet_id(),
        hex_array(field(SPEND, "replacement_wallet_id_hex"))
    );
    assert_eq!(outcome.destination_index(), 0);
    assert_eq!(
        outcome.review_hash(),
        hex_array(field(SPEND, "review_hash_hex"))
    );
    assert_eq!(
        outcome.completeness(),
        CoordinatorCompletenessStatementV2::AllFundsIncluded
    );
    assert_eq!(
        outcome.finalized().finalized_psbt(),
        hex(field(SPEND, "finalized_psbt_hex"))
    );
    assert_eq!(
        outcome.finalized().raw_transaction(),
        hex(field(SPEND, "raw_transaction_hex"))
    );
    assert_eq!(
        outcome.finalized().txid(),
        hex_array(field(SPEND, "txid_raw_hex"))
    );
    assert_eq!(
        outcome.finalized().wtxid(),
        hex_array(field(SPEND, "wtxid_raw_hex"))
    );
}

#[test]
fn all_readiness_forms_and_all_screen_named_digits_reach_the_same_one_sweep() {
    for (mode, order) in [
        (KitInputModeV2::Scanner, [1, 2]),
        (KitInputModeV2::Scanner, [2, 1]),
        (KitInputModeV2::Fallback, [1, 2]),
        (KitInputModeV2::Fallback, [2, 1]),
    ] {
        let session = session_for(mode, order, 4);
        assert_eq!(session.screen().unwrap().input_mode(), mode);
        assert_eq!(
            session
                .frame_identities()
                .map(|identity| identity.share_index().as_u8()),
            order
        );
        assert_eq!(execute_registered(session, 4).destination_index(), 0);
    }
    for digit in 0..=9 {
        assert_eq!(
            execute_registered(session(digit), digit).destination_index(),
            0
        );
    }
}

#[test]
fn wrong_door_wrong_d_and_invalid_digit_terminate_before_transaction_acceptance() {
    assert!(matches!(
        KitSpendSessionV2::begin(
            ready(KitDoorV2::KitRestore, KitInputModeV2::Scanner, [1, 2]),
            &old_descriptors(),
            KitSpendAssertionDigitV2::new(0).unwrap(),
        ),
        Err(KitSpendErrorV2::WrongDoor)
    ));
    let mut wrong_d = old_descriptors();
    wrong_d[0][0] ^= 1;
    assert!(matches!(
        KitSpendSessionV2::begin(
            ready(KitDoorV2::KitSpend, KitInputModeV2::Scanner, [1, 2]),
            &wrong_d,
            KitSpendAssertionDigitV2::new(0).unwrap(),
        ),
        Err(KitSpendErrorV2::RecoveredWalletMismatch)
    ));
    assert_eq!(
        KitSpendAssertionDigitV2::new(10).err(),
        Some(KitSpendErrorV2::InvalidHumanAssertionDigit)
    );
}

#[test]
fn transaction_failure_and_completeness_failures_wipe_and_close_the_session() {
    let mut malformed = session(3);
    let mut bytes = vec![0xa5; 32];
    assert!(matches!(
        malformed.submit_sweep(
            &mut bytes,
            InputSource::MicroSd,
            &replacement_descriptors(),
            ReplacementReceiveIndexV2::from_untrusted(0),
        ),
        Err(KitSpendErrorV2::Intake(_) | KitSpendErrorV2::Sweep(_))
    ));
    assert!(bytes.iter().all(|byte| *byte == 0));
    assert!(malformed.screen().is_none());

    let mut missing = session(3);
    submit_registered(&mut missing);
    assert_eq!(
        missing.execute(KeypadKey::Three).err(),
        Some(KitSpendErrorV2::CompletenessStatementMissing)
    );

    let mut mismatch = session(3);
    submit_registered(&mut mismatch);
    mismatch
        .confirm_completeness(CoordinatorCompletenessStatementV2::AllFundsIncluded)
        .unwrap();
    assert_eq!(
        mismatch.execute(KeypadKey::FourLeft).err(),
        Some(KitSpendErrorV2::HumanAssertionMismatch)
    );

    let mut repeated = session(3);
    submit_registered(&mut repeated);
    repeated
        .confirm_completeness(CoordinatorCompletenessStatementV2::AllFundsIncluded)
        .unwrap();
    assert_eq!(
        repeated
            .confirm_completeness(CoordinatorCompletenessStatementV2::AllFundsIncluded)
            .err(),
        Some(KitSpendErrorV2::InvalidTransition)
    );
    assert_eq!(
        repeated.terminal(),
        Some(FlowTerminalV2::FailedWiped(
            WipingReasonV2::InvalidTransition
        ))
    );

    let mut cancelled = session(3);
    submit_registered(&mut cancelled);
    cancelled
        .confirm_completeness(CoordinatorCompletenessStatementV2::AllFundsIncluded)
        .unwrap();
    assert_eq!(
        cancelled.execute(KeypadKey::CancelBack).err(),
        Some(KitSpendErrorV2::Cancelled)
    );
}

#[test]
fn every_non_cancel_key_except_the_named_digit_is_a_terminal_mismatch() {
    let keys = [
        KeypadKey::Seven,
        KeypadKey::EightUp,
        KeypadKey::Nine,
        KeypadKey::CeDelete,
        KeypadKey::FourLeft,
        KeypadKey::Five,
        KeypadKey::SixRight,
        KeypadKey::Multiply,
        KeypadKey::Divide,
        KeypadKey::One,
        KeypadKey::TwoDown,
        KeypadKey::Minus,
        KeypadKey::Percent,
        KeypadKey::Zero,
        KeypadKey::Decimal,
        KeypadKey::Plus,
        KeypadKey::EqualsConfirmEnter,
    ];
    for key in keys {
        let mut mismatch = session(3);
        submit_registered(&mut mismatch);
        mismatch
            .confirm_completeness(CoordinatorCompletenessStatementV2::AllFundsIncluded)
            .unwrap();
        assert_eq!(
            mismatch.execute(key).err(),
            Some(KitSpendErrorV2::HumanAssertionMismatch),
            "unexpected assertion-key outcome for {key:?}"
        );
    }
}

#[test]
fn every_foreign_operation_is_a_distinct_terminal_rejection() {
    let cases = [
        (
            KitSpendForeignOperationV2::Signing,
            KitSpendErrorV2::SigningOutsideSweep,
        ),
        (
            KitSpendForeignOperationV2::Transaction,
            KitSpendErrorV2::TransactionOutsideSweep,
        ),
        (
            KitSpendForeignOperationV2::Review,
            KitSpendErrorV2::ReviewOutsideSweep,
        ),
        (
            KitSpendForeignOperationV2::Approval,
            KitSpendErrorV2::ApprovalProhibited,
        ),
        (
            KitSpendForeignOperationV2::Export,
            KitSpendErrorV2::ExportProhibited,
        ),
        (
            KitSpendForeignOperationV2::Intake,
            KitSpendErrorV2::ForeignInputProhibited,
        ),
        (
            KitSpendForeignOperationV2::NormalWallet,
            KitSpendErrorV2::NormalWalletOperationProhibited,
        ),
        (
            KitSpendForeignOperationV2::Restore,
            KitSpendErrorV2::RestoreProhibited,
        ),
        (
            KitSpendForeignOperationV2::KitGeneration,
            KitSpendErrorV2::KitGenerationProhibited,
        ),
        (
            KitSpendForeignOperationV2::KitRegeneration,
            KitSpendErrorV2::KitRegenerationProhibited,
        ),
        (
            KitSpendForeignOperationV2::DoorSwitch,
            KitSpendErrorV2::DoorSwitchAttempt,
        ),
    ];
    for (operation, expected) in cases {
        let mut session = session(0);
        assert_eq!(
            session.reject_foreign_operation(operation).err(),
            Some(expected)
        );
        assert_eq!(expected.to_string(), expected.name());
        assert_eq!(
            session.reject_foreign_operation(operation).err(),
            Some(KitSpendErrorV2::Finished)
        );
    }
}

#[test]
fn every_closed_interruption_wipes_from_each_reachable_stage() {
    let cases = [
        (
            KitSpendInterruptionV2::Cancelled,
            KitSpendErrorV2::Cancelled,
            WipingReasonV2::Cancelled,
        ),
        (
            KitSpendInterruptionV2::OperationFailed,
            KitSpendErrorV2::OperationFailed,
            WipingReasonV2::OperationFailed,
        ),
        (
            KitSpendInterruptionV2::MediaRemoved,
            KitSpendErrorV2::MediaRemoved,
            WipingReasonV2::MediaRemoved,
        ),
        (
            KitSpendInterruptionV2::CardRemoved,
            KitSpendErrorV2::CardRemoved,
            WipingReasonV2::CardRemoved,
        ),
        (
            KitSpendInterruptionV2::SessionTimeout,
            KitSpendErrorV2::SessionTimeout,
            WipingReasonV2::SessionTimeout,
        ),
        (
            KitSpendInterruptionV2::Shutdown,
            KitSpendErrorV2::Shutdown,
            WipingReasonV2::Shutdown,
        ),
        (
            KitSpendInterruptionV2::Restart,
            KitSpendErrorV2::Restart,
            WipingReasonV2::Restart,
        ),
        (
            KitSpendInterruptionV2::PowerLoss,
            KitSpendErrorV2::PowerLoss,
            WipingReasonV2::PowerLoss,
        ),
    ];
    for stage in 0..3 {
        for (interruption, expected, reason) in cases {
            let mut session = session(0);
            if stage >= 1 {
                submit_registered(&mut session);
            }
            if stage >= 2 {
                session
                    .confirm_completeness(CoordinatorCompletenessStatementV2::AllFundsIncluded)
                    .unwrap();
            }
            assert_eq!(session.interrupt(interruption).err(), Some(expected));
            assert_eq!(
                session.terminal(),
                Some(FlowTerminalV2::FailedWiped(reason))
            );
            assert_eq!(
                session.interrupt(interruption).err(),
                Some(KitSpendErrorV2::Finished)
            );
        }
    }
}

#[test]
fn caught_unwind_drops_the_only_live_session_without_releasing_an_artifact() {
    let result = catch_unwind(AssertUnwindSafe(|| {
        let mut session = session(8);
        submit_registered(&mut session);
        panic!("exercise unwind cleanup");
    }));
    assert!(result.is_err());
}
