//! Slice-5 v2 topology checks over typed, already-bound HOST facts.

use qk_descriptor::{parse_descriptor_pair_v2, DescriptorPairV2};
use qk_host_sim::{
    CardRemainsStatementV2, CompletedOperationV2, DeferredBoundaryV2, EntropyInputModeV2,
    FlowApplyOutcomeV2, FlowEventV2, FlowKindV2, FlowTerminalV2, KeypadKey, KitDoorV2,
    KitRestoreActionV2, ReviewReadyV3, ReviewReadyV3Workflow, ReviewSessionOutcomeV2,
    ReviewSessionV2, ScopedApplyOutcomeV2, ScreenFlowV2, ScreenKindV2, ScreenV2,
    StatePreservingRejectionV2, WipingReasonV2,
};
use qk_psbt::InputSource;

const REVIEW_FIXTURE: &str = include_str!("../../qk-psbt/tests/fixtures/review_v3.txt");
const DESCRIPTOR_FIXTURE: &str =
    include_str!("../../qk-descriptor/tests/fixtures/descriptor_pairs.txt");

fn field(name: &str) -> &'static str {
    REVIEW_FIXTURE
        .lines()
        .find_map(|line| line.strip_prefix(&format!("{name}: ")))
        .expect("review-v3 fixture field")
}

fn descriptor_field(name: &str) -> &'static str {
    DESCRIPTOR_FIXTURE
        .split("\n\n")
        .find(|block| block.lines().any(|line| line == "case: GOLDEN"))
        .expect("GOLDEN descriptor block")
        .lines()
        .find_map(|line| line.strip_prefix(&format!("{name}: ")))
        .expect("GOLDEN descriptor field")
}

fn decode_hex(value: &str) -> Vec<u8> {
    value
        .as_bytes()
        .chunks_exact(2)
        .map(|pair| {
            u8::from_str_radix(core::str::from_utf8(pair).expect("ASCII hex"), 16)
                .expect("valid hex")
        })
        .collect()
}

fn descriptor() -> DescriptorPairV2 {
    parse_descriptor_pair_v2(
        descriptor_field("receive").as_bytes(),
        descriptor_field("change").as_bytes(),
    )
    .expect("registered v2 descriptor")
}

fn ready_workflow() -> ReviewReadyV3Workflow {
    let s0 = decode_hex(field("s0_hex"));
    let mut workflow = ReviewReadyV3Workflow::new(descriptor()).expect("workflow");
    workflow
        .intake(&s0, InputSource::MicroSd)
        .expect("immutable S0 intake");
    workflow.wake().expect("wake");
    workflow.begin_validation().expect("begin validation");
    workflow.validate().expect("validate");
    workflow.construct_review().expect("construct review v3");
    workflow
}

fn root_continue(flow: &mut ScreenFlowV2, event: FlowEventV2<'_>, expected: ScreenKindV2) {
    assert!(matches!(
        flow.apply(event).expect("root transition"),
        FlowApplyOutcomeV2::Continue(actual) if actual == expected
    ));
}

fn normal_to_validation(flow: &mut ScreenFlowV2) {
    root_continue(
        flow,
        FlowEventV2::Key(KeypadKey::EqualsConfirmEnter),
        ScreenKindV2::Transport,
    );
    root_continue(flow, FlowEventV2::TransportPresented, ScreenKindV2::Intake);
    root_continue(flow, FlowEventV2::IntakePresented, ScreenKindV2::FactorB);
    root_continue(
        flow,
        FlowEventV2::OperationCompleted(CompletedOperationV2::Plain),
        ScreenKindV2::FactorA1,
    );
    root_continue(
        flow,
        FlowEventV2::OperationCompleted(CompletedOperationV2::Plain),
        ScreenKindV2::Validation,
    );
}

fn enter_review<'flow, 'facts>(
    flow: &'flow mut ScreenFlowV2,
    ready: &'facts ReviewReadyV3,
) -> ReviewSessionV2<'flow, 'facts> {
    match flow
        .apply(FlowEventV2::OperationCompleted(
            CompletedOperationV2::Review(ready),
        ))
        .expect("review transition")
    {
        FlowApplyOutcomeV2::Review(session) => session,
        _ => panic!("expected review scope"),
    }
}

fn advance_review<'flow, 'facts>(
    session: ReviewSessionV2<'flow, 'facts>,
) -> ReviewSessionV2<'flow, 'facts> {
    match session
        .apply(FlowEventV2::Key(KeypadKey::EqualsConfirmEnter))
        .expect("review transition")
    {
        ReviewSessionOutcomeV2::Continue(next) => next,
        ReviewSessionOutcomeV2::Released(_) => panic!("review released early"),
    }
}

fn review_at_final<'flow, 'facts>(
    mut session: ReviewSessionV2<'flow, 'facts>,
) -> (ReviewSessionV2<'flow, 'facts>, Vec<ScreenKindV2>) {
    let mut visited = Vec::new();
    loop {
        let kind = session.screen().expect("typed review screen").kind();
        visited.push(kind);
        if kind == ScreenKindV2::FinalApproval {
            return (session, visited);
        }
        session = advance_review(session);
    }
}

fn kit_to_confirmation(flow: &mut ScreenFlowV2, door: KitDoorV2) {
    root_continue(
        flow,
        FlowEventV2::Key(KeypadKey::EqualsConfirmEnter),
        ScreenKindV2::KitDoorSelection,
    );
    root_continue(
        flow,
        FlowEventV2::SelectKitDoor(door),
        ScreenKindV2::KitDoorConfirmation,
    );
}

fn kit_to_combined(flow: &mut ScreenFlowV2, door: KitDoorV2) {
    kit_to_confirmation(flow, door);
    root_continue(
        flow,
        FlowEventV2::ConfirmKitDoor(door),
        ScreenKindV2::ScanKitShareOne,
    );
    root_continue(
        flow,
        FlowEventV2::KitShareAccepted,
        ScreenKindV2::ScanKitShareTwo,
    );
    root_continue(
        flow,
        FlowEventV2::KitShareAccepted,
        ScreenKindV2::CombineKitShares,
    );
    let expected = match door {
        KitDoorV2::KitSpend => ScreenKindV2::KitSpendTransaction,
        KitDoorV2::KitRestore => ScreenKindV2::KitRestoreActionSelection,
    };
    root_continue(
        flow,
        FlowEventV2::OperationCompleted(CompletedOperationV2::Plain),
        expected,
    );
}

fn failed(flow: &mut ScreenFlowV2, event: FlowEventV2<'_>, expected: WipingReasonV2) {
    assert!(matches!(
        flow.apply(event).expect("wiping transition"),
        FlowApplyOutcomeV2::FailedWiped(actual) if actual == expected
    ));
    assert_eq!(flow.terminal(), Some(FlowTerminalV2::FailedWiped(expected)));
    assert!(flow.is_finished());
}

#[test]
fn setup_selects_only_manual_while_dice_grid_is_unavailable() {
    let mut flow = ScreenFlowV2::new(FlowKindV2::Setup);
    root_continue(
        &mut flow,
        FlowEventV2::Key(KeypadKey::EqualsConfirmEnter),
        ScreenKindV2::TierSelection,
    );
    root_continue(
        &mut flow,
        FlowEventV2::Key(KeypadKey::EqualsConfirmEnter),
        ScreenKindV2::EntropyModeSelection,
    );
    assert!(matches!(
        flow.apply(FlowEventV2::CameraPresented)
            .expect("state-preserving rejection"),
        FlowApplyOutcomeV2::Rejected(StatePreservingRejectionV2::DiceGridUnavailable)
    ));
    assert_eq!(flow.screen_kind(), Some(ScreenKindV2::EntropyModeSelection));
    root_continue(
        &mut flow,
        FlowEventV2::Key(KeypadKey::SixRight),
        ScreenKindV2::EntropyModeSelection,
    );
    assert!(matches!(
        flow.screen(),
        Some(ScreenV2::EntropyModeSelection {
            selected: EntropyInputModeV2::ManualKeypad
        })
    ));
    root_continue(
        &mut flow,
        FlowEventV2::Key(KeypadKey::EqualsConfirmEnter),
        ScreenKindV2::CeremonyInput,
    );
}

#[test]
fn normal_flow_visits_the_complete_ordered_schema_v3_review_before_hold() {
    let workflow = ready_workflow();
    let ready = workflow.review_ready().expect("review ready");
    let mut flow = ScreenFlowV2::new(FlowKindV2::A1B);
    normal_to_validation(&mut flow);
    let session = enter_review(&mut flow, &ready);
    let (mut session, visited) = review_at_final(session);
    assert_eq!(visited.first(), Some(&ScreenKindV2::ReviewOverview));
    assert_eq!(visited.get(1), Some(&ScreenKindV2::ReviewArithmetic));
    assert!(visited.contains(&ScreenKindV2::ReviewRecipient));
    assert!(visited.contains(&ScreenKindV2::ReviewChange));
    assert!(visited.contains(&ScreenKindV2::ReviewOpReturn));
    assert!(visited.contains(&ScreenKindV2::ReviewLocktime));
    assert!(visited.contains(&ScreenKindV2::ReviewSequence));
    assert!(visited.contains(&ScreenKindV2::ReviewFeePolicy));
    assert_eq!(visited.last(), Some(&ScreenKindV2::FinalApproval));
    assert!(matches!(
        session.screen(),
        Some(ScreenV2::FinalApproval(view)) if view.review_hash() == ready.review_hash()
    ));

    session = match session
        .apply(FlowEventV2::ApprovalHoldStarted)
        .expect("start approval hold")
    {
        ReviewSessionOutcomeV2::Continue(next) => next,
        ReviewSessionOutcomeV2::Released(_) => panic!("hold released early"),
    };
    let token = session.pending_hold_token().expect("opaque hold token");
    assert!(matches!(
        session
            .apply(FlowEventV2::ApprovalHoldCompleted(token))
            .expect("complete approval hold"),
        ReviewSessionOutcomeV2::Released(ScopedApplyOutcomeV2::Released(
            ScreenKindV2::AwaitingSigning
        ))
    ));
    let identity = flow.approval_identity().expect("review-bound identity");
    assert_eq!(identity.review_hash(), ready.review_hash());
    root_continue(
        &mut flow,
        FlowEventV2::SigningOutcome { identity },
        ScreenKindV2::Export,
    );
}

#[test]
fn early_hold_and_foreign_hold_token_fail_closed() {
    let workflow = ready_workflow();
    let ready = workflow.review_ready().expect("review ready");
    let mut early_flow = ScreenFlowV2::new(FlowKindV2::A1B);
    normal_to_validation(&mut early_flow);
    let early = enter_review(&mut early_flow, &ready);
    assert!(matches!(
        early
            .apply(FlowEventV2::ApprovalHoldStarted)
            .expect("early hold rejection"),
        ReviewSessionOutcomeV2::Released(ScopedApplyOutcomeV2::FailedWiped(
            WipingReasonV2::ReviewIncomplete
        ))
    ));

    let workflow_a = ready_workflow();
    let ready_a = workflow_a.review_ready().expect("review A");
    let workflow_b = ready_workflow();
    let ready_b = workflow_b.review_ready().expect("review B");
    let mut flow_a = ScreenFlowV2::new(FlowKindV2::A1B);
    let mut flow_b = ScreenFlowV2::new(FlowKindV2::A1B);
    normal_to_validation(&mut flow_a);
    normal_to_validation(&mut flow_b);
    let (session_a, _) = review_at_final(enter_review(&mut flow_a, &ready_a));
    let (session_b, _) = review_at_final(enter_review(&mut flow_b, &ready_b));
    let session_b = match session_b
        .apply(FlowEventV2::ApprovalHoldStarted)
        .expect("start foreign hold")
    {
        ReviewSessionOutcomeV2::Continue(next) => next,
        ReviewSessionOutcomeV2::Released(_) => panic!("foreign hold released"),
    };
    let foreign = session_b.pending_hold_token().expect("foreign token");
    drop(session_b);
    assert!(matches!(
        session_a
            .apply(FlowEventV2::ApprovalHoldCompleted(foreign))
            .expect("foreign completion"),
        ReviewSessionOutcomeV2::Released(ScopedApplyOutcomeV2::FailedWiped(
            WipingReasonV2::ReviewIdentityMismatch
        ))
    ));
}

#[test]
fn every_post_approval_intake_or_transport_event_is_a_no_yield_failure() {
    for case in 0..7 {
        let workflow = ready_workflow();
        let ready = workflow.review_ready().expect("review ready");
        let mut flow = ScreenFlowV2::new(FlowKindV2::A1B);
        normal_to_validation(&mut flow);
        let (session, _) = review_at_final(enter_review(&mut flow, &ready));
        let session = match session
            .apply(FlowEventV2::ApprovalHoldStarted)
            .expect("start hold")
        {
            ReviewSessionOutcomeV2::Continue(next) => next,
            ReviewSessionOutcomeV2::Released(_) => panic!("hold released"),
        };
        let token = session.pending_hold_token().expect("token");
        assert!(matches!(
            session
                .apply(FlowEventV2::ApprovalHoldCompleted(token))
                .expect("complete hold"),
            ReviewSessionOutcomeV2::Released(ScopedApplyOutcomeV2::Released(
                ScreenKindV2::AwaitingSigning
            ))
        ));
        let event = match case {
            0 => FlowEventV2::TransportPresented,
            1 => FlowEventV2::CameraPresented,
            2 => FlowEventV2::IntakePresented,
            3 => FlowEventV2::PsbtPresented,
            4 => FlowEventV2::A1Presented,
            5 => FlowEventV2::BbqrTransactionPresented,
            6 => FlowEventV2::CoordinatorPresented,
            _ => unreachable!(),
        };
        failed(&mut flow, event, WipingReasonV2::PostApprovalYield);
    }
}

#[test]
fn kit_door_is_immutable_and_both_share_scans_are_mode_locked() {
    let mut switched = ScreenFlowV2::new(FlowKindV2::Kit);
    kit_to_confirmation(&mut switched, KitDoorV2::KitSpend);
    failed(
        &mut switched,
        FlowEventV2::ConfirmKitDoor(KitDoorV2::KitRestore),
        WipingReasonV2::DoorSwitchAttempt,
    );

    for second_scan in [false, true] {
        for case in 0..7 {
            let mut flow = ScreenFlowV2::new(FlowKindV2::Kit);
            kit_to_confirmation(&mut flow, KitDoorV2::KitSpend);
            root_continue(
                &mut flow,
                FlowEventV2::ConfirmKitDoor(KitDoorV2::KitSpend),
                ScreenKindV2::ScanKitShareOne,
            );
            if second_scan {
                root_continue(
                    &mut flow,
                    FlowEventV2::KitShareAccepted,
                    ScreenKindV2::ScanKitShareTwo,
                );
            }
            let event = match case {
                0 => FlowEventV2::PsbtPresented,
                1 => FlowEventV2::A1Presented,
                2 => FlowEventV2::BbqrTransactionPresented,
                3 => FlowEventV2::CoordinatorPresented,
                4 => FlowEventV2::CameraPresented,
                5 => FlowEventV2::TransportPresented,
                6 => FlowEventV2::IntakePresented,
                _ => unreachable!(),
            };
            failed(&mut flow, event, WipingReasonV2::KitScannerModeMismatch);
        }
    }
}

#[test]
fn kit_spend_requires_transaction_validation_then_completeness() {
    let mut flow = ScreenFlowV2::new(FlowKindV2::Kit);
    kit_to_combined(&mut flow, KitDoorV2::KitSpend);
    root_continue(
        &mut flow,
        FlowEventV2::KitSpendTransactionPresented,
        ScreenKindV2::KitSpendValidation,
    );
    root_continue(
        &mut flow,
        FlowEventV2::KitSpendValidated,
        ScreenKindV2::KitSpendCompleteness,
    );
    root_continue(
        &mut flow,
        FlowEventV2::CoordinatorUtxoCompletenessConfirmed,
        ScreenKindV2::KitSpendDeferred,
    );
    assert!(matches!(
        flow.apply(FlowEventV2::Key(KeypadKey::EqualsConfirmEnter))
            .expect("typed defer"),
        FlowApplyOutcomeV2::DeferredWiped(DeferredBoundaryV2::KitSpendSlice11)
    ));
}

#[test]
fn kit_restore_supports_only_the_two_deferred_actions_and_in_hand_replacement() {
    let mut a1 = ScreenFlowV2::new(FlowKindV2::Kit);
    kit_to_combined(&mut a1, KitDoorV2::KitRestore);
    root_continue(
        &mut a1,
        FlowEventV2::SelectKitRestoreAction(KitRestoreActionV2::A1Reprint),
        ScreenKindV2::KitRestoreDeferred,
    );
    assert!(matches!(
        a1.apply(FlowEventV2::Key(KeypadKey::EqualsConfirmEnter))
            .expect("A1 defer"),
        FlowApplyOutcomeV2::DeferredWiped(DeferredBoundaryV2::KitRestoreSlice10)
    ));

    let mut replacement = ScreenFlowV2::new(FlowKindV2::Kit);
    kit_to_combined(&mut replacement, KitDoorV2::KitRestore);
    root_continue(
        &mut replacement,
        FlowEventV2::SelectKitRestoreAction(KitRestoreActionV2::ReplacementB),
        ScreenKindV2::CardRemainsConfirmation,
    );
    root_continue(
        &mut replacement,
        FlowEventV2::CardRemainsStatement(CardRemainsStatementV2::InHand),
        ScreenKindV2::KitRestoreDeferred,
    );

    let mut missing = ScreenFlowV2::new(FlowKindV2::Kit);
    kit_to_combined(&mut missing, KitDoorV2::KitRestore);
    root_continue(
        &mut missing,
        FlowEventV2::SelectKitRestoreAction(KitRestoreActionV2::ReplacementB),
        ScreenKindV2::CardRemainsConfirmation,
    );
    failed(
        &mut missing,
        FlowEventV2::CardRemainsStatement(CardRemainsStatementV2::Missing),
        WipingReasonV2::MissingCardRequiresKitSpend,
    );
}

#[test]
fn every_closed_interruption_wipes_each_flow_kind_and_finished_state_is_stable() {
    let reasons = [
        WipingReasonV2::Cancelled,
        WipingReasonV2::OperationFailed,
        WipingReasonV2::MediaRemoved,
        WipingReasonV2::CardRemoved,
        WipingReasonV2::SessionTimeout,
        WipingReasonV2::Shutdown,
        WipingReasonV2::Restart,
        WipingReasonV2::PowerLoss,
    ];
    for kind in [FlowKindV2::Setup, FlowKindV2::A1B, FlowKindV2::Kit] {
        for (case, expected) in reasons.into_iter().enumerate() {
            let mut flow = ScreenFlowV2::new(kind);
            let event = match case {
                0 => FlowEventV2::Key(KeypadKey::CancelBack),
                1 => FlowEventV2::OperationFailed,
                2 => FlowEventV2::MediaRemoved,
                3 => FlowEventV2::CardRemoved,
                4 => FlowEventV2::SessionTimeout,
                5 => FlowEventV2::Shutdown,
                6 => FlowEventV2::Restart,
                7 => FlowEventV2::PowerLoss,
                _ => unreachable!(),
            };
            failed(&mut flow, event, expected);
            assert!(flow.apply(FlowEventV2::Restart).is_err());
            assert_eq!(flow.terminal(), Some(FlowTerminalV2::FailedWiped(expected)));
        }
    }
}
