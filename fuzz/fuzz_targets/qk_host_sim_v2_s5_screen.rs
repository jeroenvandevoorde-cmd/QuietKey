#![no_main]

use libfuzzer_sys::fuzz_target;
use qk_descriptor::{parse_descriptor_pair_v2, DescriptorPairV2};
use qk_host_sim::{
    CardRemainsStatementV2, CompletedOperationV2, DeferredBoundaryV2, FlowApplyOutcomeV2,
    FlowEventV2, FlowKindV2, FlowTerminalV2, KeypadKey, KitDoorV2, KitRestoreActionV2,
    ReviewReadyV3, ReviewReadyV3Workflow, ReviewSessionOutcomeV2, ScopedApplyOutcomeV2,
    ScreenFlowV2, ScreenKindV2, SpareBChoiceV2, StatePreservingRejectionV2, WipingReasonV2,
};
use qk_psbt::{InputSource, ReviewV3Hash};
use std::sync::OnceLock;

const MAX_EVENTS: usize = 256;
const REVIEW_FIXTURE: &str = include_str!("../../host/qk-psbt/tests/fixtures/review_v3.txt");
const DESCRIPTOR_FIXTURE: &str =
    include_str!("../../host/qk-descriptor/tests/fixtures/descriptor_pairs.txt");

static REVIEW_WORKFLOW: OnceLock<ReviewReadyV3Workflow> = OnceLock::new();

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct RootSnapshot {
    flow: FlowKindV2,
    screen: Option<ScreenKindV2>,
    terminal: Option<FlowTerminalV2>,
    door: Option<KitDoorV2>,
    approval_hash: Option<ReviewV3Hash>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct CampaignSnapshot {
    setup: Vec<RootSnapshot>,
    normal_views: Vec<ScreenKindV2>,
    normal_terminal: RootSnapshot,
    kit_spend: Vec<RootSnapshot>,
    kit_restore: Vec<RootSnapshot>,
    random: Vec<RootSnapshot>,
}

fn fixture_field<'a>(fixture: &'a str, name: &str) -> &'a str {
    fixture
        .lines()
        .find_map(|line| line.strip_prefix(&format!("{name}: ")))
        .expect("registered v2 fixture field")
}

fn descriptor_field(name: &str) -> &'static str {
    let golden = DESCRIPTOR_FIXTURE
        .split("\n\n")
        .find(|block| block.lines().any(|line| line == "case: GOLDEN"))
        .expect("registered v2 GOLDEN descriptor block");
    golden
        .lines()
        .find_map(|line| line.strip_prefix(&format!("{name}: ")))
        .expect("registered v2 GOLDEN descriptor field")
}

fn decode_hex(value: &str) -> Vec<u8> {
    assert!(value.len().is_multiple_of(2), "fixture hex width");
    value
        .as_bytes()
        .chunks_exact(2)
        .map(|pair| {
            u8::from_str_radix(core::str::from_utf8(pair).expect("ASCII hex"), 16)
                .expect("registered fixture hex")
        })
        .collect()
}

fn descriptor() -> DescriptorPairV2 {
    parse_descriptor_pair_v2(
        descriptor_field("receive").as_bytes(),
        descriptor_field("change").as_bytes(),
    )
    .expect("registered v2 GOLDEN descriptor pair")
}

fn build_review_workflow() -> ReviewReadyV3Workflow {
    let s0 = decode_hex(fixture_field(REVIEW_FIXTURE, "s0_hex"));
    let mut workflow = ReviewReadyV3Workflow::new(descriptor()).expect("v2 review workflow");
    workflow
        .intake(&s0, InputSource::MicroSd)
        .expect("registered immutable S0 intake");
    workflow.wake().expect("registered v2 wake");
    workflow
        .begin_validation()
        .expect("registered v2 validation start");
    workflow.validate().expect("registered v2 validation");
    workflow
        .construct_review()
        .expect("registered v2 review construction");
    workflow
}

fn review_ready() -> &'static ReviewReadyV3 {
    REVIEW_WORKFLOW
        .get_or_init(build_review_workflow)
        .review_ready()
        .expect("registered schema-v3 ReviewReady")
}

fn snapshot(flow: &ScreenFlowV2) -> RootSnapshot {
    RootSnapshot {
        flow: flow.flow_kind(),
        screen: flow.screen_kind(),
        terminal: flow.terminal(),
        door: flow.selected_kit_door(),
        approval_hash: flow
            .approval_identity()
            .map(|identity| identity.review_hash()),
    }
}

fn assert_named_reason(reason: WipingReasonV2) {
    match reason {
        WipingReasonV2::InvalidTransition
        | WipingReasonV2::Cancelled
        | WipingReasonV2::OperationFailed
        | WipingReasonV2::MediaRemoved
        | WipingReasonV2::CardRemoved
        | WipingReasonV2::SessionTimeout
        | WipingReasonV2::Shutdown
        | WipingReasonV2::Restart
        | WipingReasonV2::PowerLoss
        | WipingReasonV2::DoorSwitchAttempt
        | WipingReasonV2::KitScannerModeMismatch
        | WipingReasonV2::ReviewIncomplete
        | WipingReasonV2::ReviewIdentityMismatch
        | WipingReasonV2::PostApprovalYield
        | WipingReasonV2::RestoreSigningProhibited
        | WipingReasonV2::MissingCardRequiresKitSpend => {}
    }
}

fn expect_continue(flow: &mut ScreenFlowV2, event: FlowEventV2<'_>, expected: ScreenKindV2) {
    match flow.apply(event).expect("active v2 transition") {
        FlowApplyOutcomeV2::Continue(actual) => assert_eq!(actual, expected),
        FlowApplyOutcomeV2::Rejected(_)
        | FlowApplyOutcomeV2::ProvisioningResult(_)
        | FlowApplyOutcomeV2::Review(_)
        | FlowApplyOutcomeV2::TransactionResult(_)
        | FlowApplyOutcomeV2::CompletedWiped
        | FlowApplyOutcomeV2::DeferredWiped(_)
        | FlowApplyOutcomeV2::FailedWiped(_) => panic!("v2 transition reached wrong category"),
    }
    assert_eq!(flow.screen_kind(), Some(expected));
}

fn expect_failure(flow: &mut ScreenFlowV2, event: FlowEventV2<'_>, expected: WipingReasonV2) {
    assert_named_reason(expected);
    match flow.apply(event).expect("active v2 rejection") {
        FlowApplyOutcomeV2::FailedWiped(actual) => assert_eq!(actual, expected),
        FlowApplyOutcomeV2::Continue(_)
        | FlowApplyOutcomeV2::Rejected(_)
        | FlowApplyOutcomeV2::ProvisioningResult(_)
        | FlowApplyOutcomeV2::Review(_)
        | FlowApplyOutcomeV2::TransactionResult(_)
        | FlowApplyOutcomeV2::CompletedWiped
        | FlowApplyOutcomeV2::DeferredWiped(_) => panic!("v2 rejection was wrongly accepted"),
    }
    assert_eq!(flow.terminal(), Some(FlowTerminalV2::FailedWiped(expected)));
    assert!(
        flow.apply(event).is_err(),
        "terminal accepted another event"
    );
}

fn setup_oracle(interruption_selector: u8) -> Vec<RootSnapshot> {
    let mut flow = ScreenFlowV2::new(FlowKindV2::Setup);
    let mut snapshots = vec![snapshot(&flow)];
    expect_continue(
        &mut flow,
        FlowEventV2::Key(KeypadKey::EqualsConfirmEnter),
        ScreenKindV2::TierSelection,
    );
    snapshots.push(snapshot(&flow));
    expect_continue(
        &mut flow,
        FlowEventV2::Key(KeypadKey::EqualsConfirmEnter),
        ScreenKindV2::EntropyModeSelection,
    );
    snapshots.push(snapshot(&flow));

    let before = snapshot(&flow);
    assert!(matches!(
        flow.apply(FlowEventV2::Key(KeypadKey::EqualsConfirmEnter)),
        Ok(FlowApplyOutcomeV2::Rejected(
            StatePreservingRejectionV2::DiceGridUnavailable
        ))
    ));
    assert_eq!(snapshot(&flow), before, "DiceGrid rejection changed state");
    snapshots.push(snapshot(&flow));

    expect_continue(
        &mut flow,
        FlowEventV2::Key(KeypadKey::SixRight),
        ScreenKindV2::EntropyModeSelection,
    );
    expect_continue(
        &mut flow,
        FlowEventV2::Key(KeypadKey::EqualsConfirmEnter),
        ScreenKindV2::CeremonyInput,
    );
    snapshots.push(snapshot(&flow));

    let interruptions = [
        (
            FlowEventV2::Key(KeypadKey::CancelBack),
            WipingReasonV2::Cancelled,
        ),
        (
            FlowEventV2::OperationFailed,
            WipingReasonV2::OperationFailed,
        ),
        (FlowEventV2::MediaRemoved, WipingReasonV2::MediaRemoved),
        (FlowEventV2::CardRemoved, WipingReasonV2::CardRemoved),
        (FlowEventV2::SessionTimeout, WipingReasonV2::SessionTimeout),
        (FlowEventV2::Shutdown, WipingReasonV2::Shutdown),
        (FlowEventV2::Restart, WipingReasonV2::Restart),
        (FlowEventV2::PowerLoss, WipingReasonV2::PowerLoss),
    ];
    let (event, reason) = interruptions[usize::from(interruption_selector) % interruptions.len()];
    expect_failure(&mut flow, event, reason);
    snapshots.push(snapshot(&flow));
    snapshots
}

fn start_kit(door: KitDoorV2) -> ScreenFlowV2 {
    let mut flow = ScreenFlowV2::new(FlowKindV2::Kit);
    expect_continue(
        &mut flow,
        FlowEventV2::Key(KeypadKey::EqualsConfirmEnter),
        ScreenKindV2::KitDoorSelection,
    );
    expect_continue(
        &mut flow,
        FlowEventV2::SelectKitDoor(door),
        ScreenKindV2::KitDoorConfirmation,
    );
    assert_eq!(flow.selected_kit_door(), Some(door));
    expect_continue(
        &mut flow,
        FlowEventV2::ConfirmKitDoor(door),
        ScreenKindV2::ScanKitShareOne,
    );
    flow
}

fn combine_kit(door: KitDoorV2) -> ScreenFlowV2 {
    let mut flow = start_kit(door);
    expect_continue(
        &mut flow,
        FlowEventV2::KitShareAccepted,
        ScreenKindV2::ScanKitShareTwo,
    );
    expect_continue(
        &mut flow,
        FlowEventV2::KitShareAccepted,
        ScreenKindV2::CombineKitShares,
    );
    let expected = match door {
        KitDoorV2::KitSpend => ScreenKindV2::KitSpendTransaction,
        KitDoorV2::KitRestore => ScreenKindV2::KitRestoreActionSelection,
    };
    expect_continue(
        &mut flow,
        FlowEventV2::OperationCompleted(CompletedOperationV2::Plain),
        expected,
    );
    flow
}

fn door_lock_oracle() {
    let mut flow = ScreenFlowV2::new(FlowKindV2::Kit);
    expect_continue(
        &mut flow,
        FlowEventV2::Key(KeypadKey::EqualsConfirmEnter),
        ScreenKindV2::KitDoorSelection,
    );
    expect_continue(
        &mut flow,
        FlowEventV2::SelectKitDoor(KitDoorV2::KitSpend),
        ScreenKindV2::KitDoorConfirmation,
    );
    expect_failure(
        &mut flow,
        FlowEventV2::SelectKitDoor(KitDoorV2::KitRestore),
        WipingReasonV2::DoorSwitchAttempt,
    );
}

fn scanner_mode_oracle(selector: u8) {
    let mismatches = [
        FlowEventV2::PsbtPresented,
        FlowEventV2::A1Presented,
        FlowEventV2::BbqrTransactionPresented,
        FlowEventV2::CoordinatorPresented,
        FlowEventV2::CameraPresented,
        FlowEventV2::TransportPresented,
        FlowEventV2::IntakePresented,
    ];
    let mut flow = start_kit(KitDoorV2::KitSpend);
    expect_failure(
        &mut flow,
        mismatches[usize::from(selector) % mismatches.len()],
        WipingReasonV2::KitScannerModeMismatch,
    );
}

fn kit_spend_oracle() -> Vec<RootSnapshot> {
    let mut flow = combine_kit(KitDoorV2::KitSpend);
    let mut snapshots = vec![snapshot(&flow)];
    expect_continue(
        &mut flow,
        FlowEventV2::KitSpendTransactionPresented,
        ScreenKindV2::KitSpendValidation,
    );
    snapshots.push(snapshot(&flow));
    expect_continue(
        &mut flow,
        FlowEventV2::KitSpendValidated,
        ScreenKindV2::KitSpendCompleteness,
    );
    snapshots.push(snapshot(&flow));
    expect_continue(
        &mut flow,
        FlowEventV2::CoordinatorUtxoCompletenessConfirmed,
        ScreenKindV2::KitSpendDeferred,
    );
    snapshots.push(snapshot(&flow));
    assert!(matches!(
        flow.apply(FlowEventV2::Key(KeypadKey::EqualsConfirmEnter)),
        Ok(FlowApplyOutcomeV2::DeferredWiped(
            DeferredBoundaryV2::KitSpendSlice11
        ))
    ));
    assert_eq!(
        flow.terminal(),
        Some(FlowTerminalV2::DeferredWiped(
            DeferredBoundaryV2::KitSpendSlice11
        ))
    );
    assert!(flow
        .apply(FlowEventV2::Key(KeypadKey::EqualsConfirmEnter))
        .is_err());
    snapshots.push(snapshot(&flow));
    snapshots
}

fn kit_restore_oracle(action_selector: u8) -> Vec<RootSnapshot> {
    let action = if action_selector & 1 == 0 {
        KitRestoreActionV2::ReplacementB
    } else {
        KitRestoreActionV2::A1Reprint
    };
    let mut flow = combine_kit(KitDoorV2::KitRestore);
    let mut snapshots = vec![snapshot(&flow)];
    let expected = match action {
        KitRestoreActionV2::ReplacementB => ScreenKindV2::CardRemainsConfirmation,
        KitRestoreActionV2::A1Reprint => ScreenKindV2::KitRestoreDeferred,
    };
    expect_continue(
        &mut flow,
        FlowEventV2::SelectKitRestoreAction(action),
        expected,
    );
    snapshots.push(snapshot(&flow));
    if action == KitRestoreActionV2::ReplacementB {
        expect_continue(
            &mut flow,
            FlowEventV2::CardRemainsStatement(CardRemainsStatementV2::InHand),
            ScreenKindV2::KitRestoreDeferred,
        );
        snapshots.push(snapshot(&flow));
    }
    assert!(matches!(
        flow.apply(FlowEventV2::Key(KeypadKey::EqualsConfirmEnter)),
        Ok(FlowApplyOutcomeV2::DeferredWiped(
            DeferredBoundaryV2::KitRestoreSlice10
        ))
    ));
    assert_eq!(
        flow.terminal(),
        Some(FlowTerminalV2::DeferredWiped(
            DeferredBoundaryV2::KitRestoreSlice10
        ))
    );
    snapshots.push(snapshot(&flow));
    snapshots
}

fn restore_rejection_oracles() {
    let mut prohibited = combine_kit(KitDoorV2::KitRestore);
    expect_failure(
        &mut prohibited,
        FlowEventV2::PsbtPresented,
        WipingReasonV2::RestoreSigningProhibited,
    );

    let mut missing = combine_kit(KitDoorV2::KitRestore);
    expect_continue(
        &mut missing,
        FlowEventV2::SelectKitRestoreAction(KitRestoreActionV2::ReplacementB),
        ScreenKindV2::CardRemainsConfirmation,
    );
    expect_failure(
        &mut missing,
        FlowEventV2::CardRemainsStatement(CardRemainsStatementV2::Missing),
        WipingReasonV2::MissingCardRequiresKitSpend,
    );
}

fn start_normal_review(flow: &mut ScreenFlowV2) -> qk_host_sim::ReviewSessionV2<'_, 'static> {
    expect_continue(
        flow,
        FlowEventV2::Key(KeypadKey::EqualsConfirmEnter),
        ScreenKindV2::Transport,
    );
    expect_continue(flow, FlowEventV2::TransportPresented, ScreenKindV2::Intake);
    expect_continue(flow, FlowEventV2::IntakePresented, ScreenKindV2::FactorB);
    expect_continue(
        flow,
        FlowEventV2::OperationCompleted(CompletedOperationV2::Plain),
        ScreenKindV2::FactorA1,
    );
    expect_continue(
        flow,
        FlowEventV2::OperationCompleted(CompletedOperationV2::Plain),
        ScreenKindV2::Validation,
    );
    match flow
        .apply(FlowEventV2::OperationCompleted(
            CompletedOperationV2::Review(review_ready()),
        ))
        .expect("registered v2 review transition")
    {
        FlowApplyOutcomeV2::Review(session) => session,
        FlowApplyOutcomeV2::Continue(_)
        | FlowApplyOutcomeV2::Rejected(_)
        | FlowApplyOutcomeV2::ProvisioningResult(_)
        | FlowApplyOutcomeV2::TransactionResult(_)
        | FlowApplyOutcomeV2::CompletedWiped
        | FlowApplyOutcomeV2::DeferredWiped(_)
        | FlowApplyOutcomeV2::FailedWiped(_) => panic!("review capability was not retained"),
    }
}

fn approve_normal_flow() -> (ScreenFlowV2, Vec<ScreenKindV2>) {
    let mut flow = ScreenFlowV2::new(FlowKindV2::A1B);
    let mut session = start_normal_review(&mut flow);
    let mut views = Vec::new();
    loop {
        let kind = session
            .screen()
            .expect("bound schema-v3 review screen")
            .kind();
        views.push(kind);
        if kind == ScreenKindV2::FinalApproval {
            break;
        }
        session = match session
            .apply(FlowEventV2::Key(KeypadKey::EqualsConfirmEnter))
            .expect("active schema-v3 review")
        {
            ReviewSessionOutcomeV2::Continue(next) => next,
            ReviewSessionOutcomeV2::Released(_) => panic!("review path skipped a bound fact"),
        };
        assert!(views.len() < 64, "bounded review topology");
    }
    assert_eq!(
        views,
        vec![
            ScreenKindV2::ReviewOverview,
            ScreenKindV2::ReviewArithmetic,
            ScreenKindV2::ReviewRecipient,
            ScreenKindV2::ReviewRecipient,
            ScreenKindV2::ReviewChange,
            ScreenKindV2::ReviewOpReturn,
            ScreenKindV2::ReviewLocktime,
            ScreenKindV2::ReviewSequence,
            ScreenKindV2::ReviewFeePolicy,
            ScreenKindV2::FinalApproval,
        ]
    );
    session = match session
        .apply(FlowEventV2::ApprovalHoldStarted)
        .expect("final-review approval hold")
    {
        ReviewSessionOutcomeV2::Continue(next) => next,
        ReviewSessionOutcomeV2::Released(_) => panic!("approval hold did not remain scoped"),
    };
    let token = session
        .pending_hold_token()
        .expect("opaque current-cycle token");
    match session
        .apply(FlowEventV2::ApprovalHoldCompleted(token))
        .expect("completed approval hold")
    {
        ReviewSessionOutcomeV2::Released(ScopedApplyOutcomeV2::Released(
            ScreenKindV2::AwaitingSigning,
        )) => {}
        ReviewSessionOutcomeV2::Continue(_)
        | ReviewSessionOutcomeV2::Released(
            ScopedApplyOutcomeV2::Continue(_)
            | ScopedApplyOutcomeV2::Released(_)
            | ScopedApplyOutcomeV2::CompletedWiped
            | ScopedApplyOutcomeV2::DeferredWiped(_)
            | ScopedApplyOutcomeV2::FailedWiped(_),
        ) => panic!("approval reached wrong category"),
    }
    let identity = flow.approval_identity().expect("bound approval identity");
    assert_eq!(identity.review_hash(), review_ready().review_hash());
    assert_eq!(flow.screen_kind(), Some(ScreenKindV2::AwaitingSigning));
    (flow, views)
}

fn normal_oracle(no_yield_selector: u8) -> (Vec<ScreenKindV2>, RootSnapshot) {
    let mut no_skip = ScreenFlowV2::new(FlowKindV2::A1B);
    expect_failure(
        &mut no_skip,
        FlowEventV2::ApprovalHoldStarted,
        WipingReasonV2::ReviewIncomplete,
    );

    let (mut flow, views) = approve_normal_flow();
    let yields = [
        FlowEventV2::TransportPresented,
        FlowEventV2::CameraPresented,
        FlowEventV2::IntakePresented,
        FlowEventV2::PsbtPresented,
        FlowEventV2::A1Presented,
        FlowEventV2::BbqrTransactionPresented,
        FlowEventV2::CoordinatorPresented,
    ];
    expect_failure(
        &mut flow,
        yields[usize::from(no_yield_selector) % yields.len()],
        WipingReasonV2::PostApprovalYield,
    );
    (views, snapshot(&flow))
}

fn keypad(selector: u8) -> KeypadKey {
    match selector % 19 {
        0 => KeypadKey::Seven,
        1 => KeypadKey::EightUp,
        2 => KeypadKey::Nine,
        3 => KeypadKey::CeDelete,
        4 => KeypadKey::CancelBack,
        5 => KeypadKey::FourLeft,
        6 => KeypadKey::Five,
        7 => KeypadKey::SixRight,
        8 => KeypadKey::Multiply,
        9 => KeypadKey::Divide,
        10 => KeypadKey::One,
        11 => KeypadKey::TwoDown,
        12 => KeypadKey::Three,
        13 => KeypadKey::Minus,
        14 => KeypadKey::Percent,
        15 => KeypadKey::Zero,
        16 => KeypadKey::Decimal,
        17 => KeypadKey::Plus,
        18 => KeypadKey::EqualsConfirmEnter,
        _ => unreachable!("modulo nineteen is exhaustive"),
    }
}

fn symbolic_event(selector: u8) -> FlowEventV2<'static> {
    match selector % 43 {
        0..=18 => FlowEventV2::Key(keypad(selector)),
        19 => FlowEventV2::OperationCompleted(CompletedOperationV2::Plain),
        20 => FlowEventV2::OperationFailed,
        21 => FlowEventV2::CeremonyCommitmentReady([selector; 32]),
        22 => FlowEventV2::SelectSpareB(SpareBChoiceV2::NoSpare),
        23 => FlowEventV2::SelectSpareB(SpareBChoiceV2::ProvisionSpare),
        24 => FlowEventV2::TransportPresented,
        25 => FlowEventV2::CameraPresented,
        26 => FlowEventV2::IntakePresented,
        27 => FlowEventV2::PsbtPresented,
        28 => FlowEventV2::A1Presented,
        29 => FlowEventV2::BbqrTransactionPresented,
        30 => FlowEventV2::CoordinatorPresented,
        31 => FlowEventV2::MediaRemoved,
        32 => FlowEventV2::ApprovalHoldStarted,
        33 => FlowEventV2::SelectKitDoor(KitDoorV2::KitSpend),
        34 => FlowEventV2::SelectKitDoor(KitDoorV2::KitRestore),
        35 => FlowEventV2::KitShareAccepted,
        36 => FlowEventV2::KitSpendTransactionPresented,
        37 => FlowEventV2::KitSpendValidated,
        38 => FlowEventV2::CoordinatorUtxoCompletenessConfirmed,
        39 => FlowEventV2::CardRemoved,
        40 => FlowEventV2::SessionTimeout,
        41 => FlowEventV2::Shutdown,
        42 => FlowEventV2::PowerLoss,
        _ => unreachable!("modulo forty-three is exhaustive"),
    }
}

fn random_trace(data: &[u8]) -> Vec<RootSnapshot> {
    let kind = match data.first().copied().unwrap_or(0) % 3 {
        0 => FlowKindV2::Setup,
        1 => FlowKindV2::A1B,
        2 => FlowKindV2::Kit,
        _ => unreachable!("modulo three is exhaustive"),
    };
    let mut flow = ScreenFlowV2::new(kind);
    let mut snapshots = vec![snapshot(&flow)];
    for selector in data.iter().copied().skip(1).take(MAX_EVENTS) {
        let event = symbolic_event(selector);
        match flow.apply(event) {
            Ok(FlowApplyOutcomeV2::Continue(_))
            | Ok(FlowApplyOutcomeV2::Rejected(StatePreservingRejectionV2::DiceGridUnavailable))
            | Ok(FlowApplyOutcomeV2::CompletedWiped)
            | Ok(FlowApplyOutcomeV2::DeferredWiped(_))
            | Ok(FlowApplyOutcomeV2::FailedWiped(_)) => {}
            Ok(
                FlowApplyOutcomeV2::ProvisioningResult(_)
                | FlowApplyOutcomeV2::Review(_)
                | FlowApplyOutcomeV2::TransactionResult(_),
            ) => panic!("symbolic event minted an unpresented fact capability"),
            Err(_) => break,
        }
        snapshots.push(snapshot(&flow));
        if let Some(FlowTerminalV2::FailedWiped(reason)) = flow.terminal() {
            assert_named_reason(reason);
        }
        if flow.is_finished() {
            assert!(
                flow.apply(event).is_err(),
                "terminal accepted another event"
            );
            break;
        }
    }
    snapshots
}

fn run_once(data: &[u8]) -> CampaignSnapshot {
    let selectors = [
        data.first().copied().unwrap_or(0),
        data.get(1).copied().unwrap_or(0),
        data.get(2).copied().unwrap_or(0),
    ];
    door_lock_oracle();
    scanner_mode_oracle(selectors[1]);
    restore_rejection_oracles();
    let (normal_views, normal_terminal) = normal_oracle(selectors[2]);
    CampaignSnapshot {
        setup: setup_oracle(selectors[0]),
        normal_views,
        normal_terminal,
        kit_spend: kit_spend_oracle(),
        kit_restore: kit_restore_oracle(selectors[0]),
        random: random_trace(data),
    }
}

fuzz_target!(|data: &[u8]| {
    if data.len() > MAX_EVENTS + 1 {
        return;
    }
    let first = run_once(data);
    let second = run_once(data);
    assert_eq!(first, second, "v2 screen outcomes must be stable");
});
