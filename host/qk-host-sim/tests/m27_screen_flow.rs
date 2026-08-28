//! M27 scoped screen-flow tests over existing public NEVER-FUND fixtures.

use qk_descriptor::parse_descriptor_pair;
use qk_host_sim::{
    ApprovalIdentity, CeremonyPurpose, CeremonySessionOutcome, CompletedOperation,
    EntropyInputMode, ExportArtifactKind, ExportArtifacts, FactorRole, FlowApplyOutcome, FlowEvent,
    FlowKind, FlowTerminal, KeypadKey, KitTier, RecipientFactView, ReviewReady,
    ReviewReadyWorkflow, ReviewSession, ReviewSessionOutcome, ScopedApplyOutcome, Screen,
    ScreenFlow, ScreenKind, TierArtifacts, WipingReason,
};
use qk_provisioning::ProvisioningArtifacts;
use qk_psbt::{InputSource, ReviewV2OutputOwnership};

const REVIEW_FIXTURE: &str = include_str!("../../qk-psbt/tests/fixtures/review_v2.txt");
const DESCRIPTOR_FIXTURE: &str =
    include_str!("../../qk-psbt/tests/fixtures/descriptor_ownership.txt");
const EXPORT_FIXTURE: &[u8] = include_bytes!("fixtures/m25_export.txt");

static PROVISIONING_FACTS: ProvisioningArtifacts = ProvisioningArtifacts {
    account_xpubs: [[0x11; 111], [0x22; 111], [0x33; 111]],
    descriptors: [[0x44; 445], [0x55; 445]],
    wallet_id: [0x66; 32],
    first_scripts: [[0x77; 34], [0x88; 34]],
    first_addresses: [[0x99; 62], [0xaa; 62]],
    a1_capsule: [0xbb; 67],
};

fn field<'a>(text: &'a str, name: &str) -> &'a str {
    text.lines()
        .find_map(|line| line.strip_prefix(name))
        .expect("fixture field")
}

fn export_field(name: &str) -> &'static str {
    EXPORT_FIXTURE
        .split(|byte| *byte == b'\n')
        .find_map(|line| {
            core::str::from_utf8(line)
                .expect("UTF-8 fixture")
                .strip_prefix(&format!("{name}: "))
        })
        .expect("M25 fixture field")
}

fn hex(value: &str) -> Vec<u8> {
    assert!(value.len().is_multiple_of(2));
    value
        .as_bytes()
        .chunks_exact(2)
        .map(|pair| {
            u8::from_str_radix(core::str::from_utf8(pair).expect("ASCII"), 16).expect("hex")
        })
        .collect()
}

fn review_workflow() -> ReviewReadyWorkflow {
    let descriptor = parse_descriptor_pair(
        field(DESCRIPTOR_FIXTURE, "receive: ").as_bytes(),
        field(DESCRIPTOR_FIXTURE, "change: ").as_bytes(),
    )
    .expect("M23 descriptor");
    let s0 = hex(field(REVIEW_FIXTURE, "s0_hex: "));
    ready_workflow(descriptor, &s0)
}

fn export_workflow() -> ReviewReadyWorkflow {
    let descriptor = parse_descriptor_pair(
        export_field("receive_descriptor").as_bytes(),
        export_field("change_descriptor").as_bytes(),
    )
    .expect("M25 descriptor");
    let s0 = hex(export_field("initial_psbt_hex"));
    ready_workflow(descriptor, &s0)
}

fn ready_workflow(descriptor: qk_descriptor::DescriptorPair, s0: &[u8]) -> ReviewReadyWorkflow {
    let mut workflow = ReviewReadyWorkflow::new(descriptor).expect("workflow");
    workflow.intake(s0, InputSource::MicroSd).expect("intake");
    workflow.wake().expect("wake");
    workflow.begin_validation().expect("begin validation");
    workflow.validate().expect("validation");
    workflow.construct_review().expect("review");
    workflow
}

fn export_artifacts(tier: KitTier) -> ExportArtifacts {
    let finalized = export_workflow()
        .sign_and_finalize_m24(Vec::new(), &[])
        .expect("threshold-complete public fixture");
    ExportArtifacts::from_finalized(finalized, tier).expect("export facts")
}

fn root_continue(flow: &mut ScreenFlow, event: FlowEvent<'_>, expected: ScreenKind) {
    match flow.apply(event).expect("live flow") {
        FlowApplyOutcome::Continue(actual) => assert_eq!(actual, expected),
        _ => panic!("expected root continuation"),
    }
    assert_eq!(flow.screen_kind(), Some(expected));
    assert_eq!(flow.screen().expect("typed root screen").kind(), expected);
}

fn enter(flow: &mut ScreenFlow, expected: ScreenKind) {
    root_continue(
        flow,
        FlowEvent::Key(KeypadKey::EqualsConfirmEnter),
        expected,
    );
}

fn open_review<'flow, 'facts>(
    flow: &'flow mut ScreenFlow,
    ready: &'facts ReviewReady,
) -> ReviewSession<'flow, 'facts> {
    enter(flow, ScreenKind::Route);
    enter(flow, ScreenKind::Transport);
    root_continue(flow, FlowEvent::TransportPresented, ScreenKind::Intake);
    root_continue(flow, FlowEvent::IntakePresented, ScreenKind::Factor);
    root_continue(
        flow,
        FlowEvent::OperationCompleted(CompletedOperation::Plain),
        ScreenKind::Factor,
    );
    root_continue(
        flow,
        FlowEvent::OperationCompleted(CompletedOperation::Plain),
        ScreenKind::Validation,
    );
    match flow
        .apply(FlowEvent::OperationCompleted(CompletedOperation::Review(
            ready,
        )))
        .expect("open review")
    {
        FlowApplyOutcome::Review(session) => session,
        _ => panic!("expected review session"),
    }
}

fn review_enter<'flow, 'facts>(
    session: ReviewSession<'flow, 'facts>,
    expected: ScreenKind,
) -> ReviewSession<'flow, 'facts> {
    match session
        .apply(FlowEvent::Key(KeypadKey::EqualsConfirmEnter))
        .expect("review event")
    {
        ReviewSessionOutcome::Continue(next) => {
            assert_eq!(next.screen().expect("review screen").kind(), expected);
            next
        }
        ReviewSessionOutcome::Released(_) => panic!("review released early"),
    }
}

fn visit_review<'flow, 'facts>(
    mut session: ReviewSession<'flow, 'facts>,
) -> ReviewSession<'flow, 'facts> {
    match session.screen().expect("overview") {
        Screen::ReviewOverview(view) => {
            assert_eq!(view.total_input_amount(), 1_000_000);
        }
        _ => panic!("overview view"),
    }
    session = review_enter(session, ScreenKind::ReviewArithmetic);
    session = review_enter(session, ScreenKind::ReviewRecipient);
    match session.screen().expect("self transfer") {
        Screen::ReviewRecipient(view) => {
            assert_eq!(view.index(), 1);
            assert!(matches!(
                view.recipient(),
                RecipientFactView::SelfTransfer { .. }
            ));
        }
        _ => panic!("recipient view"),
    }
    session = review_enter(session, ScreenKind::ReviewRecipient);
    match session.screen().expect("external recipient") {
        Screen::ReviewRecipient(view) => {
            assert_eq!(view.index(), 2);
            assert!(matches!(
                view.recipient(),
                RecipientFactView::External { .. }
            ));
        }
        _ => panic!("recipient view"),
    }
    session = review_enter(session, ScreenKind::ReviewChange);
    assert!(matches!(session.screen(), Some(Screen::ReviewChange(view)) if view.index() == 0));
    session = review_enter(session, ScreenKind::ReviewOpReturn);
    assert!(
        matches!(session.screen(), Some(Screen::ReviewOpReturn(view)) if view.index() == 3 && view.payload() == [0xaa, 0xbb, 0xcc])
    );
    session = review_enter(session, ScreenKind::ReviewLocktime);
    session = review_enter(session, ScreenKind::ReviewSequence);
    session = review_enter(session, ScreenKind::ReviewFeePolicy);
    match session.screen().expect("fee view") {
        Screen::ReviewFeePolicy(view) => {
            assert_eq!(view.fee(), 100_000);
            assert_eq!(view.warnings().count(), 2);
        }
        _ => panic!("fee view"),
    }
    review_enter(session, ScreenKind::FinalApproval)
}

fn approve<'flow, 'facts>(
    session: ReviewSession<'flow, 'facts>,
    expected: ScreenKind,
) -> (qk_host_sim::ApprovalToken, [u8; 32]) {
    let session = match session
        .apply(FlowEvent::ApprovalHoldStarted)
        .expect("hold start")
    {
        ReviewSessionOutcome::Continue(session) => session,
        ReviewSessionOutcome::Released(_) => panic!("hold start released"),
    };
    let token = session.pending_hold_token().expect("pending token");
    let review_hash = match session.screen().expect("approval view") {
        Screen::FinalApproval(view) => view.review_hash(),
        _ => panic!("approval view"),
    };
    match session
        .apply(FlowEvent::ApprovalHoldCompleted(token))
        .expect("hold complete")
    {
        ReviewSessionOutcome::Released(ScopedApplyOutcome::Released(actual)) => {
            assert_eq!(actual, expected)
        }
        _ => panic!("approval did not release"),
    }
    (token, review_hash)
}

#[test]
fn entropy_mode_selection_is_typed_and_manual_entry_is_scoped() {
    let mut flow = ScreenFlow::new(FlowKind::Provisioning);
    enter(&mut flow, ScreenKind::TierSelection);
    enter(&mut flow, ScreenKind::EntropyModeSelection);
    assert!(matches!(
        flow.screen(),
        Some(Screen::EntropyModeSelection {
            selected: EntropyInputMode::DiceGrid
        })
    ));

    root_continue(
        &mut flow,
        FlowEvent::Key(KeypadKey::SixRight),
        ScreenKind::EntropyModeSelection,
    );
    root_continue(
        &mut flow,
        FlowEvent::Key(KeypadKey::SixRight),
        ScreenKind::EntropyModeSelection,
    );
    assert!(matches!(
        flow.screen(),
        Some(Screen::EntropyModeSelection {
            selected: EntropyInputMode::ManualKeypad
        })
    ));

    root_continue(
        &mut flow,
        FlowEvent::Key(KeypadKey::CancelBack),
        ScreenKind::TierSelection,
    );
    enter(&mut flow, ScreenKind::EntropyModeSelection);
    assert!(matches!(
        flow.screen(),
        Some(Screen::EntropyModeSelection {
            selected: EntropyInputMode::ManualKeypad
        })
    ));
    enter(&mut flow, ScreenKind::CeremonyInput);
    assert!(matches!(
        flow.screen(),
        Some(Screen::CeremonyInput {
            purpose: CeremonyPurpose::SeedA,
            mode: EntropyInputMode::ManualKeypad
        })
    ));

    assert!(matches!(
        flow.apply(FlowEvent::Key(KeypadKey::CancelBack)),
        Ok(FlowApplyOutcome::FailedWiped(WipingReason::Cancelled))
    ));

    let mut flow = ScreenFlow::new(FlowKind::Provisioning);
    enter(&mut flow, ScreenKind::TierSelection);
    enter(&mut flow, ScreenKind::EntropyModeSelection);
    root_continue(
        &mut flow,
        FlowEvent::Key(KeypadKey::FourLeft),
        ScreenKind::EntropyModeSelection,
    );
    root_continue(
        &mut flow,
        FlowEvent::Key(KeypadKey::FourLeft),
        ScreenKind::EntropyModeSelection,
    );
    assert!(matches!(
        flow.screen(),
        Some(Screen::EntropyModeSelection {
            selected: EntropyInputMode::DiceGrid
        })
    ));
}

#[test]
fn ceremony_scope_releases_exact_unit_before_commitment() {
    let mut flow = ScreenFlow::new(FlowKind::Provisioning);
    enter(&mut flow, ScreenKind::TierSelection);
    enter(&mut flow, ScreenKind::EntropyModeSelection);
    enter(&mut flow, ScreenKind::CeremonyInput);

    let mut unit = b"public transient unit".to_vec();
    let session = match flow
        .apply(FlowEvent::CeremonyEchoReady(&unit))
        .expect("echo scope")
    {
        FlowApplyOutcome::Ceremony(session) => session,
        _ => panic!("expected ceremony session"),
    };
    assert!(
        matches!(session.screen(), Screen::CeremonyEcho { unit: view, .. } if core::ptr::eq(view.bytes(), unit.as_slice()))
    );
    let session = match session
        .apply(FlowEvent::Key(KeypadKey::EqualsConfirmEnter))
        .expect("echo acknowledgement")
    {
        CeremonySessionOutcome::Continue(session) => session,
        CeremonySessionOutcome::Released(_) => panic!("released before confirmation"),
    };
    assert!(
        matches!(session.screen(), Screen::CeremonyConfirm { unit: Some(view), .. } if core::ptr::eq(view.bytes(), unit.as_slice()))
    );
    assert!(matches!(
        session
            .apply(FlowEvent::Key(KeypadKey::EqualsConfirmEnter))
            .expect("explicit confirmation"),
        CeremonySessionOutcome::Released(ScopedApplyOutcome::Released(ScreenKind::CeremonyConfirm))
    ));

    // This mutation compiles and runs before the root flow advances: no unit
    // borrow remains after explicit confirmation.
    unit.fill(0);
    assert!(matches!(
        flow.screen(),
        Some(Screen::CeremonyConfirm { unit: None, .. })
    ));
    let commitment = [0x5a; 32];
    root_continue(
        &mut flow,
        FlowEvent::CeremonyCommitmentReady(commitment),
        ScreenKind::CeremonyCommitment,
    );
    assert!(
        matches!(flow.screen(), Some(Screen::CeremonyCommitment { commitment: view, .. }) if view.bytes() == &commitment)
    );
}

fn finish_one_ceremony(flow: &mut ScreenFlow, unit: &[u8], commitment: [u8; 32]) {
    let session = match flow
        .apply(FlowEvent::CeremonyEchoReady(unit))
        .expect("echo session")
    {
        FlowApplyOutcome::Ceremony(session) => session,
        _ => panic!("echo session"),
    };
    let session = match session
        .apply(FlowEvent::Key(KeypadKey::EqualsConfirmEnter))
        .expect("echo to confirm")
    {
        CeremonySessionOutcome::Continue(session) => session,
        _ => panic!("confirm session"),
    };
    assert!(matches!(
        session
            .apply(FlowEvent::Key(KeypadKey::EqualsConfirmEnter))
            .expect("confirm release"),
        CeremonySessionOutcome::Released(ScopedApplyOutcome::Released(ScreenKind::CeremonyConfirm))
    ));
    root_continue(
        flow,
        FlowEvent::CeremonyCommitmentReady(commitment),
        ScreenKind::CeremonyCommitment,
    );
}

#[test]
fn provisioning_path_scopes_result_facts_and_completes_wiped() {
    let mut flow = ScreenFlow::new(FlowKind::Provisioning);
    enter(&mut flow, ScreenKind::TierSelection);
    enter(&mut flow, ScreenKind::EntropyModeSelection);
    enter(&mut flow, ScreenKind::CeremonyInput);
    for (index, purpose) in [
        CeremonyPurpose::SeedA,
        CeremonyPurpose::SignerB,
        CeremonyPurpose::SignerC,
        CeremonyPurpose::A2,
    ]
    .into_iter()
    .enumerate()
    {
        assert!(
            matches!(flow.screen(), Some(Screen::CeremonyInput { purpose: actual, .. }) if actual == purpose)
        );
        finish_one_ceremony(&mut flow, b"obviously public unit", [index as u8; 32]);
        enter(
            &mut flow,
            if index == 3 {
                ScreenKind::DerivationExplanation
            } else {
                ScreenKind::CeremonyInput
            },
        );
    }

    let result = match flow
        .apply(FlowEvent::OperationCompleted(
            CompletedOperation::Provisioning(&PROVISIONING_FACTS),
        ))
        .expect("provisioning result")
    {
        FlowApplyOutcome::ProvisioningResult(session) => session,
        _ => panic!("result scope"),
    };
    match result.screen() {
        Screen::ProvisioningResult(view) => {
            assert_eq!(view.wallet_id(), PROVISIONING_FACTS.wallet_id);
        }
        _ => panic!("provisioning result view"),
    }
    assert_eq!(
        result
            .apply(FlowEvent::Key(KeypadKey::EqualsConfirmEnter))
            .expect("result release"),
        ScopedApplyOutcome::Released(ScreenKind::ProvisionB)
    );
    for expected in [
        ScreenKind::VerifyB,
        ScreenKind::ProvisionC,
        ScreenKind::VerifyC,
        ScreenKind::CreateA1,
        ScreenKind::ScanBackA1,
        ScreenKind::CoordinatorMaterial,
        ScreenKind::Rehearsal,
        ScreenKind::KitReady,
    ] {
        root_continue(
            &mut flow,
            FlowEvent::OperationCompleted(CompletedOperation::Plain),
            expected,
        );
    }
    assert!(matches!(
        flow.apply(FlowEvent::Key(KeypadKey::EqualsConfirmEnter))
            .expect("kit complete"),
        FlowApplyOutcome::CompletedWiped
    ));
    assert_eq!(flow.terminal(), Some(FlowTerminal::CompletedWiped));
    assert!(matches!(
        flow.apply(FlowEvent::SessionTimeout),
        Err(qk_host_sim::FlowFinished)
    ));
}

#[test]
fn all_transaction_routes_bind_token_then_scope_exact_result_facts() {
    for (flow_kind, tier) in [
        (FlowKind::SigningA1B, KitTier::SimpleRecovery),
        (FlowKind::RecoveryA1C, KitTier::Inheritance),
        (FlowKind::RecoveryBC, KitTier::QuantumShelter),
    ] {
        let review_owner = review_workflow();
        let ready = review_owner.review_ready().expect("review ready");
        let export = export_artifacts(tier);
        let mut flow = ScreenFlow::new(flow_kind);
        let review = visit_review(open_review(&mut flow, ready));
        let expected_after_hold = if flow_kind == FlowKind::RecoveryBC {
            ScreenKind::PostApprovalFactor
        } else {
            ScreenKind::AwaitingSigning
        };
        let (token, review_hash) = approve(review, expected_after_hold);
        let identity = flow.approval_identity().expect("approval identity");
        assert!(identity.token() == token);
        assert_eq!(identity.review_hash(), review_hash);

        if flow_kind == FlowKind::RecoveryBC {
            assert!(matches!(
                flow.screen(),
                Some(Screen::PostApprovalFactor {
                    role: qk_host_sim::FactorRole::SignerB
                })
            ));
            root_continue(
                &mut flow,
                FlowEvent::OperationCompleted(CompletedOperation::Plain),
                ScreenKind::PostApprovalFactor,
            );
            assert!(matches!(
                flow.screen(),
                Some(Screen::PostApprovalFactor {
                    role: qk_host_sim::FactorRole::SignerC
                })
            ));
            root_continue(
                &mut flow,
                FlowEvent::OperationCompleted(CompletedOperation::Plain),
                ScreenKind::AwaitingSigning,
            );
        }
        root_continue(
            &mut flow,
            FlowEvent::SigningOutcome { identity },
            ScreenKind::Export,
        );
        let result = match flow
            .apply(FlowEvent::OperationCompleted(CompletedOperation::Export(
                &export,
            )))
            .expect("result scope")
        {
            FlowApplyOutcome::TransactionResult(session) => session,
            _ => panic!("transaction result scope"),
        };
        match (result.screen(), export.artifacts()) {
            (
                Screen::TransactionResult(view),
                TierArtifacts::SimpleRecovery {
                    finalized_psbt,
                    raw_transaction,
                }
                | TierArtifacts::Inheritance {
                    finalized_psbt,
                    raw_transaction,
                },
            ) => {
                assert_eq!(view.finalized_psbt(), Some(finalized_psbt.metadata()));
                assert_eq!(view.raw_transaction(), raw_transaction.metadata());
                assert_eq!(
                    view.finalized_psbt().expect("PSBT").kind(),
                    ExportArtifactKind::FinalizedPsbt
                );
            }
            (
                Screen::TransactionResult(view),
                TierArtifacts::QuantumShelter { raw_transaction },
            ) => {
                assert_eq!(view.finalized_psbt(), None);
                assert_eq!(view.raw_transaction(), raw_transaction.metadata());
            }
            _ => panic!("wrong result view"),
        }
        let outcome = result
            .apply(FlowEvent::Key(KeypadKey::EqualsConfirmEnter))
            .expect("result acknowledgement");
        if flow_kind == FlowKind::SigningA1B {
            assert_eq!(outcome, ScopedApplyOutcome::CompletedWiped);
        } else {
            assert_eq!(
                outcome,
                ScopedApplyOutcome::Released(ScreenKind::RecoveryRotation)
            );
            assert!(matches!(
                flow.apply(FlowEvent::Key(KeypadKey::EqualsConfirmEnter))
                    .expect("rotation acknowledgement"),
                FlowApplyOutcome::CompletedWiped
            ));
        }
        assert_eq!(flow.terminal(), Some(FlowTerminal::CompletedWiped));
        assert!(matches!(
            flow.apply(FlowEvent::SessionTimeout),
            Err(qk_host_sim::FlowFinished)
        ));
    }
}

fn visit_to_final<'flow, 'facts>(
    mut session: ReviewSession<'flow, 'facts>,
) -> ReviewSession<'flow, 'facts> {
    while session.screen().expect("review screen").kind() != ScreenKind::FinalApproval {
        session = match session
            .apply(FlowEvent::Key(KeypadKey::EqualsConfirmEnter))
            .expect("review advance")
        {
            ReviewSessionOutcome::Continue(session) => session,
            ReviewSessionOutcome::Released(_) => panic!("review released early"),
        };
    }
    session
}

#[test]
fn review_scope_releases_workflow_for_immediate_m24_consumption() {
    let workflow = export_workflow();
    let mut flow = ScreenFlow::new(FlowKind::SigningA1B);
    {
        let ready = workflow.review_ready().expect("M25 ready");
        let review = visit_to_final(open_review(&mut flow, ready));
        let _ = approve(review, ScreenKind::AwaitingSigning);
    }
    assert!(flow.approval_identity().is_some());
    let finalized = workflow
        .sign_and_finalize_m24(Vec::new(), &[])
        .expect("ReviewReady owner is consumable after scoped approval");
    assert!(!finalized.raw_transaction().is_empty());
}

#[test]
fn foreign_hold_completion_is_identity_mismatch_and_abandoned_scope_wipes() {
    let owner = review_workflow();
    let ready = owner.review_ready().expect("ready");
    let mut first_flow = ScreenFlow::new(FlowKind::SigningA1B);
    let mut second_flow = ScreenFlow::new(FlowKind::SigningA1B);
    let first = visit_review(open_review(&mut first_flow, ready));
    let second = visit_review(open_review(&mut second_flow, ready));
    let first = match first
        .apply(FlowEvent::ApprovalHoldStarted)
        .expect("first hold")
    {
        ReviewSessionOutcome::Continue(session) => session,
        _ => panic!("first hold"),
    };
    let second = match second
        .apply(FlowEvent::ApprovalHoldStarted)
        .expect("second hold")
    {
        ReviewSessionOutcome::Continue(session) => session,
        _ => panic!("second hold"),
    };
    let foreign = second.pending_hold_token().expect("foreign token");
    assert!(first.pending_hold_token().expect("first token") != foreign);
    assert!(matches!(
        first
            .apply(FlowEvent::ApprovalHoldCompleted(foreign))
            .expect("foreign completion"),
        ReviewSessionOutcome::Released(ScopedApplyOutcome::FailedWiped(
            WipingReason::ReviewIdentityMismatch
        ))
    ));
    assert_eq!(
        first_flow.terminal(),
        Some(FlowTerminal::FailedWiped(
            WipingReason::ReviewIdentityMismatch
        ))
    );

    // Dropping a still-active review scope is itself a closed cancellation.
    drop(second);
    assert_eq!(
        second_flow.terminal(),
        Some(FlowTerminal::FailedWiped(WipingReason::Cancelled))
    );
}

#[test]
fn postapproval_no_yield_and_universal_session_interrupts_are_named() {
    for event in [
        FlowEvent::TransportPresented,
        FlowEvent::CameraPresented,
        FlowEvent::IntakePresented,
    ] {
        let owner = review_workflow();
        let ready = owner.review_ready().expect("ready");
        let mut flow = ScreenFlow::new(FlowKind::SigningA1B);
        let review = visit_review(open_review(&mut flow, ready));
        let _ = approve(review, ScreenKind::AwaitingSigning);
        assert!(matches!(
            flow.apply(event).expect("postapproval event"),
            FlowApplyOutcome::FailedWiped(WipingReason::PostApprovalYield)
        ));
        assert!(flow.approval_identity().is_none());
    }

    for (event, reason) in [
        (FlowEvent::CardRemoved, WipingReason::CardRemoved),
        (FlowEvent::SessionTimeout, WipingReason::SessionTimeout),
    ] {
        let mut flow = ScreenFlow::new(FlowKind::Provisioning);
        enter(&mut flow, ScreenKind::TierSelection);
        enter(&mut flow, ScreenKind::EntropyModeSelection);
        enter(&mut flow, ScreenKind::CeremonyInput);
        let session = match flow
            .apply(FlowEvent::CeremonyEchoReady(b"public interruption unit"))
            .expect("ceremony scope")
        {
            FlowApplyOutcome::Ceremony(session) => session,
            _ => panic!("ceremony scope"),
        };
        assert!(matches!(
            session.apply(event).expect("session interruption"),
            CeremonySessionOutcome::Released(ScopedApplyOutcome::FailedWiped(actual))
                if actual == reason
        ));
        assert_eq!(flow.terminal(), Some(FlowTerminal::FailedWiped(reason)));
    }
}

const ALL_KEYS: [KeypadKey; 19] = [
    KeypadKey::Seven,
    KeypadKey::EightUp,
    KeypadKey::Nine,
    KeypadKey::CeDelete,
    KeypadKey::CancelBack,
    KeypadKey::FourLeft,
    KeypadKey::Five,
    KeypadKey::SixRight,
    KeypadKey::Multiply,
    KeypadKey::Divide,
    KeypadKey::One,
    KeypadKey::TwoDown,
    KeypadKey::Three,
    KeypadKey::Minus,
    KeypadKey::Percent,
    KeypadKey::Zero,
    KeypadKey::Decimal,
    KeypadKey::Plus,
    KeypadKey::EqualsConfirmEnter,
];

#[derive(Clone, Copy, Debug)]
enum EventCase {
    Key(KeypadKey),
    OperationCompleted,
    OperationFailed,
    CeremonyEchoReady,
    CeremonyCommitmentReady,
    TransportPresented,
    CameraPresented,
    IntakePresented,
    MediaRemoved,
    ApprovalHoldStarted,
    ApprovalHoldCompleted,
    ForeignHoldCompletion,
    SigningOutcome,
    ForeignSigningOutcome,
    CardRemoved,
    SessionTimeout,
    Shutdown,
    Restart,
    PowerLoss,
}

fn event_cases() -> Vec<EventCase> {
    let mut cases = ALL_KEYS.into_iter().map(EventCase::Key).collect::<Vec<_>>();
    cases.extend([
        EventCase::OperationCompleted,
        EventCase::OperationFailed,
        EventCase::CeremonyEchoReady,
        EventCase::CeremonyCommitmentReady,
        EventCase::TransportPresented,
        EventCase::CameraPresented,
        EventCase::IntakePresented,
        EventCase::MediaRemoved,
        EventCase::ApprovalHoldStarted,
        EventCase::ApprovalHoldCompleted,
        EventCase::ForeignHoldCompletion,
        EventCase::SigningOutcome,
        EventCase::ForeignSigningOutcome,
        EventCase::CardRemoved,
        EventCase::SessionTimeout,
        EventCase::Shutdown,
        EventCase::Restart,
        EventCase::PowerLoss,
    ]);
    cases
}

fn event_for(
    case: EventCase,
    token: qk_host_sim::ApprovalToken,
    identity: ApprovalIdentity,
    foreign_identity: ApprovalIdentity,
) -> FlowEvent<'static> {
    match case {
        EventCase::Key(key) => FlowEvent::Key(key),
        EventCase::OperationCompleted => FlowEvent::OperationCompleted(CompletedOperation::Plain),
        EventCase::OperationFailed => FlowEvent::OperationFailed,
        EventCase::CeremonyEchoReady => FlowEvent::CeremonyEchoReady(b"matrix public unit"),
        EventCase::CeremonyCommitmentReady => FlowEvent::CeremonyCommitmentReady([0x42; 32]),
        EventCase::TransportPresented => FlowEvent::TransportPresented,
        EventCase::CameraPresented => FlowEvent::CameraPresented,
        EventCase::IntakePresented => FlowEvent::IntakePresented,
        EventCase::MediaRemoved => FlowEvent::MediaRemoved,
        EventCase::ApprovalHoldStarted => FlowEvent::ApprovalHoldStarted,
        EventCase::ApprovalHoldCompleted => FlowEvent::ApprovalHoldCompleted(token),
        EventCase::ForeignHoldCompletion => {
            FlowEvent::ApprovalHoldCompleted(foreign_identity.token())
        }
        EventCase::SigningOutcome => FlowEvent::SigningOutcome { identity },
        EventCase::ForeignSigningOutcome => FlowEvent::SigningOutcome {
            identity: foreign_identity,
        },
        EventCase::CardRemoved => FlowEvent::CardRemoved,
        EventCase::SessionTimeout => FlowEvent::SessionTimeout,
        EventCase::Shutdown => FlowEvent::Shutdown,
        EventCase::Restart => FlowEvent::Restart,
        EventCase::PowerLoss => FlowEvent::PowerLoss,
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum OutcomeClass {
    Continue(ScreenKind),
    Scoped(ScreenKind),
    Released(ScreenKind),
    CompletedWiped,
    FailedWiped(WipingReason),
}

fn classify_root(outcome: FlowApplyOutcome<'_, '_>) -> OutcomeClass {
    match outcome {
        FlowApplyOutcome::Continue(kind) => OutcomeClass::Continue(kind),
        FlowApplyOutcome::Ceremony(session) => OutcomeClass::Scoped(session.screen().kind()),
        FlowApplyOutcome::ProvisioningResult(session) => {
            OutcomeClass::Scoped(session.screen().kind())
        }
        FlowApplyOutcome::Review(session) => {
            OutcomeClass::Scoped(session.screen().expect("review screen").kind())
        }
        FlowApplyOutcome::TransactionResult(session) => {
            OutcomeClass::Scoped(session.screen().kind())
        }
        FlowApplyOutcome::CompletedWiped => OutcomeClass::CompletedWiped,
        FlowApplyOutcome::FailedWiped(reason) => OutcomeClass::FailedWiped(reason),
    }
}

fn classify_scoped(outcome: ScopedApplyOutcome) -> OutcomeClass {
    match outcome {
        ScopedApplyOutcome::Continue(kind) => OutcomeClass::Continue(kind),
        ScopedApplyOutcome::Released(kind) => OutcomeClass::Released(kind),
        ScopedApplyOutcome::CompletedWiped => OutcomeClass::CompletedWiped,
        ScopedApplyOutcome::FailedWiped(reason) => OutcomeClass::FailedWiped(reason),
    }
}

const ROOT_SCREEN_KINDS: [ScreenKind; 26] = [
    ScreenKind::ProvisioningStart,
    ScreenKind::TierSelection,
    ScreenKind::EntropyModeSelection,
    ScreenKind::CeremonyInput,
    ScreenKind::CeremonyConfirm,
    ScreenKind::CeremonyCommitment,
    ScreenKind::DerivationExplanation,
    ScreenKind::ProvisionB,
    ScreenKind::VerifyB,
    ScreenKind::ProvisionC,
    ScreenKind::VerifyC,
    ScreenKind::CreateA1,
    ScreenKind::ScanBackA1,
    ScreenKind::CoordinatorMaterial,
    ScreenKind::Rehearsal,
    ScreenKind::KitReady,
    ScreenKind::FlowStart,
    ScreenKind::Route,
    ScreenKind::Transport,
    ScreenKind::Intake,
    ScreenKind::Factor,
    ScreenKind::Validation,
    ScreenKind::PostApprovalFactor,
    ScreenKind::AwaitingSigning,
    ScreenKind::Export,
    ScreenKind::RecoveryRotation,
];

fn release_echo_to_confirm(flow: &mut ScreenFlow) {
    let session = match flow
        .apply(FlowEvent::CeremonyEchoReady(b"matrix public unit"))
        .expect("matrix ceremony")
    {
        FlowApplyOutcome::Ceremony(session) => session,
        _ => panic!("matrix ceremony"),
    };
    let session = match session
        .apply(FlowEvent::Key(KeypadKey::EqualsConfirmEnter))
        .expect("matrix echo")
    {
        CeremonySessionOutcome::Continue(session) => session,
        _ => panic!("matrix confirm"),
    };
    assert!(matches!(
        session
            .apply(FlowEvent::Key(KeypadKey::EqualsConfirmEnter))
            .expect("matrix confirmation"),
        CeremonySessionOutcome::Released(ScopedApplyOutcome::Released(ScreenKind::CeremonyConfirm))
    ));
}

fn provisioning_root_at(target: ScreenKind) -> ScreenFlow {
    let mut flow = ScreenFlow::new(FlowKind::Provisioning);
    if target == ScreenKind::ProvisioningStart {
        return flow;
    }
    enter(&mut flow, ScreenKind::TierSelection);
    if target == ScreenKind::TierSelection {
        return flow;
    }
    enter(&mut flow, ScreenKind::EntropyModeSelection);
    if target == ScreenKind::EntropyModeSelection {
        return flow;
    }
    enter(&mut flow, ScreenKind::CeremonyInput);
    if target == ScreenKind::CeremonyInput {
        return flow;
    }
    if target == ScreenKind::CeremonyConfirm {
        release_echo_to_confirm(&mut flow);
        return flow;
    }
    if target == ScreenKind::CeremonyCommitment {
        release_echo_to_confirm(&mut flow);
        root_continue(
            &mut flow,
            FlowEvent::CeremonyCommitmentReady([0x33; 32]),
            ScreenKind::CeremonyCommitment,
        );
        return flow;
    }
    for index in 0..4 {
        finish_one_ceremony(&mut flow, b"matrix public unit", [0x40 + index; 32]);
        enter(
            &mut flow,
            if index == 3 {
                ScreenKind::DerivationExplanation
            } else {
                ScreenKind::CeremonyInput
            },
        );
    }
    if target == ScreenKind::DerivationExplanation {
        return flow;
    }
    let result = match flow
        .apply(FlowEvent::OperationCompleted(
            CompletedOperation::Provisioning(&PROVISIONING_FACTS),
        ))
        .expect("matrix provisioning result")
    {
        FlowApplyOutcome::ProvisioningResult(session) => session,
        _ => panic!("matrix provisioning result"),
    };
    assert_eq!(
        result
            .apply(FlowEvent::Key(KeypadKey::EqualsConfirmEnter))
            .expect("matrix result release"),
        ScopedApplyOutcome::Released(ScreenKind::ProvisionB)
    );
    if target == ScreenKind::ProvisionB {
        return flow;
    }
    for next in [
        ScreenKind::VerifyB,
        ScreenKind::ProvisionC,
        ScreenKind::VerifyC,
        ScreenKind::CreateA1,
        ScreenKind::ScanBackA1,
        ScreenKind::CoordinatorMaterial,
        ScreenKind::Rehearsal,
        ScreenKind::KitReady,
    ] {
        root_continue(
            &mut flow,
            FlowEvent::OperationCompleted(CompletedOperation::Plain),
            next,
        );
        if target == next {
            return flow;
        }
    }
    panic!("not a provisioning root screen")
}

fn transaction_root_at(
    target: ScreenKind,
    ready: &ReviewReady,
    export: &ExportArtifacts,
) -> ScreenFlow {
    let flow_kind = match target {
        ScreenKind::PostApprovalFactor => FlowKind::RecoveryBC,
        ScreenKind::RecoveryRotation => FlowKind::RecoveryA1C,
        _ => FlowKind::SigningA1B,
    };
    let mut flow = ScreenFlow::new(flow_kind);
    if target == ScreenKind::FlowStart {
        return flow;
    }
    enter(&mut flow, ScreenKind::Route);
    if target == ScreenKind::Route {
        return flow;
    }
    enter(&mut flow, ScreenKind::Transport);
    if target == ScreenKind::Transport {
        return flow;
    }
    root_continue(&mut flow, FlowEvent::TransportPresented, ScreenKind::Intake);
    if target == ScreenKind::Intake {
        return flow;
    }
    root_continue(&mut flow, FlowEvent::IntakePresented, ScreenKind::Factor);
    if target == ScreenKind::Factor {
        return flow;
    }
    root_continue(
        &mut flow,
        FlowEvent::OperationCompleted(CompletedOperation::Plain),
        ScreenKind::Factor,
    );
    root_continue(
        &mut flow,
        FlowEvent::OperationCompleted(CompletedOperation::Plain),
        ScreenKind::Validation,
    );
    if target == ScreenKind::Validation {
        return flow;
    }
    let review = visit_to_final(
        match flow
            .apply(FlowEvent::OperationCompleted(CompletedOperation::Review(
                ready,
            )))
            .expect("matrix review")
        {
            FlowApplyOutcome::Review(session) => session,
            _ => panic!("matrix review"),
        },
    );
    let expected = if flow_kind == FlowKind::RecoveryBC {
        ScreenKind::PostApprovalFactor
    } else {
        ScreenKind::AwaitingSigning
    };
    let _ = approve(review, expected);
    if target == ScreenKind::PostApprovalFactor || target == ScreenKind::AwaitingSigning {
        return flow;
    }
    if flow_kind == FlowKind::RecoveryBC {
        root_continue(
            &mut flow,
            FlowEvent::OperationCompleted(CompletedOperation::Plain),
            ScreenKind::PostApprovalFactor,
        );
        root_continue(
            &mut flow,
            FlowEvent::OperationCompleted(CompletedOperation::Plain),
            ScreenKind::AwaitingSigning,
        );
    }
    let identity = flow.approval_identity().expect("matrix identity");
    root_continue(
        &mut flow,
        FlowEvent::SigningOutcome { identity },
        ScreenKind::Export,
    );
    if target == ScreenKind::Export {
        return flow;
    }
    let result = match flow
        .apply(FlowEvent::OperationCompleted(CompletedOperation::Export(
            export,
        )))
        .expect("matrix result")
    {
        FlowApplyOutcome::TransactionResult(session) => session,
        _ => panic!("matrix result"),
    };
    assert_eq!(
        result
            .apply(FlowEvent::Key(KeypadKey::EqualsConfirmEnter))
            .expect("matrix result release"),
        ScopedApplyOutcome::Released(ScreenKind::RecoveryRotation)
    );
    if target == ScreenKind::RecoveryRotation {
        return flow;
    }
    panic!("not a transaction root screen")
}

fn root_at(target: ScreenKind, ready: &ReviewReady, export: &ExportArtifacts) -> ScreenFlow {
    if matches!(
        target,
        ScreenKind::ProvisioningStart
            | ScreenKind::TierSelection
            | ScreenKind::EntropyModeSelection
            | ScreenKind::CeremonyInput
            | ScreenKind::CeremonyConfirm
            | ScreenKind::CeremonyCommitment
            | ScreenKind::DerivationExplanation
            | ScreenKind::ProvisionB
            | ScreenKind::VerifyB
            | ScreenKind::ProvisionC
            | ScreenKind::VerifyC
            | ScreenKind::CreateA1
            | ScreenKind::ScanBackA1
            | ScreenKind::CoordinatorMaterial
            | ScreenKind::Rehearsal
            | ScreenKind::KitReady
    ) {
        provisioning_root_at(target)
    } else {
        transaction_root_at(target, ready, export)
    }
}

fn donor_identity(ready: &ReviewReady) -> ApprovalIdentity {
    let mut flow = ScreenFlow::new(FlowKind::SigningA1B);
    let review = visit_to_final(open_review(&mut flow, ready));
    let _ = approve(review, ScreenKind::AwaitingSigning);
    flow.approval_identity().expect("donor identity")
}

fn universal_expected(case: EventCase) -> Option<OutcomeClass> {
    Some(OutcomeClass::FailedWiped(match case {
        EventCase::OperationFailed => WipingReason::OperationFailed,
        EventCase::MediaRemoved => WipingReason::MediaRemoved,
        EventCase::CardRemoved => WipingReason::CardRemoved,
        EventCase::SessionTimeout => WipingReason::SessionTimeout,
        EventCase::Shutdown => WipingReason::Shutdown,
        EventCase::Restart => WipingReason::Restart,
        EventCase::PowerLoss => WipingReason::PowerLoss,
        _ => return None,
    }))
}

fn expected_root(screen: ScreenKind, case: EventCase) -> OutcomeClass {
    if let Some(expected) = universal_expected(case) {
        return expected;
    }
    let transaction = matches!(
        screen,
        ScreenKind::FlowStart
            | ScreenKind::Route
            | ScreenKind::Transport
            | ScreenKind::Intake
            | ScreenKind::Factor
            | ScreenKind::Validation
            | ScreenKind::PostApprovalFactor
            | ScreenKind::AwaitingSigning
            | ScreenKind::Export
            | ScreenKind::RecoveryRotation
    );
    if transaction
        && matches!(
            case,
            EventCase::ApprovalHoldStarted
                | EventCase::ApprovalHoldCompleted
                | EventCase::ForeignHoldCompletion
        )
    {
        return OutcomeClass::FailedWiped(WipingReason::ReviewIncomplete);
    }
    if matches!(
        screen,
        ScreenKind::PostApprovalFactor | ScreenKind::AwaitingSigning
    ) && matches!(
        case,
        EventCase::TransportPresented | EventCase::CameraPresented | EventCase::IntakePresented
    ) {
        return OutcomeClass::FailedWiped(WipingReason::PostApprovalYield);
    }
    match (screen, case) {
        (ScreenKind::ProvisioningStart, EventCase::Key(KeypadKey::EqualsConfirmEnter)) => {
            OutcomeClass::Continue(ScreenKind::TierSelection)
        }
        (ScreenKind::TierSelection, EventCase::Key(KeypadKey::EqualsConfirmEnter)) => {
            OutcomeClass::Continue(ScreenKind::EntropyModeSelection)
        }
        (ScreenKind::TierSelection, EventCase::Key(KeypadKey::CancelBack)) => {
            OutcomeClass::Continue(ScreenKind::ProvisioningStart)
        }
        (ScreenKind::EntropyModeSelection, EventCase::Key(KeypadKey::EqualsConfirmEnter)) => {
            OutcomeClass::Continue(ScreenKind::CeremonyInput)
        }
        (
            ScreenKind::EntropyModeSelection,
            EventCase::Key(KeypadKey::FourLeft | KeypadKey::SixRight),
        ) => OutcomeClass::Continue(ScreenKind::EntropyModeSelection),
        (ScreenKind::EntropyModeSelection, EventCase::Key(KeypadKey::CancelBack)) => {
            OutcomeClass::Continue(ScreenKind::TierSelection)
        }
        (
            ScreenKind::CeremonyInput,
            EventCase::Key(
                KeypadKey::One
                | KeypadKey::TwoDown
                | KeypadKey::Three
                | KeypadKey::FourLeft
                | KeypadKey::Five
                | KeypadKey::SixRight
                | KeypadKey::CeDelete,
            ),
        ) => OutcomeClass::Continue(ScreenKind::CeremonyInput),
        (ScreenKind::CeremonyInput, EventCase::Key(KeypadKey::CancelBack)) => {
            OutcomeClass::Continue(ScreenKind::EntropyModeSelection)
        }
        (ScreenKind::CeremonyInput, EventCase::CeremonyEchoReady) => {
            OutcomeClass::Scoped(ScreenKind::CeremonyEcho)
        }
        (ScreenKind::CeremonyConfirm, EventCase::CeremonyCommitmentReady) => {
            OutcomeClass::Continue(ScreenKind::CeremonyCommitment)
        }
        (ScreenKind::CeremonyCommitment, EventCase::Key(KeypadKey::EqualsConfirmEnter)) => {
            OutcomeClass::Continue(ScreenKind::CeremonyInput)
        }
        (ScreenKind::ProvisionB, EventCase::OperationCompleted) => {
            OutcomeClass::Continue(ScreenKind::VerifyB)
        }
        (ScreenKind::VerifyB, EventCase::OperationCompleted) => {
            OutcomeClass::Continue(ScreenKind::ProvisionC)
        }
        (ScreenKind::ProvisionC, EventCase::OperationCompleted) => {
            OutcomeClass::Continue(ScreenKind::VerifyC)
        }
        (ScreenKind::VerifyC, EventCase::OperationCompleted) => {
            OutcomeClass::Continue(ScreenKind::CreateA1)
        }
        (ScreenKind::CreateA1, EventCase::OperationCompleted) => {
            OutcomeClass::Continue(ScreenKind::ScanBackA1)
        }
        (ScreenKind::ScanBackA1, EventCase::OperationCompleted) => {
            OutcomeClass::Continue(ScreenKind::CoordinatorMaterial)
        }
        (ScreenKind::CoordinatorMaterial, EventCase::OperationCompleted) => {
            OutcomeClass::Continue(ScreenKind::Rehearsal)
        }
        (ScreenKind::Rehearsal, EventCase::OperationCompleted) => {
            OutcomeClass::Continue(ScreenKind::KitReady)
        }
        (ScreenKind::KitReady, EventCase::Key(KeypadKey::EqualsConfirmEnter)) => {
            OutcomeClass::CompletedWiped
        }
        (ScreenKind::FlowStart, EventCase::Key(KeypadKey::EqualsConfirmEnter)) => {
            OutcomeClass::Continue(ScreenKind::Route)
        }
        (ScreenKind::Route, EventCase::Key(KeypadKey::EqualsConfirmEnter)) => {
            OutcomeClass::Continue(ScreenKind::Transport)
        }
        (ScreenKind::Transport, EventCase::TransportPresented | EventCase::CameraPresented) => {
            OutcomeClass::Continue(ScreenKind::Intake)
        }
        (ScreenKind::Intake, EventCase::IntakePresented) => {
            OutcomeClass::Continue(ScreenKind::Factor)
        }
        (ScreenKind::Factor, EventCase::OperationCompleted) => {
            OutcomeClass::Continue(ScreenKind::Factor)
        }
        (ScreenKind::PostApprovalFactor, EventCase::OperationCompleted) => {
            OutcomeClass::Continue(ScreenKind::PostApprovalFactor)
        }
        (ScreenKind::AwaitingSigning, EventCase::SigningOutcome) => {
            OutcomeClass::Continue(ScreenKind::Export)
        }
        (ScreenKind::AwaitingSigning, EventCase::ForeignSigningOutcome) => {
            OutcomeClass::FailedWiped(WipingReason::ReviewIdentityMismatch)
        }
        (ScreenKind::RecoveryRotation, EventCase::Key(KeypadKey::EqualsConfirmEnter)) => {
            OutcomeClass::CompletedWiped
        }
        (_, EventCase::Key(KeypadKey::CancelBack)) => {
            OutcomeClass::FailedWiped(WipingReason::Cancelled)
        }
        _ => OutcomeClass::FailedWiped(WipingReason::InvalidTransition),
    }
}

#[test]
fn every_root_screen_event_cell_is_total_and_deterministic() {
    let owner = review_workflow();
    let ready = owner.review_ready().expect("ready");
    let export = export_artifacts(KitTier::SimpleRecovery);
    let fallback_identity = donor_identity(ready);
    let foreign_identity = donor_identity(ready);
    let fallback_token = fallback_identity.token();
    let cases = event_cases();
    assert_eq!(cases.len(), 37);
    for screen in ROOT_SCREEN_KINDS {
        for case in cases.iter().copied() {
            let mut first = root_at(screen, ready, &export);
            let identity = first.approval_identity().unwrap_or(fallback_identity);
            let first_outcome = classify_root(
                first
                    .apply(event_for(case, fallback_token, identity, foreign_identity))
                    .expect("first root cell"),
            );
            let mut second = root_at(screen, ready, &export);
            let identity = second.approval_identity().unwrap_or(fallback_identity);
            let second_outcome = classify_root(
                second
                    .apply(event_for(case, fallback_token, identity, foreign_identity))
                    .expect("second root cell"),
            );
            assert_eq!(
                first_outcome, second_outcome,
                "root cell differs: {screen:?}/{case:?}"
            );
            assert_eq!(
                first_outcome,
                expected_root(screen, case),
                "root oracle differs: {screen:?}/{case:?}"
            );
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum CeremonyMatrixStage {
    Input,
    Echo,
    ConfirmScoped,
    ConfirmReleased,
    Commitment,
}

fn ceremony_input_at(purpose: CeremonyPurpose) -> ScreenFlow {
    let mut flow = ScreenFlow::new(FlowKind::Provisioning);
    enter(&mut flow, ScreenKind::TierSelection);
    enter(&mut flow, ScreenKind::EntropyModeSelection);
    enter(&mut flow, ScreenKind::CeremonyInput);
    for (index, current) in [
        CeremonyPurpose::SeedA,
        CeremonyPurpose::SignerB,
        CeremonyPurpose::SignerC,
        CeremonyPurpose::A2,
    ]
    .into_iter()
    .enumerate()
    {
        if current == purpose {
            return flow;
        }
        finish_one_ceremony(&mut flow, b"matrix purpose unit", [index as u8; 32]);
        enter(&mut flow, ScreenKind::CeremonyInput);
    }
    panic!("unknown ceremony purpose")
}

fn classify_ceremony_outcome(outcome: CeremonySessionOutcome<'_, '_>) -> OutcomeClass {
    match outcome {
        CeremonySessionOutcome::Continue(session) => {
            OutcomeClass::Continue(session.screen().kind())
        }
        CeremonySessionOutcome::Released(outcome) => classify_scoped(outcome),
    }
}

fn ceremony_cell(
    purpose: CeremonyPurpose,
    stage: CeremonyMatrixStage,
    case: EventCase,
    token: qk_host_sim::ApprovalToken,
    identity: ApprovalIdentity,
    foreign_identity: ApprovalIdentity,
) -> OutcomeClass {
    let mut flow = ceremony_input_at(purpose);
    match stage {
        CeremonyMatrixStage::Input => classify_root(
            flow.apply(event_for(case, token, identity, foreign_identity))
                .expect("ceremony input cell"),
        ),
        CeremonyMatrixStage::ConfirmReleased => {
            release_echo_to_confirm(&mut flow);
            classify_root(
                flow.apply(event_for(case, token, identity, foreign_identity))
                    .expect("ceremony released-confirm cell"),
            )
        }
        CeremonyMatrixStage::Commitment => {
            release_echo_to_confirm(&mut flow);
            root_continue(
                &mut flow,
                FlowEvent::CeremonyCommitmentReady([0x39; 32]),
                ScreenKind::CeremonyCommitment,
            );
            classify_root(
                flow.apply(event_for(case, token, identity, foreign_identity))
                    .expect("ceremony commitment cell"),
            )
        }
        CeremonyMatrixStage::Echo | CeremonyMatrixStage::ConfirmScoped => {
            let session = match flow
                .apply(FlowEvent::CeremonyEchoReady(b"matrix exact echo unit"))
                .expect("open ceremony matrix session")
            {
                FlowApplyOutcome::Ceremony(session) => session,
                _ => panic!("ceremony matrix session"),
            };
            let session = if stage == CeremonyMatrixStage::ConfirmScoped {
                match session
                    .apply(FlowEvent::Key(KeypadKey::EqualsConfirmEnter))
                    .expect("advance matrix echo")
                {
                    CeremonySessionOutcome::Continue(session) => session,
                    CeremonySessionOutcome::Released(_) => panic!("matrix echo released"),
                }
            } else {
                session
            };
            classify_ceremony_outcome(
                session
                    .apply(event_for(case, token, identity, foreign_identity))
                    .expect("ceremony scoped cell"),
            )
        }
    }
}

fn expected_ceremony(
    purpose: CeremonyPurpose,
    stage: CeremonyMatrixStage,
    case: EventCase,
) -> OutcomeClass {
    if let Some(expected) = universal_expected(case) {
        return expected;
    }
    match (stage, case) {
        (CeremonyMatrixStage::Input, EventCase::CeremonyEchoReady) => {
            OutcomeClass::Scoped(ScreenKind::CeremonyEcho)
        }
        (
            CeremonyMatrixStage::Input,
            EventCase::Key(
                KeypadKey::One
                | KeypadKey::TwoDown
                | KeypadKey::Three
                | KeypadKey::FourLeft
                | KeypadKey::Five
                | KeypadKey::SixRight
                | KeypadKey::CeDelete,
            ),
        ) => OutcomeClass::Continue(ScreenKind::CeremonyInput),
        (CeremonyMatrixStage::Input, EventCase::Key(KeypadKey::CancelBack))
            if purpose == CeremonyPurpose::SeedA =>
        {
            OutcomeClass::Continue(ScreenKind::EntropyModeSelection)
        }
        (CeremonyMatrixStage::Echo, EventCase::Key(KeypadKey::EqualsConfirmEnter)) => {
            OutcomeClass::Continue(ScreenKind::CeremonyConfirm)
        }
        (CeremonyMatrixStage::ConfirmScoped, EventCase::Key(KeypadKey::EqualsConfirmEnter)) => {
            OutcomeClass::Released(ScreenKind::CeremonyConfirm)
        }
        (CeremonyMatrixStage::ConfirmReleased, EventCase::CeremonyCommitmentReady) => {
            OutcomeClass::Continue(ScreenKind::CeremonyCommitment)
        }
        (CeremonyMatrixStage::Commitment, EventCase::Key(KeypadKey::EqualsConfirmEnter)) => {
            OutcomeClass::Continue(if purpose == CeremonyPurpose::A2 {
                ScreenKind::DerivationExplanation
            } else {
                ScreenKind::CeremonyInput
            })
        }
        (
            CeremonyMatrixStage::Echo
            | CeremonyMatrixStage::ConfirmScoped
            | CeremonyMatrixStage::ConfirmReleased
            | CeremonyMatrixStage::Commitment,
            EventCase::Key(KeypadKey::CancelBack),
        )
        | (CeremonyMatrixStage::Input, EventCase::Key(KeypadKey::CancelBack)) => {
            OutcomeClass::FailedWiped(WipingReason::Cancelled)
        }
        _ => OutcomeClass::FailedWiped(WipingReason::InvalidTransition),
    }
}

#[test]
fn every_ceremony_purpose_and_scoped_stage_event_cell_matches_the_named_oracle() {
    let owner = review_workflow();
    let ready = owner.review_ready().expect("ready");
    let identity = donor_identity(ready);
    let foreign_identity = donor_identity(ready);
    let token = identity.token();
    for purpose in [
        CeremonyPurpose::SeedA,
        CeremonyPurpose::SignerB,
        CeremonyPurpose::SignerC,
        CeremonyPurpose::A2,
    ] {
        for stage in [
            CeremonyMatrixStage::Input,
            CeremonyMatrixStage::Echo,
            CeremonyMatrixStage::ConfirmScoped,
            CeremonyMatrixStage::ConfirmReleased,
            CeremonyMatrixStage::Commitment,
        ] {
            for case in event_cases() {
                let actual = ceremony_cell(purpose, stage, case, token, identity, foreign_identity);
                assert_eq!(
                    actual,
                    expected_ceremony(purpose, stage, case),
                    "ceremony oracle differs: {purpose:?}/{stage:?}/{case:?}"
                );
            }
        }
    }
}

fn provisioning_result_cell(
    case: EventCase,
    token: qk_host_sim::ApprovalToken,
    identity: ApprovalIdentity,
    foreign_identity: ApprovalIdentity,
) -> OutcomeClass {
    let mut flow = provisioning_root_at(ScreenKind::DerivationExplanation);
    let session = match flow
        .apply(FlowEvent::OperationCompleted(
            CompletedOperation::Provisioning(&PROVISIONING_FACTS),
        ))
        .expect("open provisioning-result cell")
    {
        FlowApplyOutcome::ProvisioningResult(session) => session,
        _ => panic!("provisioning-result cell"),
    };
    classify_scoped(
        session
            .apply(event_for(case, token, identity, foreign_identity))
            .expect("provisioning-result event"),
    )
}

fn expected_provisioning_result(case: EventCase) -> OutcomeClass {
    universal_expected(case).unwrap_or(match case {
        EventCase::Key(KeypadKey::EqualsConfirmEnter) => {
            OutcomeClass::Released(ScreenKind::ProvisionB)
        }
        EventCase::Key(KeypadKey::CancelBack) => OutcomeClass::FailedWiped(WipingReason::Cancelled),
        _ => OutcomeClass::FailedWiped(WipingReason::InvalidTransition),
    })
}

#[test]
fn every_provisioning_result_event_cell_matches_the_named_oracle() {
    let owner = review_workflow();
    let ready = owner.review_ready().expect("ready");
    let identity = donor_identity(ready);
    let foreign_identity = donor_identity(ready);
    for case in event_cases() {
        let actual = provisioning_result_cell(case, identity.token(), identity, foreign_identity);
        assert_eq!(
            actual,
            expected_provisioning_result(case),
            "provisioning-result oracle differs: {case:?}"
        );
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum TransactionMatrixStage {
    FlowStart,
    Route,
    Transport,
    Intake,
    Factor(u8),
    Validation,
    PostApprovalFactor(u8),
    AwaitingSigning,
    Export,
    RecoveryRotation,
}

fn expected_factor_role(flow: FlowKind, step: u8) -> FactorRole {
    match (flow, step) {
        (FlowKind::SigningA1B, 0) | (FlowKind::RecoveryBC, 0) => FactorRole::SignerB,
        (FlowKind::RecoveryA1C, 0) => FactorRole::EmergencySignerC,
        (FlowKind::SigningA1B | FlowKind::RecoveryA1C, 1) => FactorRole::A1,
        (FlowKind::RecoveryBC, 1) => FactorRole::SignerC,
        _ => panic!("invalid factor matrix state"),
    }
}

fn transaction_flow_at(
    flow_kind: FlowKind,
    stage: TransactionMatrixStage,
    ready: &ReviewReady,
    export: &ExportArtifacts,
) -> ScreenFlow {
    let mut flow = ScreenFlow::new(flow_kind);
    if stage == TransactionMatrixStage::FlowStart {
        return flow;
    }
    enter(&mut flow, ScreenKind::Route);
    if stage == TransactionMatrixStage::Route {
        return flow;
    }
    enter(&mut flow, ScreenKind::Transport);
    if stage == TransactionMatrixStage::Transport {
        return flow;
    }
    root_continue(&mut flow, FlowEvent::TransportPresented, ScreenKind::Intake);
    if stage == TransactionMatrixStage::Intake {
        return flow;
    }
    root_continue(&mut flow, FlowEvent::IntakePresented, ScreenKind::Factor);
    if stage == TransactionMatrixStage::Factor(0) {
        assert!(matches!(
            flow.screen(),
            Some(Screen::Factor { role, .. }) if role == expected_factor_role(flow_kind, 0)
        ));
        return flow;
    }
    root_continue(
        &mut flow,
        FlowEvent::OperationCompleted(CompletedOperation::Plain),
        ScreenKind::Factor,
    );
    if stage == TransactionMatrixStage::Factor(1) {
        assert!(matches!(
            flow.screen(),
            Some(Screen::Factor { role, .. }) if role == expected_factor_role(flow_kind, 1)
        ));
        return flow;
    }
    root_continue(
        &mut flow,
        FlowEvent::OperationCompleted(CompletedOperation::Plain),
        ScreenKind::Validation,
    );
    if stage == TransactionMatrixStage::Validation {
        return flow;
    }
    let review = visit_to_final(
        match flow
            .apply(FlowEvent::OperationCompleted(CompletedOperation::Review(
                ready,
            )))
            .expect("transaction matrix review")
        {
            FlowApplyOutcome::Review(session) => session,
            _ => panic!("transaction matrix review"),
        },
    );
    let next = if flow_kind == FlowKind::RecoveryBC {
        ScreenKind::PostApprovalFactor
    } else {
        ScreenKind::AwaitingSigning
    };
    let _ = approve(review, next);
    if flow_kind == FlowKind::RecoveryBC {
        if stage == TransactionMatrixStage::PostApprovalFactor(0) {
            assert!(matches!(
                flow.screen(),
                Some(Screen::PostApprovalFactor {
                    role: FactorRole::SignerB
                })
            ));
            return flow;
        }
        root_continue(
            &mut flow,
            FlowEvent::OperationCompleted(CompletedOperation::Plain),
            ScreenKind::PostApprovalFactor,
        );
        if stage == TransactionMatrixStage::PostApprovalFactor(1) {
            assert!(matches!(
                flow.screen(),
                Some(Screen::PostApprovalFactor {
                    role: FactorRole::SignerC
                })
            ));
            return flow;
        }
        root_continue(
            &mut flow,
            FlowEvent::OperationCompleted(CompletedOperation::Plain),
            ScreenKind::AwaitingSigning,
        );
    }
    if stage == TransactionMatrixStage::AwaitingSigning {
        return flow;
    }
    let identity = flow
        .approval_identity()
        .expect("transaction matrix identity");
    root_continue(
        &mut flow,
        FlowEvent::SigningOutcome { identity },
        ScreenKind::Export,
    );
    if stage == TransactionMatrixStage::Export {
        return flow;
    }
    let result = match flow
        .apply(FlowEvent::OperationCompleted(CompletedOperation::Export(
            export,
        )))
        .expect("transaction matrix result")
    {
        FlowApplyOutcome::TransactionResult(session) => session,
        _ => panic!("transaction matrix result"),
    };
    assert_eq!(
        result
            .apply(FlowEvent::Key(KeypadKey::EqualsConfirmEnter))
            .expect("transaction matrix result release"),
        ScopedApplyOutcome::Released(ScreenKind::RecoveryRotation)
    );
    assert_eq!(stage, TransactionMatrixStage::RecoveryRotation);
    flow
}

fn transaction_stages(flow: FlowKind) -> Vec<TransactionMatrixStage> {
    let mut stages = vec![
        TransactionMatrixStage::FlowStart,
        TransactionMatrixStage::Route,
        TransactionMatrixStage::Transport,
        TransactionMatrixStage::Intake,
        TransactionMatrixStage::Factor(0),
        TransactionMatrixStage::Factor(1),
        TransactionMatrixStage::Validation,
    ];
    if flow == FlowKind::RecoveryBC {
        stages.extend([
            TransactionMatrixStage::PostApprovalFactor(0),
            TransactionMatrixStage::PostApprovalFactor(1),
        ]);
    }
    stages.extend([
        TransactionMatrixStage::AwaitingSigning,
        TransactionMatrixStage::Export,
    ]);
    if flow != FlowKind::SigningA1B {
        stages.push(TransactionMatrixStage::RecoveryRotation);
    }
    stages
}

fn expected_transaction_root(stage: TransactionMatrixStage, case: EventCase) -> OutcomeClass {
    if let Some(expected) = universal_expected(case) {
        return expected;
    }
    if matches!(
        case,
        EventCase::ApprovalHoldStarted
            | EventCase::ApprovalHoldCompleted
            | EventCase::ForeignHoldCompletion
    ) {
        return OutcomeClass::FailedWiped(WipingReason::ReviewIncomplete);
    }
    if matches!(
        stage,
        TransactionMatrixStage::PostApprovalFactor(_) | TransactionMatrixStage::AwaitingSigning
    ) && matches!(
        case,
        EventCase::TransportPresented | EventCase::CameraPresented | EventCase::IntakePresented
    ) {
        return OutcomeClass::FailedWiped(WipingReason::PostApprovalYield);
    }
    match (stage, case) {
        (TransactionMatrixStage::FlowStart, EventCase::Key(KeypadKey::EqualsConfirmEnter)) => {
            OutcomeClass::Continue(ScreenKind::Route)
        }
        (TransactionMatrixStage::Route, EventCase::Key(KeypadKey::EqualsConfirmEnter)) => {
            OutcomeClass::Continue(ScreenKind::Transport)
        }
        (
            TransactionMatrixStage::Transport,
            EventCase::TransportPresented | EventCase::CameraPresented,
        ) => OutcomeClass::Continue(ScreenKind::Intake),
        (TransactionMatrixStage::Intake, EventCase::IntakePresented) => {
            OutcomeClass::Continue(ScreenKind::Factor)
        }
        (TransactionMatrixStage::Factor(0), EventCase::OperationCompleted) => {
            OutcomeClass::Continue(ScreenKind::Factor)
        }
        (TransactionMatrixStage::Factor(1), EventCase::OperationCompleted) => {
            OutcomeClass::Continue(ScreenKind::Validation)
        }
        (TransactionMatrixStage::PostApprovalFactor(0), EventCase::OperationCompleted) => {
            OutcomeClass::Continue(ScreenKind::PostApprovalFactor)
        }
        (TransactionMatrixStage::PostApprovalFactor(1), EventCase::OperationCompleted) => {
            OutcomeClass::Continue(ScreenKind::AwaitingSigning)
        }
        (TransactionMatrixStage::AwaitingSigning, EventCase::SigningOutcome) => {
            OutcomeClass::Continue(ScreenKind::Export)
        }
        (TransactionMatrixStage::AwaitingSigning, EventCase::ForeignSigningOutcome) => {
            OutcomeClass::FailedWiped(WipingReason::ReviewIdentityMismatch)
        }
        (
            TransactionMatrixStage::RecoveryRotation,
            EventCase::Key(KeypadKey::EqualsConfirmEnter),
        ) => OutcomeClass::CompletedWiped,
        (_, EventCase::Key(KeypadKey::CancelBack)) => {
            OutcomeClass::FailedWiped(WipingReason::Cancelled)
        }
        _ => OutcomeClass::FailedWiped(WipingReason::InvalidTransition),
    }
}

#[test]
fn every_route_and_factor_step_root_event_cell_matches_the_named_oracle() {
    let owner = review_workflow();
    let ready = owner.review_ready().expect("ready");
    let export = export_artifacts(KitTier::Inheritance);
    let foreign_identity = donor_identity(ready);
    for flow_kind in [
        FlowKind::SigningA1B,
        FlowKind::RecoveryA1C,
        FlowKind::RecoveryBC,
    ] {
        for stage in transaction_stages(flow_kind) {
            for case in event_cases() {
                let mut flow = transaction_flow_at(flow_kind, stage, ready, &export);
                let matching = flow.approval_identity().unwrap_or(foreign_identity);
                let actual = classify_root(
                    flow.apply(event_for(
                        case,
                        foreign_identity.token(),
                        matching,
                        foreign_identity,
                    ))
                    .expect("transaction root matrix cell"),
                );
                assert_eq!(
                    actual,
                    expected_transaction_root(stage, case),
                    "transaction oracle differs: {flow_kind:?}/{stage:?}/{case:?}"
                );
            }
        }
    }
}

const REVIEW_STEP_KINDS: [ScreenKind; 10] = [
    ScreenKind::ReviewOverview,
    ScreenKind::ReviewArithmetic,
    ScreenKind::ReviewRecipient,
    ScreenKind::ReviewRecipient,
    ScreenKind::ReviewChange,
    ScreenKind::ReviewOpReturn,
    ScreenKind::ReviewLocktime,
    ScreenKind::ReviewSequence,
    ScreenKind::ReviewFeePolicy,
    ScreenKind::FinalApproval,
];

fn classify_review_outcome(outcome: ReviewSessionOutcome<'_, '_>) -> OutcomeClass {
    match outcome {
        ReviewSessionOutcome::Continue(session) => {
            OutcomeClass::Continue(session.screen().expect("review matrix screen").kind())
        }
        ReviewSessionOutcome::Released(outcome) => classify_scoped(outcome),
    }
}

fn review_cell(
    flow_kind: FlowKind,
    step: usize,
    pending_hold: bool,
    case: EventCase,
    ready: &ReviewReady,
    foreign_identity: ApprovalIdentity,
) -> OutcomeClass {
    let mut flow = ScreenFlow::new(flow_kind);
    let mut session = open_review(&mut flow, ready);
    for expected in REVIEW_STEP_KINDS.iter().copied().skip(1).take(step) {
        session = review_enter(session, expected);
    }
    assert_eq!(
        session.screen().expect("review matrix state").kind(),
        REVIEW_STEP_KINDS[step]
    );
    let matching_token = if pending_hold {
        session = match session
            .apply(FlowEvent::ApprovalHoldStarted)
            .expect("matrix hold start")
        {
            ReviewSessionOutcome::Continue(session) => session,
            ReviewSessionOutcome::Released(_) => panic!("matrix hold released"),
        };
        session.pending_hold_token().expect("matrix hold token")
    } else {
        foreign_identity.token()
    };
    classify_review_outcome(
        session
            .apply(event_for(
                case,
                matching_token,
                foreign_identity,
                foreign_identity,
            ))
            .expect("review matrix event"),
    )
}

fn expected_review(
    flow_kind: FlowKind,
    step: usize,
    pending_hold: bool,
    case: EventCase,
) -> OutcomeClass {
    if let Some(expected) = universal_expected(case) {
        return expected;
    }
    let final_step = REVIEW_STEP_KINDS.len() - 1;
    if step != final_step
        && matches!(
            case,
            EventCase::ApprovalHoldStarted
                | EventCase::ApprovalHoldCompleted
                | EventCase::ForeignHoldCompletion
        )
    {
        return OutcomeClass::FailedWiped(WipingReason::ReviewIncomplete);
    }
    if pending_hold {
        return match case {
            EventCase::ApprovalHoldCompleted => {
                OutcomeClass::Released(if flow_kind == FlowKind::RecoveryBC {
                    ScreenKind::PostApprovalFactor
                } else {
                    ScreenKind::AwaitingSigning
                })
            }
            EventCase::ApprovalHoldStarted | EventCase::ForeignHoldCompletion => {
                OutcomeClass::FailedWiped(WipingReason::ReviewIdentityMismatch)
            }
            EventCase::Key(KeypadKey::CancelBack) => {
                OutcomeClass::FailedWiped(WipingReason::Cancelled)
            }
            _ => OutcomeClass::FailedWiped(WipingReason::InvalidTransition),
        };
    }
    match case {
        EventCase::Key(
            KeypadKey::EqualsConfirmEnter | KeypadKey::SixRight | KeypadKey::TwoDown,
        ) if step < final_step => OutcomeClass::Continue(REVIEW_STEP_KINDS[step + 1]),
        EventCase::Key(KeypadKey::FourLeft | KeypadKey::EightUp | KeypadKey::CancelBack)
            if step > 0 =>
        {
            OutcomeClass::Continue(REVIEW_STEP_KINDS[step - 1])
        }
        EventCase::ApprovalHoldStarted if step == final_step => {
            OutcomeClass::Continue(ScreenKind::FinalApproval)
        }
        EventCase::ApprovalHoldCompleted | EventCase::ForeignHoldCompletion
            if step == final_step =>
        {
            OutcomeClass::FailedWiped(WipingReason::ReviewIdentityMismatch)
        }
        EventCase::Key(KeypadKey::CancelBack) => OutcomeClass::FailedWiped(WipingReason::Cancelled),
        _ => OutcomeClass::FailedWiped(WipingReason::InvalidTransition),
    }
}

#[test]
fn every_review_item_index_and_pending_hold_event_cell_matches_the_named_oracle() {
    let owner = review_workflow();
    let ready = owner.review_ready().expect("ready");
    let foreign_identity = donor_identity(ready);
    for flow_kind in [
        FlowKind::SigningA1B,
        FlowKind::RecoveryA1C,
        FlowKind::RecoveryBC,
    ] {
        for step in 0..REVIEW_STEP_KINDS.len() {
            for case in event_cases() {
                let actual = review_cell(flow_kind, step, false, case, ready, foreign_identity);
                assert_eq!(
                    actual,
                    expected_review(flow_kind, step, false, case),
                    "review oracle differs: {flow_kind:?}/step-{step}/{case:?}"
                );
            }
        }
        for case in event_cases() {
            let actual = review_cell(
                flow_kind,
                REVIEW_STEP_KINDS.len() - 1,
                true,
                case,
                ready,
                foreign_identity,
            );
            assert_eq!(
                actual,
                expected_review(flow_kind, REVIEW_STEP_KINDS.len() - 1, true, case,),
                "pending-hold oracle differs: {flow_kind:?}/{case:?}"
            );
        }
    }
}

fn transaction_result_cell(
    flow_kind: FlowKind,
    case: EventCase,
    ready: &ReviewReady,
    export: &ExportArtifacts,
    foreign_identity: ApprovalIdentity,
) -> OutcomeClass {
    let mut flow = transaction_flow_at(flow_kind, TransactionMatrixStage::Export, ready, export);
    let session = match flow
        .apply(FlowEvent::OperationCompleted(CompletedOperation::Export(
            export,
        )))
        .expect("open result matrix")
    {
        FlowApplyOutcome::TransactionResult(session) => session,
        _ => panic!("result matrix session"),
    };
    classify_scoped(
        session
            .apply(event_for(
                case,
                foreign_identity.token(),
                foreign_identity,
                foreign_identity,
            ))
            .expect("result matrix event"),
    )
}

fn expected_transaction_result(flow_kind: FlowKind, case: EventCase) -> OutcomeClass {
    universal_expected(case).unwrap_or(match case {
        EventCase::Key(KeypadKey::EqualsConfirmEnter) if flow_kind == FlowKind::SigningA1B => {
            OutcomeClass::CompletedWiped
        }
        EventCase::Key(KeypadKey::EqualsConfirmEnter) => {
            OutcomeClass::Released(ScreenKind::RecoveryRotation)
        }
        EventCase::Key(KeypadKey::CancelBack) => OutcomeClass::FailedWiped(WipingReason::Cancelled),
        _ => OutcomeClass::FailedWiped(WipingReason::InvalidTransition),
    })
}

#[test]
fn every_transaction_result_event_cell_matches_the_named_oracle() {
    let owner = review_workflow();
    let ready = owner.review_ready().expect("ready");
    let export = export_artifacts(KitTier::Inheritance);
    let foreign_identity = donor_identity(ready);
    for flow_kind in [
        FlowKind::SigningA1B,
        FlowKind::RecoveryA1C,
        FlowKind::RecoveryBC,
    ] {
        for case in event_cases() {
            let actual = transaction_result_cell(flow_kind, case, ready, &export, foreign_identity);
            assert_eq!(
                actual,
                expected_transaction_result(flow_kind, case),
                "result oracle differs: {flow_kind:?}/{case:?}"
            );
        }
    }
}

#[test]
fn every_review_screen_field_is_an_exact_selection_from_review_ready() {
    let owner = review_workflow();
    let ready = owner.review_ready().expect("ready");
    let review = ready.review();
    let mut flow = ScreenFlow::new(FlowKind::SigningA1B);
    let mut session = open_review(&mut flow, ready);

    match session.screen().expect("overview") {
        Screen::ReviewOverview(view) => {
            assert_eq!(view.network(), review.context().network);
            assert_eq!(view.wallet_id(), review.wallet_id());
            assert_eq!(view.input_count(), review.input_count());
            assert_eq!(view.total_input_amount(), review.total_input_amount());
        }
        _ => panic!("overview"),
    }
    session = review_enter(session, ScreenKind::ReviewArithmetic);
    match session.screen().expect("arithmetic") {
        Screen::ReviewArithmetic(view) => {
            assert_eq!(view.total_input_amount(), review.total_input_amount());
            assert_eq!(view.total_output_amount(), review.total_output_amount());
            assert_eq!(view.fee(), review.fee());
        }
        _ => panic!("arithmetic"),
    }
    for output_index in [1usize, 2] {
        session = review_enter(session, ScreenKind::ReviewRecipient);
        let output = &review.outputs()[output_index];
        match session.screen().expect("recipient") {
            Screen::ReviewRecipient(view) => {
                assert_eq!(view.index(), output.index());
                assert_eq!(view.amount(), output.amount());
                assert_eq!(view.script_pubkey(), output.script_pubkey());
                match (view.recipient(), output.ownership()) {
                    (
                        RecipientFactView::External {
                            recipient_type,
                            data,
                        },
                        ReviewV2OutputOwnership::NotOwned {
                            recipient_type: expected_type,
                            data: expected_data,
                        },
                    ) => {
                        assert_eq!(recipient_type, *expected_type);
                        assert_eq!(data, expected_data);
                    }
                    (
                        RecipientFactView::SelfTransfer {
                            child_index,
                            witness_program,
                        },
                        ReviewV2OutputOwnership::ProvenSelfTransfer {
                            child_index: expected_child,
                            witness_program: expected_program,
                        },
                    ) => {
                        assert_eq!(child_index, *expected_child);
                        assert_eq!(witness_program, expected_program);
                    }
                    _ => panic!("recipient fact selection"),
                }
            }
            _ => panic!("recipient"),
        }
    }
    session = review_enter(session, ScreenKind::ReviewChange);
    let change = &review.outputs()[0];
    match session.screen().expect("change") {
        Screen::ReviewChange(view) => {
            assert_eq!(view.index(), change.index());
            assert_eq!(view.amount(), change.amount());
            assert_eq!(view.script_pubkey(), change.script_pubkey());
            let ReviewV2OutputOwnership::ProvenChange { child_index } = change.ownership() else {
                panic!("fixture change")
            };
            assert_eq!(view.child_index(), *child_index);
        }
        _ => panic!("change"),
    }
    session = review_enter(session, ScreenKind::ReviewOpReturn);
    let op_return = &review.outputs()[3];
    match session.screen().expect("OP_RETURN") {
        Screen::ReviewOpReturn(view) => {
            assert_eq!(view.index(), op_return.index());
            assert_eq!(view.amount(), op_return.amount());
            assert_eq!(view.script_pubkey(), op_return.script_pubkey());
            let ReviewV2OutputOwnership::NotOwned { data, .. } = op_return.ownership() else {
                panic!("fixture OP_RETURN")
            };
            assert_eq!(view.payload(), data);
        }
        _ => panic!("OP_RETURN"),
    }
    session = review_enter(session, ScreenKind::ReviewLocktime);
    assert!(
        matches!(session.screen(), Some(Screen::ReviewLocktime(view)) if view.locktime() == review.locktime())
    );
    session = review_enter(session, ScreenKind::ReviewSequence);
    let input = &review.inputs()[0];
    match session.screen().expect("sequence") {
        Screen::ReviewSequence(view) => {
            assert_eq!(view.input_index(), input.index());
            assert_eq!(view.sequence(), input.sequence());
            assert_eq!(view.direct_rbf(), input.direct_rbf());
        }
        _ => panic!("sequence"),
    }
    session = review_enter(session, ScreenKind::ReviewFeePolicy);
    match session.screen().expect("fee policy") {
        Screen::ReviewFeePolicy(view) => {
            assert_eq!(view.identifier(), review.fee_policy_identifier());
            assert_eq!(view.fee(), review.fee());
            assert_eq!(view.estimated_vsize(), review.estimated_vsize());
            assert_eq!(
                view.fee_rate_msat_per_vbyte(),
                review.fee_rate_msat_per_vbyte()
            );
            assert_eq!(
                view.warnings().collect::<Vec<_>>(),
                review.fee_warnings().collect::<Vec<_>>()
            );
        }
        _ => panic!("fee policy"),
    }
    session = review_enter(session, ScreenKind::FinalApproval);
    assert!(
        matches!(session.screen(), Some(Screen::FinalApproval(view)) if view.review_hash() == ready.review_hash())
    );
    drop(session);
    assert_eq!(
        flow.terminal(),
        Some(FlowTerminal::FailedWiped(WipingReason::Cancelled))
    );
}

#[test]
fn public_screen_surface_keeps_fact_owners_and_secret_sessions_scoped() {
    let source = include_str!("../src/screen_flow.rs");
    assert!(source.contains("pub struct ScreenFlow {"));
    assert!(!source.contains("pub struct ScreenFlow<'"));
    assert!(!source.contains("FinalizedTransaction"));
    assert!(!source.contains("pub fn review(&self)"));
    assert!(!source.contains("pub fn ready(&self)"));
    assert!(!source.contains("pub fn export(&self)"));
    assert!(!source.contains("pub fn facts(&self)"));
    assert!(source.contains("input_count: review.input_count()"));
    for deferred_provisioning_fact in [
        "pub const fn account_xpubs",
        "pub const fn descriptors",
        "pub const fn first_scripts",
        "pub const fn first_addresses",
        "pub const fn a1_capsule",
    ] {
        assert!(!source.contains(deferred_provisioning_fact));
    }
    assert!(!source.contains("derive(Debug)\npub enum FlowEvent"));
    assert!(!source.contains("derive(Debug)\npub enum Screen"));
}
