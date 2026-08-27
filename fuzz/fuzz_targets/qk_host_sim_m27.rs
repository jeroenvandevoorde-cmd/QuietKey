#![no_main]

use libfuzzer_sys::fuzz_target;
use qk_descriptor::{parse_descriptor_pair, DescriptorPair};
use qk_host_sim::{
    ApprovalIdentity, ApprovalToken, CeremonyPurpose, CeremonySession, CeremonySessionOutcome,
    CompletedOperation, EntropyInputMode, ExportArtifactKind, ExportArtifacts, FactorRole,
    FlowApplyOutcome, FlowEvent, FlowKind, FlowTerminal, KeypadKey, KitTier,
    ProvisioningResultSession, RecipientFactView, ReviewReady, ReviewReadyWorkflow, ReviewSession,
    ReviewSessionOutcome, ScopedApplyOutcome, Screen, ScreenFlow, ScreenKind, SdArtifactMetadata,
    TierArtifacts, TransactionResultSession, WipingReason,
};
use qk_provisioning::{HostProvisioningRun, ProvisioningArtifacts};
use qk_psbt::{InputSource, RecipientType, ReviewV2Output, ReviewV2OutputOwnership};
use std::sync::OnceLock;

const MAX_PRESENTED_BYTES: usize = 1_024;
const MAX_EVENTS: usize = 256;
const FIXTURE: &[u8] = include_bytes!("../../host/qk-host-sim/tests/fixtures/m25_export.txt");
const CEREMONY_UNIT: &[u8] = b"1234561234561234561234561";
const CEREMONY_COMMITMENT: [u8; 32] = [0x27; 32];

static GOLDEN_S0: OnceLock<Vec<u8>> = OnceLock::new();
static REVIEW_WORKFLOW: OnceLock<ReviewReadyWorkflow> = OnceLock::new();
static PROVISIONING: OnceLock<ProvisioningArtifacts> = OnceLock::new();
static EXPORT: OnceLock<ExportArtifacts> = OnceLock::new();
static FOREIGN_IDENTITY: OnceLock<ApprovalIdentity> = OnceLock::new();

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct Snapshot {
    flow: FlowKind,
    screen: Option<ScreenKind>,
    entropy_mode: Option<EntropyInputMode>,
    fact_index: Option<u32>,
    factor_role: Option<FactorRole>,
    terminal: Option<FlowTerminal>,
    has_approval: bool,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct Trace {
    snapshots: Vec<Snapshot>,
}

fn fixture_value(prefix: &[u8]) -> &'static [u8] {
    FIXTURE
        .split(|byte| *byte == b'\n')
        .find_map(|line| line.strip_prefix(prefix))
        .expect("committed M25 public fixture field")
}

fn hex_nibble(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        b'A'..=b'F' => Some(byte - b'A' + 10),
        _ => None,
    }
}

fn decode_fixture_hex(encoded: &[u8]) -> Vec<u8> {
    assert!(encoded.len().is_multiple_of(2), "fixture hex width");
    encoded
        .chunks_exact(2)
        .map(|pair| {
            let high = hex_nibble(pair[0]).expect("fixture high hex digit");
            let low = hex_nibble(pair[1]).expect("fixture low hex digit");
            (high << 4) | low
        })
        .collect()
}

fn descriptor() -> DescriptorPair {
    parse_descriptor_pair(
        fixture_value(b"receive_descriptor: "),
        fixture_value(b"change_descriptor: "),
    )
    .expect("committed M25 descriptor pair")
}

fn golden_s0() -> &'static [u8] {
    GOLDEN_S0
        .get_or_init(|| decode_fixture_hex(fixture_value(b"initial_psbt_hex: ")))
        .as_slice()
}

fn build_review_workflow() -> ReviewReadyWorkflow {
    let mut workflow = ReviewReadyWorkflow::new(descriptor()).expect("M27 review workflow");
    workflow
        .intake(golden_s0(), InputSource::MicroSd)
        .expect("M27 fixture intake");
    workflow.wake().expect("M27 fixture wake");
    workflow
        .begin_validation()
        .expect("M27 fixture validation start");
    workflow.validate().expect("M27 fixture validation");
    workflow
        .construct_review()
        .expect("M27 fixture review construction");
    workflow
}

fn review_ready() -> &'static ReviewReady {
    REVIEW_WORKFLOW
        .get_or_init(build_review_workflow)
        .review_ready()
        .expect("M27 fixture review-ready capability")
}

fn provisioning() -> &'static ProvisioningArtifacts {
    PROVISIONING.get_or_init(|| {
        let transcripts = [[b'1'; 100], [b'2'; 100], [b'3'; 100], [b'4'; 100]];
        let references = [
            &transcripts[0][..],
            &transcripts[1][..],
            &transcripts[2][..],
            &transcripts[3][..],
        ];
        let mut run = HostProvisioningRun::from_dice(references)
            .expect("public deterministic M26 provisioning fixture");
        run.encrypt_a1(&[0x26; 12])
            .expect("public deterministic M26 A1 fixture")
    })
}

fn finalized() -> qk_host_sim::FinalizedTransaction {
    let workflow = build_review_workflow();
    let finalized = workflow
        .sign_and_finalize_m24(Vec::new(), &[])
        .expect("threshold-complete M25 fixture finalization");
    assert_eq!(
        finalized.finalized_psbt(),
        decode_fixture_hex(fixture_value(b"finalized_psbt_hex: "))
    );
    assert_eq!(
        finalized.raw_transaction(),
        decode_fixture_hex(fixture_value(b"raw_tx_hex: "))
    );
    finalized
}

fn export() -> &'static ExportArtifacts {
    EXPORT.get_or_init(|| {
        ExportArtifacts::from_finalized(finalized(), KitTier::SimpleRecovery)
            .expect("public deterministic M25 export fixture")
    })
}

fn flow_kind(selector: u8) -> FlowKind {
    match selector & 3 {
        0 => FlowKind::Provisioning,
        1 => FlowKind::SigningA1B,
        2 => FlowKind::RecoveryA1C,
        3 => FlowKind::RecoveryBC,
        _ => unreachable!("two-bit flow selector"),
    }
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

fn is_recipient(output: &ReviewV2Output) -> bool {
    matches!(
        output.ownership(),
        ReviewV2OutputOwnership::NotOwned {
            recipient_type: RecipientType::P2wpkh
                | RecipientType::P2wsh
                | RecipientType::P2tr
                | RecipientType::P2pkh
                | RecipientType::P2sh,
            ..
        } | ReviewV2OutputOwnership::ProvenSelfTransfer { .. }
    )
}

fn is_change(output: &ReviewV2Output) -> bool {
    matches!(
        output.ownership(),
        ReviewV2OutputOwnership::ProvenChange { .. }
    )
}

fn is_op_return(output: &ReviewV2Output) -> bool {
    matches!(
        output.ownership(),
        ReviewV2OutputOwnership::NotOwned {
            recipient_type: RecipientType::OpReturn,
            ..
        }
    )
}

fn expected_metadata() -> (Option<SdArtifactMetadata>, SdArtifactMetadata) {
    match export().artifacts() {
        TierArtifacts::SimpleRecovery {
            finalized_psbt,
            raw_transaction,
        }
        | TierArtifacts::Inheritance {
            finalized_psbt,
            raw_transaction,
        } => (Some(finalized_psbt.metadata()), raw_transaction.metadata()),
        TierArtifacts::QuantumShelter { raw_transaction } => (None, raw_transaction.metadata()),
    }
}

fn assert_factor(flow: FlowKind, role: FactorRole) {
    match (flow, role) {
        (FlowKind::SigningA1B | FlowKind::RecoveryA1C, FactorRole::A1)
        | (FlowKind::SigningA1B | FlowKind::RecoveryBC, FactorRole::SignerB)
        | (FlowKind::RecoveryA1C, FactorRole::EmergencySignerC)
        | (FlowKind::RecoveryBC, FactorRole::SignerC) => {}
        _ => panic!("factor role does not belong to flow"),
    }
}

fn assert_named_reason(reason: WipingReason) {
    match reason {
        WipingReason::InvalidTransition
        | WipingReason::Cancelled
        | WipingReason::OperationFailed
        | WipingReason::MediaRemoved
        | WipingReason::CardRemoved
        | WipingReason::SessionTimeout
        | WipingReason::Shutdown
        | WipingReason::Restart
        | WipingReason::PowerLoss
        | WipingReason::ReviewIncomplete
        | WipingReason::ReviewIdentityMismatch
        | WipingReason::PostApprovalYield => {}
    }
}

fn assert_purpose(purpose: CeremonyPurpose) {
    match purpose {
        CeremonyPurpose::SeedA
        | CeremonyPurpose::SignerB
        | CeremonyPurpose::SignerC
        | CeremonyPurpose::A2 => {}
    }
}

fn assert_entropy_mode(mode: EntropyInputMode) {
    match mode {
        EntropyInputMode::DiceGrid | EntropyInputMode::ManualKeypad => {}
    }
}

fn assert_screen(flow: FlowKind, screen: Screen<'_>) {
    let review = review_ready().review();
    match screen {
        Screen::ProvisioningStart
        | Screen::TierSelection
        | Screen::DerivationExplanation
        | Screen::ProvisionB
        | Screen::VerifyB
        | Screen::ProvisionC
        | Screen::VerifyC
        | Screen::CreateA1
        | Screen::ScanBackA1
        | Screen::CoordinatorMaterial
        | Screen::Rehearsal
        | Screen::KitReady
        | Screen::Validation
        | Screen::AwaitingSigning
        | Screen::Export
        | Screen::RecoveryRotation => {}
        Screen::EntropyModeSelection { selected } => assert_entropy_mode(selected),
        Screen::CeremonyInput { purpose, mode } => {
            assert_purpose(purpose);
            assert_entropy_mode(mode);
        }
        Screen::CeremonyEcho {
            purpose,
            mode,
            unit,
        } => {
            assert_purpose(purpose);
            assert_entropy_mode(mode);
            assert!(!unit.bytes().is_empty());
            assert!(unit.bytes().len() <= MAX_PRESENTED_BYTES);
        }
        Screen::CeremonyConfirm {
            purpose,
            mode,
            unit,
        } => {
            assert_purpose(purpose);
            assert_entropy_mode(mode);
            if let Some(unit) = unit {
                assert!(!unit.bytes().is_empty());
                assert!(unit.bytes().len() <= MAX_PRESENTED_BYTES);
            }
        }
        Screen::CeremonyCommitment {
            purpose,
            mode,
            commitment,
        } => {
            assert_purpose(purpose);
            assert_entropy_mode(mode);
            assert_eq!(commitment.bytes().len(), 32);
        }
        Screen::ProvisioningResult(view) => {
            assert_eq!(view.wallet_id(), provisioning().wallet_id);
        }
        Screen::FlowStart { flow: screen_flow }
        | Screen::Route { flow: screen_flow }
        | Screen::Transport { flow: screen_flow }
        | Screen::Intake { flow: screen_flow } => {
            assert_eq!(screen_flow, flow);
            assert_ne!(screen_flow, FlowKind::Provisioning);
        }
        Screen::Factor {
            flow: screen_flow,
            role,
        } => {
            assert_eq!(screen_flow, flow);
            assert_factor(screen_flow, role);
        }
        Screen::ReviewOverview(view) => {
            assert_eq!(view.network(), review.context().network);
            assert_eq!(view.wallet_id(), review.wallet_id());
            assert_eq!(view.input_count(), review.input_count());
            assert_eq!(view.total_input_amount(), review.total_input_amount());
        }
        Screen::ReviewArithmetic(view) => {
            assert_eq!(view.total_input_amount(), review.total_input_amount());
            assert_eq!(view.total_output_amount(), review.total_output_amount());
            assert_eq!(view.fee(), review.fee());
        }
        Screen::ReviewRecipient(view) => {
            let expected = &review.outputs()[view.index() as usize];
            assert!(is_recipient(expected));
            assert_eq!(view.amount(), expected.amount());
            assert_eq!(view.script_pubkey(), expected.script_pubkey());
            match (view.recipient(), expected.ownership()) {
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
                        child_index: expected_index,
                        witness_program: expected_program,
                    },
                ) => {
                    assert_eq!(child_index, *expected_index);
                    assert_eq!(witness_program, expected_program);
                }
                _ => panic!("recipient typed view changed ownership class"),
            }
        }
        Screen::ReviewChange(view) => {
            let expected = &review.outputs()[view.index() as usize];
            let ReviewV2OutputOwnership::ProvenChange { child_index } = expected.ownership() else {
                panic!("change typed view changed ownership class");
            };
            assert_eq!(view.amount(), expected.amount());
            assert_eq!(view.script_pubkey(), expected.script_pubkey());
            assert_eq!(view.child_index(), *child_index);
        }
        Screen::ReviewOpReturn(view) => {
            let expected = &review.outputs()[view.index() as usize];
            let ReviewV2OutputOwnership::NotOwned {
                recipient_type: RecipientType::OpReturn,
                data,
            } = expected.ownership()
            else {
                panic!("OP_RETURN typed view changed ownership class");
            };
            assert_eq!(view.amount(), expected.amount());
            assert_eq!(view.script_pubkey(), expected.script_pubkey());
            assert_eq!(view.payload(), data);
        }
        Screen::ReviewLocktime(view) => assert_eq!(view.locktime(), review.locktime()),
        Screen::ReviewSequence(view) => {
            let expected = &review.inputs()[view.input_index() as usize];
            assert_eq!(view.sequence(), expected.sequence());
            assert_eq!(view.direct_rbf(), expected.direct_rbf());
        }
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
        Screen::FinalApproval(view) => {
            assert_eq!(view.review_hash(), review_ready().review_hash());
        }
        Screen::PostApprovalFactor { role } => {
            assert_eq!(flow, FlowKind::RecoveryBC);
            assert_factor(flow, role);
        }
        Screen::TransactionResult(view) => {
            let (expected_psbt, expected_raw) = expected_metadata();
            assert_eq!(view.finalized_psbt(), expected_psbt);
            assert_eq!(view.raw_transaction(), expected_raw);
            assert_eq!(
                view.raw_transaction().kind(),
                ExportArtifactKind::RawTransaction
            );
        }
    }
}

fn fact_index(screen: Screen<'_>) -> Option<u32> {
    match screen {
        Screen::ReviewRecipient(view) => Some(view.index()),
        Screen::ReviewChange(view) => Some(view.index()),
        Screen::ReviewOpReturn(view) => Some(view.index()),
        Screen::ReviewSequence(view) => Some(view.input_index()),
        _ => None,
    }
}

fn factor_role(screen: Screen<'_>) -> Option<FactorRole> {
    match screen {
        Screen::Factor { role, .. } | Screen::PostApprovalFactor { role } => Some(role),
        _ => None,
    }
}

fn entropy_input_mode(screen: Screen<'_>) -> Option<EntropyInputMode> {
    match screen {
        Screen::EntropyModeSelection { selected } => Some(selected),
        Screen::CeremonyInput { mode, .. }
        | Screen::CeremonyEcho { mode, .. }
        | Screen::CeremonyConfirm { mode, .. }
        | Screen::CeremonyCommitment { mode, .. } => Some(mode),
        _ => None,
    }
}

fn record_screen(flow: FlowKind, screen: Screen<'_>, trace: &mut Trace) {
    let kind = screen.kind();
    let mode = entropy_input_mode(screen);
    let index = fact_index(screen);
    let role = factor_role(screen);
    assert_screen(flow, screen);
    trace.snapshots.push(Snapshot {
        flow,
        screen: Some(kind),
        entropy_mode: mode,
        fact_index: index,
        factor_role: role,
        terminal: None,
        has_approval: false,
    });
}

fn record_root(flow: &ScreenFlow, trace: &mut Trace) {
    let screen = flow.screen();
    let mode = screen.and_then(entropy_input_mode);
    let role = screen.and_then(factor_role);
    match (flow.screen_kind(), screen) {
        (Some(kind), Some(screen)) => {
            assert_eq!(kind, screen.kind());
            assert_screen(flow.flow_kind(), screen);
        }
        (None, None) => {
            assert!(flow.is_finished());
            assert!(flow.approval_identity().is_none());
            if let Some(FlowTerminal::FailedWiped(reason)) = flow.terminal() {
                assert_named_reason(reason);
            }
        }
        _ => panic!("root screen availability disagrees with root state"),
    }
    trace.snapshots.push(Snapshot {
        flow: flow.flow_kind(),
        screen: flow.screen_kind(),
        entropy_mode: mode,
        fact_index: screen.and_then(fact_index),
        factor_role: role,
        terminal: flow.terminal(),
        has_approval: flow.approval_identity().is_some(),
    });
}

fn assert_scoped_outcome(flow: &ScreenFlow, outcome: ScopedApplyOutcome) {
    match outcome {
        ScopedApplyOutcome::Continue(kind) | ScopedApplyOutcome::Released(kind) => {
            assert_eq!(flow.screen_kind(), Some(kind));
            assert!(flow.terminal().is_none());
        }
        ScopedApplyOutcome::CompletedWiped => {
            assert_eq!(flow.terminal(), Some(FlowTerminal::CompletedWiped));
        }
        ScopedApplyOutcome::FailedWiped(reason) => {
            assert_named_reason(reason);
            assert_eq!(flow.terminal(), Some(FlowTerminal::FailedWiped(reason)));
        }
    }
}

fn fixed_failure(event: FlowEvent<'_>) -> Option<WipingReason> {
    match event {
        FlowEvent::CardRemoved => Some(WipingReason::CardRemoved),
        FlowEvent::SessionTimeout => Some(WipingReason::SessionTimeout),
        FlowEvent::OperationFailed => Some(WipingReason::OperationFailed),
        FlowEvent::MediaRemoved => Some(WipingReason::MediaRemoved),
        FlowEvent::Shutdown => Some(WipingReason::Shutdown),
        FlowEvent::Restart => Some(WipingReason::Restart),
        FlowEvent::PowerLoss => Some(WipingReason::PowerLoss),
        _ => None,
    }
}

fn assert_expected_failure(flow: &ScreenFlow, expected: Option<WipingReason>) {
    if let Some(reason) = expected {
        assert_eq!(
            flow.terminal(),
            Some(FlowTerminal::FailedWiped(reason)),
            "closed event must route to its named wiping outcome"
        );
    }
}

fn raw_commitment(payload: &[u8]) -> [u8; 32] {
    let mut commitment = [0u8; 32];
    for (index, byte) in payload.iter().copied().take(32).enumerate() {
        commitment[index] = byte;
    }
    commitment
}

fn decode_event<'a>(
    selector: u8,
    payload: &'a [u8],
    current_identity: Option<ApprovalIdentity>,
    pending_hold: Option<ApprovalToken>,
) -> FlowEvent<'a> {
    match selector % 39 {
        0..=18 => FlowEvent::Key(keypad(selector % 39)),
        19 => FlowEvent::OperationCompleted(CompletedOperation::Plain),
        20 => FlowEvent::OperationCompleted(CompletedOperation::Provisioning(provisioning())),
        21 => FlowEvent::OperationCompleted(CompletedOperation::Review(review_ready())),
        22 => FlowEvent::OperationCompleted(CompletedOperation::Export(export())),
        23 => FlowEvent::OperationFailed,
        24 => FlowEvent::CeremonyEchoReady(payload),
        25 => FlowEvent::CeremonyCommitmentReady(raw_commitment(payload)),
        26 => FlowEvent::TransportPresented,
        27 => FlowEvent::CameraPresented,
        28 => FlowEvent::IntakePresented,
        29 => FlowEvent::MediaRemoved,
        30 => FlowEvent::ApprovalHoldStarted,
        31 => FlowEvent::ApprovalHoldCompleted(if selector & 0x40 == 0 {
            pending_hold.unwrap_or_else(|| foreign_identity().token())
        } else {
            foreign_identity().token()
        }),
        32 => FlowEvent::SigningOutcome {
            identity: current_identity.unwrap_or_else(foreign_identity),
        },
        33 => FlowEvent::SigningOutcome {
            identity: foreign_identity(),
        },
        34 => FlowEvent::CardRemoved,
        35 => FlowEvent::SessionTimeout,
        36 => FlowEvent::Shutdown,
        37 => FlowEvent::Restart,
        38 => FlowEvent::PowerLoss,
        _ => unreachable!("modulo thirty-nine is exhaustive"),
    }
}

fn next_selector(data: &[u8], cursor: &mut usize) -> Option<u8> {
    if *cursor >= data.len() || *cursor >= MAX_EVENTS + 2 {
        return None;
    }
    let selector = data[*cursor];
    *cursor += 1;
    Some(selector)
}

fn drive_ceremony_raw(
    mut session: CeremonySession<'_, '_>,
    flow: FlowKind,
    data: &[u8],
    cursor: &mut usize,
    trace: &mut Trace,
) {
    let payload = &data[..data.len().min(MAX_PRESENTED_BYTES)];
    record_screen(flow, session.screen(), trace);
    loop {
        let Some(selector) = next_selector(data, cursor) else {
            drop(session);
            return;
        };
        let event = decode_event(selector, payload, None, None);
        let expected = fixed_failure(event);
        match session.apply(event).expect("live ceremony session") {
            CeremonySessionOutcome::Continue(next) => {
                session = next;
                record_screen(flow, session.screen(), trace);
            }
            CeremonySessionOutcome::Released(outcome) => {
                if let Some(reason) = expected {
                    assert_eq!(outcome, ScopedApplyOutcome::FailedWiped(reason));
                }
                return;
            }
        }
    }
}

fn drive_provisioning_result_raw(
    session: ProvisioningResultSession<'_, '_>,
    flow: FlowKind,
    data: &[u8],
    cursor: &mut usize,
    trace: &mut Trace,
) {
    record_screen(flow, session.screen(), trace);
    let Some(selector) = next_selector(data, cursor) else {
        drop(session);
        return;
    };
    let payload = &data[..data.len().min(MAX_PRESENTED_BYTES)];
    let event = decode_event(selector, payload, None, None);
    let expected = fixed_failure(event);
    let outcome = session
        .apply(event)
        .expect("live provisioning-result session");
    if let Some(reason) = expected {
        assert_eq!(outcome, ScopedApplyOutcome::FailedWiped(reason));
    }
}

fn drive_review_raw(
    mut session: ReviewSession<'_, '_>,
    flow: FlowKind,
    data: &[u8],
    cursor: &mut usize,
    trace: &mut Trace,
) {
    let payload = &data[..data.len().min(MAX_PRESENTED_BYTES)];
    record_screen(flow, session.screen().expect("live review screen"), trace);
    loop {
        let Some(selector) = next_selector(data, cursor) else {
            drop(session);
            return;
        };
        let pending = session.pending_hold_token();
        let event = decode_event(selector, payload, None, pending);
        let before = session.screen().expect("live review screen").kind();
        let expected = fixed_failure(event).or_else(|| match event {
            FlowEvent::ApprovalHoldStarted | FlowEvent::ApprovalHoldCompleted(_)
                if before != ScreenKind::FinalApproval =>
            {
                Some(WipingReason::ReviewIncomplete)
            }
            FlowEvent::ApprovalHoldStarted if pending.is_some() => {
                Some(WipingReason::ReviewIdentityMismatch)
            }
            FlowEvent::ApprovalHoldCompleted(token) if pending != Some(token) => {
                Some(WipingReason::ReviewIdentityMismatch)
            }
            _ => None,
        });
        match session.apply(event).expect("live review session") {
            ReviewSessionOutcome::Continue(next) => {
                assert!(expected.is_none());
                session = next;
                record_screen(
                    flow,
                    session.screen().expect("continued review screen"),
                    trace,
                );
            }
            ReviewSessionOutcome::Released(outcome) => {
                if let Some(reason) = expected {
                    assert_eq!(outcome, ScopedApplyOutcome::FailedWiped(reason));
                }
                return;
            }
        }
    }
}

fn drive_transaction_result_raw(
    session: TransactionResultSession<'_, '_>,
    flow: FlowKind,
    data: &[u8],
    cursor: &mut usize,
    trace: &mut Trace,
) {
    record_screen(flow, session.screen(), trace);
    let Some(selector) = next_selector(data, cursor) else {
        drop(session);
        return;
    };
    let payload = &data[..data.len().min(MAX_PRESENTED_BYTES)];
    let event = decode_event(selector, payload, None, None);
    let expected = fixed_failure(event);
    let outcome = session
        .apply(event)
        .expect("live transaction-result session");
    if let Some(reason) = expected {
        assert_eq!(outcome, ScopedApplyOutcome::FailedWiped(reason));
    }
}

fn apply_root_raw_event(
    flow: &mut ScreenFlow,
    selector: u8,
    data: &[u8],
    cursor: &mut usize,
    trace: &mut Trace,
) {
    let payload = &data[..data.len().min(MAX_PRESENTED_BYTES)];
    let current = flow.approval_identity();
    let event = decode_event(selector, payload, current, None);
    let kind = flow.flow_kind();
    let expected = fixed_failure(event)
        .or_else(|| {
            matches!(
                event,
                FlowEvent::TransportPresented
                    | FlowEvent::CameraPresented
                    | FlowEvent::IntakePresented
            )
            .then_some(WipingReason::PostApprovalYield)
            .filter(|_| current.is_some())
        })
        .or_else(|| {
            matches!(
                event,
                FlowEvent::ApprovalHoldStarted | FlowEvent::ApprovalHoldCompleted(_)
            )
            .then_some(WipingReason::ReviewIncomplete)
            .filter(|_| kind != FlowKind::Provisioning)
        })
        .or_else(|| match event {
            FlowEvent::SigningOutcome { identity }
                if flow.screen_kind() == Some(ScreenKind::AwaitingSigning)
                    && current != Some(identity) =>
            {
                Some(WipingReason::ReviewIdentityMismatch)
            }
            _ => None,
        });
    let mut direct_outcome = None;
    match flow.apply(event) {
        Ok(FlowApplyOutcome::Continue(next)) => {
            direct_outcome = Some(ScopedApplyOutcome::Continue(next));
        }
        Ok(FlowApplyOutcome::Ceremony(session)) => {
            assert!(expected.is_none());
            drive_ceremony_raw(session, kind, data, cursor, trace);
        }
        Ok(FlowApplyOutcome::ProvisioningResult(session)) => {
            assert!(expected.is_none());
            drive_provisioning_result_raw(session, kind, data, cursor, trace);
        }
        Ok(FlowApplyOutcome::Review(session)) => {
            assert!(expected.is_none());
            drive_review_raw(session, kind, data, cursor, trace);
        }
        Ok(FlowApplyOutcome::TransactionResult(session)) => {
            assert!(expected.is_none());
            drive_transaction_result_raw(session, kind, data, cursor, trace);
        }
        Ok(FlowApplyOutcome::CompletedWiped) => {
            direct_outcome = Some(ScopedApplyOutcome::CompletedWiped);
        }
        Ok(FlowApplyOutcome::FailedWiped(reason)) => {
            direct_outcome = Some(ScopedApplyOutcome::FailedWiped(reason));
        }
        Err(_) => panic!("event submitted only to live root"),
    }
    if let Some(outcome) = direct_outcome {
        assert_scoped_outcome(flow, outcome);
    }
    assert_expected_failure(flow, expected);
    record_root(flow, trace);
}

fn drive_ceremony_canonical(session: CeremonySession<'_, '_>, flow: FlowKind, trace: &mut Trace) {
    record_screen(flow, session.screen(), trace);
    let session = match session
        .apply(FlowEvent::Key(KeypadKey::EqualsConfirmEnter))
        .expect("ceremony echo confirmation")
    {
        CeremonySessionOutcome::Continue(session) => session,
        CeremonySessionOutcome::Released(_) => panic!("echo confirmation released early"),
    };
    record_screen(flow, session.screen(), trace);
    match session
        .apply(FlowEvent::Key(KeypadKey::EqualsConfirmEnter))
        .expect("ceremony unit acceptance")
    {
        CeremonySessionOutcome::Released(ScopedApplyOutcome::Released(
            ScreenKind::CeremonyConfirm,
        )) => {}
        _ => panic!("ceremony unit did not release at exact boundary"),
    }
}

fn drive_provisioning_result_canonical(
    session: ProvisioningResultSession<'_, '_>,
    flow: FlowKind,
    trace: &mut Trace,
) {
    record_screen(flow, session.screen(), trace);
    assert_eq!(
        session
            .apply(FlowEvent::Key(KeypadKey::EqualsConfirmEnter))
            .expect("provisioning-result confirmation"),
        ScopedApplyOutcome::Released(ScreenKind::ProvisionB)
    );
}

fn drive_review_canonical(mut session: ReviewSession<'_, '_>, flow: FlowKind, trace: &mut Trace) {
    loop {
        let screen = session.screen().expect("canonical review screen");
        let kind = screen.kind();
        record_screen(flow, screen, trace);
        let event = if kind == ScreenKind::FinalApproval {
            match session.pending_hold_token() {
                None => FlowEvent::ApprovalHoldStarted,
                Some(token) => FlowEvent::ApprovalHoldCompleted(token),
            }
        } else {
            FlowEvent::Key(KeypadKey::EqualsConfirmEnter)
        };
        match session.apply(event).expect("canonical review transition") {
            ReviewSessionOutcome::Continue(next) => session = next,
            ReviewSessionOutcome::Released(ScopedApplyOutcome::Released(kind)) => {
                assert!(matches!(
                    kind,
                    ScreenKind::AwaitingSigning | ScreenKind::PostApprovalFactor
                ));
                return;
            }
            ReviewSessionOutcome::Released(_) => panic!("canonical review failed"),
        }
    }
}

fn drive_transaction_result_canonical(
    session: TransactionResultSession<'_, '_>,
    flow: FlowKind,
    trace: &mut Trace,
) {
    record_screen(flow, session.screen(), trace);
    let outcome = session
        .apply(FlowEvent::Key(KeypadKey::EqualsConfirmEnter))
        .expect("transaction-result confirmation");
    match flow {
        FlowKind::SigningA1B => assert_eq!(outcome, ScopedApplyOutcome::CompletedWiped),
        FlowKind::RecoveryA1C | FlowKind::RecoveryBC => assert_eq!(
            outcome,
            ScopedApplyOutcome::Released(ScreenKind::RecoveryRotation)
        ),
        FlowKind::Provisioning => panic!("provisioning has no transaction result"),
    }
}

fn canonical_root_event(flow: &ScreenFlow) -> Option<FlowEvent<'static>> {
    Some(match flow.screen_kind()? {
        ScreenKind::ProvisioningStart
        | ScreenKind::TierSelection
        | ScreenKind::EntropyModeSelection
        | ScreenKind::CeremonyCommitment
        | ScreenKind::KitReady
        | ScreenKind::FlowStart
        | ScreenKind::Route
        | ScreenKind::RecoveryRotation => FlowEvent::Key(KeypadKey::EqualsConfirmEnter),
        ScreenKind::CeremonyInput => FlowEvent::CeremonyEchoReady(CEREMONY_UNIT),
        ScreenKind::CeremonyConfirm => FlowEvent::CeremonyCommitmentReady(CEREMONY_COMMITMENT),
        ScreenKind::DerivationExplanation => {
            FlowEvent::OperationCompleted(CompletedOperation::Provisioning(provisioning()))
        }
        ScreenKind::ProvisionB
        | ScreenKind::VerifyB
        | ScreenKind::ProvisionC
        | ScreenKind::VerifyC
        | ScreenKind::CreateA1
        | ScreenKind::ScanBackA1
        | ScreenKind::CoordinatorMaterial
        | ScreenKind::Rehearsal
        | ScreenKind::Factor
        | ScreenKind::PostApprovalFactor => {
            FlowEvent::OperationCompleted(CompletedOperation::Plain)
        }
        ScreenKind::Transport => FlowEvent::TransportPresented,
        ScreenKind::Intake => FlowEvent::IntakePresented,
        ScreenKind::Validation => {
            FlowEvent::OperationCompleted(CompletedOperation::Review(review_ready()))
        }
        ScreenKind::AwaitingSigning => FlowEvent::SigningOutcome {
            identity: flow
                .approval_identity()
                .expect("canonical signing retains approval identity"),
        },
        ScreenKind::Export => FlowEvent::OperationCompleted(CompletedOperation::Export(export())),
        ScreenKind::CeremonyEcho
        | ScreenKind::ProvisioningResult
        | ScreenKind::ReviewOverview
        | ScreenKind::ReviewArithmetic
        | ScreenKind::ReviewRecipient
        | ScreenKind::ReviewChange
        | ScreenKind::ReviewOpReturn
        | ScreenKind::ReviewLocktime
        | ScreenKind::ReviewSequence
        | ScreenKind::ReviewFeePolicy
        | ScreenKind::FinalApproval
        | ScreenKind::TransactionResult => return None,
    })
}

fn drive_canonical(flow: &mut ScreenFlow, trace: &mut Trace, limit: usize) {
    for _ in 0..limit {
        if flow.is_finished() {
            break;
        }
        let event = canonical_root_event(flow).expect("canonical root event");
        let kind = flow.flow_kind();
        match flow.apply(event).expect("live canonical root") {
            FlowApplyOutcome::Continue(_) => {}
            FlowApplyOutcome::Ceremony(session) => drive_ceremony_canonical(session, kind, trace),
            FlowApplyOutcome::ProvisioningResult(session) => {
                drive_provisioning_result_canonical(session, kind, trace)
            }
            FlowApplyOutcome::Review(session) => drive_review_canonical(session, kind, trace),
            FlowApplyOutcome::TransactionResult(session) => {
                drive_transaction_result_canonical(session, kind, trace)
            }
            FlowApplyOutcome::CompletedWiped => {}
            FlowApplyOutcome::FailedWiped(reason) => {
                panic!("canonical route failed with {reason:?}")
            }
        }
        record_root(flow, trace);
    }
}

fn assert_fixed_review_order(trace: &Trace) {
    let review = review_ready().review();
    let mut expected = vec![
        (ScreenKind::ReviewOverview, None),
        (ScreenKind::ReviewArithmetic, None),
    ];
    expected.extend(
        review
            .outputs()
            .iter()
            .filter(|output| is_recipient(output))
            .map(|output| (ScreenKind::ReviewRecipient, Some(output.index()))),
    );
    expected.extend(
        review
            .outputs()
            .iter()
            .filter(|output| is_change(output))
            .map(|output| (ScreenKind::ReviewChange, Some(output.index()))),
    );
    expected.extend(
        review
            .outputs()
            .iter()
            .filter(|output| is_op_return(output))
            .map(|output| (ScreenKind::ReviewOpReturn, Some(output.index()))),
    );
    expected.push((ScreenKind::ReviewLocktime, None));
    expected.extend(
        review
            .inputs()
            .iter()
            .map(|input| (ScreenKind::ReviewSequence, Some(input.index()))),
    );
    expected.push((ScreenKind::ReviewFeePolicy, None));
    expected.push((ScreenKind::FinalApproval, None));
    expected.push((ScreenKind::FinalApproval, None));

    let observed: Vec<_> = trace
        .snapshots
        .iter()
        .filter_map(|snapshot| {
            snapshot.screen.and_then(|kind| {
                matches!(
                    kind,
                    ScreenKind::ReviewOverview
                        | ScreenKind::ReviewArithmetic
                        | ScreenKind::ReviewRecipient
                        | ScreenKind::ReviewChange
                        | ScreenKind::ReviewOpReturn
                        | ScreenKind::ReviewLocktime
                        | ScreenKind::ReviewSequence
                        | ScreenKind::ReviewFeePolicy
                        | ScreenKind::FinalApproval
                )
                .then_some((kind, snapshot.fact_index))
            })
        })
        .collect();
    assert_eq!(observed, expected, "canonical review visitation order");
}

fn assert_fixed_factor_order(trace: &Trace, flow: FlowKind) {
    let observed = trace
        .snapshots
        .iter()
        .filter_map(|snapshot| snapshot.factor_role)
        .collect::<Vec<_>>();
    let expected = match flow {
        FlowKind::Provisioning => Vec::new(),
        FlowKind::SigningA1B => vec![FactorRole::SignerB, FactorRole::A1],
        FlowKind::RecoveryA1C => vec![FactorRole::EmergencySignerC, FactorRole::A1],
        FlowKind::RecoveryBC => vec![
            FactorRole::SignerB,
            FactorRole::SignerC,
            FactorRole::SignerB,
            FactorRole::SignerC,
        ],
    };
    assert_eq!(observed, expected, "canonical factor order");
}

fn assert_terminal_stability(flow: &mut ScreenFlow, trace: &mut Trace) {
    if flow.is_finished() {
        let terminal = flow.terminal();
        assert!(flow
            .apply(FlowEvent::Key(KeypadKey::EqualsConfirmEnter))
            .is_err());
        assert_eq!(flow.terminal(), terminal);
        record_root(flow, trace);
    }
}

fn foreign_identity() -> ApprovalIdentity {
    *FOREIGN_IDENTITY.get_or_init(|| {
        let mut flow = ScreenFlow::new(FlowKind::SigningA1B);
        let mut trace = Trace {
            snapshots: Vec::new(),
        };
        record_root(&flow, &mut trace);
        for _ in 0..MAX_EVENTS {
            if flow.screen_kind() == Some(ScreenKind::AwaitingSigning) {
                break;
            }
            drive_canonical(&mut flow, &mut trace, 1);
        }
        flow.approval_identity()
            .expect("foreign fixture reaches approval")
    })
}

fn run_raw(data: &[u8]) -> Trace {
    let kind = flow_kind(data.get(1).copied().unwrap_or(0));
    let mut flow = ScreenFlow::new(kind);
    let mut trace = Trace {
        snapshots: Vec::new(),
    };
    record_root(&flow, &mut trace);
    let mut cursor = 2;
    while !flow.is_finished() {
        let Some(selector) = next_selector(data, &mut cursor) else {
            break;
        };
        apply_root_raw_event(&mut flow, selector, data, &mut cursor, &mut trace);
    }
    assert_terminal_stability(&mut flow, &mut trace);
    trace
}

fn run_canonical(data: &[u8]) -> Trace {
    let kind = flow_kind(data.get(1).copied().unwrap_or(0));
    let mut flow = ScreenFlow::new(kind);
    let mut trace = Trace {
        snapshots: Vec::new(),
    };
    record_root(&flow, &mut trace);
    drive_canonical(&mut flow, &mut trace, MAX_EVENTS);
    assert_eq!(flow.terminal(), Some(FlowTerminal::CompletedWiped));
    if kind != FlowKind::Provisioning {
        assert_fixed_review_order(&trace);
    }
    assert_fixed_factor_order(&trace, kind);
    assert_terminal_stability(&mut flow, &mut trace);
    trace
}

fn run_prefix_injection(data: &[u8]) -> Trace {
    let kind = flow_kind(data.get(1).copied().unwrap_or(0));
    let mut flow = ScreenFlow::new(kind);
    let mut trace = Trace {
        snapshots: Vec::new(),
    };
    record_root(&flow, &mut trace);
    let prefix = usize::from(data.get(2).copied().unwrap_or(0)) % 48;
    drive_canonical(&mut flow, &mut trace, prefix);
    let mut cursor = 4;
    if !flow.is_finished() {
        let selector = data.get(3).copied().unwrap_or(0);
        apply_root_raw_event(&mut flow, selector, data, &mut cursor, &mut trace);
    }
    while !flow.is_finished() {
        let Some(selector) = next_selector(data, &mut cursor) else {
            break;
        };
        apply_root_raw_event(&mut flow, selector, data, &mut cursor, &mut trace);
    }
    assert_terminal_stability(&mut flow, &mut trace);
    trace
}

fn drive_to_approved(flow: &mut ScreenFlow, trace: &mut Trace) {
    for _ in 0..MAX_EVENTS {
        if flow.screen_kind() == Some(ScreenKind::AwaitingSigning)
            && flow.approval_identity().is_some()
        {
            return;
        }
        drive_canonical(flow, trace, 1);
    }
    panic!("bounded canonical path did not reach approved signing state");
}

fn run_post_approval(data: &[u8]) -> Trace {
    let kind = match data.get(1).copied().unwrap_or(0) % 3 {
        0 => FlowKind::SigningA1B,
        1 => FlowKind::RecoveryA1C,
        2 => FlowKind::RecoveryBC,
        _ => unreachable!("modulo three is exhaustive"),
    };
    let mut flow = ScreenFlow::new(kind);
    let mut trace = Trace {
        snapshots: Vec::new(),
    };
    record_root(&flow, &mut trace);
    drive_to_approved(&mut flow, &mut trace);
    let current = flow
        .approval_identity()
        .expect("approved path retains identity");
    let event = match data.get(2).copied().unwrap_or(0) % 5 {
        0 => FlowEvent::TransportPresented,
        1 => FlowEvent::CameraPresented,
        2 => FlowEvent::IntakePresented,
        3 => FlowEvent::SigningOutcome {
            identity: foreign_identity(),
        },
        4 => FlowEvent::SigningOutcome { identity: current },
        _ => unreachable!("modulo five is exhaustive"),
    };
    match flow.apply(event).expect("live approved root") {
        FlowApplyOutcome::Continue(_) => {}
        FlowApplyOutcome::FailedWiped(reason) => assert_named_reason(reason),
        _ => panic!("post-approval event returned impossible scoped outcome"),
    }
    record_root(&flow, &mut trace);
    match data.get(2).copied().unwrap_or(0) % 5 {
        0..=2 => assert_eq!(
            flow.terminal(),
            Some(FlowTerminal::FailedWiped(WipingReason::PostApprovalYield))
        ),
        3 => assert_eq!(
            flow.terminal(),
            Some(FlowTerminal::FailedWiped(
                WipingReason::ReviewIdentityMismatch
            ))
        ),
        4 => {
            drive_canonical(&mut flow, &mut trace, MAX_EVENTS);
            assert_eq!(flow.terminal(), Some(FlowTerminal::CompletedWiped));
        }
        _ => unreachable!("modulo five is exhaustive"),
    }
    assert_terminal_stability(&mut flow, &mut trace);
    trace
}

fn execute(data: &[u8]) -> Trace {
    match data.first().copied().unwrap_or(0) & 3 {
        0 => run_raw(data),
        1 => run_canonical(data),
        2 => run_prefix_injection(data),
        3 => run_post_approval(data),
        _ => unreachable!("two-bit strategy selector"),
    }
}

fuzz_target!(|data: &[u8]| {
    if data.len() > MAX_PRESENTED_BYTES {
        return;
    }
    let first = execute(data);
    let second = execute(data);
    assert_eq!(
        first, second,
        "same event bytes must have one observable trace"
    );
});
