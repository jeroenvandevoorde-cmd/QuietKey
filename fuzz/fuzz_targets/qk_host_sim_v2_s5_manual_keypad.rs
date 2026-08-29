#![no_main]

use libfuzzer_sys::fuzz_target;
use qk_host_sim::{
    CeremonyPurposeV2, EntropyInputModeV2, FlowApplyOutcomeV2, FlowEventV2, FlowKindV2,
    FlowTerminalV2, KeypadKey, ManualKeypadErrorV2, ManualKeypadEventV2, ManualKeypadOutcomeV2,
    ManualKeypadScreenV2, ManualKeypadSessionV2, ScreenFlowV2, ScreenKindV2, ScreenV2,
    WipingReasonV2, MANUAL_TRANSCRIPT_BYTES_V2,
};

const MAX_EVENTS: usize = 1_024;

#[derive(Clone, Debug, Eq, PartialEq)]
enum OutcomeKind {
    Continue,
    ProvisioningReady,
    Rejected(ManualKeypadErrorV2),
}

#[derive(Clone, Debug, Eq, PartialEq)]
enum ScreenSnapshot {
    Entry(CeremonyPurposeV2, usize),
    Echo(CeremonyPurposeV2, Vec<u8>),
    Confirm(CeremonyPurposeV2, Vec<u8>),
    AwaitingCommitment(CeremonyPurposeV2),
    Commitment(CeremonyPurposeV2, [u8; 32]),
    Complete,
    Failed(ManualKeypadErrorV2),
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct StepSnapshot {
    outcome: OutcomeKind,
    screen: ScreenSnapshot,
    retained_counts: [usize; 4],
    terminal: Option<FlowTerminalV2>,
}

fn root_continue(flow: &mut ScreenFlowV2, event: FlowEventV2<'_>, expected: ScreenKindV2) {
    assert!(matches!(
        flow.apply(event).expect("closed v2 setup transition"),
        FlowApplyOutcomeV2::Continue(actual) if actual == expected
    ));
}

fn manual_root_flow() -> ScreenFlowV2 {
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
    flow
}

fn entry_session() -> ManualKeypadSessionV2 {
    ManualKeypadSessionV2::begin(manual_root_flow()).expect("closed v2 manual-keypad entry")
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

fn event(selector: u8) -> ManualKeypadEventV2 {
    match selector % 28 {
        0..=18 => ManualKeypadEventV2::Key(keypad(selector)),
        19 => ManualKeypadEventV2::CommitmentReady([selector; 32]),
        20 => ManualKeypadEventV2::OperationFailed,
        21 => ManualKeypadEventV2::MediaRemoved,
        22 => ManualKeypadEventV2::CardRemoved,
        23 => ManualKeypadEventV2::SessionTimeout,
        24 => ManualKeypadEventV2::Shutdown,
        25 => ManualKeypadEventV2::Restart,
        26 => ManualKeypadEventV2::PowerLoss,
        27 => ManualKeypadEventV2::Key(KeypadKey::EqualsConfirmEnter),
        _ => unreachable!("modulo twenty-eight is exhaustive"),
    }
}

fn screen_snapshot(session: &ManualKeypadSessionV2) -> ScreenSnapshot {
    match session.screen() {
        ManualKeypadScreenV2::Entry { purpose, count } => ScreenSnapshot::Entry(purpose, count),
        ManualKeypadScreenV2::Echo {
            purpose,
            transcript,
        } => ScreenSnapshot::Echo(purpose, transcript.bytes().to_vec()),
        ManualKeypadScreenV2::Confirm {
            purpose,
            transcript,
        } => ScreenSnapshot::Confirm(purpose, transcript.bytes().to_vec()),
        ManualKeypadScreenV2::AwaitingCommitment { purpose } => {
            ScreenSnapshot::AwaitingCommitment(purpose)
        }
        ManualKeypadScreenV2::Commitment {
            purpose,
            commitment,
        } => ScreenSnapshot::Commitment(purpose, commitment),
        ManualKeypadScreenV2::Complete => ScreenSnapshot::Complete,
        ManualKeypadScreenV2::Failed(error) => ScreenSnapshot::Failed(error),
    }
}

fn apply_snapshot(session: &mut ManualKeypadSessionV2, event: ManualKeypadEventV2) -> StepSnapshot {
    let outcome = match session.apply(event) {
        Ok(ManualKeypadOutcomeV2::Continue) => OutcomeKind::Continue,
        Ok(ManualKeypadOutcomeV2::ProvisioningReady(_)) => OutcomeKind::ProvisioningReady,
        Err(error) => OutcomeKind::Rejected(error),
    };
    StepSnapshot {
        outcome,
        screen: screen_snapshot(session),
        retained_counts: session.retained_counts(),
        terminal: session.terminal(),
    }
}

fn assert_secret_visible_only_during_echo_or_confirm(snapshot: &ScreenSnapshot) {
    match snapshot {
        ScreenSnapshot::Echo(_, bytes) | ScreenSnapshot::Confirm(_, bytes) => {
            assert_eq!(bytes.len(), MANUAL_TRANSCRIPT_BYTES_V2);
            assert!(bytes.iter().all(|byte| (b'1'..=b'6').contains(byte)));
        }
        ScreenSnapshot::Entry(_, _)
        | ScreenSnapshot::AwaitingCommitment(_)
        | ScreenSnapshot::Commitment(_, _)
        | ScreenSnapshot::Complete
        | ScreenSnapshot::Failed(_) => {}
    }
}

fn trace(data: &[u8]) -> Vec<StepSnapshot> {
    let mut session = entry_session();
    data.iter()
        .copied()
        .take(MAX_EVENTS)
        .map(|selector| {
            let snapshot = apply_snapshot(&mut session, event(selector));
            assert_secret_visible_only_during_echo_or_confirm(&snapshot.screen);
            snapshot
        })
        .collect()
}

fn press(session: &mut ManualKeypadSessionV2, key: KeypadKey) -> StepSnapshot {
    let snapshot = apply_snapshot(session, ManualKeypadEventV2::Key(key));
    assert_eq!(snapshot.outcome, OutcomeKind::Continue);
    snapshot
}

fn fill(session: &mut ManualKeypadSessionV2, key: KeypadKey, count: usize) {
    for _ in 0..count {
        let _ = press(session, key);
    }
}

fn assert_rejection(
    session: &mut ManualKeypadSessionV2,
    event: ManualKeypadEventV2,
    expected: ManualKeypadErrorV2,
    counts: [usize; 4],
) -> StepSnapshot {
    let before = screen_snapshot(session);
    let snapshot = apply_snapshot(session, event);
    assert_eq!(snapshot.outcome, OutcomeKind::Rejected(expected));
    assert_eq!(snapshot.screen, before);
    assert_eq!(snapshot.retained_counts, counts);
    assert_eq!(snapshot.terminal, None);
    assert!(!expected.name().is_empty());
    snapshot
}

fn rejection_oracles(selector: u8) -> Vec<StepSnapshot> {
    let invalid_keys = [
        KeypadKey::Seven,
        KeypadKey::EightUp,
        KeypadKey::Nine,
        KeypadKey::Zero,
        KeypadKey::Decimal,
        KeypadKey::Plus,
        KeypadKey::Minus,
        KeypadKey::Multiply,
        KeypadKey::Divide,
        KeypadKey::Percent,
    ];
    let mut snapshots = Vec::with_capacity(4);

    let mut invalid = entry_session();
    let _ = press(&mut invalid, KeypadKey::One);
    snapshots.push(assert_rejection(
        &mut invalid,
        ManualKeypadEventV2::Key(invalid_keys[usize::from(selector) % invalid_keys.len()]),
        ManualKeypadErrorV2::InvalidFaceKey,
        [1, 0, 0, 0],
    ));

    let mut empty = entry_session();
    snapshots.push(assert_rejection(
        &mut empty,
        ManualKeypadEventV2::Key(KeypadKey::CeDelete),
        ManualKeypadErrorV2::EmptyDelete,
        [0; 4],
    ));

    let mut incomplete = entry_session();
    let _ = press(&mut incomplete, KeypadKey::TwoDown);
    snapshots.push(assert_rejection(
        &mut incomplete,
        ManualKeypadEventV2::Key(KeypadKey::EqualsConfirmEnter),
        ManualKeypadErrorV2::TranscriptCountIncomplete,
        [1, 0, 0, 0],
    ));

    let mut full = entry_session();
    fill(&mut full, KeypadKey::Three, MANUAL_TRANSCRIPT_BYTES_V2);
    snapshots.push(assert_rejection(
        &mut full,
        ManualKeypadEventV2::Key(KeypadKey::FourLeft),
        ManualKeypadErrorV2::TranscriptFull,
        [MANUAL_TRANSCRIPT_BYTES_V2, 0, 0, 0],
    ));
    snapshots
}

fn finish_purpose(
    session: &mut ManualKeypadSessionV2,
    purpose: CeremonyPurposeV2,
    key: KeypadKey,
    commitment: [u8; 32],
    snapshots: &mut Vec<StepSnapshot>,
) -> OutcomeKind {
    assert_eq!(screen_snapshot(session), ScreenSnapshot::Entry(purpose, 0));
    fill(session, key, MANUAL_TRANSCRIPT_BYTES_V2);
    snapshots.push(press(session, KeypadKey::EqualsConfirmEnter));
    assert!(matches!(
        screen_snapshot(session),
        ScreenSnapshot::Echo(actual, _) if actual == purpose
    ));
    snapshots.push(press(session, KeypadKey::EqualsConfirmEnter));
    assert!(matches!(
        screen_snapshot(session),
        ScreenSnapshot::Confirm(actual, _) if actual == purpose
    ));
    snapshots.push(press(session, KeypadKey::EqualsConfirmEnter));
    assert_eq!(
        screen_snapshot(session),
        ScreenSnapshot::AwaitingCommitment(purpose)
    );
    let commitment_snapshot =
        apply_snapshot(session, ManualKeypadEventV2::CommitmentReady(commitment));
    assert_eq!(commitment_snapshot.outcome, OutcomeKind::Continue);
    snapshots.push(commitment_snapshot);
    assert_eq!(
        screen_snapshot(session),
        ScreenSnapshot::Commitment(purpose, commitment)
    );
    let final_snapshot = apply_snapshot(
        session,
        ManualKeypadEventV2::Key(KeypadKey::EqualsConfirmEnter),
    );
    let outcome = final_snapshot.outcome.clone();
    snapshots.push(final_snapshot);
    outcome
}

fn complete_oracle() -> Vec<StepSnapshot> {
    let cases = [
        (CeremonyPurposeV2::SeedA, KeypadKey::One, [0x11; 32]),
        (CeremonyPurposeV2::SignerB, KeypadKey::TwoDown, [0x22; 32]),
        (CeremonyPurposeV2::KitR, KeypadKey::Three, [0x33; 32]),
        (CeremonyPurposeV2::A2, KeypadKey::FourLeft, [0x44; 32]),
    ];
    let mut session = entry_session();
    let mut snapshots = Vec::new();
    for (index, (purpose, key, commitment)) in cases.into_iter().enumerate() {
        let outcome = finish_purpose(&mut session, purpose, key, commitment, &mut snapshots);
        assert_eq!(
            outcome,
            if index == 3 {
                OutcomeKind::ProvisioningReady
            } else {
                OutcomeKind::Continue
            }
        );
        assert_eq!(
            session.retained_counts(),
            if index == 3 {
                [0; 4]
            } else {
                core::array::from_fn(|slot| {
                    if slot <= index {
                        MANUAL_TRANSCRIPT_BYTES_V2
                    } else {
                        0
                    }
                })
            }
        );
        assert_secret_visible_only_during_echo_or_confirm(&screen_snapshot(&session));
    }
    assert_eq!(screen_snapshot(&session), ScreenSnapshot::Complete);
    snapshots
}

fn reuse_oracle(pair_selector: u8) -> Vec<StepSnapshot> {
    let pairs = [(0, 1), (0, 2), (0, 3), (1, 2), (1, 3), (2, 3)];
    let (first, duplicate) = pairs[usize::from(pair_selector) % pairs.len()];
    let purposes = [
        CeremonyPurposeV2::SeedA,
        CeremonyPurposeV2::SignerB,
        CeremonyPurposeV2::KitR,
        CeremonyPurposeV2::A2,
    ];
    let mut keys = [
        KeypadKey::One,
        KeypadKey::TwoDown,
        KeypadKey::Three,
        KeypadKey::FourLeft,
    ];
    keys[duplicate] = keys[first];
    let mut session = entry_session();
    let mut snapshots = Vec::new();
    for index in 0..4 {
        let outcome = finish_purpose(
            &mut session,
            purposes[index],
            keys[index],
            [index as u8; 32],
            &mut snapshots,
        );
        if index < 3 {
            assert_eq!(outcome, OutcomeKind::Continue);
        } else {
            assert_eq!(
                outcome,
                OutcomeKind::Rejected(ManualKeypadErrorV2::TranscriptReuse)
            );
        }
    }
    assert_eq!(session.retained_counts(), [0; 4]);
    assert_eq!(
        session.terminal(),
        Some(FlowTerminalV2::FailedWiped(WipingReasonV2::OperationFailed))
    );
    assert_eq!(
        screen_snapshot(&session),
        ScreenSnapshot::Failed(ManualKeypadErrorV2::TranscriptReuse)
    );
    snapshots
}

fn interruption_oracle(selector: u8) -> Vec<StepSnapshot> {
    let cases = [
        (
            ManualKeypadEventV2::Key(KeypadKey::CancelBack),
            ManualKeypadErrorV2::Cancelled,
            WipingReasonV2::Cancelled,
        ),
        (
            ManualKeypadEventV2::OperationFailed,
            ManualKeypadErrorV2::OperationFailed,
            WipingReasonV2::OperationFailed,
        ),
        (
            ManualKeypadEventV2::MediaRemoved,
            ManualKeypadErrorV2::MediaRemoved,
            WipingReasonV2::MediaRemoved,
        ),
        (
            ManualKeypadEventV2::CardRemoved,
            ManualKeypadErrorV2::CardRemoved,
            WipingReasonV2::CardRemoved,
        ),
        (
            ManualKeypadEventV2::SessionTimeout,
            ManualKeypadErrorV2::SessionTimeout,
            WipingReasonV2::SessionTimeout,
        ),
        (
            ManualKeypadEventV2::Shutdown,
            ManualKeypadErrorV2::Shutdown,
            WipingReasonV2::Shutdown,
        ),
        (
            ManualKeypadEventV2::Restart,
            ManualKeypadErrorV2::Restart,
            WipingReasonV2::Restart,
        ),
        (
            ManualKeypadEventV2::PowerLoss,
            ManualKeypadErrorV2::PowerLoss,
            WipingReasonV2::PowerLoss,
        ),
    ];
    let (event, error, reason) = cases[usize::from(selector) % cases.len()];
    let mut session = entry_session();
    let _ = press(&mut session, KeypadKey::One);
    let snapshot = apply_snapshot(&mut session, event);
    assert_eq!(snapshot.outcome, OutcomeKind::Rejected(error));
    assert_eq!(snapshot.retained_counts, [0; 4]);
    assert_eq!(snapshot.terminal, Some(FlowTerminalV2::FailedWiped(reason)));
    assert_eq!(snapshot.screen, ScreenSnapshot::Failed(error));
    vec![snapshot]
}

fn run_once(data: &[u8]) -> Vec<StepSnapshot> {
    let mode = data.first().copied().unwrap_or(0) % 5;
    let tail = data.get(1..).unwrap_or_default();
    match mode {
        0 => trace(tail),
        1 => rejection_oracles(tail.first().copied().unwrap_or(0)),
        2 => complete_oracle(),
        3 => reuse_oracle(tail.first().copied().unwrap_or(0)),
        4 => interruption_oracle(tail.first().copied().unwrap_or(0)),
        _ => unreachable!("modulo five is exhaustive"),
    }
}

fuzz_target!(|data: &[u8]| {
    if data.len() > MAX_EVENTS + 1 {
        return;
    }
    let first = run_once(data);
    let second = run_once(data);
    assert_eq!(first, second, "v2 manual-keypad outcomes must be stable");
});
