#![no_main]

use libfuzzer_sys::fuzz_target;
use qk_host_sim::{
    CeremonyPurpose, EntropyInputMode, FlowApplyOutcome, FlowEvent, FlowKind, FlowTerminal,
    KeypadKey, ManualKeypadError, ManualKeypadEvent, ManualKeypadOutcome, ManualKeypadScreen,
    ManualKeypadSession, Screen, ScreenFlow, ScreenKind, WipingReason, MANUAL_TRANSCRIPT_BYTES,
};

const MAX_EVENTS: usize = 1_024;

#[derive(Clone, Debug, Eq, PartialEq)]
enum OutcomeKind {
    Continue,
    ProvisioningReady,
    Rejected(ManualKeypadError),
}

#[derive(Clone, Debug, Eq, PartialEq)]
enum ScreenSnapshot {
    Entry(CeremonyPurpose, usize),
    Echo(CeremonyPurpose, Vec<u8>),
    Confirm(CeremonyPurpose, Vec<u8>),
    AwaitingCommitment(CeremonyPurpose),
    Commitment(CeremonyPurpose, [u8; 32]),
    Complete,
    Failed(ManualKeypadError),
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct StepSnapshot {
    outcome: OutcomeKind,
    screen: ScreenSnapshot,
    retained_counts: [usize; 4],
    terminal: Option<FlowTerminal>,
}

fn root_continue(flow: &mut ScreenFlow, event: FlowEvent<'_>, expected: ScreenKind) {
    assert!(matches!(
        flow.apply(event).expect("closed M29 setup transition"),
        FlowApplyOutcome::Continue(actual) if actual == expected
    ));
}

fn manual_root_flow() -> ScreenFlow {
    let mut flow = ScreenFlow::new(FlowKind::Provisioning);
    root_continue(
        &mut flow,
        FlowEvent::Key(KeypadKey::EqualsConfirmEnter),
        ScreenKind::TierSelection,
    );
    root_continue(
        &mut flow,
        FlowEvent::Key(KeypadKey::EqualsConfirmEnter),
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
        FlowEvent::Key(KeypadKey::EqualsConfirmEnter),
        ScreenKind::CeremonyInput,
    );
    flow
}

fn entry_session() -> ManualKeypadSession {
    ManualKeypadSession::begin(manual_root_flow()).expect("closed M29 manual-keypad entry")
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

fn event(selector: u8) -> ManualKeypadEvent {
    match selector % 28 {
        0..=18 => ManualKeypadEvent::Key(keypad(selector)),
        19 => ManualKeypadEvent::CommitmentReady([selector; 32]),
        20 => ManualKeypadEvent::OperationFailed,
        21 => ManualKeypadEvent::MediaRemoved,
        22 => ManualKeypadEvent::CardRemoved,
        23 => ManualKeypadEvent::SessionTimeout,
        24 => ManualKeypadEvent::Shutdown,
        25 => ManualKeypadEvent::Restart,
        26 => ManualKeypadEvent::PowerLoss,
        27 => ManualKeypadEvent::Key(KeypadKey::EqualsConfirmEnter),
        _ => unreachable!("modulo twenty-eight is exhaustive"),
    }
}

fn screen_snapshot(session: &ManualKeypadSession) -> ScreenSnapshot {
    match session.screen() {
        ManualKeypadScreen::Entry { purpose, count } => ScreenSnapshot::Entry(purpose, count),
        ManualKeypadScreen::Echo {
            purpose,
            transcript,
        } => ScreenSnapshot::Echo(purpose, transcript.bytes().to_vec()),
        ManualKeypadScreen::Confirm {
            purpose,
            transcript,
        } => ScreenSnapshot::Confirm(purpose, transcript.bytes().to_vec()),
        ManualKeypadScreen::AwaitingCommitment { purpose } => {
            ScreenSnapshot::AwaitingCommitment(purpose)
        }
        ManualKeypadScreen::Commitment {
            purpose,
            commitment,
        } => ScreenSnapshot::Commitment(purpose, commitment),
        ManualKeypadScreen::Complete => ScreenSnapshot::Complete,
        ManualKeypadScreen::Failed(error) => ScreenSnapshot::Failed(error),
    }
}

fn apply_snapshot(session: &mut ManualKeypadSession, event: ManualKeypadEvent) -> StepSnapshot {
    let outcome = match session.apply(event) {
        Ok(ManualKeypadOutcome::Continue) => OutcomeKind::Continue,
        Ok(ManualKeypadOutcome::ProvisioningReady(_)) => OutcomeKind::ProvisioningReady,
        Err(error) => OutcomeKind::Rejected(error),
    };
    StepSnapshot {
        outcome,
        screen: screen_snapshot(session),
        retained_counts: session.retained_counts(),
        terminal: session.terminal(),
    }
}

fn trace(data: &[u8]) -> Vec<StepSnapshot> {
    let mut session = entry_session();
    data.iter()
        .copied()
        .take(MAX_EVENTS)
        .map(|selector| apply_snapshot(&mut session, event(selector)))
        .collect()
}

fn press(session: &mut ManualKeypadSession, key: KeypadKey) {
    assert_eq!(
        apply_snapshot(session, ManualKeypadEvent::Key(key)).outcome,
        OutcomeKind::Continue
    );
}

fn fill(session: &mut ManualKeypadSession, key: KeypadKey, count: usize) {
    for _ in 0..count {
        press(session, key);
    }
}

fn assert_echo(session: &ManualKeypadSession, purpose: CeremonyPurpose, bytes: &[u8]) {
    assert_eq!(
        screen_snapshot(session),
        ScreenSnapshot::Echo(purpose, bytes.to_vec())
    );
}

fn assert_rejection(
    session: &mut ManualKeypadSession,
    event: ManualKeypadEvent,
    expected: ManualKeypadError,
    counts: [usize; 4],
) {
    let before = screen_snapshot(session);
    let outcome = apply_snapshot(session, event);
    assert_eq!(outcome.outcome, OutcomeKind::Rejected(expected));
    assert_eq!(outcome.screen, before);
    assert_eq!(outcome.retained_counts, counts);
    assert_eq!(outcome.terminal, None);
    assert!(!expected.name().is_empty());
}

fn rejection_oracles() {
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
    for invalid in invalid_keys {
        let mut session = entry_session();
        press(&mut session, KeypadKey::One);
        assert_rejection(
            &mut session,
            ManualKeypadEvent::Key(invalid),
            ManualKeypadError::InvalidFaceKey,
            [1, 0, 0, 0],
        );
        fill(&mut session, KeypadKey::TwoDown, 99);
        press(&mut session, KeypadKey::EqualsConfirmEnter);
        let mut expected = vec![b'1'];
        expected.extend([b'2'; 99]);
        assert_echo(&session, CeremonyPurpose::SeedA, &expected);
    }

    let mut session = entry_session();
    assert_rejection(
        &mut session,
        ManualKeypadEvent::Key(KeypadKey::CeDelete),
        ManualKeypadError::EmptyDelete,
        [0; 4],
    );
    fill(&mut session, KeypadKey::FourLeft, MANUAL_TRANSCRIPT_BYTES);
    press(&mut session, KeypadKey::EqualsConfirmEnter);
    assert_echo(
        &session,
        CeremonyPurpose::SeedA,
        &[b'4'; MANUAL_TRANSCRIPT_BYTES],
    );

    let mut session = entry_session();
    press(&mut session, KeypadKey::One);
    press(&mut session, KeypadKey::TwoDown);
    assert_rejection(
        &mut session,
        ManualKeypadEvent::Key(KeypadKey::EqualsConfirmEnter),
        ManualKeypadError::TranscriptCountIncomplete,
        [2, 0, 0, 0],
    );
    fill(&mut session, KeypadKey::Three, 98);
    press(&mut session, KeypadKey::EqualsConfirmEnter);
    let mut expected = vec![b'1', b'2'];
    expected.extend([b'3'; 98]);
    assert_echo(&session, CeremonyPurpose::SeedA, &expected);

    let mut session = entry_session();
    fill(&mut session, KeypadKey::Five, MANUAL_TRANSCRIPT_BYTES);
    assert_rejection(
        &mut session,
        ManualKeypadEvent::Key(KeypadKey::SixRight),
        ManualKeypadError::TranscriptFull,
        [100, 0, 0, 0],
    );
    press(&mut session, KeypadKey::EqualsConfirmEnter);
    assert_echo(
        &session,
        CeremonyPurpose::SeedA,
        &[b'5'; MANUAL_TRANSCRIPT_BYTES],
    );
}

fn finish_purpose(
    session: &mut ManualKeypadSession,
    purpose: CeremonyPurpose,
    key: KeypadKey,
    face: u8,
    commitment: [u8; 32],
) -> OutcomeKind {
    assert_eq!(screen_snapshot(session), ScreenSnapshot::Entry(purpose, 0));
    fill(session, key, MANUAL_TRANSCRIPT_BYTES);
    press(session, KeypadKey::EqualsConfirmEnter);
    assert_echo(session, purpose, &[face; MANUAL_TRANSCRIPT_BYTES]);
    press(session, KeypadKey::EqualsConfirmEnter);
    assert_eq!(
        screen_snapshot(session),
        ScreenSnapshot::Confirm(purpose, vec![face; MANUAL_TRANSCRIPT_BYTES])
    );
    press(session, KeypadKey::EqualsConfirmEnter);
    assert_eq!(
        screen_snapshot(session),
        ScreenSnapshot::AwaitingCommitment(purpose)
    );
    assert_eq!(
        apply_snapshot(session, ManualKeypadEvent::CommitmentReady(commitment)).outcome,
        OutcomeKind::Continue
    );
    assert_eq!(
        screen_snapshot(session),
        ScreenSnapshot::Commitment(purpose, commitment)
    );
    apply_snapshot(
        session,
        ManualKeypadEvent::Key(KeypadKey::EqualsConfirmEnter),
    )
    .outcome
}

fn complete_oracle() {
    let mut session = entry_session();
    let cases = [
        (CeremonyPurpose::SeedA, KeypadKey::One, b'1', [0x11; 32]),
        (
            CeremonyPurpose::SignerB,
            KeypadKey::TwoDown,
            b'2',
            [0x22; 32],
        ),
        (CeremonyPurpose::SignerC, KeypadKey::Three, b'3', [0x33; 32]),
        (CeremonyPurpose::A2, KeypadKey::FourLeft, b'4', [0x44; 32]),
    ];
    for (index, (purpose, key, face, commitment)) in cases.into_iter().enumerate() {
        let outcome = finish_purpose(&mut session, purpose, key, face, commitment);
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
                core::array::from_fn(|slot| if slot <= index { 100 } else { 0 })
            }
        );
    }
    assert_eq!(screen_snapshot(&session), ScreenSnapshot::Complete);
}

fn reuse_oracle(pair_selector: u8) {
    let pairs = [(0, 1), (0, 2), (0, 3), (1, 2), (1, 3), (2, 3)];
    let (first, duplicate) = pairs[usize::from(pair_selector) % pairs.len()];
    let purposes = [
        CeremonyPurpose::SeedA,
        CeremonyPurpose::SignerB,
        CeremonyPurpose::SignerC,
        CeremonyPurpose::A2,
    ];
    let mut keys = [
        (KeypadKey::One, b'1'),
        (KeypadKey::TwoDown, b'2'),
        (KeypadKey::Three, b'3'),
        (KeypadKey::FourLeft, b'4'),
    ];
    keys[duplicate] = keys[first];
    let mut session = entry_session();
    for index in 0..4 {
        let outcome = finish_purpose(
            &mut session,
            purposes[index],
            keys[index].0,
            keys[index].1,
            [index as u8; 32],
        );
        if index < 3 {
            assert_eq!(outcome, OutcomeKind::Continue);
        } else {
            assert_eq!(
                outcome,
                OutcomeKind::Rejected(ManualKeypadError::TranscriptReuse)
            );
        }
    }
    assert_eq!(session.retained_counts(), [0; 4]);
    assert_eq!(
        session.terminal(),
        Some(FlowTerminal::FailedWiped(WipingReason::OperationFailed))
    );
}

#[derive(Clone, Copy)]
enum ActiveStage {
    Entry,
    Echo,
    Confirm,
    AwaitingCommitment,
    Commitment,
}

fn position_after_retained_seed(stage: ActiveStage) -> ManualKeypadSession {
    let mut session = entry_session();
    assert_eq!(
        finish_purpose(
            &mut session,
            CeremonyPurpose::SeedA,
            KeypadKey::One,
            b'1',
            [0x11; 32],
        ),
        OutcomeKind::Continue
    );
    assert_eq!(session.retained_counts(), [100, 0, 0, 0]);
    if matches!(stage, ActiveStage::Entry) {
        press(&mut session, KeypadKey::TwoDown);
        return session;
    }
    fill(&mut session, KeypadKey::TwoDown, MANUAL_TRANSCRIPT_BYTES);
    press(&mut session, KeypadKey::EqualsConfirmEnter);
    if matches!(stage, ActiveStage::Echo) {
        return session;
    }
    press(&mut session, KeypadKey::EqualsConfirmEnter);
    if matches!(stage, ActiveStage::Confirm) {
        return session;
    }
    press(&mut session, KeypadKey::EqualsConfirmEnter);
    if matches!(stage, ActiveStage::AwaitingCommitment) {
        return session;
    }
    assert_eq!(
        apply_snapshot(&mut session, ManualKeypadEvent::CommitmentReady([0x22; 32])).outcome,
        OutcomeKind::Continue
    );
    session
}

fn legacy_bypass_oracle() {
    for selector in 0..19 {
        let key = keypad(selector);
        let expected = if key == KeypadKey::CancelBack {
            WipingReason::Cancelled
        } else {
            WipingReason::InvalidTransition
        };
        let mut flow = manual_root_flow();
        assert!(matches!(
            flow.apply(FlowEvent::Key(key)),
            Ok(FlowApplyOutcome::FailedWiped(actual)) if actual == expected
        ));
        assert_eq!(flow.terminal(), Some(FlowTerminal::FailedWiped(expected)));
    }
    let mut flow = manual_root_flow();
    assert!(matches!(
        flow.apply(FlowEvent::CeremonyEchoReady(b"1")),
        Ok(FlowApplyOutcome::FailedWiped(
            WipingReason::InvalidTransition
        ))
    ));
    assert_eq!(
        flow.terminal(),
        Some(FlowTerminal::FailedWiped(WipingReason::InvalidTransition))
    );
}

fn interruption_oracle(selector: u8) {
    let cases = [
        (
            ManualKeypadEvent::Key(KeypadKey::CancelBack),
            ManualKeypadError::Cancelled,
            WipingReason::Cancelled,
        ),
        (
            ManualKeypadEvent::OperationFailed,
            ManualKeypadError::OperationFailed,
            WipingReason::OperationFailed,
        ),
        (
            ManualKeypadEvent::MediaRemoved,
            ManualKeypadError::MediaRemoved,
            WipingReason::MediaRemoved,
        ),
        (
            ManualKeypadEvent::CardRemoved,
            ManualKeypadError::CardRemoved,
            WipingReason::CardRemoved,
        ),
        (
            ManualKeypadEvent::SessionTimeout,
            ManualKeypadError::SessionTimeout,
            WipingReason::SessionTimeout,
        ),
        (
            ManualKeypadEvent::Shutdown,
            ManualKeypadError::Shutdown,
            WipingReason::Shutdown,
        ),
        (
            ManualKeypadEvent::Restart,
            ManualKeypadError::Restart,
            WipingReason::Restart,
        ),
        (
            ManualKeypadEvent::PowerLoss,
            ManualKeypadError::PowerLoss,
            WipingReason::PowerLoss,
        ),
    ];
    let event_index = usize::from(selector) % 9;
    let stage_index = (usize::from(selector) / 9) % 5;
    let stage = [
        ActiveStage::Entry,
        ActiveStage::Echo,
        ActiveStage::Confirm,
        ActiveStage::AwaitingCommitment,
        ActiveStage::Commitment,
    ][stage_index];
    let (event, error, reason) = if event_index == cases.len() {
        (
            if matches!(stage, ActiveStage::AwaitingCommitment) {
                ManualKeypadEvent::Key(KeypadKey::One)
            } else {
                ManualKeypadEvent::CommitmentReady([0x99; 32])
            },
            ManualKeypadError::InvalidTransition,
            WipingReason::InvalidTransition,
        )
    } else {
        cases[event_index]
    };
    let mut session = position_after_retained_seed(stage);
    let outcome = apply_snapshot(&mut session, event);
    assert_eq!(outcome.outcome, OutcomeKind::Rejected(error));
    assert_eq!(outcome.retained_counts, [0; 4]);
    assert_eq!(outcome.terminal, Some(FlowTerminal::FailedWiped(reason)));
    assert_eq!(outcome.screen, ScreenSnapshot::Failed(error));
}

fuzz_target!(|data: &[u8]| {
    let mode = data.first().copied().unwrap_or(0) % 7;
    let tail = data.get(1..).unwrap_or_default();
    match mode {
        0 => {
            let first = trace(tail);
            let second = trace(tail);
            assert_eq!(first, second, "M29 transition result must be stable");
        }
        1 => rejection_oracles(),
        2 => {
            rejection_oracles();
            for selector in 0..19 {
                let first = trace(&[selector]);
                let second = trace(&[selector]);
                assert_eq!(first, second, "every P0.1 logical key is deterministic");
            }
        }
        3 => complete_oracle(),
        4 => reuse_oracle(tail.first().copied().unwrap_or(0)),
        5 => interruption_oracle(tail.first().copied().unwrap_or(0)),
        6 => {
            rejection_oracles();
            legacy_bypass_oracle();
            complete_oracle();
            for pair in 0..6 {
                reuse_oracle(pair);
            }
            for stage in 0..5 {
                for interruption in 0..9 {
                    interruption_oracle(stage * 9 + interruption);
                }
            }
        }
        _ => unreachable!("modulo seven is exhaustive"),
    }
});
