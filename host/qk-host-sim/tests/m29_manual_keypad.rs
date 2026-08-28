use qk_host_sim::{
    EntropyInputMode, FlowApplyOutcome, FlowEvent, FlowKind, KeypadKey, ManualKeypadError,
    ManualKeypadEvent, ManualKeypadOutcome, ManualKeypadScreen, ManualKeypadSession, Screen,
    ScreenFlow, ScreenKind, WipingReason, MANUAL_TRANSCRIPT_BYTES,
};

fn root_continue(flow: &mut ScreenFlow, event: FlowEvent<'_>, expected: ScreenKind) {
    assert!(matches!(
        flow.apply(event).expect("root transition"),
        FlowApplyOutcome::Continue(actual) if actual == expected
    ));
}

fn entry_session() -> ManualKeypadSession {
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
    ManualKeypadSession::begin(flow).expect("manual entry")
}

fn press(session: &mut ManualKeypadSession, key: KeypadKey) {
    assert!(matches!(
        session.apply(ManualKeypadEvent::Key(key)),
        Ok(ManualKeypadOutcome::Continue)
    ));
}

fn rejection(result: Result<ManualKeypadOutcome, ManualKeypadError>) -> ManualKeypadError {
    match result {
        Err(error) => error,
        Ok(_) => panic!("expected named rejection"),
    }
}

fn fill(session: &mut ManualKeypadSession, key: KeypadKey) {
    for _ in 0..MANUAL_TRANSCRIPT_BYTES {
        press(session, key);
    }
}

fn finish_purpose(
    session: &mut ManualKeypadSession,
    key: KeypadKey,
    commitment: [u8; 32],
) -> Option<qk_provisioning::HostProvisioningRun> {
    fill(session, key);
    press(session, KeypadKey::EqualsConfirmEnter);
    let face = match key {
        KeypadKey::One => b'1',
        KeypadKey::TwoDown => b'2',
        KeypadKey::Three => b'3',
        KeypadKey::FourLeft => b'4',
        _ => panic!("test face"),
    };
    assert!(matches!(
        session.screen(),
        ManualKeypadScreen::Echo { transcript, .. }
            if transcript.bytes() == [face; MANUAL_TRANSCRIPT_BYTES]
    ));
    press(session, KeypadKey::EqualsConfirmEnter);
    assert!(matches!(
        session.screen(),
        ManualKeypadScreen::Confirm { transcript, .. }
            if transcript.bytes() == [face; MANUAL_TRANSCRIPT_BYTES]
    ));
    press(session, KeypadKey::EqualsConfirmEnter);
    assert!(matches!(
        session.screen(),
        ManualKeypadScreen::AwaitingCommitment { .. }
    ));
    assert!(matches!(
        session.apply(ManualKeypadEvent::CommitmentReady(commitment)),
        Ok(ManualKeypadOutcome::Continue)
    ));
    assert!(matches!(
        session.screen(),
        ManualKeypadScreen::Commitment {
            commitment: actual,
            ..
        } if actual == commitment
    ));
    match session.apply(ManualKeypadEvent::Key(KeypadKey::EqualsConfirmEnter)) {
        Ok(ManualKeypadOutcome::Continue) => None,
        Ok(ManualKeypadOutcome::ProvisioningReady(run)) => Some(*run),
        Err(error) => panic!("commitment rejected: {error:?}"),
    }
}

#[test]
fn four_input_rejections_preserve_stage_count_and_bytes() {
    assert_eq!(ManualKeypadError::InvalidFaceKey.name(), "InvalidFaceKey");
    assert_eq!(ManualKeypadError::TranscriptFull.name(), "TranscriptFull");
    assert_eq!(ManualKeypadError::EmptyDelete.name(), "EmptyDelete");
    assert_eq!(
        ManualKeypadError::TranscriptCountIncomplete.name(),
        "TranscriptCountIncomplete"
    );
    assert_eq!(
        ManualKeypadError::TranscriptCountIncomplete.to_string(),
        "TranscriptCountIncomplete"
    );
    let invalid = [
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
    let mut session = entry_session();
    press(&mut session, KeypadKey::One);
    for key in invalid {
        assert_eq!(
            rejection(session.apply(ManualKeypadEvent::Key(key))),
            ManualKeypadError::InvalidFaceKey
        );
        assert_eq!(session.retained_counts(), [1, 0, 0, 0]);
    }
    assert_eq!(
        rejection(session.apply(ManualKeypadEvent::Key(KeypadKey::EqualsConfirmEnter)),),
        ManualKeypadError::TranscriptCountIncomplete
    );
    assert_eq!(session.retained_counts(), [1, 0, 0, 0]);
    press(&mut session, KeypadKey::CeDelete);
    assert_eq!(
        rejection(session.apply(ManualKeypadEvent::Key(KeypadKey::CeDelete))),
        ManualKeypadError::EmptyDelete
    );
    assert_eq!(session.retained_counts(), [0, 0, 0, 0]);

    fill(&mut session, KeypadKey::SixRight);
    assert_eq!(
        rejection(session.apply(ManualKeypadEvent::Key(KeypadKey::One))),
        ManualKeypadError::TranscriptFull
    );
    assert_eq!(session.retained_counts(), [100, 0, 0, 0]);
    assert!(matches!(
        session.screen(),
        ManualKeypadScreen::Entry { count: 100, .. }
    ));
    press(&mut session, KeypadKey::CeDelete);
    assert_eq!(session.retained_counts(), [99, 0, 0, 0]);
    assert_eq!(
        rejection(session.apply(ManualKeypadEvent::Key(KeypadKey::EqualsConfirmEnter))),
        ManualKeypadError::TranscriptCountIncomplete
    );
    assert_eq!(session.retained_counts(), [99, 0, 0, 0]);
}

#[test]
fn all_six_face_keys_append_their_exact_ascii_symbols() {
    let mut session = entry_session();
    let keys = [
        KeypadKey::One,
        KeypadKey::TwoDown,
        KeypadKey::Three,
        KeypadKey::FourLeft,
        KeypadKey::Five,
        KeypadKey::SixRight,
    ];
    let mut expected = [0u8; MANUAL_TRANSCRIPT_BYTES];
    for (index, byte) in expected.iter_mut().enumerate() {
        let key_index = index % keys.len();
        press(&mut session, keys[key_index]);
        *byte = b'1' + key_index as u8;
    }
    press(&mut session, KeypadKey::EqualsConfirmEnter);
    assert!(matches!(
        session.screen(),
        ManualKeypadScreen::Echo { transcript, .. } if transcript.bytes() == expected
    ));
}

#[test]
fn exact_echo_confirm_commit_order_retains_all_four_until_validation() {
    let mut session = entry_session();
    assert!(finish_purpose(&mut session, KeypadKey::One, [0x11; 32]).is_none());
    assert_eq!(session.retained_counts(), [100, 0, 0, 0]);
    assert!(finish_purpose(&mut session, KeypadKey::TwoDown, [0x22; 32]).is_none());
    assert_eq!(session.retained_counts(), [100, 100, 0, 0]);
    assert!(finish_purpose(&mut session, KeypadKey::Three, [0x33; 32]).is_none());
    assert_eq!(session.retained_counts(), [100, 100, 100, 0]);
    let run = finish_purpose(&mut session, KeypadKey::FourLeft, [0x44; 32]);
    assert!(run.is_some());
    assert_eq!(session.retained_counts(), [0; 4]);
    assert!(matches!(session.screen(), ManualKeypadScreen::Complete));
    let flow = session.take_completed_flow().expect("completed M27 flow");
    assert_eq!(flow.screen_kind(), Some(ScreenKind::DerivationExplanation));
}

#[test]
fn transcript_reuse_is_pairwise_hard_error_and_wipes() {
    for (first, duplicate) in [(0, 1), (0, 2), (0, 3), (1, 2), (1, 3), (2, 3)] {
        let mut session = entry_session();
        let mut keys = [
            KeypadKey::One,
            KeypadKey::TwoDown,
            KeypadKey::Three,
            KeypadKey::FourLeft,
        ];
        keys[duplicate] = keys[first];
        for index in 0..4 {
            let key = keys[index];
            if index < 3 {
                assert!(finish_purpose(&mut session, key, [index as u8; 32]).is_none());
            } else {
                fill(&mut session, key);
                press(&mut session, KeypadKey::EqualsConfirmEnter);
                press(&mut session, KeypadKey::EqualsConfirmEnter);
                press(&mut session, KeypadKey::EqualsConfirmEnter);
                assert!(matches!(
                    session.apply(ManualKeypadEvent::CommitmentReady([3; 32])),
                    Ok(ManualKeypadOutcome::Continue)
                ));
                assert_eq!(
                    rejection(session.apply(ManualKeypadEvent::Key(KeypadKey::EqualsConfirmEnter)),),
                    ManualKeypadError::TranscriptReuse
                );
            }
        }
        assert_eq!(session.retained_counts(), [0; 4]);
        assert_eq!(
            session.terminal(),
            Some(qk_host_sim::FlowTerminal::FailedWiped(
                WipingReason::OperationFailed
            ))
        );
    }
}

#[test]
fn cancellation_and_every_closed_interruption_wipe() {
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
    for (event, expected_error, expected_reason) in cases {
        let mut session = entry_session();
        press(&mut session, KeypadKey::One);
        assert_eq!(rejection(session.apply(event)), expected_error);
        assert_eq!(session.retained_counts(), [0; 4]);
        assert_eq!(
            session.terminal(),
            Some(qk_host_sim::FlowTerminal::FailedWiped(expected_reason))
        );
    }
}

#[test]
fn secret_owner_uses_established_optimization_resistant_wipe() {
    let source = include_str!("../src/manual_keypad.rs");
    assert!(source.contains("#[inline(never)]\nfn wipe(bytes: &mut [u8])"));
    assert!(source.contains("bytes.fill(0);"));
    assert!(source.contains("core::hint::black_box(bytes);"));
    assert!(source.contains("impl Drop for SecretTranscript"));
    assert!(source.contains("impl Drop for ManualKeypadSession"));
    assert!(!source.contains("derive(Clone, Copy, Debug)\npub struct ManualKeypadSession"));
}
