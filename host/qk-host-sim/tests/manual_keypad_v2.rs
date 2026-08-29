use qk_host_sim::{
    CeremonyPurposeV2, EntropyInputModeV2, FlowApplyOutcomeV2, FlowEventV2, FlowKindV2,
    FlowTerminalV2, KeypadKey, ManualKeypadErrorV2, ManualKeypadEventV2, ManualKeypadOutcomeV2,
    ManualKeypadScreenV2, ManualKeypadSessionV2, ScreenFlowV2, ScreenKindV2, ScreenV2,
    WipingReasonV2, MANUAL_TRANSCRIPT_BYTES_V2,
};

fn root_continue(flow: &mut ScreenFlowV2, event: FlowEventV2<'_>, expected: ScreenKindV2) {
    assert!(matches!(
        flow.apply(event).expect("root transition"),
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
    assert!(matches!(
        flow.screen(),
        Some(ScreenV2::CeremonyInput {
            purpose: CeremonyPurposeV2::SeedA,
            mode: EntropyInputModeV2::ManualKeypad,
        })
    ));
    flow
}

fn entry_session() -> ManualKeypadSessionV2 {
    ManualKeypadSessionV2::begin(manual_root_flow()).expect("v2 manual entry")
}

fn press(session: &mut ManualKeypadSessionV2, key: KeypadKey) {
    assert!(matches!(
        session.apply(ManualKeypadEventV2::Key(key)),
        Ok(ManualKeypadOutcomeV2::Continue)
    ));
}

fn rejection(result: Result<ManualKeypadOutcomeV2, ManualKeypadErrorV2>) -> ManualKeypadErrorV2 {
    match result {
        Err(error) => error,
        Ok(_) => panic!("expected named rejection"),
    }
}

fn fill(session: &mut ManualKeypadSessionV2, key: KeypadKey) {
    for _ in 0..MANUAL_TRANSCRIPT_BYTES_V2 {
        press(session, key);
    }
}

fn finish_purpose(
    session: &mut ManualKeypadSessionV2,
    key: KeypadKey,
    expected_purpose: CeremonyPurposeV2,
    commitment: [u8; 32],
) -> Option<qk_provisioning::HostProvisioningRunV2> {
    assert!(matches!(
        session.screen(),
        ManualKeypadScreenV2::Entry { purpose, count: 0 } if purpose == expected_purpose
    ));
    fill(session, key);
    press(session, KeypadKey::EqualsConfirmEnter);
    let face = match key {
        KeypadKey::One => b'1',
        KeypadKey::TwoDown => b'2',
        KeypadKey::Three => b'3',
        KeypadKey::FourLeft => b'4',
        KeypadKey::Five => b'5',
        KeypadKey::SixRight => b'6',
        _ => panic!("test face"),
    };
    assert!(matches!(
        session.screen(),
        ManualKeypadScreenV2::Echo { purpose, transcript }
            if purpose == expected_purpose
                && transcript.bytes() == [face; MANUAL_TRANSCRIPT_BYTES_V2]
    ));
    press(session, KeypadKey::EqualsConfirmEnter);
    assert!(matches!(
        session.screen(),
        ManualKeypadScreenV2::Confirm { purpose, transcript }
            if purpose == expected_purpose
                && transcript.bytes() == [face; MANUAL_TRANSCRIPT_BYTES_V2]
    ));
    press(session, KeypadKey::EqualsConfirmEnter);
    assert!(matches!(
        session.screen(),
        ManualKeypadScreenV2::AwaitingCommitment { purpose }
            if purpose == expected_purpose
    ));
    assert!(matches!(
        session.apply(ManualKeypadEventV2::CommitmentReady(commitment)),
        Ok(ManualKeypadOutcomeV2::Continue)
    ));
    assert!(matches!(
        session.screen(),
        ManualKeypadScreenV2::Commitment {
            purpose,
            commitment: actual,
        } if purpose == expected_purpose && actual == commitment
    ));
    match session.apply(ManualKeypadEventV2::Key(KeypadKey::EqualsConfirmEnter)) {
        Ok(ManualKeypadOutcomeV2::Continue) => None,
        Ok(ManualKeypadOutcomeV2::ProvisioningReady(run)) => Some(*run),
        Err(error) => panic!("commitment rejected: {error:?}"),
    }
}

#[test]
fn four_input_rejections_are_named_and_preserve_stage_count_and_bytes() {
    assert_eq!(ManualKeypadErrorV2::InvalidFaceKey.name(), "InvalidFaceKey");
    assert_eq!(ManualKeypadErrorV2::TranscriptFull.name(), "TranscriptFull");
    assert_eq!(ManualKeypadErrorV2::EmptyDelete.name(), "EmptyDelete");
    assert_eq!(
        ManualKeypadErrorV2::TranscriptCountIncomplete.name(),
        "TranscriptCountIncomplete"
    );
    assert_eq!(
        ManualKeypadErrorV2::TranscriptCountIncomplete.to_string(),
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
            rejection(session.apply(ManualKeypadEventV2::Key(key))),
            ManualKeypadErrorV2::InvalidFaceKey
        );
        assert_eq!(session.retained_counts(), [1, 0, 0, 0]);
        assert!(matches!(
            session.screen(),
            ManualKeypadScreenV2::Entry {
                purpose: CeremonyPurposeV2::SeedA,
                count: 1,
            }
        ));
    }
    assert_eq!(
        rejection(session.apply(ManualKeypadEventV2::Key(KeypadKey::EqualsConfirmEnter,))),
        ManualKeypadErrorV2::TranscriptCountIncomplete
    );
    assert_eq!(session.retained_counts(), [1, 0, 0, 0]);

    press(&mut session, KeypadKey::CeDelete);
    assert_eq!(
        rejection(session.apply(ManualKeypadEventV2::Key(KeypadKey::CeDelete))),
        ManualKeypadErrorV2::EmptyDelete
    );
    assert_eq!(session.retained_counts(), [0, 0, 0, 0]);

    fill(&mut session, KeypadKey::SixRight);
    assert_eq!(
        rejection(session.apply(ManualKeypadEventV2::Key(KeypadKey::One))),
        ManualKeypadErrorV2::TranscriptFull
    );
    assert_eq!(session.retained_counts(), [100, 0, 0, 0]);
    assert!(matches!(
        session.screen(),
        ManualKeypadScreenV2::Entry { count: 100, .. }
    ));
    press(&mut session, KeypadKey::CeDelete);
    assert_eq!(session.retained_counts(), [99, 0, 0, 0]);
    assert_eq!(
        rejection(session.apply(ManualKeypadEventV2::Key(KeypadKey::EqualsConfirmEnter,))),
        ManualKeypadErrorV2::TranscriptCountIncomplete
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
    let mut expected = [0u8; MANUAL_TRANSCRIPT_BYTES_V2];
    for (index, byte) in expected.iter_mut().enumerate() {
        let key_index = index % keys.len();
        press(&mut session, keys[key_index]);
        *byte = b'1' + key_index as u8;
    }
    press(&mut session, KeypadKey::EqualsConfirmEnter);
    assert!(matches!(
        session.screen(),
        ManualKeypadScreenV2::Echo { purpose: CeremonyPurposeV2::SeedA, transcript }
            if transcript.bytes() == expected
    ));
}

#[test]
fn exact_v2_purpose_order_retains_all_four_until_one_validator_submission() {
    let mut session = entry_session();
    assert!(finish_purpose(
        &mut session,
        KeypadKey::One,
        CeremonyPurposeV2::SeedA,
        [0x11; 32],
    )
    .is_none());
    assert_eq!(session.retained_counts(), [100, 0, 0, 0]);
    assert!(finish_purpose(
        &mut session,
        KeypadKey::TwoDown,
        CeremonyPurposeV2::SignerB,
        [0x22; 32],
    )
    .is_none());
    assert_eq!(session.retained_counts(), [100, 100, 0, 0]);
    assert!(finish_purpose(
        &mut session,
        KeypadKey::Three,
        CeremonyPurposeV2::KitR,
        [0x33; 32],
    )
    .is_none());
    assert_eq!(session.retained_counts(), [100, 100, 100, 0]);
    let mut run = finish_purpose(
        &mut session,
        KeypadKey::FourLeft,
        CeremonyPurposeV2::A2,
        [0x44; 32],
    )
    .expect("v2 provisioning run");

    assert_eq!(session.retained_counts(), [0; 4]);
    assert!(matches!(session.screen(), ManualKeypadScreenV2::Complete));
    let flow = session.take_completed_flow().expect("completed v2 flow");
    assert_eq!(
        flow.screen_kind(),
        Some(ScreenKindV2::DerivationExplanation)
    );

    // A usable v2 run, rather than the frozen three-account M26 run, is the
    // sole released capability. The public result has exactly two accounts.
    let artifacts = run
        .encrypt_a1(b"QKV2S4NONCE1")
        .expect("public deterministic A1 capsule");
    assert_eq!(artifacts.account_xpubs.len(), 2);
    assert_eq!(artifacts.descriptors.len(), 2);
    assert_eq!(artifacts.first_scripts.len(), 2);
    assert_eq!(artifacts.first_addresses.len(), 2);
}

#[test]
fn every_pairwise_transcript_reuse_is_a_hard_error_and_wipes() {
    let purposes = [
        CeremonyPurposeV2::SeedA,
        CeremonyPurposeV2::SignerB,
        CeremonyPurposeV2::KitR,
        CeremonyPurposeV2::A2,
    ];
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
                assert!(
                    finish_purpose(&mut session, key, purposes[index], [index as u8; 32],)
                        .is_none()
                );
            } else {
                fill(&mut session, key);
                press(&mut session, KeypadKey::EqualsConfirmEnter);
                press(&mut session, KeypadKey::EqualsConfirmEnter);
                press(&mut session, KeypadKey::EqualsConfirmEnter);
                assert!(matches!(
                    session.apply(ManualKeypadEventV2::CommitmentReady([3; 32])),
                    Ok(ManualKeypadOutcomeV2::Continue)
                ));
                assert_eq!(
                    rejection(
                        session.apply(ManualKeypadEventV2::Key(KeypadKey::EqualsConfirmEnter,))
                    ),
                    ManualKeypadErrorV2::TranscriptReuse
                );
            }
        }
        assert_eq!(session.retained_counts(), [0; 4]);
        assert_eq!(
            session.terminal(),
            Some(FlowTerminalV2::FailedWiped(WipingReasonV2::OperationFailed,))
        );
        assert_eq!(
            rejection(session.apply(ManualKeypadEventV2::Key(KeypadKey::One))),
            ManualKeypadErrorV2::Finished
        );
    }
}

#[test]
fn cancellation_and_every_closed_interruption_wipe() {
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
    for (event, expected_error, expected_reason) in cases {
        let mut session = entry_session();
        press(&mut session, KeypadKey::One);
        assert_eq!(rejection(session.apply(event)), expected_error);
        assert_eq!(session.retained_counts(), [0; 4]);
        assert_eq!(
            session.terminal(),
            Some(FlowTerminalV2::FailedWiped(expected_reason))
        );
    }
}

#[derive(Clone, Copy)]
enum PositionedStage {
    Entry,
    Echo,
    Confirm,
    AwaitingCommitment,
    Commitment,
}

fn position_after_retained_seed(stage: PositionedStage) -> ManualKeypadSessionV2 {
    let mut session = entry_session();
    assert!(finish_purpose(
        &mut session,
        KeypadKey::One,
        CeremonyPurposeV2::SeedA,
        [0x11; 32],
    )
    .is_none());
    assert_eq!(session.retained_counts(), [100, 0, 0, 0]);
    if matches!(stage, PositionedStage::Entry) {
        press(&mut session, KeypadKey::TwoDown);
        return session;
    }
    fill(&mut session, KeypadKey::TwoDown);
    press(&mut session, KeypadKey::EqualsConfirmEnter);
    if matches!(stage, PositionedStage::Echo) {
        return session;
    }
    press(&mut session, KeypadKey::EqualsConfirmEnter);
    if matches!(stage, PositionedStage::Confirm) {
        return session;
    }
    press(&mut session, KeypadKey::EqualsConfirmEnter);
    if matches!(stage, PositionedStage::AwaitingCommitment) {
        return session;
    }
    assert!(matches!(
        session.apply(ManualKeypadEventV2::CommitmentReady([0x22; 32])),
        Ok(ManualKeypadOutcomeV2::Continue)
    ));
    session
}

#[test]
fn every_wiping_event_clears_prior_transcripts_from_every_active_stage() {
    let stages = [
        PositionedStage::Entry,
        PositionedStage::Echo,
        PositionedStage::Confirm,
        PositionedStage::AwaitingCommitment,
        PositionedStage::Commitment,
    ];
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
    for stage in stages {
        for (event, expected_error, expected_reason) in cases {
            let mut session = position_after_retained_seed(stage);
            assert_eq!(rejection(session.apply(event)), expected_error);
            assert_eq!(session.retained_counts(), [0; 4]);
            assert_eq!(
                session.terminal(),
                Some(FlowTerminalV2::FailedWiped(expected_reason))
            );
        }

        let invalid_event = if matches!(stage, PositionedStage::AwaitingCommitment) {
            ManualKeypadEventV2::Key(KeypadKey::One)
        } else {
            ManualKeypadEventV2::CommitmentReady([0x99; 32])
        };
        let mut session = position_after_retained_seed(stage);
        assert_eq!(
            rejection(session.apply(invalid_event)),
            ManualKeypadErrorV2::InvalidTransition
        );
        assert_eq!(session.retained_counts(), [0; 4]);
        assert_eq!(
            session.terminal(),
            Some(FlowTerminalV2::FailedWiped(
                WipingReasonV2::InvalidTransition,
            ))
        );
    }
}

#[test]
fn mismatched_root_is_rejected_without_widening_another_route() {
    for kind in [FlowKindV2::A1B, FlowKindV2::Kit] {
        assert!(matches!(
            ManualKeypadSessionV2::begin(ScreenFlowV2::new(kind)),
            Err(ManualKeypadErrorV2::InvalidTransition)
        ));
    }

    let setup_at_start = ScreenFlowV2::new(FlowKindV2::Setup);
    assert!(matches!(
        ManualKeypadSessionV2::begin(setup_at_start),
        Err(ManualKeypadErrorV2::InvalidTransition)
    ));
}

#[test]
fn secret_owner_has_no_owned_transcript_surface_and_uses_scoped_cleanup() {
    let source = include_str!("../src/manual_keypad_v2.rs");
    assert!(source.contains("pub struct ManualKeypadSessionV2"));
    assert!(source.contains("impl Drop for SecretTranscriptV2"));
    assert!(source.contains("impl Drop for ManualKeypadSessionV2"));
    assert!(source.contains("#[inline(never)]\nfn wipe(bytes: &mut [u8])"));
    assert!(source.contains("bytes.fill(0);"));
    assert!(source.contains("core::hint::black_box(bytes);"));
    assert!(!source.contains("pub fn transcript"));
    assert!(!source.contains("pub fn transcripts"));
    assert!(!source.contains("derive(Clone, Copy, Debug)\npub struct ManualKeypadSessionV2"));
    assert!(!source.contains("HostProvisioningRun::from_dice"));
    assert!(source.contains("HostProvisioningRunV2::from_manual_dice"));
    assert!(source.contains("2 => CeremonyPurposeV2::KitR"));
    assert!(!source.contains("CeremonyPurposeV2::SignerC"));
}
