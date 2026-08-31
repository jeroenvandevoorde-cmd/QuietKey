#![no_main]

use libfuzzer_sys::fuzz_target;
use qk_core::fuzz::{reset_wiped_bytes, wiped_bytes};
use qk_core::{
    CardPresence, CeremonyPurposeV2, CoreDeviceGrants, EntropyInputModeV2, Interruption, KeypadKey,
    MockCardSlot, MockDisplay, MockKeypad, SetupErrorV2, SetupOutcomeV2, SetupScreenV2,
    SetupSessionV2, SetupStageV2, MANUAL_TRANSCRIPT_BYTES_V2,
};
use qk_ipc::{encode_frame, parse_frame, Direction, MessageKind, HEADER_BYTES};

#[allow(dead_code, clippy::chunks_exact_to_as_chunks)]
#[path = "../../host/qk-psbt/src/sha256.rs"]
mod reference_sha256;

const COMMITMENT_DOMAIN: &[u8] = b"QuietKey/CeremonyTranscriptCommitment/v2";
const PURPOSES: [CeremonyPurposeV2; 4] = [
    CeremonyPurposeV2::SeedA,
    CeremonyPurposeV2::SignerB,
    CeremonyPurposeV2::KitR,
    CeremonyPurposeV2::A2,
];
const ACTIVE_ENTRY_DROP_BYTES: usize = 828;
const ACTIVE_COMMITMENT_DROP_BYTES: usize = 860;
const TERMINAL_DROP_BYTES: usize = 800;
const TERMINATION_CLEANUP_BYTES: usize = 428;
const COMMITMENT_BYTES: usize = 32;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct EntryFact {
    stage: Option<SetupStageV2>,
    mode: EntropyInputModeV2,
    counts: [usize; 4],
    terminal: bool,
    terminal_error: Option<&'static str>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct RunFact {
    scenario: u8,
    final_stage: Option<SetupStageV2>,
    terminal_error: Option<&'static str>,
    wiped: usize,
    drop_delta: usize,
}

struct Cursor<'a> {
    bytes: &'a [u8],
    offset: usize,
}

impl<'a> Cursor<'a> {
    const fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, offset: 0 }
    }

    fn byte(&mut self) -> u8 {
        let value = self.bytes.get(self.offset).copied().unwrap_or(0);
        self.offset = self.offset.saturating_add(1);
        value
    }

    fn array<const N: usize>(&mut self) -> [u8; N] {
        core::array::from_fn(|_| self.byte())
    }
}

fn grants() -> CoreDeviceGrants {
    CoreDeviceGrants::validate(
        Some(MockDisplay::new()),
        Some(MockKeypad::new()),
        Some(MockCardSlot::new(CardPresence::Present)),
        false,
    )
    .expect("fixed setup grants")
}

fn setup_error_name(error: SetupErrorV2) -> &'static str {
    let name = match error {
        SetupErrorV2::InvalidTransition => "InvalidTransition",
        SetupErrorV2::DiceGridUnavailable => "DiceGridUnavailable",
        SetupErrorV2::InvalidFaceKey => "InvalidFaceKey",
        SetupErrorV2::TranscriptFull => "TranscriptFull",
        SetupErrorV2::EmptyDelete => "EmptyDelete",
        SetupErrorV2::TranscriptCountIncomplete => "TranscriptCountIncomplete",
        SetupErrorV2::TranscriptReuse => "TranscriptReuse",
        SetupErrorV2::ProvisioningRejected => "ProvisioningRejected",
        SetupErrorV2::CommitmentInvariant => "CommitmentInvariant",
        SetupErrorV2::CardAbsent => "CardAbsent",
        SetupErrorV2::CardInstanceAlreadyProvisioned => "CardInstanceAlreadyProvisioned",
        SetupErrorV2::CardBindingMismatch => "CardBindingMismatch",
        SetupErrorV2::SpareChoiceAlreadyMade => "SpareChoiceAlreadyMade",
        SetupErrorV2::ArtifactInvariant => "ArtifactInvariant",
        SetupErrorV2::A1ScanbackMismatch => "A1ScanbackMismatch",
        SetupErrorV2::PrintReceiptMismatch => "PrintReceiptMismatch",
        SetupErrorV2::SetupFinished => "SetupFinished",
        SetupErrorV2::Interrupted(reason) => interruption_name(reason),
        SetupErrorV2::Core(_) => "Core",
    };
    assert_eq!(error.name(), name);
    assert_eq!(error.to_string(), name);
    name
}

fn interruption_name(reason: Interruption) -> &'static str {
    let name = match reason {
        Interruption::Cancelled => "Cancelled",
        Interruption::OperationFailed => "OperationFailed",
        Interruption::MediaRemoved => "MediaRemoved",
        Interruption::CardRemoved => "CardRemoved",
        Interruption::SessionTimeout => "SessionTimeout",
        Interruption::Shutdown => "Shutdown",
        Interruption::Restart => "Restart",
        Interruption::PowerLoss => "PowerLoss",
        Interruption::PeerLost => "PeerLost",
        Interruption::CapabilityFailed => "CapabilityFailed",
    };
    assert_eq!(reason.name(), name);
    assert_eq!(reason.to_string(), name);
    name
}

fn fact(session: &SetupSessionV2) -> EntryFact {
    EntryFact {
        stage: session.stage(),
        mode: session.entropy_mode(),
        counts: session.retained_counts(),
        terminal: session.is_terminal(),
        terminal_error: session.terminal_error().map(setup_error_name),
    }
}

fn response(request: &[u8], kind: MessageKind, payload: &[u8]) -> Vec<u8> {
    let request = parse_frame(request).expect("qk-core emitted a canonical QKIP frame");
    let mut output = vec![0u8; HEADER_BYTES + payload.len()];
    let written = encode_frame(
        Direction::IoToCore,
        kind,
        *request.header().session_id(),
        request.header().exchange_id(),
        payload,
        &mut output,
    )
    .expect("bounded canonical response");
    assert_eq!(written, output.len());
    output
}

fn start_ready(namespace: [u8; 12], nonce: [u8; 12]) -> SetupSessionV2 {
    let mut caller_nonce = nonce;
    let (mut session, opening) =
        SetupSessionV2::fuzz_start(namespace, 0, grants(), &mut caller_nonce)
            .expect("bounded deterministic setup start");
    assert_eq!(caller_nonce, [0; 12]);
    let ready = response(opening.frame_bytes(), MessageKind::SessionReady, &[]);
    let received = session
        .receive(&ready, false)
        .expect("canonical ready response");
    assert_eq!(received.consumed(), ready.len());
    assert_eq!(
        received.outcome(),
        SetupOutcomeV2::Continue(SetupStageV2::SetupStart)
    );
    assert!(received.outbound().is_none());
    session
}

fn expect_stage(session: &mut SetupSessionV2, key: KeypadKey, stage: SetupStageV2) {
    let progress = session.apply_key(key).expect("valid setup transition");
    assert_eq!(progress.outcome(), SetupOutcomeV2::Continue(stage));
    assert!(progress.outbound().is_none());
    assert_eq!(session.stage(), Some(stage));
}

fn expect_continue(
    session: &mut SetupSessionV2,
    key: KeypadKey,
    stage: SetupStageV2,
    counts: [usize; 4],
    mode: EntropyInputModeV2,
    exact_wipe_delta: Option<usize>,
) {
    let before_wipe = wiped_bytes();
    let progress = session.apply_key(key).expect("modeled continuing key");
    assert_eq!(progress.outcome(), SetupOutcomeV2::Continue(stage));
    assert!(progress.outbound().is_none());
    assert_eq!(
        fact(session),
        EntryFact {
            stage: Some(stage),
            mode,
            counts,
            terminal: false,
            terminal_error: None,
        }
    );
    if let Some(expected) = exact_wipe_delta {
        assert_eq!(wiped_bytes().saturating_sub(before_wipe), expected);
    }
}

fn expect_state_preserving(session: &mut SetupSessionV2, key: KeypadKey, expected: SetupErrorV2) {
    let before = fact(session);
    let before_wipe = wiped_bytes();
    let progress = session
        .apply_key(key)
        .expect("modeled state-preserving key");
    assert_eq!(
        progress.outcome(),
        SetupOutcomeV2::StatePreserving(expected)
    );
    assert!(progress.outbound().is_none());
    assert_eq!(setup_error_name(expected), expected.name());
    assert_eq!(fact(session), before);
    assert_eq!(wiped_bytes(), before_wipe);
}

fn expect_key_termination(
    session: &mut SetupSessionV2,
    key: KeypadKey,
    expected: SetupErrorV2,
    cleanup_bytes: usize,
) {
    let before_wipe = wiped_bytes();
    let error = match session.apply_key(key) {
        Ok(_) => panic!("modeled terminating key must reject"),
        Err(error) => error,
    };
    assert_eq!(error, expected);
    assert_eq!(setup_error_name(error), expected.name());
    assert_eq!(wiped_bytes().saturating_sub(before_wipe), cleanup_bytes);
    assert_eq!(session.terminal_error(), Some(expected));
    assert_terminal_absorption(session);
}

fn enter_manual(session: &mut SetupSessionV2) {
    expect_stage(
        session,
        KeypadKey::EqualsConfirmEnter,
        SetupStageV2::TierSelection,
    );
    expect_stage(
        session,
        KeypadKey::EqualsConfirmEnter,
        SetupStageV2::EntropyModeSelection,
    );

    expect_state_preserving(
        session,
        KeypadKey::EqualsConfirmEnter,
        SetupErrorV2::DiceGridUnavailable,
    );
    expect_continue(
        session,
        KeypadKey::FourLeft,
        SetupStageV2::EntropyModeSelection,
        [0; 4],
        EntropyInputModeV2::DiceGrid,
        Some(0),
    );
    let before_camera = fact(session);
    let before_camera_wipe = wiped_bytes();
    let camera = session
        .camera_presented()
        .expect("camera cannot widen unavailable grid mode");
    assert_eq!(
        camera.outcome(),
        SetupOutcomeV2::StatePreserving(SetupErrorV2::DiceGridUnavailable)
    );
    assert!(camera.outbound().is_none());
    assert_eq!(fact(session), before_camera);
    assert_eq!(wiped_bytes(), before_camera_wipe);

    expect_continue(
        session,
        KeypadKey::SixRight,
        SetupStageV2::EntropyModeSelection,
        [0; 4],
        EntropyInputModeV2::ManualKeypad,
        Some(0),
    );
    expect_continue(
        session,
        KeypadKey::EqualsConfirmEnter,
        SetupStageV2::CeremonyInput,
        [0; 4],
        EntropyInputModeV2::ManualKeypad,
        Some(0),
    );
}

fn key(byte: u8) -> KeypadKey {
    match byte % 19 {
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

fn face_key(face: u8) -> KeypadKey {
    match face {
        b'1' => KeypadKey::One,
        b'2' => KeypadKey::TwoDown,
        b'3' => KeypadKey::Three,
        b'4' => KeypadKey::FourLeft,
        b'5' => KeypadKey::Five,
        b'6' => KeypadKey::SixRight,
        _ => unreachable!("generated faces are canonical"),
    }
}

fn purpose_tag(purpose: CeremonyPurposeV2) -> u8 {
    match purpose {
        CeremonyPurposeV2::SeedA => 1,
        CeremonyPurposeV2::SignerB => 2,
        CeremonyPurposeV2::KitR => 3,
        CeremonyPurposeV2::A2 => 4,
    }
}

fn reference_commitment(purpose: CeremonyPurposeV2, transcript: &[u8; 100]) -> [u8; 32] {
    let mut hasher = reference_sha256::Sha256::new();
    hasher.update(COMMITMENT_DOMAIN).expect("fixed domain");
    hasher.update(&[0]).expect("fixed separator");
    hasher
        .update(&[purpose_tag(purpose)])
        .expect("fixed purpose");
    hasher.update(transcript).expect("fixed transcript");
    hasher.finalize().expect("bounded commitment")
}

fn generated_transcripts(seed: &[u8]) -> [[u8; 100]; 4] {
    core::array::from_fn(|purpose| {
        core::array::from_fn(|position| {
            if position == 0 {
                b'1' + purpose as u8
            } else {
                b'1' + seed.get(position - 1).copied().unwrap_or(0) % 6
            }
        })
    })
}

fn representative_count(selector: u8) -> usize {
    match selector % 5 {
        0 => 0,
        1 => 1,
        2 => 50,
        3 => 99,
        4 => MANUAL_TRANSCRIPT_BYTES_V2,
        _ => unreachable!("modulo five is exhaustive"),
    }
}

fn face_for_key(key: KeypadKey) -> Option<u8> {
    match key {
        KeypadKey::One => Some(b'1'),
        KeypadKey::TwoDown => Some(b'2'),
        KeypadKey::Three => Some(b'3'),
        KeypadKey::FourLeft => Some(b'4'),
        KeypadKey::Five => Some(b'5'),
        KeypadKey::SixRight => Some(b'6'),
        KeypadKey::Seven
        | KeypadKey::EightUp
        | KeypadKey::Nine
        | KeypadKey::CeDelete
        | KeypadKey::CancelBack
        | KeypadKey::Multiply
        | KeypadKey::Divide
        | KeypadKey::Minus
        | KeypadKey::Percent
        | KeypadKey::Zero
        | KeypadKey::Decimal
        | KeypadKey::Plus
        | KeypadKey::EqualsConfirmEnter => None,
    }
}

fn expected_counts(purpose_index: usize, current_count: usize) -> [usize; 4] {
    let mut counts = [0; 4];
    counts[..purpose_index].fill(MANUAL_TRANSCRIPT_BYTES_V2);
    counts[purpose_index] = current_count;
    counts
}

fn assert_entry_screen(session: &SetupSessionV2, purpose: CeremonyPurposeV2, count: usize) {
    assert!(matches!(
        session.screen(),
        Some(SetupScreenV2::CeremonyInput {
            purpose: actual,
            count: actual_count,
        }) if actual == purpose && actual_count == count
    ));
}

fn assert_echo_screen(
    session: &SetupSessionV2,
    purpose: CeremonyPurposeV2,
    transcript: &[u8; MANUAL_TRANSCRIPT_BYTES_V2],
) {
    assert!(matches!(
        session.screen(),
        Some(SetupScreenV2::CeremonyEcho {
            purpose: actual,
            transcript: actual_transcript,
        }) if actual == purpose && actual_transcript == transcript
    ));
}

fn enter_prefix(
    session: &mut SetupSessionV2,
    purpose_index: usize,
    transcript: &[u8; MANUAL_TRANSCRIPT_BYTES_V2],
    count: usize,
) {
    assert_entry_screen(session, PURPOSES[purpose_index], 0);
    for (index, face) in transcript.iter().take(count).enumerate() {
        expect_continue(
            session,
            face_key(*face),
            SetupStageV2::CeremonyInput,
            expected_counts(purpose_index, index + 1),
            EntropyInputModeV2::ManualKeypad,
            Some(0),
        );
    }
}

fn complete_to_echo(
    session: &mut SetupSessionV2,
    purpose_index: usize,
    transcript: &[u8; MANUAL_TRANSCRIPT_BYTES_V2],
    mut current_count: usize,
) {
    for face in transcript.iter().skip(current_count) {
        current_count += 1;
        expect_continue(
            session,
            face_key(*face),
            SetupStageV2::CeremonyInput,
            expected_counts(purpose_index, current_count),
            EntropyInputModeV2::ManualKeypad,
            Some(0),
        );
    }
    expect_continue(
        session,
        KeypadKey::EqualsConfirmEnter,
        SetupStageV2::CeremonyEcho,
        expected_counts(purpose_index, MANUAL_TRANSCRIPT_BYTES_V2),
        EntropyInputModeV2::ManualKeypad,
        Some(0),
    );
    assert_echo_screen(session, PURPOSES[purpose_index], transcript);
}

fn enter_one(
    session: &mut SetupSessionV2,
    purpose: CeremonyPurposeV2,
    transcript: &[u8; MANUAL_TRANSCRIPT_BYTES_V2],
) {
    let purpose_index = usize::from(purpose_tag(purpose) - 1);
    enter_prefix(
        session,
        purpose_index,
        transcript,
        MANUAL_TRANSCRIPT_BYTES_V2,
    );
    expect_state_preserving(session, KeypadKey::One, SetupErrorV2::TranscriptFull);

    expect_continue(
        session,
        KeypadKey::EqualsConfirmEnter,
        SetupStageV2::CeremonyEcho,
        expected_counts(purpose_index, MANUAL_TRANSCRIPT_BYTES_V2),
        EntropyInputModeV2::ManualKeypad,
        Some(0),
    );
    assert_echo_screen(session, purpose, transcript);
    expect_continue(
        session,
        KeypadKey::EqualsConfirmEnter,
        SetupStageV2::CeremonyConfirm,
        expected_counts(purpose_index, MANUAL_TRANSCRIPT_BYTES_V2),
        EntropyInputModeV2::ManualKeypad,
        Some(0),
    );
    match session.screen().expect("confirmation screen") {
        SetupScreenV2::CeremonyConfirm {
            purpose: actual,
            transcript: actual_transcript,
        } => {
            assert_eq!(actual, purpose);
            assert_eq!(actual_transcript, transcript);
        }
        _ => panic!("confirm stage exposes only its typed confirmation screen"),
    }
    let progress = session
        .apply_key(KeypadKey::EqualsConfirmEnter)
        .expect("confirmation commits the exact transcript");
    assert_eq!(
        progress.outcome(),
        SetupOutcomeV2::Continue(SetupStageV2::CeremonyCommitment)
    );
    assert!(progress.outbound().is_none());
    assert_eq!(
        session.retained_counts(),
        expected_counts(purpose_index, MANUAL_TRANSCRIPT_BYTES_V2)
    );
    match session.screen().expect("commitment screen") {
        SetupScreenV2::CeremonyCommitment {
            purpose: actual,
            commitment,
        } => {
            assert_eq!(actual, purpose);
            assert_eq!(*commitment, reference_commitment(purpose, transcript));
        }
        _ => panic!("commitment stage exposes only its typed commitment screen"),
    }
}

fn advance_to_purpose(
    session: &mut SetupSessionV2,
    transcripts: &[[u8; MANUAL_TRANSCRIPT_BYTES_V2]; 4],
    target: usize,
) {
    for purpose_index in 0..target {
        enter_one(
            session,
            PURPOSES[purpose_index],
            &transcripts[purpose_index],
        );
        let before_wipe = wiped_bytes();
        let progress = session
            .apply_key(KeypadKey::EqualsConfirmEnter)
            .expect("earlier commitment advances to the next purpose");
        assert_eq!(
            progress.outcome(),
            SetupOutcomeV2::Continue(SetupStageV2::CeremonyInput)
        );
        assert!(progress.outbound().is_none());
        assert_eq!(
            session.retained_counts(),
            expected_counts(purpose_index + 1, 0)
        );
        assert_eq!(wiped_bytes().saturating_sub(before_wipe), COMMITMENT_BYTES);
        assert_entry_screen(session, PURPOSES[purpose_index + 1], 0);
    }
}

fn finish_session(
    session: SetupSessionV2,
    scenario: u8,
    expected_drop_delta: Option<usize>,
) -> RunFact {
    let final_stage = session.stage();
    let terminal_error = session.terminal_error().map(setup_error_name);
    let before_drop = wiped_bytes();
    drop(session);
    let wiped = wiped_bytes();
    let drop_delta = wiped.saturating_sub(before_drop);
    if let Some(expected) = expected_drop_delta {
        assert_eq!(drop_delta, expected);
    } else {
        assert!(drop_delta >= TERMINAL_DROP_BYTES);
    }
    RunFact {
        scenario,
        final_stage,
        terminal_error,
        wiped,
        drop_delta,
    }
}

fn exercise_entry_action(
    mut session: SetupSessionV2,
    transcripts: &[[u8; MANUAL_TRANSCRIPT_BYTES_V2]; 4],
    purpose_index: usize,
    count: usize,
    chosen: KeypadKey,
    scenario: u8,
) -> RunFact {
    enter_manual(&mut session);
    advance_to_purpose(&mut session, transcripts, purpose_index);
    let mut expected = transcripts[purpose_index];
    enter_prefix(&mut session, purpose_index, &expected, count);
    let mode = EntropyInputModeV2::ManualKeypad;
    let current_count = match chosen {
        KeypadKey::One
        | KeypadKey::TwoDown
        | KeypadKey::Three
        | KeypadKey::FourLeft
        | KeypadKey::Five
        | KeypadKey::SixRight => {
            if count == MANUAL_TRANSCRIPT_BYTES_V2 {
                expect_state_preserving(&mut session, chosen, SetupErrorV2::TranscriptFull);
                count
            } else {
                expected[count] = face_for_key(chosen).expect("exhaustive face key");
                expect_continue(
                    &mut session,
                    chosen,
                    SetupStageV2::CeremonyInput,
                    expected_counts(purpose_index, count + 1),
                    mode,
                    Some(0),
                );
                count + 1
            }
        }
        KeypadKey::CeDelete => {
            if count == 0 {
                expect_state_preserving(&mut session, chosen, SetupErrorV2::EmptyDelete);
                0
            } else {
                expect_continue(
                    &mut session,
                    chosen,
                    SetupStageV2::CeremonyInput,
                    expected_counts(purpose_index, count - 1),
                    mode,
                    Some(1),
                );
                count - 1
            }
        }
        KeypadKey::EqualsConfirmEnter => {
            if count == MANUAL_TRANSCRIPT_BYTES_V2 {
                expect_continue(
                    &mut session,
                    chosen,
                    SetupStageV2::CeremonyEcho,
                    expected_counts(purpose_index, count),
                    mode,
                    Some(0),
                );
                assert_echo_screen(&session, PURPOSES[purpose_index], &expected);
            } else {
                expect_state_preserving(
                    &mut session,
                    chosen,
                    SetupErrorV2::TranscriptCountIncomplete,
                );
            }
            count
        }
        KeypadKey::CancelBack => {
            expect_key_termination(
                &mut session,
                chosen,
                SetupErrorV2::Interrupted(Interruption::Cancelled),
                TERMINATION_CLEANUP_BYTES,
            );
            return finish_session(session, scenario, Some(TERMINAL_DROP_BYTES));
        }
        KeypadKey::Seven
        | KeypadKey::EightUp
        | KeypadKey::Nine
        | KeypadKey::Multiply
        | KeypadKey::Divide
        | KeypadKey::Minus
        | KeypadKey::Percent
        | KeypadKey::Zero
        | KeypadKey::Decimal
        | KeypadKey::Plus => {
            expect_state_preserving(&mut session, chosen, SetupErrorV2::InvalidFaceKey);
            count
        }
    };

    if session.stage() != Some(SetupStageV2::CeremonyEcho) {
        complete_to_echo(&mut session, purpose_index, &expected, current_count);
    }
    assert_echo_screen(&session, PURPOSES[purpose_index], &expected);
    finish_session(session, scenario, Some(ACTIVE_ENTRY_DROP_BYTES))
}

fn prepare_modeled_stage(
    session: &mut SetupSessionV2,
    transcripts: &[[u8; MANUAL_TRANSCRIPT_BYTES_V2]; 4],
    stage_case: u8,
    purpose_index: usize,
) {
    match stage_case {
        0 => {}
        1 => expect_continue(
            session,
            KeypadKey::EqualsConfirmEnter,
            SetupStageV2::TierSelection,
            [0; 4],
            EntropyInputModeV2::DiceGrid,
            Some(0),
        ),
        2 => {
            expect_continue(
                session,
                KeypadKey::EqualsConfirmEnter,
                SetupStageV2::TierSelection,
                [0; 4],
                EntropyInputModeV2::DiceGrid,
                Some(0),
            );
            expect_continue(
                session,
                KeypadKey::EqualsConfirmEnter,
                SetupStageV2::EntropyModeSelection,
                [0; 4],
                EntropyInputModeV2::DiceGrid,
                Some(0),
            );
        }
        3..=5 => {
            enter_manual(session);
            advance_to_purpose(session, transcripts, purpose_index);
            complete_to_echo(session, purpose_index, &transcripts[purpose_index], 0);
            if stage_case >= 4 {
                expect_continue(
                    session,
                    KeypadKey::EqualsConfirmEnter,
                    SetupStageV2::CeremonyConfirm,
                    expected_counts(purpose_index, MANUAL_TRANSCRIPT_BYTES_V2),
                    EntropyInputModeV2::ManualKeypad,
                    Some(0),
                );
            }
            if stage_case == 5 {
                let progress = session
                    .apply_key(KeypadKey::EqualsConfirmEnter)
                    .expect("modeled confirmation commits");
                assert_eq!(
                    progress.outcome(),
                    SetupOutcomeV2::Continue(SetupStageV2::CeremonyCommitment)
                );
                assert!(progress.outbound().is_none());
                assert_eq!(
                    session.retained_counts(),
                    expected_counts(purpose_index, MANUAL_TRANSCRIPT_BYTES_V2)
                );
                assert!(matches!(
                    session.screen(),
                    Some(SetupScreenV2::CeremonyCommitment {
                        purpose: actual,
                        commitment,
                    }) if actual == PURPOSES[purpose_index]
                        && *commitment
                            == reference_commitment(actual, &transcripts[purpose_index])
                ));
            }
        }
        _ => unreachable!("stage case is bounded modulo six"),
    }
}

fn expect_invalid_transition_key(
    session: &mut SetupSessionV2,
    key: KeypadKey,
    commitment_live: bool,
) {
    let cleanup = if commitment_live {
        TERMINATION_CLEANUP_BYTES + COMMITMENT_BYTES
    } else {
        TERMINATION_CLEANUP_BYTES
    };
    expect_key_termination(session, key, SetupErrorV2::InvalidTransition, cleanup);
}

fn exercise_stage_action(
    mut session: SetupSessionV2,
    transcripts: &[[u8; MANUAL_TRANSCRIPT_BYTES_V2]; 4],
    stage_case: u8,
    purpose_index: usize,
    chosen: KeypadKey,
    scenario: u8,
) -> RunFact {
    prepare_modeled_stage(&mut session, transcripts, stage_case, purpose_index);
    let counts = session.retained_counts();
    let mode = session.entropy_mode();
    let commitment_live = stage_case == 5;

    if chosen == KeypadKey::CancelBack {
        let cleanup = if commitment_live {
            TERMINATION_CLEANUP_BYTES + COMMITMENT_BYTES
        } else {
            TERMINATION_CLEANUP_BYTES
        };
        expect_key_termination(
            &mut session,
            chosen,
            SetupErrorV2::Interrupted(Interruption::Cancelled),
            cleanup,
        );
        return finish_session(session, scenario, Some(TERMINAL_DROP_BYTES));
    }

    match stage_case {
        0 => match chosen {
            KeypadKey::EqualsConfirmEnter => expect_continue(
                &mut session,
                chosen,
                SetupStageV2::TierSelection,
                counts,
                mode,
                Some(0),
            ),
            KeypadKey::CancelBack => unreachable!("cancellation handled above"),
            KeypadKey::Seven
            | KeypadKey::EightUp
            | KeypadKey::Nine
            | KeypadKey::CeDelete
            | KeypadKey::FourLeft
            | KeypadKey::Five
            | KeypadKey::SixRight
            | KeypadKey::Multiply
            | KeypadKey::Divide
            | KeypadKey::One
            | KeypadKey::TwoDown
            | KeypadKey::Three
            | KeypadKey::Minus
            | KeypadKey::Percent
            | KeypadKey::Zero
            | KeypadKey::Decimal
            | KeypadKey::Plus => {
                expect_invalid_transition_key(&mut session, chosen, false);
                return finish_session(session, scenario, Some(TERMINAL_DROP_BYTES));
            }
        },
        1 | 3 | 4 => match chosen {
            KeypadKey::EqualsConfirmEnter => {
                let expected_stage = match stage_case {
                    1 => SetupStageV2::EntropyModeSelection,
                    3 => SetupStageV2::CeremonyConfirm,
                    4 => SetupStageV2::CeremonyCommitment,
                    _ => unreachable!("grouped stage cases are exhaustive"),
                };
                if stage_case == 4 {
                    let progress = session
                        .apply_key(chosen)
                        .expect("modeled confirmation commits");
                    assert_eq!(progress.outcome(), SetupOutcomeV2::Continue(expected_stage));
                    assert!(progress.outbound().is_none());
                    assert_eq!(session.retained_counts(), counts);
                    assert!(matches!(
                        session.screen(),
                        Some(SetupScreenV2::CeremonyCommitment {
                            purpose: actual,
                            commitment,
                        }) if actual == PURPOSES[purpose_index]
                            && *commitment
                                == reference_commitment(actual, &transcripts[purpose_index])
                    ));
                } else {
                    expect_continue(&mut session, chosen, expected_stage, counts, mode, Some(0));
                }
            }
            KeypadKey::CancelBack => unreachable!("cancellation handled above"),
            KeypadKey::Seven
            | KeypadKey::EightUp
            | KeypadKey::Nine
            | KeypadKey::CeDelete
            | KeypadKey::FourLeft
            | KeypadKey::Five
            | KeypadKey::SixRight
            | KeypadKey::Multiply
            | KeypadKey::Divide
            | KeypadKey::One
            | KeypadKey::TwoDown
            | KeypadKey::Three
            | KeypadKey::Minus
            | KeypadKey::Percent
            | KeypadKey::Zero
            | KeypadKey::Decimal
            | KeypadKey::Plus => {
                expect_invalid_transition_key(&mut session, chosen, false);
                return finish_session(session, scenario, Some(TERMINAL_DROP_BYTES));
            }
        },
        2 => match chosen {
            KeypadKey::FourLeft => expect_continue(
                &mut session,
                chosen,
                SetupStageV2::EntropyModeSelection,
                counts,
                EntropyInputModeV2::DiceGrid,
                Some(0),
            ),
            KeypadKey::SixRight => expect_continue(
                &mut session,
                chosen,
                SetupStageV2::EntropyModeSelection,
                counts,
                EntropyInputModeV2::ManualKeypad,
                Some(0),
            ),
            KeypadKey::EqualsConfirmEnter => {
                expect_state_preserving(&mut session, chosen, SetupErrorV2::DiceGridUnavailable)
            }
            KeypadKey::CancelBack => unreachable!("cancellation handled above"),
            KeypadKey::Seven
            | KeypadKey::EightUp
            | KeypadKey::Nine
            | KeypadKey::CeDelete
            | KeypadKey::Five
            | KeypadKey::Multiply
            | KeypadKey::Divide
            | KeypadKey::One
            | KeypadKey::TwoDown
            | KeypadKey::Three
            | KeypadKey::Minus
            | KeypadKey::Percent
            | KeypadKey::Zero
            | KeypadKey::Decimal
            | KeypadKey::Plus => {
                expect_invalid_transition_key(&mut session, chosen, false);
                return finish_session(session, scenario, Some(TERMINAL_DROP_BYTES));
            }
        },
        5 => match chosen {
            KeypadKey::EqualsConfirmEnter => {
                let before_wipe = wiped_bytes();
                let progress = session
                    .apply_key(chosen)
                    .expect("commitment acknowledgement follows the modeled topology");
                assert!(progress.outbound().is_none());
                if purpose_index == 3 {
                    assert_eq!(
                        progress.outcome(),
                        SetupOutcomeV2::Continue(SetupStageV2::DerivationExplanation)
                    );
                    assert_eq!(session.stage(), Some(SetupStageV2::DerivationExplanation));
                    assert_eq!(session.retained_counts(), [0; 4]);
                    assert!(session.public_facts().is_some());
                    return finish_session(session, scenario, None);
                }
                assert_eq!(
                    progress.outcome(),
                    SetupOutcomeV2::Continue(SetupStageV2::CeremonyInput)
                );
                assert_eq!(session.stage(), Some(SetupStageV2::CeremonyInput));
                assert_eq!(
                    session.retained_counts(),
                    expected_counts(purpose_index + 1, 0)
                );
                assert_eq!(wiped_bytes().saturating_sub(before_wipe), COMMITMENT_BYTES);
                assert_entry_screen(&session, PURPOSES[purpose_index + 1], 0);
            }
            KeypadKey::CancelBack => unreachable!("cancellation handled above"),
            KeypadKey::Seven
            | KeypadKey::EightUp
            | KeypadKey::Nine
            | KeypadKey::CeDelete
            | KeypadKey::FourLeft
            | KeypadKey::Five
            | KeypadKey::SixRight
            | KeypadKey::Multiply
            | KeypadKey::Divide
            | KeypadKey::One
            | KeypadKey::TwoDown
            | KeypadKey::Three
            | KeypadKey::Minus
            | KeypadKey::Percent
            | KeypadKey::Zero
            | KeypadKey::Decimal
            | KeypadKey::Plus => {
                expect_invalid_transition_key(&mut session, chosen, true);
                return finish_session(session, scenario, Some(TERMINAL_DROP_BYTES));
            }
        },
        _ => unreachable!("stage case is bounded modulo six"),
    }

    let expected_drop = if session.stage() == Some(SetupStageV2::CeremonyCommitment) {
        ACTIVE_COMMITMENT_DROP_BYTES
    } else {
        ACTIVE_ENTRY_DROP_BYTES
    };
    finish_session(session, scenario, Some(expected_drop))
}

fn interruption(selector: u8) -> Interruption {
    match selector % 10 {
        0 => Interruption::Cancelled,
        1 => Interruption::OperationFailed,
        2 => Interruption::MediaRemoved,
        3 => Interruption::CardRemoved,
        4 => Interruption::SessionTimeout,
        5 => Interruption::Shutdown,
        6 => Interruption::Restart,
        7 => Interruption::PowerLoss,
        8 => Interruption::PeerLost,
        9 => Interruption::CapabilityFailed,
        _ => unreachable!("modulo ten is exhaustive"),
    }
}

fn prepare_interruption_position(
    session: &mut SetupSessionV2,
    transcripts: &[[u8; MANUAL_TRANSCRIPT_BYTES_V2]; 4],
    position: u8,
) -> bool {
    match position {
        0 => {
            assert_eq!(session.stage(), Some(SetupStageV2::SetupStart));
        }
        1 => expect_continue(
            session,
            KeypadKey::EqualsConfirmEnter,
            SetupStageV2::TierSelection,
            [0; 4],
            EntropyInputModeV2::DiceGrid,
            Some(0),
        ),
        2 => {
            expect_continue(
                session,
                KeypadKey::EqualsConfirmEnter,
                SetupStageV2::TierSelection,
                [0; 4],
                EntropyInputModeV2::DiceGrid,
                Some(0),
            );
            expect_continue(
                session,
                KeypadKey::EqualsConfirmEnter,
                SetupStageV2::EntropyModeSelection,
                [0; 4],
                EntropyInputModeV2::DiceGrid,
                Some(0),
            );
        }
        3 => {
            enter_manual(session);
            enter_prefix(session, 0, &transcripts[0], 3);
        }
        4 => {
            enter_manual(session);
            complete_to_echo(session, 0, &transcripts[0], 0);
        }
        5 => {
            enter_manual(session);
            complete_to_echo(session, 0, &transcripts[0], 0);
            expect_continue(
                session,
                KeypadKey::EqualsConfirmEnter,
                SetupStageV2::CeremonyConfirm,
                expected_counts(0, MANUAL_TRANSCRIPT_BYTES_V2),
                EntropyInputModeV2::ManualKeypad,
                Some(0),
            );
        }
        6 => {
            enter_manual(session);
            enter_one(session, PURPOSES[0], &transcripts[0]);
        }
        7 => {
            enter_manual(session);
            advance_to_purpose(session, transcripts, 1);
            enter_prefix(session, 1, &transcripts[1], 3);
        }
        8 => {
            enter_manual(session);
            advance_to_purpose(session, transcripts, 2);
            complete_to_echo(session, 2, &transcripts[2], 0);
        }
        9 => {
            enter_manual(session);
            advance_to_purpose(session, transcripts, 3);
            complete_to_echo(session, 3, &transcripts[3], 0);
            expect_continue(
                session,
                KeypadKey::EqualsConfirmEnter,
                SetupStageV2::CeremonyConfirm,
                expected_counts(3, MANUAL_TRANSCRIPT_BYTES_V2),
                EntropyInputModeV2::ManualKeypad,
                Some(0),
            );
        }
        _ => unreachable!("interruption position is bounded modulo ten"),
    }
    position == 6
}

fn exercise_interruption(
    mut session: SetupSessionV2,
    transcripts: &[[u8; MANUAL_TRANSCRIPT_BYTES_V2]; 4],
    position: u8,
    scenario: u8,
) -> RunFact {
    let commitment_live = prepare_interruption_position(&mut session, transcripts, position);
    let reason = interruption(position);
    let cleanup = if commitment_live {
        TERMINATION_CLEANUP_BYTES + COMMITMENT_BYTES
    } else {
        TERMINATION_CLEANUP_BYTES
    };
    let before_wipe = wiped_bytes();
    assert_eq!(session.interrupt(reason), Ok(reason));
    assert_eq!(wiped_bytes().saturating_sub(before_wipe), cleanup);
    assert_eq!(
        session.terminal_error().map(setup_error_name),
        Some(interruption_name(reason))
    );
    assert_terminal_absorption(&mut session);
    finish_session(session, scenario, Some(TERMINAL_DROP_BYTES))
}

fn exercise_reuse_pair(
    mut session: SetupSessionV2,
    mut transcripts: [[u8; MANUAL_TRANSCRIPT_BYTES_V2]; 4],
    pair: usize,
    scenario: u8,
) -> RunFact {
    let pairs = [(0, 1), (0, 2), (0, 3), (1, 2), (1, 3), (2, 3)];
    let (left, right) = pairs[pair];
    transcripts[right] = transcripts[left];
    enter_manual(&mut session);
    for purpose_index in 0..4 {
        enter_one(
            &mut session,
            PURPOSES[purpose_index],
            &transcripts[purpose_index],
        );
        let before_wipe = wiped_bytes();
        let next = session.apply_key(KeypadKey::EqualsConfirmEnter);
        if purpose_index == 3 {
            let error = match next {
                Ok(_) => panic!("pairwise reuse must reject"),
                Err(error) => error,
            };
            assert_eq!(error, SetupErrorV2::TranscriptReuse);
            assert_eq!(setup_error_name(error), "TranscriptReuse");
            assert_eq!(
                wiped_bytes().saturating_sub(before_wipe),
                COMMITMENT_BYTES + 2 * 4 * MANUAL_TRANSCRIPT_BYTES_V2 + 12 + 16
            );
            assert_terminal_absorption(&mut session);
        } else {
            let progress = next.expect("earlier purpose advances");
            assert_eq!(
                progress.outcome(),
                SetupOutcomeV2::Continue(SetupStageV2::CeremonyInput)
            );
            assert!(progress.outbound().is_none());
            assert_eq!(
                session.retained_counts(),
                expected_counts(purpose_index + 1, 0)
            );
            assert_eq!(wiped_bytes().saturating_sub(before_wipe), COMMITMENT_BYTES);
        }
    }
    finish_session(session, scenario, Some(TERMINAL_DROP_BYTES))
}

fn assert_terminal_absorption(session: &mut SetupSessionV2) {
    assert!(session.is_terminal());
    assert_eq!(session.retained_counts(), [0; 4]);
    assert!(session.public_facts().is_none());
    assert_eq!(
        session
            .apply_key(KeypadKey::One)
            .err()
            .map(setup_error_name),
        Some("SetupFinished")
    );
    assert_eq!(
        session.camera_presented().err().map(setup_error_name),
        Some("SetupFinished")
    );
    assert_eq!(
        session
            .interrupt(Interruption::Shutdown)
            .err()
            .map(setup_error_name),
        Some("SetupFinished")
    );
}

fn run(data: &[u8]) -> RunFact {
    reset_wiped_bytes();
    let mut cursor = Cursor::new(data);
    let namespace = cursor.array::<12>();
    let nonce = cursor.array::<12>();
    let scenario = cursor.byte() % 4;
    let selector = cursor.byte();
    let transcripts = generated_transcripts(data.get(26..).unwrap_or_default());
    let session = start_ready(namespace, nonce);

    match scenario {
        0 => exercise_entry_action(
            session,
            &transcripts,
            usize::from(selector % 4),
            representative_count(cursor.byte()),
            key(cursor.byte()),
            scenario,
        ),
        1 => exercise_stage_action(
            session,
            &transcripts,
            selector % 6,
            usize::from(cursor.byte() % 4),
            key(cursor.byte()),
            scenario,
        ),
        2 => exercise_reuse_pair(session, transcripts, usize::from(selector % 6), scenario),
        3 => exercise_interruption(session, &transcripts, selector % 10, scenario),
        _ => unreachable!("scenario is bounded modulo four"),
    }
}

fuzz_target!(|data: &[u8]| {
    let first = run(data);
    let second = run(data);
    assert_eq!(first, second);
});
