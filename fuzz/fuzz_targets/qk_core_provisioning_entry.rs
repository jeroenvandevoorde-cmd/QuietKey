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
const MAX_TRACE_KEYS: usize = 128;

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

    let before = fact(session);
    for key in [KeypadKey::EqualsConfirmEnter, KeypadKey::FourLeft] {
        let result = session
            .apply_key(key)
            .expect("unavailable grid is recoverable");
        if key == KeypadKey::EqualsConfirmEnter {
            assert_eq!(
                result.outcome(),
                SetupOutcomeV2::StatePreserving(SetupErrorV2::DiceGridUnavailable)
            );
            assert_eq!(fact(session), before);
        }
    }
    let before_camera = fact(session);
    let camera = session
        .camera_presented()
        .expect("camera cannot widen unavailable grid mode");
    assert_eq!(
        camera.outcome(),
        SetupOutcomeV2::StatePreserving(SetupErrorV2::DiceGridUnavailable)
    );
    assert_eq!(fact(session), before_camera);

    expect_stage(
        session,
        KeypadKey::SixRight,
        SetupStageV2::EntropyModeSelection,
    );
    expect_stage(
        session,
        KeypadKey::EqualsConfirmEnter,
        SetupStageV2::CeremonyInput,
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

fn assert_input_rejections(session: &mut SetupSessionV2) {
    for (key, expected) in [
        (KeypadKey::CeDelete, SetupErrorV2::EmptyDelete),
        (
            KeypadKey::EqualsConfirmEnter,
            SetupErrorV2::TranscriptCountIncomplete,
        ),
        (KeypadKey::Seven, SetupErrorV2::InvalidFaceKey),
        (KeypadKey::EightUp, SetupErrorV2::InvalidFaceKey),
        (KeypadKey::Nine, SetupErrorV2::InvalidFaceKey),
        (KeypadKey::Zero, SetupErrorV2::InvalidFaceKey),
        (KeypadKey::Decimal, SetupErrorV2::InvalidFaceKey),
        (KeypadKey::Plus, SetupErrorV2::InvalidFaceKey),
        (KeypadKey::Minus, SetupErrorV2::InvalidFaceKey),
        (KeypadKey::Multiply, SetupErrorV2::InvalidFaceKey),
        (KeypadKey::Divide, SetupErrorV2::InvalidFaceKey),
        (KeypadKey::Percent, SetupErrorV2::InvalidFaceKey),
    ] {
        let before = fact(session);
        let progress = session
            .apply_key(key)
            .expect("entry rejection is recoverable");
        assert_eq!(
            progress.outcome(),
            SetupOutcomeV2::StatePreserving(expected)
        );
        assert!(progress.outbound().is_none());
        assert_eq!(fact(session), before);
        assert_eq!(setup_error_name(expected), expected.name());
    }
}

fn enter_one(
    session: &mut SetupSessionV2,
    purpose: CeremonyPurposeV2,
    transcript: &[u8; MANUAL_TRANSCRIPT_BYTES_V2],
) {
    for face in transcript {
        expect_stage(session, face_key(*face), SetupStageV2::CeremonyInput);
    }
    let before_full = fact(session);
    let full = session
        .apply_key(KeypadKey::One)
        .expect("full transcript rejection is recoverable");
    assert_eq!(
        full.outcome(),
        SetupOutcomeV2::StatePreserving(SetupErrorV2::TranscriptFull)
    );
    assert_eq!(fact(session), before_full);

    expect_stage(
        session,
        KeypadKey::EqualsConfirmEnter,
        SetupStageV2::CeremonyEcho,
    );
    match session.screen().expect("echo screen") {
        SetupScreenV2::CeremonyEcho {
            purpose: actual,
            transcript: actual_transcript,
        } => {
            assert_eq!(actual, purpose);
            assert_eq!(actual_transcript, transcript);
        }
        _ => panic!("echo stage exposes only its typed echo screen"),
    }
    expect_stage(
        session,
        KeypadKey::EqualsConfirmEnter,
        SetupStageV2::CeremonyConfirm,
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
    expect_stage(
        session,
        KeypadKey::EqualsConfirmEnter,
        SetupStageV2::CeremonyCommitment,
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
    let scenario = cursor.byte() % 3;
    let selector = cursor.byte();
    let pair = selector as usize % 6;
    let mut transcripts = generated_transcripts(data.get(26..).unwrap_or_default());

    let mut session = start_ready(namespace, nonce);
    enter_manual(&mut session);
    assert_input_rejections(&mut session);

    if scenario == 0 {
        let trace_len = usize::from(cursor.byte()) % (MAX_TRACE_KEYS + 1);
        for _ in 0..trace_len {
            if session.is_terminal() {
                break;
            }
            let before = fact(&session);
            let chosen = key(cursor.byte());
            match session.apply_key(chosen) {
                Ok(progress) => {
                    if let SetupOutcomeV2::StatePreserving(error) = progress.outcome() {
                        setup_error_name(error);
                        assert_eq!(fact(&session), before);
                    }
                }
                Err(error) => {
                    setup_error_name(error);
                    assert_terminal_absorption(&mut session);
                }
            }
        }
    } else if scenario == 1 {
        let pairs = [(0, 1), (0, 2), (0, 3), (1, 2), (1, 3), (2, 3)];
        let (left, right) = pairs[pair];
        transcripts[right] = transcripts[left];
        for purpose_index in 0..4 {
            let purpose = [
                CeremonyPurposeV2::SeedA,
                CeremonyPurposeV2::SignerB,
                CeremonyPurposeV2::KitR,
                CeremonyPurposeV2::A2,
            ][purpose_index];
            enter_one(&mut session, purpose, &transcripts[purpose_index]);
            let next = session.apply_key(KeypadKey::EqualsConfirmEnter);
            if purpose_index == 3 {
                let error = match next {
                    Ok(_) => panic!("pairwise reuse must reject"),
                    Err(error) => error,
                };
                assert_eq!(setup_error_name(error), "TranscriptReuse");
                assert_terminal_absorption(&mut session);
            } else {
                assert_eq!(
                    next.expect("next purpose").outcome(),
                    SetupOutcomeV2::Continue(SetupStageV2::CeremonyInput)
                );
            }
        }
    } else {
        let target_stage = selector % 4;
        if target_stage > 0 {
            enter_one(&mut session, CeremonyPurposeV2::SeedA, &transcripts[0]);
            if target_stage > 1 {
                expect_stage(
                    &mut session,
                    KeypadKey::EqualsConfirmEnter,
                    SetupStageV2::CeremonyInput,
                );
                enter_one(&mut session, CeremonyPurposeV2::SignerB, &transcripts[1]);
            }
        }
        let reason = interruption(cursor.byte());
        assert_eq!(session.interrupt(reason), Ok(reason));
        assert_eq!(
            session.terminal_error().map(setup_error_name),
            Some(interruption_name(reason))
        );
        assert_terminal_absorption(&mut session);
    }

    let final_stage = session.stage();
    let terminal_error = session.terminal_error().map(setup_error_name);
    drop(session);
    let wiped = wiped_bytes();
    assert!(wiped >= 12 + 4 * MANUAL_TRANSCRIPT_BYTES_V2);
    RunFact {
        scenario,
        final_stage,
        terminal_error,
        wiped,
    }
}

fuzz_target!(|data: &[u8]| {
    let first = run(data);
    let second = run(data);
    assert_eq!(first, second);
});
