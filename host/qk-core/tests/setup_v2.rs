//! Headless QK-DEC-145 setup topology, retention, and terminality tests.

use qk_core::{
    CardBPublicBindingV2, CardInstanceV2, CardMockErrorV2, CardPresence, CeremonyPurposeV2,
    CoreDeviceGrants, Interruption, KeypadKey, MockCardSlot, MockDisplay, MockKeypad, SetupErrorV2,
    SetupOutcomeV2, SetupScreenV2, SetupSessionV2, SetupStageV2, SpareBChoiceV2,
};
use qk_io::{BrokerReply, BrokerSession, MockInput, MockOutputWriter, Sink, Source as IoSource};
use qk_ipc::{ReceivedFrame, StreamDecoder};
use std::collections::BTreeMap;

const FIXTURE: &str = include_str!("../../qk-provisioning/tests/fixtures/provisioning_v2.txt");

const INVALID_FACE_KEYS: [KeypadKey; 10] = [
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

const INTERRUPTIONS: [Interruption; 10] = [
    Interruption::Cancelled,
    Interruption::OperationFailed,
    Interruption::MediaRemoved,
    Interruption::CardRemoved,
    Interruption::SessionTimeout,
    Interruption::Shutdown,
    Interruption::Restart,
    Interruption::PowerLoss,
    Interruption::PeerLost,
    Interruption::CapabilityFailed,
];

const PURPOSES: [CeremonyPurposeV2; 4] = [
    CeremonyPurposeV2::SeedA,
    CeremonyPurposeV2::SignerB,
    CeremonyPurposeV2::KitR,
    CeremonyPurposeV2::A2,
];

const COMMITMENT_HEX: [&str; 4] = [
    "0d4394563d6015cdf34067107826012ae15ce485cae3ea4f3d260a20b21aee5e",
    "87b5219e60218bad5891c15acb36cca72b25f6b36c0606d18418ca47df80ad96",
    "33ac98439468d7c7e837a839349dbe7057140e285ab5f2bf11af5cf9bc444ddb",
    "137fcd6aeaaa8f44e9fd2d2f62803461ad64d21942ad21e22573deb0b2ea73be",
];

fn fixture_fields() -> BTreeMap<&'static str, &'static str> {
    let mut fields = BTreeMap::new();
    for line in FIXTURE.lines().filter(|line| !line.starts_with('#')) {
        if line.is_empty() {
            continue;
        }
        let (name, value) = line.split_once(": ").expect("framed fixture fact");
        assert!(fields.insert(name, value).is_none(), "unique {name}");
    }
    fields
}

fn hex_array<const N: usize>(text: &str) -> [u8; N] {
    assert_eq!(text.len(), N * 2);
    let mut output = [0u8; N];
    for (slot, position) in output.iter_mut().zip((0..text.len()).step_by(2)) {
        *slot = u8::from_str_radix(&text[position..position + 2], 16).expect("fixture hex");
    }
    output
}

fn fixture_transcripts() -> [[u8; 100]; 4] {
    let fields = fixture_fields();
    [
        fields["seed_a_transcript_ascii"]
            .as_bytes()
            .try_into()
            .expect("Seed-A transcript"),
        fields["signer_b_transcript_ascii"]
            .as_bytes()
            .try_into()
            .expect("Signer-B transcript"),
        fields["kit_r_transcript_ascii"]
            .as_bytes()
            .try_into()
            .expect("Kit-R transcript"),
        fields["a2_transcript_ascii"]
            .as_bytes()
            .try_into()
            .expect("A2 transcript"),
    ]
}

fn grants(card: MockCardSlot) -> CoreDeviceGrants {
    CoreDeviceGrants::validate(
        Some(MockDisplay::new()),
        Some(MockKeypad::new()),
        Some(card),
        false,
    )
    .expect("exact setup grants")
}

fn decode_one(bytes: &[u8]) -> ReceivedFrame {
    let mut decoder = StreamDecoder::new();
    let outcome = decoder.ingest(bytes, false).expect("complete QKIP frame");
    assert_eq!(outcome.consumed(), bytes.len());
    assert!(outcome.frame_ready());
    decoder.take_frame().expect("owned QKIP frame")
}

fn broker_reply(
    broker: &mut BrokerSession,
    outbound: &qk_core::CoreOutbound,
    input: Option<&mut MockInput>,
    writer: Option<&mut MockOutputWriter>,
) -> BrokerReply {
    let frame = decode_one(outbound.frame_bytes());
    broker
        .accept(&frame, input, writer)
        .expect("broker accepts exact request")
}

fn start_setup(card: MockCardSlot) -> (SetupSessionV2, BrokerSession) {
    let mut nonce = hex_array::<12>(fixture_fields()["a1_nonce_hex"]);
    let (mut setup, opening) = SetupSessionV2::start(grants(card), &mut nonce).expect("setup");
    assert_eq!(nonce, [0; 12]);

    let mut broker = BrokerSession::new();
    let ready = broker_reply(&mut broker, &opening, None, None);
    let progress = setup
        .receive(ready.frame_bytes(), false)
        .expect("session ready");
    assert_eq!(
        progress.outcome(),
        SetupOutcomeV2::Continue(SetupStageV2::SetupStart)
    );
    (setup, broker)
}

fn advance_to_manual_entry(card: MockCardSlot) -> (SetupSessionV2, BrokerSession) {
    let (mut setup, broker) = start_setup(card);
    expect_key_stage(
        &mut setup,
        KeypadKey::EqualsConfirmEnter,
        SetupStageV2::TierSelection,
    );
    expect_key_stage(
        &mut setup,
        KeypadKey::EqualsConfirmEnter,
        SetupStageV2::EntropyModeSelection,
    );
    expect_key_stage(
        &mut setup,
        KeypadKey::SixRight,
        SetupStageV2::EntropyModeSelection,
    );
    expect_key_stage(
        &mut setup,
        KeypadKey::EqualsConfirmEnter,
        SetupStageV2::CeremonyInput,
    );
    (setup, broker)
}

fn expect_key_stage(setup: &mut SetupSessionV2, key: KeypadKey, stage: SetupStageV2) {
    assert_eq!(
        setup.apply_key(key).expect("valid setup key").outcome(),
        SetupOutcomeV2::Continue(stage)
    );
    assert_eq!(setup.stage(), Some(stage));
}

fn key_for_face(face: u8) -> KeypadKey {
    match face {
        b'1' => KeypadKey::One,
        b'2' => KeypadKey::TwoDown,
        b'3' => KeypadKey::Three,
        b'4' => KeypadKey::FourLeft,
        b'5' => KeypadKey::Five,
        b'6' => KeypadKey::SixRight,
        _ => panic!("registered transcript face"),
    }
}

fn assert_entry_screen(setup: &SetupSessionV2, purpose: CeremonyPurposeV2, count: usize) {
    assert!(matches!(
        setup.screen(),
        Some(SetupScreenV2::CeremonyInput {
            purpose: actual,
            count: actual_count,
        }) if actual == purpose && actual_count == count
    ));
}

fn enter_one_transcript(
    setup: &mut SetupSessionV2,
    purpose_index: usize,
    transcript: &[u8; 100],
    registered_commitment: bool,
) {
    let purpose = PURPOSES[purpose_index];
    assert_entry_screen(setup, purpose, 0);
    for (index, face) in transcript.iter().enumerate() {
        expect_key_stage(setup, key_for_face(*face), SetupStageV2::CeremonyInput);
        assert_eq!(setup.retained_counts()[purpose_index], index + 1);
    }

    expect_key_stage(
        setup,
        KeypadKey::EqualsConfirmEnter,
        SetupStageV2::CeremonyEcho,
    );
    assert!(matches!(
        setup.screen(),
        Some(SetupScreenV2::CeremonyEcho {
            purpose: actual,
            transcript: actual_transcript,
        }) if actual == purpose && actual_transcript == transcript
    ));

    expect_key_stage(
        setup,
        KeypadKey::EqualsConfirmEnter,
        SetupStageV2::CeremonyConfirm,
    );
    assert!(matches!(
        setup.screen(),
        Some(SetupScreenV2::CeremonyConfirm {
            purpose: actual,
            transcript: actual_transcript,
        }) if actual == purpose && actual_transcript == transcript
    ));

    expect_key_stage(
        setup,
        KeypadKey::EqualsConfirmEnter,
        SetupStageV2::CeremonyCommitment,
    );
    if registered_commitment {
        let expected_commitment = hex_array::<32>(COMMITMENT_HEX[purpose_index]);
        assert!(matches!(
            setup.screen(),
            Some(SetupScreenV2::CeremonyCommitment {
                purpose: actual,
                commitment,
            }) if actual == purpose && commitment == &expected_commitment
        ));
    } else {
        assert!(matches!(
            setup.screen(),
            Some(SetupScreenV2::CeremonyCommitment {
                purpose: actual,
                ..
            }) if actual == purpose
        ));
    }
}

fn enter_all_transcripts(
    setup: &mut SetupSessionV2,
    transcripts: &[[u8; 100]; 4],
) -> Result<(), SetupErrorV2> {
    for (purpose_index, transcript) in transcripts.iter().enumerate() {
        enter_one_transcript(setup, purpose_index, transcript, true);
        let next = setup.apply_key(KeypadKey::EqualsConfirmEnter)?;
        let expected = if purpose_index == 3 {
            SetupStageV2::DerivationExplanation
        } else {
            SetupStageV2::CeremonyInput
        };
        assert_eq!(next.outcome(), SetupOutcomeV2::Continue(expected));
        assert_eq!(setup.stage(), Some(expected));
    }
    Ok(())
}

fn advance_to_provision_b(card: MockCardSlot) -> SetupSessionV2 {
    let (mut setup, _broker) = advance_to_manual_entry(card);
    enter_all_transcripts(&mut setup, &fixture_transcripts()).expect("unique transcripts");
    assert_eq!(setup.retained_counts(), [0; 4]);
    expect_key_stage(
        &mut setup,
        KeypadKey::EqualsConfirmEnter,
        SetupStageV2::ProvisioningResult,
    );
    expect_key_stage(
        &mut setup,
        KeypadKey::EqualsConfirmEnter,
        SetupStageV2::ProvisionB,
    );
    setup
}

#[test]
fn entry_rejections_preserve_the_exact_buffer_and_count() {
    let (mut setup, _broker) = advance_to_manual_entry(MockCardSlot::new(CardPresence::Present));
    assert_entry_screen(&setup, CeremonyPurposeV2::SeedA, 0);

    let empty_delete = setup.apply_key(KeypadKey::CeDelete).expect("named outcome");
    assert_eq!(
        empty_delete.outcome(),
        SetupOutcomeV2::StatePreserving(SetupErrorV2::EmptyDelete)
    );
    let incomplete = setup
        .apply_key(KeypadKey::EqualsConfirmEnter)
        .expect("named outcome");
    assert_eq!(
        incomplete.outcome(),
        SetupOutcomeV2::StatePreserving(SetupErrorV2::TranscriptCountIncomplete)
    );

    for key in INVALID_FACE_KEYS {
        let rejected = setup.apply_key(key).expect("named invalid face");
        assert_eq!(
            rejected.outcome(),
            SetupOutcomeV2::StatePreserving(SetupErrorV2::InvalidFaceKey)
        );
        assert_entry_screen(&setup, CeremonyPurposeV2::SeedA, 0);
    }

    expect_key_stage(&mut setup, KeypadKey::One, SetupStageV2::CeremonyInput);
    expect_key_stage(&mut setup, KeypadKey::TwoDown, SetupStageV2::CeremonyInput);
    expect_key_stage(&mut setup, KeypadKey::CeDelete, SetupStageV2::CeremonyInput);
    expect_key_stage(&mut setup, KeypadKey::Three, SetupStageV2::CeremonyInput);
    let mut expected = vec![b'1', b'3'];
    expected.extend(std::iter::repeat_n(b'4', 98));
    for _ in 0..98 {
        expect_key_stage(&mut setup, KeypadKey::FourLeft, SetupStageV2::CeremonyInput);
    }
    assert_eq!(setup.retained_counts(), [100, 0, 0, 0]);

    let full = setup.apply_key(KeypadKey::SixRight).expect("named full");
    assert_eq!(
        full.outcome(),
        SetupOutcomeV2::StatePreserving(SetupErrorV2::TranscriptFull)
    );
    assert_eq!(setup.retained_counts(), [100, 0, 0, 0]);
    expect_key_stage(
        &mut setup,
        KeypadKey::EqualsConfirmEnter,
        SetupStageV2::CeremonyEcho,
    );
    assert!(matches!(
        setup.screen(),
        Some(SetupScreenV2::CeremonyEcho {
            purpose: CeremonyPurposeV2::SeedA,
            transcript,
        }) if transcript == expected.as_slice()
    ));
}

#[test]
fn fixture_transcripts_follow_echo_confirm_commitment_order_and_remain_retained() {
    let transcripts = fixture_transcripts();
    let (mut setup, _broker) = advance_to_manual_entry(MockCardSlot::new(CardPresence::Present));

    for (purpose_index, transcript) in transcripts.iter().enumerate() {
        enter_one_transcript(&mut setup, purpose_index, transcript, true);
        let mut expected_counts = [0; 4];
        expected_counts[..=purpose_index].fill(100);
        assert_eq!(setup.retained_counts(), expected_counts);
        let next = setup
            .apply_key(KeypadKey::EqualsConfirmEnter)
            .expect("commitment acknowledged");
        if purpose_index == 3 {
            assert_eq!(
                next.outcome(),
                SetupOutcomeV2::Continue(SetupStageV2::DerivationExplanation)
            );
            assert_eq!(setup.retained_counts(), [0; 4]);
            assert!(setup.public_facts().is_some());
        } else {
            assert_eq!(
                next.outcome(),
                SetupOutcomeV2::Continue(SetupStageV2::CeremonyInput)
            );
        }
    }
}

#[test]
fn all_six_transcript_reuse_pairs_terminate_and_wipe() {
    for first in 0..4 {
        for second in (first + 1)..4 {
            let mut transcripts = fixture_transcripts();
            transcripts[second] = transcripts[first];
            let (mut setup, _broker) =
                advance_to_manual_entry(MockCardSlot::new(CardPresence::Present));

            for (purpose_index, transcript) in transcripts.iter().enumerate() {
                enter_one_transcript(&mut setup, purpose_index, transcript, false);
                let result = setup.apply_key(KeypadKey::EqualsConfirmEnter);
                if purpose_index == 3 {
                    assert_eq!(result.err(), Some(SetupErrorV2::TranscriptReuse));
                } else {
                    assert_eq!(
                        result.expect("earlier purpose").outcome(),
                        SetupOutcomeV2::Continue(SetupStageV2::CeremonyInput)
                    );
                }
            }
            assert!(setup.is_terminal());
            assert_eq!(setup.terminal_error(), Some(SetupErrorV2::TranscriptReuse));
            assert_eq!(setup.retained_counts(), [0; 4]);
            assert!(setup.public_facts().is_none());
            assert_eq!(
                setup.apply_key(KeypadKey::One).err(),
                Some(SetupErrorV2::SetupFinished)
            );
        }
    }
}

#[test]
fn card_and_spare_failures_have_distinct_names_and_are_absorbing() {
    let mut absent = advance_to_provision_b(MockCardSlot::new(CardPresence::Absent));
    assert_eq!(
        absent.provision_card(CardInstanceV2::Required).err(),
        Some(SetupErrorV2::CardAbsent)
    );
    assert_eq!(absent.terminal_error(), Some(SetupErrorV2::CardAbsent));
    assert!(absent.public_facts().is_none());
    assert_eq!(
        absent.provision_card(CardInstanceV2::Required).err(),
        Some(SetupErrorV2::SetupFinished)
    );

    let fields = fixture_fields();
    let wallet_id = hex_array::<32>(fields["wallet_id"]);
    let account_xpub = fields["role_b_account_xpub"]
        .as_bytes()
        .try_into()
        .expect("fixed account xpub");
    let exact = CardBPublicBindingV2::new(CardInstanceV2::Required, wallet_id, account_xpub);
    let mut preloaded = MockCardSlot::new(CardPresence::Present);
    preloaded
        .provision_b(exact)
        .expect("preloaded card binding");
    let mut duplicate = advance_to_provision_b(preloaded);
    assert_eq!(
        duplicate.provision_card(CardInstanceV2::Required).err(),
        Some(SetupErrorV2::CardInstanceAlreadyProvisioned)
    );
    assert_eq!(
        duplicate.terminal_error(),
        Some(SetupErrorV2::CardInstanceAlreadyProvisioned)
    );

    let mut card = MockCardSlot::new(CardPresence::Present);
    card.provision_b(exact).expect("binding recorded");
    let wrong = CardBPublicBindingV2::new(CardInstanceV2::Required, [0x55; 32], account_xpub);
    assert_eq!(
        card.verify_b(wrong),
        Err(CardMockErrorV2::CardBindingMismatch)
    );
    assert_eq!(
        CardMockErrorV2::CardBindingMismatch.name(),
        SetupErrorV2::CardBindingMismatch.name()
    );

    let mut spare = advance_to_provision_b(MockCardSlot::new(CardPresence::Present));
    assert_eq!(
        spare
            .provision_card(CardInstanceV2::Required)
            .expect("required provision")
            .outcome(),
        SetupOutcomeV2::Continue(SetupStageV2::VerifyB)
    );
    assert_eq!(
        spare
            .verify_card(CardInstanceV2::Required)
            .expect("required verify")
            .outcome(),
        SetupOutcomeV2::Continue(SetupStageV2::SpareBSelection)
    );
    assert_eq!(
        spare
            .select_spare(SpareBChoiceV2::NoSpare)
            .expect("first choice")
            .outcome(),
        SetupOutcomeV2::Continue(SetupStageV2::CreateA1)
    );
    assert_eq!(
        spare.select_spare(SpareBChoiceV2::ProvisionSpare).err(),
        Some(SetupErrorV2::SpareChoiceAlreadyMade)
    );
    assert_eq!(
        spare.terminal_error(),
        Some(SetupErrorV2::SpareChoiceAlreadyMade)
    );
}

#[test]
fn cancellation_and_every_closed_interruption_wipe_and_absorb() {
    let (mut cancelled, _broker) =
        advance_to_manual_entry(MockCardSlot::new(CardPresence::Present));
    expect_key_stage(
        &mut cancelled,
        KeypadKey::SixRight,
        SetupStageV2::CeremonyInput,
    );
    assert_eq!(
        cancelled.apply_key(KeypadKey::CancelBack).err(),
        Some(SetupErrorV2::Interrupted(Interruption::Cancelled))
    );
    assert_eq!(cancelled.retained_counts(), [0; 4]);
    assert!(cancelled.is_terminal());
    assert_eq!(
        cancelled.camera_presented().err(),
        Some(SetupErrorV2::SetupFinished)
    );

    for reason in INTERRUPTIONS {
        let (mut setup, _broker) =
            advance_to_manual_entry(MockCardSlot::new(CardPresence::Present));
        for key in [KeypadKey::One, KeypadKey::TwoDown, KeypadKey::Three] {
            expect_key_stage(&mut setup, key, SetupStageV2::CeremonyInput);
        }
        assert_eq!(setup.retained_counts(), [3, 0, 0, 0]);
        assert_eq!(setup.interrupt(reason), Ok(reason));
        assert_eq!(setup.retained_counts(), [0; 4]);
        assert_eq!(
            setup.terminal_error(),
            Some(SetupErrorV2::Interrupted(reason))
        );
        assert!(setup.is_terminal());
        assert_eq!(
            setup.apply_key(KeypadKey::One).err(),
            Some(SetupErrorV2::SetupFinished)
        );
        assert_eq!(
            setup.observe_card(CardPresence::Present),
            Err(SetupErrorV2::SetupFinished)
        );
        assert_eq!(setup.interrupt(reason), Err(SetupErrorV2::SetupFinished));
    }
}

#[test]
fn full_setup_completes_only_after_the_close_receipt() {
    let fields = fixture_fields();
    let expected_a1 = hex_array::<67>(fields["a1_capsule_hex"]);
    let (mut setup, mut broker) = advance_to_manual_entry(MockCardSlot::new(CardPresence::Present));
    enter_all_transcripts(&mut setup, &fixture_transcripts()).expect("unique transcripts");
    expect_key_stage(
        &mut setup,
        KeypadKey::EqualsConfirmEnter,
        SetupStageV2::ProvisioningResult,
    );
    expect_key_stage(
        &mut setup,
        KeypadKey::EqualsConfirmEnter,
        SetupStageV2::ProvisionB,
    );
    assert_eq!(
        setup
            .provision_card(CardInstanceV2::Required)
            .expect("required provision")
            .outcome(),
        SetupOutcomeV2::Continue(SetupStageV2::VerifyB)
    );
    assert_eq!(
        setup
            .verify_card(CardInstanceV2::Required)
            .expect("required verify")
            .outcome(),
        SetupOutcomeV2::Continue(SetupStageV2::SpareBSelection)
    );
    assert_eq!(
        setup
            .select_spare(SpareBChoiceV2::NoSpare)
            .expect("no spare")
            .outcome(),
        SetupOutcomeV2::Continue(SetupStageV2::CreateA1)
    );

    let mut outbound = setup
        .begin_a1_print()
        .expect("A1 print")
        .into_outbound()
        .expect("A1 begin");
    for step in 0..3 {
        let mut writer = MockOutputWriter::new(Sink::Print);
        let reply = if step == 2 {
            broker_reply(&mut broker, &outbound, None, Some(&mut writer))
        } else {
            broker_reply(&mut broker, &outbound, None, None)
        };
        let received = setup
            .receive(reply.frame_bytes(), false)
            .expect("A1 receipt");
        if step == 2 {
            assert_eq!(writer.final_bytes(), Some(expected_a1.as_slice()));
        }
        outbound = received.into_outbound().expect("next A1 operation");
    }
    assert_eq!(setup.stage(), Some(SetupStageV2::ScanBackA1));

    let mut scanback =
        MockInput::try_new(IoSource::CameraA1Candidate, &expected_a1).expect("scan-back input");
    let reply = broker_reply(&mut broker, &outbound, Some(&mut scanback), None);
    outbound = setup
        .receive(reply.frame_bytes(), false)
        .expect("scan begin")
        .into_outbound()
        .expect("scan read");
    let reply = broker_reply(&mut broker, &outbound, None, None);
    assert_eq!(
        setup
            .receive(reply.frame_bytes(), false)
            .expect("scan complete")
            .outcome(),
        SetupOutcomeV2::Continue(SetupStageV2::CoordinatorMaterial)
    );
    expect_key_stage(
        &mut setup,
        KeypadKey::EqualsConfirmEnter,
        SetupStageV2::CreateTwoKits,
    );

    outbound = setup
        .begin_kit_print()
        .expect("Kit print")
        .into_outbound()
        .expect("Kit begin");
    for page in 0..4 {
        for step in 0..3 {
            let mut writer = MockOutputWriter::new(Sink::Print);
            let reply = if step == 2 {
                broker_reply(&mut broker, &outbound, None, Some(&mut writer))
            } else {
                broker_reply(&mut broker, &outbound, None, None)
            };
            let received = setup
                .receive(reply.frame_bytes(), false)
                .expect("Kit receipt");
            if page == 3 && step == 2 {
                assert_eq!(
                    received.outcome(),
                    SetupOutcomeV2::Continue(SetupStageV2::VerifyTwoKits)
                );
                assert!(received.outbound().is_none());
            } else {
                outbound = received.into_outbound().expect("next Kit operation");
            }
        }
    }

    expect_key_stage(
        &mut setup,
        KeypadKey::EqualsConfirmEnter,
        SetupStageV2::Rehearsal,
    );
    expect_key_stage(
        &mut setup,
        KeypadKey::EqualsConfirmEnter,
        SetupStageV2::SetupReady,
    );
    let closing = setup
        .apply_key(KeypadKey::EqualsConfirmEnter)
        .expect("close requested");
    assert_eq!(closing.outcome(), SetupOutcomeV2::TransportPending);
    assert_eq!(setup.stage(), Some(SetupStageV2::SetupReady));
    assert!(!setup.is_terminal());
    assert_eq!(
        setup.apply_key(KeypadKey::EqualsConfirmEnter).err(),
        Some(SetupErrorV2::SetupFinished)
    );

    let closing = closing.into_outbound().expect("session close");
    let reply = broker_reply(&mut broker, &closing, None, None);
    let closed = setup
        .receive(reply.frame_bytes(), false)
        .expect("close receipt");
    assert_eq!(closed.outcome(), SetupOutcomeV2::CompletedWiped);
    assert_eq!(setup.stage(), Some(SetupStageV2::CompletedWiped));
    assert!(setup.is_terminal());
    assert_eq!(setup.retained_counts(), [0; 4]);
    assert!(setup.public_facts().is_none());
    assert_eq!(
        setup.apply_key(KeypadKey::One).err(),
        Some(SetupErrorV2::SetupFinished)
    );
}
