//! Full registered setup flow through the byte-frozen qk-io broker boundary.

use qk_core::{
    CardInstanceV2, CardPresence, CoreDeviceGrants, KeypadKey, MockCardSlot, MockDisplay,
    MockKeypad, SetupOutcomeV2, SetupSessionV2, SetupStageV2, SpareBChoiceV2,
};
use qk_io::{
    BrokerReply, BrokerSession, BrokerState, MockInput, MockOutputWriter, Operation as IoOperation,
    ReplyStatus, Sink, Source as IoSource,
};
use qk_ipc::{ReceivedFrame, StreamDecoder};
use qk_provisioning::{
    HostProvisioningRunV2, KitCopyV2, KitPageDispositionV2, KitPrintPageV2, KitShareIndexV2,
};
use std::collections::BTreeMap;

const FIXTURE: &str = include_str!("../../qk-provisioning/tests/fixtures/provisioning_v2.txt");
const A1_BYTES: usize = 67;
const KIT_PAGE_BYTES: usize = 829;

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

fn transcripts(fields: &BTreeMap<&str, &str>) -> [[u8; 100]; 4] {
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

fn serialize_page(page: KitPrintPageV2<'_>) -> [u8; KIT_PAGE_BYTES] {
    let mut bytes = Vec::with_capacity(KIT_PAGE_BYTES);
    bytes.extend_from_slice(b"QKKP");
    bytes.push(1);
    bytes.push(match page.copy() {
        KitCopyV2::One => 1,
        KitCopyV2::Two => 2,
    });
    bytes.push(match page.share_index() {
        KitShareIndexV2::One => 1,
        KitShareIndexV2::Two => 2,
    });
    bytes.extend_from_slice(page.wallet_id());
    let metadata = page.qr_metadata();
    bytes.push(metadata.mask);
    for penalty in metadata.penalties {
        bytes.extend_from_slice(&penalty.to_le_bytes());
    }
    for line in 0..4 {
        bytes.extend_from_slice(page.fallback_line(line).expect("four fixed lines"));
    }
    bytes.extend_from_slice(page.qr_packed());
    assert_eq!(bytes.len(), KIT_PAGE_BYTES);
    bytes.try_into().expect("fixed QKKP page")
}

fn registered_outputs(
    values: &[[u8; 100]; 4],
    nonce: &[u8; 12],
) -> ([u8; A1_BYTES], [u8; 32], Vec<[u8; KIT_PAGE_BYTES]>) {
    let mut run =
        HostProvisioningRunV2::from_manual_dice([&values[0], &values[1], &values[2], &values[3]])
            .expect("registered transcripts");
    let artifacts = run.encrypt_a1(nonce).expect("registered nonce");
    let mut pages = Vec::new();
    let receipt = run
        .emit_two_kit_copies(|page| {
            pages.push(serialize_page(page));
            KitPageDispositionV2::Accepted
        })
        .expect("four registered pages");
    assert_eq!(pages.len(), 4);
    (artifacts.a1_capsule, receipt.wallet_id(), pages)
}

fn grants() -> CoreDeviceGrants {
    CoreDeviceGrants::validate(
        Some(MockDisplay::new()),
        Some(MockKeypad::new()),
        Some(MockCardSlot::new(CardPresence::Present)),
        false,
    )
    .expect("exact setup grants")
}

fn decode_one(bytes: &[u8]) -> ReceivedFrame {
    let mut decoder = StreamDecoder::new();
    let outcome = decoder.ingest(bytes, false).expect("complete QKIP frame");
    assert_eq!(outcome.consumed(), bytes.len());
    assert!(outcome.frame_ready());
    decoder.take_frame().expect("owned frame")
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
        .expect("broker accepts exact operation")
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

fn expect_stage(outcome: SetupOutcomeV2, stage: SetupStageV2) {
    assert_eq!(outcome, SetupOutcomeV2::Continue(stage));
}

#[test]
fn golden_setup_prints_scans_and_receipts_cross_the_frozen_broker_exactly() {
    let fields = fixture_fields();
    let values = transcripts(&fields);
    let nonce = hex_array::<12>(fields["a1_nonce_hex"]);
    let (expected_a1, expected_wallet, expected_pages) = registered_outputs(&values, &nonce);
    assert_eq!(expected_a1, hex_array(fields["a1_capsule_hex"]));
    assert_eq!(expected_wallet, hex_array(fields["wallet_id"]));

    let mut setup_nonce = nonce;
    let (mut setup, opening) =
        SetupSessionV2::start(grants(), &mut setup_nonce).expect("setup session");
    assert_eq!(setup_nonce, [0; 12]);
    let mut broker = BrokerSession::new();
    let ready = broker_reply(&mut broker, &opening, None, None);
    assert_eq!(ready.status(), ReplyStatus::Control);
    let ready = setup
        .receive(ready.frame_bytes(), false)
        .expect("setup start");
    expect_stage(ready.outcome(), SetupStageV2::SetupStart);
    assert!(ready.outbound().is_none());

    expect_stage(
        setup
            .apply_key(KeypadKey::EqualsConfirmEnter)
            .expect("tier")
            .outcome(),
        SetupStageV2::TierSelection,
    );
    expect_stage(
        setup
            .apply_key(KeypadKey::EqualsConfirmEnter)
            .expect("entropy selection")
            .outcome(),
        SetupStageV2::EntropyModeSelection,
    );
    expect_stage(
        setup
            .apply_key(KeypadKey::SixRight)
            .expect("manual mode")
            .outcome(),
        SetupStageV2::EntropyModeSelection,
    );
    expect_stage(
        setup
            .apply_key(KeypadKey::EqualsConfirmEnter)
            .expect("manual entry")
            .outcome(),
        SetupStageV2::CeremonyInput,
    );

    for (purpose_index, transcript) in values.iter().enumerate() {
        for face in transcript {
            expect_stage(
                setup
                    .apply_key(key_for_face(*face))
                    .expect("face entry")
                    .outcome(),
                SetupStageV2::CeremonyInput,
            );
        }
        expect_stage(
            setup
                .apply_key(KeypadKey::EqualsConfirmEnter)
                .expect("echo")
                .outcome(),
            SetupStageV2::CeremonyEcho,
        );
        expect_stage(
            setup
                .apply_key(KeypadKey::EqualsConfirmEnter)
                .expect("confirm")
                .outcome(),
            SetupStageV2::CeremonyConfirm,
        );
        expect_stage(
            setup
                .apply_key(KeypadKey::EqualsConfirmEnter)
                .expect("commitment")
                .outcome(),
            SetupStageV2::CeremonyCommitment,
        );
        let next = setup
            .apply_key(KeypadKey::EqualsConfirmEnter)
            .expect("next purpose");
        let expected = if purpose_index == 3 {
            SetupStageV2::DerivationExplanation
        } else {
            SetupStageV2::CeremonyInput
        };
        expect_stage(next.outcome(), expected);
    }

    expect_stage(
        setup
            .apply_key(KeypadKey::EqualsConfirmEnter)
            .expect("public facts")
            .outcome(),
        SetupStageV2::ProvisioningResult,
    );
    let facts = setup.public_facts().expect("public setup facts");
    assert_eq!(facts.wallet_id(), expected_wallet);
    assert_eq!(
        facts.account_xpubs()[0].as_slice(),
        fields["role_a_account_xpub"].as_bytes()
    );
    assert_eq!(
        facts.account_xpubs()[1].as_slice(),
        fields["role_b_account_xpub"].as_bytes()
    );

    expect_stage(
        setup
            .apply_key(KeypadKey::EqualsConfirmEnter)
            .expect("required B")
            .outcome(),
        SetupStageV2::ProvisionB,
    );
    expect_stage(
        setup
            .provision_card(CardInstanceV2::Required)
            .expect("provision B")
            .outcome(),
        SetupStageV2::VerifyB,
    );
    expect_stage(
        setup
            .verify_card(CardInstanceV2::Required)
            .expect("verify B")
            .outcome(),
        SetupStageV2::SpareBSelection,
    );
    expect_stage(
        setup
            .select_spare(SpareBChoiceV2::NoSpare)
            .expect("no spare")
            .outcome(),
        SetupStageV2::CreateA1,
    );

    let mut outbound = setup
        .begin_a1_print()
        .expect("A1 print begin")
        .into_outbound()
        .expect("A1 begin request");
    let begin_reply = broker_reply(&mut broker, &outbound, None, None);
    assert_eq!(
        begin_reply.status(),
        ReplyStatus::Success(IoOperation::EgressBegin)
    );
    outbound = setup
        .receive(begin_reply.frame_bytes(), false)
        .expect("A1 begin receipt")
        .into_outbound()
        .expect("A1 write request");
    let write_reply = broker_reply(&mut broker, &outbound, None, None);
    assert_eq!(
        write_reply.status(),
        ReplyStatus::Success(IoOperation::EgressWrite)
    );
    outbound = setup
        .receive(write_reply.frame_bytes(), false)
        .expect("A1 write receipt")
        .into_outbound()
        .expect("A1 finish request");
    let mut a1_writer = MockOutputWriter::new(Sink::Print);
    let finish_reply = broker_reply(&mut broker, &outbound, None, Some(&mut a1_writer));
    assert_eq!(
        finish_reply.status(),
        ReplyStatus::Success(IoOperation::EgressFinish)
    );
    assert!(a1_writer.is_used());
    assert_eq!(a1_writer.final_bytes(), Some(expected_a1.as_slice()));

    outbound = setup
        .receive(finish_reply.frame_bytes(), false)
        .expect("A1 finish receipt")
        .into_outbound()
        .expect("scan-back begin");
    assert_eq!(setup.stage(), Some(SetupStageV2::ScanBackA1));
    let mut scanback = MockInput::try_new(IoSource::CameraA1Candidate, &expected_a1)
        .expect("one-use scan-back input");
    let scan_begin_reply = broker_reply(&mut broker, &outbound, Some(&mut scanback), None);
    assert!(scanback.is_used());
    assert_eq!(
        scan_begin_reply.status(),
        ReplyStatus::Success(IoOperation::IngressBegin)
    );
    outbound = setup
        .receive(scan_begin_reply.frame_bytes(), false)
        .expect("scan-back begin receipt")
        .into_outbound()
        .expect("scan-back read");
    let scan_read_reply = broker_reply(&mut broker, &outbound, None, None);
    assert_eq!(
        scan_read_reply.status(),
        ReplyStatus::Success(IoOperation::IngressRead)
    );
    let scan_complete = setup
        .receive(scan_read_reply.frame_bytes(), false)
        .expect("scan-back exact match");
    expect_stage(scan_complete.outcome(), SetupStageV2::CoordinatorMaterial);
    assert!(scan_complete.outbound().is_none());

    expect_stage(
        setup
            .apply_key(KeypadKey::EqualsConfirmEnter)
            .expect("coordinator fact checkpoint")
            .outcome(),
        SetupStageV2::CreateTwoKits,
    );
    outbound = setup
        .begin_kit_print()
        .expect("Kit page one begin")
        .into_outbound()
        .expect("Kit begin request");

    let mut kit_writers = Vec::new();
    for expected_page in &expected_pages {
        let begin_reply = broker_reply(&mut broker, &outbound, None, None);
        assert_eq!(
            begin_reply.status(),
            ReplyStatus::Success(IoOperation::EgressBegin)
        );
        outbound = setup
            .receive(begin_reply.frame_bytes(), false)
            .expect("Kit begin receipt")
            .into_outbound()
            .expect("Kit write request");
        let write_reply = broker_reply(&mut broker, &outbound, None, None);
        assert_eq!(
            write_reply.status(),
            ReplyStatus::Success(IoOperation::EgressWrite)
        );
        outbound = setup
            .receive(write_reply.frame_bytes(), false)
            .expect("Kit write receipt")
            .into_outbound()
            .expect("Kit finish request");
        let mut writer = MockOutputWriter::new(Sink::Print);
        let finish_reply = broker_reply(&mut broker, &outbound, None, Some(&mut writer));
        assert_eq!(
            finish_reply.status(),
            ReplyStatus::Success(IoOperation::EgressFinish)
        );
        assert!(writer.is_used());
        assert_eq!(writer.final_bytes(), Some(expected_page.as_slice()));
        let received = setup
            .receive(finish_reply.frame_bytes(), false)
            .expect("Kit finish receipt");
        kit_writers.push(writer);
        if kit_writers.len() == 4 {
            expect_stage(received.outcome(), SetupStageV2::VerifyTwoKits);
            assert!(received.outbound().is_none());
            break;
        }
        outbound = received.into_outbound().expect("next Kit page begin");
    }

    assert_eq!(kit_writers.len(), 4);
    assert_eq!(setup.stage(), Some(SetupStageV2::VerifyTwoKits));
    assert_eq!(broker.state(), BrokerState::Idle);
    for (actual, expected) in kit_writers.iter().zip(&expected_pages) {
        assert_eq!(actual.final_bytes(), Some(expected.as_slice()));
        assert!(actual.final_name().is_none());
        assert!(actual.temporary_bytes().is_none());
    }
    assert_eq!(&expected_pages[0][0..5], b"QKKP\x01");
    assert_eq!(&expected_pages[0][7..39], expected_wallet.as_slice());
    assert_eq!(&expected_pages[0][40..], &expected_pages[2][40..]);
    assert_eq!(&expected_pages[1][40..], &expected_pages[3][40..]);

    expect_stage(
        setup
            .apply_key(KeypadKey::EqualsConfirmEnter)
            .expect("two-Kit confirmation")
            .outcome(),
        SetupStageV2::Rehearsal,
    );
    expect_stage(
        setup
            .apply_key(KeypadKey::EqualsConfirmEnter)
            .expect("rehearsal confirmation")
            .outcome(),
        SetupStageV2::SetupReady,
    );

    let close = setup
        .apply_key(KeypadKey::EqualsConfirmEnter)
        .expect("setup close")
        .into_outbound()
        .expect("close request");
    let closed = broker_reply(&mut broker, &close, None, None);
    assert_eq!(closed.status(), ReplyStatus::Control);
    assert_eq!(broker.state(), BrokerState::Closed);
    let completed = setup
        .receive(closed.frame_bytes(), false)
        .expect("closed receipt");
    assert_eq!(completed.outcome(), SetupOutcomeV2::CompletedWiped);
    assert!(completed.outbound().is_none());
    assert!(setup.is_terminal());
    assert_eq!(setup.stage(), Some(SetupStageV2::CompletedWiped));
}
