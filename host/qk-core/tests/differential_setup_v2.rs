//! Provisioning parity with the byte-frozen v2 HOST simulator.

use qk_core::{
    CardInstanceV2, CardPresence, CoreDeviceGrants, Interruption, KeypadKey as CoreKey,
    MockCardSlot, MockDisplay, MockKeypad, SetupOutcomeV2, SetupScreenV2, SetupSessionV2,
    SetupStageV2, SpareBChoiceV2,
};
use qk_host_sim::{
    CeremonyPurposeV2 as SimPurpose, CompletedOperationV2, EntropyInputModeV2 as SimEntropy,
    FlowApplyOutcomeV2, FlowEventV2, FlowKindV2, FlowTerminalV2, KeypadKey as SimKey,
    ManualKeypadErrorV2, ManualKeypadEventV2, ManualKeypadOutcomeV2, ManualKeypadScreenV2,
    ManualKeypadSessionV2, ScopedApplyOutcomeV2, ScreenFlowV2, ScreenKindV2, ScreenV2,
    SpareBChoiceV2 as SimSpareBChoiceV2, WipingReasonV2,
};
use qk_io::{
    BrokerReply, BrokerSession, MockInput, MockOutputWriter, ReplyStatus, Sink, Source as IoSource,
};
use qk_ipc::{ReceivedFrame, StreamDecoder};
use qk_provisioning::{
    HostProvisioningRunV2, KitCopyV2, KitPageDispositionV2, KitPrintPageV2, KitShareIndexV2,
    ProvisioningArtifactsV2,
};
use std::collections::BTreeMap;

const FIXTURE: &str = include_str!("../../qk-provisioning/tests/fixtures/provisioning_v2.txt");
const KIT_PAGE_BYTES: usize = 829;

fn fields() -> BTreeMap<&'static str, &'static str> {
    let mut fields = BTreeMap::new();
    for line in FIXTURE.lines().filter(|line| !line.starts_with('#')) {
        if line.is_empty() {
            continue;
        }
        let (name, value) = line.split_once(": ").expect("framed fixture fact");
        assert!(fields.insert(name, value).is_none(), "unique {name}");
    }
    assert_eq!(fields.len(), 66, "exact registered fact count");
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

fn expect_core_stage(outcome: SetupOutcomeV2, stage: SetupStageV2) {
    assert_eq!(outcome, SetupOutcomeV2::Continue(stage));
}

fn sim_continue(flow: &mut ScreenFlowV2, event: FlowEventV2<'_>, expected: ScreenKindV2) {
    assert!(matches!(
        flow.apply(event).expect("sim transition"),
        FlowApplyOutcomeV2::Continue(actual) if actual == expected
    ));
}

fn sim_entry() -> ManualKeypadSessionV2 {
    let mut flow = ScreenFlowV2::new(FlowKindV2::Setup);
    sim_continue(
        &mut flow,
        FlowEventV2::Key(SimKey::EqualsConfirmEnter),
        ScreenKindV2::TierSelection,
    );
    sim_continue(
        &mut flow,
        FlowEventV2::Key(SimKey::EqualsConfirmEnter),
        ScreenKindV2::EntropyModeSelection,
    );
    sim_continue(
        &mut flow,
        FlowEventV2::Key(SimKey::SixRight),
        ScreenKindV2::EntropyModeSelection,
    );
    assert!(matches!(
        flow.screen(),
        Some(ScreenV2::EntropyModeSelection {
            selected: SimEntropy::ManualKeypad
        })
    ));
    sim_continue(
        &mut flow,
        FlowEventV2::Key(SimKey::EqualsConfirmEnter),
        ScreenKindV2::CeremonyInput,
    );
    ManualKeypadSessionV2::begin(flow).expect("frozen simulator manual entry")
}

fn core_entry(nonce: &mut [u8; 12]) -> (SetupSessionV2, BrokerSession) {
    let (mut setup, opening) = SetupSessionV2::start(grants(), nonce).expect("core setup session");
    assert_eq!(*nonce, [0; 12], "caller nonce is consumed");
    let mut broker = BrokerSession::new();
    let ready = broker_reply(&mut broker, &opening, None, None);
    assert_eq!(ready.status(), ReplyStatus::Control);
    expect_core_stage(
        setup
            .receive(ready.frame_bytes(), false)
            .expect("session-ready response")
            .outcome(),
        SetupStageV2::SetupStart,
    );
    expect_core_stage(
        setup
            .apply_key(CoreKey::EqualsConfirmEnter)
            .expect("tier screen")
            .outcome(),
        SetupStageV2::TierSelection,
    );
    expect_core_stage(
        setup
            .apply_key(CoreKey::EqualsConfirmEnter)
            .expect("entropy screen")
            .outcome(),
        SetupStageV2::EntropyModeSelection,
    );
    expect_core_stage(
        setup
            .apply_key(CoreKey::SixRight)
            .expect("manual mode")
            .outcome(),
        SetupStageV2::EntropyModeSelection,
    );
    expect_core_stage(
        setup
            .apply_key(CoreKey::EqualsConfirmEnter)
            .expect("manual entry")
            .outcome(),
        SetupStageV2::CeremonyInput,
    );
    (setup, broker)
}

fn core_key(face: u8) -> CoreKey {
    match face {
        b'1' => CoreKey::One,
        b'2' => CoreKey::TwoDown,
        b'3' => CoreKey::Three,
        b'4' => CoreKey::FourLeft,
        b'5' => CoreKey::Five,
        b'6' => CoreKey::SixRight,
        _ => panic!("registered face"),
    }
}

fn sim_key(face: u8) -> SimKey {
    match face {
        b'1' => SimKey::One,
        b'2' => SimKey::TwoDown,
        b'3' => SimKey::Three,
        b'4' => SimKey::FourLeft,
        b'5' => SimKey::Five,
        b'6' => SimKey::SixRight,
        _ => panic!("registered face"),
    }
}

fn sim_apply(session: &mut ManualKeypadSessionV2, event: ManualKeypadEventV2) {
    assert!(matches!(
        session.apply(event),
        Ok(ManualKeypadOutcomeV2::Continue)
    ));
}

fn drive_ceremony_pair(
    core: &mut SetupSessionV2,
    sim: &mut ManualKeypadSessionV2,
    values: &[[u8; 100]; 4],
) -> HostProvisioningRunV2 {
    let core_purposes = [
        qk_core::CeremonyPurposeV2::SeedA,
        qk_core::CeremonyPurposeV2::SignerB,
        qk_core::CeremonyPurposeV2::KitR,
        qk_core::CeremonyPurposeV2::A2,
    ];
    let sim_purposes = [
        SimPurpose::SeedA,
        SimPurpose::SignerB,
        SimPurpose::KitR,
        SimPurpose::A2,
    ];
    let mut completed = None;

    for (purpose_index, transcript) in values.iter().enumerate() {
        for face in transcript {
            expect_core_stage(
                core.apply_key(core_key(*face))
                    .expect("core face")
                    .outcome(),
                SetupStageV2::CeremonyInput,
            );
            sim_apply(sim, ManualKeypadEventV2::Key(sim_key(*face)));
        }
        assert_eq!(core.retained_counts(), sim.retained_counts());

        expect_core_stage(
            core.apply_key(CoreKey::EqualsConfirmEnter)
                .expect("core echo")
                .outcome(),
            SetupStageV2::CeremonyEcho,
        );
        sim_apply(sim, ManualKeypadEventV2::Key(SimKey::EqualsConfirmEnter));
        let core_echo = match core.screen().expect("core echo screen") {
            SetupScreenV2::CeremonyEcho {
                purpose,
                transcript,
            } => {
                assert_eq!(purpose, core_purposes[purpose_index]);
                transcript
            }
            _ => panic!("core echo facts"),
        };
        match sim.screen() {
            ManualKeypadScreenV2::Echo {
                purpose,
                transcript,
            } => {
                assert_eq!(purpose, sim_purposes[purpose_index]);
                assert_eq!(transcript.bytes(), core_echo);
            }
            _ => panic!("sim echo facts"),
        }

        expect_core_stage(
            core.apply_key(CoreKey::EqualsConfirmEnter)
                .expect("core confirm")
                .outcome(),
            SetupStageV2::CeremonyConfirm,
        );
        sim_apply(sim, ManualKeypadEventV2::Key(SimKey::EqualsConfirmEnter));
        let core_confirm = match core.screen().expect("core confirm screen") {
            SetupScreenV2::CeremonyConfirm {
                purpose,
                transcript,
            } => {
                assert_eq!(purpose, core_purposes[purpose_index]);
                transcript
            }
            _ => panic!("core confirm facts"),
        };
        match sim.screen() {
            ManualKeypadScreenV2::Confirm {
                purpose,
                transcript,
            } => {
                assert_eq!(purpose, sim_purposes[purpose_index]);
                assert_eq!(transcript.bytes(), core_confirm);
            }
            _ => panic!("sim confirm facts"),
        }

        expect_core_stage(
            core.apply_key(CoreKey::EqualsConfirmEnter)
                .expect("core commitment")
                .outcome(),
            SetupStageV2::CeremonyCommitment,
        );
        sim_apply(sim, ManualKeypadEventV2::Key(SimKey::EqualsConfirmEnter));
        let commitment = match core.screen().expect("core commitment screen") {
            SetupScreenV2::CeremonyCommitment {
                purpose,
                commitment,
            } => {
                assert_eq!(purpose, core_purposes[purpose_index]);
                *commitment
            }
            _ => panic!("core commitment facts"),
        };
        sim_apply(sim, ManualKeypadEventV2::CommitmentReady(commitment));
        assert!(matches!(
            sim.screen(),
            ManualKeypadScreenV2::Commitment {
                purpose,
                commitment: actual
            } if purpose == sim_purposes[purpose_index] && actual == commitment
        ));

        let core_next = core
            .apply_key(CoreKey::EqualsConfirmEnter)
            .expect("core commitment acceptance");
        let expected_core = if purpose_index == 3 {
            SetupStageV2::DerivationExplanation
        } else {
            SetupStageV2::CeremonyInput
        };
        expect_core_stage(core_next.outcome(), expected_core);
        match sim.apply(ManualKeypadEventV2::Key(SimKey::EqualsConfirmEnter)) {
            Ok(ManualKeypadOutcomeV2::Continue) if purpose_index != 3 => {}
            Ok(ManualKeypadOutcomeV2::ProvisioningReady(run)) if purpose_index == 3 => {
                completed = Some(*run)
            }
            Ok(_) => panic!("sim ceremony completion class"),
            Err(error) => panic!("sim ceremony completion rejected: {error:?}"),
        }
    }

    assert_eq!(core.retained_counts(), [0; 4]);
    assert_eq!(sim.retained_counts(), [0; 4]);
    completed.expect("sim provisioning capability")
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
        bytes.extend_from_slice(page.fallback_line(line).expect("four fixed fallback lines"));
    }
    bytes.extend_from_slice(page.qr_packed());
    assert_eq!(bytes.len(), KIT_PAGE_BYTES);
    bytes.try_into().expect("fixed QKKP page")
}

fn sim_outputs(
    mut run: HostProvisioningRunV2,
    nonce: &[u8; 12],
) -> (ProvisioningArtifactsV2, Vec<[u8; KIT_PAGE_BYTES]>) {
    let artifacts = run.encrypt_a1(nonce).expect("sim A1 artifact");
    let mut pages = Vec::new();
    let receipt = run
        .emit_two_kit_copies(|page| {
            pages.push(serialize_page(page));
            KitPageDispositionV2::Accepted
        })
        .expect("sim two-Kit artifact set");
    assert_eq!(receipt.wallet_id(), artifacts.wallet_id);
    assert_eq!(pages.len(), 4);
    (artifacts, pages)
}

#[test]
fn registered_setup_matches_frozen_sim_public_facts_a1_and_all_kit_pages() {
    assert_eq!(FIXTURE.len(), 9_219);
    assert_eq!(FIXTURE.bytes().filter(|byte| *byte == b'\n').count(), 83);
    assert!(FIXTURE.ends_with('\n'));
    assert!(!FIXTURE.contains('\r'));
    let fixture = fields();
    assert_eq!(
        fixture["funding_status"],
        "PERMANENTLY NEVER-FUND PUBLIC PRIVATE MATERIAL"
    );
    let values = transcripts(&fixture);
    let nonce = hex_array::<12>(fixture["a1_nonce_hex"]);
    let mut core_nonce = nonce;
    let (mut core, mut broker) = core_entry(&mut core_nonce);
    let mut sim = sim_entry();
    let sim_run = drive_ceremony_pair(&mut core, &mut sim, &values);
    let mut sim_flow = sim.take_completed_flow().expect("completed sim setup flow");
    let (sim_artifacts, sim_pages) = sim_outputs(sim_run, &nonce);

    expect_core_stage(
        core.apply_key(CoreKey::EqualsConfirmEnter)
            .expect("core public facts")
            .outcome(),
        SetupStageV2::ProvisioningResult,
    );
    let core_facts = core.public_facts().expect("core public facts owner");
    assert_eq!(core_facts.account_xpubs(), &sim_artifacts.account_xpubs);
    assert_eq!(core_facts.descriptors(), &sim_artifacts.descriptors);
    assert_eq!(core_facts.wallet_id(), sim_artifacts.wallet_id);
    assert_eq!(core_facts.first_scripts(), &sim_artifacts.first_scripts);
    assert_eq!(core_facts.first_addresses(), &sim_artifacts.first_addresses);
    assert_eq!(core_facts.wallet_id(), hex_array(fixture["wallet_id"]));
    assert_eq!(
        sim_artifacts.a1_capsule,
        hex_array(fixture["a1_capsule_hex"])
    );

    {
        let result = match sim_flow
            .apply(FlowEventV2::OperationCompleted(
                CompletedOperationV2::Provisioning(&sim_artifacts),
            ))
            .expect("sim public result")
        {
            FlowApplyOutcomeV2::ProvisioningResult(result) => result,
            _ => panic!("sim provisioning-result scope"),
        };
        match result.screen() {
            ScreenV2::ProvisioningResult(view) => {
                assert_eq!(view.wallet_id(), core_facts.wallet_id());
            }
            _ => panic!("sim provisioning-result screen"),
        }
        assert!(matches!(
            result.apply(FlowEventV2::Key(SimKey::EqualsConfirmEnter)),
            Ok(ScopedApplyOutcomeV2::Released(ScreenKindV2::ProvisionB))
        ));
    }

    expect_core_stage(
        core.apply_key(CoreKey::EqualsConfirmEnter)
            .expect("required B screen")
            .outcome(),
        SetupStageV2::ProvisionB,
    );
    expect_core_stage(
        core.provision_card(CardInstanceV2::Required)
            .expect("public card bind")
            .outcome(),
        SetupStageV2::VerifyB,
    );
    sim_continue(
        &mut sim_flow,
        FlowEventV2::OperationCompleted(CompletedOperationV2::Plain),
        ScreenKindV2::VerifyB,
    );
    expect_core_stage(
        core.verify_card(CardInstanceV2::Required)
            .expect("public card verify")
            .outcome(),
        SetupStageV2::SpareBSelection,
    );
    sim_continue(
        &mut sim_flow,
        FlowEventV2::OperationCompleted(CompletedOperationV2::Plain),
        ScreenKindV2::SpareBSelection,
    );
    expect_core_stage(
        core.select_spare(SpareBChoiceV2::NoSpare)
            .expect("no-spare choice")
            .outcome(),
        SetupStageV2::CreateA1,
    );
    sim_continue(
        &mut sim_flow,
        FlowEventV2::SelectSpareB(SimSpareBChoiceV2::NoSpare),
        ScreenKindV2::CreateA1,
    );

    let mut outbound = core
        .begin_a1_print()
        .expect("A1 print begin")
        .into_outbound()
        .expect("A1 begin request");
    let reply = broker_reply(&mut broker, &outbound, None, None);
    outbound = core
        .receive(reply.frame_bytes(), false)
        .expect("A1 begin receipt")
        .into_outbound()
        .expect("A1 write request");
    let reply = broker_reply(&mut broker, &outbound, None, None);
    outbound = core
        .receive(reply.frame_bytes(), false)
        .expect("A1 write receipt")
        .into_outbound()
        .expect("A1 finish request");
    let mut a1_writer = MockOutputWriter::new(Sink::Print);
    let reply = broker_reply(&mut broker, &outbound, None, Some(&mut a1_writer));
    assert_eq!(
        a1_writer.final_bytes(),
        Some(sim_artifacts.a1_capsule.as_slice())
    );
    sim_continue(
        &mut sim_flow,
        FlowEventV2::OperationCompleted(CompletedOperationV2::Plain),
        ScreenKindV2::ScanBackA1,
    );
    outbound = core
        .receive(reply.frame_bytes(), false)
        .expect("A1 finish receipt")
        .into_outbound()
        .expect("A1 scan-back request");

    let mut scanback = MockInput::try_new(IoSource::CameraA1Candidate, &sim_artifacts.a1_capsule)
        .expect("one-use A1 scan-back");
    let reply = broker_reply(&mut broker, &outbound, Some(&mut scanback), None);
    outbound = core
        .receive(reply.frame_bytes(), false)
        .expect("A1 scan-back begin")
        .into_outbound()
        .expect("A1 scan-back read");
    let reply = broker_reply(&mut broker, &outbound, None, None);
    expect_core_stage(
        core.receive(reply.frame_bytes(), false)
            .expect("A1 scan-back match")
            .outcome(),
        SetupStageV2::CoordinatorMaterial,
    );
    sim_continue(
        &mut sim_flow,
        FlowEventV2::OperationCompleted(CompletedOperationV2::Plain),
        ScreenKindV2::CoordinatorMaterial,
    );
    expect_core_stage(
        core.apply_key(CoreKey::EqualsConfirmEnter)
            .expect("coordinator checkpoint")
            .outcome(),
        SetupStageV2::CreateTwoKits,
    );
    sim_continue(
        &mut sim_flow,
        FlowEventV2::OperationCompleted(CompletedOperationV2::Plain),
        ScreenKindV2::CreateTwoKits,
    );

    outbound = core
        .begin_kit_print()
        .expect("Kit page one begin")
        .into_outbound()
        .expect("Kit begin request");
    let mut core_pages = Vec::new();
    for expected in &sim_pages {
        let reply = broker_reply(&mut broker, &outbound, None, None);
        outbound = core
            .receive(reply.frame_bytes(), false)
            .expect("Kit begin receipt")
            .into_outbound()
            .expect("Kit write request");
        let reply = broker_reply(&mut broker, &outbound, None, None);
        outbound = core
            .receive(reply.frame_bytes(), false)
            .expect("Kit write receipt")
            .into_outbound()
            .expect("Kit finish request");
        let mut writer = MockOutputWriter::new(Sink::Print);
        let reply = broker_reply(&mut broker, &outbound, None, Some(&mut writer));
        let actual: [u8; KIT_PAGE_BYTES] = writer
            .final_bytes()
            .expect("complete Kit page")
            .try_into()
            .expect("exact Kit page width");
        assert_eq!(&actual, expected);
        core_pages.push(actual);
        let received = core
            .receive(reply.frame_bytes(), false)
            .expect("Kit finish receipt");
        if core_pages.len() == 4 {
            expect_core_stage(received.outcome(), SetupStageV2::VerifyTwoKits);
        } else {
            outbound = received.into_outbound().expect("next Kit begin request");
        }
    }
    assert_eq!(core_pages, sim_pages);
    assert_eq!(core_pages.len(), 4);
    sim_continue(
        &mut sim_flow,
        FlowEventV2::OperationCompleted(CompletedOperationV2::Plain),
        ScreenKindV2::VerifyTwoKits,
    );

    expect_core_stage(
        core.apply_key(CoreKey::EqualsConfirmEnter)
            .expect("two-Kit confirmation")
            .outcome(),
        SetupStageV2::Rehearsal,
    );
    sim_continue(
        &mut sim_flow,
        FlowEventV2::OperationCompleted(CompletedOperationV2::Plain),
        ScreenKindV2::Rehearsal,
    );
    expect_core_stage(
        core.apply_key(CoreKey::EqualsConfirmEnter)
            .expect("rehearsal confirmation")
            .outcome(),
        SetupStageV2::SetupReady,
    );
    sim_continue(
        &mut sim_flow,
        FlowEventV2::OperationCompleted(CompletedOperationV2::Plain),
        ScreenKindV2::SetupReady,
    );
    assert_eq!(
        core.apply_key(CoreKey::EqualsConfirmEnter)
            .expect("core setup close")
            .outcome(),
        SetupOutcomeV2::TransportPending
    );
    assert!(matches!(
        sim_flow
            .apply(FlowEventV2::Key(SimKey::EqualsConfirmEnter))
            .expect("sim setup completion"),
        FlowApplyOutcomeV2::CompletedWiped
    ));
}

#[derive(Clone, Copy)]
enum SharedInterruption {
    Cancelled,
    OperationFailed,
    MediaRemoved,
    CardRemoved,
    SessionTimeout,
    Shutdown,
    Restart,
    PowerLoss,
}

const INTERRUPTIONS: [SharedInterruption; 8] = [
    SharedInterruption::Cancelled,
    SharedInterruption::OperationFailed,
    SharedInterruption::MediaRemoved,
    SharedInterruption::CardRemoved,
    SharedInterruption::SessionTimeout,
    SharedInterruption::Shutdown,
    SharedInterruption::Restart,
    SharedInterruption::PowerLoss,
];

const fn core_reason(case: SharedInterruption) -> Interruption {
    match case {
        SharedInterruption::Cancelled => Interruption::Cancelled,
        SharedInterruption::OperationFailed => Interruption::OperationFailed,
        SharedInterruption::MediaRemoved => Interruption::MediaRemoved,
        SharedInterruption::CardRemoved => Interruption::CardRemoved,
        SharedInterruption::SessionTimeout => Interruption::SessionTimeout,
        SharedInterruption::Shutdown => Interruption::Shutdown,
        SharedInterruption::Restart => Interruption::Restart,
        SharedInterruption::PowerLoss => Interruption::PowerLoss,
    }
}

const fn sim_event(case: SharedInterruption) -> ManualKeypadEventV2 {
    match case {
        SharedInterruption::Cancelled => ManualKeypadEventV2::Key(SimKey::CancelBack),
        SharedInterruption::OperationFailed => ManualKeypadEventV2::OperationFailed,
        SharedInterruption::MediaRemoved => ManualKeypadEventV2::MediaRemoved,
        SharedInterruption::CardRemoved => ManualKeypadEventV2::CardRemoved,
        SharedInterruption::SessionTimeout => ManualKeypadEventV2::SessionTimeout,
        SharedInterruption::Shutdown => ManualKeypadEventV2::Shutdown,
        SharedInterruption::Restart => ManualKeypadEventV2::Restart,
        SharedInterruption::PowerLoss => ManualKeypadEventV2::PowerLoss,
    }
}

const fn sim_reason(case: SharedInterruption) -> WipingReasonV2 {
    match case {
        SharedInterruption::Cancelled => WipingReasonV2::Cancelled,
        SharedInterruption::OperationFailed => WipingReasonV2::OperationFailed,
        SharedInterruption::MediaRemoved => WipingReasonV2::MediaRemoved,
        SharedInterruption::CardRemoved => WipingReasonV2::CardRemoved,
        SharedInterruption::SessionTimeout => WipingReasonV2::SessionTimeout,
        SharedInterruption::Shutdown => WipingReasonV2::Shutdown,
        SharedInterruption::Restart => WipingReasonV2::Restart,
        SharedInterruption::PowerLoss => WipingReasonV2::PowerLoss,
    }
}

const fn sim_error(case: SharedInterruption) -> ManualKeypadErrorV2 {
    match case {
        SharedInterruption::Cancelled => ManualKeypadErrorV2::Cancelled,
        SharedInterruption::OperationFailed => ManualKeypadErrorV2::OperationFailed,
        SharedInterruption::MediaRemoved => ManualKeypadErrorV2::MediaRemoved,
        SharedInterruption::CardRemoved => ManualKeypadErrorV2::CardRemoved,
        SharedInterruption::SessionTimeout => ManualKeypadErrorV2::SessionTimeout,
        SharedInterruption::Shutdown => ManualKeypadErrorV2::Shutdown,
        SharedInterruption::Restart => ManualKeypadErrorV2::Restart,
        SharedInterruption::PowerLoss => ManualKeypadErrorV2::PowerLoss,
    }
}

#[test]
fn setup_entry_matches_all_eight_frozen_sim_interruption_terminals() {
    for case in INTERRUPTIONS {
        let mut nonce = *b"QKV2S4NONCE1";
        let (mut core, _broker) = core_entry(&mut nonce);
        let mut sim = sim_entry();
        expect_core_stage(
            core.apply_key(CoreKey::One)
                .expect("one retained core face")
                .outcome(),
            SetupStageV2::CeremonyInput,
        );
        sim_apply(&mut sim, ManualKeypadEventV2::Key(SimKey::One));
        assert_eq!(core.retained_counts(), sim.retained_counts());

        let reason = core_reason(case);
        if matches!(case, SharedInterruption::Cancelled) {
            assert!(matches!(
                core.apply_key(CoreKey::CancelBack),
                Err(qk_core::SetupErrorV2::Interrupted(actual)) if actual == reason
            ));
        } else {
            assert_eq!(core.interrupt(reason), Ok(reason));
        }
        let sim_result = sim.apply(sim_event(case));
        assert!(matches!(sim_result, Err(error) if error == sim_error(case)));
        assert_eq!(core.retained_counts(), [0; 4]);
        assert_eq!(sim.retained_counts(), [0; 4]);
        assert!(core.is_terminal());
        assert_eq!(
            core.terminal_error().expect("core terminal error").name(),
            sim_error(case).name()
        );
        assert_eq!(
            sim.terminal(),
            Some(FlowTerminalV2::FailedWiped(sim_reason(case)))
        );
    }
}
