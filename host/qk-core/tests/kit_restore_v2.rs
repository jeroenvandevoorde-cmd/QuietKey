//! QK-DEC-151 Kit-Restore product-owner behavior over frozen public facts.

use qk_core::{
    CardPresence, CardRemainsStatementV2, CoreDeviceGrants, CoreMode, CoreScreen, CoreSession,
    HumanAssertionDigitV2, Interruption, KeypadKey, KitDoorV2, KitInputModeV2, KitIntakeOutcomeV2,
    KitIntakeSessionV2, KitRestoreActionV2, KitRestoreArtifactV2, KitRestoreErrorV2,
    KitRestoreForeignOperationV2, KitRestoreSessionV2, KitRestoreStageV2,
    MandatoryFreshWalletMigrationV2, MockCardSlot, MockDisplay, MockKeypad, SurvivingBFactorV2,
    KIT_FALLBACK_TABLE_V2,
};
use qk_io::{BrokerSession, MockInput, MockOutputWriter, Sink, Source as IoSource};
use qk_ipc::{ReceivedFrame, StreamDecoder};
use std::panic::{catch_unwind, AssertUnwindSafe};

const PROVISIONING: &str = include_str!("../../qk-provisioning/tests/fixtures/provisioning_v2.txt");
const KIT_SHARES: &str = include_str!("../../qk-kit/tests/fixtures/kit_share_v2.txt");
const FRESH_NONCE: [u8; 12] = *b"QKV2S10NEW01";

fn field<'a>(fixture: &'a str, name: &str) -> &'a str {
    fixture
        .lines()
        .find_map(|line| line.strip_prefix(name)?.strip_prefix(": "))
        .unwrap_or_else(|| panic!("missing registered field {name}"))
}

fn hex_array<const N: usize>(value: &str) -> [u8; N] {
    assert_eq!(value.len(), N * 2);
    let mut output = [0u8; N];
    for (slot, pair) in output.iter_mut().zip(value.as_bytes().chunks_exact(2)) {
        let nibble = |byte| match byte {
            b'0'..=b'9' => byte - b'0',
            b'a'..=b'f' => byte - b'a' + 10,
            _ => panic!("registered lowercase hex"),
        };
        *slot = (nibble(pair[0]) << 4) | nibble(pair[1]);
    }
    output
}

fn descriptors() -> [[u8; 306]; 2] {
    [
        field(PROVISIONING, "receive_descriptor")
            .as_bytes()
            .try_into()
            .expect("receive descriptor width"),
        field(PROVISIONING, "change_descriptor")
            .as_bytes()
            .try_into()
            .expect("change descriptor width"),
    ]
}

fn wallet_id() -> [u8; 32] {
    hex_array(field(PROVISIONING, "wallet_id"))
}

fn account_xpub_b() -> [u8; 111] {
    field(PROVISIONING, "role_b_account_xpub")
        .as_bytes()
        .try_into()
        .expect("role-B xpub width")
}

fn fingerprint_b() -> [u8; 4] {
    hex_array(field(PROVISIONING, "role_b_origin_fingerprint"))
}

fn frame(number: u8) -> [u8; 142] {
    match number {
        1 => hex_array(field(KIT_SHARES, "frame_1_hex")),
        2 => hex_array(field(KIT_SHARES, "frame_2_hex")),
        _ => panic!("registered share index"),
    }
}

fn fallback(number: u8) -> [u8; 228] {
    match number {
        1 => field(KIT_SHARES, "fallback_1_ascii"),
        2 => field(KIT_SHARES, "fallback_2_ascii"),
        _ => panic!("registered share index"),
    }
    .as_bytes()
    .try_into()
    .expect("registered fallback width")
}

fn numeric_key(number: u8) -> KeypadKey {
    match number {
        0 => KeypadKey::Zero,
        1 => KeypadKey::One,
        2 => KeypadKey::TwoDown,
        3 => KeypadKey::Three,
        4 => KeypadKey::FourLeft,
        5 => KeypadKey::Five,
        6 => KeypadKey::SixRight,
        7 => KeypadKey::Seven,
        8 => KeypadKey::EightUp,
        9 => KeypadKey::Nine,
        _ => panic!("decimal key"),
    }
}

fn ready(
    core: &mut CoreSession,
    broker: &mut BrokerSession,
    door: KitDoorV2,
    mode: KitInputModeV2,
    order: [u8; 2],
) -> qk_core::KitIntakeReadyV2 {
    let mut intake = KitIntakeSessionV2::begin_in_core(core, door, mode).expect("product intake");
    match mode {
        KitInputModeV2::Scanner => {
            for bytes in [frame(order[0]), frame(order[1])] {
                let mut input =
                    MockInput::try_new(IoSource::CameraKitCandidate, &bytes).expect("input");
                let begin = core
                    .begin_ingress(qk_core::Source::CameraKitCandidate)
                    .expect("begin share");
                let response = broker_reply(broker, &begin, Some(&mut input), None);
                core.receive(response.frame_bytes(), false)
                    .expect("accept begin");
                while core.state() == qk_core::CoreState::IngressReadReady {
                    let read = core.request_next_chunk().expect("read share");
                    let response = broker_reply(broker, &read, None, None);
                    core.receive(response.frame_bytes(), false)
                        .expect("accept chunk");
                }
                if let KitIntakeOutcomeV2::Ready(ready) = intake
                    .submit_scanner_from_core(core)
                    .expect("registered scanner share")
                {
                    return ready;
                }
            }
            panic!("registered pair releases readiness")
        }
        KitInputModeV2::Fallback => {
            for symbols in [fallback(order[0]), fallback(order[1])] {
                for symbol in symbols {
                    let position = KIT_FALLBACK_TABLE_V2
                        .iter()
                        .flatten()
                        .position(|candidate| *candidate == symbol)
                        .expect("registered fallback symbol");
                    for key in [
                        numeric_key(u8::try_from(position / 8 + 1).expect("row")),
                        numeric_key(u8::try_from(position % 8 + 1).expect("column")),
                    ] {
                        intake
                            .apply_fallback_key_from_core(core, key)
                            .expect("fallback coordinate");
                    }
                }
                if let KitIntakeOutcomeV2::Ready(ready) = intake
                    .apply_fallback_key_from_core(core, KeypadKey::EqualsConfirmEnter)
                    .expect("fallback confirmation")
                {
                    return ready;
                }
            }
            panic!("registered fallback pair releases readiness")
        }
    }
}

fn decode_one(bytes: &[u8]) -> ReceivedFrame {
    let mut decoder = StreamDecoder::new();
    let outcome = decoder.ingest(bytes, false).expect("complete QKIP frame");
    assert!(outcome.frame_ready());
    decoder.take_frame().expect("owned QKIP frame")
}

fn ready_core_and_broker() -> (CoreSession, BrokerSession) {
    let grants = CoreDeviceGrants::validate(
        Some(MockDisplay::new()),
        Some(MockKeypad::new()),
        Some(MockCardSlot::new(CardPresence::Present)),
        false,
    )
    .expect("Kit grants");
    let (mut core, opening) = CoreSession::start(CoreMode::Kit, grants).expect("Kit core");
    let mut broker = BrokerSession::new();
    let response = broker
        .accept(&decode_one(opening.frame_bytes()), None, None)
        .expect("session ready");
    core.receive(response.frame_bytes(), false)
        .expect("accept session ready");
    (core, broker)
}

fn broker_reply(
    broker: &mut BrokerSession,
    outbound: &qk_core::CoreOutbound,
    input: Option<&mut MockInput>,
    writer: Option<&mut MockOutputWriter>,
) -> qk_io::BrokerReply {
    broker
        .accept(&decode_one(outbound.frame_bytes()), input, writer)
        .expect("broker accepts exact Kit operation")
}

fn begin(
    door: KitDoorV2,
    mode: KitInputModeV2,
    order: [u8; 2],
    descriptors: &[[u8; 306]; 2],
    digit: HumanAssertionDigitV2,
) -> Result<(KitRestoreSessionV2, CoreSession, BrokerSession), KitRestoreErrorV2> {
    let (mut core, mut broker) = ready_core_and_broker();
    let ready = ready(&mut core, &mut broker, door, mode, order);
    KitRestoreSessionV2::begin(&mut core, ready, descriptors, digit)
        .map(|session| (session, core, broker))
}

fn session_for(
    mode: KitInputModeV2,
    order: [u8; 2],
    digit: u8,
) -> (KitRestoreSessionV2, CoreSession, BrokerSession) {
    begin(
        KitDoorV2::KitRestore,
        mode,
        order,
        &descriptors(),
        HumanAssertionDigitV2::new(digit).expect("decimal digit"),
    )
    .expect("registered restore capability")
}

fn session(digit: u8) -> (KitRestoreSessionV2, CoreSession, BrokerSession) {
    session_for(KitInputModeV2::Scanner, [1, 2], digit)
}

fn surviving_b() -> SurvivingBFactorV2 {
    let mut a2 = hex_array(field(PROVISIONING, "a2_transcript_sha256"));
    let factor = SurvivingBFactorV2::take(wallet_id(), account_xpub_b(), fingerprint_b(), &mut a2);
    assert_eq!(a2, [0; 32]);
    factor
}

fn prepare_replacement(
    session: &mut KitRestoreSessionV2,
    core: &mut CoreSession,
    broker: &mut BrokerSession,
) {
    assert_eq!(
        session
            .select_action_in_core(core, KitRestoreActionV2::ReplacementB)
            .expect("select replacement")
            .stage(),
        KitRestoreStageV2::CardRemainsConfirmation
    );
    assert_eq!(
        core.current_screen(),
        Some(CoreScreen::CardRemainsConfirmation)
    );
    assert_eq!(
        session
            .confirm_card_remains_in_core(core, CardRemainsStatementV2::InHand)
            .expect("old B remains")
            .stage(),
        KitRestoreStageV2::BranchPreparation
    );
    assert_eq!(
        core.current_screen(),
        Some(CoreScreen::KitRestorePreparation)
    );
    let capsule = hex_array::<67>(field(PROVISIONING, "a1_capsule_hex"));
    let mut input = MockInput::try_new(IoSource::CameraA1Candidate, &capsule).expect("A1 input");
    let begin = core
        .begin_ingress(qk_core::Source::CameraA1Candidate)
        .expect("begin surviving A1");
    let response = broker_reply(broker, &begin, Some(&mut input), None);
    core.receive(response.frame_bytes(), false)
        .expect("accept A1 begin");
    while core.state() == qk_core::CoreState::IngressReadReady {
        let read = core.request_next_chunk().expect("read surviving A1");
        let response = broker_reply(broker, &read, None, None);
        core.receive(response.frame_bytes(), false)
            .expect("accept A1 chunk");
    }
    let screen = session
        .prepare_replacement_b_from_core(core)
        .expect("registered surviving A1");
    assert_eq!(screen.stage(), KitRestoreStageV2::HumanAssertion);
    assert_eq!(
        core.current_screen(),
        Some(CoreScreen::KitRestoreHumanAssertion)
    );
}

#[test]
fn exact_restore_readiness_and_exact_old_d_are_required() {
    assert!(matches!(
        begin(
            KitDoorV2::KitSpend,
            KitInputModeV2::Scanner,
            [1, 2],
            &descriptors(),
            HumanAssertionDigitV2::new(0).expect("digit"),
        ),
        Err(KitRestoreErrorV2::WrongDoor)
    ));

    let mut wrong_d = descriptors();
    wrong_d[0][0] ^= 1;
    assert!(matches!(
        begin(
            KitDoorV2::KitRestore,
            KitInputModeV2::Scanner,
            [1, 2],
            &wrong_d,
            HumanAssertionDigitV2::new(0).expect("digit"),
        ),
        Err(KitRestoreErrorV2::RecoveredWalletMismatch)
    ));
    assert_eq!(
        HumanAssertionDigitV2::new(10).err(),
        Some(KitRestoreErrorV2::InvalidHumanAssertionDigit)
    );

    for (mode, order) in [
        (KitInputModeV2::Scanner, [1, 2]),
        (KitInputModeV2::Scanner, [2, 1]),
        (KitInputModeV2::Fallback, [1, 2]),
        (KitInputModeV2::Fallback, [2, 1]),
    ] {
        let (session, _core, _broker) = session_for(mode, order, 4);
        let screen = session.screen().expect("active screen");
        assert_eq!(screen.stage(), KitRestoreStageV2::ActionSelection);
        assert_eq!(screen.wallet_id(), wallet_id());
        assert_eq!(screen.input_mode(), mode);
        assert_eq!(screen.assertion_digit(), None);
        assert_eq!(
            session
                .frame_identities()
                .map(|identity| identity.share_index().as_u8()),
            order
        );
    }
}

#[test]
fn replacement_b_requires_remains_factor_and_exact_digit_before_one_call() {
    let (mut restore, mut core, mut broker) = session(7);
    prepare_replacement(&mut restore, &mut core, &mut broker);
    assert_eq!(
        restore.screen().and_then(|screen| screen.assertion_digit()),
        Some(HumanAssertionDigitV2::new(7).expect("digit"))
    );
    let outcome = restore
        .execute_replacement_b_in_core(&mut core, KeypadKey::Seven)
        .expect("one replacement call");
    assert_eq!(core.state(), qk_core::CoreState::Closed);
    assert_eq!(outcome.posture(), MandatoryFreshWalletMigrationV2::Required);
    let KitRestoreArtifactV2::ReplacementB(receipt) = outcome.artifact() else {
        panic!("replacement artifact only");
    };
    assert_eq!(receipt.wallet_id(), wallet_id());
    assert_eq!(receipt.account_xpub(), account_xpub_b());
    assert_eq!(receipt.origin_fingerprint(), fingerprint_b());

    let (mut missing, mut missing_core, _broker) = session(1);
    missing
        .select_action_in_core(&mut missing_core, KitRestoreActionV2::ReplacementB)
        .expect("select replacement");
    assert_eq!(
        missing
            .confirm_card_remains_in_core(&mut missing_core, CardRemainsStatementV2::Missing,)
            .err(),
        Some(KitRestoreErrorV2::MissingCardRequiresKitSpend)
    );
    assert!(missing.is_terminal());
}

#[test]
fn product_bridge_uses_typed_display_keypad_and_one_use_card_boundary() {
    let (mut core, mut broker) = ready_core_and_broker();
    let ready = ready(
        &mut core,
        &mut broker,
        KitDoorV2::KitRestore,
        KitInputModeV2::Scanner,
        [1, 2],
    );
    let mut restore = KitRestoreSessionV2::begin(
        &mut core,
        ready,
        &descriptors(),
        HumanAssertionDigitV2::new(7).expect("digit"),
    )
    .expect("product restore");
    assert_eq!(
        core.current_screen(),
        Some(CoreScreen::KitRestoreActionSelection)
    );
    prepare_replacement(&mut restore, &mut core, &mut broker);
    assert_eq!(
        core.current_screen(),
        Some(CoreScreen::KitRestoreHumanAssertion)
    );
    let outcome = restore
        .execute_replacement_b_in_core(&mut core, KeypadKey::Seven)
        .expect("one qk-core replacement call");
    assert_eq!(outcome.posture(), MandatoryFreshWalletMigrationV2::Required);
    assert_eq!(core.state(), qk_core::CoreState::Closed);
    assert_eq!(
        core.current_screen(),
        Some(CoreScreen::MandatoryFreshWalletMigration)
    );
}

#[test]
fn staged_a1_reprint_uses_fresh_nonce_and_consumes_exact_scanback() {
    let (mut restore, mut core, mut broker) = session(2);
    restore
        .select_action_in_core(&mut core, KitRestoreActionV2::A1Reprint)
        .expect("select reprint");
    let assertion = restore
        .prepare_a1_reprint_in_core(&mut core, surviving_b(), &FRESH_NONCE)
        .expect("surviving B and fresh nonce");
    assert_eq!(
        assertion.assertion_digit(),
        Some(HumanAssertionDigitV2::new(2).expect("digit"))
    );
    let mut staged = restore
        .begin_a1_reprint_in_core(&mut core, KeypadKey::TwoDown)
        .expect("exact assertion digit");
    let a2 = hex_array::<32>(field(PROVISIONING, "a2_transcript_sha256"));
    let seed_a = hex_array::<32>(field(PROVISIONING, "seed_a_transcript_sha256"));
    let expected = qk_a1::encrypt(&a2, &wallet_id(), &FRESH_NONCE, &seed_a);
    let mut outbound = staged.begin_print(&mut core).expect("print begin");
    let reply = broker_reply(&mut broker, &outbound, None, None);
    core.receive(reply.frame_bytes(), false)
        .expect("begin receipt");
    outbound = staged.write_print(&mut core).expect("print write");
    let reply = broker_reply(&mut broker, &outbound, None, None);
    core.receive(reply.frame_bytes(), false)
        .expect("write receipt");
    outbound = staged.finish_print(&mut core).expect("print finish");
    let mut writer = MockOutputWriter::new(Sink::Print);
    let reply = broker_reply(&mut broker, &outbound, None, Some(&mut writer));
    core.receive(reply.frame_bytes(), false)
        .expect("finish receipt");
    assert_eq!(writer.final_bytes(), Some(expected.as_slice()));
    let old = hex_array::<67>(field(PROVISIONING, "a1_capsule_hex"));
    assert_ne!(expected, old);
    assert_eq!(&expected[..7], b"QKA1\x01\x01\x01");
    assert_eq!(&expected[7..19], &FRESH_NONCE);
    outbound = staged.begin_scan_back(&mut core).expect("scan begin");
    let mut scan = MockInput::try_new(IoSource::CameraA1Candidate, &expected).expect("scan");
    let reply = broker_reply(&mut broker, &outbound, Some(&mut scan), None);
    core.receive(reply.frame_bytes(), false)
        .expect("scan begin receipt");
    outbound = staged.request_scan_back(&mut core).expect("scan read");
    let reply = broker_reply(&mut broker, &outbound, None, None);
    core.receive(reply.frame_bytes(), false)
        .expect("scan read receipt");
    let outcome = staged
        .complete_from_core(&mut core)
        .expect("verified scan-back");
    assert_eq!(core.state(), qk_core::CoreState::Closed);
    assert_eq!(outcome.posture(), MandatoryFreshWalletMigrationV2::Required);
    let KitRestoreArtifactV2::A1Reprint(receipt) = outcome.artifact() else {
        panic!("A1 reprint artifact only");
    };
    assert_eq!(receipt.wallet_id(), wallet_id());
    assert_eq!(receipt.nonce(), FRESH_NONCE);
    assert_eq!(
        receipt.capsule_sha256(),
        hex_array("ea4aed0ce7a38dab3cb95f1887d0b0d3268fa54f277c458017136a7dc69b927c")
    );
}

#[test]
fn product_a1_reprint_drives_exact_print_and_source_01_scanback() {
    let (mut core, mut broker) = ready_core_and_broker();
    let ready = ready(
        &mut core,
        &mut broker,
        KitDoorV2::KitRestore,
        KitInputModeV2::Scanner,
        [1, 2],
    );
    let mut restore = KitRestoreSessionV2::begin(
        &mut core,
        ready,
        &descriptors(),
        HumanAssertionDigitV2::new(2).expect("digit"),
    )
    .expect("product restore");
    restore
        .select_action_in_core(&mut core, KitRestoreActionV2::A1Reprint)
        .expect("select reprint");
    restore
        .prepare_a1_reprint_in_core(&mut core, surviving_b(), &FRESH_NONCE)
        .expect("prepare reprint");
    let mut staged = restore
        .begin_a1_reprint_in_core(&mut core, KeypadKey::TwoDown)
        .expect("authorize reprint");

    let a2 = hex_array::<32>(field(PROVISIONING, "a2_transcript_sha256"));
    let seed_a = hex_array::<32>(field(PROVISIONING, "seed_a_transcript_sha256"));
    let expected = qk_a1::encrypt(&a2, &wallet_id(), &FRESH_NONCE, &seed_a);

    let mut outbound = staged.begin_print(&mut core).expect("print begin");
    let reply = broker_reply(&mut broker, &outbound, None, None);
    core.receive(reply.frame_bytes(), false)
        .expect("print begin receipt");
    outbound = staged.write_print(&mut core).expect("one capsule write");
    let reply = broker_reply(&mut broker, &outbound, None, None);
    core.receive(reply.frame_bytes(), false)
        .expect("print write receipt");
    outbound = staged.finish_print(&mut core).expect("print finish");
    let mut writer = MockOutputWriter::new(Sink::Print);
    let reply = broker_reply(&mut broker, &outbound, None, Some(&mut writer));
    core.receive(reply.frame_bytes(), false)
        .expect("print finish receipt");
    assert_eq!(writer.final_bytes(), Some(expected.as_slice()));

    outbound = staged
        .begin_scan_back(&mut core)
        .expect("source-01 scan begin");
    let mut scan = MockInput::try_new(IoSource::CameraA1Candidate, &expected)
        .expect("exact source-01 candidate");
    let reply = broker_reply(&mut broker, &outbound, Some(&mut scan), None);
    core.receive(reply.frame_bytes(), false)
        .expect("scan begin receipt");
    outbound = staged.request_scan_back(&mut core).expect("sole scan read");
    let reply = broker_reply(&mut broker, &outbound, None, None);
    core.receive(reply.frame_bytes(), false)
        .expect("scan read receipt");
    let outcome = staged
        .complete_from_core(&mut core)
        .expect("authenticated scan-back");
    assert_eq!(outcome.posture(), MandatoryFreshWalletMigrationV2::Required);
    assert_eq!(core.state(), qk_core::CoreState::Closed);
    assert_eq!(
        core.current_screen(),
        Some(CoreScreen::MandatoryFreshWalletMigration)
    );
}

#[test]
fn wrong_digit_print_failure_and_scanback_mismatch_are_terminal_without_retry() {
    let (mut wrong_digit, mut wrong_core, _broker) = session(6);
    wrong_digit
        .select_action_in_core(&mut wrong_core, KitRestoreActionV2::A1Reprint)
        .expect("select reprint");
    wrong_digit
        .prepare_a1_reprint_in_core(&mut wrong_core, surviving_b(), &FRESH_NONCE)
        .expect("prepare reprint");
    assert!(matches!(
        wrong_digit.begin_a1_reprint_in_core(&mut wrong_core, KeypadKey::Five),
        Err(KitRestoreErrorV2::HumanAssertionMismatch)
    ));

    let (mut print_failure, mut print_core, _broker) = session(6);
    print_failure
        .select_action_in_core(&mut print_core, KitRestoreActionV2::A1Reprint)
        .expect("select reprint");
    print_failure
        .prepare_a1_reprint_in_core(&mut print_core, surviving_b(), &FRESH_NONCE)
        .expect("prepare reprint");
    let mut staged = print_failure
        .begin_a1_reprint_in_core(&mut print_core, KeypadKey::SixRight)
        .expect("authorize reprint");
    assert_eq!(
        staged.write_print(&mut print_core).err(),
        Some(KitRestoreErrorV2::A1PrintRejected)
    );

    let (mut mismatch, mut mismatch_core, mut mismatch_broker) = session(6);
    mismatch
        .select_action_in_core(&mut mismatch_core, KitRestoreActionV2::A1Reprint)
        .expect("select reprint");
    mismatch
        .prepare_a1_reprint_in_core(&mut mismatch_core, surviving_b(), &FRESH_NONCE)
        .expect("prepare reprint");
    let mut staged = mismatch
        .begin_a1_reprint_in_core(&mut mismatch_core, KeypadKey::SixRight)
        .expect("authorize reprint");
    let a2 = hex_array::<32>(field(PROVISIONING, "a2_transcript_sha256"));
    let seed_a = hex_array::<32>(field(PROVISIONING, "seed_a_transcript_sha256"));
    let mut scan_back = qk_a1::encrypt(&a2, &wallet_id(), &FRESH_NONCE, &seed_a);
    let mut outbound = staged.begin_print(&mut mismatch_core).expect("print begin");
    let reply = broker_reply(&mut mismatch_broker, &outbound, None, None);
    mismatch_core
        .receive(reply.frame_bytes(), false)
        .expect("begin receipt");
    outbound = staged.write_print(&mut mismatch_core).expect("print write");
    let reply = broker_reply(&mut mismatch_broker, &outbound, None, None);
    mismatch_core
        .receive(reply.frame_bytes(), false)
        .expect("write receipt");
    outbound = staged
        .finish_print(&mut mismatch_core)
        .expect("print finish");
    let mut writer = MockOutputWriter::new(Sink::Print);
    let reply = broker_reply(&mut mismatch_broker, &outbound, None, Some(&mut writer));
    mismatch_core
        .receive(reply.frame_bytes(), false)
        .expect("finish receipt");
    outbound = staged
        .begin_scan_back(&mut mismatch_core)
        .expect("scan begin");
    scan_back[31] ^= 1;
    let mut scan = MockInput::try_new(IoSource::CameraA1Candidate, &scan_back).expect("scan");
    let reply = broker_reply(&mut mismatch_broker, &outbound, Some(&mut scan), None);
    mismatch_core
        .receive(reply.frame_bytes(), false)
        .expect("scan begin receipt");
    outbound = staged
        .request_scan_back(&mut mismatch_core)
        .expect("scan read");
    let reply = broker_reply(&mut mismatch_broker, &outbound, None, None);
    mismatch_core
        .receive(reply.frame_bytes(), false)
        .expect("scan read receipt");
    assert_eq!(
        staged.complete_from_core(&mut mismatch_core).err(),
        Some(KitRestoreErrorV2::A1VerificationMismatch)
    );

    let (mut core, mut broker) = ready_core_and_broker();
    let ready = ready(
        &mut core,
        &mut broker,
        KitDoorV2::KitRestore,
        KitInputModeV2::Scanner,
        [1, 2],
    );
    let mut wrong_order = KitRestoreSessionV2::begin(
        &mut core,
        ready,
        &descriptors(),
        HumanAssertionDigitV2::new(6).expect("digit"),
    )
    .expect("product restore");
    wrong_order
        .select_action_in_core(&mut core, KitRestoreActionV2::A1Reprint)
        .expect("select reprint");
    wrong_order
        .prepare_a1_reprint_in_core(&mut core, surviving_b(), &FRESH_NONCE)
        .expect("prepare reprint");
    let mut staged = wrong_order
        .begin_a1_reprint_in_core(&mut core, KeypadKey::SixRight)
        .expect("authorize reprint");
    assert_eq!(
        staged.write_print(&mut core).err(),
        Some(KitRestoreErrorV2::A1PrintRejected)
    );
    assert_eq!(
        staged.begin_print(&mut core).err(),
        Some(KitRestoreErrorV2::A1PrintRejected)
    );
}

#[test]
fn foreign_operations_interruptions_and_unwind_never_create_a_second_action() {
    let foreign = [
        (KitRestoreForeignOperationV2::Signing, "SigningProhibited"),
        (
            KitRestoreForeignOperationV2::Transaction,
            "TransactionProhibited",
        ),
        (KitRestoreForeignOperationV2::Review, "ReviewProhibited"),
        (KitRestoreForeignOperationV2::Approval, "ApprovalProhibited"),
        (KitRestoreForeignOperationV2::Export, "ExportProhibited"),
        (
            KitRestoreForeignOperationV2::Intake,
            "ForeignInputProhibited",
        ),
        (
            KitRestoreForeignOperationV2::GenericWalletOutput,
            "GenericWalletOutputProhibited",
        ),
        (
            KitRestoreForeignOperationV2::KitGeneration,
            "KitGenerationProhibited",
        ),
        (
            KitRestoreForeignOperationV2::KitRegeneration,
            "KitRegenerationProhibited",
        ),
        (
            KitRestoreForeignOperationV2::DoorSwitch,
            "DoorSwitchAttempt",
        ),
    ];
    for (operation, expected_name) in foreign {
        let (mut restore, mut core, _broker) = session(0);
        let error = restore
            .reject_foreign_operation_in_core(&mut core, operation)
            .expect_err("foreign operation rejects");
        assert_eq!(error.name(), expected_name);
        assert!(restore.is_terminal());
        assert_eq!(core.state(), qk_core::CoreState::Terminated);
    }

    for reason in [
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
    ] {
        let (mut restore, mut core, _broker) = session(0);
        assert_eq!(
            restore
                .interrupt_in_core(&mut core, reason)
                .expect_err("interrupts")
                .name(),
            reason.name()
        );
        assert!(restore.is_terminal());
        assert_eq!(core.state(), qk_core::CoreState::Terminated);
        assert_eq!(core.terminal_reason(), Some(reason));
    }

    let result = catch_unwind(AssertUnwindSafe(|| {
        let (mut restore, mut core, mut broker) = session(3);
        prepare_replacement(&mut restore, &mut core, &mut broker);
        let _restore = restore;
        panic!("caught restore-owner unwind");
    }));
    assert!(result.is_err());
}

#[test]
fn foreign_restore_rejection_clears_pending_a1_ingress() {
    let (mut restore, mut core, mut broker) = session(0);
    restore
        .select_action_in_core(&mut core, KitRestoreActionV2::ReplacementB)
        .expect("select replacement");
    restore
        .confirm_card_remains_in_core(&mut core, CardRemainsStatementV2::InHand)
        .expect("old card remains");

    let capsule = hex_array::<67>(field(PROVISIONING, "a1_capsule_hex"));
    let mut input = MockInput::try_new(IoSource::CameraA1Candidate, &capsule).expect("A1 input");
    let begin = core
        .begin_ingress(qk_core::Source::CameraA1Candidate)
        .expect("begin surviving A1");
    let response = broker_reply(&mut broker, &begin, Some(&mut input), None);
    core.receive(response.frame_bytes(), false)
        .expect("accept A1 begin");
    while core.state() == qk_core::CoreState::IngressReadReady {
        let read = core.request_next_chunk().expect("read surviving A1");
        let response = broker_reply(&mut broker, &read, None, None);
        core.receive(response.frame_bytes(), false)
            .expect("accept A1 chunk");
    }
    assert!(core.completed_ingress().is_some());

    assert_eq!(
        restore
            .reject_foreign_operation_in_core(&mut core, KitRestoreForeignOperationV2::Signing,)
            .err(),
        Some(KitRestoreErrorV2::SigningProhibited)
    );
    assert_eq!(core.state(), qk_core::CoreState::Terminated);
    assert!(core.completed_ingress().is_none());
}
