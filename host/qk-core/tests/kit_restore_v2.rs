//! QK-DEC-151 Kit-Restore product-owner behavior over frozen public facts.

use qk_core::{
    CardPresence, CardRemainsStatementV2, CoreDeviceGrants, CoreMode, CoreScreen, CoreSession,
    HumanAssertionDigitV2, Interruption, KeypadKey, KitDoorV2, KitInputModeV2, KitIntakeOutcomeV2,
    KitIntakeSessionV2, KitRestoreActionV2, KitRestoreArtifactV2, KitRestoreDispositionV2,
    KitRestoreErrorV2, KitRestoreForeignOperationV2, KitRestoreSessionV2, KitRestoreStageV2,
    MandatoryFreshWalletMigrationV2, MockCardSlot, MockDisplay, MockKeypad, SurvivingBFactorV2,
    KIT_FALLBACK_TABLE_V2,
};
use qk_io::BrokerSession;
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

fn submit_fallback(intake: &mut KitIntakeSessionV2, symbols: &[u8; 228]) {
    for symbol in symbols {
        let position = KIT_FALLBACK_TABLE_V2
            .iter()
            .flatten()
            .position(|candidate| candidate == symbol)
            .expect("registered fallback symbol");
        let row = numeric_key(u8::try_from(position / 8 + 1).expect("row"));
        let column = numeric_key(u8::try_from(position % 8 + 1).expect("column"));
        assert!(matches!(
            intake.apply_fallback_key(row).expect("row"),
            KitIntakeOutcomeV2::Continue(_)
        ));
        assert!(matches!(
            intake.apply_fallback_key(column).expect("column"),
            KitIntakeOutcomeV2::Continue(_)
        ));
    }
}

fn ready(door: KitDoorV2, mode: KitInputModeV2, order: [u8; 2]) -> qk_core::KitIntakeReadyV2 {
    let mut intake = KitIntakeSessionV2::begin(door, mode);
    match mode {
        KitInputModeV2::Scanner => {
            let mut first = frame(order[0]);
            assert!(matches!(
                intake
                    .submit_scanner_frame(&mut first)
                    .expect("first scanner share"),
                KitIntakeOutcomeV2::FirstShareAccepted(_)
            ));
            assert_eq!(first, [0; 142]);
            let mut second = frame(order[1]);
            let KitIntakeOutcomeV2::Ready(ready) = intake
                .submit_scanner_frame(&mut second)
                .expect("second scanner share")
            else {
                panic!("registered pair releases readiness");
            };
            assert_eq!(second, [0; 142]);
            ready
        }
        KitInputModeV2::Fallback => {
            submit_fallback(&mut intake, &fallback(order[0]));
            assert!(matches!(
                intake
                    .apply_fallback_key(KeypadKey::EqualsConfirmEnter)
                    .expect("first fallback share"),
                KitIntakeOutcomeV2::FirstShareAccepted(_)
            ));
            submit_fallback(&mut intake, &fallback(order[1]));
            let KitIntakeOutcomeV2::Ready(ready) = intake
                .apply_fallback_key(KeypadKey::EqualsConfirmEnter)
                .expect("second fallback share")
            else {
                panic!("registered fallback pair releases readiness");
            };
            ready
        }
    }
}

fn decode_one(bytes: &[u8]) -> ReceivedFrame {
    let mut decoder = StreamDecoder::new();
    let outcome = decoder.ingest(bytes, false).expect("complete QKIP frame");
    assert!(outcome.frame_ready());
    decoder.take_frame().expect("owned QKIP frame")
}

fn ready_core() -> CoreSession {
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
    core
}

fn begin(
    ready: qk_core::KitIntakeReadyV2,
    descriptors: &[[u8; 306]; 2],
    digit: HumanAssertionDigitV2,
) -> Result<KitRestoreSessionV2, KitRestoreErrorV2> {
    let mut core = ready_core();
    KitRestoreSessionV2::begin(&mut core, ready, descriptors, digit)
}

fn session_for(mode: KitInputModeV2, order: [u8; 2], digit: u8) -> KitRestoreSessionV2 {
    begin(
        ready(KitDoorV2::KitRestore, mode, order),
        &descriptors(),
        HumanAssertionDigitV2::new(digit).expect("decimal digit"),
    )
    .expect("registered restore capability")
}

fn session(digit: u8) -> KitRestoreSessionV2 {
    session_for(KitInputModeV2::Scanner, [1, 2], digit)
}

fn surviving_b() -> SurvivingBFactorV2 {
    let mut a2 = hex_array(field(PROVISIONING, "a2_transcript_sha256"));
    let factor = SurvivingBFactorV2::take(wallet_id(), account_xpub_b(), fingerprint_b(), &mut a2);
    assert_eq!(a2, [0; 32]);
    factor
}

fn prepare_replacement(session: &mut KitRestoreSessionV2) {
    assert_eq!(
        session
            .select_action(KitRestoreActionV2::ReplacementB)
            .expect("select replacement")
            .stage(),
        KitRestoreStageV2::CardRemainsConfirmation
    );
    assert_eq!(
        session
            .confirm_card_remains(CardRemainsStatementV2::InHand)
            .expect("old B remains")
            .stage(),
        KitRestoreStageV2::BranchPreparation
    );
    let mut capsule = hex_array(field(PROVISIONING, "a1_capsule_hex"));
    let screen = session
        .prepare_replacement_b(&mut capsule)
        .expect("registered surviving A1");
    assert_eq!(capsule, [0; 67]);
    assert_eq!(screen.stage(), KitRestoreStageV2::HumanAssertion);
}

#[test]
fn exact_restore_readiness_and_exact_old_d_are_required() {
    assert!(matches!(
        begin(
            ready(KitDoorV2::KitSpend, KitInputModeV2::Scanner, [1, 2]),
            &descriptors(),
            HumanAssertionDigitV2::new(0).expect("digit"),
        ),
        Err(KitRestoreErrorV2::WrongDoor)
    ));

    let mut wrong_d = descriptors();
    wrong_d[0][0] ^= 1;
    assert!(matches!(
        begin(
            ready(KitDoorV2::KitRestore, KitInputModeV2::Scanner, [1, 2]),
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
        let session = session_for(mode, order, 4);
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
    let mut restore = session(7);
    prepare_replacement(&mut restore);
    assert_eq!(
        restore.screen().and_then(|screen| screen.assertion_digit()),
        Some(HumanAssertionDigitV2::new(7).expect("digit"))
    );
    let mut calls = 0usize;
    let outcome = restore
        .execute_replacement_b(KeypadKey::Seven, |view| {
            calls += 1;
            assert_eq!(view.wallet_id(), &wallet_id());
            assert_eq!(view.account_xpub(), &account_xpub_b());
            assert_eq!(view.origin_fingerprint(), &fingerprint_b());
            KitRestoreDispositionV2::Accepted
        })
        .expect("one replacement call");
    assert_eq!(calls, 1);
    assert_eq!(outcome.posture(), MandatoryFreshWalletMigrationV2::Required);
    let KitRestoreArtifactV2::ReplacementB(receipt) = outcome.artifact() else {
        panic!("replacement artifact only");
    };
    assert_eq!(receipt.wallet_id(), wallet_id());
    assert_eq!(receipt.account_xpub(), account_xpub_b());
    assert_eq!(receipt.origin_fingerprint(), fingerprint_b());

    let mut missing = session(1);
    missing
        .select_action(KitRestoreActionV2::ReplacementB)
        .expect("select replacement");
    assert_eq!(
        missing
            .confirm_card_remains(CardRemainsStatementV2::Missing)
            .err(),
        Some(KitRestoreErrorV2::MissingCardRequiresKitSpend)
    );
    assert!(missing.is_terminal());
}

#[test]
fn product_bridge_uses_typed_display_keypad_and_one_use_card_boundary() {
    let mut core = ready_core();
    let mut restore = KitRestoreSessionV2::begin(
        &mut core,
        ready(KitDoorV2::KitRestore, KitInputModeV2::Scanner, [1, 2]),
        &descriptors(),
        HumanAssertionDigitV2::new(7).expect("digit"),
    )
    .expect("product restore");
    assert_eq!(
        core.current_screen(),
        Some(CoreScreen::KitRestoreActionSelection)
    );
    restore
        .select_action_in_core(&mut core, KitRestoreActionV2::ReplacementB)
        .expect("replacement action");
    assert_eq!(
        core.current_screen(),
        Some(CoreScreen::CardRemainsConfirmation)
    );
    restore
        .confirm_card_remains_in_core(&mut core, CardRemainsStatementV2::InHand)
        .expect("old card remains");
    let mut capsule = hex_array(field(PROVISIONING, "a1_capsule_hex"));
    restore
        .prepare_replacement_b(&mut capsule)
        .expect("registered surviving A1");
    let outcome = restore
        .execute_replacement_b_in_core(&mut core, KeypadKey::Seven)
        .expect("one qk-core replacement call");
    assert_eq!(outcome.posture(), MandatoryFreshWalletMigrationV2::Required);
    assert_eq!(
        core.current_screen(),
        Some(CoreScreen::MandatoryFreshWalletMigration)
    );
}

#[test]
fn staged_a1_reprint_uses_fresh_nonce_and_consumes_exact_scanback() {
    let mut restore = session(2);
    restore
        .select_action(KitRestoreActionV2::A1Reprint)
        .expect("select reprint");
    let assertion = restore
        .prepare_a1_reprint(surviving_b(), &FRESH_NONCE)
        .expect("surviving B and fresh nonce");
    assert_eq!(
        assertion.assertion_digit(),
        Some(HumanAssertionDigitV2::new(2).expect("digit"))
    );
    let staged = restore
        .begin_a1_reprint(KeypadKey::TwoDown)
        .expect("exact assertion digit");
    let mut scan_back = *staged.capsule().expect("one staged capsule");
    let old = hex_array::<67>(field(PROVISIONING, "a1_capsule_hex"));
    assert_ne!(scan_back, old);
    assert_eq!(&scan_back[..7], b"QKA1\x01\x01\x01");
    assert_eq!(&scan_back[7..19], &FRESH_NONCE);
    let outcome = staged
        .complete_scan_back(&mut scan_back)
        .expect("verified scan-back");
    assert_eq!(scan_back, [0; 67]);
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
fn wrong_digit_print_failure_and_scanback_mismatch_are_terminal_without_retry() {
    let mut wrong_digit = session(6);
    wrong_digit
        .select_action(KitRestoreActionV2::A1Reprint)
        .expect("select reprint");
    wrong_digit
        .prepare_a1_reprint(surviving_b(), &FRESH_NONCE)
        .expect("prepare reprint");
    assert!(matches!(
        wrong_digit.begin_a1_reprint(KeypadKey::Five),
        Err(KitRestoreErrorV2::HumanAssertionMismatch)
    ));

    let mut print_failure = session(6);
    print_failure
        .select_action(KitRestoreActionV2::A1Reprint)
        .expect("select reprint");
    print_failure
        .prepare_a1_reprint(surviving_b(), &FRESH_NONCE)
        .expect("prepare reprint");
    let staged = print_failure
        .begin_a1_reprint(KeypadKey::SixRight)
        .expect("authorize reprint");
    assert_eq!(staged.reject_print(), KitRestoreErrorV2::A1PrintRejected);

    let mut mismatch = session(6);
    mismatch
        .select_action(KitRestoreActionV2::A1Reprint)
        .expect("select reprint");
    mismatch
        .prepare_a1_reprint(surviving_b(), &FRESH_NONCE)
        .expect("prepare reprint");
    let staged = mismatch
        .begin_a1_reprint(KeypadKey::SixRight)
        .expect("authorize reprint");
    let mut scan_back = *staged.capsule().expect("capsule");
    scan_back[31] ^= 1;
    assert_eq!(
        staged.complete_scan_back(&mut scan_back).err(),
        Some(KitRestoreErrorV2::A1VerificationMismatch)
    );
    assert_eq!(scan_back, [0; 67]);
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
        let mut restore = session(0);
        let error = restore
            .reject_foreign_operation(operation)
            .expect_err("foreign operation rejects");
        assert_eq!(error.name(), expected_name);
        assert_eq!(
            restore.select_action(KitRestoreActionV2::A1Reprint).err(),
            Some(KitRestoreErrorV2::Finished)
        );
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
        let mut restore = session(0);
        assert_eq!(
            restore.interrupt(reason).expect_err("interrupts").name(),
            reason.name()
        );
        assert!(restore.is_terminal());
    }

    let result = catch_unwind(AssertUnwindSafe(|| {
        let mut restore = session(3);
        prepare_replacement(&mut restore);
        let _ = restore
            .execute_replacement_b(KeypadKey::Three, |_| panic!("caught mock-boundary unwind"));
    }));
    assert!(result.is_err());
}
