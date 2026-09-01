#![no_main]

use libfuzzer_sys::fuzz_target;
use qk_core::fuzz::{fuzz_start_session, reset_wiped_bytes, wiped_bytes};
use qk_core::{
    AuthorizedA1ReprintV2, CardPresence, CardRemainsStatementV2, CoreDeviceGrants, CoreError,
    CoreMode, CoreOutbound, CoreReceiveEvent, CoreScreen, CoreSession, CoreState,
    HumanAssertionDigitV2, Interruption, KIT_FALLBACK_TABLE_V2, KeypadKey, KitDoorV2,
    KitInputModeV2, KitIntakeOutcomeV2, KitIntakeSessionV2, KitRestoreActionV2,
    KitRestoreArtifactV2, KitRestoreDispositionV2, KitRestoreErrorV2, KitRestoreForeignOperationV2,
    KitRestoreSessionV2, MandatoryFreshWalletMigrationV2, MockCardSlot, MockDisplay, MockKeypad,
    Source, SurvivingBFactorV2,
};
use qk_ipc::{Direction, HEADER_BYTES, MessageKind, encode_frame, parse_frame};

const MAX_PRESENTED_BYTES: usize = 512;
const NAMESPACE: [u8; 12] = *b"QKS7RESTORE1";
const FRESH_NONCE: [u8; 12] = *b"QKV2S10NEW01";
const PROVISIONING: &str =
    include_str!("../../host/qk-provisioning/tests/fixtures/provisioning_v2.txt");
const SHARES: &str = include_str!("../../host/qk-kit/tests/fixtures/kit_share_v2.txt");
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

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct Fact {
    error: Option<&'static str>,
    success: u8,
    wiped: usize,
}

fn field<'a>(fixture: &'a str, name: &str) -> &'a str {
    fixture
        .lines()
        .find_map(|line| line.strip_prefix(name)?.strip_prefix(": "))
        .expect("registered fixture field")
}

fn nibble(value: u8) -> u8 {
    match value {
        b'0'..=b'9' => value - b'0',
        b'a'..=b'f' => value - b'a' + 10,
        _ => panic!("registered lowercase hex"),
    }
}

#[allow(clippy::chunks_exact_to_as_chunks)]
fn hex_array<const N: usize>(value: &str) -> [u8; N] {
    assert_eq!(value.len(), N * 2);
    let mut output = [0u8; N];
    for (slot, pair) in output.iter_mut().zip(value.as_bytes().chunks_exact(2)) {
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

fn grants() -> CoreDeviceGrants {
    CoreDeviceGrants::validate(
        Some(MockDisplay::new()),
        Some(MockKeypad::new()),
        Some(MockCardSlot::new(CardPresence::Present)),
        false,
    )
    .expect("complete Kit capability set")
}

fn outer_payload(outbound: &CoreOutbound) -> &[u8] {
    parse_frame(outbound.frame_bytes())
        .expect("qk-core emitted canonical QKIP")
        .payload()
}

fn response(request: &CoreOutbound, kind: MessageKind, payload: &[u8]) -> Vec<u8> {
    let request = parse_frame(request.frame_bytes()).expect("qk-core emitted canonical QKIP");
    let mut output = vec![0u8; HEADER_BYTES + payload.len()];
    let written = encode_frame(
        Direction::IoToCore,
        kind,
        *request.header().session_id(),
        request.header().exchange_id(),
        payload,
        &mut output,
    )
    .expect("bounded canonical peer response");
    assert_eq!(written, output.len());
    output
}

fn inner_success(opcode: u8, body: &[u8]) -> Vec<u8> {
    let mut payload = Vec::with_capacity(8 + body.len());
    payload.extend_from_slice(&[1, opcode, 0, 0]);
    payload.extend_from_slice(&(body.len() as u32).to_le_bytes());
    payload.extend_from_slice(body);
    payload
}

fn operation_response(request: &CoreOutbound, opcode: u8, body: &[u8]) -> Vec<u8> {
    response(
        request,
        MessageKind::OperationResponse,
        &inner_success(opcode, body),
    )
}

fn open_core(counter: u32) -> CoreSession {
    let (mut core, opening) =
        fuzz_start_session(NAMESPACE, counter, CoreMode::Kit, grants()).expect("Kit core start");
    assert!(outer_payload(&opening).is_empty());
    let ready = response(&opening, MessageKind::SessionReady, &[]);
    let outcome = core
        .receive(&ready, false)
        .expect("canonical session ready");
    assert_eq!(outcome.consumed(), ready.len());
    assert_eq!(outcome.event(), CoreReceiveEvent::SessionReady);
    assert_eq!(core.state(), CoreState::Ready);
    core
}

fn load_ingress(core: &mut CoreSession, source: Source, bytes: &[u8]) {
    let begin = core.begin_ingress(source).expect("begin hostile ingress");
    assert_eq!(
        outer_payload(&begin),
        [1, 1, 0, 0, 3, 0, 0, 0, source.wire_value(), 0, 0]
    );
    let mut begin_body = Vec::with_capacity(5);
    begin_body.push(source.wire_value());
    begin_body.extend_from_slice(&(bytes.len() as u32).to_le_bytes());
    let began = operation_response(&begin, 1, &begin_body);
    assert_eq!(
        core.receive(&began, false)
            .expect("canonical ingress-begin response")
            .event(),
        CoreReceiveEvent::IngressBegan {
            source,
            total_len: bytes.len() as u32,
        }
    );
    let read = core
        .request_next_chunk()
        .expect("request exact ingress chunk");
    assert_eq!(outer_payload(&read), [1, 2, 0, 0, 4, 0, 0, 0, 0, 0, 0, 0]);
    let mut read_body = Vec::with_capacity(9 + bytes.len());
    read_body.extend_from_slice(&0u32.to_le_bytes());
    read_body.extend_from_slice(&(bytes.len() as u32).to_le_bytes());
    read_body.push(1);
    read_body.extend_from_slice(bytes);
    let read_response = operation_response(&read, 2, &read_body);
    assert_eq!(
        core.receive(&read_response, false)
            .expect("canonical ingress-read response")
            .event(),
        CoreReceiveEvent::IngressChunk {
            offset: 0,
            chunk_len: bytes.len() as u32,
            final_chunk: true,
        }
    );
    assert_eq!(core.state(), CoreState::IngressComplete);
}

fn assert_core_absorbing(core: &mut CoreSession) {
    assert_eq!(core.state(), CoreState::Terminated);
    assert_eq!(
        core.begin_ingress(Source::CameraA1Candidate).err(),
        Some(CoreError::CoreTerminated)
    );
    assert_eq!(
        core.request_next_chunk().err(),
        Some(CoreError::CoreTerminated)
    );
    assert_eq!(core.begin_close().err(), Some(CoreError::CoreTerminated));
    assert_eq!(
        core.receive(&[], false).err(),
        Some(CoreError::CoreTerminated)
    );
    assert_eq!(
        core.interrupt(Interruption::Shutdown).err(),
        Some(CoreError::CoreTerminated)
    );
    assert_eq!(
        core.handle_key(KeypadKey::One).err(),
        Some(CoreError::CoreTerminated)
    );
    assert_eq!(
        core.observe_card(CardPresence::Present).err(),
        Some(CoreError::CoreTerminated)
    );
}

fn key(digit: u8) -> KeypadKey {
    match digit {
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
        _ => panic!("bounded decimal key"),
    }
}

fn error_name(error: KitRestoreErrorV2) -> &'static str {
    let name = match error {
        KitRestoreErrorV2::InvalidHumanAssertionDigit => "InvalidHumanAssertionDigit",
        KitRestoreErrorV2::WrongDoor => "WrongDoor",
        KitRestoreErrorV2::InvalidStart => "InvalidStart",
        KitRestoreErrorV2::RecoveredWalletMismatch => "RecoveredWalletMismatch",
        KitRestoreErrorV2::InvalidTransition => "InvalidTransition",
        KitRestoreErrorV2::ActionSwitchAttempt => "ActionSwitchAttempt",
        KitRestoreErrorV2::DoorSwitchAttempt => "DoorSwitchAttempt",
        KitRestoreErrorV2::RestoreModeMismatch => "RestoreModeMismatch",
        KitRestoreErrorV2::TransactionProhibited => "TransactionProhibited",
        KitRestoreErrorV2::ReviewProhibited => "ReviewProhibited",
        KitRestoreErrorV2::ApprovalProhibited => "ApprovalProhibited",
        KitRestoreErrorV2::ExportProhibited => "ExportProhibited",
        KitRestoreErrorV2::ForeignInputProhibited => "ForeignInputProhibited",
        KitRestoreErrorV2::GenericWalletOutputProhibited => "GenericWalletOutputProhibited",
        KitRestoreErrorV2::KitGenerationProhibited => "KitGenerationProhibited",
        KitRestoreErrorV2::MissingCardRequiresKitSpend => "MissingCardRequiresKitSpend",
        KitRestoreErrorV2::HumanAssertionMismatch => "HumanAssertionMismatch",
        KitRestoreErrorV2::SurvivingA1Mismatch => "SurvivingA1Mismatch",
        KitRestoreErrorV2::SurvivingBFactorMismatch => "SurvivingBFactorMismatch",
        KitRestoreErrorV2::A1PrintRejected => "A1PrintRejected",
        KitRestoreErrorV2::A1VerificationMismatch => "A1VerificationMismatch",
        KitRestoreErrorV2::ReplacementBRejected => "ReplacementBRejected",
        KitRestoreErrorV2::SigningProhibited => "SigningProhibited",
        KitRestoreErrorV2::KitRegenerationProhibited => "KitRegenerationProhibited",
        KitRestoreErrorV2::Interrupted(reason) => reason.name(),
        KitRestoreErrorV2::Finished => "Finished",
    };
    assert_eq!(error.name(), name);
    assert_eq!(error.to_string(), name);
    name
}

fn coordinate_key(number: usize) -> KeypadKey {
    key(u8::try_from(number).expect("bounded coordinate"))
}

fn enter_fallback(intake: &mut KitIntakeSessionV2, symbols: &[u8; 228]) {
    for symbol in symbols {
        let position = KIT_FALLBACK_TABLE_V2
            .iter()
            .flatten()
            .position(|candidate| candidate == symbol)
            .expect("registered fallback symbol");
        assert!(matches!(
            intake.apply_fallback_key(coordinate_key(position / 8 + 1)),
            Ok(KitIntakeOutcomeV2::Continue(_))
        ));
        assert!(matches!(
            intake.apply_fallback_key(coordinate_key(position % 8 + 1)),
            Ok(KitIntakeOutcomeV2::Continue(_))
        ));
    }
}

fn ready(mode: KitInputModeV2, reversed: bool, door: KitDoorV2) -> qk_core::KitIntakeReadyV2 {
    let mut intake = KitIntakeSessionV2::begin(door, mode);
    match mode {
        KitInputModeV2::Scanner => {
            let mut one = hex_array::<142>(field(SHARES, "frame_1_hex"));
            let mut two = hex_array::<142>(field(SHARES, "frame_2_hex"));
            let (first, second) = if reversed {
                (&mut two, &mut one)
            } else {
                (&mut one, &mut two)
            };
            assert!(matches!(
                intake.submit_scanner_frame(first),
                Ok(KitIntakeOutcomeV2::FirstShareAccepted(_))
            ));
            let outcome = intake
                .submit_scanner_frame(second)
                .expect("registered second frame");
            let KitIntakeOutcomeV2::Ready(ready) = outcome else {
                panic!("registered pair must release readiness");
            };
            ready
        }
        KitInputModeV2::Fallback => {
            let one: &[u8; 228] = field(SHARES, "fallback_1_ascii")
                .as_bytes()
                .try_into()
                .expect("fallback one width");
            let two: &[u8; 228] = field(SHARES, "fallback_2_ascii")
                .as_bytes()
                .try_into()
                .expect("fallback two width");
            let (first, second) = if reversed { (two, one) } else { (one, two) };
            enter_fallback(&mut intake, first);
            assert!(matches!(
                intake.apply_fallback_key(KeypadKey::EqualsConfirmEnter),
                Ok(KitIntakeOutcomeV2::FirstShareAccepted(_))
            ));
            enter_fallback(&mut intake, second);
            let outcome = intake
                .apply_fallback_key(KeypadKey::EqualsConfirmEnter)
                .expect("registered second fallback");
            let KitIntakeOutcomeV2::Ready(ready) = outcome else {
                panic!("registered fallback pair must release readiness");
            };
            ready
        }
    }
}

fn enter_fallback_in_core(
    intake: &mut KitIntakeSessionV2,
    core: &mut CoreSession,
    symbols: &[u8; 228],
) {
    for symbol in symbols {
        let position = KIT_FALLBACK_TABLE_V2
            .iter()
            .flatten()
            .position(|candidate| candidate == symbol)
            .expect("registered fallback symbol");
        assert!(matches!(
            intake.apply_fallback_key_from_core(core, coordinate_key(position / 8 + 1)),
            Ok(KitIntakeOutcomeV2::Continue(_))
        ));
        assert!(matches!(
            intake.apply_fallback_key_from_core(core, coordinate_key(position % 8 + 1)),
            Ok(KitIntakeOutcomeV2::Continue(_))
        ));
    }
}

fn ready_in_core(
    core: &mut CoreSession,
    mode: KitInputModeV2,
    reversed: bool,
) -> qk_core::KitIntakeReadyV2 {
    let order = if reversed { [2u8, 1u8] } else { [1, 2] };
    let mut intake = KitIntakeSessionV2::begin_in_core(core, KitDoorV2::KitRestore, mode)
        .expect("typed Kit-Restore intake");
    assert_eq!(core.current_screen(), Some(CoreScreen::ScanKitShareOne));
    let outcome = match mode {
        KitInputModeV2::Scanner => {
            let first = hex_array::<142>(field(
                SHARES,
                if order[0] == 1 {
                    "frame_1_hex"
                } else {
                    "frame_2_hex"
                },
            ));
            load_ingress(core, Source::CameraKitCandidate, &first);
            assert!(matches!(
                intake.submit_scanner_from_core(core),
                Ok(KitIntakeOutcomeV2::FirstShareAccepted(_))
            ));
            let second = hex_array::<142>(field(
                SHARES,
                if order[1] == 1 {
                    "frame_1_hex"
                } else {
                    "frame_2_hex"
                },
            ));
            load_ingress(core, Source::CameraKitCandidate, &second);
            intake.submit_scanner_from_core(core)
        }
        KitInputModeV2::Fallback => {
            let one: &[u8; 228] = field(
                SHARES,
                if order[0] == 1 {
                    "fallback_1_ascii"
                } else {
                    "fallback_2_ascii"
                },
            )
            .as_bytes()
            .try_into()
            .expect("fallback width");
            let two: &[u8; 228] = field(
                SHARES,
                if order[1] == 1 {
                    "fallback_1_ascii"
                } else {
                    "fallback_2_ascii"
                },
            )
            .as_bytes()
            .try_into()
            .expect("fallback width");
            enter_fallback_in_core(&mut intake, core, one);
            assert!(matches!(
                intake.apply_fallback_key_from_core(core, KeypadKey::EqualsConfirmEnter),
                Ok(KitIntakeOutcomeV2::FirstShareAccepted(_))
            ));
            enter_fallback_in_core(&mut intake, core, two);
            intake.apply_fallback_key_from_core(core, KeypadKey::EqualsConfirmEnter)
        }
    };
    let KitIntakeOutcomeV2::Ready(ready) = outcome.expect("registered share pair") else {
        panic!("second share must release readiness");
    };
    assert_eq!(
        ready
            .frame_identities()
            .map(|identity| identity.share_index().as_u8()),
        order
    );
    assert_eq!(core.current_screen(), Some(CoreScreen::CombineKitShares));
    ready
}

fn begin(selector: u8, digit: u8) -> KitRestoreSessionV2 {
    let mode = if selector & 1 == 0 {
        KitInputModeV2::Scanner
    } else {
        KitInputModeV2::Fallback
    };
    KitRestoreSessionV2::fuzz_begin(
        ready(mode, selector & 2 != 0, KitDoorV2::KitRestore),
        &descriptors(),
        HumanAssertionDigitV2::new(digit).expect("bounded digit"),
    )
    .expect("registered restore readiness")
}

fn surviving_b(mutate: bool) -> SurvivingBFactorV2 {
    let mut wallet_id = hex_array(field(PROVISIONING, "wallet_id"));
    if mutate {
        wallet_id[0] ^= 1;
    }
    let account_xpub = field(PROVISIONING, "role_b_account_xpub")
        .as_bytes()
        .try_into()
        .expect("role-B xpub width");
    let fingerprint = hex_array(field(PROVISIONING, "role_b_origin_fingerprint"));
    let mut a2 = hex_array(field(PROVISIONING, "a2_transcript_sha256"));
    let factor = SurvivingBFactorV2::take(wallet_id, account_xpub, fingerprint, &mut a2);
    assert_eq!(a2, [0; 32]);
    factor
}

fn fail(error: KitRestoreErrorV2) -> Fact {
    Fact {
        error: Some(error_name(error)),
        success: 0,
        wiped: wiped_bytes(),
    }
}

fn foreign(selector: u8) -> KitRestoreForeignOperationV2 {
    match selector % 10 {
        0 => KitRestoreForeignOperationV2::Signing,
        1 => KitRestoreForeignOperationV2::Transaction,
        2 => KitRestoreForeignOperationV2::Review,
        3 => KitRestoreForeignOperationV2::Approval,
        4 => KitRestoreForeignOperationV2::Export,
        5 => KitRestoreForeignOperationV2::Intake,
        6 => KitRestoreForeignOperationV2::GenericWalletOutput,
        7 => KitRestoreForeignOperationV2::KitGeneration,
        8 => KitRestoreForeignOperationV2::KitRegeneration,
        9 => KitRestoreForeignOperationV2::DoorSwitch,
        _ => unreachable!(),
    }
}

fn product_restore(selector: u8, digit: u8, reprint: bool) -> Fact {
    let mode = if selector & 1 == 0 {
        KitInputModeV2::Scanner
    } else {
        KitInputModeV2::Fallback
    };
    let reversed = selector & 2 != 0;
    let mut core = open_core(u32::from(selector));
    let ready = ready_in_core(&mut core, mode, reversed);
    let mut session = KitRestoreSessionV2::begin(
        &mut core,
        ready,
        &descriptors(),
        HumanAssertionDigitV2::new(digit).expect("digit"),
    )
    .expect("registered product restore");
    assert_eq!(
        core.current_screen(),
        Some(CoreScreen::KitRestoreActionSelection)
    );

    let success = if reprint {
        session
            .select_action_in_core(&mut core, KitRestoreActionV2::A1Reprint)
            .expect("A1 reprint action");
        session
            .prepare_a1_reprint_in_core(&mut core, surviving_b(false), &FRESH_NONCE)
            .expect("surviving B factor");
        let staged = session
            .begin_a1_reprint_in_core(&mut core, key(digit))
            .expect("exact assertion digit");
        let outcome =
            complete_product_print(&mut core, staged, false).expect("exact print and scan-back");
        let KitRestoreArtifactV2::A1Reprint(receipt) = outcome.artifact() else {
            panic!("A1 reprint artifact only");
        };
        assert_eq!(receipt.nonce(), FRESH_NONCE);
        assert_eq!(outcome.posture(), MandatoryFreshWalletMigrationV2::Required);
        2
    } else {
        session
            .select_action_in_core(&mut core, KitRestoreActionV2::ReplacementB)
            .expect("replacement action");
        session
            .confirm_card_remains_in_core(&mut core, CardRemainsStatementV2::InHand)
            .expect("old B remains");
        let a1 = hex_array::<67>(field(PROVISIONING, "a1_capsule_hex"));
        load_ingress(&mut core, Source::CameraA1Candidate, &a1);
        session
            .prepare_replacement_b_from_core(&mut core)
            .expect("exact surviving A1 ingress");
        let outcome = session
            .execute_replacement_b_in_core(&mut core, key(digit))
            .expect("one replacement call");
        let KitRestoreArtifactV2::ReplacementB(receipt) = outcome.artifact() else {
            panic!("replacement-B artifact only");
        };
        assert_eq!(
            receipt.wallet_id(),
            hex_array(field(PROVISIONING, "wallet_id"))
        );
        assert_eq!(outcome.posture(), MandatoryFreshWalletMigrationV2::Required);
        1
    };
    assert_eq!(
        core.current_screen(),
        Some(CoreScreen::MandatoryFreshWalletMigration)
    );
    drop(core);
    let wiped = wiped_bytes();
    assert!(wiped > 0);
    Fact {
        error: None,
        success,
        wiped,
    }
}

fn accept_print_event(
    core: &mut CoreSession,
    request: &CoreOutbound,
    opcode: u8,
    body: &[u8],
    expected: CoreReceiveEvent,
) {
    let response = operation_response(request, opcode, body);
    let received = core
        .receive(&response, false)
        .expect("canonical print peer response");
    assert_eq!(received.consumed(), response.len());
    assert_eq!(received.event(), expected);
}

fn complete_product_print(
    core: &mut CoreSession,
    mut staged: AuthorizedA1ReprintV2,
    corrupt_scanback: bool,
) -> Result<qk_core::KitRestoreOutcomeV2, KitRestoreErrorV2> {
    let mut capsule = *staged.capsule().expect("staged capsule");
    assert_eq!(&capsule[..7], b"QKA1\x01\x01\x01");
    assert_eq!(&capsule[7..19], &FRESH_NONCE);

    let begin = staged.begin_print(core)?;
    assert_eq!(
        outer_payload(&begin),
        [1, 3, 0, 0, 8, 0, 0, 0, 3, 4, 67, 0, 0, 0, 0, 0]
    );
    accept_print_event(core, &begin, 3, &[], CoreReceiveEvent::A1PrintBegan);

    let write = staged.write_print(core)?;
    let write_payload = outer_payload(&write);
    assert_eq!(write_payload.len(), 83);
    assert_eq!(
        &write_payload[..16],
        &[1, 4, 0, 0, 75, 0, 0, 0, 0, 0, 0, 0, 67, 0, 0, 0]
    );
    assert_eq!(&write_payload[16..], &capsule);
    accept_print_event(
        core,
        &write,
        4,
        &67u32.to_le_bytes(),
        CoreReceiveEvent::A1PrintWritten { accepted_total: 67 },
    );

    let finish = staged.finish_print(core)?;
    assert_eq!(outer_payload(&finish), [1, 5, 0, 0, 0, 0, 0, 0]);
    accept_print_event(
        core,
        &finish,
        5,
        &[3, 4, 67, 0, 0, 0],
        CoreReceiveEvent::A1PrintFinished { total_len: 67 },
    );

    let scan_begin = staged.begin_scan_back(core)?;
    assert_eq!(
        outer_payload(&scan_begin),
        [1, 1, 0, 0, 3, 0, 0, 0, 1, 0, 0]
    );
    let mut begin_body = Vec::with_capacity(5);
    begin_body.push(Source::CameraA1Candidate.wire_value());
    begin_body.extend_from_slice(&67u32.to_le_bytes());
    accept_print_event(
        core,
        &scan_begin,
        1,
        &begin_body,
        CoreReceiveEvent::IngressBegan {
            source: Source::CameraA1Candidate,
            total_len: 67,
        },
    );

    let scan_read = staged.request_scan_back(core)?;
    assert_eq!(
        outer_payload(&scan_read),
        [1, 2, 0, 0, 4, 0, 0, 0, 0, 0, 0, 0]
    );
    if corrupt_scanback {
        capsule[31] ^= 1;
    }
    let mut read_body = Vec::with_capacity(76);
    read_body.extend_from_slice(&0u32.to_le_bytes());
    read_body.extend_from_slice(&67u32.to_le_bytes());
    read_body.push(1);
    read_body.extend_from_slice(&capsule);
    accept_print_event(
        core,
        &scan_read,
        2,
        &read_body,
        CoreReceiveEvent::IngressChunk {
            offset: 0,
            chunk_len: 67,
            final_chunk: true,
        },
    );
    staged.complete_from_core(core)
}

fn product_wrong_a1_source(selector: u8, digit: u8) -> Fact {
    let mut core = open_core(u32::from(selector));
    let ready = ready_in_core(&mut core, KitInputModeV2::Scanner, false);
    let mut session = KitRestoreSessionV2::begin(
        &mut core,
        ready,
        &descriptors(),
        HumanAssertionDigitV2::new(digit).expect("digit"),
    )
    .expect("product restore");
    session
        .select_action_in_core(&mut core, KitRestoreActionV2::ReplacementB)
        .expect("replacement action");
    session
        .confirm_card_remains_in_core(&mut core, CardRemainsStatementV2::InHand)
        .expect("old B remains");
    let a1 = hex_array::<67>(field(PROVISIONING, "a1_capsule_hex"));
    load_ingress(&mut core, Source::CameraBbqrPsbt, &a1);
    let error = session
        .prepare_replacement_b_from_core(&mut core)
        .expect_err("foreign A1 source terminates");
    assert_eq!(error, KitRestoreErrorV2::ForeignInputProhibited);
    assert_core_absorbing(&mut core);
    drop(session);
    drop(core);
    fail(error)
}

fn product_wrong_digit(selector: u8, digit: u8) -> Fact {
    let mut core = open_core(u32::from(selector));
    let ready = ready_in_core(&mut core, KitInputModeV2::Scanner, true);
    let mut session = KitRestoreSessionV2::begin(
        &mut core,
        ready,
        &descriptors(),
        HumanAssertionDigitV2::new(digit).expect("digit"),
    )
    .expect("product restore");
    session
        .select_action_in_core(&mut core, KitRestoreActionV2::A1Reprint)
        .expect("reprint action");
    session
        .prepare_a1_reprint_in_core(&mut core, surviving_b(false), &FRESH_NONCE)
        .expect("surviving B");
    let error = session
        .begin_a1_reprint_in_core(&mut core, key((digit + 1) % 10))
        .err()
        .expect("wrong digit terminates");
    assert_eq!(error, KitRestoreErrorV2::HumanAssertionMismatch);
    assert_core_absorbing(&mut core);
    drop(core);
    fail(error)
}

fn product_print_order(selector: u8, digit: u8) -> Fact {
    let mut core = open_core(u32::from(selector));
    let ready = ready_in_core(&mut core, KitInputModeV2::Fallback, false);
    let mut session = KitRestoreSessionV2::begin(
        &mut core,
        ready,
        &descriptors(),
        HumanAssertionDigitV2::new(digit).expect("digit"),
    )
    .expect("product restore");
    session
        .select_action_in_core(&mut core, KitRestoreActionV2::A1Reprint)
        .expect("reprint action");
    session
        .prepare_a1_reprint_in_core(&mut core, surviving_b(false), &FRESH_NONCE)
        .expect("surviving B");
    let mut staged = session
        .begin_a1_reprint_in_core(&mut core, key(digit))
        .expect("authorize reprint");
    let error = staged
        .write_print(&mut core)
        .err()
        .expect("write before begin terminates");
    assert_eq!(error, KitRestoreErrorV2::A1PrintRejected);
    assert_core_absorbing(&mut core);
    assert_eq!(
        staged.begin_print(&mut core).err(),
        Some(KitRestoreErrorV2::A1PrintRejected)
    );
    drop(staged);
    drop(core);
    fail(error)
}

fn product_scan_mismatch(selector: u8, digit: u8) -> Fact {
    let mut core = open_core(u32::from(selector));
    let ready = ready_in_core(&mut core, KitInputModeV2::Fallback, true);
    let mut session = KitRestoreSessionV2::begin(
        &mut core,
        ready,
        &descriptors(),
        HumanAssertionDigitV2::new(digit).expect("digit"),
    )
    .expect("product restore");
    session
        .select_action_in_core(&mut core, KitRestoreActionV2::A1Reprint)
        .expect("reprint action");
    session
        .prepare_a1_reprint_in_core(&mut core, surviving_b(false), &FRESH_NONCE)
        .expect("surviving B");
    let staged = session
        .begin_a1_reprint_in_core(&mut core, key(digit))
        .expect("authorize reprint");
    let error = complete_product_print(&mut core, staged, true)
        .err()
        .expect("scan-back mismatch terminates");
    assert_eq!(error, KitRestoreErrorV2::A1VerificationMismatch);
    assert_core_absorbing(&mut core);
    drop(core);
    fail(error)
}

fn semantic_drive(case: u8, digit: u8, auxiliary: u8) -> Fact {
    match case % 18 {
        0 => {
            let error = HumanAssertionDigitV2::new(10).expect_err("invalid digit");
            fail(error)
        }
        1 => {
            let error = KitRestoreSessionV2::fuzz_begin(
                ready(KitInputModeV2::Scanner, false, KitDoorV2::KitSpend),
                &descriptors(),
                HumanAssertionDigitV2::new(digit).expect("digit"),
            )
            .err()
            .expect("wrong door");
            fail(error)
        }
        2 => {
            let mut wrong = descriptors();
            wrong[0][0] ^= 1;
            let error = KitRestoreSessionV2::fuzz_begin(
                ready(KitInputModeV2::Scanner, false, KitDoorV2::KitRestore),
                &wrong,
                HumanAssertionDigitV2::new(digit).expect("digit"),
            )
            .err()
            .expect("wrong descriptor");
            fail(error)
        }
        3 => {
            let mut session = begin(case, digit);
            session
                .select_action(KitRestoreActionV2::ReplacementB)
                .expect("replacement action");
            session
                .confirm_card_remains(CardRemainsStatementV2::InHand)
                .expect("old card remains");
            let mut a1 = hex_array(field(PROVISIONING, "a1_capsule_hex"));
            session
                .prepare_replacement_b(&mut a1)
                .expect("surviving A1");
            assert_eq!(a1, [0; 67]);
            let outcome = session
                .execute_replacement_b(key(digit), |_| KitRestoreDispositionV2::Accepted)
                .expect("replacement accepted");
            assert_eq!(outcome.posture(), MandatoryFreshWalletMigrationV2::Required);
            Fact {
                error: None,
                success: 1,
                wiped: wiped_bytes(),
            }
        }
        4 => {
            let mut session = begin(case, digit);
            session
                .select_action(KitRestoreActionV2::A1Reprint)
                .expect("reprint action");
            let mut nonce = [0u8; 12];
            nonce.copy_from_slice(b"QKV2S10NEW01");
            session
                .prepare_a1_reprint(surviving_b(false), &nonce)
                .expect("surviving B");
            let staged = session
                .begin_a1_reprint(key(digit))
                .expect("authorize reprint");
            let mut scanback = *staged.capsule().expect("staged capsule");
            let outcome = staged
                .complete_scan_back(&mut scanback)
                .expect("exact scanback");
            assert_eq!(scanback, [0; 67]);
            assert_eq!(outcome.posture(), MandatoryFreshWalletMigrationV2::Required);
            Fact {
                error: None,
                success: 2,
                wiped: wiped_bytes(),
            }
        }
        5 => {
            let mut session = begin(case, digit);
            session
                .select_action(KitRestoreActionV2::ReplacementB)
                .expect("replacement action");
            let error = session
                .confirm_card_remains(CardRemainsStatementV2::Missing)
                .expect_err("missing card requires spend");
            fail(error)
        }
        6 => {
            let mut session = begin(case, digit);
            session
                .select_action(KitRestoreActionV2::A1Reprint)
                .expect("first action");
            let error = session
                .select_action(KitRestoreActionV2::ReplacementB)
                .expect_err("action switch");
            fail(error)
        }
        7 => {
            let mut session = begin(case, digit);
            let error = session
                .reject_foreign_operation(foreign(auxiliary))
                .expect_err("foreign operation");
            fail(error)
        }
        8 => {
            let mut session = begin(case, digit);
            let reason = INTERRUPTIONS[usize::from(auxiliary % 10)];
            let error = session.interrupt(reason).expect_err("interruption");
            fail(error)
        }
        9 => {
            let mut session = begin(case, digit);
            session
                .select_action(KitRestoreActionV2::ReplacementB)
                .expect("replacement action");
            session
                .confirm_card_remains(CardRemainsStatementV2::InHand)
                .expect("old card remains");
            let mut a1 = hex_array(field(PROVISIONING, "a1_capsule_hex"));
            a1[0] ^= 1;
            let error = session
                .prepare_replacement_b(&mut a1)
                .expect_err("surviving A1 mismatch");
            assert_eq!(a1, [0; 67]);
            fail(error)
        }
        10 => {
            let mut session = begin(case, digit);
            session
                .select_action(KitRestoreActionV2::A1Reprint)
                .expect("reprint action");
            let error = session
                .prepare_a1_reprint(surviving_b(true), b"QKV2S10NEW01")
                .expect_err("surviving B mismatch");
            fail(error)
        }
        11 => {
            let mut session = begin(case, digit);
            session
                .select_action(KitRestoreActionV2::ReplacementB)
                .expect("replacement action");
            session
                .confirm_card_remains(CardRemainsStatementV2::InHand)
                .expect("old card remains");
            let mut a1 = hex_array(field(PROVISIONING, "a1_capsule_hex"));
            session
                .prepare_replacement_b(&mut a1)
                .expect("surviving A1");
            let wrong = (digit + 1) % 10;
            let error = session
                .execute_replacement_b(key(wrong), |_| KitRestoreDispositionV2::Accepted)
                .err()
                .expect("wrong digit");
            fail(error)
        }
        12 => {
            let mut session = begin(case, digit);
            session
                .select_action(KitRestoreActionV2::ReplacementB)
                .expect("replacement action");
            session
                .confirm_card_remains(CardRemainsStatementV2::InHand)
                .expect("old card remains");
            let mut a1 = hex_array(field(PROVISIONING, "a1_capsule_hex"));
            session
                .prepare_replacement_b(&mut a1)
                .expect("surviving A1");
            let error = session
                .execute_replacement_b(key(digit), |_| KitRestoreDispositionV2::Rejected)
                .err()
                .expect("replacement rejected");
            fail(error)
        }
        13 => {
            let mut session = begin(case, digit);
            session
                .select_action(KitRestoreActionV2::A1Reprint)
                .expect("reprint action");
            session
                .prepare_a1_reprint(surviving_b(false), b"QKV2S10NEW01")
                .expect("surviving B");
            let staged = session
                .begin_a1_reprint(key(digit))
                .expect("authorize reprint");
            fail(staged.reject_print())
        }
        14 => {
            let mut session = begin(case, digit);
            session
                .select_action(KitRestoreActionV2::A1Reprint)
                .expect("reprint action");
            session
                .prepare_a1_reprint(surviving_b(false), b"QKV2S10NEW01")
                .expect("surviving B");
            let staged = session
                .begin_a1_reprint(key(digit))
                .expect("authorize reprint");
            let mut scanback = *staged.capsule().expect("capsule");
            scanback[31] ^= 1;
            let error = staged
                .complete_scan_back(&mut scanback)
                .err()
                .expect("scanback mismatch");
            assert_eq!(scanback, [0; 67]);
            fail(error)
        }
        15..=17 => {
            let mut session = begin(case, digit);
            let error = match case % 3 {
                0 => session
                    .confirm_card_remains(CardRemainsStatementV2::InHand)
                    .expect_err("invalid ordering"),
                1 => {
                    let mut a1 = hex_array(field(PROVISIONING, "a1_capsule_hex"));
                    session
                        .prepare_replacement_b(&mut a1)
                        .expect_err("invalid ordering")
                }
                2 => session
                    .select_action(KitRestoreActionV2::ReplacementB)
                    .and_then(|_| session.select_action(KitRestoreActionV2::ReplacementB))
                    .expect_err("duplicate action"),
                _ => unreachable!(),
            };
            fail(error)
        }
        _ => unreachable!(),
    }
}

fn drive(data: &[u8]) -> Fact {
    reset_wiped_bytes();
    let selector = data.first().copied().unwrap_or(0);
    let digit = data.get(1).copied().unwrap_or(0) % 10;
    let auxiliary = data.get(2).copied().unwrap_or(0);
    match selector % 50 {
        0..=3 => product_restore(selector, digit, false),
        4..=7 => product_restore(selector, digit, true),
        8 => product_wrong_a1_source(selector, digit),
        9 => product_wrong_digit(selector, digit),
        10 => product_print_order(selector, digit),
        11 => product_scan_mismatch(selector, digit),
        12..=29 => semantic_drive(selector - 12, digit, auxiliary),
        30..=39 => semantic_drive(7, digit, selector - 30),
        40..=49 => semantic_drive(8, digit, selector - 40),
        _ => unreachable!(),
    }
}

fuzz_target!(|data: &[u8]| {
    if data.len() > MAX_PRESENTED_BYTES {
        return;
    }
    let first = drive(data);
    let second = drive(data);
    assert_eq!(first, second);
});
