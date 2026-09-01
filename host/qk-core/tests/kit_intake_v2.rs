//! Process-slice-7 qk-core Kit intake behavior.

use qk_core::{
    CardPresence, CoreDeviceGrants, CoreMode, CoreReceiveEvent, CoreScreen, CoreSession, CoreState,
    Interruption, KitDoorV2, KitForeignInputV2, KitInputModeV2, KitIntakeErrorV2,
    KitIntakeOutcomeV2, KitIntakeSessionV2, KitShareOrdinalV2, MockCardSlot, MockDisplay,
    MockKeypad, Source,
};
#[cfg(feature = "fuzzing")]
use qk_core::{KeypadKey, KIT_FALLBACK_TABLE_V2};
use qk_io::{BrokerSession, MockInput, Source as IoSource};
use qk_ipc::{ReceivedFrame, StreamDecoder};
use qk_kit::FRAME_LEN;
#[cfg(feature = "fuzzing")]
use qk_kit::{encode_frame, KitError, ShareIndex, FALLBACK_SYMBOLS};

const FIXTURE: &str = include_str!("../../qk-kit/tests/fixtures/kit_share_v2.txt");
#[cfg(feature = "fuzzing")]
const EXPECTED_TABLE: [[u8; 8]; 4] = [*b"23456789", *b"abcdefgh", *b"ijkmnpqr", *b"stuvwxyz"];

fn field(name: &str) -> &'static str {
    let prefix = format!("{name}: ");
    FIXTURE
        .lines()
        .find_map(|line| line.strip_prefix(&prefix))
        .unwrap_or_else(|| panic!("missing fixture field {name}"))
}

fn nibble(value: u8) -> u8 {
    match value {
        b'0'..=b'9' => value - b'0',
        b'a'..=b'f' => value - b'a' + 10,
        _ => panic!("canonical fixture hex"),
    }
}

fn hex_array<const N: usize>(value: &str) -> [u8; N] {
    assert_eq!(value.len(), N * 2);
    let mut output = [0u8; N];
    for (slot, pair) in output.iter_mut().zip(value.as_bytes().chunks_exact(2)) {
        *slot = (nibble(pair[0]) << 4) | nibble(pair[1]);
    }
    output
}

fn frame(number: u8) -> [u8; FRAME_LEN] {
    hex_array(field(&format!("frame_{number}_hex")))
}

#[cfg(feature = "fuzzing")]
fn fallback(number: u8) -> [u8; FALLBACK_SYMBOLS] {
    field(&format!("fallback_{number}_ascii"))
        .as_bytes()
        .try_into()
        .expect("exact fallback width")
}

#[cfg(feature = "fuzzing")]
fn wallet_id() -> [u8; 32] {
    hex_array(field("wallet_id_hex"))
}

fn decode_one(bytes: &[u8]) -> ReceivedFrame {
    let mut decoder = StreamDecoder::new();
    let outcome = decoder.ingest(bytes, false).expect("complete QKIP frame");
    assert!(outcome.frame_ready());
    decoder.take_frame().expect("owned QKIP frame")
}

fn opened_kit_core() -> (CoreSession, BrokerSession) {
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
    assert_eq!(
        core.receive(response.frame_bytes(), false)
            .expect("accept session ready")
            .event(),
        CoreReceiveEvent::SessionReady
    );
    (core, broker)
}

fn load_kit_candidate(core: &mut CoreSession, broker: &mut BrokerSession, bytes: &[u8; 142]) {
    let mut input = MockInput::try_new(IoSource::CameraKitCandidate, bytes).expect("Kit input");
    let begin = decode_one(
        core.begin_ingress(Source::CameraKitCandidate)
            .expect("begin Kit ingress")
            .frame_bytes(),
    );
    let response = broker
        .accept(&begin, Some(&mut input), None)
        .expect("ingress begin response");
    core.receive(response.frame_bytes(), false)
        .expect("accept ingress begin");
    while core.state() == CoreState::IngressReadReady {
        let read = decode_one(
            core.request_next_chunk()
                .expect("request Kit chunk")
                .frame_bytes(),
        );
        let response = broker
            .accept(&read, None, None)
            .expect("ingress read response");
        core.receive(response.frame_bytes(), false)
            .expect("accept ingress chunk");
    }
    assert_eq!(core.state(), CoreState::IngressComplete);
}

#[cfg(feature = "fuzzing")]
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
        _ => panic!("single decimal digit"),
    }
}

#[cfg(feature = "fuzzing")]
fn append_symbol(session: &mut KitIntakeSessionV2, symbol: u8) {
    let (row, column) = EXPECTED_TABLE
        .iter()
        .enumerate()
        .find_map(|(row, symbols)| {
            symbols
                .iter()
                .position(|candidate| *candidate == symbol)
                .map(|column| (row + 1, column + 1))
        })
        .unwrap_or_else(|| panic!("fixture symbol outside fallback alphabet"));
    assert!(matches!(
        session.apply_fallback_key(numeric_key(row as u8)),
        Ok(KitIntakeOutcomeV2::Continue(_))
    ));
    assert!(matches!(
        session.apply_fallback_key(numeric_key(column as u8)),
        Ok(KitIntakeOutcomeV2::Continue(_))
    ));
}

#[cfg(feature = "fuzzing")]
fn submit_fallback(
    session: &mut KitIntakeSessionV2,
    symbols: &[u8; FALLBACK_SYMBOLS],
) -> Result<KitIntakeOutcomeV2, KitIntakeErrorV2> {
    for symbol in symbols {
        append_symbol(session, *symbol);
    }
    session.apply_fallback_key(KeypadKey::EqualsConfirmEnter)
}

fn assert_first(outcome: KitIntakeOutcomeV2) {
    let KitIntakeOutcomeV2::FirstShareAccepted(screen) = outcome else {
        panic!("first share must retain an intake owner");
    };
    assert_eq!(screen.page(), KitShareOrdinalV2::Two);
    assert_eq!(screen.fallback().committed_symbols(), 0);
}

#[test]
fn product_bridge_consumes_source_02_and_selects_typed_share_screens() {
    let (mut core, mut broker) = opened_kit_core();
    let mut intake =
        KitIntakeSessionV2::begin_in_core(&mut core, KitDoorV2::KitSpend, KitInputModeV2::Scanner)
            .expect("product intake");
    assert_eq!(core.current_screen(), Some(CoreScreen::ScanKitShareOne));

    load_kit_candidate(&mut core, &mut broker, &frame(1));
    assert_first(
        intake
            .submit_scanner_from_core(&mut core)
            .expect("first source-02 share"),
    );
    assert_eq!(core.current_screen(), Some(CoreScreen::ScanKitShareTwo));

    load_kit_candidate(&mut core, &mut broker, &frame(2));
    assert!(matches!(
        intake.submit_scanner_from_core(&mut core),
        Ok(KitIntakeOutcomeV2::Ready(_))
    ));
    assert_eq!(core.current_screen(), Some(CoreScreen::CombineKitShares));
}

#[test]
fn one_core_session_claims_exactly_one_kit_intake() {
    let (mut core, _broker) = opened_kit_core();
    let _first =
        KitIntakeSessionV2::begin_in_core(&mut core, KitDoorV2::KitSpend, KitInputModeV2::Scanner)
            .expect("first intake claims the shell");
    assert_eq!(
        KitIntakeSessionV2::begin_in_core(
            &mut core,
            KitDoorV2::KitRestore,
            KitInputModeV2::Fallback,
        )
        .err(),
        Some(KitIntakeErrorV2::Interrupted(Interruption::OperationFailed))
    );
    assert_eq!(core.state(), CoreState::Terminated);
}

#[test]
#[cfg(feature = "fuzzing")]
fn scanner_accepts_both_doors_and_both_share_orders_and_clears_callers() {
    for door in [KitDoorV2::KitRestore, KitDoorV2::KitSpend] {
        for order in [[1u8, 2u8], [2, 1]] {
            let mut session = KitIntakeSessionV2::begin(door, KitInputModeV2::Scanner);
            let initial = session.screen().expect("active intake");
            assert_eq!(initial.door(), door);
            assert_eq!(initial.mode(), KitInputModeV2::Scanner);
            assert_eq!(initial.page(), KitShareOrdinalV2::One);

            let mut first = frame(order[0]);
            assert_first(
                session
                    .submit_scanner_frame(&mut first)
                    .expect("first share"),
            );
            assert_eq!(first, [0; FRAME_LEN]);

            let mut second = frame(order[1]);
            let KitIntakeOutcomeV2::Ready(ready) = session
                .submit_scanner_frame(&mut second)
                .expect("opposite share")
            else {
                panic!("second share must release opaque readiness");
            };
            assert_eq!(second, [0; FRAME_LEN]);
            assert_eq!(ready.door(), door);
            assert_eq!(ready.mode(), KitInputModeV2::Scanner);
            assert_eq!(ready.wallet_id(), wallet_id());
            assert_eq!(
                ready
                    .frame_identities()
                    .map(|identity| identity.share_index().as_u8()),
                order
            );
            assert_eq!(session.screen(), None);
            assert_eq!(session.failure(), None);
        }
    }
}

#[test]
#[cfg(feature = "fuzzing")]
fn scanner_rejections_are_named_terminal_and_clear_every_candidate() {
    let mut checksum = KitIntakeSessionV2::begin(KitDoorV2::KitSpend, KitInputModeV2::Scanner);
    let mut bad = frame(1);
    bad[FRAME_LEN - 1] ^= 1;
    assert_eq!(
        checksum.submit_scanner_frame(&mut bad).err(),
        Some(KitIntakeErrorV2::Codec(KitError::FrameChecksum))
    );
    assert_eq!(bad, [0; FRAME_LEN]);
    assert_eq!(checksum.screen(), None);

    for (second, expected) in [
        (frame(1), KitError::DuplicateShare),
        (
            encode_frame(ShareIndex::One, &wallet_id(), &[0x33; 96]),
            KitError::SameShareIndex,
        ),
        (
            encode_frame(ShareIndex::Two, &[0x44; 32], &[0x55; 96]),
            KitError::WalletMismatch,
        ),
    ] {
        let mut session = KitIntakeSessionV2::begin(KitDoorV2::KitRestore, KitInputModeV2::Scanner);
        let mut first = frame(1);
        assert_first(session.submit_scanner_frame(&mut first).unwrap());
        let mut candidate = second;
        assert_eq!(
            session.submit_scanner_frame(&mut candidate).err(),
            Some(KitIntakeErrorV2::Codec(expected))
        );
        assert_eq!(candidate, [0; FRAME_LEN]);
        assert_eq!(session.failure(), Some(KitIntakeErrorV2::Codec(expected)));

        let mut after = frame(2);
        assert_eq!(
            session.submit_scanner_frame(&mut after).err(),
            Some(KitIntakeErrorV2::Finished)
        );
        assert_eq!(after, [0; FRAME_LEN]);
    }
}

#[test]
#[cfg(feature = "fuzzing")]
fn door_mode_foreign_inputs_and_all_interruptions_terminate() {
    let mut mode = KitIntakeSessionV2::begin(KitDoorV2::KitSpend, KitInputModeV2::Scanner);
    assert_eq!(
        mode.select_mode(KitInputModeV2::Fallback).err(),
        Some(KitIntakeErrorV2::KitScannerModeMismatch)
    );

    let mut door = KitIntakeSessionV2::begin(KitDoorV2::KitSpend, KitInputModeV2::Scanner);
    assert_eq!(
        door.reselect_door(KitDoorV2::KitRestore).err(),
        Some(KitIntakeErrorV2::DoorSwitchAttempt)
    );

    for foreign in [
        KitForeignInputV2::Image,
        KitForeignInputV2::Camera,
        KitForeignInputV2::A1,
        KitForeignInputV2::Psbt,
        KitForeignInputV2::BbqrTransaction,
        KitForeignInputV2::Coordinator,
        KitForeignInputV2::Transport,
        KitForeignInputV2::GenericIntake,
        KitForeignInputV2::QrWrapper,
        KitForeignInputV2::ModeSelection,
        KitForeignInputV2::Other,
    ] {
        let mut session = KitIntakeSessionV2::begin(KitDoorV2::KitRestore, KitInputModeV2::Scanner);
        assert_eq!(
            session.reject_foreign_input(foreign).err(),
            Some(KitIntakeErrorV2::KitScannerModeMismatch)
        );
    }

    for event in [
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
        let mut session =
            KitIntakeSessionV2::begin(KitDoorV2::KitRestore, KitInputModeV2::Fallback);
        assert_eq!(
            session.interrupt(event).err(),
            Some(KitIntakeErrorV2::Interrupted(event))
        );
        assert_eq!(
            session.failure(),
            Some(KitIntakeErrorV2::Interrupted(event))
        );
        assert_eq!(KitIntakeErrorV2::Interrupted(event).name(), event.name());
    }
}

#[test]
fn product_terminal_inputs_terminate_the_core_and_clear_completed_ingress() {
    let (mut mode_core, _broker) = opened_kit_core();
    let mut mode = KitIntakeSessionV2::begin_in_core(
        &mut mode_core,
        KitDoorV2::KitSpend,
        KitInputModeV2::Scanner,
    )
    .expect("product intake");
    assert_eq!(
        mode.select_mode_in_core(&mut mode_core, KitInputModeV2::Fallback)
            .err(),
        Some(KitIntakeErrorV2::KitScannerModeMismatch)
    );
    assert_eq!(mode_core.state(), CoreState::Terminated);

    let (mut door_core, mut door_broker) = opened_kit_core();
    let mut door = KitIntakeSessionV2::begin_in_core(
        &mut door_core,
        KitDoorV2::KitSpend,
        KitInputModeV2::Scanner,
    )
    .expect("product intake");
    load_kit_candidate(&mut door_core, &mut door_broker, &frame(1));
    assert!(door_core.completed_ingress().is_some());
    assert_eq!(
        door.reselect_door_in_core(&mut door_core, KitDoorV2::KitRestore)
            .err(),
        Some(KitIntakeErrorV2::DoorSwitchAttempt)
    );
    assert_eq!(door_core.state(), CoreState::Terminated);
    assert!(door_core.completed_ingress().is_none());

    let (mut foreign_core, _broker) = opened_kit_core();
    let mut foreign = KitIntakeSessionV2::begin_in_core(
        &mut foreign_core,
        KitDoorV2::KitRestore,
        KitInputModeV2::Fallback,
    )
    .expect("product intake");
    assert_eq!(
        foreign
            .reject_foreign_input_in_core(&mut foreign_core, KitForeignInputV2::Transport)
            .err(),
        Some(KitIntakeErrorV2::KitScannerModeMismatch)
    );
    assert_eq!(foreign_core.state(), CoreState::Terminated);

    let (mut interrupted_core, _broker) = opened_kit_core();
    let mut interrupted = KitIntakeSessionV2::begin_in_core(
        &mut interrupted_core,
        KitDoorV2::KitRestore,
        KitInputModeV2::Fallback,
    )
    .expect("product intake");
    assert_eq!(
        interrupted
            .interrupt_in_core(&mut interrupted_core, Interruption::SessionTimeout)
            .err(),
        Some(KitIntakeErrorV2::Interrupted(Interruption::SessionTimeout))
    );
    assert_eq!(interrupted_core.state(), CoreState::Terminated);
    assert_eq!(
        interrupted_core.terminal_reason(),
        Some(Interruption::SessionTimeout)
    );
}

#[test]
#[cfg(feature = "fuzzing")]
fn fallback_accepts_both_doors_and_both_orders_with_exact_progress() {
    assert_eq!(KIT_FALLBACK_TABLE_V2, EXPECTED_TABLE);
    for door in [KitDoorV2::KitRestore, KitDoorV2::KitSpend] {
        for order in [[1u8, 2u8], [2, 1]] {
            let mut session = KitIntakeSessionV2::begin(door, KitInputModeV2::Fallback);
            let initial = session.screen().unwrap();
            assert_eq!(initial.fallback_table(), &EXPECTED_TABLE);
            assert_eq!(initial.fallback().next_line(), Some(1));
            assert_eq!(initial.fallback().next_column(), Some(1));

            assert_first(submit_fallback(&mut session, &fallback(order[0])).unwrap());
            let KitIntakeOutcomeV2::Ready(ready) =
                submit_fallback(&mut session, &fallback(order[1])).unwrap()
            else {
                panic!("second fallback share must release readiness");
            };
            assert_eq!(ready.door(), door);
            assert_eq!(ready.mode(), KitInputModeV2::Fallback);
            assert_eq!(ready.wallet_id(), wallet_id());
            assert_eq!(
                ready
                    .frame_identities()
                    .map(|identity| identity.share_index().as_u8()),
                order
            );
        }
    }
}

#[test]
#[cfg(feature = "fuzzing")]
fn fallback_ce_and_each_entry_rejection_are_exact_and_non_retrying() {
    let mut ce = KitIntakeSessionV2::begin(KitDoorV2::KitSpend, KitInputModeV2::Fallback);
    assert!(matches!(
        ce.apply_fallback_key(KeypadKey::One),
        Ok(KitIntakeOutcomeV2::Continue(_))
    ));
    assert_eq!(ce.screen().unwrap().fallback().pending_row(), Some(1));
    assert!(matches!(
        ce.apply_fallback_key(KeypadKey::CeDelete),
        Ok(KitIntakeOutcomeV2::Continue(_))
    ));
    assert_eq!(ce.screen().unwrap().fallback().pending_row(), None);

    let cases = [
        (vec![KeypadKey::Nine], KitIntakeErrorV2::InvalidFallbackRow),
        (
            vec![KeypadKey::One, KeypadKey::Nine],
            KitIntakeErrorV2::InvalidFallbackColumn,
        ),
        (
            vec![KeypadKey::CeDelete],
            KitIntakeErrorV2::FallbackEmptyDelete,
        ),
        (
            vec![KeypadKey::EqualsConfirmEnter],
            KitIntakeErrorV2::FallbackIncomplete,
        ),
        (
            vec![KeypadKey::One, KeypadKey::EqualsConfirmEnter],
            KitIntakeErrorV2::FallbackPendingCoordinate,
        ),
    ];
    for (keys, expected) in cases {
        let mut session = KitIntakeSessionV2::begin(KitDoorV2::KitSpend, KitInputModeV2::Fallback);
        let mut actual = None;
        for key in keys {
            if let Err(error) = session.apply_fallback_key(key) {
                actual = Some(error);
                break;
            }
        }
        assert_eq!(actual, Some(expected));
        assert_eq!(session.screen(), None);
        assert_eq!(
            session.apply_fallback_key(KeypadKey::One).err(),
            Some(KitIntakeErrorV2::Finished)
        );
    }

    let mut scanner = KitIntakeSessionV2::begin(KitDoorV2::KitSpend, KitInputModeV2::Scanner);
    assert_eq!(
        scanner.apply_fallback_key(KeypadKey::One).err(),
        Some(KitIntakeErrorV2::KitScannerModeMismatch)
    );

    let mut fallback_mode =
        KitIntakeSessionV2::begin(KitDoorV2::KitSpend, KitInputModeV2::Fallback);
    let mut candidate = frame(1);
    assert_eq!(
        fallback_mode.submit_scanner_frame(&mut candidate).err(),
        Some(KitIntakeErrorV2::KitScannerModeMismatch)
    );
    assert_eq!(candidate, [0; FRAME_LEN]);
}

#[test]
#[cfg(feature = "fuzzing")]
fn malformed_fallback_never_releases_a_ready_capability() {
    let mut malformed = fallback(1);
    malformed[0] = if malformed[0] == b'2' { b'3' } else { b'2' };
    let mut session = KitIntakeSessionV2::begin(KitDoorV2::KitRestore, KitInputModeV2::Fallback);
    assert_eq!(
        submit_fallback(&mut session, &malformed).err(),
        Some(KitIntakeErrorV2::Codec(KitError::FrameChecksum))
    );

    let mut padding = fallback(1);
    padding[FALLBACK_SYMBOLS - 1] = b'3';
    let mut session = KitIntakeSessionV2::begin(KitDoorV2::KitSpend, KitInputModeV2::Fallback);
    assert_eq!(
        submit_fallback(&mut session, &padding).err(),
        Some(KitIntakeErrorV2::Codec(KitError::NonCanonicalPadding))
    );
}
