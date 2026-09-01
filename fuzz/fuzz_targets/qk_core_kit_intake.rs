#![no_main]

use libfuzzer_sys::fuzz_target;
use qk_core::fuzz::{fuzz_start_session, reset_wiped_bytes, wiped_bytes};
use qk_core::{
    CardPresence, CoreDeviceGrants, CoreError, CoreMode, CoreOutbound, CoreReceiveEvent,
    CoreScreen, CoreSession, CoreState, Interruption, KIT_FALLBACK_TABLE_V2, KeypadKey, KitDoorV2,
    KitForeignInputV2, KitInputModeV2, KitIntakeErrorV2, KitIntakeOutcomeV2, KitIntakeSessionV2,
    MockCardSlot, MockDisplay, MockKeypad, Source,
};
use qk_ipc::{Direction, HEADER_BYTES, MessageKind, encode_frame, parse_frame};

#[allow(dead_code, clippy::chunks_exact_to_as_chunks)]
#[path = "../../host/qk-psbt/src/sha256.rs"]
mod reference_sha256;

const MAX_PRESENTED_BYTES: usize = 512;
const FIXTURE: &str = include_str!("../../host/qk-kit/tests/fixtures/kit_share_v2.txt");
const NAMESPACE: [u8; 12] = *b"QKS7INTAKE01";
const FRAME_BYTES: usize = 142;
const FALLBACK_SYMBOLS: usize = 228;
const FRAME_CHECKSUM_OFFSET: usize = 134;
const FRAME_CHECKSUM_BYTES: usize = 8;
const FRAME_DOMAIN: &[u8] = b"QuietKey/KitShare/v1";
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
    ready: bool,
    indices: [u8; 2],
    screen: Option<CoreScreen>,
    wiped: usize,
}

fn field(name: &str) -> &'static str {
    FIXTURE
        .lines()
        .find_map(|line| line.strip_prefix(name)?.strip_prefix(": "))
        .expect("registered Kit fixture field")
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

fn frame(index: u8) -> [u8; FRAME_BYTES] {
    match index {
        1 => hex_array(field("frame_1_hex")),
        2 => hex_array(field("frame_2_hex")),
        _ => panic!("registered share index"),
    }
}

fn fallback(index: u8) -> [u8; FALLBACK_SYMBOLS] {
    match index {
        1 => field("fallback_1_ascii"),
        2 => field("fallback_2_ascii"),
        _ => panic!("registered share index"),
    }
    .as_bytes()
    .try_into()
    .expect("registered fallback width")
}

fn rewrite_checksum(candidate: &mut [u8; FRAME_BYTES]) {
    let digest =
        reference_sha256::sha256(&[FRAME_DOMAIN, &[0], &candidate[..FRAME_CHECKSUM_OFFSET]])
            .expect("bounded frame hash");
    candidate[FRAME_CHECKSUM_OFFSET..].copy_from_slice(&digest[..FRAME_CHECKSUM_BYTES]);
}

fn error_name(error: KitIntakeErrorV2) -> &'static str {
    let name = match error {
        KitIntakeErrorV2::InvalidTransition => "InvalidTransition",
        KitIntakeErrorV2::KitScannerModeMismatch => "KitScannerModeMismatch",
        KitIntakeErrorV2::WrongIngressSource => "WrongIngressSource",
        KitIntakeErrorV2::DoorSwitchAttempt => "DoorSwitchAttempt",
        KitIntakeErrorV2::InvalidFallbackRow => "InvalidFallbackRow",
        KitIntakeErrorV2::InvalidFallbackColumn => "InvalidFallbackColumn",
        KitIntakeErrorV2::FallbackEmptyDelete => "FallbackEmptyDelete",
        KitIntakeErrorV2::FallbackIncomplete => "FallbackIncomplete",
        KitIntakeErrorV2::FallbackPendingCoordinate => "FallbackPendingCoordinate",
        KitIntakeErrorV2::FallbackFull => "FallbackFull",
        KitIntakeErrorV2::Codec(_) => {
            let actual = error.name();
            assert!(matches!(
                actual,
                "FrameLength"
                    | "FrameChecksum"
                    | "InvalidMagic"
                    | "UnsupportedVersion"
                    | "InvalidShareIndex"
                    | "FallbackLength"
                    | "MalformedSymbol"
                    | "NonCanonicalPadding"
                    | "DuplicateShare"
                    | "SameShareIndex"
                    | "WalletMismatch"
            ));
            actual
        }
        KitIntakeErrorV2::Interrupted(reason) => interruption_name(reason),
        KitIntakeErrorV2::Finished => "Finished",
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
        core.begin_ingress(Source::CameraKitCandidate).err(),
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

fn coordinate_key(number: usize) -> KeypadKey {
    match number {
        1 => KeypadKey::One,
        2 => KeypadKey::TwoDown,
        3 => KeypadKey::Three,
        4 => KeypadKey::FourLeft,
        5 => KeypadKey::Five,
        6 => KeypadKey::SixRight,
        7 => KeypadKey::Seven,
        8 => KeypadKey::EightUp,
        _ => panic!("bounded fallback coordinate"),
    }
}

fn append_symbol(session: &mut KitIntakeSessionV2, symbol: u8) {
    let position = KIT_FALLBACK_TABLE_V2
        .iter()
        .flatten()
        .position(|candidate| *candidate == symbol)
        .expect("registered fallback alphabet");
    assert!(matches!(
        session.apply_fallback_key(coordinate_key(position / 8 + 1)),
        Ok(KitIntakeOutcomeV2::Continue(_))
    ));
    assert!(matches!(
        session.apply_fallback_key(coordinate_key(position % 8 + 1)),
        Ok(KitIntakeOutcomeV2::Continue(_))
    ));
}

fn append_symbol_from_core(session: &mut KitIntakeSessionV2, core: &mut CoreSession, symbol: u8) {
    let position = KIT_FALLBACK_TABLE_V2
        .iter()
        .flatten()
        .position(|candidate| *candidate == symbol)
        .expect("registered fallback alphabet");
    assert!(matches!(
        session.apply_fallback_key_from_core(core, coordinate_key(position / 8 + 1)),
        Ok(KitIntakeOutcomeV2::Continue(_))
    ));
    assert!(matches!(
        session.apply_fallback_key_from_core(core, coordinate_key(position % 8 + 1)),
        Ok(KitIntakeOutcomeV2::Continue(_))
    ));
}

fn enter_fallback(session: &mut KitIntakeSessionV2, symbols: &[u8; FALLBACK_SYMBOLS]) {
    for symbol in symbols {
        append_symbol(session, *symbol);
    }
}

fn enter_fallback_from_core(
    session: &mut KitIntakeSessionV2,
    core: &mut CoreSession,
    symbols: &[u8; FALLBACK_SYMBOLS],
) {
    for symbol in symbols {
        append_symbol_from_core(session, core, *symbol);
    }
}

fn assert_intake_absorbing(session: &mut KitIntakeSessionV2) {
    let latched = session.failure();
    let mut candidate = [0xa5; FRAME_BYTES];
    assert_eq!(
        session.submit_scanner_frame(&mut candidate).err(),
        Some(KitIntakeErrorV2::Finished)
    );
    assert_eq!(candidate, [0; FRAME_BYTES]);
    assert_eq!(
        session.apply_fallback_key(KeypadKey::One).err(),
        Some(KitIntakeErrorV2::Finished)
    );
    assert_eq!(
        session.select_mode(KitInputModeV2::Scanner).err(),
        Some(KitIntakeErrorV2::Finished)
    );
    assert_eq!(
        session.reselect_door(KitDoorV2::KitSpend).err(),
        Some(KitIntakeErrorV2::Finished)
    );
    assert_eq!(
        session.reject_foreign_input(KitForeignInputV2::Other).err(),
        Some(KitIntakeErrorV2::Finished)
    );
    assert_eq!(
        session.interrupt(Interruption::OperationFailed).err(),
        Some(KitIntakeErrorV2::Finished)
    );
    assert_eq!(session.failure(), latched);
}

fn failure_fact(mut session: KitIntakeSessionV2, error: KitIntakeErrorV2) -> Fact {
    let name = error_name(error);
    assert_eq!(session.failure(), Some(error));
    assert_intake_absorbing(&mut session);
    drop(session);
    let wiped = wiped_bytes();
    assert!(wiped > 0);
    Fact {
        error: Some(name),
        ready: false,
        indices: [0; 2],
        screen: None,
        wiped,
    }
}

fn product_success(selector: u8) -> Fact {
    let door = if selector & 1 == 0 {
        KitDoorV2::KitRestore
    } else {
        KitDoorV2::KitSpend
    };
    let mode = if selector & 2 == 0 {
        KitInputModeV2::Scanner
    } else {
        KitInputModeV2::Fallback
    };
    let reversed = selector & 4 != 0;
    let order = if reversed { [2u8, 1u8] } else { [1, 2] };
    let mut core = open_core(u32::from(selector));
    let mut session =
        KitIntakeSessionV2::begin_in_core(&mut core, door, mode).expect("typed product intake");
    assert_eq!(core.current_screen(), Some(CoreScreen::ScanKitShareOne));

    let outcome = match mode {
        KitInputModeV2::Scanner => {
            let first = frame(order[0]);
            load_ingress(&mut core, Source::CameraKitCandidate, &first);
            assert!(matches!(
                session.submit_scanner_from_core(&mut core),
                Ok(KitIntakeOutcomeV2::FirstShareAccepted(_))
            ));
            assert_eq!(core.current_screen(), Some(CoreScreen::ScanKitShareTwo));
            let second = frame(order[1]);
            load_ingress(&mut core, Source::CameraKitCandidate, &second);
            session.submit_scanner_from_core(&mut core)
        }
        KitInputModeV2::Fallback => {
            enter_fallback_from_core(&mut session, &mut core, &fallback(order[0]));
            assert!(matches!(
                session.apply_fallback_key_from_core(&mut core, KeypadKey::EqualsConfirmEnter),
                Ok(KitIntakeOutcomeV2::FirstShareAccepted(_))
            ));
            assert_eq!(core.current_screen(), Some(CoreScreen::ScanKitShareTwo));
            enter_fallback_from_core(&mut session, &mut core, &fallback(order[1]));
            session.apply_fallback_key_from_core(&mut core, KeypadKey::EqualsConfirmEnter)
        }
    };
    let KitIntakeOutcomeV2::Ready(ready) = outcome.expect("registered opposite-index pair") else {
        panic!("second share must release readiness");
    };
    assert_eq!(ready.door(), door);
    assert_eq!(ready.mode(), mode);
    assert_eq!(
        ready
            .frame_identities()
            .map(|identity| identity.share_index().as_u8()),
        order
    );
    assert_eq!(core.current_screen(), Some(CoreScreen::CombineKitShares));
    assert_intake_absorbing(&mut session);
    drop(ready);
    drop(session);
    let screen = core.current_screen();
    drop(core);
    let wiped = wiped_bytes();
    assert!(wiped > 0);
    Fact {
        error: None,
        ready: true,
        indices: order,
        screen,
        wiped,
    }
}

fn product_wrong_source(selector: u8) -> Fact {
    let mut core = open_core(u32::from(selector));
    let mut session = KitIntakeSessionV2::begin_in_core(
        &mut core,
        KitDoorV2::KitRestore,
        KitInputModeV2::Scanner,
    )
    .expect("product intake");
    load_ingress(&mut core, Source::CameraBbqrPsbt, &frame(1));
    let error = session
        .submit_scanner_from_core(&mut core)
        .err()
        .expect("wrong broker source terminates");
    assert_eq!(error, KitIntakeErrorV2::WrongIngressSource);
    assert_eq!(core.terminal_reason(), Some(Interruption::OperationFailed));
    assert_core_absorbing(&mut core);
    assert_intake_absorbing(&mut session);
    drop(core);
    drop(session);
    let wiped = wiped_bytes();
    assert!(wiped > 0);
    Fact {
        error: Some(error_name(error)),
        ready: false,
        indices: [0; 2],
        screen: None,
        wiped,
    }
}

fn product_source_one_use(selector: u8) -> Fact {
    let mut core = open_core(u32::from(selector));
    let mut session =
        KitIntakeSessionV2::begin_in_core(&mut core, KitDoorV2::KitSpend, KitInputModeV2::Scanner)
            .expect("product intake");
    load_ingress(&mut core, Source::CameraKitCandidate, &frame(1));
    assert!(matches!(
        session.submit_scanner_from_core(&mut core),
        Ok(KitIntakeOutcomeV2::FirstShareAccepted(_))
    ));
    let error = session
        .submit_scanner_from_core(&mut core)
        .err()
        .expect("source-02 transfer is one-use");
    assert_eq!(
        error,
        KitIntakeErrorV2::Interrupted(Interruption::OperationFailed)
    );
    assert_core_absorbing(&mut core);
    assert_intake_absorbing(&mut session);
    drop(core);
    drop(session);
    let wiped = wiped_bytes();
    assert!(wiped > 0);
    Fact {
        error: Some(error_name(error)),
        ready: false,
        indices: [0; 2],
        screen: None,
        wiped,
    }
}

fn malformed_frame(case: u8) -> Fact {
    let mut session = KitIntakeSessionV2::begin(KitDoorV2::KitRestore, KitInputModeV2::Scanner);
    let mut candidate = frame(1);
    match case % 4 {
        0 => candidate[FRAME_BYTES - 1] ^= 1,
        1 => {
            candidate[0] ^= 1;
            rewrite_checksum(&mut candidate);
        }
        2 => {
            candidate[4] = 2;
            rewrite_checksum(&mut candidate);
        }
        3 => {
            candidate[5] = 0;
            rewrite_checksum(&mut candidate);
        }
        _ => unreachable!(),
    }
    let error = session
        .submit_scanner_frame(&mut candidate)
        .err()
        .expect("malformed frame rejects");
    assert_eq!(candidate, [0; FRAME_BYTES]);
    let expected = match case % 4 {
        0 => "FrameChecksum",
        1 => "InvalidMagic",
        2 => "UnsupportedVersion",
        3 => "InvalidShareIndex",
        _ => unreachable!(),
    };
    assert_eq!(error_name(error), expected);
    failure_fact(session, error)
}

fn pair_rejection(case: u8) -> Fact {
    let mut session = KitIntakeSessionV2::begin(KitDoorV2::KitSpend, KitInputModeV2::Scanner);
    let mut first = frame(1);
    assert!(matches!(
        session.submit_scanner_frame(&mut first),
        Ok(KitIntakeOutcomeV2::FirstShareAccepted(_))
    ));
    let mut second = match case % 3 {
        0 => frame(1),
        1 => {
            let mut value = frame(1);
            value[38] ^= 1;
            rewrite_checksum(&mut value);
            value
        }
        2 => {
            let mut value = frame(2);
            value[6] ^= 1;
            rewrite_checksum(&mut value);
            value
        }
        _ => unreachable!(),
    };
    let error = session
        .submit_scanner_frame(&mut second)
        .err()
        .expect("invalid pair rejects");
    assert_eq!(second, [0; FRAME_BYTES]);
    let expected = match case % 3 {
        0 => "DuplicateShare",
        1 => "SameShareIndex",
        2 => "WalletMismatch",
        _ => unreachable!(),
    };
    assert_eq!(error_name(error), expected);
    failure_fact(session, error)
}

fn fallback_rejection(case: u8) -> Fact {
    let mut session = KitIntakeSessionV2::begin(KitDoorV2::KitRestore, KitInputModeV2::Fallback);
    let error = match case % 8 {
        0 => session
            .apply_fallback_key(KeypadKey::Nine)
            .err()
            .expect("invalid row"),
        1 => {
            session.apply_fallback_key(KeypadKey::One).expect("row");
            session
                .apply_fallback_key(KeypadKey::Nine)
                .err()
                .expect("invalid column")
        }
        2 => session
            .apply_fallback_key(KeypadKey::CeDelete)
            .err()
            .expect("empty delete"),
        3 => session
            .apply_fallback_key(KeypadKey::EqualsConfirmEnter)
            .err()
            .expect("incomplete fallback"),
        4 => {
            session.apply_fallback_key(KeypadKey::One).expect("row");
            session
                .apply_fallback_key(KeypadKey::EqualsConfirmEnter)
                .err()
                .expect("pending coordinate")
        }
        5 => {
            enter_fallback(&mut session, &fallback(1));
            session.apply_fallback_key(KeypadKey::One).expect("row");
            session
                .apply_fallback_key(KeypadKey::One)
                .err()
                .expect("full fallback")
        }
        6 => {
            let mut symbols = fallback(1);
            symbols[0] = if symbols[0] == b'2' { b'3' } else { b'2' };
            enter_fallback(&mut session, &symbols);
            session
                .apply_fallback_key(KeypadKey::EqualsConfirmEnter)
                .err()
                .expect("fallback frame checksum")
        }
        7 => {
            let mut symbols = fallback(1);
            symbols[FALLBACK_SYMBOLS - 1] = b'3';
            enter_fallback(&mut session, &symbols);
            session
                .apply_fallback_key(KeypadKey::EqualsConfirmEnter)
                .err()
                .expect("noncanonical pad bits")
        }
        _ => unreachable!(),
    };
    failure_fact(session, error)
}

fn coordinate_matrix() -> Fact {
    let mut session = KitIntakeSessionV2::begin(KitDoorV2::KitSpend, KitInputModeV2::Fallback);
    assert_eq!(
        session.screen().expect("screen").fallback_table(),
        &KIT_FALLBACK_TABLE_V2
    );
    for row in 1..=4 {
        for column in 1..=8 {
            let start = session
                .screen()
                .expect("active fallback")
                .fallback()
                .committed_symbols();
            assert!(matches!(
                session.apply_fallback_key(coordinate_key(row)),
                Ok(KitIntakeOutcomeV2::Continue(_))
            ));
            assert!(matches!(
                session.apply_fallback_key(coordinate_key(column)),
                Ok(KitIntakeOutcomeV2::Continue(_))
            ));
            assert_eq!(
                session
                    .screen()
                    .expect("active fallback")
                    .fallback()
                    .committed_symbols(),
                start + 1
            );
            assert!(matches!(
                session.apply_fallback_key(KeypadKey::CeDelete),
                Ok(KitIntakeOutcomeV2::Continue(_))
            ));
            assert_eq!(
                session
                    .screen()
                    .expect("active fallback")
                    .fallback()
                    .committed_symbols(),
                start
            );
        }
    }
    drop(session);
    let wiped = wiped_bytes();
    assert!(wiped > 0);
    Fact {
        error: None,
        ready: false,
        indices: [0; 2],
        screen: Some(CoreScreen::ScanKitShareOne),
        wiped,
    }
}

fn transition_rejection(selector: u8, data: &[u8]) -> Fact {
    let mut session = match selector % 6 {
        1 => KitIntakeSessionV2::begin(KitDoorV2::KitRestore, KitInputModeV2::Fallback),
        _ => KitIntakeSessionV2::begin(KitDoorV2::KitRestore, KitInputModeV2::Scanner),
    };
    let error = match selector % 6 {
        0 => session
            .apply_fallback_key(KeypadKey::One)
            .err()
            .expect("fallback key in scanner"),
        1 => {
            let mut candidate = frame(1);
            let error = session
                .submit_scanner_frame(&mut candidate)
                .err()
                .expect("scanner bytes in fallback");
            assert_eq!(candidate, [0; FRAME_BYTES]);
            error
        }
        2 => session
            .select_mode(KitInputModeV2::Scanner)
            .err()
            .expect("mode immutable"),
        3 => session
            .reselect_door(KitDoorV2::KitSpend)
            .err()
            .expect("door immutable"),
        4 => {
            let foreign = match data.get(1).copied().unwrap_or(0) % 11 {
                0 => KitForeignInputV2::Image,
                1 => KitForeignInputV2::Camera,
                2 => KitForeignInputV2::A1,
                3 => KitForeignInputV2::Psbt,
                4 => KitForeignInputV2::BbqrTransaction,
                5 => KitForeignInputV2::Coordinator,
                6 => KitForeignInputV2::Transport,
                7 => KitForeignInputV2::GenericIntake,
                8 => KitForeignInputV2::QrWrapper,
                9 => KitForeignInputV2::ModeSelection,
                10 => KitForeignInputV2::Other,
                _ => unreachable!(),
            };
            session
                .reject_foreign_input(foreign)
                .err()
                .expect("foreign representation")
        }
        5 => session
            .apply_fallback_key(KeypadKey::CancelBack)
            .err()
            .expect("red C cancels"),
        _ => unreachable!(),
    };
    failure_fact(session, error)
}

fn interruption(selector: u8) -> Fact {
    let mut session = KitIntakeSessionV2::begin(KitDoorV2::KitSpend, KitInputModeV2::Fallback);
    append_symbol(&mut session, fallback(1)[0]);
    let reason = INTERRUPTIONS[usize::from(selector % 10)];
    let error = session
        .interrupt(reason)
        .err()
        .expect("closed interruption");
    assert_eq!(error, KitIntakeErrorV2::Interrupted(reason));
    failure_fact(session, error)
}

fn drive(data: &[u8]) -> Fact {
    reset_wiped_bytes();
    let selector = data.first().copied().unwrap_or(0);
    match selector % 48 {
        0..=7 => product_success(selector),
        8 => product_wrong_source(selector),
        9 => product_source_one_use(selector),
        10..=13 => malformed_frame(selector - 10),
        14..=16 => pair_rejection(selector - 14),
        17..=24 => fallback_rejection(selector - 17),
        25 => coordinate_matrix(),
        26..=31 => transition_rejection(selector - 26, data),
        32..=41 => interruption(selector - 32),
        42..=47 => transition_rejection(selector - 42, data),
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
