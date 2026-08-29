//! V2 slice-9 mode-locked Kit intake behavior.

use qk_host_sim::{
    FlowApplyOutcomeV2, FlowEventV2, FlowKindV2, FlowTerminalV2, KeypadKey, KitDoorV2,
    KitForeignInputV2, KitInputModeV2, KitIntakeErrorV2, KitIntakeInterruptionV2,
    KitIntakeOutcomeV2, KitIntakeSessionV2, KitShareOrdinalV2, ScreenFlowV2, ScreenKindV2,
    WipingReasonV2, KIT_FALLBACK_TABLE_V2,
};
use qk_kit::{encode_frame, KitError, ShareIndex, FALLBACK_SYMBOLS, FRAME_LEN};

const FIXTURE: &str = include_str!("../../qk-kit/tests/fixtures/kit_share_v2.txt");
const EXPECTED_FALLBACK_TABLE: [[u8; 8]; 4] =
    [*b"23456789", *b"abcdefgh", *b"ijkmnpqr", *b"stuvwxyz"];

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

fn fallback(number: u8) -> [u8; FALLBACK_SYMBOLS] {
    field(&format!("fallback_{number}_ascii"))
        .as_bytes()
        .try_into()
        .expect("exact fixture fallback width")
}

fn wallet_id() -> [u8; 32] {
    hex_array(field("wallet_id_hex"))
}

fn root_continue(flow: &mut ScreenFlowV2, event: FlowEventV2<'_>, expected: ScreenKindV2) {
    assert!(matches!(
        flow.apply(event).expect("active v2 flow"),
        FlowApplyOutcomeV2::Continue(actual) if actual == expected
    ));
}

fn flow_at_share_one(door: KitDoorV2) -> ScreenFlowV2 {
    let mut flow = ScreenFlowV2::new(FlowKindV2::Kit);
    root_continue(
        &mut flow,
        FlowEventV2::Key(KeypadKey::EqualsConfirmEnter),
        ScreenKindV2::KitDoorSelection,
    );
    root_continue(
        &mut flow,
        FlowEventV2::SelectKitDoor(door),
        ScreenKindV2::KitDoorConfirmation,
    );
    root_continue(
        &mut flow,
        FlowEventV2::ConfirmKitDoor(door),
        ScreenKindV2::ScanKitShareOne,
    );
    flow
}

fn first_accepted(outcome: KitIntakeOutcomeV2) {
    let KitIntakeOutcomeV2::FirstShareAccepted(screen) = outcome else {
        panic!("first share must not release payload");
    };
    assert_eq!(screen.page(), KitShareOrdinalV2::Two);
    assert_eq!(screen.fallback().committed_symbols(), 0);
}

fn expected_next(door: KitDoorV2) -> ScreenKindV2 {
    match door {
        KitDoorV2::KitSpend => ScreenKindV2::KitSpendTransaction,
        KitDoorV2::KitRestore => ScreenKindV2::KitRestoreActionSelection,
    }
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
        _ => panic!("single decimal digit"),
    }
}

fn append_fallback_symbol(session: &mut KitIntakeSessionV2, symbol: u8, expected_count: usize) {
    let (row, column) = EXPECTED_FALLBACK_TABLE
        .iter()
        .enumerate()
        .find_map(|(row, symbols)| {
            symbols
                .iter()
                .position(|candidate| *candidate == symbol)
                .map(|column| (row + 1, column + 1))
        })
        .unwrap_or_else(|| panic!("symbol outside exact fallback alphabet: {symbol}"));
    let KitIntakeOutcomeV2::Continue(screen) = session
        .apply_fallback_key(numeric_key(row as u8))
        .expect("valid fallback row")
    else {
        panic!("row selection must retain current screen");
    };
    assert_eq!(screen.fallback().pending_row(), Some(row as u8));
    assert_eq!(screen.fallback().committed_symbols(), expected_count);

    let KitIntakeOutcomeV2::Continue(screen) = session
        .apply_fallback_key(numeric_key(column as u8))
        .expect("valid fallback column")
    else {
        panic!("coordinate completion must retain current screen");
    };
    assert_eq!(screen.fallback().pending_row(), None);
    assert_eq!(screen.fallback().committed_symbols(), expected_count + 1);
    let progress = screen.fallback();
    if expected_count + 1 == FALLBACK_SYMBOLS {
        assert_eq!(progress.next_line(), None);
        assert_eq!(progress.next_column(), None);
    } else {
        assert_eq!(
            progress.next_line(),
            Some(((expected_count + 1) / 57 + 1) as u8)
        );
        assert_eq!(
            progress.next_column(),
            Some(((expected_count + 1) % 57 + 1) as u8)
        );
    }
}

fn enter_fallback_without_submit(session: &mut KitIntakeSessionV2, symbols: &[u8; 228]) {
    for (index, symbol) in symbols.iter().copied().enumerate() {
        append_fallback_symbol(session, symbol, index);
    }
}

fn submit_fallback(
    session: &mut KitIntakeSessionV2,
    symbols: &[u8; 228],
) -> Result<KitIntakeOutcomeV2, KitIntakeErrorV2> {
    enter_fallback_without_submit(session, symbols);
    session.apply_fallback_key(KeypadKey::EqualsConfirmEnter)
}

#[test]
fn scanner_accepts_both_doors_and_both_presentation_orders() {
    for door in [KitDoorV2::KitSpend, KitDoorV2::KitRestore] {
        for order in [[1u8, 2u8], [2, 1]] {
            let mut session =
                KitIntakeSessionV2::begin(flow_at_share_one(door), KitInputModeV2::Scanner)
                    .expect("typed Kit start");
            let initial = session.screen().expect("share-one screen");
            assert_eq!(initial.door(), door);
            assert_eq!(initial.mode(), KitInputModeV2::Scanner);
            assert_eq!(initial.page(), KitShareOrdinalV2::One);

            let mut first = frame(order[0]);
            first_accepted(
                session
                    .submit_scanner_frame(&mut first)
                    .expect("first canonical frame"),
            );
            assert_eq!(first, [0u8; FRAME_LEN]);

            let mut second = frame(order[1]);
            let KitIntakeOutcomeV2::Ready(ready) = session
                .submit_scanner_frame(&mut second)
                .expect("opposite same-wallet frame")
            else {
                panic!("second canonical frame must release ready owner");
            };
            assert_eq!(second, [0u8; FRAME_LEN]);
            assert_eq!(ready.door(), door);
            assert_eq!(ready.mode(), KitInputModeV2::Scanner);
            assert_eq!(ready.wallet_id(), wallet_id());
            assert_eq!(ready.next_screen(), expected_next(door));
            let identities = ready.frame_identities();
            assert_eq!(identities[0].share_index().as_u8(), order[0]);
            assert_eq!(identities[1].share_index().as_u8(), order[1]);
            assert_eq!(identities[0].wallet_id(), wallet_id());
            assert_eq!(identities[1].wallet_id(), wallet_id());
            let expected_checksum: [u8; 8] = frame(order[0])[FRAME_LEN - 8..]
                .try_into()
                .expect("eight checksum bytes");
            assert_eq!(identities[0].checksum(), expected_checksum);
            assert_eq!(session.screen(), None);
            assert_eq!(session.failure(), None);
        }
    }
}

#[test]
fn scanner_codec_and_pair_rejections_are_named_terminal_and_clear_callers() {
    let mut session = KitIntakeSessionV2::begin(
        flow_at_share_one(KitDoorV2::KitSpend),
        KitInputModeV2::Scanner,
    )
    .unwrap();
    let mut checksum_bad = frame(1);
    checksum_bad[FRAME_LEN - 1] ^= 1;
    assert_eq!(
        session.submit_scanner_frame(&mut checksum_bad).err(),
        Some(KitIntakeErrorV2::Codec(KitError::FrameChecksum))
    );
    assert_eq!(checksum_bad, [0u8; FRAME_LEN]);
    assert_eq!(
        session.terminal(),
        Some(FlowTerminalV2::FailedWiped(WipingReasonV2::OperationFailed))
    );

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
        let mut session = KitIntakeSessionV2::begin(
            flow_at_share_one(KitDoorV2::KitRestore),
            KitInputModeV2::Scanner,
        )
        .unwrap();
        let mut first = frame(1);
        first_accepted(session.submit_scanner_frame(&mut first).unwrap());
        let mut candidate = second;
        assert_eq!(
            session.submit_scanner_frame(&mut candidate).err(),
            Some(KitIntakeErrorV2::Codec(expected))
        );
        assert_eq!(candidate, [0u8; FRAME_LEN]);
        assert_eq!(session.failure(), Some(KitIntakeErrorV2::Codec(expected)));
        assert_eq!(
            session.terminal(),
            Some(FlowTerminalV2::FailedWiped(WipingReasonV2::OperationFailed))
        );

        let mut post_failure = frame(2);
        assert_eq!(
            session.submit_scanner_frame(&mut post_failure).err(),
            Some(KitIntakeErrorV2::Finished)
        );
        assert_eq!(post_failure, [0u8; FRAME_LEN]);
    }
}

#[test]
fn scanner_mode_rejects_every_foreign_representation_at_both_pages() {
    let foreign = [
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
    ];
    for second_page in [false, true] {
        for input in foreign {
            let mut session = KitIntakeSessionV2::begin(
                flow_at_share_one(KitDoorV2::KitSpend),
                KitInputModeV2::Scanner,
            )
            .unwrap();
            if second_page {
                let mut first = frame(1);
                first_accepted(session.submit_scanner_frame(&mut first).unwrap());
            }
            assert_eq!(
                session.reject_foreign_input(input).err(),
                Some(KitIntakeErrorV2::KitScannerModeMismatch)
            );
            assert_eq!(
                session.terminal(),
                Some(FlowTerminalV2::FailedWiped(
                    WipingReasonV2::KitScannerModeMismatch
                ))
            );
        }
    }
}

#[test]
fn mode_and_door_are_immutable_with_distinct_terminal_reasons() {
    let mut mode = KitIntakeSessionV2::begin(
        flow_at_share_one(KitDoorV2::KitSpend),
        KitInputModeV2::Scanner,
    )
    .unwrap();
    assert_eq!(
        mode.select_mode(KitInputModeV2::Fallback).err(),
        Some(KitIntakeErrorV2::KitScannerModeMismatch)
    );
    assert_eq!(
        mode.terminal(),
        Some(FlowTerminalV2::FailedWiped(
            WipingReasonV2::KitScannerModeMismatch
        ))
    );

    let mut door = KitIntakeSessionV2::begin(
        flow_at_share_one(KitDoorV2::KitSpend),
        KitInputModeV2::Scanner,
    )
    .unwrap();
    assert_eq!(
        door.reselect_door(KitDoorV2::KitRestore).err(),
        Some(KitIntakeErrorV2::DoorSwitchAttempt)
    );
    assert_eq!(
        door.terminal(),
        Some(FlowTerminalV2::FailedWiped(
            WipingReasonV2::DoorSwitchAttempt
        ))
    );
}

#[test]
fn scanner_interruptions_are_closed_at_each_share_screen() {
    let cases = [
        (
            KitIntakeInterruptionV2::Cancelled,
            KitIntakeErrorV2::Cancelled,
            WipingReasonV2::Cancelled,
        ),
        (
            KitIntakeInterruptionV2::OperationFailed,
            KitIntakeErrorV2::OperationFailed,
            WipingReasonV2::OperationFailed,
        ),
        (
            KitIntakeInterruptionV2::MediaRemoved,
            KitIntakeErrorV2::MediaRemoved,
            WipingReasonV2::MediaRemoved,
        ),
        (
            KitIntakeInterruptionV2::CardRemoved,
            KitIntakeErrorV2::CardRemoved,
            WipingReasonV2::CardRemoved,
        ),
        (
            KitIntakeInterruptionV2::SessionTimeout,
            KitIntakeErrorV2::SessionTimeout,
            WipingReasonV2::SessionTimeout,
        ),
        (
            KitIntakeInterruptionV2::Shutdown,
            KitIntakeErrorV2::Shutdown,
            WipingReasonV2::Shutdown,
        ),
        (
            KitIntakeInterruptionV2::Restart,
            KitIntakeErrorV2::Restart,
            WipingReasonV2::Restart,
        ),
        (
            KitIntakeInterruptionV2::PowerLoss,
            KitIntakeErrorV2::PowerLoss,
            WipingReasonV2::PowerLoss,
        ),
    ];
    for second_page in [false, true] {
        for (event, expected_error, expected_reason) in cases {
            let mut session = KitIntakeSessionV2::begin(
                flow_at_share_one(KitDoorV2::KitRestore),
                KitInputModeV2::Scanner,
            )
            .unwrap();
            if second_page {
                let mut first = frame(1);
                first_accepted(session.submit_scanner_frame(&mut first).unwrap());
            }
            assert_eq!(session.interrupt(event).err(), Some(expected_error));
            assert_eq!(
                session.terminal(),
                Some(FlowTerminalV2::FailedWiped(expected_reason))
            );
        }
    }
}

#[test]
fn invalid_start_is_named_and_cannot_release_a_session() {
    assert!(matches!(
        KitIntakeSessionV2::begin(ScreenFlowV2::new(FlowKindV2::Kit), KitInputModeV2::Scanner),
        Err(KitIntakeErrorV2::InvalidStart)
    ));
    assert!(matches!(
        KitIntakeSessionV2::begin(ScreenFlowV2::new(FlowKindV2::A1B), KitInputModeV2::Scanner),
        Err(KitIntakeErrorV2::InvalidStart)
    ));
}

#[test]
fn fixture_helpers_cover_exact_registered_input_widths() {
    assert_eq!(frame(1).len(), FRAME_LEN);
    assert_eq!(frame(2).len(), FRAME_LEN);
    assert_eq!(fallback(1).len(), FALLBACK_SYMBOLS);
    assert_eq!(fallback(2).len(), FALLBACK_SYMBOLS);
}

#[test]
fn fallback_accepts_both_doors_orders_and_all_coordinate_positions() {
    assert_eq!(KIT_FALLBACK_TABLE_V2, EXPECTED_FALLBACK_TABLE);
    let mut seen = [false; 32];
    for symbol in fallback(1).into_iter().chain(fallback(2)) {
        let position = EXPECTED_FALLBACK_TABLE
            .iter()
            .flatten()
            .position(|candidate| *candidate == symbol)
            .expect("fixture symbol in exact table");
        seen[position] = true;
    }
    assert!(seen.into_iter().all(|value| value));

    for door in [KitDoorV2::KitSpend, KitDoorV2::KitRestore] {
        for order in [[1u8, 2u8], [2, 1]] {
            let mut session =
                KitIntakeSessionV2::begin(flow_at_share_one(door), KitInputModeV2::Fallback)
                    .unwrap();
            let initial = session.screen().unwrap();
            assert_eq!(initial.fallback_table(), &EXPECTED_FALLBACK_TABLE);
            assert_eq!(initial.fallback().next_line(), Some(1));
            assert_eq!(initial.fallback().next_column(), Some(1));

            let first = fallback(order[0]);
            first_accepted(submit_fallback(&mut session, &first).unwrap());
            let second = fallback(order[1]);
            let KitIntakeOutcomeV2::Ready(ready) = submit_fallback(&mut session, &second).unwrap()
            else {
                panic!("second fallback must release ready owner");
            };
            assert_eq!(ready.door(), door);
            assert_eq!(ready.mode(), KitInputModeV2::Fallback);
            assert_eq!(ready.wallet_id(), wallet_id());
            assert_eq!(ready.next_screen(), expected_next(door));
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
fn fallback_progress_and_ce_boundaries_are_exact() {
    let mut session = KitIntakeSessionV2::begin(
        flow_at_share_one(KitDoorV2::KitSpend),
        KitInputModeV2::Fallback,
    )
    .unwrap();
    let symbols = fallback(1);
    for (index, symbol) in symbols[..57].iter().copied().enumerate() {
        append_fallback_symbol(&mut session, symbol, index);
    }
    let progress = session.screen().unwrap().fallback();
    assert_eq!(progress.committed_symbols(), 57);
    assert_eq!(progress.next_line(), Some(2));
    assert_eq!(progress.next_column(), Some(1));

    assert!(matches!(
        session.apply_fallback_key(KeypadKey::One).unwrap(),
        KitIntakeOutcomeV2::Continue(_)
    ));
    assert_eq!(session.screen().unwrap().fallback().pending_row(), Some(1));
    assert!(matches!(
        session.apply_fallback_key(KeypadKey::CeDelete).unwrap(),
        KitIntakeOutcomeV2::Continue(_)
    ));
    assert_eq!(session.screen().unwrap().fallback().pending_row(), None);
    assert_eq!(session.screen().unwrap().fallback().committed_symbols(), 57);

    assert!(matches!(
        session.apply_fallback_key(KeypadKey::CeDelete).unwrap(),
        KitIntakeOutcomeV2::Continue(_)
    ));
    let progress = session.screen().unwrap().fallback();
    assert_eq!(progress.committed_symbols(), 56);
    assert_eq!(progress.next_line(), Some(1));
    assert_eq!(progress.next_column(), Some(57));
}

#[test]
fn every_fallback_entry_rejection_is_distinct_terminal_and_non_retrying() {
    let invalid_rows = [
        KeypadKey::Five,
        KeypadKey::SixRight,
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
    for key in invalid_rows {
        let mut session = KitIntakeSessionV2::begin(
            flow_at_share_one(KitDoorV2::KitSpend),
            KitInputModeV2::Fallback,
        )
        .unwrap();
        assert_eq!(
            session.apply_fallback_key(key).err(),
            Some(KitIntakeErrorV2::InvalidFallbackRow)
        );
        assert_eq!(session.screen(), None);
        assert_eq!(
            session.terminal(),
            Some(FlowTerminalV2::FailedWiped(WipingReasonV2::OperationFailed))
        );
        assert_eq!(
            session.apply_fallback_key(KeypadKey::One).err(),
            Some(KitIntakeErrorV2::Finished)
        );
    }

    for key in [
        KeypadKey::Nine,
        KeypadKey::Zero,
        KeypadKey::Decimal,
        KeypadKey::Plus,
        KeypadKey::Minus,
        KeypadKey::Multiply,
        KeypadKey::Divide,
        KeypadKey::Percent,
    ] {
        let mut session = KitIntakeSessionV2::begin(
            flow_at_share_one(KitDoorV2::KitRestore),
            KitInputModeV2::Fallback,
        )
        .unwrap();
        session.apply_fallback_key(KeypadKey::One).unwrap();
        assert_eq!(
            session.apply_fallback_key(key).err(),
            Some(KitIntakeErrorV2::InvalidFallbackColumn)
        );
    }

    let mut empty_delete = KitIntakeSessionV2::begin(
        flow_at_share_one(KitDoorV2::KitSpend),
        KitInputModeV2::Fallback,
    )
    .unwrap();
    assert_eq!(
        empty_delete.apply_fallback_key(KeypadKey::CeDelete).err(),
        Some(KitIntakeErrorV2::FallbackEmptyDelete)
    );

    let mut incomplete = KitIntakeSessionV2::begin(
        flow_at_share_one(KitDoorV2::KitSpend),
        KitInputModeV2::Fallback,
    )
    .unwrap();
    assert_eq!(
        incomplete
            .apply_fallback_key(KeypadKey::EqualsConfirmEnter)
            .err(),
        Some(KitIntakeErrorV2::FallbackIncomplete)
    );

    let mut pending = KitIntakeSessionV2::begin(
        flow_at_share_one(KitDoorV2::KitSpend),
        KitInputModeV2::Fallback,
    )
    .unwrap();
    pending.apply_fallback_key(KeypadKey::One).unwrap();
    assert_eq!(
        pending
            .apply_fallback_key(KeypadKey::EqualsConfirmEnter)
            .err(),
        Some(KitIntakeErrorV2::FallbackPendingCoordinate)
    );

    let mut full = KitIntakeSessionV2::begin(
        flow_at_share_one(KitDoorV2::KitSpend),
        KitInputModeV2::Fallback,
    )
    .unwrap();
    enter_fallback_without_submit(&mut full, &fallback(1));
    let progress = full.screen().unwrap().fallback();
    assert_eq!(progress.committed_symbols(), FALLBACK_SYMBOLS);
    assert_eq!(progress.next_line(), None);
    assert_eq!(progress.next_column(), None);
    assert_eq!(
        full.apply_fallback_key(KeypadKey::Nine).err(),
        Some(KitIntakeErrorV2::InvalidFallbackRow)
    );

    let mut full = KitIntakeSessionV2::begin(
        flow_at_share_one(KitDoorV2::KitSpend),
        KitInputModeV2::Fallback,
    )
    .unwrap();
    enter_fallback_without_submit(&mut full, &fallback(1));
    assert!(matches!(
        full.apply_fallback_key(KeypadKey::One).unwrap(),
        KitIntakeOutcomeV2::Continue(_)
    ));
    assert_eq!(
        full.apply_fallback_key(KeypadKey::Nine).err(),
        Some(KitIntakeErrorV2::InvalidFallbackColumn)
    );

    let mut full = KitIntakeSessionV2::begin(
        flow_at_share_one(KitDoorV2::KitSpend),
        KitInputModeV2::Fallback,
    )
    .unwrap();
    enter_fallback_without_submit(&mut full, &fallback(1));
    full.apply_fallback_key(KeypadKey::One).unwrap();
    assert_eq!(
        full.apply_fallback_key(KeypadKey::One).err(),
        Some(KitIntakeErrorV2::FallbackFull)
    );
}

#[test]
fn fallback_codec_rejection_and_cancel_are_terminal() {
    let mut bad_checksum = fallback(1);
    bad_checksum[0] = if bad_checksum[0] == b'2' { b'3' } else { b'2' };
    let mut session = KitIntakeSessionV2::begin(
        flow_at_share_one(KitDoorV2::KitSpend),
        KitInputModeV2::Fallback,
    )
    .unwrap();
    assert_eq!(
        submit_fallback(&mut session, &bad_checksum).err(),
        Some(KitIntakeErrorV2::Codec(KitError::FrameChecksum))
    );

    let mut bad_padding = fallback(1);
    bad_padding[FALLBACK_SYMBOLS - 1] = b'3';
    let mut session = KitIntakeSessionV2::begin(
        flow_at_share_one(KitDoorV2::KitRestore),
        KitInputModeV2::Fallback,
    )
    .unwrap();
    assert_eq!(
        submit_fallback(&mut session, &bad_padding).err(),
        Some(KitIntakeErrorV2::Codec(KitError::NonCanonicalPadding))
    );

    let mut cancelled = KitIntakeSessionV2::begin(
        flow_at_share_one(KitDoorV2::KitRestore),
        KitInputModeV2::Fallback,
    )
    .unwrap();
    append_fallback_symbol(&mut cancelled, fallback(1)[0], 0);
    assert_eq!(
        cancelled.apply_fallback_key(KeypadKey::CancelBack).err(),
        Some(KitIntakeErrorV2::Cancelled)
    );
    assert_eq!(
        cancelled.terminal(),
        Some(FlowTerminalV2::FailedWiped(WipingReasonV2::Cancelled))
    );
}

#[test]
fn modes_accept_only_their_selected_representation_at_both_pages() {
    let mut fallback_session = KitIntakeSessionV2::begin(
        flow_at_share_one(KitDoorV2::KitSpend),
        KitInputModeV2::Fallback,
    )
    .unwrap();
    let mut scanner_candidate = frame(1);
    assert_eq!(
        fallback_session
            .submit_scanner_frame(&mut scanner_candidate)
            .err(),
        Some(KitIntakeErrorV2::KitScannerModeMismatch)
    );
    assert_eq!(scanner_candidate, [0u8; FRAME_LEN]);

    for second_page in [false, true] {
        let mut fallback_session = KitIntakeSessionV2::begin(
            flow_at_share_one(KitDoorV2::KitRestore),
            KitInputModeV2::Fallback,
        )
        .unwrap();
        if second_page {
            first_accepted(submit_fallback(&mut fallback_session, &fallback(1)).unwrap());
        }
        assert_eq!(
            fallback_session
                .reject_foreign_input(KitForeignInputV2::Camera)
                .err(),
            Some(KitIntakeErrorV2::KitScannerModeMismatch)
        );
        assert_eq!(
            fallback_session.terminal(),
            Some(FlowTerminalV2::FailedWiped(
                WipingReasonV2::KitScannerModeMismatch
            ))
        );
    }

    for second_page in [false, true] {
        let mut scanner_session = KitIntakeSessionV2::begin(
            flow_at_share_one(KitDoorV2::KitSpend),
            KitInputModeV2::Scanner,
        )
        .unwrap();
        if second_page {
            let mut first = frame(1);
            first_accepted(scanner_session.submit_scanner_frame(&mut first).unwrap());
        }
        assert_eq!(
            scanner_session.apply_fallback_key(KeypadKey::One).err(),
            Some(KitIntakeErrorV2::KitScannerModeMismatch)
        );
        assert_eq!(
            scanner_session.terminal(),
            Some(FlowTerminalV2::FailedWiped(
                WipingReasonV2::KitScannerModeMismatch
            ))
        );
    }
}
