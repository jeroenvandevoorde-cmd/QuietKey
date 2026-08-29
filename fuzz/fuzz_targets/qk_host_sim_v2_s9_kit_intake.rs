#![no_main]

use libfuzzer_sys::fuzz_target;
use qk_host_sim::{
    FlowApplyOutcomeV2, FlowEventV2, FlowKindV2, FlowTerminalV2, KeypadKey, KitDoorV2,
    KitForeignInputV2, KitInputModeV2, KitIntakeErrorV2, KitIntakeInterruptionV2,
    KitIntakeOutcomeV2, KitIntakeSessionV2, ScreenFlowV2, ScreenKindV2, WipingReasonV2,
    KIT_FALLBACK_TABLE_V2,
};
use qk_kit::{
    encode_fallback, encode_frame, frame_metadata, ShareIndex, FALLBACK_SYMBOLS, FRAME_LEN,
};
use std::ptr;
use std::sync::atomic::{compiler_fence, Ordering};

#[allow(dead_code)]
#[path = "../../host/qk-psbt/src/sha256.rs"]
mod reference_sha256;

const MAX_PRESENTED_BYTES: usize = 512;
const SCENARIOS: u8 = 33;
const FRAME_PREFIX_LEN: usize = 134;
const CHECKSUM_DOMAIN: &[u8] = b"QuietKey/KitShare/v1";

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Summary {
    Ready {
        door: KitDoorV2,
        mode: KitInputModeV2,
        wallet_id: [u8; 32],
        indices: [u8; 2],
        next: ScreenKindV2,
    },
    Rejected {
        error: &'static str,
        terminal: Option<FlowTerminalV2>,
    },
    Dropped,
}

fn wipe(bytes: &mut [u8]) {
    for byte in bytes {
        // SAFETY: each byte is uniquely borrowed and live for this write.
        unsafe { ptr::write_volatile(byte, 0) };
    }
    compiler_fence(Ordering::SeqCst);
}

fn derive<const N: usize>(data: &[u8], domain: u8) -> [u8; N] {
    let mut output = [0u8; N];
    for (index, byte) in output.iter_mut().enumerate() {
        let source = data
            .get(index % data.len().max(1))
            .copied()
            .unwrap_or(index as u8);
        *byte = source
            .wrapping_add(domain)
            .wrapping_add((index as u8).wrapping_mul(37));
    }
    output
}

fn root_continue(flow: &mut ScreenFlowV2, event: FlowEventV2<'_>, expected: ScreenKindV2) {
    assert!(matches!(
        flow.apply(event).expect("active Kit topology"),
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

fn key(number: usize) -> KeypadKey {
    match number {
        1 => KeypadKey::One,
        2 => KeypadKey::TwoDown,
        3 => KeypadKey::Three,
        4 => KeypadKey::FourLeft,
        5 => KeypadKey::Five,
        6 => KeypadKey::SixRight,
        7 => KeypadKey::Seven,
        8 => KeypadKey::EightUp,
        _ => panic!("bounded coordinate digit"),
    }
}

fn append_symbol(session: &mut KitIntakeSessionV2, symbol: u8) {
    let before = session
        .screen()
        .expect("active fallback screen")
        .fallback()
        .committed_symbols();
    let position = KIT_FALLBACK_TABLE_V2
        .iter()
        .flatten()
        .position(|candidate| *candidate == symbol)
        .expect("encoder emits exact alphabet");
    let KitIntakeOutcomeV2::Continue(row_screen) =
        session.apply_fallback_key(key(position / 8 + 1)).unwrap()
    else {
        panic!("row key must retain the fallback screen");
    };
    assert_eq!(row_screen.fallback().committed_symbols(), before);
    assert_eq!(
        row_screen.fallback().pending_row(),
        Some((position / 8 + 1) as u8)
    );
    let KitIntakeOutcomeV2::Continue(column_screen) =
        session.apply_fallback_key(key(position % 8 + 1)).unwrap()
    else {
        panic!("column key must retain the fallback screen");
    };
    let progress = column_screen.fallback();
    assert_eq!(progress.committed_symbols(), before + 1);
    assert_eq!(progress.pending_row(), None);
    if before + 1 == FALLBACK_SYMBOLS {
        assert_eq!(progress.next_line(), None);
        assert_eq!(progress.next_column(), None);
    } else {
        assert_eq!(progress.next_line(), Some(((before + 1) / 57 + 1) as u8));
        assert_eq!(progress.next_column(), Some(((before + 1) % 57 + 1) as u8));
    }
}

fn enter_fallback(session: &mut KitIntakeSessionV2, symbols: &[u8; FALLBACK_SYMBOLS]) {
    for symbol in symbols {
        append_symbol(session, *symbol);
    }
}

fn expected_next(door: KitDoorV2) -> ScreenKindV2 {
    match door {
        KitDoorV2::KitSpend => ScreenKindV2::KitSpendTransaction,
        KitDoorV2::KitRestore => ScreenKindV2::KitRestoreActionSelection,
    }
}

fn ready(
    result: Result<KitIntakeOutcomeV2, KitIntakeErrorV2>,
    session: &KitIntakeSessionV2,
    door: KitDoorV2,
    mode: KitInputModeV2,
    wallet_id: [u8; 32],
    indices: [u8; 2],
    checksums: [[u8; 8]; 2],
) -> Summary {
    let KitIntakeOutcomeV2::Ready(ready) = result.expect("expected ready owner") else {
        panic!("premature non-ready outcome");
    };
    assert_eq!(ready.door(), door);
    assert_eq!(ready.mode(), mode);
    assert_eq!(ready.wallet_id(), wallet_id);
    let identities = ready.frame_identities();
    assert_eq!(
        identities.map(|identity| identity.share_index().as_u8()),
        indices
    );
    assert_eq!(
        identities.map(|identity| identity.wallet_id()),
        [wallet_id; 2]
    );
    assert_eq!(identities.map(|identity| identity.checksum()), checksums);
    assert_eq!(ready.next_screen(), expected_next(door));
    assert!(session.screen().is_none());
    assert_eq!(session.failure(), None);
    assert_eq!(session.terminal(), None);
    Summary::Ready {
        door,
        mode,
        wallet_id,
        indices,
        next: ready.next_screen(),
    }
}

fn rejected(
    result: Result<KitIntakeOutcomeV2, KitIntakeErrorV2>,
    session: &mut KitIntakeSessionV2,
    expected: &'static str,
    reason: WipingReasonV2,
) -> Summary {
    let error = result.err().expect("scenario must reject");
    assert_eq!(error.name(), expected);
    assert_eq!(error.to_string(), expected);
    assert!(session.screen().is_none());
    assert_eq!(session.failure(), Some(error));
    assert_eq!(
        session.terminal(),
        Some(FlowTerminalV2::FailedWiped(reason))
    );
    let terminal = session.terminal();
    let failure = session.failure();
    let mut post_rejection = [0xa5; FRAME_LEN];
    assert_eq!(
        session.submit_scanner_frame(&mut post_rejection).err(),
        Some(KitIntakeErrorV2::Finished)
    );
    assert_eq!(post_rejection, [0u8; FRAME_LEN]);
    assert_eq!(
        session.apply_fallback_key(KeypadKey::One).err(),
        Some(KitIntakeErrorV2::Finished)
    );
    assert_eq!(
        session.select_mode(KitInputModeV2::Scanner).err(),
        Some(KitIntakeErrorV2::Finished)
    );
    assert_eq!(
        session.reject_foreign_input(KitForeignInputV2::Other).err(),
        Some(KitIntakeErrorV2::Finished)
    );
    assert_eq!(
        session.reselect_door(KitDoorV2::KitSpend).err(),
        Some(KitIntakeErrorV2::Finished)
    );
    assert_eq!(
        session.interrupt(KitIntakeInterruptionV2::Cancelled).err(),
        Some(KitIntakeErrorV2::Finished)
    );
    assert_eq!(session.terminal(), terminal);
    assert_eq!(session.failure(), failure);
    Summary::Rejected {
        error: error.name(),
        terminal: session.terminal(),
    }
}

fn checksum(frame: &[u8; FRAME_LEN]) -> [u8; 8] {
    frame[FRAME_LEN - 8..]
        .try_into()
        .expect("fixed frame checksum width")
}

fn reference_checksum(prefix: &[u8]) -> [u8; 8] {
    assert_eq!(prefix.len(), FRAME_PREFIX_LEN);
    let mut hasher = reference_sha256::Sha256::new();
    hasher
        .update(CHECKSUM_DOMAIN)
        .expect("fixed checksum domain");
    hasher.update(&[0]).expect("fixed checksum separator");
    hasher.update(prefix).expect("bounded frame prefix");
    let digest = hasher.finalize().expect("bounded frame digest");
    digest[..8].try_into().expect("eight checksum bytes")
}

fn reference_reseal(frame: &mut [u8; FRAME_LEN]) {
    let digest = reference_checksum(&frame[..FRAME_PREFIX_LEN]);
    frame[FRAME_PREFIX_LEN..].copy_from_slice(&digest);
}

fn first_scanner(session: &mut KitIntakeSessionV2, frame: &mut [u8; FRAME_LEN]) {
    assert!(matches!(
        session.submit_scanner_frame(frame).unwrap(),
        KitIntakeOutcomeV2::FirstShareAccepted(_)
    ));
    assert_eq!(*frame, [0u8; FRAME_LEN]);
}

fn first_fallback(session: &mut KitIntakeSessionV2, symbols: &[u8; FALLBACK_SYMBOLS]) {
    enter_fallback(session, symbols);
    assert!(matches!(
        session
            .apply_fallback_key(KeypadKey::EqualsConfirmEnter)
            .unwrap(),
        KitIntakeOutcomeV2::FirstShareAccepted(_)
    ));
}

fn run(data: &[u8], scenario: u8) -> Summary {
    let door = if data.get(1).copied().unwrap_or(0) & 1 == 0 {
        KitDoorV2::KitSpend
    } else {
        KitDoorV2::KitRestore
    };
    let wallet_id = derive::<32>(data, 0x11);
    let other_wallet = derive::<32>(data, 0x91);
    let mut share_one = derive::<96>(data, 0x22);
    let mut share_two = derive::<96>(data, 0x44);
    let mut frame_one = encode_frame(ShareIndex::One, &wallet_id, &share_one);
    let mut frame_two = encode_frame(ShareIndex::Two, &wallet_id, &share_two);
    let frame_checksums = [checksum(&frame_one), checksum(&frame_two)];
    let mut fallback_one = [0u8; FALLBACK_SYMBOLS];
    let mut fallback_two = [0u8; FALLBACK_SYMBOLS];
    encode_fallback(&frame_one, &mut fallback_one).unwrap();
    encode_fallback(&frame_two, &mut fallback_two).unwrap();

    let summary = match scenario {
        0 | 1 => {
            let mut session =
                KitIntakeSessionV2::begin(flow_at_share_one(door), KitInputModeV2::Scanner)
                    .unwrap();
            let (first, second, order, checksums) = if scenario == 0 {
                (&mut frame_one, &mut frame_two, [1, 2], frame_checksums)
            } else {
                (
                    &mut frame_two,
                    &mut frame_one,
                    [2, 1],
                    [frame_checksums[1], frame_checksums[0]],
                )
            };
            first_scanner(&mut session, first);
            let result = session.submit_scanner_frame(second);
            assert_eq!(*second, [0u8; FRAME_LEN]);
            ready(
                result,
                &session,
                door,
                KitInputModeV2::Scanner,
                wallet_id,
                order,
                checksums,
            )
        }
        2 => {
            frame_one[FRAME_LEN - 1] ^= 1;
            let mut session =
                KitIntakeSessionV2::begin(flow_at_share_one(door), KitInputModeV2::Scanner)
                    .unwrap();
            let result = session.submit_scanner_frame(&mut frame_one);
            assert_eq!(frame_one, [0u8; FRAME_LEN]);
            rejected(
                result,
                &mut session,
                "FrameChecksum",
                WipingReasonV2::OperationFailed,
            )
        }
        3..=6 => {
            let mut session =
                KitIntakeSessionV2::begin(flow_at_share_one(door), KitInputModeV2::Scanner)
                    .unwrap();
            first_scanner(&mut session, &mut frame_one);
            let (mut candidate, expected) = match scenario {
                3 => {
                    frame_two[FRAME_LEN - 1] ^= 1;
                    (frame_two, "FrameChecksum")
                }
                4 => (
                    encode_frame(ShareIndex::One, &wallet_id, &share_one),
                    "DuplicateShare",
                ),
                5 => (
                    encode_frame(ShareIndex::One, &wallet_id, &share_two),
                    "SameShareIndex",
                ),
                6 => (
                    encode_frame(ShareIndex::Two, &other_wallet, &share_two),
                    "WalletMismatch",
                ),
                _ => unreachable!(),
            };
            let result = session.submit_scanner_frame(&mut candidate);
            assert_eq!(candidate, [0u8; FRAME_LEN]);
            rejected(
                result,
                &mut session,
                expected,
                WipingReasonV2::OperationFailed,
            )
        }
        7 | 8 => {
            let mut session =
                KitIntakeSessionV2::begin(flow_at_share_one(door), KitInputModeV2::Scanner)
                    .unwrap();
            if scenario == 8 {
                first_scanner(&mut session, &mut frame_one);
            }
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
            let selected = usize::from(data.get(2).copied().unwrap_or(0)) % foreign.len();
            let result = session.reject_foreign_input(foreign[selected]);
            rejected(
                result,
                &mut session,
                "KitScannerModeMismatch",
                WipingReasonV2::KitScannerModeMismatch,
            )
        }
        9 | 10 => {
            let mut session =
                KitIntakeSessionV2::begin(flow_at_share_one(door), KitInputModeV2::Scanner)
                    .unwrap();
            if scenario == 10 {
                first_scanner(&mut session, &mut frame_one);
            }
            let (event, expected, reason) = match data.get(2).copied().unwrap_or(0) % 8 {
                0 => (
                    KitIntakeInterruptionV2::Cancelled,
                    "Cancelled",
                    WipingReasonV2::Cancelled,
                ),
                1 => (
                    KitIntakeInterruptionV2::OperationFailed,
                    "OperationFailed",
                    WipingReasonV2::OperationFailed,
                ),
                2 => (
                    KitIntakeInterruptionV2::MediaRemoved,
                    "MediaRemoved",
                    WipingReasonV2::MediaRemoved,
                ),
                3 => (
                    KitIntakeInterruptionV2::CardRemoved,
                    "CardRemoved",
                    WipingReasonV2::CardRemoved,
                ),
                4 => (
                    KitIntakeInterruptionV2::SessionTimeout,
                    "SessionTimeout",
                    WipingReasonV2::SessionTimeout,
                ),
                5 => (
                    KitIntakeInterruptionV2::Shutdown,
                    "Shutdown",
                    WipingReasonV2::Shutdown,
                ),
                6 => (
                    KitIntakeInterruptionV2::Restart,
                    "Restart",
                    WipingReasonV2::Restart,
                ),
                _ => (
                    KitIntakeInterruptionV2::PowerLoss,
                    "PowerLoss",
                    WipingReasonV2::PowerLoss,
                ),
            };
            let result = session.interrupt(event);
            rejected(result, &mut session, expected, reason)
        }
        11 => {
            let mut session =
                KitIntakeSessionV2::begin(flow_at_share_one(door), KitInputModeV2::Fallback)
                    .unwrap();
            if data.get(2).copied().unwrap_or(0) & 1 != 0 {
                first_fallback(&mut session, &fallback_one);
            }
            let candidate = if session
                .screen()
                .is_some_and(|screen| screen.page() == qk_host_sim::KitShareOrdinalV2::Two)
            {
                &mut frame_two
            } else {
                &mut frame_one
            };
            if data.get(3).copied().unwrap_or(0) & 1 != 0 {
                candidate[FRAME_LEN - 1] ^= 1;
            }
            let result = session.submit_scanner_frame(candidate);
            assert_eq!(*candidate, [0u8; FRAME_LEN]);
            rejected(
                result,
                &mut session,
                "KitScannerModeMismatch",
                WipingReasonV2::KitScannerModeMismatch,
            )
        }
        12 | 13 => {
            let mut session =
                KitIntakeSessionV2::begin(flow_at_share_one(door), KitInputModeV2::Fallback)
                    .unwrap();
            let (first, second, order, checksums) = if scenario == 12 {
                (&fallback_one, &fallback_two, [1, 2], frame_checksums)
            } else {
                (
                    &fallback_two,
                    &fallback_one,
                    [2, 1],
                    [frame_checksums[1], frame_checksums[0]],
                )
            };
            first_fallback(&mut session, first);
            enter_fallback(&mut session, second);
            ready(
                session.apply_fallback_key(KeypadKey::EqualsConfirmEnter),
                &session,
                door,
                KitInputModeV2::Fallback,
                wallet_id,
                order,
                checksums,
            )
        }
        14 => {
            let mut session =
                KitIntakeSessionV2::begin(flow_at_share_one(door), KitInputModeV2::Fallback)
                    .unwrap();
            let result = session.apply_fallback_key(KeypadKey::Nine);
            rejected(
                result,
                &mut session,
                "InvalidFallbackRow",
                WipingReasonV2::OperationFailed,
            )
        }
        15 => {
            let mut session =
                KitIntakeSessionV2::begin(flow_at_share_one(door), KitInputModeV2::Fallback)
                    .unwrap();
            session.apply_fallback_key(KeypadKey::One).unwrap();
            let result = session.apply_fallback_key(KeypadKey::Nine);
            rejected(
                result,
                &mut session,
                "InvalidFallbackColumn",
                WipingReasonV2::OperationFailed,
            )
        }
        16..=18 => {
            let mut session =
                KitIntakeSessionV2::begin(flow_at_share_one(door), KitInputModeV2::Fallback)
                    .unwrap();
            if scenario == 18 {
                session.apply_fallback_key(KeypadKey::One).unwrap();
            }
            let (key, expected) = match scenario {
                16 => (KeypadKey::CeDelete, "FallbackEmptyDelete"),
                17 => (KeypadKey::EqualsConfirmEnter, "FallbackIncomplete"),
                18 => (KeypadKey::EqualsConfirmEnter, "FallbackPendingCoordinate"),
                _ => unreachable!(),
            };
            let result = session.apply_fallback_key(key);
            rejected(
                result,
                &mut session,
                expected,
                WipingReasonV2::OperationFailed,
            )
        }
        19 => {
            let mut session =
                KitIntakeSessionV2::begin(flow_at_share_one(door), KitInputModeV2::Fallback)
                    .unwrap();
            enter_fallback(&mut session, &fallback_one);
            let selector = data.get(2).copied().unwrap_or(0) % 3;
            let (result, expected) = match selector {
                0 => (
                    session.apply_fallback_key(KeypadKey::Nine),
                    "InvalidFallbackRow",
                ),
                1 => {
                    session.apply_fallback_key(KeypadKey::One).unwrap();
                    (
                        session.apply_fallback_key(KeypadKey::Nine),
                        "InvalidFallbackColumn",
                    )
                }
                _ => {
                    session.apply_fallback_key(KeypadKey::One).unwrap();
                    (session.apply_fallback_key(KeypadKey::One), "FallbackFull")
                }
            };
            rejected(
                result,
                &mut session,
                expected,
                WipingReasonV2::OperationFailed,
            )
        }
        20 | 21 => {
            let mut session =
                KitIntakeSessionV2::begin(flow_at_share_one(door), KitInputModeV2::Fallback)
                    .unwrap();
            let expected = if scenario == 20 {
                fallback_one[0] = if fallback_one[0] == b'2' { b'3' } else { b'2' };
                "FrameChecksum"
            } else {
                fallback_one[FALLBACK_SYMBOLS - 1] = b'3';
                "NonCanonicalPadding"
            };
            enter_fallback(&mut session, &fallback_one);
            let result = session.apply_fallback_key(KeypadKey::EqualsConfirmEnter);
            rejected(
                result,
                &mut session,
                expected,
                WipingReasonV2::OperationFailed,
            )
        }
        22 => {
            let mut session =
                KitIntakeSessionV2::begin(flow_at_share_one(door), KitInputModeV2::Scanner)
                    .unwrap();
            let result = session.apply_fallback_key(KeypadKey::One);
            rejected(
                result,
                &mut session,
                "KitScannerModeMismatch",
                WipingReasonV2::KitScannerModeMismatch,
            )
        }
        23 => {
            let mut session =
                KitIntakeSessionV2::begin(flow_at_share_one(door), KitInputModeV2::Scanner)
                    .unwrap();
            if data.get(2).copied().unwrap_or(0) & 1 != 0 {
                first_scanner(&mut session, &mut frame_one);
            }
            let other = match door {
                KitDoorV2::KitSpend => KitDoorV2::KitRestore,
                KitDoorV2::KitRestore => KitDoorV2::KitSpend,
            };
            let result = session.reselect_door(other);
            rejected(
                result,
                &mut session,
                "DoorSwitchAttempt",
                WipingReasonV2::DoorSwitchAttempt,
            )
        }
        24 => {
            let mut session =
                KitIntakeSessionV2::begin(flow_at_share_one(door), KitInputModeV2::Scanner)
                    .unwrap();
            if data.get(2).copied().unwrap_or(0) & 1 != 0 {
                first_scanner(&mut session, &mut frame_one);
            }
            let result = session.select_mode(KitInputModeV2::Fallback);
            rejected(
                result,
                &mut session,
                "KitScannerModeMismatch",
                WipingReasonV2::KitScannerModeMismatch,
            )
        }
        25 => {
            let mut session =
                KitIntakeSessionV2::begin(flow_at_share_one(door), KitInputModeV2::Fallback)
                    .unwrap();
            append_symbol(&mut session, fallback_one[0]);
            let result = session.apply_fallback_key(KeypadKey::CancelBack);
            rejected(result, &mut session, "Cancelled", WipingReasonV2::Cancelled)
        }
        26 => {
            let mut session =
                KitIntakeSessionV2::begin(flow_at_share_one(door), KitInputModeV2::Scanner)
                    .unwrap();
            if data.get(2).copied().unwrap_or(0) & 1 != 0 {
                first_scanner(&mut session, &mut frame_one);
            }
            drop(session);
            Summary::Dropped
        }
        27 => {
            if data.get(2).copied().unwrap_or(0) & 0x80 != 0 {
                let error = match KitIntakeSessionV2::begin(
                    ScreenFlowV2::new(FlowKindV2::Kit),
                    KitInputModeV2::Scanner,
                ) {
                    Err(error) => error,
                    Ok(_) => panic!("invalid start accepted"),
                };
                assert_eq!(error, KitIntakeErrorV2::InvalidStart);
                Summary::Rejected {
                    error: error.name(),
                    terminal: None,
                }
            } else {
                let mut raw = derive::<FRAME_LEN>(data, 0xa7);
                if let Some(candidate) = data.get(3..3 + FRAME_LEN) {
                    raw.copy_from_slice(candidate);
                }
                let expected = frame_metadata(&raw);
                let mut session =
                    KitIntakeSessionV2::begin(flow_at_share_one(door), KitInputModeV2::Scanner)
                        .unwrap();
                let result = session.submit_scanner_frame(&mut raw);
                assert_eq!(raw, [0u8; FRAME_LEN]);
                match expected {
                    Err(error) => rejected(
                        result,
                        &mut session,
                        KitIntakeErrorV2::Codec(error).name(),
                        WipingReasonV2::OperationFailed,
                    ),
                    Ok(metadata) => {
                        assert!(matches!(
                            result.unwrap(),
                            KitIntakeOutcomeV2::FirstShareAccepted(_)
                        ));
                        assert!(matches!(
                            metadata.share_index,
                            ShareIndex::One | ShareIndex::Two
                        ));
                        assert_eq!(
                            session.screen().map(|screen| screen.page()),
                            Some(qk_host_sim::KitShareOrdinalV2::Two)
                        );
                        drop(session);
                        Summary::Dropped
                    }
                }
            }
        }
        28..=30 => {
            let expected = match scenario {
                28 => {
                    frame_one[0] ^= 1;
                    "InvalidMagic"
                }
                29 => {
                    frame_one[4] = 2;
                    "UnsupportedVersion"
                }
                30 => {
                    frame_one[5] = 0;
                    "InvalidShareIndex"
                }
                _ => unreachable!(),
            };
            reference_reseal(&mut frame_one);
            let mut session =
                KitIntakeSessionV2::begin(flow_at_share_one(door), KitInputModeV2::Scanner)
                    .unwrap();
            let result = session.submit_scanner_frame(&mut frame_one);
            assert_eq!(frame_one, [0u8; FRAME_LEN]);
            rejected(
                result,
                &mut session,
                expected,
                WipingReasonV2::OperationFailed,
            )
        }
        31 => {
            let mut session =
                KitIntakeSessionV2::begin(flow_at_share_one(door), KitInputModeV2::Fallback)
                    .unwrap();
            let count = usize::from(data.get(2).copied().unwrap_or(0) % 58) + 1;
            for symbol in fallback_one.iter().take(count) {
                append_symbol(&mut session, *symbol);
            }
            let KitIntakeOutcomeV2::Continue(pending) =
                session.apply_fallback_key(KeypadKey::One).unwrap()
            else {
                panic!("pending row must retain screen");
            };
            assert_eq!(pending.fallback().committed_symbols(), count);
            assert_eq!(pending.fallback().pending_row(), Some(1));
            let KitIntakeOutcomeV2::Continue(cleared) =
                session.apply_fallback_key(KeypadKey::CeDelete).unwrap()
            else {
                panic!("CE must clear pending row");
            };
            assert_eq!(cleared.fallback().committed_symbols(), count);
            assert_eq!(cleared.fallback().pending_row(), None);
            let KitIntakeOutcomeV2::Continue(deleted) =
                session.apply_fallback_key(KeypadKey::CeDelete).unwrap()
            else {
                panic!("CE must delete one committed symbol");
            };
            assert_eq!(deleted.fallback().committed_symbols(), count - 1);
            assert_eq!(
                deleted.fallback().next_line(),
                Some(((count - 1) / 57 + 1) as u8)
            );
            assert_eq!(
                deleted.fallback().next_column(),
                Some(((count - 1) % 57 + 1) as u8)
            );
            drop(session);
            Summary::Dropped
        }
        32 => {
            let mut fallback_invalid_magic = [0u8; FALLBACK_SYMBOLS];
            frame_one[0] ^= 1;
            reference_reseal(&mut frame_one);
            encode_fallback(&frame_one, &mut fallback_invalid_magic).unwrap_err();
            // A canonical textual representation of a checksum-valid bad header is
            // produced by the fixed bit packing, independent of frame validation.
            for (symbol_index, output) in fallback_invalid_magic.iter_mut().enumerate() {
                let mut value = 0u8;
                for symbol_bit in 0..5 {
                    value <<= 1;
                    let bit_index = symbol_index * 5 + symbol_bit;
                    if bit_index < FRAME_LEN * 8 {
                        value |= (frame_one[bit_index / 8] >> (7 - bit_index % 8)) & 1;
                    }
                }
                *output = b"23456789abcdefghijkmnpqrstuvwxyz"[usize::from(value)];
            }
            let mut session =
                KitIntakeSessionV2::begin(flow_at_share_one(door), KitInputModeV2::Fallback)
                    .unwrap();
            enter_fallback(&mut session, &fallback_invalid_magic);
            let result = session.apply_fallback_key(KeypadKey::EqualsConfirmEnter);
            wipe(&mut fallback_invalid_magic);
            rejected(
                result,
                &mut session,
                "InvalidMagic",
                WipingReasonV2::OperationFailed,
            )
        }
        _ => unreachable!(),
    };

    wipe(&mut share_one);
    wipe(&mut share_two);
    wipe(&mut frame_one);
    wipe(&mut frame_two);
    wipe(&mut fallback_one);
    wipe(&mut fallback_two);
    assert_eq!(share_one, [0u8; 96]);
    assert_eq!(share_two, [0u8; 96]);
    assert_eq!(frame_one, [0u8; FRAME_LEN]);
    assert_eq!(frame_two, [0u8; FRAME_LEN]);
    assert_eq!(fallback_one, [0u8; FALLBACK_SYMBOLS]);
    assert_eq!(fallback_two, [0u8; FALLBACK_SYMBOLS]);
    summary
}

fuzz_target!(|data: &[u8]| {
    if data.len() > MAX_PRESENTED_BYTES {
        return;
    }
    let scenario = data.first().copied().unwrap_or(0) % SCENARIOS;
    let first = run(data, scenario);
    let second = run(data, scenario);
    assert_eq!(first, second);
});
