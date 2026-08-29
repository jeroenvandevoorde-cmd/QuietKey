use qk_kit::{
    combine_frames, encode_frame, frame_metadata, FrameMetadata, KitError, RecoveredKitPayload,
    ShareIndex,
};

const WALLET_A: [u8; 32] = [0x11; 32];
const WALLET_B: [u8; 32] = [0x22; 32];
const SHARE_ONE: [u8; 96] = [0x3c; 96];
const SHARE_TWO: [u8; 96] = [0xa5; 96];
const SHARE_OTHER: [u8; 96] = [0x7e; 96];

fn rejection(result: Result<RecoveredKitPayload, KitError>) -> KitError {
    match result {
        Err(error) => error,
        Ok(payload) => {
            drop(payload);
            panic!("combination unexpectedly succeeded")
        }
    }
}

fn assert_named(error: KitError, expected: KitError, name: &str) {
    assert_eq!(error, expected);
    assert_eq!(error.to_string(), name);
}

#[test]
fn opposite_indices_for_one_wallet_succeed_in_both_caller_orders() {
    let one = encode_frame(ShareIndex::One, &WALLET_A, &SHARE_ONE);
    let two = encode_frame(ShareIndex::Two, &WALLET_A, &SHARE_TWO);

    assert_eq!(
        frame_metadata(&one),
        Ok(FrameMetadata {
            share_index: ShareIndex::One,
            wallet_id: WALLET_A,
        })
    );
    assert_eq!(
        frame_metadata(&two),
        Ok(FrameMetadata {
            share_index: ShareIndex::Two,
            wallet_id: WALLET_A,
        })
    );

    let one_then_two = combine_frames(&one, &two);
    assert!(one_then_two.is_ok());
    drop(one_then_two);

    let two_then_one = combine_frames(&two, &one);
    assert!(two_then_one.is_ok());
    drop(two_then_one);
}

#[test]
fn exact_duplicate_precedes_same_index() {
    let one = encode_frame(ShareIndex::One, &WALLET_A, &SHARE_ONE);

    assert_named(
        rejection(combine_frames(&one, &one)),
        KitError::DuplicateShare,
        "DuplicateShare",
    );
}

#[test]
fn distinct_equal_index_frames_reject_before_wallet_comparison() {
    let one = encode_frame(ShareIndex::One, &WALLET_A, &SHARE_ONE);
    let other_same_wallet = encode_frame(ShareIndex::One, &WALLET_A, &SHARE_OTHER);
    let other_wallet = encode_frame(ShareIndex::One, &WALLET_B, &SHARE_OTHER);

    for right in [&other_same_wallet, &other_wallet] {
        assert_named(
            rejection(combine_frames(&one, right)),
            KitError::SameShareIndex,
            "SameShareIndex",
        );
    }
}

#[test]
fn opposite_indices_from_two_wallets_reject_in_both_caller_orders() {
    let one = encode_frame(ShareIndex::One, &WALLET_A, &SHARE_ONE);
    let two_other_wallet = encode_frame(ShareIndex::Two, &WALLET_B, &SHARE_TWO);

    for (left, right) in [(&one, &two_other_wallet), (&two_other_wallet, &one)] {
        assert_named(
            rejection(combine_frames(left, right)),
            KitError::WalletMismatch,
            "WalletMismatch",
        );
    }
}

#[test]
fn each_left_frame_is_fully_validated_before_the_right_frame() {
    let valid = encode_frame(ShareIndex::One, &WALLET_A, &SHARE_ONE);
    let short = &valid[..valid.len() - 1];
    let mut bad_checksum = valid;
    bad_checksum[bad_checksum.len() - 1] ^= 0x01;

    assert_named(
        rejection(combine_frames(short, &bad_checksum)),
        KitError::FrameLength,
        "FrameLength",
    );
    assert_named(
        rejection(combine_frames(&bad_checksum, short)),
        KitError::FrameChecksum,
        "FrameChecksum",
    );
}
