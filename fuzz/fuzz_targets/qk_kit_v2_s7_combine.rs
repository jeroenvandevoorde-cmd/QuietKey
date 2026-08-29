#![no_main]

use libfuzzer_sys::fuzz_target;
use qk_kit::{
    combine_frames, encode_frame, frame_metadata, FrameMetadata, KitError, RecoveredKitPayload,
    ShareIndex, FRAME_LEN,
};

#[allow(dead_code)]
#[path = "../../host/qk-psbt/src/sha256.rs"]
mod reference_sha256;

const MAX_PRESENTED_FRAME: usize = FRAME_LEN + 1;
const FRAME_PREFIX_LEN: usize = 134;
const CHECKSUM_DOMAIN: &[u8] = b"QuietKey/KitShare/v1";
const CAMPAIGN_MAX_LEN: usize = 512;
const CONSUMED_INPUT_BYTES: usize = 2 + 2 * MAX_PRESENTED_FRAME + 32 + 2 * 96;

const _: () = assert!(CONSUMED_INPUT_BYTES == CAMPAIGN_MAX_LEN);

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct ReferenceFrame {
    share_index: ShareIndex,
    wallet_id: [u8; 32],
}

struct Cursor<'a> {
    bytes: &'a [u8],
    offset: usize,
}

impl<'a> Cursor<'a> {
    const fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, offset: 0 }
    }

    fn byte(&mut self) -> u8 {
        let value = self.bytes.get(self.offset).copied().unwrap_or(0);
        self.offset = self.offset.saturating_add(1);
        value
    }

    fn array<const N: usize>(&mut self) -> [u8; N] {
        core::array::from_fn(|_| self.byte())
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Outcome {
    AcceptedOpaque,
    Rejected(KitError),
}

fn error_name(error: KitError) -> &'static str {
    match error {
        KitError::FrameLength => "FrameLength",
        KitError::FrameChecksum => "FrameChecksum",
        KitError::InvalidMagic => "InvalidMagic",
        KitError::UnsupportedVersion => "UnsupportedVersion",
        KitError::InvalidShareIndex => "InvalidShareIndex",
        KitError::FallbackLength => "FallbackLength",
        KitError::MalformedSymbol => "MalformedSymbol",
        KitError::NonCanonicalPadding => "NonCanonicalPadding",
        KitError::DuplicateShare => "DuplicateShare",
        KitError::SameShareIndex => "SameShareIndex",
        KitError::WalletMismatch => "WalletMismatch",
    }
}

fn assert_named_error(error: KitError) {
    assert_eq!(error.to_string(), error_name(error));
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

fn reference_frame(frame: &[u8]) -> Result<ReferenceFrame, KitError> {
    if frame.len() != FRAME_LEN {
        return Err(KitError::FrameLength);
    }
    if reference_checksum(&frame[..FRAME_PREFIX_LEN]) != frame[FRAME_PREFIX_LEN..] {
        return Err(KitError::FrameChecksum);
    }
    if &frame[..4] != b"QKKS" {
        return Err(KitError::InvalidMagic);
    }
    if frame[4] != 1 {
        return Err(KitError::UnsupportedVersion);
    }
    let share_index = match frame[5] {
        1 => ShareIndex::One,
        2 => ShareIndex::Two,
        _ => return Err(KitError::InvalidShareIndex),
    };
    let mut wallet_id = [0u8; 32];
    wallet_id.copy_from_slice(&frame[6..38]);
    Ok(ReferenceFrame {
        share_index,
        wallet_id,
    })
}

fn reference_reseal(frame: &mut [u8; FRAME_LEN]) {
    let checksum = reference_checksum(&frame[..FRAME_PREFIX_LEN]);
    frame[FRAME_PREFIX_LEN..].copy_from_slice(&checksum);
}

fn classify(result: Result<RecoveredKitPayload, KitError>) -> Outcome {
    match result {
        Ok(payload) => {
            // The public API releases only the opaque owner. This target can
            // drop it but has no payload byte, formatter, or snapshot path.
            drop(payload);
            Outcome::AcceptedOpaque
        }
        Err(error) => {
            assert_named_error(error);
            Outcome::Rejected(error)
        }
    }
}

fn expected(left: &[u8], right: &[u8]) -> Outcome {
    let left_metadata = match reference_frame(left) {
        Ok(metadata) => metadata,
        Err(error) => return Outcome::Rejected(error),
    };
    let right_metadata = match reference_frame(right) {
        Ok(metadata) => metadata,
        Err(error) => return Outcome::Rejected(error),
    };

    if left == right {
        Outcome::Rejected(KitError::DuplicateShare)
    } else if left_metadata.share_index == right_metadata.share_index {
        Outcome::Rejected(KitError::SameShareIndex)
    } else if left_metadata.wallet_id != right_metadata.wallet_id {
        Outcome::Rejected(KitError::WalletMismatch)
    } else {
        Outcome::AcceptedOpaque
    }
}

fn exercise_pair(left: &[u8], right: &[u8]) {
    let first = classify(combine_frames(left, right));
    let repeated = classify(combine_frames(left, right));
    assert_eq!(first, repeated);
    assert_eq!(first, expected(left, right));
}

fn assert_metadata(frame: &[u8], share_index: ShareIndex, wallet_id: [u8; 32]) {
    assert_eq!(
        reference_frame(frame),
        Ok(ReferenceFrame {
            share_index,
            wallet_id,
        })
    );
    assert_eq!(
        frame_metadata(frame),
        Ok(FrameMetadata {
            share_index,
            wallet_id,
        })
    );
}

fn exercise_structured(cursor: &mut Cursor<'_>) {
    let wallet_a = cursor.array::<32>();
    let mut wallet_b = wallet_a;
    wallet_b[0] ^= 1;
    let share_one = cursor.array::<96>();
    let share_two = cursor.array::<96>();
    let mut share_other = share_one;
    share_other[0] ^= 1;

    let one = encode_frame(ShareIndex::One, &wallet_a, &share_one);
    let two = encode_frame(ShareIndex::Two, &wallet_a, &share_two);
    let one_other = encode_frame(ShareIndex::One, &wallet_a, &share_other);
    let one_other_wallet = encode_frame(ShareIndex::One, &wallet_b, &share_other);
    let two_other_wallet = encode_frame(ShareIndex::Two, &wallet_b, &share_two);

    assert_metadata(&one, ShareIndex::One, wallet_a);
    assert_metadata(&two, ShareIndex::Two, wallet_a);
    exercise_pair(&one, &two);
    exercise_pair(&two, &one);
    exercise_pair(&one, &one);
    exercise_pair(&one, &one_other);
    exercise_pair(&one, &one_other_wallet);
    exercise_pair(&one, &two_other_wallet);
    exercise_pair(&two_other_wallet, &one);

    let short = &one[..FRAME_LEN - 1];
    let mut bad_checksum = two;
    bad_checksum[FRAME_LEN - 1] ^= 1;
    exercise_pair(short, &bad_checksum);
    exercise_pair(&bad_checksum, short);

    let mut invalid_magic = two;
    invalid_magic[0] ^= 1;
    invalid_magic[4] = 2;
    invalid_magic[5] = 0;
    reference_reseal(&mut invalid_magic);
    let mut invalid_version = two;
    invalid_version[4] = 2;
    invalid_version[5] = 0;
    reference_reseal(&mut invalid_version);
    let mut invalid_index = two;
    invalid_index[5] = 0;
    reference_reseal(&mut invalid_index);
    for invalid in [&invalid_magic, &invalid_version, &invalid_index] {
        exercise_pair(invalid, &one);
        exercise_pair(&one, invalid);
    }
}

fuzz_target!(|data: &[u8]| {
    let mut cursor = Cursor::new(data);

    let left_len = usize::from(cursor.byte()) % (MAX_PRESENTED_FRAME + 1);
    let right_len = usize::from(cursor.byte()) % (MAX_PRESENTED_FRAME + 1);
    let left = cursor.array::<MAX_PRESENTED_FRAME>();
    let right = cursor.array::<MAX_PRESENTED_FRAME>();
    exercise_pair(&left[..left_len], &right[..right_len]);
    exercise_pair(&right[..right_len], &left[..left_len]);

    exercise_structured(&mut cursor);
});
