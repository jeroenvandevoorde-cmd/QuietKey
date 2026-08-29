#![no_main]

use libfuzzer_sys::fuzz_target;
use qk_kit::{
    decode_fallback, encode_fallback, encode_frame, encode_qr, frame_metadata, FrameMetadata,
    KitError, ShareIndex, FALLBACK_SYMBOLS, FRAME_LEN, QR_PACKED_BYTES, QR_SIZE,
};

const ALPHABET: &[u8; 32] = b"23456789abcdefghijkmnpqrstuvwxyz";
const FRAME_SENTINEL: u8 = 0xa5;
const FALLBACK_SENTINEL: u8 = 0x5a;
const QR_SENTINEL: u8 = 0xc3;
const MAX_PRESENTED_FRAME: usize = FRAME_LEN + 1;
const MAX_PRESENTED_FALLBACK: usize = FALLBACK_SYMBOLS + 1;

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

fn alphabet_value(symbol: u8) -> Option<u8> {
    ALPHABET
        .iter()
        .position(|candidate| *candidate == symbol)
        .map(|index| index as u8)
}

fn assert_frame_metadata(frame: &[u8], metadata: FrameMetadata) {
    assert_eq!(frame.len(), FRAME_LEN);
    assert_eq!(&frame[..4], b"QKKS");
    assert_eq!(frame[4], 1);
    assert_eq!(frame[5], metadata.share_index.as_u8());
    assert_eq!(&frame[6..38], &metadata.wallet_id);
}

fn assert_qr_geometry(packed: &[u8; QR_PACKED_BYTES]) {
    assert_eq!(packed[QR_PACKED_BYTES - 1] & 0x7f, 0);
    for y in 0..QR_SIZE {
        for x in 0..QR_SIZE {
            if !(4..QR_SIZE - 4).contains(&x) || !(4..QR_SIZE - 4).contains(&y) {
                let bit_index = y * QR_SIZE + x;
                assert_eq!(packed[bit_index / 8] & (1 << (7 - bit_index % 8)), 0);
            }
        }
    }
}

fn exercise_frame(frame: &[u8]) {
    let first_metadata = frame_metadata(frame);
    let repeated_metadata = frame_metadata(frame);
    assert_eq!(first_metadata, repeated_metadata);

    let mut fallback = [FALLBACK_SENTINEL; FALLBACK_SYMBOLS];
    let fallback_result = encode_fallback(frame, &mut fallback);
    let mut repeated_fallback = [FALLBACK_SENTINEL; FALLBACK_SYMBOLS];
    let repeated_fallback_result = encode_fallback(frame, &mut repeated_fallback);
    assert_eq!(fallback_result, repeated_fallback_result);
    assert_eq!(fallback, repeated_fallback);

    let mut qr = [QR_SENTINEL; QR_PACKED_BYTES];
    let qr_result = encode_qr(frame, &mut qr);
    let mut repeated_qr = [QR_SENTINEL; QR_PACKED_BYTES];
    let repeated_qr_result = encode_qr(frame, &mut repeated_qr);
    assert_eq!(qr_result, repeated_qr_result);
    assert_eq!(qr, repeated_qr);

    match first_metadata {
        Err(error) => {
            assert_named_error(error);
            assert_eq!(fallback_result, Err(error));
            assert_eq!(fallback, [FALLBACK_SENTINEL; FALLBACK_SYMBOLS]);
            assert_eq!(qr_result, Err(error));
            assert_eq!(qr, [QR_SENTINEL; QR_PACKED_BYTES]);
        }
        Ok(metadata) => {
            assert_frame_metadata(frame, metadata);
            assert_eq!(fallback_result, Ok(()));
            assert!(fallback
                .iter()
                .all(|symbol| alphabet_value(*symbol).is_some()));
            assert_eq!(
                alphabet_value(fallback[FALLBACK_SYMBOLS - 1]).unwrap() & 0x0f,
                0
            );

            let mut decoded = [FRAME_SENTINEL; FRAME_LEN];
            assert_eq!(decode_fallback(&fallback, &mut decoded), Ok(metadata));
            assert_eq!(decoded.as_slice(), frame);

            let qr_metadata = qr_result.expect("validated frame must encode as fixed QR");
            assert!(qr_metadata.mask < 8);
            let expected_mask = qr_metadata
                .penalties
                .iter()
                .enumerate()
                .min_by_key(|(mask, penalty)| (**penalty, *mask))
                .map(|(mask, _)| mask as u8)
                .expect("eight fixed mask scores");
            assert_eq!(qr_metadata.mask, expected_mask);
            assert_qr_geometry(&qr);
        }
    }
}

fn exercise_fallback(symbols: &[u8]) {
    let mut first = [FRAME_SENTINEL; FRAME_LEN];
    let first_result = decode_fallback(symbols, &mut first);
    let mut repeated = [FRAME_SENTINEL; FRAME_LEN];
    let repeated_result = decode_fallback(symbols, &mut repeated);
    assert_eq!(first_result, repeated_result);
    assert_eq!(first, repeated);

    match first_result {
        Err(error) => {
            assert_named_error(error);
            assert_eq!(first, [FRAME_SENTINEL; FRAME_LEN]);
        }
        Ok(metadata) => {
            assert_frame_metadata(&first, metadata);
            let mut canonical = [FALLBACK_SENTINEL; FALLBACK_SYMBOLS];
            assert_eq!(encode_fallback(&first, &mut canonical), Ok(()));
            assert_eq!(canonical.as_slice(), symbols);
        }
    }
}

fuzz_target!(|data: &[u8]| {
    let mut cursor = Cursor::new(data);

    let hostile_frame_len = usize::from(cursor.byte()) % (MAX_PRESENTED_FRAME + 1);
    let hostile_frame = cursor.array::<MAX_PRESENTED_FRAME>();
    exercise_frame(&hostile_frame[..hostile_frame_len]);

    let hostile_fallback_len = usize::from(cursor.byte()) % (MAX_PRESENTED_FALLBACK + 1);
    let hostile_fallback = cursor.array::<MAX_PRESENTED_FALLBACK>();
    exercise_fallback(&hostile_fallback[..hostile_fallback_len]);

    let wallet_id = cursor.array::<32>();
    let share = cursor.array::<96>();
    let share_index = if cursor.byte() & 1 == 0 {
        ShareIndex::One
    } else {
        ShareIndex::Two
    };
    let canonical_frame = encode_frame(share_index, &wallet_id, &share);
    exercise_frame(&canonical_frame);

    let mut mutated_fallback = [0u8; FALLBACK_SYMBOLS];
    assert_eq!(
        encode_fallback(&canonical_frame, &mut mutated_fallback),
        Ok(())
    );
    let position = usize::from(cursor.byte()) % FALLBACK_SYMBOLS;
    mutated_fallback[position] = cursor.byte();
    exercise_fallback(&mutated_fallback);
});
