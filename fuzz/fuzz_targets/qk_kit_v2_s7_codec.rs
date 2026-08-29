#![no_main]

use libfuzzer_sys::fuzz_target;
use qk_kit::{
    decode_fallback, encode_fallback, encode_frame, encode_qr, frame_metadata, FrameMetadata,
    KitError, ShareIndex, FALLBACK_SYMBOLS, FRAME_LEN, QR_PACKED_BYTES, QR_SIZE,
};

#[allow(dead_code)]
#[path = "../../host/qk-psbt/src/sha256.rs"]
mod reference_sha256;

const ALPHABET: &[u8; 32] = b"23456789abcdefghijkmnpqrstuvwxyz";
const CHECKSUM_DOMAIN: &[u8] = b"QuietKey/KitShare/v1";
const FRAME_PREFIX_LEN: usize = 134;
const FRAME_SENTINEL: u8 = 0xa5;
const FALLBACK_SENTINEL: u8 = 0x5a;
const QR_SENTINEL: u8 = 0xc3;
const MAX_PRESENTED_FRAME: usize = FRAME_LEN + 1;
const MAX_PRESENTED_FALLBACK: usize = FALLBACK_SYMBOLS + 1;
const CAMPAIGN_MAX_LEN: usize = 512;
const CONSUMED_INPUT_BYTES: usize =
    1 + MAX_PRESENTED_FRAME + 1 + MAX_PRESENTED_FALLBACK + 32 + 96 + 1 + 1 + 1;

const _: () = assert!(CONSUMED_INPUT_BYTES <= CAMPAIGN_MAX_LEN);

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct ReferenceFrame {
    metadata: FrameMetadata,
    bytes: [u8; FRAME_LEN],
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
        metadata: FrameMetadata {
            share_index,
            wallet_id,
        },
        bytes: frame.try_into().expect("validated frame length"),
    })
}

fn reference_fallback(frame: &[u8; FRAME_LEN]) -> [u8; FALLBACK_SYMBOLS] {
    let mut symbols = [0u8; FALLBACK_SYMBOLS];
    for (symbol_index, output) in symbols.iter_mut().enumerate() {
        let mut value = 0u8;
        for symbol_bit in 0..5 {
            value <<= 1;
            let bit_index = symbol_index * 5 + symbol_bit;
            if bit_index < FRAME_LEN * 8 {
                value |= (frame[bit_index / 8] >> (7 - bit_index % 8)) & 1;
            }
        }
        *output = ALPHABET[usize::from(value)];
    }
    symbols
}

fn reference_decode_fallback(symbols: &[u8]) -> Result<ReferenceFrame, KitError> {
    if symbols.len() != FALLBACK_SYMBOLS {
        return Err(KitError::FallbackLength);
    }
    let mut frame = [0u8; FRAME_LEN];
    let mut final_value = 0u8;
    for (symbol_index, symbol) in symbols.iter().enumerate() {
        let value = alphabet_value(*symbol).ok_or(KitError::MalformedSymbol)?;
        if symbol_index + 1 == FALLBACK_SYMBOLS {
            final_value = value;
        }
        for symbol_bit in 0..5 {
            let bit_index = symbol_index * 5 + symbol_bit;
            if bit_index >= FRAME_LEN * 8 {
                break;
            }
            let bit = (value >> (4 - symbol_bit)) & 1;
            frame[bit_index / 8] |= bit << (7 - bit_index % 8);
        }
    }
    if final_value & 0x0f != 0 {
        return Err(KitError::NonCanonicalPadding);
    }
    reference_frame(&frame)
}

fn reference_reseal(frame: &mut [u8; FRAME_LEN]) {
    let checksum = reference_checksum(&frame[..FRAME_PREFIX_LEN]);
    frame[FRAME_PREFIX_LEN..].copy_from_slice(&checksum);
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
    let reference = reference_frame(frame);
    let first_metadata = frame_metadata(frame);
    let repeated_metadata = frame_metadata(frame);
    assert_eq!(first_metadata, repeated_metadata);
    assert_eq!(
        first_metadata,
        reference.map(|candidate| candidate.metadata)
    );

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

    match reference {
        Err(error) => {
            assert_named_error(error);
            assert_eq!(first_metadata, Err(error));
            assert_eq!(fallback_result, Err(error));
            assert_eq!(fallback, [FALLBACK_SENTINEL; FALLBACK_SYMBOLS]);
            assert_eq!(qr_result, Err(error));
            assert_eq!(qr, [QR_SENTINEL; QR_PACKED_BYTES]);
        }
        Ok(reference_frame) => {
            assert_eq!(first_metadata, Ok(reference_frame.metadata));
            assert_frame_metadata(frame, reference_frame.metadata);
            assert_eq!(fallback_result, Ok(()));
            assert_eq!(fallback, reference_fallback(&reference_frame.bytes));
            assert_eq!(
                alphabet_value(fallback[FALLBACK_SYMBOLS - 1]).unwrap() & 0x0f,
                0
            );

            let mut decoded = [FRAME_SENTINEL; FRAME_LEN];
            assert_eq!(
                decode_fallback(&fallback, &mut decoded),
                Ok(reference_frame.metadata)
            );
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
    let reference = reference_decode_fallback(symbols);
    let mut first = [FRAME_SENTINEL; FRAME_LEN];
    let first_result = decode_fallback(symbols, &mut first);
    let mut repeated = [FRAME_SENTINEL; FRAME_LEN];
    let repeated_result = decode_fallback(symbols, &mut repeated);
    assert_eq!(first_result, repeated_result);
    assert_eq!(first, repeated);

    match reference {
        Err(error) => {
            assert_named_error(error);
            assert_eq!(first_result, Err(error));
            assert_eq!(first, [FRAME_SENTINEL; FRAME_LEN]);
        }
        Ok(reference_frame) => {
            assert_eq!(first_result, Ok(reference_frame.metadata));
            assert_eq!(first, reference_frame.bytes);
            assert_frame_metadata(&first, reference_frame.metadata);
            let mut canonical = [FALLBACK_SENTINEL; FALLBACK_SYMBOLS];
            assert_eq!(encode_fallback(&first, &mut canonical), Ok(()));
            assert_eq!(canonical, reference_fallback(&reference_frame.bytes));
            assert_eq!(canonical.as_slice(), symbols);
        }
    }
}

fn assert_frame_rejection(frame: &[u8], expected: KitError) {
    assert_eq!(reference_frame(frame), Err(expected));
    exercise_frame(frame);
}

fn assert_fallback_rejection(symbols: &[u8], expected: KitError) {
    assert_eq!(reference_decode_fallback(symbols), Err(expected));
    exercise_fallback(symbols);
}

fn exercise_named_rejections(canonical_frame: &[u8; FRAME_LEN]) {
    let mut bad_checksum = *canonical_frame;
    bad_checksum[FRAME_LEN - 1] ^= 1;
    assert_frame_rejection(&bad_checksum, KitError::FrameChecksum);

    let mut invalid_magic = *canonical_frame;
    invalid_magic[0] ^= 1;
    invalid_magic[4] = 2;
    invalid_magic[5] = 0;
    reference_reseal(&mut invalid_magic);
    assert_frame_rejection(&invalid_magic, KitError::InvalidMagic);

    let mut invalid_version = *canonical_frame;
    invalid_version[4] = 2;
    invalid_version[5] = 0;
    reference_reseal(&mut invalid_version);
    assert_frame_rejection(&invalid_version, KitError::UnsupportedVersion);

    let mut invalid_index = *canonical_frame;
    invalid_index[5] = 0;
    reference_reseal(&mut invalid_index);
    assert_frame_rejection(&invalid_index, KitError::InvalidShareIndex);

    let canonical_fallback = reference_fallback(canonical_frame);
    assert_fallback_rejection(
        &canonical_fallback[..FALLBACK_SYMBOLS - 1],
        KitError::FallbackLength,
    );

    let mut malformed = canonical_fallback;
    malformed[0] = b'0';
    malformed[FALLBACK_SYMBOLS - 1] = ALPHABET[1];
    assert_fallback_rejection(&malformed, KitError::MalformedSymbol);

    let mut noncanonical_padding = canonical_fallback;
    noncanonical_padding[FALLBACK_SYMBOLS - 1] = ALPHABET[1];
    assert_fallback_rejection(&noncanonical_padding, KitError::NonCanonicalPadding);

    let mut fallback_bad_checksum = canonical_fallback;
    fallback_bad_checksum[0] = if fallback_bad_checksum[0] == ALPHABET[0] {
        ALPHABET[1]
    } else {
        ALPHABET[0]
    };
    assert_fallback_rejection(&fallback_bad_checksum, KitError::FrameChecksum);
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
    exercise_named_rejections(&canonical_frame);

    let mut mutated_fallback = [0u8; FALLBACK_SYMBOLS];
    assert_eq!(
        encode_fallback(&canonical_frame, &mut mutated_fallback),
        Ok(())
    );
    let position = usize::from(cursor.byte()) % FALLBACK_SYMBOLS;
    mutated_fallback[position] = cursor.byte();
    exercise_fallback(&mutated_fallback);
});
