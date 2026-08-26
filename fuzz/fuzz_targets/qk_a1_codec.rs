#![no_main]

use libfuzzer_sys::fuzz_target;
use qk_a1_codec::{decode, encode, CodecError, CodecProfile, DecodeReport};

const ALPHABET: &[u8; 32] = b"23456789abcdefghijkmnpqrstuvwxyz";
const FIXED_HEADER: [u8; 7] = [0x51, 0x4b, 0x41, 0x31, 0x01, 0x01, 0x01];
const CAPSULE_LEN: usize = 67;
const BODY_LEN: usize = CAPSULE_LEN - FIXED_HEADER.len();
const MAX_CODEWORD_LEN: usize = 80;
const MAX_SYMBOL_COUNT: usize = 128;
const MAX_PRESENTED_SYMBOL_COUNT: usize = MAX_SYMBOL_COUNT + 1;
const SENTINEL_CAPSULE: [u8; CAPSULE_LEN] = [0xa5; CAPSULE_LEN];

#[derive(Clone, Copy)]
struct Spec {
    profile: CodecProfile,
    codeword_len: usize,
    parity: usize,
    symbol_count: usize,
}

struct Cursor<'a> {
    bytes: &'a [u8],
    offset: usize,
}

impl<'a> Cursor<'a> {
    fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, offset: 0 }
    }

    fn byte(&mut self) -> u8 {
        let byte = self.bytes.get(self.offset).copied().unwrap_or(0);
        self.offset = self.offset.saturating_add(1);
        byte
    }

    fn array<const N: usize>(&mut self) -> [u8; N] {
        core::array::from_fn(|_| self.byte())
    }
}

fn spec(selector: u8) -> Spec {
    match selector % 3 {
        0 => Spec {
            profile: CodecProfile::Rs72_60,
            codeword_len: 72,
            parity: 12,
            symbol_count: 116,
        },
        1 => Spec {
            profile: CodecProfile::Rs76_60,
            codeword_len: 76,
            parity: 16,
            symbol_count: 122,
        },
        _ => Spec {
            profile: CodecProfile::Rs80_60,
            codeword_len: 80,
            parity: 20,
            symbol_count: 128,
        },
    }
}

fn alphabet_value(symbol: u8) -> Option<u8> {
    ALPHABET
        .iter()
        .position(|candidate| *candidate == symbol)
        .map(|index| index as u8)
}

fn structural_error(spec: Spec, symbols: &[u8], erasure_mask: &[u8]) -> Option<CodecError> {
    if symbols.len() != spec.symbol_count {
        return Some(CodecError::InvalidSymbolCount);
    }
    if erasure_mask.len() != spec.symbol_count || erasure_mask.iter().any(|marker| *marker > 1) {
        return Some(CodecError::MalformedErasureRepresentation);
    }

    for (index, (symbol, marker)) in symbols.iter().zip(erasure_mask).enumerate() {
        if *marker == 1 {
            continue;
        }
        let Some(value) = alphabet_value(*symbol) else {
            return Some(CodecError::MalformedSymbol);
        };
        let first_bit = index * 5;
        let data_bits = core::cmp::min(5, spec.codeword_len * 8 - first_bit);
        let padding_bits = 5 - data_bits;
        if padding_bits != 0 && value & ((1u8 << padding_bits) - 1) != 0 {
            return Some(CodecError::NonCanonicalPadding);
        }
    }

    let mut erased_bytes = [false; MAX_CODEWORD_LEN];
    for (index, marker) in erasure_mask.iter().enumerate() {
        if *marker == 0 {
            continue;
        }
        let first_bit = index * 5;
        let data_bits = core::cmp::min(5, spec.codeword_len * 8 - first_bit);
        let first_byte = first_bit / 8;
        let last_byte = (first_bit + data_bits - 1) / 8;
        erased_bytes[first_byte..=last_byte].fill(true);
    }
    if erased_bytes[..spec.codeword_len]
        .iter()
        .filter(|erased| **erased)
        .count()
        > spec.parity
    {
        return Some(CodecError::OverCapacity);
    }
    None
}

fn assert_named_error(error: CodecError) {
    match error {
        CodecError::InvalidCapsuleHeader
        | CodecError::InvalidSymbolCount
        | CodecError::MalformedErasureRepresentation
        | CodecError::MalformedSymbol
        | CodecError::NonCanonicalPadding
        | CodecError::OverCapacity
        | CodecError::NoUniqueCodeword => {}
    }
}

fn exercise_decode(
    spec: Spec,
    symbols: &[u8],
    erasure_mask: &[u8],
) -> Option<([u8; CAPSULE_LEN], DecodeReport)> {
    let mut capsule = SENTINEL_CAPSULE;
    let result = decode(spec.profile, symbols, erasure_mask, &mut capsule);

    if let Some(expected) = structural_error(spec, symbols, erasure_mask) {
        assert_eq!(result, Err(expected));
        assert_eq!(capsule, SENTINEL_CAPSULE);
        let mut repeated_capsule = SENTINEL_CAPSULE;
        assert_eq!(
            decode(spec.profile, symbols, erasure_mask, &mut repeated_capsule),
            Err(expected)
        );
        assert_eq!(repeated_capsule, SENTINEL_CAPSULE);
        return None;
    }

    match result {
        Err(error) => {
            assert_named_error(error);
            assert!(matches!(
                error,
                CodecError::OverCapacity | CodecError::NoUniqueCodeword
            ));
            assert_eq!(capsule, SENTINEL_CAPSULE);
            let mut repeated_capsule = SENTINEL_CAPSULE;
            assert_eq!(
                decode(spec.profile, symbols, erasure_mask, &mut repeated_capsule),
                Err(error)
            );
            assert_eq!(repeated_capsule, SENTINEL_CAPSULE);
            None
        }
        Ok(report) => {
            let used_capacity =
                2 * usize::from(report.corrected_errors) + usize::from(report.erased_bytes);
            assert!(used_capacity <= spec.parity);

            let mut canonical_symbols = [0u8; MAX_SYMBOL_COUNT];
            assert_eq!(
                encode(
                    spec.profile,
                    &capsule,
                    &mut canonical_symbols[..spec.symbol_count],
                ),
                Ok(())
            );
            if report.corrected_errors == 0 && report.erased_bytes == 0 {
                assert_eq!(symbols, &canonical_symbols[..spec.symbol_count]);
            }

            let zero_erasures = [0u8; MAX_SYMBOL_COUNT];
            let mut reparsed = SENTINEL_CAPSULE;
            assert_eq!(
                decode(
                    spec.profile,
                    &canonical_symbols[..spec.symbol_count],
                    &zero_erasures[..spec.symbol_count],
                    &mut reparsed,
                ),
                Ok(DecodeReport {
                    corrected_errors: 0,
                    erased_bytes: 0,
                })
            );
            assert_eq!(reparsed, capsule);
            let mut repeated_capsule = SENTINEL_CAPSULE;
            assert_eq!(
                decode(spec.profile, symbols, erasure_mask, &mut repeated_capsule),
                Ok(report)
            );
            assert_eq!(repeated_capsule, capsule);
            Some((capsule, report))
        }
    }
}

fn exercise_encode(spec: Spec, capsule: &[u8; CAPSULE_LEN], symbol_len: usize) {
    let mut symbols = [0xa5; MAX_PRESENTED_SYMBOL_COUNT];
    let result = encode(spec.profile, capsule, &mut symbols[..symbol_len]);
    let expected = if capsule[..FIXED_HEADER.len()] != FIXED_HEADER {
        Some(CodecError::InvalidCapsuleHeader)
    } else if symbol_len != spec.symbol_count {
        Some(CodecError::InvalidSymbolCount)
    } else {
        None
    };

    if let Some(error) = expected {
        assert_eq!(result, Err(error));
        assert!(symbols.iter().all(|symbol| *symbol == 0xa5));
        let mut repeated_symbols = [0xa5; MAX_PRESENTED_SYMBOL_COUNT];
        assert_eq!(
            encode(spec.profile, capsule, &mut repeated_symbols[..symbol_len]),
            Err(error)
        );
        assert_eq!(repeated_symbols, symbols);
        return;
    }

    assert_eq!(result, Ok(()));
    assert!(symbols[..symbol_len]
        .iter()
        .all(|symbol| alphabet_value(*symbol).is_some()));
    let zero_erasures = [0u8; MAX_SYMBOL_COUNT];
    let mut decoded = SENTINEL_CAPSULE;
    assert_eq!(
        decode(
            spec.profile,
            &symbols[..symbol_len],
            &zero_erasures[..symbol_len],
            &mut decoded
        ),
        Ok(DecodeReport {
            corrected_errors: 0,
            erased_bytes: 0,
        })
    );
    assert_eq!(decoded, *capsule);
}

fn encoded_capsule(
    spec: Spec,
    body: [u8; BODY_LEN],
) -> ([u8; CAPSULE_LEN], [u8; MAX_SYMBOL_COUNT]) {
    let mut capsule = [0u8; CAPSULE_LEN];
    capsule[..FIXED_HEADER.len()].copy_from_slice(&FIXED_HEADER);
    capsule[FIXED_HEADER.len()..].copy_from_slice(&body);
    let mut symbols = [0u8; MAX_SYMBOL_COUNT];
    assert_eq!(
        encode(spec.profile, &capsule, &mut symbols[..spec.symbol_count]),
        Ok(())
    );
    (capsule, symbols)
}

fuzz_target!(|data: &[u8]| {
    let mut cursor = Cursor::new(data);
    let spec = spec(cursor.byte());

    match cursor.byte() % 5 {
        0 => {
            // Fully hostile lengths, symbols, and masks, capped one past every
            // public profile boundary.
            let symbol_len = usize::from(cursor.byte()) % (MAX_PRESENTED_SYMBOL_COUNT + 1);
            let mask_len = usize::from(cursor.byte()) % (MAX_PRESENTED_SYMBOL_COUNT + 1);
            let symbols = cursor.array::<MAX_PRESENTED_SYMBOL_COUNT>();
            let erasure_mask = cursor.array::<MAX_PRESENTED_SYMBOL_COUNT>();
            let _ = exercise_decode(spec, &symbols[..symbol_len], &erasure_mask[..mask_len]);
        }
        1 => {
            let (capsule, symbols) = encoded_capsule(spec, cursor.array::<BODY_LEN>());
            let erasure_mask = [0u8; MAX_SYMBOL_COUNT];
            let (decoded, report) = exercise_decode(
                spec,
                &symbols[..spec.symbol_count],
                &erasure_mask[..spec.symbol_count],
            )
            .expect("an encoded codeword must decode");
            assert_eq!(decoded, capsule);
            assert_eq!(
                report,
                DecodeReport {
                    corrected_errors: 0,
                    erased_bytes: 0,
                }
            );
        }
        2 => {
            // One known-symbol change affects at most two codeword bytes and is
            // therefore within every selected profile's correction capacity.
            let (capsule, mut symbols) = encoded_capsule(spec, cursor.array::<BODY_LEN>());
            let mutation_positions = if spec.symbol_count * 5 == spec.codeword_len * 8 {
                spec.symbol_count
            } else {
                // The final symbol in padded profiles has canonical zero bits.
                // Keep this branch a correctable data-symbol mutation; the
                // hostile branches cover noncanonical terminal padding.
                spec.symbol_count - 1
            };
            let position = usize::from(cursor.byte()) % mutation_positions;
            let old_value = alphabet_value(symbols[position]).expect("encoder alphabet");
            let delta = 1 + cursor.byte() % 31;
            symbols[position] = ALPHABET[usize::from((old_value + delta) % 32)];
            let erasure_mask = [0u8; MAX_SYMBOL_COUNT];
            let (decoded, report) = exercise_decode(
                spec,
                &symbols[..spec.symbol_count],
                &erasure_mask[..spec.symbol_count],
            )
            .expect("one symbol error is within capacity");
            assert_eq!(decoded, capsule);
            assert!((1..=2).contains(&report.corrected_errors));
            assert_eq!(report.erased_bytes, 0);
        }
        3 => {
            // An erased symbol may span one or two bytes; its stored byte is
            // deliberately malformed to verify that erased content is ignored.
            let (capsule, mut symbols) = encoded_capsule(spec, cursor.array::<BODY_LEN>());
            let position = usize::from(cursor.byte()) % spec.symbol_count;
            symbols[position] = 0;
            let mut erasure_mask = [0u8; MAX_SYMBOL_COUNT];
            erasure_mask[position] = 1;
            let (decoded, report) = exercise_decode(
                spec,
                &symbols[..spec.symbol_count],
                &erasure_mask[..spec.symbol_count],
            )
            .expect("one symbol erasure is within capacity");
            assert_eq!(decoded, capsule);
            assert_eq!(report.corrected_errors, 0);
            assert!((1..=2).contains(&report.erased_bytes));
        }
        _ => {
            // Multi-edit generation reaches correction boundaries and every
            // symbol/mask representation class without an input-derived loop.
            let (_, mut symbols) = encoded_capsule(spec, cursor.array::<BODY_LEN>());
            let mut erasure_mask = [0u8; MAX_SYMBOL_COUNT];
            let edit_count = usize::from(cursor.byte()) % (spec.parity + 2);
            for _ in 0..edit_count {
                let position = usize::from(cursor.byte()) % spec.symbol_count;
                match cursor.byte() % 5 {
                    0 => {
                        let old_value = alphabet_value(symbols[position]).unwrap_or(0);
                        let delta = 1 + cursor.byte() % 31;
                        symbols[position] = ALPHABET[usize::from((old_value + delta) % 32)];
                    }
                    1 => {
                        symbols[position] = 0;
                        erasure_mask[position] = 1;
                    }
                    2 => {
                        symbols[position] = 0;
                    }
                    3 => {
                        erasure_mask[position] = 2 + cursor.byte() % 254;
                    }
                    _ => {
                        symbols[spec.symbol_count - 1] = ALPHABET[1];
                    }
                }
            }
            let _ = exercise_decode(
                spec,
                &symbols[..spec.symbol_count],
                &erasure_mask[..spec.symbol_count],
            );
        }
    }

    let hostile_capsule = cursor.array::<CAPSULE_LEN>();
    let hostile_symbol_len = usize::from(cursor.byte()) % (MAX_PRESENTED_SYMBOL_COUNT + 1);
    exercise_encode(spec, &hostile_capsule, hostile_symbol_len);

    let mut valid_capsule = [0u8; CAPSULE_LEN];
    valid_capsule[..FIXED_HEADER.len()].copy_from_slice(&FIXED_HEADER);
    valid_capsule[FIXED_HEADER.len()..].copy_from_slice(&cursor.array::<BODY_LEN>());
    let presented_len = usize::from(cursor.byte()) % (MAX_PRESENTED_SYMBOL_COUNT + 1);
    exercise_encode(spec, &valid_capsule, presented_len);
});
