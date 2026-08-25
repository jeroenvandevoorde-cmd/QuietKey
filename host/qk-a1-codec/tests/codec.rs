//! M18 public-codec conformance and bounded correction tests.

use qk_a1_codec::{decode, encode, CodecError, CodecProfile, DecodeReport};

const FIXED_HEADER: [u8; 7] = [0x51, 0x4b, 0x41, 0x31, 0x01, 0x01, 0x01];
const ALPHABET: &[u8; 32] = b"23456789abcdefghijkmnpqrstuvwxyz";
const CAPSULE_LEN: usize = 67;
const BODY_LEN: usize = 60;
const MAX_CODEWORD_LEN: usize = 80;
const MAX_SYMBOL_COUNT: usize = 128;
const SENTINEL_CAPSULE: [u8; CAPSULE_LEN] = [0xa5; CAPSULE_LEN];

#[derive(Clone, Copy)]
struct Spec {
    profile: CodecProfile,
    codeword_len: usize,
    parity: usize,
    symbol_count: usize,
    padding_bits: usize,
}

const SPECS: [Spec; 3] = [
    Spec {
        profile: CodecProfile::Rs72_60,
        codeword_len: 72,
        parity: 12,
        symbol_count: 116,
        padding_bits: 4,
    },
    Spec {
        profile: CodecProfile::Rs76_60,
        codeword_len: 76,
        parity: 16,
        symbol_count: 122,
        padding_bits: 2,
    },
    Spec {
        profile: CodecProfile::Rs80_60,
        codeword_len: 80,
        parity: 20,
        symbol_count: 128,
        padding_bits: 0,
    },
];

fn capsule(seed: u8) -> [u8; CAPSULE_LEN] {
    let mut result = [0u8; CAPSULE_LEN];
    result[..FIXED_HEADER.len()].copy_from_slice(&FIXED_HEADER);
    for (index, byte) in result[FIXED_HEADER.len()..].iter_mut().enumerate() {
        *byte = seed
            .wrapping_add((index as u8).wrapping_mul(29))
            .wrapping_add(7);
    }
    result
}

fn encoded(spec: Spec, input: &[u8; CAPSULE_LEN]) -> Vec<u8> {
    let mut result = vec![0u8; spec.symbol_count];
    encode(spec.profile, input, &mut result).unwrap();
    result
}

fn alphabet_value(symbol: u8) -> Option<u8> {
    ALPHABET
        .iter()
        .position(|candidate| *candidate == symbol)
        .map(|index| index as u8)
}

fn symbols_from_bytes(bytes: &[u8]) -> Vec<u8> {
    let symbol_count = (bytes.len() * 8).div_ceil(5);
    let mut result = vec![0u8; symbol_count];
    let bit_len = bytes.len() * 8;
    for (symbol_index, symbol) in result.iter_mut().enumerate() {
        let mut value = 0u8;
        for symbol_bit in 0..5 {
            value <<= 1;
            let bit_index = symbol_index * 5 + symbol_bit;
            if bit_index < bit_len {
                value |= (bytes[bit_index / 8] >> (7 - bit_index % 8)) & 1;
            }
        }
        *symbol = ALPHABET[value as usize];
    }
    result
}

fn bytes_from_symbols(symbols: &[u8], byte_count: usize) -> Vec<u8> {
    assert_eq!(symbols.len(), (byte_count * 8).div_ceil(5));
    let bit_len = byte_count * 8;
    let mut result = vec![0u8; byte_count];
    for (symbol_index, symbol) in symbols.iter().enumerate() {
        let value = alphabet_value(*symbol).expect("known test symbol");
        let first_bit = symbol_index * 5;
        let data_bits = core::cmp::min(5, bit_len - first_bit);
        let padding_bits = 5 - data_bits;
        assert_eq!(value & ((1u8 << padding_bits) - 1), 0);
        for symbol_bit in 0..data_bits {
            let bit_index = first_bit + symbol_bit;
            let bit = (value >> (4 - symbol_bit)) & 1;
            result[bit_index / 8] |= bit << (7 - bit_index % 8);
        }
    }
    result
}

fn byte_span(spec: Spec, symbol_index: usize) -> (usize, usize) {
    assert!(symbol_index < spec.symbol_count);
    let first_bit = symbol_index * 5;
    let data_bits = core::cmp::min(5, spec.codeword_len * 8 - first_bit);
    (first_bit / 8, (first_bit + data_bits - 1) / 8)
}

fn union_erased_bytes(spec: Spec, mask: &[u8]) -> Vec<usize> {
    let mut seen = [false; MAX_CODEWORD_LEN];
    for (symbol_index, marker) in mask.iter().enumerate() {
        if *marker == 0 {
            continue;
        }
        let (first, last) = byte_span(spec, symbol_index);
        seen[first..=last].fill(true);
    }
    seen[..spec.codeword_len]
        .iter()
        .enumerate()
        .filter_map(|(index, erased)| erased.then_some(index))
        .collect()
}

fn single_byte_erasure_symbols(spec: Spec) -> Vec<(usize, usize)> {
    let mut seen = [false; MAX_CODEWORD_LEN];
    let mut result = Vec::new();
    for symbol_index in 0..spec.symbol_count {
        let (first, last) = byte_span(spec, symbol_index);
        if first == last && !seen[first] {
            seen[first] = true;
            result.push((symbol_index, first));
        }
    }
    result
}

fn assert_decode_rejection(spec: Spec, symbols: &[u8], erasures: &[u8], expected: CodecError) {
    let mut output = SENTINEL_CAPSULE;
    assert_eq!(
        decode(spec.profile, symbols, erasures, &mut output),
        Err(expected)
    );
    assert_eq!(output, SENTINEL_CAPSULE);
}

#[test]
fn exact_geometry_systematic_body_and_roundtrip_are_locked() {
    let input = capsule(0x31);
    let changed_tag = {
        let mut value = input;
        value[CAPSULE_LEN - 1] ^= 0x80;
        value
    };

    for spec in SPECS {
        assert_eq!(spec.symbol_count, (spec.codeword_len * 8).div_ceil(5));
        assert_eq!(spec.codeword_len, BODY_LEN + spec.parity);
        assert_eq!(
            spec.padding_bits,
            spec.symbol_count * 5 - spec.codeword_len * 8
        );

        let symbols = encoded(spec, &input);
        assert_eq!(symbols.len(), spec.symbol_count);
        assert!(symbols.iter().all(|symbol| ALPHABET.contains(symbol)));
        if spec.padding_bits != 0 {
            let final_value = alphabet_value(*symbols.last().unwrap()).unwrap();
            assert_eq!(final_value & ((1 << spec.padding_bits) - 1), 0);
        }

        let codeword = bytes_from_symbols(&symbols, spec.codeword_len);
        assert_eq!(&codeword[..BODY_LEN], &input[FIXED_HEADER.len()..]);
        let mut output = SENTINEL_CAPSULE;
        assert_eq!(
            decode(
                spec.profile,
                &symbols,
                &vec![0; spec.symbol_count],
                &mut output,
            ),
            Ok(DecodeReport {
                corrected_errors: 0,
                erased_bytes: 0,
            })
        );
        assert_eq!(output, input);

        // The codec deliberately transports, but does not authenticate, a capsule body.
        let changed_symbols = encoded(spec, &changed_tag);
        assert_ne!(changed_symbols, symbols);
        let mut changed_output = SENTINEL_CAPSULE;
        assert!(decode(
            spec.profile,
            &changed_symbols,
            &vec![0; spec.symbol_count],
            &mut changed_output,
        )
        .is_ok());
        assert_eq!(changed_output, changed_tag);

        for other in SPECS {
            if other.symbol_count != spec.symbol_count {
                assert_decode_rejection(
                    other,
                    &symbols,
                    &vec![0; symbols.len()],
                    CodecError::InvalidSymbolCount,
                );
            }
        }
    }
}

#[test]
fn header_lengths_masks_and_rejection_precedence_are_exhaustive() {
    let canonical = capsule(0x42);
    let mut invalid_headers = 0usize;
    for header_index in 0..FIXED_HEADER.len() {
        for candidate in 0u8..=u8::MAX {
            if candidate == FIXED_HEADER[header_index] {
                continue;
            }
            let mut input = canonical;
            input[header_index] = candidate;
            let mut output = [0x5a; MAX_SYMBOL_COUNT];
            assert_eq!(
                encode(CodecProfile::Rs72_60, &input, &mut output[..116],),
                Err(CodecError::InvalidCapsuleHeader)
            );
            assert_eq!(output, [0x5a; MAX_SYMBOL_COUNT]);
            invalid_headers += 1;
        }
    }
    assert_eq!(invalid_headers, 7 * 255);

    let mut header_first = canonical;
    header_first[0] ^= 1;
    let mut empty_output = [];
    assert_eq!(
        encode(CodecProfile::Rs72_60, &header_first, &mut empty_output),
        Err(CodecError::InvalidCapsuleHeader)
    );

    let mut encode_wrong_lengths = 0usize;
    let mut decode_wrong_lengths = 0usize;
    let mut mask_wrong_lengths = 0usize;
    let mut invalid_markers = 0usize;
    for spec in SPECS {
        let valid_symbols = encoded(spec, &canonical);

        for length in 0..=MAX_SYMBOL_COUNT + 1 {
            if length == spec.symbol_count {
                continue;
            }
            let mut output = vec![0x5a; length];
            assert_eq!(
                encode(spec.profile, &canonical, &mut output),
                Err(CodecError::InvalidSymbolCount)
            );
            assert!(output.iter().all(|byte| *byte == 0x5a));
            encode_wrong_lengths += 1;

            // Symbol count precedes both mask representation and symbol parsing.
            let invalid_symbols = vec![0xff; length];
            assert_decode_rejection(spec, &invalid_symbols, &[2], CodecError::InvalidSymbolCount);
            decode_wrong_lengths += 1;
        }

        for length in 0..=MAX_SYMBOL_COUNT + 1 {
            if length == spec.symbol_count {
                continue;
            }
            assert_decode_rejection(
                spec,
                &valid_symbols,
                &vec![0; length],
                CodecError::MalformedErasureRepresentation,
            );
            mask_wrong_lengths += 1;
        }

        let mut mask = vec![0u8; spec.symbol_count];
        for position in 0..spec.symbol_count {
            for marker in 2u8..=u8::MAX {
                mask[position] = marker;
                assert_decode_rejection(
                    spec,
                    &valid_symbols,
                    &mask,
                    CodecError::MalformedErasureRepresentation,
                );
                mask[position] = 0;
                invalid_markers += 1;
            }
        }

        let mut invalid_symbols = valid_symbols.clone();
        invalid_symbols[0] = 0xff;
        mask[0] = 2;
        assert_decode_rejection(
            spec,
            &invalid_symbols,
            &mask,
            CodecError::MalformedErasureRepresentation,
        );

        mask.fill(0);
        invalid_symbols = valid_symbols.clone();
        invalid_symbols[0] = 0xff;
        if spec.padding_bits != 0 {
            invalid_symbols[spec.symbol_count - 1] = ALPHABET[1];
        }
        assert_decode_rejection(spec, &invalid_symbols, &mask, CodecError::MalformedSymbol);

        let singles = single_byte_erasure_symbols(spec);
        for (symbol_index, _) in &singles[..=spec.parity] {
            mask[*symbol_index] = 1;
        }
        invalid_symbols = valid_symbols.clone();
        invalid_symbols[1] = 0xff;
        assert_decode_rejection(spec, &invalid_symbols, &mask, CodecError::MalformedSymbol);
        if spec.padding_bits != 0 {
            invalid_symbols = valid_symbols.clone();
            invalid_symbols[spec.symbol_count - 1] = ALPHABET[1];
            assert_decode_rejection(
                spec,
                &invalid_symbols,
                &mask,
                CodecError::NonCanonicalPadding,
            );
        }
    }

    assert_eq!(encode_wrong_lengths, 3 * 129);
    assert_eq!(decode_wrong_lengths, 3 * 129);
    assert_eq!(mask_wrong_lengths, 3 * 129);
    assert_eq!(invalid_markers, (116 + 122 + 128) * 254);
}

#[test]
fn every_symbol_byte_and_terminal_padding_combination_is_classified() {
    let input = capsule(0x53);
    let mut malformed = 0usize;
    let mut noncanonical_padding = 0usize;
    let mut corrected_or_unchanged = 0usize;

    for spec in SPECS {
        let original = encoded(spec, &input);
        let mask = vec![0u8; spec.symbol_count];
        for position in 0..spec.symbol_count {
            for candidate in 0u8..=u8::MAX {
                let mut symbols = original.clone();
                symbols[position] = candidate;
                let Some(value) = alphabet_value(candidate) else {
                    assert_decode_rejection(spec, &symbols, &mask, CodecError::MalformedSymbol);
                    malformed += 1;
                    continue;
                };

                let bad_padding = position + 1 == spec.symbol_count
                    && spec.padding_bits != 0
                    && value & ((1 << spec.padding_bits) - 1) != 0;
                if bad_padding {
                    assert_decode_rejection(spec, &symbols, &mask, CodecError::NonCanonicalPadding);
                    noncanonical_padding += 1;
                    continue;
                }

                let mut output = SENTINEL_CAPSULE;
                let report = decode(spec.profile, &symbols, &mask, &mut output).unwrap();
                assert_eq!(output, input);
                if candidate == original[position] {
                    assert_eq!(report.corrected_errors, 0);
                } else {
                    assert!((1..=2).contains(&report.corrected_errors));
                }
                assert_eq!(report.erased_bytes, 0);
                corrected_or_unchanged += 1;
            }
        }
    }

    assert_eq!(malformed, (116 + 122 + 128) * (256 - 32));
    assert_eq!(noncanonical_padding, 30 + 24);
    assert_eq!(corrected_or_unchanged, (116 + 122 + 128) * 32 - 54);
}

#[test]
fn every_single_and_adjacent_symbol_erasure_maps_to_deduplicated_bytes() {
    let input = capsule(0x64);
    let mut singles = 0usize;
    let mut adjacent_pairs = 0usize;

    for spec in SPECS {
        let original = encoded(spec, &input);
        for position in 0..spec.symbol_count {
            let mut symbols = original.clone();
            let mut mask = vec![0u8; spec.symbol_count];
            symbols[position] = 0xff;
            mask[position] = 1;
            let expected_erased = union_erased_bytes(spec, &mask).len();
            let mut output = SENTINEL_CAPSULE;
            let report = decode(spec.profile, &symbols, &mask, &mut output).unwrap();
            assert_eq!(output, input);
            assert_eq!(report.corrected_errors, 0);
            assert_eq!(report.erased_bytes as usize, expected_erased);
            assert!((1..=2).contains(&expected_erased));
            singles += 1;
        }

        for position in 0..spec.symbol_count - 1 {
            let mut symbols = original.clone();
            let mut mask = vec![0u8; spec.symbol_count];
            symbols[position] = 0xff;
            symbols[position + 1] = 0xff;
            mask[position] = 1;
            mask[position + 1] = 1;
            let expected_erased = union_erased_bytes(spec, &mask).len();
            let mut output = SENTINEL_CAPSULE;
            let report = decode(spec.profile, &symbols, &mask, &mut output).unwrap();
            assert_eq!(output, input);
            assert_eq!(report.corrected_errors, 0);
            assert_eq!(report.erased_bytes as usize, expected_erased);
            assert!((1..=3).contains(&expected_erased));
            adjacent_pairs += 1;
        }
    }

    assert_eq!(singles, 116 + 122 + 128);
    assert_eq!(adjacent_pairs, 115 + 121 + 127);
}

fn mutate_codeword_with_capacity_case(
    spec: Spec,
    original_symbols: &[u8],
    erased_count: usize,
    error_count: usize,
) -> (Vec<u8>, Vec<u8>, Vec<usize>) {
    let singles = single_byte_erasure_symbols(spec);
    assert!(singles.len() > spec.parity);
    let chosen_erasures = &singles[..erased_count];
    let erased_bytes: Vec<usize> = chosen_erasures.iter().map(|(_, byte)| *byte).collect();

    let mut codeword = bytes_from_symbols(original_symbols, spec.codeword_len);
    let mut errors_written = 0usize;
    for (position, byte) in codeword[..spec.codeword_len].iter_mut().enumerate() {
        if erased_bytes.contains(&position) {
            continue;
        }
        if errors_written == error_count {
            break;
        }
        let magnitude = ((errors_written * 73) % 255 + 1) as u8;
        *byte ^= magnitude;
        errors_written += 1;
    }
    assert_eq!(errors_written, error_count);

    let mut symbols = symbols_from_bytes(&codeword);
    let mut mask = vec![0u8; spec.symbol_count];
    for (symbol_index, _) in chosen_erasures {
        symbols[*symbol_index] = 0xff;
        mask[*symbol_index] = 1;
    }
    (symbols, mask, erased_bytes)
}

#[test]
fn every_integer_error_erasure_pair_through_full_capacity_corrects() {
    let input = capsule(0x75);
    let expected_grids = [49usize, 81, 121];
    let expected_boundaries = [7usize, 9, 11];
    let mut total_grid = 0usize;
    let mut total_boundary = 0usize;

    for (spec_index, spec) in SPECS.into_iter().enumerate() {
        let original = encoded(spec, &input);
        let mut grid = 0usize;
        let mut boundary = 0usize;
        for erased_count in 0..=spec.parity {
            for error_count in 0..=(spec.parity - erased_count) / 2 {
                let (symbols, mask, erased_bytes) =
                    mutate_codeword_with_capacity_case(spec, &original, erased_count, error_count);
                let mut output = SENTINEL_CAPSULE;
                let report = decode(spec.profile, &symbols, &mask, &mut output).unwrap();
                assert_eq!(output, input);
                assert_eq!(report.corrected_errors as usize, error_count);
                assert_eq!(report.erased_bytes as usize, erased_count);
                assert_eq!(erased_bytes.len(), erased_count);
                grid += 1;
                if 2 * error_count + erased_count == spec.parity {
                    boundary += 1;
                }
            }
        }
        assert_eq!(grid, expected_grids[spec_index]);
        assert_eq!(boundary, expected_boundaries[spec_index]);
        total_grid += grid;
        total_boundary += boundary;
    }

    assert_eq!(total_grid, 251);
    assert_eq!(total_boundary, 27);
}

#[test]
fn every_single_codeword_byte_and_nonzero_magnitude_corrects() {
    let input = capsule(0x86);
    let mut cases = 0usize;
    for spec in SPECS {
        let original_symbols = encoded(spec, &input);
        let original_codeword = bytes_from_symbols(&original_symbols, spec.codeword_len);
        let mask = vec![0u8; spec.symbol_count];
        for position in 0..spec.codeword_len {
            for magnitude in 1u8..=u8::MAX {
                let mut codeword = original_codeword.clone();
                codeword[position] ^= magnitude;
                let symbols = symbols_from_bytes(&codeword);
                let mut output = SENTINEL_CAPSULE;
                assert_eq!(
                    decode(spec.profile, &symbols, &mask, &mut output),
                    Ok(DecodeReport {
                        corrected_errors: 1,
                        erased_bytes: 0,
                    })
                );
                assert_eq!(output, input);
                cases += 1;
            }
        }
    }
    assert_eq!(cases, (72 + 76 + 80) * 255);
}

#[test]
fn deduplication_controls_capacity_and_unique_overflow_is_rejected() {
    let input = capsule(0x97);
    let mut overflow_cases = 0usize;
    let mut deduplicated_capacity_cases = 0usize;

    for spec in SPECS {
        let original = encoded(spec, &input);
        let singles = single_byte_erasure_symbols(spec);
        assert!(singles.len() > spec.parity);

        let mut over_symbols = original.clone();
        let mut over_mask = vec![0u8; spec.symbol_count];
        for (symbol_index, _) in &singles[..=spec.parity] {
            over_symbols[*symbol_index] = 0xff;
            over_mask[*symbol_index] = 1;
        }
        assert_eq!(union_erased_bytes(spec, &over_mask).len(), spec.parity + 1);
        assert_decode_rejection(spec, &over_symbols, &over_mask, CodecError::OverCapacity);
        overflow_cases += 1;

        // Symbols 0 and 2 erase bytes 0 and 1; symbol 1 overlaps both and must
        // not count either byte twice. Fill the remaining capacity with exact
        // single-byte symbols.
        let mut at_symbols = original.clone();
        let mut at_mask = vec![0u8; spec.symbol_count];
        for symbol_index in [0usize, 1, 2] {
            at_symbols[symbol_index] = 0xff;
            at_mask[symbol_index] = 1;
        }
        let mut erased = union_erased_bytes(spec, &at_mask);
        assert_eq!(erased, vec![0, 1]);
        for (symbol_index, byte_index) in &singles {
            if erased.len() == spec.parity {
                break;
            }
            if erased.contains(byte_index) {
                continue;
            }
            at_symbols[*symbol_index] = 0xff;
            at_mask[*symbol_index] = 1;
            erased.push(*byte_index);
        }
        erased.sort_unstable();
        erased.dedup();
        assert_eq!(erased.len(), spec.parity);
        assert!(at_mask.iter().filter(|marker| **marker == 1).count() > spec.parity);
        let mut output = SENTINEL_CAPSULE;
        assert_eq!(
            decode(spec.profile, &at_symbols, &at_mask, &mut output),
            Ok(DecodeReport {
                corrected_errors: 0,
                erased_bytes: spec.parity as u8,
            })
        );
        assert_eq!(output, input);
        deduplicated_capacity_cases += 1;
    }

    assert_eq!(overflow_cases, 3);
    assert_eq!(deduplicated_capacity_cases, 3);
}

fn ambiguous_received_word(spec: Spec) -> (Vec<u8>, Vec<u8>) {
    let mut first = capsule(0);
    first[FIXED_HEADER.len()..].fill(0);
    let first_symbols = encoded(spec, &first);
    let first_codeword = bytes_from_symbols(&first_symbols, spec.codeword_len);
    let singles = single_byte_erasure_symbols(spec);

    for changed_data_byte in 0..BODY_LEN {
        let Some((erasure_symbol, _)) = singles
            .iter()
            .find(|(_, byte_index)| *byte_index == changed_data_byte)
            .copied()
        else {
            continue;
        };
        let mut second = first;
        second[FIXED_HEADER.len() + changed_data_byte] = 1;
        let second_symbols = encoded(spec, &second);
        let second_codeword = bytes_from_symbols(&second_symbols, spec.codeword_len);
        let differences: Vec<usize> = first_codeword
            .iter()
            .zip(second_codeword.iter())
            .enumerate()
            .filter_map(|(position, (left, right))| (left != right).then_some(position))
            .collect();
        if differences.len() != spec.parity + 1 || !differences.contains(&changed_data_byte) {
            continue;
        }

        let mut received = first_codeword.clone();
        let parity_differences: Vec<usize> = differences
            .into_iter()
            .filter(|position| *position != changed_data_byte)
            .collect();
        assert_eq!(parity_differences.len(), spec.parity);
        for position in &parity_differences[..spec.parity / 2] {
            received[*position] = second_codeword[*position];
        }
        let mut received_symbols = symbols_from_bytes(&received);
        let mut erasure_mask = vec![0u8; spec.symbol_count];
        received_symbols[erasure_symbol] = 0xff;
        erasure_mask[erasure_symbol] = 1;
        return (received_symbols, erasure_mask);
    }

    panic!("no full-distance systematic basis codeword found");
}

#[test]
fn deterministic_midpoints_have_no_unique_codeword() {
    let mut cases = 0usize;
    for spec in SPECS {
        let (symbols, mask) = ambiguous_received_word(spec);
        assert_eq!(union_erased_bytes(spec, &mask).len(), 1);
        assert_decode_rejection(spec, &symbols, &mask, CodecError::NoUniqueCodeword);
        cases += 1;
    }
    assert_eq!(cases, 3);
}
