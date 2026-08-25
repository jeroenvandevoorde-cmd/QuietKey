//! Private systematic shortened Reed-Solomon encoder and bounded decoder.
//!
//! Coefficients are stored most-significant first for codeword evaluation.
//! For a codeword position `p`, `X_p = alpha^(n-1-p)`. Syndromes are
//! evaluations at roots alpha^0 through alpha^(r-1). Known erasures are
//! removed from the syndrome sequence before Berlekamp-Massey finds only the
//! unknown-error locator. Magnitudes for all distinct locations are then
//! solved by a bounded Vandermonde system. A result escapes only after all
//! syndromes vanish and systematic re-encoding is byte-equal.

use crate::gf256;

const DATA_LEN: usize = 60;
const MAX_PARITY: usize = 20;
const MAX_CODEWORD: usize = DATA_LEN + MAX_PARITY;
const MATRIX_WIDTH: usize = MAX_PARITY + 1;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum DecodeError {
    OverCapacity,
    NoUniqueCodeword,
}

fn generator(parity: usize) -> [u8; MAX_PARITY + 1] {
    let mut polynomial = [0u8; MAX_PARITY + 1];
    polynomial[0] = 1;
    for (degree, root_index) in (0..parity).enumerate() {
        let root = gf256::alpha_power(root_index);
        let previous = polynomial;
        polynomial.fill(0);
        for index in 0..=degree {
            polynomial[index] ^= previous[index];
            polynomial[index + 1] ^= gf256::multiply(previous[index], root);
        }
    }
    polynomial
}

pub(crate) fn encode(data: &[u8], parity: usize, codeword_out: &mut [u8]) {
    debug_assert_eq!(data.len(), DATA_LEN);
    debug_assert!(matches!(parity, 12 | 16 | 20));
    debug_assert_eq!(codeword_out.len(), DATA_LEN + parity);

    let polynomial = generator(parity);
    let mut division = [0u8; MAX_CODEWORD];
    division[..DATA_LEN].copy_from_slice(data);
    for message_index in 0..DATA_LEN {
        let coefficient = division[message_index];
        if coefficient == 0 {
            continue;
        }
        for generator_index in 0..=parity {
            division[message_index + generator_index] ^=
                gf256::multiply(coefficient, polynomial[generator_index]);
        }
    }

    codeword_out[..DATA_LEN].copy_from_slice(data);
    codeword_out[DATA_LEN..].copy_from_slice(&division[DATA_LEN..DATA_LEN + parity]);
}

fn syndromes(codeword: &[u8], parity: usize) -> [u8; MAX_PARITY] {
    let mut result = [0u8; MAX_PARITY];
    for (root_index, syndrome) in result[..parity].iter_mut().enumerate() {
        let root = gf256::alpha_power(root_index);
        for byte in codeword {
            *syndrome = gf256::add(gf256::multiply(*syndrome, root), *byte);
        }
    }
    result
}

fn remove_erasure_syndromes(
    syndrome: &[u8; MAX_PARITY],
    codeword_len: usize,
    erasures: &[bool],
    parity: usize,
) -> ([u8; MAX_PARITY], usize) {
    let mut reduced = *syndrome;
    let mut reduced_len = parity;
    for (position, erased) in erasures.iter().enumerate() {
        if !*erased {
            continue;
        }
        let location = gf256::alpha_power(codeword_len - 1 - position);
        for index in 0..reduced_len - 1 {
            reduced[index] = gf256::add(
                reduced[index + 1],
                gf256::multiply(location, reduced[index]),
            );
        }
        reduced_len -= 1;
    }
    (reduced, reduced_len)
}

fn berlekamp_massey(sequence: &[u8]) -> Option<([u8; MAX_PARITY + 1], usize)> {
    let mut connection = [0u8; MAX_PARITY + 1];
    let mut previous = [0u8; MAX_PARITY + 1];
    connection[0] = 1;
    previous[0] = 1;
    let mut degree = 0usize;
    let mut shift = 1usize;
    let mut prior_discrepancy = 1u8;

    for index in 0..sequence.len() {
        let mut discrepancy = sequence[index];
        for coefficient in 1..=degree {
            discrepancy ^= gf256::multiply(connection[coefficient], sequence[index - coefficient]);
        }
        if discrepancy == 0 {
            shift += 1;
            continue;
        }

        let scale = gf256::divide(discrepancy, prior_discrepancy)?;
        let old_connection = connection;
        if shift > MAX_PARITY {
            return None;
        }
        for coefficient in 0..=MAX_PARITY - shift {
            connection[coefficient + shift] ^= gf256::multiply(scale, previous[coefficient]);
        }

        if 2 * degree <= index {
            degree = index + 1 - degree;
            previous = old_connection;
            prior_discrepancy = discrepancy;
            shift = 1;
        } else {
            shift += 1;
        }
    }

    (2 * degree <= sequence.len()).then_some((connection, degree))
}

fn evaluate_ascending(polynomial: &[u8], point: u8) -> u8 {
    let mut value = 0u8;
    for coefficient in polynomial.iter().rev() {
        value = gf256::add(gf256::multiply(value, point), *coefficient);
    }
    value
}

fn find_unknown_positions(
    locator: &[u8; MAX_PARITY + 1],
    degree: usize,
    codeword_len: usize,
    erasures: &[bool],
) -> Option<([usize; MAX_PARITY], usize)> {
    let mut positions = [0usize; MAX_PARITY];
    let mut count = 0usize;
    for (position, erased) in erasures.iter().enumerate() {
        let location = gf256::alpha_power(codeword_len - 1 - position);
        let inverse = gf256::inverse(location)?;
        if evaluate_ascending(&locator[..=degree], inverse) != 0 {
            continue;
        }
        if *erased || count == degree {
            return None;
        }
        positions[count] = position;
        count += 1;
    }
    (count == degree).then_some((positions, count))
}

fn solve_magnitudes(
    syndrome: &[u8; MAX_PARITY],
    codeword_len: usize,
    positions: &[usize],
) -> Option<[u8; MAX_PARITY]> {
    let count = positions.len();
    let mut matrix = [[0u8; MATRIX_WIDTH]; MAX_PARITY];
    for row in 0..count {
        for (column, position) in positions.iter().enumerate() {
            let location = gf256::alpha_power(codeword_len - 1 - position);
            matrix[row][column] = gf256::power(location, row);
        }
        matrix[row][count] = syndrome[row];
    }

    for column in 0..count {
        let pivot = (column..count).find(|row| matrix[*row][column] != 0)?;
        matrix.swap(column, pivot);
        let inverse = gf256::inverse(matrix[column][column])?;
        for value in &mut matrix[column][column..=count] {
            *value = gf256::multiply(*value, inverse);
        }
        let pivot_row = matrix[column];
        for (row_index, row) in matrix.iter_mut().enumerate().take(count) {
            if row_index == column {
                continue;
            }
            let scale = row[column];
            if scale == 0 {
                continue;
            }
            for (target, source) in row[column..=count]
                .iter_mut()
                .zip(pivot_row[column..=count].iter())
            {
                *target ^= gf256::multiply(scale, *source);
            }
        }
    }

    let mut magnitudes = [0u8; MAX_PARITY];
    for index in 0..count {
        magnitudes[index] = matrix[index][count];
    }
    Some(magnitudes)
}

fn is_systematic_codeword(codeword: &[u8], parity: usize) -> bool {
    let mut expected = [0u8; MAX_CODEWORD];
    encode(
        &codeword[..DATA_LEN],
        parity,
        &mut expected[..DATA_LEN + parity],
    );
    expected[..DATA_LEN + parity] == *codeword
}

pub(crate) fn decode(
    codeword: &mut [u8],
    erasures: &[bool],
    parity: usize,
) -> Result<usize, DecodeError> {
    debug_assert_eq!(codeword.len(), DATA_LEN + parity);
    debug_assert_eq!(erasures.len(), codeword.len());
    debug_assert!(matches!(parity, 12 | 16 | 20));

    let erasure_count = erasures.iter().filter(|erased| **erased).count();
    if erasure_count > parity {
        return Err(DecodeError::OverCapacity);
    }

    let original_syndrome = syndromes(codeword, parity);
    if original_syndrome[..parity].iter().all(|value| *value == 0) {
        return is_systematic_codeword(codeword, parity)
            .then_some(0)
            .ok_or(DecodeError::NoUniqueCodeword);
    }

    let (reduced, reduced_len) =
        remove_erasure_syndromes(&original_syndrome, codeword.len(), erasures, parity);
    let (locator, error_degree) =
        berlekamp_massey(&reduced[..reduced_len]).ok_or(DecodeError::NoUniqueCodeword)?;
    if 2 * error_degree + erasure_count > parity {
        return Err(DecodeError::NoUniqueCodeword);
    }
    let (unknown_positions, unknown_count) =
        find_unknown_positions(&locator, error_degree, codeword.len(), erasures)
            .ok_or(DecodeError::NoUniqueCodeword)?;
    if unknown_count != error_degree {
        return Err(DecodeError::NoUniqueCodeword);
    }

    let mut positions = [0usize; MAX_PARITY];
    let mut position_count = 0usize;
    for (position, erased) in erasures.iter().enumerate() {
        if *erased {
            positions[position_count] = position;
            position_count += 1;
        }
    }
    positions[position_count..position_count + unknown_count]
        .copy_from_slice(&unknown_positions[..unknown_count]);
    position_count += unknown_count;

    let magnitudes = solve_magnitudes(
        &original_syndrome,
        codeword.len(),
        &positions[..position_count],
    )
    .ok_or(DecodeError::NoUniqueCodeword)?;
    for magnitude in &magnitudes[erasure_count..position_count] {
        if *magnitude == 0 {
            return Err(DecodeError::NoUniqueCodeword);
        }
    }
    for index in 0..position_count {
        codeword[positions[index]] ^= magnitudes[index];
    }

    let corrected_syndrome = syndromes(codeword, parity);
    if corrected_syndrome[..parity].iter().any(|value| *value != 0)
        || !is_systematic_codeword(codeword, parity)
    {
        return Err(DecodeError::NoUniqueCodeword);
    }
    Ok(unknown_count)
}
