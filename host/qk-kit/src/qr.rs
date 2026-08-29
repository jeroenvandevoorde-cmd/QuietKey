//! Fixed-geometry QR encoder for the ratified Kit share frame.
//!
//! This module deliberately implements one profile only: a validated 142-byte
//! frame encoded in QR version 10, error-correction level Q, byte mode, without
//! ECI. It performs no allocation and exposes no variable QR parameters.

use crate::{KitError, QrMetadata};

const FRAME_LEN: usize = 142;
const DATA_CODEWORDS: usize = 154;
const ECC_CODEWORDS_PER_BLOCK: usize = 24;
const BLOCK_COUNT: usize = 8;
const SHORT_BLOCK_COUNT: usize = 6;
const SHORT_DATA_CODEWORDS: usize = 19;
const LONG_DATA_CODEWORDS: usize = 20;
const TOTAL_CODEWORDS: usize = 346;

const CORE_SIDE: usize = 57;
const CORE_MODULES: usize = CORE_SIDE * CORE_SIDE;
const QUIET_ZONE: usize = 4;
const OUTPUT_SIDE: usize = CORE_SIDE + QUIET_ZONE * 2;
const OUTPUT_MODULES: usize = OUTPUT_SIDE * OUTPUT_SIDE;
const PACKED_OUTPUT_BYTES: usize = OUTPUT_MODULES.div_ceil(8);

const _: () = assert!(
    SHORT_BLOCK_COUNT * SHORT_DATA_CODEWORDS
        + (BLOCK_COUNT - SHORT_BLOCK_COUNT) * LONG_DATA_CODEWORDS
        == DATA_CODEWORDS
);
const _: () = assert!(BLOCK_COUNT * ECC_CODEWORDS_PER_BLOCK == 192);
const _: () = assert!(DATA_CODEWORDS + BLOCK_COUNT * ECC_CODEWORDS_PER_BLOCK == TOTAL_CODEWORDS);
const _: () = assert!(TOTAL_CODEWORDS * 8 == 2_768);
const _: () = assert!(OUTPUT_SIDE == 65);
const _: () = assert!(PACKED_OUTPUT_BYTES == 529);

#[derive(Clone, Copy)]
struct Matrix {
    modules: [u8; CORE_MODULES],
    functions: [bool; CORE_MODULES],
}

impl Matrix {
    const fn new() -> Self {
        Self {
            modules: [0; CORE_MODULES],
            functions: [false; CORE_MODULES],
        }
    }

    fn module(&self, x: usize, y: usize) -> u8 {
        self.modules[y * CORE_SIDE + x]
    }

    fn set_function(&mut self, x: usize, y: usize, dark: bool) {
        let index = y * CORE_SIDE + x;
        self.modules[index] = u8::from(dark);
        self.functions[index] = true;
    }

    fn draw_function_patterns(&mut self) {
        for coordinate in 0..CORE_SIDE {
            self.set_function(6, coordinate, coordinate % 2 == 0);
            self.set_function(coordinate, 6, coordinate % 2 == 0);
        }

        self.draw_finder(3, 3);
        self.draw_finder(CORE_SIDE - 4, 3);
        self.draw_finder(3, CORE_SIDE - 4);

        const ALIGNMENT_CENTERS: [usize; 3] = [6, 28, 50];
        for (x_index, &x) in ALIGNMENT_CENTERS.iter().enumerate() {
            for (y_index, &y) in ALIGNMENT_CENTERS.iter().enumerate() {
                let overlaps_finder = (x_index == 0 && y_index == 0)
                    || (x_index == 0 && y_index == ALIGNMENT_CENTERS.len() - 1)
                    || (x_index == ALIGNMENT_CENTERS.len() - 1 && y_index == 0);
                if !overlaps_finder {
                    self.draw_alignment(x, y);
                }
            }
        }

        // A dummy value marks every format module as a function before data
        // placement. Each candidate later overwrites these bits with its mask.
        self.draw_format(0);
        self.draw_version();
    }

    fn draw_finder(&mut self, center_x: usize, center_y: usize) {
        for delta_y in -4i32..=4 {
            for delta_x in -4i32..=4 {
                let x = center_x as i32 + delta_x;
                let y = center_y as i32 + delta_y;
                if x < 0 || y < 0 || x >= CORE_SIDE as i32 || y >= CORE_SIDE as i32 {
                    continue;
                }
                let distance = delta_x.abs().max(delta_y.abs());
                self.set_function(x as usize, y as usize, distance != 2 && distance != 4);
            }
        }
    }

    fn draw_alignment(&mut self, center_x: usize, center_y: usize) {
        for delta_y in -2i32..=2 {
            for delta_x in -2i32..=2 {
                let distance = delta_x.abs().max(delta_y.abs());
                self.set_function(
                    (center_x as i32 + delta_x) as usize,
                    (center_y as i32 + delta_y) as usize,
                    distance != 1,
                );
            }
        }
    }

    fn draw_format(&mut self, mask: u8) {
        // Q is encoded as 0b11 in the two error-correction-level bits.
        let data = (0b11u32 << 3) | u32::from(mask);
        let mut remainder = data;
        for _ in 0..10 {
            remainder = (remainder << 1) ^ (((remainder >> 9) & 1) * 0x537);
        }
        let bits = ((data << 10) | remainder) ^ 0x5412;

        for bit in 0..6 {
            self.set_function(8, bit, get_bit(bits, bit));
        }
        self.set_function(8, 7, get_bit(bits, 6));
        self.set_function(8, 8, get_bit(bits, 7));
        self.set_function(7, 8, get_bit(bits, 8));
        for bit in 9..15 {
            self.set_function(14 - bit, 8, get_bit(bits, bit));
        }

        for bit in 0..8 {
            self.set_function(CORE_SIDE - 1 - bit, 8, get_bit(bits, bit));
        }
        for bit in 8..15 {
            self.set_function(8, CORE_SIDE - 15 + bit, get_bit(bits, bit));
        }
        self.set_function(8, CORE_SIDE - 8, true);
    }

    fn draw_version(&mut self) {
        const VERSION: u32 = 10;
        let mut remainder = VERSION;
        for _ in 0..12 {
            remainder = (remainder << 1) ^ (((remainder >> 11) & 1) * 0x1f25);
        }
        let bits = (VERSION << 12) | remainder;

        for bit in 0..18 {
            let x = CORE_SIDE - 11 + bit % 3;
            let y = bit / 3;
            let dark = get_bit(bits, bit);
            self.set_function(x, y, dark);
            self.set_function(y, x, dark);
        }
    }

    fn draw_codewords(&mut self, codewords: &[u8; TOTAL_CODEWORDS]) {
        let mut bit_index = 0usize;
        let mut right = CORE_SIDE - 1;
        loop {
            if right == 6 {
                right = 5;
            }
            for vertical in 0..CORE_SIDE {
                let upward = ((right + 1) & 2) == 0;
                let y = if upward {
                    CORE_SIDE - 1 - vertical
                } else {
                    vertical
                };
                for column in 0..2 {
                    let x = right - column;
                    let index = y * CORE_SIDE + x;
                    if !self.functions[index] {
                        debug_assert!(bit_index < TOTAL_CODEWORDS * 8);
                        self.modules[index] = (codewords[bit_index / 8] >> (7 - bit_index % 8)) & 1;
                        bit_index += 1;
                    }
                }
            }
            if right < 2 {
                break;
            }
            right -= 2;
        }
        debug_assert_eq!(bit_index, TOTAL_CODEWORDS * 8);
    }

    fn apply_mask(&mut self, mask: u8) {
        for y in 0..CORE_SIDE {
            for x in 0..CORE_SIDE {
                let product = x * y;
                let invert = match mask {
                    0 => (x + y) % 2 == 0,
                    1 => y % 2 == 0,
                    2 => x % 3 == 0,
                    3 => (x + y) % 3 == 0,
                    4 => (x / 3 + y / 2) % 2 == 0,
                    5 => product % 2 + product % 3 == 0,
                    6 => (product % 2 + product % 3) % 2 == 0,
                    7 => ((x + y) % 2 + product % 3) % 2 == 0,
                    _ => unreachable!("the fixed profile has exactly eight masks"),
                };
                let index = y * CORE_SIDE + x;
                if invert && !self.functions[index] {
                    self.modules[index] ^= 1;
                }
            }
        }
    }
}

#[derive(Clone, Copy)]
struct FinderPenalty {
    run_history: [u32; 7],
}

impl FinderPenalty {
    const fn new() -> Self {
        Self {
            run_history: [0; 7],
        }
    }

    fn add_run(&mut self, mut length: u32) {
        if self.run_history[0] == 0 {
            length += CORE_SIDE as u32;
        }
        self.run_history.copy_within(0..6, 1);
        self.run_history[0] = length;
    }

    fn pattern_count(&self) -> u32 {
        let history = &self.run_history;
        let unit = history[1];
        let core = unit > 0
            && history[2] == unit
            && history[3] == unit * 3
            && history[4] == unit
            && history[5] == unit;
        u32::from(core && history[0] >= unit * 4 && history[6] >= unit)
            + u32::from(core && history[6] >= unit * 4 && history[0] >= unit)
    }

    fn finish(mut self, run_is_dark: bool, mut run_length: u32) -> u32 {
        if run_is_dark {
            self.add_run(run_length);
            run_length = 0;
        }
        run_length += CORE_SIDE as u32;
        self.add_run(run_length);
        self.pattern_count()
    }
}

/// Encodes one validated Kit share frame into the fixed packed QR matrix.
///
/// The output uses row-major, most-significant-bit-first packing over the full
/// 65-by-65 symbol including the four-module light quiet zone. The seven unused
/// low bits of the final byte are zero. The output is unchanged on rejection.
pub fn encode_qr(frame: &[u8], output: &mut [u8; 529]) -> Result<QrMetadata, KitError> {
    crate::frame::validate(frame)?;
    debug_assert_eq!(frame.len(), FRAME_LEN);

    let data = make_data_codewords(frame);
    let codewords = add_ecc_and_interleave(&data);

    let mut base = Matrix::new();
    base.draw_function_patterns();
    base.draw_codewords(&codewords);

    let mut penalties = [0u32; 8];
    let mut selected_mask = 0u8;
    let mut selected_penalty = u32::MAX;
    for mask in 0u8..8 {
        let mut candidate = base;
        candidate.apply_mask(mask);
        candidate.draw_format(mask);
        let penalty = penalty_score(&candidate);
        penalties[usize::from(mask)] = penalty;
        if penalty < selected_penalty {
            selected_penalty = penalty;
            selected_mask = mask;
        }
    }

    let mut selected = base;
    selected.apply_mask(selected_mask);
    selected.draw_format(selected_mask);
    let packed = pack_with_quiet_zone(&selected);
    output.copy_from_slice(&packed);

    Ok(QrMetadata {
        mask: selected_mask,
        penalties,
    })
}

fn make_data_codewords(frame: &[u8]) -> [u8; DATA_CODEWORDS] {
    let mut result = [0u8; DATA_CODEWORDS];
    let mut bit_length = 0usize;

    append_bits(0b0100, 4, &mut result, &mut bit_length);
    append_bits(FRAME_LEN as u32, 16, &mut result, &mut bit_length);
    for &byte in frame {
        append_bits(u32::from(byte), 8, &mut result, &mut bit_length);
    }
    append_bits(0, 4, &mut result, &mut bit_length);

    debug_assert_eq!(bit_length, 1_160);
    debug_assert_eq!(bit_length % 8, 0);
    let mut byte_length = bit_length / 8;
    let mut use_first_pad = true;
    while byte_length < DATA_CODEWORDS {
        result[byte_length] = if use_first_pad { 0xec } else { 0x11 };
        use_first_pad = !use_first_pad;
        byte_length += 1;
    }
    result
}

fn append_bits(
    value: u32,
    count: usize,
    output: &mut [u8; DATA_CODEWORDS],
    bit_length: &mut usize,
) {
    debug_assert!(count <= 16);
    debug_assert!(count == 32 || value < (1u32 << count));
    debug_assert!(*bit_length + count <= DATA_CODEWORDS * 8);
    for shift in (0..count).rev() {
        let bit = ((value >> shift) & 1) as u8;
        output[*bit_length / 8] |= bit << (7 - *bit_length % 8);
        *bit_length += 1;
    }
}

fn add_ecc_and_interleave(data: &[u8; DATA_CODEWORDS]) -> [u8; TOTAL_CODEWORDS] {
    let divisor = reed_solomon_divisor();
    let mut blocks = [[0u8; LONG_DATA_CODEWORDS]; BLOCK_COUNT];
    let mut ecc = [[0u8; ECC_CODEWORDS_PER_BLOCK]; BLOCK_COUNT];
    let mut data_offset = 0usize;

    for block in 0..BLOCK_COUNT {
        let length = block_data_length(block);
        blocks[block][..length].copy_from_slice(&data[data_offset..data_offset + length]);
        ecc[block] = reed_solomon_remainder(&blocks[block][..length], &divisor);
        data_offset += length;
    }
    debug_assert_eq!(data_offset, DATA_CODEWORDS);

    let mut result = [0u8; TOTAL_CODEWORDS];
    let mut output_offset = 0usize;
    for column in 0..LONG_DATA_CODEWORDS {
        for (block_index, block) in blocks.iter().enumerate() {
            if column < block_data_length(block_index) {
                result[output_offset] = block[column];
                output_offset += 1;
            }
        }
    }
    for column in 0..ECC_CODEWORDS_PER_BLOCK {
        for block in &ecc {
            result[output_offset] = block[column];
            output_offset += 1;
        }
    }
    debug_assert_eq!(output_offset, TOTAL_CODEWORDS);
    result
}

const fn block_data_length(block: usize) -> usize {
    if block < SHORT_BLOCK_COUNT {
        SHORT_DATA_CODEWORDS
    } else {
        LONG_DATA_CODEWORDS
    }
}

fn reed_solomon_divisor() -> [u8; ECC_CODEWORDS_PER_BLOCK] {
    let mut result = [0u8; ECC_CODEWORDS_PER_BLOCK];
    result[ECC_CODEWORDS_PER_BLOCK - 1] = 1;
    let mut root = 1u8;
    for _ in 0..ECC_CODEWORDS_PER_BLOCK {
        for index in 0..ECC_CODEWORDS_PER_BLOCK {
            result[index] = gf_multiply(result[index], root);
            if index + 1 < ECC_CODEWORDS_PER_BLOCK {
                result[index] ^= result[index + 1];
            }
        }
        root = gf_multiply(root, 2);
    }
    result
}

fn reed_solomon_remainder(
    data: &[u8],
    divisor: &[u8; ECC_CODEWORDS_PER_BLOCK],
) -> [u8; ECC_CODEWORDS_PER_BLOCK] {
    let mut result = [0u8; ECC_CODEWORDS_PER_BLOCK];
    for &byte in data {
        let factor = byte ^ result[0];
        result.copy_within(1..ECC_CODEWORDS_PER_BLOCK, 0);
        result[ECC_CODEWORDS_PER_BLOCK - 1] = 0;
        for index in 0..ECC_CODEWORDS_PER_BLOCK {
            result[index] ^= gf_multiply(divisor[index], factor);
        }
    }
    result
}

fn gf_multiply(left: u8, right: u8) -> u8 {
    let mut result = 0u8;
    for shift in (0..8).rev() {
        result = (result << 1) ^ ((result >> 7) * 0x1d);
        result ^= ((right >> shift) & 1) * left;
    }
    result
}

fn get_bit(value: u32, bit: usize) -> bool {
    ((value >> bit) & 1) != 0
}

fn penalty_score(matrix: &Matrix) -> u32 {
    let mut n1 = 0u32;
    let mut n3 = 0u32;

    for y in 0..CORE_SIDE {
        let mut run_is_dark = false;
        let mut run_length = 0u32;
        let mut history = FinderPenalty::new();
        for x in 0..CORE_SIDE {
            let dark = matrix.module(x, y) != 0;
            if dark == run_is_dark {
                run_length += 1;
                if run_length == 5 {
                    n1 += 3;
                } else if run_length > 5 {
                    n1 += 1;
                }
            } else {
                history.add_run(run_length);
                if !run_is_dark {
                    n3 += history.pattern_count() * 40;
                }
                run_is_dark = dark;
                run_length = 1;
            }
        }
        n3 += history.finish(run_is_dark, run_length) * 40;
    }

    for x in 0..CORE_SIDE {
        let mut run_is_dark = false;
        let mut run_length = 0u32;
        let mut history = FinderPenalty::new();
        for y in 0..CORE_SIDE {
            let dark = matrix.module(x, y) != 0;
            if dark == run_is_dark {
                run_length += 1;
                if run_length == 5 {
                    n1 += 3;
                } else if run_length > 5 {
                    n1 += 1;
                }
            } else {
                history.add_run(run_length);
                if !run_is_dark {
                    n3 += history.pattern_count() * 40;
                }
                run_is_dark = dark;
                run_length = 1;
            }
        }
        n3 += history.finish(run_is_dark, run_length) * 40;
    }

    let mut n2 = 0u32;
    for y in 0..CORE_SIDE - 1 {
        for x in 0..CORE_SIDE - 1 {
            let color = matrix.module(x, y);
            if matrix.module(x + 1, y) == color
                && matrix.module(x, y + 1) == color
                && matrix.module(x + 1, y + 1) == color
            {
                n2 += 3;
            }
        }
    }

    let dark = matrix.modules.iter().copied().map(u32::from).sum::<u32>();
    let total = CORE_MODULES as u32;
    let imbalance = (dark * 20).abs_diff(total * 10);
    let bands_outside_inclusive_range = imbalance.div_ceil(total);
    let n4 = bands_outside_inclusive_range.saturating_sub(1) * 10;

    n1 + n2 + n3 + n4
}

fn pack_with_quiet_zone(matrix: &Matrix) -> [u8; PACKED_OUTPUT_BYTES] {
    let mut result = [0u8; PACKED_OUTPUT_BYTES];
    for y in 0..CORE_SIDE {
        for x in 0..CORE_SIDE {
            if matrix.module(x, y) == 0 {
                continue;
            }
            let output_x = x + QUIET_ZONE;
            let output_y = y + QUIET_ZONE;
            let bit_index = output_y * OUTPUT_SIDE + output_x;
            result[bit_index / 8] |= 1 << (7 - bit_index % 8);
        }
    }
    debug_assert_eq!(result[PACKED_OUTPUT_BYTES - 1] & 0x7f, 0);
    result
}
