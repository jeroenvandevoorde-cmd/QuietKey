//! Private IETF ChaCha20 core following RFC 8439.

use crate::wipe;

const CONSTANTS: [u32; 4] = [0x6170_7865, 0x3320_646e, 0x7962_2d32, 0x6b20_6574];

#[inline]
fn quarter_round(state: &mut [u32; 16], a: usize, b: usize, c: usize, d: usize) {
    state[a] = state[a].wrapping_add(state[b]);
    state[d] ^= state[a];
    state[d] = state[d].rotate_left(16);

    state[c] = state[c].wrapping_add(state[d]);
    state[b] ^= state[c];
    state[b] = state[b].rotate_left(12);

    state[a] = state[a].wrapping_add(state[b]);
    state[d] ^= state[a];
    state[d] = state[d].rotate_left(8);

    state[c] = state[c].wrapping_add(state[d]);
    state[b] ^= state[c];
    state[b] = state[b].rotate_left(7);
}

pub(crate) fn block_into(key: &[u8; 32], counter: u32, nonce: &[u8; 12], output: &mut [u8; 64]) {
    let mut initial = [0u32; 16];
    initial[..4].copy_from_slice(&CONSTANTS);
    for (index, word) in initial[4..12].iter_mut().enumerate() {
        let offset = index * 4;
        *word = u32::from_le_bytes([
            key[offset],
            key[offset + 1],
            key[offset + 2],
            key[offset + 3],
        ]);
    }
    initial[12] = counter;
    for (index, word) in initial[13..].iter_mut().enumerate() {
        let offset = index * 4;
        *word = u32::from_le_bytes([
            nonce[offset],
            nonce[offset + 1],
            nonce[offset + 2],
            nonce[offset + 3],
        ]);
    }

    let mut working = initial;
    for _ in 0..10 {
        quarter_round(&mut working, 0, 4, 8, 12);
        quarter_round(&mut working, 1, 5, 9, 13);
        quarter_round(&mut working, 2, 6, 10, 14);
        quarter_round(&mut working, 3, 7, 11, 15);
        quarter_round(&mut working, 0, 5, 10, 15);
        quarter_round(&mut working, 1, 6, 11, 12);
        quarter_round(&mut working, 2, 7, 8, 13);
        quarter_round(&mut working, 3, 4, 9, 14);
    }

    for (index, (word, original)) in working.iter().zip(initial.iter()).enumerate() {
        let offset = index * 4;
        output[offset..offset + 4].copy_from_slice(&word.wrapping_add(*original).to_le_bytes());
    }
    wipe::words32(&mut working);
    wipe::words32(&mut initial);
}

#[cfg(test)]
pub(crate) fn block(key: &[u8; 32], counter: u32, nonce: &[u8; 12]) -> [u8; 64] {
    let mut output = [0u8; 64];
    block_into(key, counter, nonce, &mut output);
    output
}

pub(crate) fn xor(
    key: &[u8; 32],
    nonce: &[u8; 12],
    initial_counter: u32,
    input: &[u8],
    output: &mut [u8],
) -> bool {
    if input.len() != output.len() {
        return false;
    }
    let full_blocks = input.len() / 64;
    let block_count = full_blocks + usize::from(input.len() > full_blocks * 64);
    let available_blocks = u32::MAX as u128 - initial_counter as u128 + 1;
    if block_count as u128 > available_blocks {
        return false;
    }

    let mut counter = initial_counter;
    for (input_block, output_block) in input.chunks(64).zip(output.chunks_mut(64)) {
        let mut stream = [0u8; 64];
        block_into(key, counter, nonce, &mut stream);
        for (target, (source, mask)) in output_block
            .iter_mut()
            .zip(input_block.iter().zip(stream.iter()))
        {
            *target = source ^ mask;
        }
        wipe::bytes(&mut stream);
        counter = counter.wrapping_add(1);
    }
    true
}

#[cfg(test)]
mod tests {
    use super::block;

    #[test]
    fn rfc_8439_block_answer_passes() {
        let mut key = [0u8; 32];
        for (index, byte) in key.iter_mut().enumerate() {
            *byte = index as u8;
        }
        let nonce = [
            0x00, 0x00, 0x00, 0x09, 0x00, 0x00, 0x00, 0x4a, 0x00, 0x00, 0x00, 0x00,
        ];
        assert_eq!(
            block(&key, 1, &nonce),
            [
                0x10, 0xf1, 0xe7, 0xe4, 0xd1, 0x3b, 0x59, 0x15, 0x50, 0x0f, 0xdd, 0x1f, 0xa3, 0x20,
                0x71, 0xc4, 0xc7, 0xd1, 0xf4, 0xc7, 0x33, 0xc0, 0x68, 0x03, 0x04, 0x22, 0xaa, 0x9a,
                0xc3, 0xd4, 0x6c, 0x4e, 0xd2, 0x82, 0x64, 0x46, 0x07, 0x9f, 0xaa, 0x09, 0x14, 0xc2,
                0xd7, 0x05, 0xd9, 0x8b, 0x02, 0xa2, 0xb5, 0x12, 0x9c, 0xd1, 0xde, 0x16, 0x4e, 0xb9,
                0xcb, 0xd0, 0x83, 0xe8, 0xa2, 0x50, 0x3c, 0x4e,
            ]
        );
    }
}
