//! Private fixed-memory SHA-256 following FIPS 180-4.

use crate::secret::{wipe, wipe_u32};

const BLOCK_LEN: usize = 64;

const INITIAL_STATE: [u32; 8] = [
    0x6a09_e667,
    0xbb67_ae85,
    0x3c6e_f372,
    0xa54f_f53a,
    0x510e_527f,
    0x9b05_688c,
    0x1f83_d9ab,
    0x5be0_cd19,
];

const ROUND_CONSTANTS: [u32; 64] = [
    0x428a_2f98,
    0x7137_4491,
    0xb5c0_fbcf,
    0xe9b5_dba5,
    0x3956_c25b,
    0x59f1_11f1,
    0x923f_82a4,
    0xab1c_5ed5,
    0xd807_aa98,
    0x1283_5b01,
    0x2431_85be,
    0x550c_7dc3,
    0x72be_5d74,
    0x80de_b1fe,
    0x9bdc_06a7,
    0xc19b_f174,
    0xe49b_69c1,
    0xefbe_4786,
    0x0fc1_9dc6,
    0x240c_a1cc,
    0x2de9_2c6f,
    0x4a74_84aa,
    0x5cb0_a9dc,
    0x76f9_88da,
    0x983e_5152,
    0xa831_c66d,
    0xb003_27c8,
    0xbf59_7fc7,
    0xc6e0_0bf3,
    0xd5a7_9147,
    0x06ca_6351,
    0x1429_2967,
    0x27b7_0a85,
    0x2e1b_2138,
    0x4d2c_6dfc,
    0x5338_0d13,
    0x650a_7354,
    0x766a_0abb,
    0x81c2_c92e,
    0x9272_2c85,
    0xa2bf_e8a1,
    0xa81a_664b,
    0xc24b_8b70,
    0xc76c_51a3,
    0xd192_e819,
    0xd699_0624,
    0xf40e_3585,
    0x106a_a070,
    0x19a4_c116,
    0x1e37_6c08,
    0x2748_774c,
    0x34b0_bcb5,
    0x391c_0cb3,
    0x4ed8_aa4a,
    0x5b9c_ca4f,
    0x682e_6ff3,
    0x748f_82ee,
    0x78a5_636f,
    0x84c8_7814,
    0x8cc7_0208,
    0x90be_fffa,
    0xa450_6ceb,
    0xbef9_a3f7,
    0xc671_78f2,
];

pub(crate) struct Sha256 {
    state: [u32; 8],
    buffer: [u8; BLOCK_LEN],
    buffered: usize,
    message_len: u64,
}

impl Sha256 {
    pub(crate) const fn new() -> Self {
        Self {
            state: INITIAL_STATE,
            buffer: [0u8; BLOCK_LEN],
            buffered: 0,
            message_len: 0,
        }
    }

    pub(crate) fn update(&mut self, mut input: &[u8]) {
        self.message_len = self
            .message_len
            .checked_add(input.len() as u64)
            .expect("bounded qk-kit SHA-256 input length");

        if self.buffered != 0 {
            let taken = core::cmp::min(BLOCK_LEN - self.buffered, input.len());
            self.buffer[self.buffered..self.buffered + taken].copy_from_slice(&input[..taken]);
            self.buffered += taken;
            input = &input[taken..];
            if self.buffered < BLOCK_LEN {
                return;
            }
            compress(&mut self.state, &self.buffer);
            wipe(&mut self.buffer);
            self.buffered = 0;
        }

        while input.len() >= BLOCK_LEN {
            let (block, remaining) = input.split_at(BLOCK_LEN);
            compress(&mut self.state, block);
            input = remaining;
        }

        if !input.is_empty() {
            self.buffer[..input.len()].copy_from_slice(input);
            self.buffered = input.len();
        }
    }

    pub(crate) fn finish(&mut self, digest: &mut [u8; 32]) {
        let bit_len = self
            .message_len
            .checked_mul(8)
            .expect("bounded qk-kit SHA-256 bit length");
        self.buffer[self.buffered] = 0x80;
        self.buffered += 1;

        if self.buffered > 56 {
            self.buffer[self.buffered..].fill(0);
            compress(&mut self.state, &self.buffer);
            self.buffer.fill(0);
        } else {
            self.buffer[self.buffered..56].fill(0);
        }
        self.buffer[56..].copy_from_slice(&bit_len.to_be_bytes());
        compress(&mut self.state, &self.buffer);

        for (index, word) in self.state.iter().enumerate() {
            let offset = index * 4;
            digest[offset..offset + 4].copy_from_slice(&word.to_be_bytes());
        }
        wipe_u32(&mut self.state);
        wipe(&mut self.buffer);
        self.buffered = 0;
        self.message_len = 0;
        core::hint::black_box(self);
    }
}

fn compress(state: &mut [u32; 8], block: &[u8]) {
    debug_assert_eq!(block.len(), BLOCK_LEN);
    let mut schedule = [0u32; 64];
    for (index, word) in schedule[..16].iter_mut().enumerate() {
        let offset = index * 4;
        *word = u32::from_be_bytes([
            block[offset],
            block[offset + 1],
            block[offset + 2],
            block[offset + 3],
        ]);
    }
    for index in 16..64 {
        let small0 = schedule[index - 15].rotate_right(7)
            ^ schedule[index - 15].rotate_right(18)
            ^ (schedule[index - 15] >> 3);
        let small1 = schedule[index - 2].rotate_right(17)
            ^ schedule[index - 2].rotate_right(19)
            ^ (schedule[index - 2] >> 10);
        schedule[index] = schedule[index - 16]
            .wrapping_add(small0)
            .wrapping_add(schedule[index - 7])
            .wrapping_add(small1);
    }

    let mut working = *state;
    let mut scratch = [0u32; 6];
    for index in 0..64 {
        scratch[0] =
            working[4].rotate_right(6) ^ working[4].rotate_right(11) ^ working[4].rotate_right(25);
        scratch[1] = (working[4] & working[5]) ^ ((!working[4]) & working[6]);
        scratch[2] = working[7]
            .wrapping_add(scratch[0])
            .wrapping_add(scratch[1])
            .wrapping_add(ROUND_CONSTANTS[index])
            .wrapping_add(schedule[index]);
        scratch[3] =
            working[0].rotate_right(2) ^ working[0].rotate_right(13) ^ working[0].rotate_right(22);
        scratch[4] =
            (working[0] & working[1]) ^ (working[0] & working[2]) ^ (working[1] & working[2]);
        scratch[5] = scratch[3].wrapping_add(scratch[4]);
        working[7] = working[6];
        working[6] = working[5];
        working[5] = working[4];
        working[4] = working[3].wrapping_add(scratch[2]);
        working[3] = working[2];
        working[2] = working[1];
        working[1] = working[0];
        working[0] = scratch[2].wrapping_add(scratch[5]);
    }

    for (word, mixed) in state.iter_mut().zip(working.iter()) {
        *word = word.wrapping_add(*mixed);
    }
    wipe_u32(&mut schedule);
    wipe_u32(&mut working);
    wipe_u32(&mut scratch);
}
