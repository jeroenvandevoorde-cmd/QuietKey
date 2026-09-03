//! Private fixed-memory SHA-256 following FIPS 180-4.

#![allow(clippy::chunks_exact_to_as_chunks)]

use crate::wipe;

const BLOCK_BYTES: usize = 64;
const INITIAL: [u32; 8] = [
    0x6a09_e667,
    0xbb67_ae85,
    0x3c6e_f372,
    0xa54f_f53a,
    0x510e_527f,
    0x9b05_688c,
    0x1f83_d9ab,
    0x5be0_cd19,
];
const K: [u32; 64] = [
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
    buffer: [u8; BLOCK_BYTES],
    buffered: usize,
    bytes: u64,
}

impl Sha256 {
    pub(crate) fn new() -> Self {
        Self {
            state: INITIAL,
            buffer: [0; BLOCK_BYTES],
            buffered: 0,
            bytes: 0,
        }
    }

    pub(crate) fn update(&mut self, mut input: &[u8]) {
        self.bytes = self.bytes.wrapping_add(input.len() as u64);
        if self.buffered != 0 {
            let take = core::cmp::min(BLOCK_BYTES - self.buffered, input.len());
            self.buffer[self.buffered..self.buffered + take].copy_from_slice(&input[..take]);
            self.buffered += take;
            input = &input[take..];
            if self.buffered == BLOCK_BYTES {
                compress(&mut self.state, &self.buffer);
                wipe::bytes(&mut self.buffer);
                self.buffered = 0;
            } else {
                return;
            }
        }
        while input.len() >= BLOCK_BYTES {
            let (block, rest) = input.split_at(BLOCK_BYTES);
            compress(&mut self.state, block);
            input = rest;
        }
        self.buffer[..input.len()].copy_from_slice(input);
        self.buffered = input.len();
    }

    pub(crate) fn finish(mut self, output: &mut [u8; 32]) {
        let bit_len = self.bytes.wrapping_mul(8);
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
        for (chunk, word) in output.chunks_exact_mut(4).zip(self.state.iter()) {
            chunk.copy_from_slice(&word.to_be_bytes());
        }
        wipe::bytes(&mut self.buffer);
        wipe::words32(&mut self.state);
        core::hint::black_box(&mut self);
    }
}

impl Drop for Sha256 {
    fn drop(&mut self) {
        wipe::words32(&mut self.state);
        wipe::bytes(&mut self.buffer);
        self.buffered = 0;
        self.bytes = 0;
    }
}

fn compress(state: &mut [u32; 8], block: &[u8]) {
    let mut w = [0u32; 64];
    for (word, chunk) in w[..16].iter_mut().zip(block.chunks_exact(4)) {
        *word = u32::from_be_bytes([chunk[0], chunk[1], chunk[2], chunk[3]]);
    }
    for i in 16..64 {
        let a = w[i - 15].rotate_right(7) ^ w[i - 15].rotate_right(18) ^ (w[i - 15] >> 3);
        let b = w[i - 2].rotate_right(17) ^ w[i - 2].rotate_right(19) ^ (w[i - 2] >> 10);
        w[i] = w[i - 16]
            .wrapping_add(a)
            .wrapping_add(w[i - 7])
            .wrapping_add(b);
    }
    let mut v = *state;
    for i in 0..64 {
        let s1 = v[4].rotate_right(6) ^ v[4].rotate_right(11) ^ v[4].rotate_right(25);
        let ch = (v[4] & v[5]) ^ ((!v[4]) & v[6]);
        let t1 = v[7]
            .wrapping_add(s1)
            .wrapping_add(ch)
            .wrapping_add(K[i])
            .wrapping_add(w[i]);
        let s0 = v[0].rotate_right(2) ^ v[0].rotate_right(13) ^ v[0].rotate_right(22);
        let maj = (v[0] & v[1]) ^ (v[0] & v[2]) ^ (v[1] & v[2]);
        let t2 = s0.wrapping_add(maj);
        v = [
            t1.wrapping_add(t2),
            v[0],
            v[1],
            v[2],
            v[3].wrapping_add(t1),
            v[4],
            v[5],
            v[6],
        ];
    }
    for (dst, value) in state.iter_mut().zip(v.iter()) {
        *dst = dst.wrapping_add(*value);
    }
    wipe::words32(&mut w);
    wipe::words32(&mut v);
}

pub(crate) fn hash(parts: &[&[u8]], output: &mut [u8; 32]) {
    let mut hash = Sha256::new();
    for part in parts {
        hash.update(part);
    }
    hash.finish(output);
}

#[cfg(test)]
mod tests {
    use super::hash;

    #[test]
    fn fips_known_answers() {
        let mut output = [0u8; 32];
        hash(&[b""], &mut output);
        assert_eq!(
            output,
            [
                0xe3, 0xb0, 0xc4, 0x42, 0x98, 0xfc, 0x1c, 0x14, 0x9a, 0xfb, 0xf4, 0xc8, 0x99, 0x6f,
                0xb9, 0x24, 0x27, 0xae, 0x41, 0xe4, 0x64, 0x9b, 0x93, 0x4c, 0xa4, 0x95, 0x99, 0x1b,
                0x78, 0x52, 0xb8, 0x55
            ]
        );
        hash(&[b"a", b"bc"], &mut output);
        assert_eq!(
            output,
            [
                0xba, 0x78, 0x16, 0xbf, 0x8f, 0x01, 0xcf, 0xea, 0x41, 0x41, 0x40, 0xde, 0x5d, 0xae,
                0x22, 0x23, 0xb0, 0x03, 0x61, 0xa3, 0x96, 0x17, 0x7a, 0x9c, 0xb4, 0x10, 0xff, 0x61,
                0xf2, 0x00, 0x15, 0xad
            ]
        );
        let hundred = [b'a'; 100];
        hash(
            &[&hundred[..17], &hundred[17..64], &hundred[64..]],
            &mut output,
        );
        assert_eq!(
            output,
            [
                0x28, 0x16, 0x59, 0x78, 0x88, 0xe4, 0xa0, 0xd3, 0xa3, 0x6b, 0x82, 0xb8, 0x33, 0x16,
                0xab, 0x32, 0x68, 0x0e, 0xb8, 0xf0, 0x0f, 0x8c, 0xd3, 0xb9, 0x04, 0xd6, 0x81, 0x24,
                0x6d, 0x28, 0x5a, 0x0e,
            ]
        );
    }
}
