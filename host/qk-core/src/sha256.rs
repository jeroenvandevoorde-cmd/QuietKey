//! Private fixed-memory SHA-256 for the exact v2 ceremony commitment.

#![allow(clippy::arithmetic_side_effects, clippy::indexing_slicing)]

use crate::wipe;

const BLOCK_LEN: usize = 64;
const TRANSCRIPT_LEN: usize = 100;
const COMMITMENT_DOMAIN: &[u8] = b"QuietKey/CeremonyTranscriptCommitment/v2";

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

struct Sha256 {
    state: [u32; 8],
    buffer: [u8; BLOCK_LEN],
    buffered: usize,
    message_len: u64,
}

impl Sha256 {
    const fn new() -> Self {
        Self {
            state: INITIAL_STATE,
            buffer: [0u8; BLOCK_LEN],
            buffered: 0,
            message_len: 0,
        }
    }

    fn update(&mut self, mut input: &[u8]) {
        self.message_len = self.message_len.wrapping_add(input.len() as u64);

        if self.buffered != 0 {
            let taken = core::cmp::min(BLOCK_LEN - self.buffered, input.len());
            self.buffer[self.buffered..self.buffered + taken].copy_from_slice(&input[..taken]);
            self.buffered += taken;
            input = &input[taken..];
            if self.buffered < BLOCK_LEN {
                return;
            }
            compress(&mut self.state, &self.buffer);
            wipe::bytes(&mut self.buffer);
            self.buffered = 0;
        }

        while input.len() >= BLOCK_LEN {
            let (block, remainder) = input.split_at(BLOCK_LEN);
            compress(&mut self.state, block);
            input = remainder;
        }

        if !input.is_empty() {
            self.buffer[..input.len()].copy_from_slice(input);
            self.buffered = input.len();
        }
    }

    fn finish(&mut self, digest: &mut [u8; 32]) {
        let bit_len = self.message_len.wrapping_mul(8);
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
        wipe::words32(&mut self.state);
        wipe::bytes(&mut self.buffer);
        self.buffered = 0;
        self.message_len = 0;
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
    wipe::words32(&mut schedule);
    wipe::words32(&mut working);
    wipe::words32(&mut scratch);
}

/// Construct the one ratified ceremony commitment without exposing a general
/// hashing entry point. Invalid purpose tags leave `digest` unchanged.
pub(crate) fn ceremony_transcript_commitment(
    purpose: u8,
    transcript: &[u8; TRANSCRIPT_LEN],
    digest: &mut [u8; 32],
) -> bool {
    if !matches!(purpose, 1..=4) {
        return false;
    }
    let mut context = Sha256::new();
    context.update(COMMITMENT_DOMAIN);
    context.update(&[0]);
    context.update(&[purpose]);
    context.update(transcript);
    context.finish(digest);
    true
}

#[cfg(test)]
fn hash_for_test(message: &[u8]) -> [u8; 32] {
    let mut context = Sha256::new();
    context.update(message);
    let mut digest = [0u8; 32];
    context.finish(&mut digest);
    digest
}

#[cfg(test)]
#[allow(clippy::panic)]
mod tests {
    use super::{ceremony_transcript_commitment, hash_for_test};

    #[test]
    fn nist_answers_cover_empty_and_split_padding() {
        assert_eq!(
            hash_for_test(b""),
            [
                0xe3, 0xb0, 0xc4, 0x42, 0x98, 0xfc, 0x1c, 0x14, 0x9a, 0xfb, 0xf4, 0xc8, 0x99, 0x6f,
                0xb9, 0x24, 0x27, 0xae, 0x41, 0xe4, 0x64, 0x9b, 0x93, 0x4c, 0xa4, 0x95, 0x99, 0x1b,
                0x78, 0x52, 0xb8, 0x55,
            ]
        );
        assert_eq!(
            hash_for_test(b"abc"),
            [
                0xba, 0x78, 0x16, 0xbf, 0x8f, 0x01, 0xcf, 0xea, 0x41, 0x41, 0x40, 0xde, 0x5d, 0xae,
                0x22, 0x23, 0xb0, 0x03, 0x61, 0xa3, 0x96, 0x17, 0x7a, 0x9c, 0xb4, 0x10, 0xff, 0x61,
                0xf2, 0x00, 0x15, 0xad,
            ]
        );
    }

    #[test]
    fn v2_golden_commitments_lock_domain_separator_purpose_and_transcript() {
        let cases = [
            (
                1,
                b'1',
                [
                    0x9e, 0x80, 0x88, 0xcd, 0x90, 0x68, 0xa9, 0x9a, 0x20, 0x8d, 0x7f, 0x78, 0x73,
                    0xbd, 0xa7, 0xb2, 0xe9, 0x17, 0x0f, 0xa2, 0xa7, 0x02, 0xed, 0xa5, 0xa4, 0x7e,
                    0x15, 0x45, 0xaf, 0xb9, 0x34, 0x25,
                ],
            ),
            (
                2,
                b'2',
                [
                    0xaf, 0xae, 0x04, 0x95, 0xf2, 0x74, 0x27, 0xf4, 0x7c, 0x00, 0xa6, 0xfd, 0xa7,
                    0x1f, 0x7d, 0xd5, 0xea, 0xf6, 0x31, 0x2a, 0x6d, 0x92, 0x3a, 0xde, 0x1a, 0x05,
                    0xdd, 0x6f, 0x19, 0x7a, 0xa5, 0xf4,
                ],
            ),
            (
                3,
                b'3',
                [
                    0xcc, 0x5d, 0x80, 0x23, 0xf8, 0xbb, 0xb7, 0x09, 0x78, 0x8e, 0x18, 0x68, 0xa5,
                    0x3e, 0xda, 0xe9, 0xc2, 0x10, 0x60, 0x5e, 0x77, 0xe8, 0xf6, 0xec, 0x53, 0xb2,
                    0x51, 0x67, 0x38, 0xf0, 0xb7, 0x49,
                ],
            ),
            (
                4,
                b'4',
                [
                    0x84, 0x2d, 0x4d, 0xe1, 0xbf, 0x08, 0x0e, 0x24, 0xcb, 0x12, 0x9a, 0x5f, 0xa3,
                    0xdd, 0x64, 0xbd, 0x57, 0x39, 0xde, 0xdf, 0x23, 0x71, 0xa3, 0x31, 0x6a, 0x7b,
                    0x99, 0x20, 0x99, 0xa5, 0x76, 0xea,
                ],
            ),
        ];
        for (purpose, symbol, expected) in cases {
            let transcript = [symbol; 100];
            let mut digest = [0u8; 32];
            assert!(ceremony_transcript_commitment(
                purpose,
                &transcript,
                &mut digest
            ));
            assert_eq!(digest, expected);
        }
    }

    #[test]
    fn invalid_purpose_is_rejected_without_touching_output() {
        let transcript = [b'1'; 100];
        for purpose in [0, 5, u8::MAX] {
            let mut digest = [0xa5; 32];
            assert!(!ceremony_transcript_commitment(
                purpose,
                &transcript,
                &mut digest
            ));
            assert_eq!(digest, [0xa5; 32]);
        }
    }
}
