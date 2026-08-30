//! Private dependency-free streaming SHA-256.
//!
//! HOST SCAFFOLD ONLY — NOT PRODUCT CODE — NOT A WALLET — NO TARGET CLAIM.
//!
//! Adapted from the established in-repository `qk-psbt` implementation:
//! fixed state, a fixed block buffer, big-endian words, wrapping modular
//! additions, checked message-length accounting, and consuming finalization.

#![allow(clippy::chunks_exact_to_as_chunks)]

/// One SHA-256 compression block in bytes.
const BLOCK_LEN: usize = 64;

/// The encoded SHA-256 message bit length must fit in 64 bits.
const MAX_MESSAGE_BYTES: u64 = u64::MAX / 8;

/// FIPS 180-4 section 5.3.3 initial hash value.
const H0: [u32; 8] = [
    0x6a09_e667,
    0xbb67_ae85,
    0x3c6e_f372,
    0xa54f_f53a,
    0x510e_527f,
    0x9b05_688c,
    0x1f83_d9ab,
    0x5be0_cd19,
];

/// FIPS 180-4 section 4.2.2 round constants.
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

/// Hashing failure. Carries no input bytes.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum Sha256Error {
    /// Total message length cannot be encoded in the SHA-256 length field.
    LengthOverflow,
    /// An internal fixed-buffer invariant did not hold.
    Invariant,
}

/// Compress one complete block with a rotating 16-word schedule window.
fn compress(state: [u32; 8], block: &[u8]) -> [u32; 8] {
    let mut words = [0u32; 16];
    for (slot, chunk) in words.iter_mut().zip(block.chunks_exact(4)) {
        *slot = match chunk {
            [b0, b1, b2, b3] => u32::from_be_bytes([*b0, *b1, *b2, *b3]),
            _ => 0,
        };
    }

    let [mut a, mut b, mut c, mut d, mut e, mut f, mut g, mut h] = state;
    for round_constant in K {
        let [w0, w1, w2, w3, w4, w5, w6, w7, w8, w9, w10, w11, w12, w13, w14, w15] = words;
        let sigma1 = e.rotate_right(6) ^ e.rotate_right(11) ^ e.rotate_right(25);
        let choose = (e & f) ^ ((!e) & g);
        let first = h
            .wrapping_add(sigma1)
            .wrapping_add(choose)
            .wrapping_add(round_constant)
            .wrapping_add(w0);
        let sigma0 = a.rotate_right(2) ^ a.rotate_right(13) ^ a.rotate_right(22);
        let majority = (a & b) ^ (a & c) ^ (b & c);
        let second = sigma0.wrapping_add(majority);

        h = g;
        g = f;
        f = e;
        e = d.wrapping_add(first);
        d = c;
        c = b;
        b = a;
        a = first.wrapping_add(second);

        let small0 = w1.rotate_right(7) ^ w1.rotate_right(18) ^ (w1 >> 3);
        let small1 = w14.rotate_right(17) ^ w14.rotate_right(19) ^ (w14 >> 10);
        let next = w0
            .wrapping_add(small0)
            .wrapping_add(w9)
            .wrapping_add(small1);
        words = [
            w1, w2, w3, w4, w5, w6, w7, w8, w9, w10, w11, w12, w13, w14, w15, next,
        ];
    }

    let [s0, s1, s2, s3, s4, s5, s6, s7] = state;
    [
        s0.wrapping_add(a),
        s1.wrapping_add(b),
        s2.wrapping_add(c),
        s3.wrapping_add(d),
        s4.wrapping_add(e),
        s5.wrapping_add(f),
        s6.wrapping_add(g),
        s7.wrapping_add(h),
    ]
}

/// Streaming SHA-256 state with one fixed compression-block buffer.
pub(crate) struct Sha256 {
    state: [u32; 8],
    buffer: [u8; BLOCK_LEN],
    buffered: usize,
    total_bytes: u64,
}

impl Sha256 {
    pub(crate) const fn new() -> Self {
        Self {
            state: H0,
            buffer: [0u8; BLOCK_LEN],
            buffered: 0,
            total_bytes: 0,
        }
    }

    /// Absorb one byte slice with checked total-length accounting.
    pub(crate) fn update(&mut self, data: &[u8]) -> Result<(), Sha256Error> {
        let added = u64::try_from(data.len()).map_err(|_| Sha256Error::LengthOverflow)?;
        self.total_bytes = self
            .total_bytes
            .checked_add(added)
            .ok_or(Sha256Error::LengthOverflow)?;
        if self.total_bytes > MAX_MESSAGE_BYTES {
            return Err(Sha256Error::LengthOverflow);
        }

        let mut rest = data;
        if self.buffered > 0 {
            let needed = BLOCK_LEN
                .checked_sub(self.buffered)
                .ok_or(Sha256Error::Invariant)?;
            let taken = needed.min(rest.len());
            let (head, tail) = rest.split_at(taken);
            let destination = self
                .buffer
                .get_mut(self.buffered..)
                .and_then(|open| open.get_mut(..taken))
                .ok_or(Sha256Error::Invariant)?;
            destination.copy_from_slice(head);
            self.buffered = self
                .buffered
                .checked_add(taken)
                .ok_or(Sha256Error::Invariant)?;
            rest = tail;
            if self.buffered < BLOCK_LEN {
                return Ok(());
            }
            self.state = compress(self.state, &self.buffer);
            self.buffered = 0;
        }

        let mut blocks = rest.chunks_exact(BLOCK_LEN);
        for block in &mut blocks {
            self.state = compress(self.state, block);
        }
        let remainder = blocks.remainder();
        let destination = self
            .buffer
            .get_mut(..remainder.len())
            .ok_or(Sha256Error::Invariant)?;
        destination.copy_from_slice(remainder);
        self.buffered = remainder.len();
        Ok(())
    }

    /// Consume the state and emit the padded SHA-256 digest.
    pub(crate) fn finalize(mut self) -> Result<[u8; 32], Sha256Error> {
        let bit_length = self
            .total_bytes
            .checked_mul(8)
            .ok_or(Sha256Error::LengthOverflow)?;
        let buffered = self.buffered;
        let mut tail = [0u8; 128];
        tail.get_mut(..buffered)
            .ok_or(Sha256Error::Invariant)?
            .copy_from_slice(self.buffer.get(..buffered).ok_or(Sha256Error::Invariant)?);
        *tail.get_mut(buffered).ok_or(Sha256Error::Invariant)? = 0x80;
        let (used, length_slot) = if buffered < 56 {
            (BLOCK_LEN, tail.get_mut(56..64))
        } else {
            (128, tail.get_mut(120..128))
        };
        length_slot
            .ok_or(Sha256Error::Invariant)?
            .copy_from_slice(&bit_length.to_be_bytes());
        for block in tail
            .get(..used)
            .ok_or(Sha256Error::Invariant)?
            .chunks_exact(BLOCK_LEN)
        {
            self.state = compress(self.state, block);
        }

        let mut digest = [0u8; 32];
        for (destination, word) in digest.chunks_exact_mut(4).zip(self.state) {
            destination.copy_from_slice(&word.to_be_bytes());
        }
        Ok(digest)
    }
}

/// SHA-256 over the exact concatenation of `parts`, without joining them.
pub(crate) fn sha256(parts: &[&[u8]]) -> Result<[u8; 32], Sha256Error> {
    let mut hasher = Sha256::new();
    for part in parts {
        hasher.update(part)?;
    }
    hasher.finalize()
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::indexing_slicing)]
mod tests {
    use super::{sha256, Sha256};

    #[test]
    fn standard_answers_cover_empty_and_split_streaming() {
        assert_eq!(
            sha256(&[]).unwrap(),
            [
                0xe3, 0xb0, 0xc4, 0x42, 0x98, 0xfc, 0x1c, 0x14, 0x9a, 0xfb, 0xf4, 0xc8, 0x99, 0x6f,
                0xb9, 0x24, 0x27, 0xae, 0x41, 0xe4, 0x64, 0x9b, 0x93, 0x4c, 0xa4, 0x95, 0x99, 0x1b,
                0x78, 0x52, 0xb8, 0x55,
            ]
        );
        assert_eq!(
            sha256(&[b"a", b"b", b"c"]).unwrap(),
            [
                0xba, 0x78, 0x16, 0xbf, 0x8f, 0x01, 0xcf, 0xea, 0x41, 0x41, 0x40, 0xde, 0x5d, 0xae,
                0x22, 0x23, 0xb0, 0x03, 0x61, 0xa3, 0x96, 0x17, 0x7a, 0x9c, 0xb4, 0x10, 0xff, 0x61,
                0xf2, 0x00, 0x15, 0xad,
            ]
        );

        let bytes = [0xa5; 129];
        let joined = sha256(&[&bytes]).unwrap();
        let mut streamed = Sha256::new();
        for chunk in bytes.chunks(7) {
            streamed.update(chunk).unwrap();
        }
        assert_eq!(streamed.finalize().unwrap(), joined);
    }
}
