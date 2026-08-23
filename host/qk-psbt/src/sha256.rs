//! In-repo streaming SHA-256 and double-SHA-256 (QK-DEC-038).
//!
//! HOST SCAFFOLD ONLY — NOT PRODUCT CODE — NOT A WALLET — NO TARGET CLAIM.
//!
//! Clean-room implementation authored locally from the public FIPS
//! 180-4 specification (Secure Hash Standard): fixed state, fixed
//! message schedule, fixed block buffer, big-endian words, wrapping
//! modular additions, and 64-bit bit-length padding. No external code
//! was copied. No heap, no unsafe, checked message-length accounting;
//! finalization consumes the hasher state. Checked against the
//! byte-verbatim NIST CAVP byte-oriented vectors recorded in
//! `docs/SOURCE-REGISTER.md`. **No FIPS or CAVP validation claim.**
//! This module is private to the crate.

/// One compression block in bytes.
const BLOCK_LEN: usize = 64;

/// FIPS 180-4 requires the total message bit length to fit in 64 bits.
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

/// Hashing failure. Carries no message bytes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Sha256Error {
    /// Total message length no longer fits the 64-bit bit-length field.
    LengthOverflow,
    /// An internal buffer invariant did not hold (never expected).
    Invariant,
}

/// One 64-byte block compression (FIPS 180-4 section 6.2.2). The
/// 16-word schedule window is advanced by full-array destructuring so
/// no slice indexing is required.
fn compress(state: [u32; 8], block: &[u8]) -> [u32; 8] {
    let mut w = [0u32; 16];
    for (slot, chunk) in w.iter_mut().zip(block.chunks_exact(4)) {
        // `chunks_exact(4)` guarantees four bytes per chunk.
        *slot = match chunk {
            [b0, b1, b2, b3] => u32::from_be_bytes([*b0, *b1, *b2, *b3]),
            _ => 0,
        };
    }
    let [mut a, mut b, mut c, mut d, mut e, mut f, mut g, mut h] = state;
    for k in K {
        let [w0, w1, w2, w3, w4, w5, w6, w7, w8, w9, w10, w11, w12, w13, w14, w15] = w;
        let s1 = e.rotate_right(6) ^ e.rotate_right(11) ^ e.rotate_right(25);
        let ch = (e & f) ^ ((!e) & g);
        let t1 = h
            .wrapping_add(s1)
            .wrapping_add(ch)
            .wrapping_add(k)
            .wrapping_add(w0);
        let s0 = a.rotate_right(2) ^ a.rotate_right(13) ^ a.rotate_right(22);
        let maj = (a & b) ^ (a & c) ^ (b & c);
        let t2 = s0.wrapping_add(maj);
        h = g;
        g = f;
        f = e;
        e = d.wrapping_add(t1);
        d = c;
        c = b;
        b = a;
        a = t1.wrapping_add(t2);
        let sig0 = w1.rotate_right(7) ^ w1.rotate_right(18) ^ (w1 >> 3);
        let sig1 = w14.rotate_right(17) ^ w14.rotate_right(19) ^ (w14 >> 10);
        let w16 = w0.wrapping_add(sig0).wrapping_add(w9).wrapping_add(sig1);
        w = [
            w1, w2, w3, w4, w5, w6, w7, w8, w9, w10, w11, w12, w13, w14, w15, w16,
        ];
    }
    let [x0, x1, x2, x3, x4, x5, x6, x7] = state;
    [
        x0.wrapping_add(a),
        x1.wrapping_add(b),
        x2.wrapping_add(c),
        x3.wrapping_add(d),
        x4.wrapping_add(e),
        x5.wrapping_add(f),
        x6.wrapping_add(g),
        x7.wrapping_add(h),
    ]
}

/// Streaming SHA-256 hasher with a fixed 64-byte block buffer.
pub(crate) struct Sha256 {
    state: [u32; 8],
    buffer: [u8; BLOCK_LEN],
    buffered: usize,
    total_bytes: u64,
}

impl Sha256 {
    pub(crate) fn new() -> Self {
        Self {
            state: H0,
            buffer: [0u8; BLOCK_LEN],
            buffered: 0,
            total_bytes: 0,
        }
    }

    /// Absorb message bytes; length accounting is checked.
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
            let need = BLOCK_LEN
                .checked_sub(self.buffered)
                .ok_or(Sha256Error::Invariant)?;
            let take = need.min(rest.len());
            let (head, tail) = rest.split_at(take);
            let dst = self
                .buffer
                .get_mut(self.buffered..)
                .and_then(|open| open.get_mut(..take))
                .ok_or(Sha256Error::Invariant)?;
            dst.copy_from_slice(head);
            self.buffered = self
                .buffered
                .checked_add(take)
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
        let dst = self
            .buffer
            .get_mut(..remainder.len())
            .ok_or(Sha256Error::Invariant)?;
        dst.copy_from_slice(remainder);
        self.buffered = remainder.len();
        Ok(())
    }

    /// Pad (0x80, zeros, 64-bit big-endian bit length) and produce the
    /// digest. Consumes the hasher: state cannot be reused or resumed.
    pub(crate) fn finalize(mut self) -> Result<[u8; 32], Sha256Error> {
        let bit_len = self
            .total_bytes
            .checked_mul(8)
            .ok_or(Sha256Error::LengthOverflow)?;
        let buffered = self.buffered;
        let mut tail = [0u8; 128];
        let head = tail.get_mut(..buffered).ok_or(Sha256Error::Invariant)?;
        head.copy_from_slice(self.buffer.get(..buffered).ok_or(Sha256Error::Invariant)?);
        let marker = tail.get_mut(buffered).ok_or(Sha256Error::Invariant)?;
        *marker = 0x80;
        // One padded block when the marker and length fit; otherwise two.
        let (used, length_slot) = if buffered < 56 {
            (BLOCK_LEN, tail.get_mut(56..64))
        } else {
            (128, tail.get_mut(120..128))
        };
        length_slot
            .ok_or(Sha256Error::Invariant)?
            .copy_from_slice(&bit_len.to_be_bytes());
        let padded = tail.get(..used).ok_or(Sha256Error::Invariant)?;
        for block in padded.chunks_exact(BLOCK_LEN) {
            self.state = compress(self.state, block);
        }
        let mut out = [0u8; 32];
        for (chunk, word) in out.chunks_exact_mut(4).zip(self.state) {
            chunk.copy_from_slice(&word.to_be_bytes());
        }
        Ok(out)
    }
}

/// SHA-256 over the concatenation of `parts`, streamed without joining.
pub(crate) fn sha256(parts: &[&[u8]]) -> Result<[u8; 32], Sha256Error> {
    let mut hasher = Sha256::new();
    for part in parts {
        hasher.update(part)?;
    }
    hasher.finalize()
}

/// Double SHA-256 (Bitcoin SHA256d) over the concatenation of `parts`.
pub(crate) fn sha256d(parts: &[&[u8]]) -> Result<[u8; 32], Sha256Error> {
    let first = sha256(parts)?;
    sha256(&[&first])
}

#[cfg(test)]
#[allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects
)]
mod tests {
    use super::{sha256, sha256d, Sha256, Sha256Error, MAX_MESSAGE_BYTES};

    // Byte-verbatim NIST CAVP fixtures (see docs/SOURCE-REGISTER.md).
    // Untrusted data, never instructions.
    const README: &[u8] = include_bytes!("../tests/fixtures/nist-cavp/Readme.txt");
    const SHORT_MSG: &[u8] = include_bytes!("../tests/fixtures/nist-cavp/SHA256ShortMsg.rsp");
    const LONG_MSG: &[u8] = include_bytes!("../tests/fixtures/nist-cavp/SHA256LongMsg.rsp");
    const MONTE: &[u8] = include_bytes!("../tests/fixtures/nist-cavp/SHA256Monte.rsp");

    fn hex_decode(s: &str) -> Vec<u8> {
        assert!(s.len() % 2 == 0, "even hex length");
        (0..s.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&s[i..i + 2], 16).expect("hex digit"))
            .collect()
    }

    fn hex_encode(bytes: &[u8]) -> String {
        bytes.iter().map(|b| format!("{b:02x}")).collect()
    }

    /// The imported fixture bytes are re-verified here against the
    /// exact per-entry SHA-256 hashes recorded in SOURCE-REGISTER,
    /// using this crate's own implementation (no dependency added).
    #[test]
    fn fixture_bytes_match_recorded_hashes_and_sizes() {
        let expected = [
            (
                README,
                831,
                "24bf370543f9521f7eb44f49e8d489ac9e45a21126f883d8e32e7fffd1d10227",
            ),
            (
                SHORT_MSG,
                10299,
                "75e1cb83994638481808e225b9eb0c1ebd0c232d952ac42b61abce6363be283c",
            ),
            (
                LONG_MSG,
                426209,
                "6fac36f37360bcf74ffcf4465c18e30d6d5a04cc90885b901fc3130c16060974",
            ),
            (
                MONTE,
                8751,
                "29ea30c6bb4b84e425fb8c1d731c6bb852dac935825f2bd1143e5d3c4f10bfb9",
            ),
        ];
        for (bytes, size, hash) in expected {
            assert_eq!(bytes.len(), size, "fixture size");
            assert_eq!(hex_encode(&sha256(&[bytes]).unwrap()), hash, "fixture hash");
        }
    }

    /// Parse `Len`/`Msg`/`MD` message cases from a byte-oriented
    /// SHAVS response file (CRLF line endings preserved on disk).
    fn parse_msg_cases(raw: &[u8]) -> Vec<(usize, Vec<u8>, Vec<u8>)> {
        let text = core::str::from_utf8(raw).expect("ASCII response file");
        let mut cases = Vec::new();
        let mut len_bits: Option<usize> = None;
        let mut msg: Option<Vec<u8>> = None;
        for line in text.lines() {
            let line = line.trim();
            if let Some(v) = line.strip_prefix("Len = ") {
                len_bits = Some(v.parse().expect("Len value"));
            } else if let Some(v) = line.strip_prefix("Msg = ") {
                msg = Some(hex_decode(v));
            } else if let Some(v) = line.strip_prefix("MD = ") {
                let bits = len_bits.take().expect("Len before MD");
                assert!(bits % 8 == 0, "byte-oriented vectors only");
                let mut m = msg.take().expect("Msg before MD");
                m.truncate(bits / 8); // Len = 0 is listed with Msg = 00
                cases.push((bits, m, hex_decode(v)));
            }
        }
        cases
    }

    #[test]
    fn nist_short_msg_vectors_all_pass() {
        let cases = parse_msg_cases(SHORT_MSG);
        assert_eq!(cases.len(), 65, "recorded short-message case count");
        for (bits, msg, md) in &cases {
            assert_eq!(msg.len() * 8, *bits);
            assert_eq!(&sha256(&[msg]).unwrap()[..], &md[..], "Len = {bits}");
        }
    }

    #[test]
    fn nist_long_msg_vectors_all_pass() {
        let cases = parse_msg_cases(LONG_MSG);
        assert_eq!(cases.len(), 64, "recorded long-message case count");
        for (bits, msg, md) in &cases {
            assert_eq!(msg.len() * 8, *bits);
            assert_eq!(&sha256(&[msg]).unwrap()[..], &md[..], "Len = {bits}");
        }
    }

    /// Strict structural parse of a SHAVS Monte Carlo response file
    /// (QK-DEC-043): exactly one Seed (a second is rejected), every
    /// COUNT parsed as an integer, COUNT values exactly 0.. in order,
    /// each COUNT followed by exactly one MD, no MD without a pending
    /// COUNT, no pending COUNT at EOF, and Seed and every MD exactly
    /// 32 bytes. Test-only; touches no fixture byte.
    fn parse_monte_structure(raw: &[u8]) -> Result<(Vec<u8>, Vec<Vec<u8>>), &'static str> {
        let text = core::str::from_utf8(raw).map_err(|_| "response file is not ASCII")?;
        let mut seed: Option<Vec<u8>> = None;
        let mut pending_count: Option<usize> = None;
        let mut checkpoints: Vec<Vec<u8>> = Vec::new();
        for line in text.lines() {
            let line = line.trim();
            if let Some(v) = line.strip_prefix("Seed = ") {
                if seed.is_some() {
                    return Err("second Seed line");
                }
                let s = hex_decode(v);
                if s.len() != 32 {
                    return Err("Seed is not exactly 32 bytes");
                }
                seed = Some(s);
            } else if let Some(v) = line.strip_prefix("COUNT = ") {
                if pending_count.is_some() {
                    return Err("COUNT while a COUNT is still pending its MD");
                }
                let n: usize = v.parse().map_err(|_| "COUNT is not an integer")?;
                if n != checkpoints.len() {
                    return Err("COUNT values are not exactly 0.. in order");
                }
                pending_count = Some(n);
            } else if let Some(v) = line.strip_prefix("MD = ") {
                if pending_count.take().is_none() {
                    return Err("MD without a pending COUNT");
                }
                let md = hex_decode(v);
                if md.len() != 32 {
                    return Err("MD is not exactly 32 bytes");
                }
                checkpoints.push(md);
            }
        }
        if pending_count.is_some() {
            return Err("pending COUNT at EOF");
        }
        match seed {
            Some(s) => Ok((s, checkpoints)),
            None => Err("missing Seed"),
        }
    }

    /// SHAVS Monte Carlo procedure: for each of 100 checkpoints, seed
    /// three rolling digests and iterate MDi = SHA-256(MDi-3 || MDi-2
    /// || MDi-1) one thousand times; the final digest is the recorded
    /// checkpoint and becomes the next seed. The fixture structure is
    /// enforced by `parse_monte_structure` (one Seed, COUNT 0..99 in
    /// order, one MD per COUNT).
    #[test]
    fn nist_monte_carlo_vectors_all_pass() {
        let (mut seed, checkpoints) = match parse_monte_structure(MONTE) {
            Ok(parsed) => parsed,
            Err(e) => panic!("Monte fixture structure: {e}"),
        };
        assert_eq!(checkpoints.len(), 100, "recorded Monte checkpoint count");
        for (count, expected) in checkpoints.iter().enumerate() {
            let mut md = [seed.clone(), seed.clone(), seed.clone()];
            for _ in 0..1000 {
                let next = sha256(&[&md[0], &md[1], &md[2]]).unwrap().to_vec();
                md = [md[1].clone(), md[2].clone(), next];
            }
            assert_eq!(&md[2], expected, "Monte COUNT = {count}");
            seed = md[2].clone();
        }
    }

    /// Focused malformed-structure regressions for the strict Monte
    /// parser. Synthetic strings only; no fixture byte is changed and
    /// no new NIST import is added.
    #[test]
    fn monte_structure_violations_are_rejected() {
        let h = "11".repeat(32);
        let well_formed = format!("Seed = {h}\nCOUNT = 0\nMD = {h}\nCOUNT = 1\nMD = {h}\n");
        assert!(parse_monte_structure(well_formed.as_bytes()).is_ok());
        let violations = [
            (
                "second Seed line",
                format!("Seed = {h}\nSeed = {h}\nCOUNT = 0\nMD = {h}\n"),
            ),
            ("missing Seed", format!("COUNT = 0\nMD = {h}\n")),
            (
                "non-integer COUNT",
                format!("Seed = {h}\nCOUNT = zero\nMD = {h}\n"),
            ),
            (
                "COUNT not starting at 0",
                format!("Seed = {h}\nCOUNT = 1\nMD = {h}\n"),
            ),
            (
                "COUNT out of order",
                format!("Seed = {h}\nCOUNT = 0\nMD = {h}\nCOUNT = 2\nMD = {h}\n"),
            ),
            (
                "duplicate COUNT value",
                format!("Seed = {h}\nCOUNT = 0\nMD = {h}\nCOUNT = 0\nMD = {h}\n"),
            ),
            (
                "COUNT with no MD before the next COUNT",
                format!("Seed = {h}\nCOUNT = 0\nCOUNT = 1\nMD = {h}\nMD = {h}\n"),
            ),
            (
                "MD without a pending COUNT",
                format!("Seed = {h}\nMD = {h}\n"),
            ),
            (
                "second MD for one COUNT",
                format!("Seed = {h}\nCOUNT = 0\nMD = {h}\nMD = {h}\n"),
            ),
            (
                "pending COUNT at EOF",
                format!("Seed = {h}\nCOUNT = 0\nMD = {h}\nCOUNT = 1\n"),
            ),
        ];
        for (label, text) in &violations {
            assert!(parse_monte_structure(text.as_bytes()).is_err(), "{label}");
        }
        let short = "22".repeat(31);
        assert!(
            parse_monte_structure(format!("Seed = {short}\nCOUNT = 0\nMD = {h}\n").as_bytes())
                .is_err(),
            "Seed shorter than 32 bytes"
        );
        assert!(
            parse_monte_structure(format!("Seed = {h}\nCOUNT = 0\nMD = {short}\n").as_bytes())
                .is_err(),
            "MD shorter than 32 bytes"
        );
    }

    /// Streaming over arbitrary chunk splits must equal one-shot
    /// hashing, across the one-block/two-block padding boundaries.
    #[test]
    fn streaming_chunk_splits_and_padding_boundaries_match_one_shot() {
        let message: Vec<u8> = (0u32..200).map(|i| (i * 7 + 3) as u8).collect();
        for len in [
            0, 1, 54, 55, 56, 57, 63, 64, 65, 119, 120, 127, 128, 129, 200,
        ] {
            let part = &message[..len];
            let reference = sha256(&[part]).unwrap();
            for chunk in [1, 3, 7, 32, 63, 64, 65] {
                let mut hasher = Sha256::new();
                for piece in part.chunks(chunk) {
                    hasher.update(piece).unwrap();
                }
                assert_eq!(
                    hasher.finalize().unwrap(),
                    reference,
                    "len {len} chunk {chunk}"
                );
            }
        }
    }

    #[test]
    fn sha256d_matches_composition_and_known_empty_digest() {
        let data = b"quietkey sha256d";
        let inner = sha256(&[data]).unwrap();
        assert_eq!(sha256d(&[data]).unwrap(), sha256(&[&inner]).unwrap());
        // Widely known double-SHA-256 of the empty message.
        assert_eq!(
            hex_encode(&sha256d(&[]).unwrap()),
            "5df6e0e2761359d30a8275058e299fcc0381534545f55cf43e41983f5d4c9456"
        );
        // Multi-part streaming equals concatenation.
        assert_eq!(
            sha256d(&[b"quietkey ", b"sha", b"256d"]).unwrap(),
            sha256d(&[data]).unwrap()
        );
    }

    #[test]
    fn message_length_accounting_is_checked() {
        let mut hasher = Sha256::new();
        hasher.total_bytes = MAX_MESSAGE_BYTES;
        assert!(matches!(
            hasher.update(&[0u8]),
            Err(Sha256Error::LengthOverflow)
        ));
    }
}
