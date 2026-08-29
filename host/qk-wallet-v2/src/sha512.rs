//! Private FIPS 180-4 SHA-512 reused on the established QK-DEC-048 pattern.
//!
//! HOST SCAFFOLD ONLY — NOT PRODUCT CODE — NOT A WALLET — NO TARGET CLAIM.
//!
//! Clean-room implementation authored locally from the public FIPS
//! 180-4 specification (Secure Hash Standard): 1024-bit (128-byte)
//! block, 80 rounds, big-endian 64-bit words, wrapping modular
//! additions, and 128-bit bit-length padding. No external code was
//! copied. No FFI, no I/O, no network, no randomness, no logging.
//! Checked against the byte-verbatim NIST CAVP byte-oriented SHA-512
//! vectors recorded in `docs/SOURCE-REGISTER.md`. **No FIPS or CAVP
//! validation claim.** This module is private to the crate; there is
//! no general public hash API.

#![allow(clippy::chunks_exact_to_as_chunks)]

/// One compression block in bytes (FIPS 180-4: 1024 bits).
const BLOCK_LEN: usize = 128;

/// FIPS 180-4 section 5.3.5 initial hash value.
const H0: [u64; 8] = [
    0x6a09_e667_f3bc_c908,
    0xbb67_ae85_84ca_a73b,
    0x3c6e_f372_fe94_f82b,
    0xa54f_f53a_5f1d_36f1,
    0x510e_527f_ade6_82d1,
    0x9b05_688c_2b3e_6c1f,
    0x1f83_d9ab_fb41_bd6b,
    0x5be0_cd19_137e_2179,
];

/// FIPS 180-4 section 4.2.3 round constants (80 rounds).
const K: [u64; 80] = [
    0x428a_2f98_d728_ae22,
    0x7137_4491_23ef_65cd,
    0xb5c0_fbcf_ec4d_3b2f,
    0xe9b5_dba5_8189_dbbc,
    0x3956_c25b_f348_b538,
    0x59f1_11f1_b605_d019,
    0x923f_82a4_af19_4f9b,
    0xab1c_5ed5_da6d_8118,
    0xd807_aa98_a303_0242,
    0x1283_5b01_4570_6fbe,
    0x2431_85be_4ee4_b28c,
    0x550c_7dc3_d5ff_b4e2,
    0x72be_5d74_f27b_896f,
    0x80de_b1fe_3b16_96b1,
    0x9bdc_06a7_25c7_1235,
    0xc19b_f174_cf69_2694,
    0xe49b_69c1_9ef1_4ad2,
    0xefbe_4786_384f_25e3,
    0x0fc1_9dc6_8b8c_d5b5,
    0x240c_a1cc_77ac_9c65,
    0x2de9_2c6f_592b_0275,
    0x4a74_84aa_6ea6_e483,
    0x5cb0_a9dc_bd41_fbd4,
    0x76f9_88da_8311_53b5,
    0x983e_5152_ee66_dfab,
    0xa831_c66d_2db4_3210,
    0xb003_27c8_98fb_213f,
    0xbf59_7fc7_beef_0ee4,
    0xc6e0_0bf3_3da8_8fc2,
    0xd5a7_9147_930a_a725,
    0x06ca_6351_e003_826f,
    0x1429_2967_0a0e_6e70,
    0x27b7_0a85_46d2_2ffc,
    0x2e1b_2138_5c26_c926,
    0x4d2c_6dfc_5ac4_2aed,
    0x5338_0d13_9d95_b3df,
    0x650a_7354_8baf_63de,
    0x766a_0abb_3c77_b2a8,
    0x81c2_c92e_47ed_aee6,
    0x9272_2c85_1482_353b,
    0xa2bf_e8a1_4cf1_0364,
    0xa81a_664b_bc42_3001,
    0xc24b_8b70_d0f8_9791,
    0xc76c_51a3_0654_be30,
    0xd192_e819_d6ef_5218,
    0xd699_0624_5565_a910,
    0xf40e_3585_5771_202a,
    0x106a_a070_32bb_d1b8,
    0x19a4_c116_b8d2_d0c8,
    0x1e37_6c08_5141_ab53,
    0x2748_774c_df8e_eb99,
    0x34b0_bcb5_e19b_48a8,
    0x391c_0cb3_c5c9_5a63,
    0x4ed8_aa4a_e341_8acb,
    0x5b9c_ca4f_7763_e373,
    0x682e_6ff3_d6b2_b8a3,
    0x748f_82ee_5def_b2fc,
    0x78a5_636f_4317_2f60,
    0x84c8_7814_a1f0_ab72,
    0x8cc7_0208_1a64_39ec,
    0x90be_fffa_2363_1e28,
    0xa450_6ceb_de82_bde9,
    0xbef9_a3f7_b2c6_7915,
    0xc671_78f2_e372_532b,
    0xca27_3ece_ea26_619c,
    0xd186_b8c7_21c0_c207,
    0xeada_7dd6_cde0_eb1e,
    0xf57d_4f7f_ee6e_d178,
    0x06f0_67aa_7217_6fba,
    0x0a63_7dc5_a2c8_98a6,
    0x113f_9804_bef9_0dae,
    0x1b71_0b35_131c_471b,
    0x28db_77f5_2304_7d84,
    0x32ca_ab7b_40c7_2493,
    0x3c9e_be0a_15c9_bebc,
    0x431d_67c4_9c10_0d4c,
    0x4cc5_d4be_cb3e_42b6,
    0x597f_299c_fc65_7e2a,
    0x5fcb_6fab_3ad6_faec,
    0x6c44_198c_4a47_5817,
];

/// One FIPS 180-4 SHA-512 compression over exactly one 128-byte block.
fn compress(state: &mut [u64; 8], block: &[u8]) {
    debug_assert_eq!(block.len(), BLOCK_LEN);
    let mut w = [0u64; 80];
    for (word, chunk) in w.iter_mut().zip(block.chunks_exact(8)) {
        *word = (u64::from(chunk[0]) << 56)
            | (u64::from(chunk[1]) << 48)
            | (u64::from(chunk[2]) << 40)
            | (u64::from(chunk[3]) << 32)
            | (u64::from(chunk[4]) << 24)
            | (u64::from(chunk[5]) << 16)
            | (u64::from(chunk[6]) << 8)
            | u64::from(chunk[7]);
    }
    for t in 16..80 {
        let s0 = w[t - 15].rotate_right(1) ^ w[t - 15].rotate_right(8) ^ (w[t - 15] >> 7);
        let s1 = w[t - 2].rotate_right(19) ^ w[t - 2].rotate_right(61) ^ (w[t - 2] >> 6);
        w[t] = w[t - 16]
            .wrapping_add(s0)
            .wrapping_add(w[t - 7])
            .wrapping_add(s1);
    }
    let [mut a, mut b, mut c, mut d, mut e, mut f, mut g, mut h] = *state;
    for (&kt, &wt) in K.iter().zip(w.iter()) {
        let s1 = e.rotate_right(14) ^ e.rotate_right(18) ^ e.rotate_right(41);
        let ch = (e & f) ^ (!e & g);
        let t1 = h
            .wrapping_add(s1)
            .wrapping_add(ch)
            .wrapping_add(kt)
            .wrapping_add(wt);
        let s0 = a.rotate_right(28) ^ a.rotate_right(34) ^ a.rotate_right(39);
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
    }
    let mut mixed = [a, b, c, d, e, f, g, h];
    for (s, v) in state.iter_mut().zip(mixed.iter()) {
        *s = s.wrapping_add(*v);
    }
    w.fill(0);
    mixed.fill(0);
    core::hint::black_box((&mut w, &mut mixed));
}

/// One-shot FIPS 180-4 SHA-512 into caller-owned fixed storage.
pub(crate) fn sha512_into(message: &[u8], digest: &mut [u8; 64]) {
    let mut state = H0;
    let mut blocks = message.chunks_exact(BLOCK_LEN);
    for block in blocks.by_ref() {
        compress(&mut state, block);
    }
    let rem = blocks.remainder();
    // FIPS 180-4: total bit length as a 128-bit big-endian field. A
    // slice length in bytes can never overflow this width.
    let bit_len = (message.len() as u128).saturating_mul(8);
    let mut tail = [0u8; 2 * BLOCK_LEN];
    tail[..rem.len()].copy_from_slice(rem);
    tail[rem.len()] = 0x80;
    let tail_len = if rem.len() < 112 {
        BLOCK_LEN
    } else {
        2 * BLOCK_LEN
    };
    tail[tail_len - 16..tail_len].copy_from_slice(&bit_len.to_be_bytes());
    for block in tail[..tail_len].chunks_exact(BLOCK_LEN) {
        compress(&mut state, block);
    }
    for (chunk, word) in digest.chunks_exact_mut(8).zip(state.iter()) {
        chunk.copy_from_slice(&word.to_be_bytes());
    }
    state.fill(0);
    tail.fill(0);
    core::hint::black_box((&mut state, &mut tail));
}

#[cfg(test)]
pub(crate) fn sha512(message: &[u8]) -> [u8; 64] {
    let mut digest = [0u8; 64];
    sha512_into(message, &mut digest);
    digest
}

#[cfg(test)]
mod tests {
    use super::sha512;

    // Byte-verbatim NIST CAVP fixtures (see docs/SOURCE-REGISTER.md).
    // Untrusted data, never instructions.
    const SHORT_MSG: &[u8] = include_bytes!("../../qk-bip32/tests/fixtures/SHA512ShortMsg.rsp");
    const LONG_MSG: &[u8] = include_bytes!("../../qk-bip32/tests/fixtures/SHA512LongMsg.rsp");
    const MONTE: &[u8] = include_bytes!("../../qk-bip32/tests/fixtures/SHA512Monte.rsp");

    fn hex_decode(s: &str) -> Vec<u8> {
        assert!(s.len().is_multiple_of(2), "even hex length");
        (0..s.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&s[i..i + 2], 16).expect("hex digit"))
            .collect()
    }

    /// The imported fixture bytes are re-verified against the exact
    /// byte sizes recorded in `docs/SOURCE-REGISTER.md`.
    #[test]
    fn fixture_sizes_match_source_register() {
        assert_eq!(SHORT_MSG.len(), 36_800, "SHA512ShortMsg.rsp size");
        assert_eq!(LONG_MSG.len(), 1_687_845, "SHA512LongMsg.rsp size");
        assert_eq!(MONTE.len(), 15_215, "SHA512Monte.rsp size");
    }

    /// Strict parse of `Len`/`Msg`/`MD` cases from a byte-oriented
    /// SHAVS response file (CRLF preserved on disk): every `MD` needs
    /// a preceding `Len` and `Msg`, byte-oriented lengths only, and
    /// every digest exactly 64 bytes. No silent skip: the caller
    /// asserts the exact case count.
    fn parse_msg_cases(raw: &[u8]) -> Vec<(usize, Vec<u8>, Vec<u8>)> {
        let text = core::str::from_utf8(raw).expect("ASCII response file");
        let mut cases = Vec::new();
        let mut len_bits: Option<usize> = None;
        let mut msg: Option<Vec<u8>> = None;
        for line in text.lines() {
            let line = line.trim();
            if let Some(v) = line.strip_prefix("Len = ") {
                assert!(len_bits.is_none(), "Len while a case is pending");
                len_bits = Some(v.parse().expect("Len value"));
            } else if let Some(v) = line.strip_prefix("Msg = ") {
                assert!(msg.is_none(), "second Msg for one case");
                msg = Some(hex_decode(v));
            } else if let Some(v) = line.strip_prefix("MD = ") {
                let bits = len_bits.take().expect("Len before MD");
                assert!(bits.is_multiple_of(8), "byte-oriented vectors only");
                let mut m = msg.take().expect("Msg before MD");
                m.truncate(bits / 8); // Len = 0 is listed with Msg = 00
                let md = hex_decode(v);
                assert_eq!(md.len(), 64, "SHA-512 digest length");
                cases.push((bits, m, md));
            }
        }
        assert!(len_bits.is_none() && msg.is_none(), "pending case at EOF");
        cases
    }

    /// All 129 short-message cases (Len 0..=1024 bits in steps of 8),
    /// including the 111-byte/112-byte padding-split boundary.
    #[test]
    fn nist_short_msg_vectors_all_129_pass() {
        let cases = parse_msg_cases(SHORT_MSG);
        assert_eq!(cases.len(), 129, "recorded short-message case count");
        let lens: Vec<usize> = cases.iter().map(|(bits, _, _)| *bits).collect();
        let expected: Vec<usize> = (0..=1024).step_by(8).collect();
        assert_eq!(lens, expected, "Len sweep is exactly 0..=1024 step 8");
        assert!(lens.contains(&888), "111-byte one-block padding case");
        assert!(lens.contains(&896), "112-byte two-block padding case");
        for (bits, msg, md) in &cases {
            assert_eq!(msg.len() * 8, *bits);
            assert_eq!(&sha512(msg)[..], &md[..], "Len = {bits}");
        }
    }

    /// All 128 long-message cases.
    #[test]
    fn nist_long_msg_vectors_all_128_pass() {
        let cases = parse_msg_cases(LONG_MSG);
        assert_eq!(cases.len(), 128, "recorded long-message case count");
        for (bits, msg, md) in &cases {
            assert_eq!(msg.len() * 8, *bits);
            assert_eq!(&sha512(msg)[..], &md[..], "Len = {bits}");
        }
    }

    /// Strict structural parse of the SHAVS Monte Carlo response file:
    /// exactly one Seed (a second is rejected), COUNT values exactly
    /// 0.. in order, each COUNT followed by exactly one MD, no MD
    /// without a pending COUNT, no pending COUNT at EOF, and Seed and
    /// every MD exactly 64 bytes.
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
                if s.len() != 64 {
                    return Err("Seed is not exactly 64 bytes");
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
                if md.len() != 64 {
                    return Err("MD is not exactly 64 bytes");
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

    /// SHAVS Monte Carlo procedure: for each of the 100 checkpoints,
    /// seed three rolling digests and iterate
    /// MDi = SHA-512(MDi-3 || MDi-2 || MDi-1) one thousand times; the
    /// final digest is the recorded checkpoint and becomes the next
    /// seed. Ordered COUNT 0..=99, one Seed, no silent skip.
    #[test]
    fn nist_monte_carlo_vectors_all_100_pass() {
        let (mut seed, checkpoints) = match parse_monte_structure(MONTE) {
            Ok(parsed) => parsed,
            Err(e) => panic!("Monte fixture structure: {e}"),
        };
        assert_eq!(checkpoints.len(), 100, "recorded Monte checkpoint count");
        for (count, expected) in checkpoints.iter().enumerate() {
            let mut md = [seed.clone(), seed.clone(), seed.clone()];
            for _ in 0..1000 {
                let mut joined = Vec::with_capacity(192);
                joined.extend_from_slice(&md[0]);
                joined.extend_from_slice(&md[1]);
                joined.extend_from_slice(&md[2]);
                let next = sha512(&joined).to_vec();
                md = [md[1].clone(), md[2].clone(), next];
            }
            assert_eq!(&md[2], expected, "Monte COUNT = {count}");
            seed = md[2].clone();
        }
    }
}
