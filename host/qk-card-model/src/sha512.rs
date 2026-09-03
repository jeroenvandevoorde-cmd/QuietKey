//! Private fixed-memory SHA-512 following FIPS 180-4.

#![allow(clippy::chunks_exact_to_as_chunks)]

use crate::wipe;

const BLOCK_BYTES: usize = 128;
const INITIAL: [u64; 8] = [
    0x6a09_e667_f3bc_c908,
    0xbb67_ae85_84ca_a73b,
    0x3c6e_f372_fe94_f82b,
    0xa54f_f53a_5f1d_36f1,
    0x510e_527f_ade6_82d1,
    0x9b05_688c_2b3e_6c1f,
    0x1f83_d9ab_fb41_bd6b,
    0x5be0_cd19_137e_2179,
];
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

fn compress(state: &mut [u64; 8], block: &[u8]) {
    let mut w = wipe::WipingWords64::<80>::new([0u64; 80]);
    for (word, chunk) in w.as_mut_array()[..16].iter_mut().zip(block.chunks_exact(8)) {
        *word = u64::from_be_bytes([
            chunk[0], chunk[1], chunk[2], chunk[3], chunk[4], chunk[5], chunk[6], chunk[7],
        ]);
    }
    for i in 16..80 {
        let a = w.as_array()[i - 15].rotate_right(1)
            ^ w.as_array()[i - 15].rotate_right(8)
            ^ (w.as_array()[i - 15] >> 7);
        let b = w.as_array()[i - 2].rotate_right(19)
            ^ w.as_array()[i - 2].rotate_right(61)
            ^ (w.as_array()[i - 2] >> 6);
        let next = w.as_array()[i - 16]
            .wrapping_add(a)
            .wrapping_add(w.as_array()[i - 7])
            .wrapping_add(b);
        w.as_mut_array()[i] = next;
    }
    let mut v = wipe::WipingWords64::<8>::new(*state);
    for (&round_constant, &schedule) in K.iter().zip(w.as_array().iter()) {
        let s1 = v.as_array()[4].rotate_right(14)
            ^ v.as_array()[4].rotate_right(18)
            ^ v.as_array()[4].rotate_right(41);
        let ch = (v.as_array()[4] & v.as_array()[5]) ^ ((!v.as_array()[4]) & v.as_array()[6]);
        let t1 = v.as_array()[7]
            .wrapping_add(s1)
            .wrapping_add(ch)
            .wrapping_add(round_constant)
            .wrapping_add(schedule);
        let s0 = v.as_array()[0].rotate_right(28)
            ^ v.as_array()[0].rotate_right(34)
            ^ v.as_array()[0].rotate_right(39);
        let maj = (v.as_array()[0] & v.as_array()[1])
            ^ (v.as_array()[0] & v.as_array()[2])
            ^ (v.as_array()[1] & v.as_array()[2]);
        let t2 = s0.wrapping_add(maj);
        let mut old = *v.as_array();
        *v.as_mut_array() = [
            t1.wrapping_add(t2),
            old[0],
            old[1],
            old[2],
            old[3].wrapping_add(t1),
            old[4],
            old[5],
            old[6],
        ];
        wipe::words64(&mut old);
    }
    for (dst, value) in state.iter_mut().zip(v.as_array().iter()) {
        *dst = dst.wrapping_add(*value);
    }
}

pub(crate) fn hash(message: &[u8], output: &mut [u8; 64]) {
    let mut state = wipe::WipingWords64::<8>::new(INITIAL);
    let mut blocks = message.chunks_exact(BLOCK_BYTES);
    for block in blocks.by_ref() {
        compress(state.as_mut_array(), block);
    }
    let rest = blocks.remainder();
    let mut tail = wipe::WipingArray::<{ 2 * BLOCK_BYTES }>::zeroed();
    tail.as_mut_slice()[..rest.len()].copy_from_slice(rest);
    tail.as_mut_slice()[rest.len()] = 0x80;
    let tail_len = if rest.len() < 112 {
        BLOCK_BYTES
    } else {
        2 * BLOCK_BYTES
    };
    let bit_len = (message.len() as u128).saturating_mul(8);
    tail.as_mut_slice()[tail_len - 16..tail_len].copy_from_slice(&bit_len.to_be_bytes());
    for block in tail.as_slice()[..tail_len].chunks_exact(BLOCK_BYTES) {
        compress(state.as_mut_array(), block);
    }
    for (chunk, word) in output.chunks_exact_mut(8).zip(state.as_array().iter()) {
        chunk.copy_from_slice(&word.to_be_bytes());
    }
}

#[cfg(test)]
mod tests {
    use super::hash;

    #[test]
    fn fips_abc_known_answer() {
        let mut output = [0u8; 64];
        hash(b"abc", &mut output);
        assert_eq!(
            output,
            [
                0xdd, 0xaf, 0x35, 0xa1, 0x93, 0x61, 0x7a, 0xba, 0xcc, 0x41, 0x73, 0x49, 0xae, 0x20,
                0x41, 0x31, 0x12, 0xe6, 0xfa, 0x4e, 0x89, 0xa9, 0x7e, 0xa2, 0x0a, 0x9e, 0xee, 0xe6,
                0x4b, 0x55, 0xd3, 0x9a, 0x21, 0x92, 0x99, 0x2a, 0x27, 0x4f, 0xc1, 0xa8, 0x36, 0xba,
                0x3c, 0x23, 0xa3, 0xfe, 0xeb, 0xbd, 0x45, 0x4d, 0x44, 0x23, 0x64, 0x3c, 0xe8, 0x0e,
                0x2a, 0x9a, 0xc9, 0x4f, 0xa5, 0x4c, 0xa4, 0x9f
            ]
        );
    }
}
