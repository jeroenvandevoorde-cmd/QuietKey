//! Private RIPEMD-160 used only for BIP32 parent fingerprints.

#![allow(clippy::chunks_exact_to_as_chunks)]

const R: [usize; 80] = [
    0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 7, 4, 13, 1, 10, 6, 15, 3, 12, 0, 9, 5,
    2, 14, 11, 8, 3, 10, 14, 4, 9, 15, 8, 1, 2, 7, 0, 6, 13, 11, 5, 12, 1, 9, 11, 10, 0, 8, 12, 4,
    13, 3, 7, 15, 14, 5, 6, 2, 4, 0, 5, 9, 7, 12, 2, 10, 14, 1, 3, 8, 11, 6, 15, 13,
];
const RP: [usize; 80] = [
    5, 14, 7, 0, 9, 2, 11, 4, 13, 6, 15, 8, 1, 10, 3, 12, 6, 11, 3, 7, 0, 13, 5, 10, 14, 15, 8, 12,
    4, 9, 1, 2, 15, 5, 1, 3, 7, 14, 6, 9, 11, 8, 12, 2, 10, 0, 4, 13, 8, 6, 4, 1, 3, 11, 15, 0, 5,
    12, 2, 13, 9, 7, 10, 14, 12, 15, 10, 4, 1, 5, 8, 7, 6, 2, 13, 14, 0, 3, 9, 11,
];
const S: [u32; 80] = [
    11, 14, 15, 12, 5, 8, 7, 9, 11, 13, 14, 15, 6, 7, 9, 8, 7, 6, 8, 13, 11, 9, 7, 15, 7, 12, 15,
    9, 11, 7, 13, 12, 11, 13, 6, 7, 14, 9, 13, 15, 14, 8, 13, 6, 5, 12, 7, 5, 11, 12, 14, 15, 14,
    15, 9, 8, 9, 14, 5, 6, 8, 6, 5, 12, 9, 15, 5, 11, 6, 8, 13, 12, 5, 12, 13, 14, 11, 8, 5, 6,
];
const SP: [u32; 80] = [
    8, 9, 9, 11, 13, 15, 15, 5, 7, 7, 8, 11, 14, 14, 12, 6, 9, 13, 15, 7, 12, 8, 9, 11, 7, 7, 12,
    7, 6, 15, 13, 11, 9, 7, 15, 11, 8, 6, 6, 14, 12, 13, 5, 14, 13, 13, 7, 5, 15, 5, 8, 11, 14, 14,
    6, 14, 6, 9, 12, 9, 12, 5, 15, 8, 8, 5, 12, 9, 12, 5, 14, 6, 8, 13, 6, 5, 15, 13, 11, 11,
];

fn f(round: usize, x: u32, y: u32, z: u32) -> u32 {
    match round {
        0 => x ^ y ^ z,
        1 => (x & y) | (!x & z),
        2 => (x | !y) ^ z,
        3 => (x & z) | (y & !z),
        _ => x ^ (y | !z),
    }
}

fn k(round: usize) -> u32 {
    [
        0x0000_0000,
        0x5a82_7999,
        0x6ed9_eba1,
        0x8f1b_bcdc,
        0xa953_fd4e,
    ][round]
}

fn kp(round: usize) -> u32 {
    [
        0x50a2_8be6,
        0x5c4d_d124,
        0x6d70_3ef3,
        0x7a6d_76e9,
        0x0000_0000,
    ][round]
}

fn compress(state: &mut [u32; 5], block: &[u8; 64]) {
    let mut x = [0u32; 16];
    for (word, bytes) in x.iter_mut().zip(block.chunks_exact(4)) {
        *word = u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]);
    }
    let (mut al, mut bl, mut cl, mut dl, mut el) =
        (state[0], state[1], state[2], state[3], state[4]);
    let (mut ar, mut br, mut cr, mut dr, mut er) =
        (state[0], state[1], state[2], state[3], state[4]);
    for j in 0..80 {
        let round = j / 16;
        let tl = al
            .wrapping_add(f(round, bl, cl, dl))
            .wrapping_add(x[R[j]])
            .wrapping_add(k(round))
            .rotate_left(S[j])
            .wrapping_add(el);
        al = el;
        el = dl;
        dl = cl.rotate_left(10);
        cl = bl;
        bl = tl;

        let rr = 4 - round;
        let tr = ar
            .wrapping_add(f(rr, br, cr, dr))
            .wrapping_add(x[RP[j]])
            .wrapping_add(kp(round))
            .rotate_left(SP[j])
            .wrapping_add(er);
        ar = er;
        er = dr;
        dr = cr.rotate_left(10);
        cr = br;
        br = tr;
    }
    let t = state[1].wrapping_add(cl).wrapping_add(dr);
    state[1] = state[2].wrapping_add(dl).wrapping_add(er);
    state[2] = state[3].wrapping_add(el).wrapping_add(ar);
    state[3] = state[4].wrapping_add(al).wrapping_add(br);
    state[4] = state[0].wrapping_add(bl).wrapping_add(cr);
    state[0] = t;
}

pub(crate) fn ripemd160(message: &[u8]) -> [u8; 20] {
    let mut state = [
        0x6745_2301,
        0xefcd_ab89,
        0x98ba_dcfe,
        0x1032_5476,
        0xc3d2_e1f0,
    ];
    let mut chunks = message.chunks_exact(64);
    for chunk in chunks.by_ref() {
        let mut block = [0u8; 64];
        block.copy_from_slice(chunk);
        compress(&mut state, &block);
    }
    let remainder = chunks.remainder();
    let mut tail = [0u8; 128];
    tail[..remainder.len()].copy_from_slice(remainder);
    tail[remainder.len()] = 0x80;
    let tail_len = if remainder.len() < 56 { 64 } else { 128 };
    tail[tail_len - 8..tail_len].copy_from_slice(&((message.len() as u64) * 8).to_le_bytes());
    for chunk in tail[..tail_len].chunks_exact(64) {
        let mut block = [0u8; 64];
        block.copy_from_slice(chunk);
        compress(&mut state, &block);
    }
    let mut output = [0u8; 20];
    for (bytes, word) in output.chunks_exact_mut(4).zip(state) {
        bytes.copy_from_slice(&word.to_le_bytes());
    }
    output
}

#[cfg(test)]
mod tests {
    use super::ripemd160;

    fn hex(input: &str) -> Vec<u8> {
        (0..input.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&input[i..i + 2], 16).expect("hex"))
            .collect()
    }

    #[test]
    fn published_short_answers() {
        assert_eq!(
            ripemd160(b"").as_slice(),
            hex("9c1185a5c5e9fc54612808977ee8f548b2258d31")
        );
        assert_eq!(
            ripemd160(b"abc").as_slice(),
            hex("8eb208f7e05d987a9b044a8e98c6b087f15a0bfc")
        );
    }
}
