//! Private Poly1305 authenticator following RFC 8439 section 2.5.

fn load_u32(input: &[u8]) -> u32 {
    u32::from_le_bytes([input[0], input[1], input[2], input[3]])
}

struct Poly1305 {
    r: [u32; 5],
    scaled: [u32; 4],
    h: [u32; 5],
    pad: [u32; 4],
}

impl Poly1305 {
    fn new(one_time_key: &[u8; 32]) -> Self {
        let r0 = load_u32(&one_time_key[0..4]) & 0x03ff_ffff;
        let r1 = (load_u32(&one_time_key[3..7]) >> 2) & 0x03ff_ff03;
        let r2 = (load_u32(&one_time_key[6..10]) >> 4) & 0x03ff_c0ff;
        let r3 = (load_u32(&one_time_key[9..13]) >> 6) & 0x03f0_3fff;
        let r4 = (load_u32(&one_time_key[12..16]) >> 8) & 0x000f_ffff;
        Self {
            r: [r0, r1, r2, r3, r4],
            scaled: [r1 * 5, r2 * 5, r3 * 5, r4 * 5],
            h: [0u32; 5],
            pad: [
                load_u32(&one_time_key[16..20]),
                load_u32(&one_time_key[20..24]),
                load_u32(&one_time_key[24..28]),
                load_u32(&one_time_key[28..32]),
            ],
        }
    }

    fn full_block(&mut self, block: &[u8; 16]) {
        let t0 = load_u32(&block[0..4]);
        let t1 = load_u32(&block[4..8]);
        let t2 = load_u32(&block[8..12]);
        let t3 = load_u32(&block[12..16]);
        self.h[0] = self.h[0].wrapping_add(t0 & 0x03ff_ffff);
        self.h[1] = self.h[1].wrapping_add(((t0 >> 26) | (t1 << 6)) & 0x03ff_ffff);
        self.h[2] = self.h[2].wrapping_add(((t1 >> 20) | (t2 << 12)) & 0x03ff_ffff);
        self.h[3] = self.h[3].wrapping_add(((t2 >> 14) | (t3 << 18)) & 0x03ff_ffff);
        self.h[4] = self.h[4].wrapping_add((t3 >> 8) | (1 << 24));

        let [r0, r1, r2, r3, r4] = self.r;
        let [s1, s2, s3, s4] = self.scaled;
        let d0 = self.h[0] as u64 * r0 as u64
            + self.h[1] as u64 * s4 as u64
            + self.h[2] as u64 * s3 as u64
            + self.h[3] as u64 * s2 as u64
            + self.h[4] as u64 * s1 as u64;
        let d1 = self.h[0] as u64 * r1 as u64
            + self.h[1] as u64 * r0 as u64
            + self.h[2] as u64 * s4 as u64
            + self.h[3] as u64 * s3 as u64
            + self.h[4] as u64 * s2 as u64;
        let d2 = self.h[0] as u64 * r2 as u64
            + self.h[1] as u64 * r1 as u64
            + self.h[2] as u64 * r0 as u64
            + self.h[3] as u64 * s4 as u64
            + self.h[4] as u64 * s3 as u64;
        let d3 = self.h[0] as u64 * r3 as u64
            + self.h[1] as u64 * r2 as u64
            + self.h[2] as u64 * r1 as u64
            + self.h[3] as u64 * r0 as u64
            + self.h[4] as u64 * s4 as u64;
        let d4 = self.h[0] as u64 * r4 as u64
            + self.h[1] as u64 * r3 as u64
            + self.h[2] as u64 * r2 as u64
            + self.h[3] as u64 * r1 as u64
            + self.h[4] as u64 * r0 as u64;

        let mut carry = (d0 >> 26) as u32;
        self.h[0] = d0 as u32 & 0x03ff_ffff;
        let d1 = d1 + carry as u64;
        carry = (d1 >> 26) as u32;
        self.h[1] = d1 as u32 & 0x03ff_ffff;
        let d2 = d2 + carry as u64;
        carry = (d2 >> 26) as u32;
        self.h[2] = d2 as u32 & 0x03ff_ffff;
        let d3 = d3 + carry as u64;
        carry = (d3 >> 26) as u32;
        self.h[3] = d3 as u32 & 0x03ff_ffff;
        let d4 = d4 + carry as u64;
        carry = (d4 >> 26) as u32;
        self.h[4] = d4 as u32 & 0x03ff_ffff;
        self.h[0] = self.h[0].wrapping_add(carry * 5);
        carry = self.h[0] >> 26;
        self.h[0] &= 0x03ff_ffff;
        self.h[1] = self.h[1].wrapping_add(carry);
    }

    fn padded(&mut self, input: &[u8]) {
        let mut offset = 0usize;
        while input.len() - offset >= 16 {
            let mut block = [0u8; 16];
            block.copy_from_slice(&input[offset..offset + 16]);
            self.full_block(&block);
            offset += 16;
        }
        let remainder = &input[offset..];
        if !remainder.is_empty() {
            let mut block = [0u8; 16];
            block[..remainder.len()].copy_from_slice(remainder);
            self.full_block(&block);
        }
    }

    fn finish(mut self) -> [u8; 16] {
        let mut carry = self.h[1] >> 26;
        self.h[1] &= 0x03ff_ffff;
        self.h[2] = self.h[2].wrapping_add(carry);
        carry = self.h[2] >> 26;
        self.h[2] &= 0x03ff_ffff;
        self.h[3] = self.h[3].wrapping_add(carry);
        carry = self.h[3] >> 26;
        self.h[3] &= 0x03ff_ffff;
        self.h[4] = self.h[4].wrapping_add(carry);
        carry = self.h[4] >> 26;
        self.h[4] &= 0x03ff_ffff;
        self.h[0] = self.h[0].wrapping_add(carry * 5);
        carry = self.h[0] >> 26;
        self.h[0] &= 0x03ff_ffff;
        self.h[1] = self.h[1].wrapping_add(carry);

        let mut g = [0u32; 5];
        g[0] = self.h[0].wrapping_add(5);
        carry = g[0] >> 26;
        g[0] &= 0x03ff_ffff;
        for (index, candidate) in g.iter_mut().enumerate().take(4).skip(1) {
            *candidate = self.h[index].wrapping_add(carry);
            carry = *candidate >> 26;
            *candidate &= 0x03ff_ffff;
        }
        g[4] = self.h[4].wrapping_add(carry).wrapping_sub(1 << 26);

        let choose_g = (g[4] >> 31).wrapping_sub(1);
        for (h, candidate) in self.h.iter_mut().zip(g) {
            *h = (*h & !choose_g) | (candidate & choose_g);
        }

        let word0 = (self.h[0] | (self.h[1] << 26)) as u64;
        let mut value = word0.wrapping_add(self.pad[0] as u64);
        let f0 = value as u32;
        let word1 = ((self.h[1] >> 6) | (self.h[2] << 20)) as u64;
        value = word1
            .wrapping_add(self.pad[1] as u64)
            .wrapping_add(value >> 32);
        let f1 = value as u32;
        let word2 = ((self.h[2] >> 12) | (self.h[3] << 14)) as u64;
        value = word2
            .wrapping_add(self.pad[2] as u64)
            .wrapping_add(value >> 32);
        let f2 = value as u32;
        let word3 = ((self.h[3] >> 18) | (self.h[4] << 8)) as u64;
        value = word3
            .wrapping_add(self.pad[3] as u64)
            .wrapping_add(value >> 32);
        let f3 = value as u32;

        let mut tag = [0u8; 16];
        for (index, word) in [f0, f1, f2, f3].iter().enumerate() {
            let offset = index * 4;
            tag[offset..offset + 4].copy_from_slice(&word.to_le_bytes());
        }
        tag
    }
}

pub(crate) fn authenticate(one_time_key: &[u8; 32], aad: &[u8], ciphertext: &[u8]) -> [u8; 16] {
    let mut state = Poly1305::new(one_time_key);
    state.padded(aad);
    state.padded(ciphertext);
    let mut lengths = [0u8; 16];
    lengths[..8].copy_from_slice(&(aad.len() as u64).to_le_bytes());
    lengths[8..].copy_from_slice(&(ciphertext.len() as u64).to_le_bytes());
    state.full_block(&lengths);
    state.finish()
}
