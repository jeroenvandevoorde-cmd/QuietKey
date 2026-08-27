//! Private Poly1305 authenticator following RFC 8439 section 2.5.

use crate::wipe;

fn load_u32(input: &[u8]) -> u32 {
    u32::from_le_bytes([input[0], input[1], input[2], input[3]])
}

struct Poly1305 {
    r: [u32; 5],
    scaled: [u32; 4],
    h: [u32; 5],
    pad: [u32; 4],
}

impl Drop for Poly1305 {
    fn drop(&mut self) {
        self.clear();
    }
}

impl Poly1305 {
    fn clear(&mut self) {
        wipe::words32(&mut self.r);
        wipe::words32(&mut self.scaled);
        wipe::words32(&mut self.h);
        wipe::words32(&mut self.pad);
    }

    fn zeroed() -> Self {
        Self {
            r: [0u32; 5],
            scaled: [0u32; 4],
            h: [0u32; 5],
            pad: [0u32; 4],
        }
    }

    fn initialize(&mut self, one_time_key: &[u8; 32]) {
        self.r[0] = load_u32(&one_time_key[0..4]) & 0x03ff_ffff;
        self.r[1] = (load_u32(&one_time_key[3..7]) >> 2) & 0x03ff_ff03;
        self.r[2] = (load_u32(&one_time_key[6..10]) >> 4) & 0x03ff_c0ff;
        self.r[3] = (load_u32(&one_time_key[9..13]) >> 6) & 0x03f0_3fff;
        self.r[4] = (load_u32(&one_time_key[12..16]) >> 8) & 0x000f_ffff;
        for (scaled, r) in self.scaled.iter_mut().zip(self.r.iter().skip(1)) {
            *scaled = r.wrapping_mul(5);
        }
        let (pad_chunks, remainder) = one_time_key[16..].as_chunks::<4>();
        debug_assert!(remainder.is_empty());
        for (pad, chunk) in self.pad.iter_mut().zip(pad_chunks.iter()) {
            *pad = load_u32(chunk);
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

        let mut products = [0u64; 5];
        products[0] = self.h[0] as u64 * self.r[0] as u64
            + self.h[1] as u64 * self.scaled[3] as u64
            + self.h[2] as u64 * self.scaled[2] as u64
            + self.h[3] as u64 * self.scaled[1] as u64
            + self.h[4] as u64 * self.scaled[0] as u64;
        products[1] = self.h[0] as u64 * self.r[1] as u64
            + self.h[1] as u64 * self.r[0] as u64
            + self.h[2] as u64 * self.scaled[3] as u64
            + self.h[3] as u64 * self.scaled[2] as u64
            + self.h[4] as u64 * self.scaled[1] as u64;
        products[2] = self.h[0] as u64 * self.r[2] as u64
            + self.h[1] as u64 * self.r[1] as u64
            + self.h[2] as u64 * self.r[0] as u64
            + self.h[3] as u64 * self.scaled[3] as u64
            + self.h[4] as u64 * self.scaled[2] as u64;
        products[3] = self.h[0] as u64 * self.r[3] as u64
            + self.h[1] as u64 * self.r[2] as u64
            + self.h[2] as u64 * self.r[1] as u64
            + self.h[3] as u64 * self.r[0] as u64
            + self.h[4] as u64 * self.scaled[3] as u64;
        products[4] = self.h[0] as u64 * self.r[4] as u64
            + self.h[1] as u64 * self.r[3] as u64
            + self.h[2] as u64 * self.r[2] as u64
            + self.h[3] as u64 * self.r[1] as u64
            + self.h[4] as u64 * self.r[0] as u64;

        let mut carry = (products[0] >> 26) as u32;
        self.h[0] = products[0] as u32 & 0x03ff_ffff;
        for (index, product) in products.iter_mut().enumerate().skip(1) {
            *product = product.wrapping_add(carry as u64);
            carry = (*product >> 26) as u32;
            self.h[index] = *product as u32 & 0x03ff_ffff;
        }
        self.h[0] = self.h[0].wrapping_add(carry * 5);
        carry = self.h[0] >> 26;
        self.h[0] &= 0x03ff_ffff;
        self.h[1] = self.h[1].wrapping_add(carry);
        carry = 0;
        core::hint::black_box(&mut carry);
        wipe::words64(&mut products);
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

    fn finish(&mut self, tag: &mut [u8; 16]) {
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

        let mut choose_g = (g[4] >> 31).wrapping_sub(1);
        for (h, candidate) in self.h.iter_mut().zip(g.iter()) {
            *h = (*h & !choose_g) | (*candidate & choose_g);
        }
        let mut words = [0u64; 4];
        words[0] = (self.h[0] | (self.h[1] << 26)) as u64;
        words[1] = ((self.h[1] >> 6) | (self.h[2] << 20)) as u64;
        words[2] = ((self.h[2] >> 12) | (self.h[3] << 14)) as u64;
        words[3] = ((self.h[3] >> 18) | (self.h[4] << 8)) as u64;
        let mut sums = [0u64; 4];
        sums[0] = words[0].wrapping_add(self.pad[0] as u64);
        for index in 1..4 {
            sums[index] = words[index]
                .wrapping_add(self.pad[index] as u64)
                .wrapping_add(sums[index - 1] >> 32);
        }
        let mut final_words = [0u32; 4];
        for (word, sum) in final_words.iter_mut().zip(sums.iter()) {
            *word = *sum as u32;
        }
        for (index, word) in final_words.iter().enumerate() {
            let offset = index * 4;
            tag[offset..offset + 4].copy_from_slice(&word.to_le_bytes());
        }
        carry = 0;
        choose_g = 0;
        core::hint::black_box((&mut carry, &mut choose_g));
        wipe::words32(&mut g);
        wipe::words64(&mut words);
        wipe::words64(&mut sums);
        wipe::words32(&mut final_words);
    }
}

pub(crate) fn authenticate(
    one_time_key: &[u8; 32],
    aad: &[u8],
    ciphertext: &[u8],
    tag: &mut [u8; 16],
) {
    let mut state = Poly1305::zeroed();
    state.initialize(one_time_key);
    state.padded(aad);
    state.padded(ciphertext);
    let mut lengths = [0u8; 16];
    lengths[..8].copy_from_slice(&(aad.len() as u64).to_le_bytes());
    lengths[8..].copy_from_slice(&(ciphertext.len() as u64).to_le_bytes());
    state.full_block(&lengths);
    state.finish(tag);
    state.clear();
    wipe::bytes(&mut lengths);
}
