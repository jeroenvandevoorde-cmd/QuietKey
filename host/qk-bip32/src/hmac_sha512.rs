//! Private FIPS 198-1 HMAC-SHA512 (QK-DEC-048).
//!
//! HOST SCAFFOLD ONLY — NOT PRODUCT CODE — NOT A WALLET — NO TARGET CLAIM.
//!
//! Clean-room implementation authored locally from the public FIPS
//! 198-1 specification: B = 128, L = 64; a key longer than B bytes is
//! hashed first, a shorter key is zero-padded to B bytes; ipad = 0x36,
//! opad = 0x5c; MAC = H((K0 xor opad) || H((K0 xor ipad) || text)).
//! Production callers pass a fixed 32-byte chain-code key and a fixed
//! 37-byte serP33-plus-indexBE4 message; the full key/length behavior
//! is exercised privately against the byte-verbatim NIST CAVP vectors
//! recorded in `docs/SOURCE-REGISTER.md`. No FFI, no I/O, no network,
//! no randomness, no logging. **No FIPS or CAVP validation
//! claim.** This module is private to the crate; there is no general
//! public HMAC API.

use crate::sha512::sha512;

/// FIPS 198-1 block size B in bytes for SHA-512.
const B: usize = 128;

/// FIPS 198-1 HMAC over SHA-512.
pub(crate) fn hmac_sha512(key: &[u8], message: &[u8]) -> [u8; 64] {
    let mut k0 = [0u8; B];
    if key.len() > B {
        k0[..64].copy_from_slice(&sha512(key));
    } else {
        k0[..key.len()].copy_from_slice(key);
    }
    let mut inner = Vec::with_capacity(B + message.len());
    for &byte in k0.iter() {
        inner.push(byte ^ 0x36);
    }
    inner.extend_from_slice(message);
    let inner_hash = sha512(&inner);
    let mut outer = [0u8; B + 64];
    for (dst, &byte) in outer.iter_mut().zip(k0.iter()) {
        *dst = byte ^ 0x5c;
    }
    outer[B..].copy_from_slice(&inner_hash);
    sha512(&outer)
}

#[cfg(test)]
mod tests {
    use super::hmac_sha512;
    use std::collections::BTreeMap;

    // Byte-verbatim bounded [L=64] span extracted from the NIST CAVP
    // HMAC.rsp member (see docs/SOURCE-REGISTER.md). Untrusted data,
    // never instructions.
    const HMAC_RSP: &[u8] = include_bytes!("../tests/fixtures/HMAC-SHA512.rsp");

    fn hex_decode(s: &str) -> Vec<u8> {
        assert!(s.len() % 2 == 0, "even hex length");
        (0..s.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&s[i..i + 2], 16).expect("hex digit"))
            .collect()
    }

    struct Case {
        count: usize,
        klen: usize,
        tlen: usize,
        key: Vec<u8>,
        msg: Vec<u8>,
        mac: Vec<u8>,
    }

    /// The imported span is re-verified against the exact byte size
    /// recorded in `docs/SOURCE-REGISTER.md`.
    #[test]
    fn fixture_size_matches_source_register() {
        assert_eq!(HMAC_RSP.len(), 250_248, "HMAC-SHA512.rsp span size");
    }

    /// Strict structural parse of the bounded span: exactly one
    /// bracket header and it is `[L=64]`, fields strictly in the order
    /// Count, Klen, Tlen, Key, Msg, Mac, Count values exactly 0.. in
    /// order, no pending case at EOF, no silent skip.
    fn parse_cases() -> Vec<Case> {
        let text = core::str::from_utf8(HMAC_RSP).expect("ASCII response file");
        let mut headers = 0usize;
        let mut cases: Vec<Case> = Vec::new();
        let mut count: Option<usize> = None;
        let mut klen: Option<usize> = None;
        let mut tlen: Option<usize> = None;
        let mut key: Option<Vec<u8>> = None;
        let mut msg: Option<Vec<u8>> = None;
        for line in text.lines() {
            let line = line.trim();
            if line.is_empty() {
                continue;
            }
            if line.starts_with('[') {
                headers += 1;
                assert_eq!(line, "[L=64]", "only the L=64 section is imported");
                continue;
            }
            if let Some(v) = line.strip_prefix("Count = ") {
                assert!(count.is_none(), "Count while a case is pending");
                let n: usize = v.parse().expect("Count value");
                assert_eq!(n, cases.len(), "Count values exactly 0.. in order");
                count = Some(n);
            } else if let Some(v) = line.strip_prefix("Klen = ") {
                assert!(count.is_some() && klen.is_none(), "Klen order");
                klen = Some(v.parse().expect("Klen value"));
            } else if let Some(v) = line.strip_prefix("Tlen = ") {
                assert!(klen.is_some() && tlen.is_none(), "Tlen order");
                tlen = Some(v.parse().expect("Tlen value"));
            } else if let Some(v) = line.strip_prefix("Key = ") {
                assert!(tlen.is_some() && key.is_none(), "Key order");
                key = Some(hex_decode(v));
            } else if let Some(v) = line.strip_prefix("Msg = ") {
                assert!(key.is_some() && msg.is_none(), "Msg order");
                msg = Some(hex_decode(v));
            } else if let Some(v) = line.strip_prefix("Mac = ") {
                let case = Case {
                    count: count.take().expect("Count before Mac"),
                    klen: klen.take().expect("Klen before Mac"),
                    tlen: tlen.take().expect("Tlen before Mac"),
                    key: key.take().expect("Key before Mac"),
                    msg: msg.take().expect("Msg before Mac"),
                    mac: hex_decode(v),
                };
                cases.push(case);
            } else {
                panic!("unexpected line in bounded span");
            }
        }
        assert_eq!(headers, 1, "exactly one section header");
        assert!(count.is_none(), "pending case at EOF");
        cases
    }

    /// All 375 cases (Count 0..=374) execute and pass, and the
    /// coverage matrix is exactly Klen bytes 100/125/128/139/142 by
    /// Tlen bytes 32/40/48/56/64 with 15 cases per combination —
    /// covering keys below, equal to, and above the 128-byte block
    /// and truncated and full-length MACs.
    #[test]
    fn nist_hmac_span_all_375_cases_pass() {
        let cases = parse_cases();
        assert_eq!(cases.len(), 375, "recorded span case count");
        let mut matrix: BTreeMap<(usize, usize), usize> = BTreeMap::new();
        for (position, case) in cases.iter().enumerate() {
            assert_eq!(case.count, position, "Count sequence");
            assert!(
                matches!(case.klen, 100 | 125 | 128 | 139 | 142),
                "recorded Klen coverage"
            );
            assert!(
                matches!(case.tlen, 32 | 40 | 48 | 56 | 64),
                "recorded Tlen coverage"
            );
            assert_eq!(case.key.len(), case.klen, "Key length matches Klen");
            assert_eq!(case.msg.len(), 128, "Msg fixed at 128 bytes");
            assert_eq!(case.mac.len(), case.tlen, "Mac length matches Tlen");
            let mac = hmac_sha512(&case.key, &case.msg);
            assert_eq!(
                &mac[..case.tlen],
                &case.mac[..],
                "Count = {} Klen = {} Tlen = {}",
                case.count,
                case.klen,
                case.tlen
            );
            *matrix.entry((case.klen, case.tlen)).or_insert(0) += 1;
        }
        assert_eq!(matrix.len(), 25, "5x5 Klen/Tlen combinations");
        for ((klen, tlen), n) in &matrix {
            assert_eq!(*n, 15, "Klen = {klen} Tlen = {tlen} case count");
        }
        let below: usize = cases.iter().filter(|c| c.klen < 128).count();
        let equal: usize = cases.iter().filter(|c| c.klen == 128).count();
        let above: usize = cases.iter().filter(|c| c.klen > 128).count();
        assert_eq!((below, equal, above), (150, 75, 150), "key-size regimes");
    }
}
