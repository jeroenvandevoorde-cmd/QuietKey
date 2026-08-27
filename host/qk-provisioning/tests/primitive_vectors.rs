//! Exact registered NIST and RFC execution against M26's private primitives.

#[allow(dead_code)]
#[path = "../src/hkdf_sha256.rs"]
mod hkdf_sha256;
#[allow(dead_code)]
#[path = "../src/hmac_sha256.rs"]
mod hmac_sha256;
#[allow(dead_code)]
#[path = "../src/sha256.rs"]
mod sha256;

use std::collections::BTreeMap;

const SHA_SHORT: &[u8] =
    include_bytes!("../../qk-psbt/tests/fixtures/nist-cavp/SHA256ShortMsg.rsp");
const SHA_LONG: &[u8] = include_bytes!("../../qk-psbt/tests/fixtures/nist-cavp/SHA256LongMsg.rsp");
const SHA_MONTE: &[u8] = include_bytes!("../../qk-psbt/tests/fixtures/nist-cavp/SHA256Monte.rsp");
const HMAC_SHA256: &[u8] = include_bytes!("../../qk-a1/tests/fixtures/nist-cavp/HMAC-SHA256.rsp");
const RFC5869: &[u8] = include_bytes!("../../qk-a1/tests/fixtures/rfc/hkdf-sha256.txt");

fn hex_nibble(byte: u8) -> u8 {
    match byte {
        b'0'..=b'9' => byte - b'0',
        b'a'..=b'f' => byte - b'a' + 10,
        b'A'..=b'F' => byte - b'A' + 10,
        _ => panic!("non-hex byte"),
    }
}

fn hex_decode(value: &str) -> Vec<u8> {
    assert!(value.len().is_multiple_of(2), "hex must have even length");
    let bytes = value.as_bytes();
    let mut output = Vec::with_capacity(bytes.len() / 2);
    for offset in (0..bytes.len()).step_by(2) {
        output.push((hex_nibble(bytes[offset]) << 4) | hex_nibble(bytes[offset + 1]));
    }
    output
}

fn hex_encode(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut output = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        output.push(char::from(HEX[usize::from(byte >> 4)]));
        output.push(char::from(HEX[usize::from(byte & 0x0f)]));
    }
    output
}

#[derive(Debug)]
struct ShaCase {
    bits: usize,
    message: Vec<u8>,
    digest: [u8; 32],
}

fn parse_sha_cases(raw: &[u8]) -> Vec<ShaCase> {
    let text = core::str::from_utf8(raw).expect("ASCII SHA response file");
    let mut header_count = 0usize;
    let mut bits = None;
    let mut message = None;
    let mut cases = Vec::new();
    for source_line in text.lines() {
        let line = source_line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        if line == "[L = 32]" {
            header_count += 1;
        } else if let Some(value) = line.strip_prefix("Len = ") {
            assert!(bits.is_none() && message.is_none(), "Len field order");
            bits = Some(value.parse::<usize>().expect("decimal Len"));
        } else if let Some(value) = line.strip_prefix("Msg = ") {
            assert!(bits.is_some() && message.is_none(), "Msg field order");
            message = Some(hex_decode(value));
        } else if let Some(value) = line.strip_prefix("MD = ") {
            let bit_len = bits.take().expect("Len before MD");
            assert_eq!(bit_len % 8, 0, "byte-oriented vector");
            let mut msg = message.take().expect("Msg before MD");
            assert!(msg.len() >= bit_len / 8, "Msg contains Len bytes");
            msg.truncate(bit_len / 8);
            cases.push(ShaCase {
                bits: bit_len,
                message: msg,
                digest: hex_decode(value).try_into().expect("32-byte MD"),
            });
        } else {
            panic!("unexpected SHA response line: {line}");
        }
    }
    assert_eq!(header_count, 1, "one SHA-256 header");
    assert!(bits.is_none() && message.is_none(), "no partial SHA case");
    cases
}

fn parse_sha_monte(raw: &[u8]) -> ([u8; 32], Vec<[u8; 32]>) {
    let text = core::str::from_utf8(raw).expect("ASCII SHA Monte response file");
    let mut header_count = 0usize;
    let mut seed = None;
    let mut pending_count = None;
    let mut checkpoints = Vec::new();
    for source_line in text.lines() {
        let line = source_line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        if line == "[L = 32]" {
            header_count += 1;
        } else if let Some(value) = line.strip_prefix("Seed = ") {
            assert!(seed.is_none(), "one Seed");
            seed = Some(hex_decode(value).try_into().expect("32-byte Seed"));
        } else if let Some(value) = line.strip_prefix("COUNT = ") {
            assert!(pending_count.is_none(), "COUNT must receive one MD");
            let count = value.parse::<usize>().expect("decimal COUNT");
            assert_eq!(count, checkpoints.len(), "contiguous COUNT sequence");
            pending_count = Some(count);
        } else if let Some(value) = line.strip_prefix("MD = ") {
            pending_count.take().expect("COUNT before MD");
            checkpoints.push(hex_decode(value).try_into().expect("32-byte Monte MD"));
        } else {
            panic!("unexpected SHA Monte response line: {line}");
        }
    }
    assert_eq!(header_count, 1, "one SHA-256 header");
    assert!(pending_count.is_none(), "no pending Monte COUNT");
    (seed.expect("one Monte Seed"), checkpoints)
}

#[test]
fn m26_sha256_executes_exact_nist_files_and_counts() {
    for (raw, expected_bytes, expected_hash, expected_cases) in [
        (
            SHA_SHORT,
            10_299usize,
            "75e1cb83994638481808e225b9eb0c1ebd0c232d952ac42b61abce6363be283c",
            65usize,
        ),
        (
            SHA_LONG,
            426_209usize,
            "6fac36f37360bcf74ffcf4465c18e30d6d5a04cc90885b901fc3130c16060974",
            64usize,
        ),
    ] {
        assert_eq!(raw.len(), expected_bytes, "exact fixture bytes");
        assert_eq!(hex_encode(&sha256::sha256(raw)), expected_hash);
        let cases = parse_sha_cases(raw);
        assert_eq!(cases.len(), expected_cases, "exact parsed case count");
        let mut executed = 0usize;
        for case in cases {
            assert_eq!(case.message.len() * 8, case.bits);
            assert_eq!(sha256::sha256(&case.message), case.digest);
            executed += 1;
        }
        assert_eq!(executed, expected_cases, "exact executed case count");
    }

    assert_eq!(SHA_MONTE.len(), 8_751, "exact Monte fixture bytes");
    assert_eq!(
        hex_encode(&sha256::sha256(SHA_MONTE)),
        "29ea30c6bb4b84e425fb8c1d731c6bb852dac935825f2bd1143e5d3c4f10bfb9"
    );
    let (mut seed, checkpoints) = parse_sha_monte(SHA_MONTE);
    assert_eq!(checkpoints.len(), 100, "exact parsed Monte count");
    let mut executed = 0usize;
    for (count, expected) in checkpoints.iter().enumerate() {
        let mut rolling = [seed; 3];
        for _ in 0..1_000 {
            let mut input = [0u8; 96];
            input[..32].copy_from_slice(&rolling[0]);
            input[32..64].copy_from_slice(&rolling[1]);
            input[64..].copy_from_slice(&rolling[2]);
            rolling = [rolling[1], rolling[2], sha256::sha256(&input)];
        }
        assert_eq!(&rolling[2], expected, "Monte COUNT {count}");
        seed = rolling[2];
        executed += 1;
    }
    assert_eq!(executed, 100, "exact executed Monte count");
}

#[derive(Debug)]
struct HmacCase {
    count: usize,
    key_len: usize,
    tag_len: usize,
    key: Vec<u8>,
    message: Vec<u8>,
    tag: Vec<u8>,
}

fn parse_hmac_cases(raw: &[u8]) -> Vec<HmacCase> {
    let text = core::str::from_utf8(raw).expect("ASCII HMAC response file");
    let mut header_count = 0usize;
    let mut count = None;
    let mut key_len = None;
    let mut tag_len = None;
    let mut key = None;
    let mut message = None;
    let mut cases = Vec::new();
    for source_line in text.lines() {
        let line = source_line.trim();
        if line.is_empty() {
            continue;
        }
        if line == "[L=32]" {
            header_count += 1;
        } else if let Some(value) = line.strip_prefix("Count = ") {
            assert!(count.is_none(), "Count while case pending");
            let parsed = value.parse::<usize>().expect("decimal Count");
            assert_eq!(parsed, cases.len(), "contiguous Count sequence");
            count = Some(parsed);
        } else if let Some(value) = line.strip_prefix("Klen = ") {
            assert!(count.is_some() && key_len.is_none(), "Klen field order");
            key_len = Some(value.parse::<usize>().expect("decimal Klen"));
        } else if let Some(value) = line.strip_prefix("Tlen = ") {
            assert!(key_len.is_some() && tag_len.is_none(), "Tlen field order");
            tag_len = Some(value.parse::<usize>().expect("decimal Tlen"));
        } else if let Some(value) = line.strip_prefix("Key = ") {
            assert!(tag_len.is_some() && key.is_none(), "Key field order");
            key = Some(hex_decode(value));
        } else if let Some(value) = line.strip_prefix("Msg = ") {
            assert!(key.is_some() && message.is_none(), "Msg field order");
            message = Some(hex_decode(value));
        } else if let Some(value) = line.strip_prefix("Mac = ") {
            cases.push(HmacCase {
                count: count.take().expect("Count before Mac"),
                key_len: key_len.take().expect("Klen before Mac"),
                tag_len: tag_len.take().expect("Tlen before Mac"),
                key: key.take().expect("Key before Mac"),
                message: message.take().expect("Msg before Mac"),
                tag: hex_decode(value),
            });
        } else {
            panic!("unexpected HMAC response line: {line}");
        }
    }
    assert_eq!(header_count, 1, "one L=32 span header");
    assert!(
        count.is_none()
            && key_len.is_none()
            && tag_len.is_none()
            && key.is_none()
            && message.is_none(),
        "no partial HMAC case"
    );
    cases
}

#[test]
fn m26_hmac_sha256_executes_exact_nist_matrix_and_count() {
    assert_eq!(HMAC_SHA256.len(), 108_395, "exact imported span bytes");
    assert_eq!(
        hex_encode(&sha256::sha256(HMAC_SHA256)),
        "fc34c586cde748d583e46a5081cee98e9750f3fb155356a95a3a5d4db11eb642"
    );
    let cases = parse_hmac_cases(HMAC_SHA256);
    assert_eq!(cases.len(), 225, "exact parsed HMAC count");
    let mut matrix = BTreeMap::<(usize, usize), usize>::new();
    let mut executed = 0usize;
    for (position, case) in cases.iter().enumerate() {
        assert_eq!(case.count, position, "Count sequence");
        assert!(matches!(case.key_len, 40 | 45 | 64 | 70 | 74));
        assert!(matches!(case.tag_len, 16 | 24 | 32));
        assert_eq!(case.key.len(), case.key_len);
        assert_eq!(case.message.len(), 128);
        assert_eq!(case.tag.len(), case.tag_len);
        let actual = hmac_sha256::hmac_sha256(&case.key, &case.message);
        assert_eq!(&actual[..case.tag_len], case.tag.as_slice());
        *matrix.entry((case.key_len, case.tag_len)).or_default() += 1;
        executed += 1;
    }
    assert_eq!(executed, 225, "exact executed HMAC count");
    assert_eq!(matrix.len(), 15, "complete 5 by 3 matrix");
    for key_len in [40usize, 45, 64, 70, 74] {
        for tag_len in [16usize, 24, 32] {
            assert_eq!(matrix.get(&(key_len, tag_len)), Some(&15));
        }
    }
}

fn parse_local_records(raw: &[u8], magic: &str, expected_fields: &[&str]) -> Vec<Vec<String>> {
    let text = core::str::from_utf8(raw).expect("ASCII local fixture");
    assert!(text.ends_with('\n'));
    assert!(!text.contains('\r'));
    let mut saw_magic = false;
    let mut current = Vec::new();
    let mut records = Vec::new();
    for line in text.lines() {
        if line.starts_with('#') {
            if !saw_magic {
                assert_eq!(line, magic, "exact fixture magic");
                saw_magic = true;
            }
            continue;
        }
        if line.is_empty() {
            if !current.is_empty() {
                assert_eq!(current.len(), expected_fields.len());
                records.push(core::mem::take(&mut current));
            }
            continue;
        }
        assert!(saw_magic, "magic before data");
        let (field, value) = line.split_once('=').expect("one field delimiter");
        assert_eq!(field, expected_fields[current.len()], "strict field order");
        current.push(value.to_owned());
    }
    if !current.is_empty() {
        assert_eq!(current.len(), expected_fields.len());
        records.push(current);
    }
    assert!(saw_magic, "fixture magic present");
    records
}

#[test]
fn m26_hkdf_sha256_executes_all_three_exact_rfc5869_cases() {
    assert_eq!(RFC5869.len(), 2_119, "exact bounded fixture bytes");
    assert_eq!(
        hex_encode(&sha256::sha256(RFC5869)),
        "6bbc7e0fa92cdf125f3cd70396aa7cd69afaeac1dfe4720482331d14dd705a8a"
    );
    let fields = ["case", "ikm", "salt", "info", "length", "prk", "okm"];
    let records = parse_local_records(
        RFC5869,
        "# QUIETKEY_M17_RFC5869_HKDF_SHA256_VECTORS_V1",
        &fields,
    );
    assert_eq!(records.len(), 3, "exact parsed HKDF count");
    let expected_shapes = [
        ("A.1", 22usize, 13usize, 10usize, 42usize),
        ("A.2", 80usize, 80usize, 80usize, 82usize),
        ("A.3", 22usize, 0usize, 0usize, 42usize),
    ];
    let mut executed = 0usize;
    for (record, shape) in records.iter().zip(expected_shapes) {
        assert_eq!(record[0], shape.0);
        let ikm = hex_decode(&record[1]);
        let salt = hex_decode(&record[2]);
        let info = hex_decode(&record[3]);
        let length = record[4].parse::<usize>().expect("decimal output length");
        let expected_prk = hex_decode(&record[5]);
        let expected_okm = hex_decode(&record[6]);
        assert_eq!(
            (ikm.len(), salt.len(), info.len(), length),
            (shape.1, shape.2, shape.3, shape.4)
        );
        assert_eq!(expected_prk.len(), 32);
        assert_eq!(expected_okm.len(), length);
        let prk = hkdf_sha256::extract(&salt, &ikm);
        assert_eq!(prk.as_slice(), expected_prk.as_slice(), "{} PRK", record[0]);
        let mut okm = vec![0u8; length];
        assert!(hkdf_sha256::expand(&prk, &info, &mut okm));
        assert_eq!(okm, expected_okm, "{} OKM", record[0]);
        executed += 1;
    }
    assert_eq!(executed, 3, "exact executed HKDF count");
}
