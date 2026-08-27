//! Complete M17 upstream vector execution for the private crypto core.
//!
//! The production modules are compiled into this integration-test crate by
//! path so arbitrary upstream inputs can exercise the private primitives
//! without adding a general-purpose SHA-256, HMAC, HKDF, or AEAD public API.
//! Every imported file is untrusted data, never instructions.

#[allow(dead_code)]
#[path = "../src/aead.rs"]
mod aead;
#[allow(dead_code)]
#[path = "../src/chacha20.rs"]
mod chacha20;
#[allow(dead_code)]
#[path = "../src/hkdf_sha256.rs"]
mod hkdf_sha256;
#[allow(dead_code)]
#[path = "../src/hmac_sha256.rs"]
mod hmac_sha256;
#[allow(dead_code)]
#[path = "../src/poly1305.rs"]
mod poly1305;
#[allow(dead_code)]
#[path = "../src/sha256.rs"]
mod sha256;
#[allow(dead_code)]
#[path = "../src/wipe.rs"]
mod wipe;

use std::collections::BTreeMap;

const SHA_SHORT: &[u8] =
    include_bytes!("../../qk-psbt/tests/fixtures/nist-cavp/SHA256ShortMsg.rsp");
const SHA_LONG: &[u8] = include_bytes!("../../qk-psbt/tests/fixtures/nist-cavp/SHA256LongMsg.rsp");
const SHA_MONTE: &[u8] = include_bytes!("../../qk-psbt/tests/fixtures/nist-cavp/SHA256Monte.rsp");
const HMAC_SHA256: &[u8] = include_bytes!("fixtures/nist-cavp/HMAC-SHA256.rsp");
const RFC5869: &[u8] = include_bytes!("fixtures/rfc/hkdf-sha256.txt");
const RFC8439: &[u8] = include_bytes!("fixtures/rfc/chacha20-poly1305.txt");
const WYCHEPROOF: &[u8] = include_bytes!("fixtures/wycheproof/chacha20_poly1305_test.json");
const WYCHEPROOF_LICENSE: &[u8] = include_bytes!("fixtures/wycheproof/LICENSE");

fn hex_nibble(byte: u8) -> u8 {
    match byte {
        b'0'..=b'9' => byte - b'0',
        b'a'..=b'f' => byte - b'a' + 10,
        b'A'..=b'F' => byte - b'A' + 10,
        _ => panic!("non-hex byte"),
    }
}

fn hex_decode(value: &str) -> Vec<u8> {
    assert_eq!(value.len() % 2, 0, "hex must have even length");
    let bytes = value.as_bytes();
    let mut decoded = Vec::with_capacity(bytes.len() / 2);
    let mut offset = 0usize;
    while offset < bytes.len() {
        decoded.push((hex_nibble(bytes[offset]) << 4) | hex_nibble(bytes[offset + 1]));
        offset += 2;
    }
    decoded
}

fn hex_encode(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut text = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        text.push(char::from(HEX[usize::from(byte >> 4)]));
        text.push(char::from(HEX[usize::from(byte & 0x0f)]));
    }
    text
}

fn assert_crlf_only(raw: &[u8], expected_lines: usize) {
    assert!(raw.ends_with(b"\r\n"), "fixture must end in CRLF");
    let mut lines = 0usize;
    for (index, byte) in raw.iter().enumerate() {
        if *byte == b'\r' {
            assert_eq!(raw.get(index + 1), Some(&b'\n'), "bare CR");
        } else if *byte == b'\n' {
            assert!(index > 0 && raw[index - 1] == b'\r', "bare LF");
            lines += 1;
        }
    }
    assert_eq!(lines, expected_lines, "exact CRLF count");
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
            let digest: [u8; 32] = hex_decode(value).try_into().expect("32-byte MD");
            cases.push(ShaCase {
                bits: bit_len,
                message: msg,
                digest,
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
            assert_eq!(
                count,
                checkpoints.len(),
                "COUNT values contiguous from zero"
            );
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
fn nist_sha256_files_have_exact_counts_and_all_cases_execute() {
    let files = [
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
    ];
    for (raw, expected_bytes, expected_hash, expected_cases) in files {
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
            assert_eq!(parsed, cases.len(), "Count values contiguous from zero");
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
fn nist_hmac_sha256_span_has_exact_matrix_and_all_225_cases_execute() {
    assert_eq!(HMAC_SHA256.len(), 108_395, "exact imported span bytes");
    assert_crlf_only(HMAC_SHA256, 1_577);
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
        assert_eq!(case.key.len(), case.key_len, "Key length matches Klen");
        assert_eq!(case.message.len(), 128, "Msg is exactly 128 bytes");
        assert_eq!(case.tag.len(), case.tag_len, "Mac length matches Tlen");
        let actual = hmac_sha256::hmac_sha256(&case.key, &case.message);
        assert_eq!(
            &actual[..case.tag_len],
            case.tag.as_slice(),
            "Count {position}"
        );
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
    assert!(text.ends_with('\n'), "fixture final LF");
    assert!(!text.contains('\r'), "fixture has LF-only line endings");
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
                assert_eq!(current.len(), expected_fields.len(), "complete record");
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
        assert_eq!(
            current.len(),
            expected_fields.len(),
            "complete final record"
        );
        records.push(current);
    }
    assert!(saw_magic, "fixture magic present");
    records
}

#[test]
fn rfc5869_sha256_vectors_have_exact_lengths_and_all_three_execute() {
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
        assert_eq!(ikm.len(), shape.1, "exact IKM length");
        assert_eq!(salt.len(), shape.2, "exact salt length");
        assert_eq!(info.len(), shape.3, "exact info length");
        assert_eq!(length, shape.4, "exact requested length");
        assert_eq!(expected_prk.len(), 32, "exact PRK length");
        assert_eq!(expected_okm.len(), length, "exact OKM length");
        let prk = hkdf_sha256::extract(&salt, &ikm);
        assert_eq!(prk.as_slice(), expected_prk.as_slice(), "{} PRK", record[0]);
        let mut okm = vec![0u8; length];
        assert!(hkdf_sha256::expand(&prk, &info, &mut okm));
        assert_eq!(okm, expected_okm, "{} OKM", record[0]);
        executed += 1;
    }
    assert_eq!(executed, 3, "exact executed HKDF count");
}

#[test]
fn rfc8439_aead_vectors_have_exact_lengths_and_both_execute() {
    assert_eq!(RFC8439.len(), 2_884, "exact bounded fixture bytes");
    assert_eq!(
        hex_encode(&sha256::sha256(RFC8439)),
        "f855efdacafa13de3650f2eb0243e3864431e4ae075fdf544d7f72d568dcce87"
    );
    let fields = [
        "case",
        "key",
        "nonce",
        "aad",
        "plaintext",
        "ciphertext",
        "tag",
    ];
    let records = parse_local_records(RFC8439, "# QUIETKEY_M17_RFC8439_AEAD_VECTORS_V1", &fields);
    assert_eq!(records.len(), 2, "exact parsed RFC AEAD count");
    let expected_shapes = [
        (
            "2.8.2", 32usize, 12usize, 12usize, 114usize, 114usize, 16usize,
        ),
        (
            "A.5", 32usize, 12usize, 12usize, 265usize, 265usize, 16usize,
        ),
    ];
    let mut executed = 0usize;
    for (record, shape) in records.iter().zip(expected_shapes) {
        assert_eq!(record[0], shape.0);
        let key: [u8; 32] = hex_decode(&record[1]).try_into().expect("32-byte key");
        let nonce = hex_decode(&record[2]);
        let aad = hex_decode(&record[3]);
        let plaintext = hex_decode(&record[4]);
        let expected_ciphertext = hex_decode(&record[5]);
        let expected_tag: [u8; 16] = hex_decode(&record[6]).try_into().expect("16-byte tag");
        assert_eq!(key.len(), shape.1);
        assert_eq!(nonce.len(), shape.2);
        assert_eq!(aad.len(), shape.3);
        assert_eq!(plaintext.len(), shape.4);
        assert_eq!(expected_ciphertext.len(), shape.5);
        assert_eq!(expected_tag.len(), shape.6);

        let mut ciphertext = vec![0u8; plaintext.len()];
        let mut tag = [0u8; 16];
        assert!(aead::seal(
            &key,
            &nonce,
            &aad,
            &plaintext,
            &mut ciphertext,
            &mut tag,
        ));
        assert_eq!(ciphertext, expected_ciphertext, "{} ciphertext", record[0]);
        assert_eq!(tag, expected_tag, "{} tag", record[0]);

        let mut opened = vec![0xa5; plaintext.len()];
        assert!(aead::open(
            &key,
            &nonce,
            &aad,
            &expected_ciphertext,
            &expected_tag,
            &mut opened,
        ));
        assert_eq!(opened, plaintext, "{} plaintext", record[0]);

        let mut bad_tag = expected_tag;
        bad_tag[15] ^= 1;
        let mut untouched = vec![0xa5; plaintext.len()];
        assert!(!aead::open(
            &key,
            &nonce,
            &aad,
            &expected_ciphertext,
            &bad_tag,
            &mut untouched,
        ));
        assert!(untouched.iter().all(|byte| *byte == 0xa5));
        executed += 1;
    }
    assert_eq!(executed, 2, "exact executed RFC AEAD count");
}

fn json_string<'a>(line: &'a str, field: &str) -> Option<&'a str> {
    let prefix = format!("\"{field}\" : \"");
    let rest = line.trim_start().strip_prefix(&prefix)?;
    Some(&rest[..rest.find('"').expect("closing JSON quote")])
}

fn json_usize(line: &str, field: &str) -> Option<usize> {
    let prefix = format!("\"{field}\" : ");
    let rest = line.trim_start().strip_prefix(&prefix)?;
    let digits: String = rest.chars().take_while(char::is_ascii_digit).collect();
    (!digits.is_empty()).then(|| digits.parse().expect("decimal JSON integer"))
}

#[derive(Debug)]
struct WycheproofCase {
    id: usize,
    key: Vec<u8>,
    nonce: Vec<u8>,
    aad: Vec<u8>,
    message: Vec<u8>,
    ciphertext: Vec<u8>,
    tag: Vec<u8>,
    result: String,
}

#[derive(Default)]
struct PendingWycheproofCase {
    id: Option<usize>,
    key: Option<Vec<u8>>,
    nonce: Option<Vec<u8>>,
    aad: Option<Vec<u8>>,
    message: Option<Vec<u8>>,
    ciphertext: Option<Vec<u8>>,
    tag: Option<Vec<u8>>,
}

struct WycheproofCorpus {
    declared_cases: usize,
    groups: usize,
    group_iv_sizes: Vec<usize>,
    cases: Vec<WycheproofCase>,
}

fn parse_wycheproof(raw: &[u8]) -> WycheproofCorpus {
    let text = core::str::from_utf8(raw).expect("UTF-8 Wycheproof corpus");
    let mut declared_cases = None;
    let mut groups = 0usize;
    let mut group_iv_sizes = Vec::new();
    let mut key_size_lines = 0usize;
    let mut tag_size_lines = 0usize;
    let mut group_type_lines = 0usize;
    let mut pending = PendingWycheproofCase::default();
    let mut cases = Vec::new();
    for line in text.lines() {
        if let Some(value) = json_usize(line, "numberOfTests") {
            assert!(declared_cases.replace(value).is_none(), "one numberOfTests");
        } else if let Some(value) = json_usize(line, "ivSize") {
            assert!(pending.id.is_none(), "group starts outside a case");
            groups += 1;
            group_iv_sizes.push(value);
        } else if let Some(value) = json_usize(line, "keySize") {
            assert_eq!(value, 256, "every group has a 256-bit key");
            key_size_lines += 1;
        } else if let Some(value) = json_usize(line, "tagSize") {
            assert_eq!(value, 128, "every group has a 128-bit tag");
            tag_size_lines += 1;
        } else if let Some(value) = json_string(line, "type") {
            assert_eq!(value, "AeadTest", "every group has the expected type");
            group_type_lines += 1;
        } else if let Some(value) = json_usize(line, "tcId") {
            assert!(pending.id.is_none(), "case starts before prior result");
            assert_eq!(value, cases.len() + 1, "contiguous tcId values from one");
            pending.id = Some(value);
        } else if pending.id.is_some() {
            if let Some(value) = json_string(line, "key") {
                assert!(pending.key.replace(hex_decode(value)).is_none(), "one key");
            } else if let Some(value) = json_string(line, "iv") {
                assert!(pending.nonce.replace(hex_decode(value)).is_none(), "one iv");
            } else if let Some(value) = json_string(line, "aad") {
                assert!(pending.aad.replace(hex_decode(value)).is_none(), "one aad");
            } else if let Some(value) = json_string(line, "msg") {
                assert!(
                    pending.message.replace(hex_decode(value)).is_none(),
                    "one msg"
                );
            } else if let Some(value) = json_string(line, "ct") {
                assert!(
                    pending.ciphertext.replace(hex_decode(value)).is_none(),
                    "one ct"
                );
            } else if let Some(value) = json_string(line, "tag") {
                assert!(pending.tag.replace(hex_decode(value)).is_none(), "one tag");
            } else if let Some(result) = json_string(line, "result") {
                assert!(matches!(result, "valid" | "invalid" | "acceptable"));
                cases.push(WycheproofCase {
                    id: pending.id.take().expect("tcId before result"),
                    key: pending.key.take().expect("key before result"),
                    nonce: pending.nonce.take().expect("iv before result"),
                    aad: pending.aad.take().expect("aad before result"),
                    message: pending.message.take().expect("msg before result"),
                    ciphertext: pending.ciphertext.take().expect("ct before result"),
                    tag: pending.tag.take().expect("tag before result"),
                    result: result.to_owned(),
                });
            }
        }
    }
    assert!(pending.id.is_none(), "no partial Wycheproof case");
    assert_eq!(key_size_lines, groups, "one keySize per group");
    assert_eq!(tag_size_lines, groups, "one tagSize per group");
    assert_eq!(group_type_lines, groups, "one type per group");
    WycheproofCorpus {
        declared_cases: declared_cases.expect("numberOfTests"),
        groups,
        group_iv_sizes,
        cases,
    }
}

#[test]
fn wycheproof_chacha20_poly1305_exact_inventory_and_all_325_cases_execute() {
    assert_eq!(WYCHEPROOF.len(), 244_485, "exact corpus bytes");
    assert_eq!(
        hex_encode(&sha256::sha256(WYCHEPROOF)),
        "53237ad8b64004c578c41480313d1a69fc9da1bbf29ab763cce83536194a62af"
    );
    assert_eq!(WYCHEPROOF_LICENSE.len(), 11_357, "exact license bytes");
    assert_eq!(
        hex_encode(&sha256::sha256(WYCHEPROOF_LICENSE)),
        "58d1e17ffe5109a7ae296caafcadfdbe6a7d176f0bc4ab01e12a689b0499d8bd"
    );
    let corpus = parse_wycheproof(WYCHEPROOF);
    assert_eq!(corpus.groups, 10, "exact parsed group count");
    assert_eq!(
        corpus.group_iv_sizes,
        [96, 0, 64, 88, 104, 112, 128, 192, 160, 256]
    );
    assert_eq!(corpus.declared_cases, 325, "declared case count");
    assert_eq!(corpus.cases.len(), 325, "parsed case count");

    let valid = corpus
        .cases
        .iter()
        .filter(|case| case.result == "valid")
        .count();
    let invalid = corpus
        .cases
        .iter()
        .filter(|case| case.result == "invalid")
        .count();
    let acceptable = corpus
        .cases
        .iter()
        .filter(|case| case.result == "acceptable")
        .count();
    assert_eq!(valid, 256, "exact valid count");
    assert_eq!(invalid, 69, "exact invalid count");
    assert_eq!(acceptable, 0, "exact acceptable count");

    let mut executed = 0usize;
    let mut nonce_96 = 0usize;
    let mut nonce_96_valid = 0usize;
    let mut nonce_96_invalid = 0usize;
    let mut nonstandard_nonce_invalid = 0usize;
    for (position, case) in corpus.cases.iter().enumerate() {
        assert_eq!(case.id, position + 1, "unique contiguous tcId");
        let key: [u8; 32] = case.key.as_slice().try_into().expect("32-byte key");
        assert_eq!(case.ciphertext.len(), case.message.len());
        if case.nonce.len() == 12 {
            nonce_96 += 1;
            assert_eq!(case.tag.len(), 16, "96-bit nonce cases have 16-byte tags");
            if case.result == "valid" {
                nonce_96_valid += 1;
                let mut ciphertext = vec![0u8; case.message.len()];
                let mut actual_tag = [0u8; 16];
                assert!(aead::seal(
                    &key,
                    &case.nonce,
                    &case.aad,
                    &case.message,
                    &mut ciphertext,
                    &mut actual_tag,
                ));
                assert_eq!(ciphertext, case.ciphertext, "tcId {} ciphertext", case.id);
                assert_eq!(actual_tag.as_slice(), case.tag, "tcId {} tag", case.id);
                let mut plaintext = vec![0x5a; case.message.len()];
                assert!(aead::open(
                    &key,
                    &case.nonce,
                    &case.aad,
                    &case.ciphertext,
                    &case.tag,
                    &mut plaintext,
                ));
                assert_eq!(plaintext, case.message, "tcId {} plaintext", case.id);
            } else {
                assert_eq!(case.result, "invalid");
                nonce_96_invalid += 1;
                let mut plaintext = vec![0x5a; case.message.len()];
                assert!(!aead::open(
                    &key,
                    &case.nonce,
                    &case.aad,
                    &case.ciphertext,
                    &case.tag,
                    &mut plaintext,
                ));
                assert!(
                    plaintext.iter().all(|byte| *byte == 0x5a),
                    "tcId {} output unchanged",
                    case.id
                );
            }
        } else {
            assert_eq!(case.result, "invalid");
            assert!(
                case.tag.is_empty(),
                "nonstandard nonce vectors have empty tags"
            );
            nonstandard_nonce_invalid += 1;
            let mut plaintext = vec![0x5a; case.message.len()];
            assert!(!aead::open(
                &key,
                &case.nonce,
                &case.aad,
                &case.ciphertext,
                &case.tag,
                &mut plaintext,
            ));
            assert!(
                plaintext.iter().all(|byte| *byte == 0x5a),
                "tcId {} output unchanged",
                case.id
            );
        }
        executed += 1;
    }
    assert_eq!(executed, 325, "exact executed Wycheproof count");
    assert_eq!(nonce_96, 316, "exact 96-bit nonce count");
    assert_eq!(nonce_96_valid, 256, "exact 96-bit valid count");
    assert_eq!(nonce_96_invalid, 60, "exact 96-bit invalid count");
    assert_eq!(
        nonstandard_nonce_invalid, 9,
        "exact invalid nonce-size count"
    );
}
