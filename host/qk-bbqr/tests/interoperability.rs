//! M22 clean-room public interoperability fixtures and exact-byte oracles.

use qk_bbqr::{
    decode_frame, encode_frame, Reassembler, MAX_FRAME_TEXT_BYTES, MAX_PART_DECODED_BYTES,
    MAX_TOTAL_DECODED_BYTES,
};
use std::collections::BTreeMap;

#[path = "../../qk-a1/src/sha256.rs"]
mod fixture_sha256;
#[allow(dead_code)]
#[path = "../../qk-a1/src/wipe.rs"]
mod wipe;

const FIXTURE: &str = include_str!("fixtures/interoperability.txt");
const FIXTURE_SHA256_HEX: &str = "a4700ba05534088c5129a7cff84187d7c109f8d7c775889d2fb36ecd620a28b8";
const AGREED_BODY_SHA256_HEX: &str =
    "efd89e1cdf76fd7f3701d965b96ae12f4497832651674eb8e8411f3a2e08d085";

type Fields = BTreeMap<String, String>;

fn header_field(name: &str) -> &str {
    let prefix = format!("# {name}=");
    FIXTURE
        .lines()
        .take_while(|line| !line.starts_with("case="))
        .find_map(|line| line.strip_prefix(&prefix))
        .expect("fixture header field")
}

fn cases() -> Vec<Fields> {
    FIXTURE
        .split("\n\n")
        .filter(|block| block.lines().any(|line| line.starts_with("case=")))
        .map(|block| {
            let mut fields = Fields::new();
            for line in block.lines().filter(|line| !line.starts_with('#')) {
                let (name, value) = line.split_once('=').expect("fixture field separator");
                assert!(fields.insert(name.to_owned(), value.to_owned()).is_none());
            }
            fields
        })
        .collect()
}

fn field<'a>(fields: &'a Fields, name: &str) -> &'a str {
    fields.get(name).map(String::as_str).expect("fixture field")
}

fn decode_hex(value: &str) -> Vec<u8> {
    assert_eq!(value.len() % 2, 0);
    let (pairs, remainder) = value.as_bytes().as_chunks::<2>();
    assert!(remainder.is_empty());
    pairs
        .iter()
        .map(|pair| {
            u8::from_str_radix(core::str::from_utf8(pair).expect("ASCII hex"), 16)
                .expect("valid hex")
        })
        .collect()
}

fn digest_hex(message: &[u8]) -> String {
    fixture_sha256::sha256(message)
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

fn frame(fields: &Fields, index: usize) -> &str {
    field(fields, &format!("frame_{index:03}"))
}

fn parse_usize(fields: &Fields, name: &str) -> usize {
    field(fields, name).parse().expect("fixture integer")
}

fn storage() -> Box<[u8; MAX_TOTAL_DECODED_BYTES]> {
    vec![0xa5; MAX_TOTAL_DECODED_BYTES]
        .into_boxed_slice()
        .try_into()
        .expect("exact fixed storage length")
}

#[test]
fn fixture_inventory_hashes_and_authority_order_are_exact() {
    assert_eq!(FIXTURE.len(), 9_033);
    assert_eq!(FIXTURE.lines().count(), 91);
    assert!(FIXTURE.ends_with('\n'));
    assert!(!FIXTURE.contains('\r'));
    assert_eq!(digest_hex(FIXTURE.as_bytes()), FIXTURE_SHA256_HEX);

    let body_offset = FIXTURE.find("\ncase=").expect("first case") + 1;
    let body = &FIXTURE.as_bytes()[body_offset..];
    assert_eq!(body.len(), 6_898);
    assert_eq!(body.iter().filter(|byte| **byte == b'\n').count(), 66);
    assert_eq!(digest_hex(body), AGREED_BODY_SHA256_HEX);

    for (name, expected) in [
        ("case_count", "3"),
        ("frame_count", "40"),
        ("generator_a_source_bytes", "1737"),
        ("generator_a_source_lf", "58"),
        (
            "generator_a_source_sha256",
            "85d5fbc8e9a274f7c9cab57209196388179fc0be952dec6d204664c82c100236",
        ),
        ("generator_b_source_bytes", "2858"),
        ("generator_b_source_lf", "101"),
        (
            "generator_b_source_sha256",
            "6677a9e561e191eb91e1719c22c8cd22d4b70b3b210168771f279523a55cf9d9",
        ),
        ("agreed_body_bytes", "6898"),
        ("agreed_body_lf", "66"),
        ("agreed_body_sha256", AGREED_BODY_SHA256_HEX),
    ] {
        assert_eq!(header_field(name), expected, "header {name}");
    }
    assert!(header_field("normative_source").contains("8dc7ef07d0d520763cc0001a885ca8d29ac8719a"));
    assert!(header_field("normative_source").contains("6a2e6b22cd8645a74d74b5e4ff1469f1a68fd962"));
    assert!(
        header_field("seedsigner_cross_check").contains("5088588dd4f913a489329d2422b0f925ed281856")
    );
    assert!(
        header_field("coldcard_cross_check").contains("55f93844b56e3637468321e1c68638a8138a3a2b")
    );
    assert!(header_field("authority_order").starts_with("the pinned specification is normative"));
    assert_eq!(cases().len(), 3);
    assert_eq!(
        cases()
            .iter()
            .map(|case| parse_usize(case, "frame_count"))
            .sum::<usize>(),
        40
    );
}

#[test]
fn constructed_payload_bytes_and_behavioral_shapes_are_exact() {
    let cases = cases();
    let expected = [
        (
            "spec-rfc4648-foobar",
            6,
            5,
            2,
            "c3ab8ff13720e8ad9047dd39466b3c8974e592c2fa383d4a3960714caef0c4f2",
        ),
        (
            "seedsigner-two-part-shape",
            1_306,
            655,
            2,
            "05230ad2142dd9255e25e13d18471ce45ba6449e793c75257afb4a3652c162d4",
        ),
        (
            "coldcard-base36-multipart-shape",
            176,
            5,
            36,
            "08e6378b0cf34ee52e0dd6781aa35fc049744a89830ac37cbe79935480e00b49",
        ),
    ];
    for (fields, (name, payload_len, part_len, count, payload_hash)) in cases.iter().zip(expected) {
        assert_eq!(field(fields, "case"), name);
        assert_eq!(parse_usize(fields, "payload_len"), payload_len);
        assert_eq!(parse_usize(fields, "non_final_part_len"), part_len);
        assert_eq!(parse_usize(fields, "declared_parts"), count);
        assert_eq!(parse_usize(fields, "frame_count"), count);
        let payload = decode_hex(field(fields, "payload_hex"));
        assert_eq!(payload.len(), payload_len);
        assert_eq!(digest_hex(&payload), payload_hash);

        match name {
            "spec-rfc4648-foobar" => assert_eq!(payload, b"foobar"),
            "seedsigner-two-part-shape" => {
                assert_eq!(&payload[..5], b"psbt\xff");
                for (index, byte) in payload.iter().enumerate().skip(5) {
                    assert_eq!(*byte, (index as u8).wrapping_mul(73).wrapping_add(41));
                }
                assert_eq!(frame(fields, 0).len(), 1_056);
                assert_eq!(frame(fields, 1).len(), 1_050);
            }
            "coldcard-base36-multipart-shape" => {
                assert_eq!(&payload[..5], b"psbt\xff");
                for (index, byte) in payload.iter().enumerate().skip(5) {
                    assert_eq!(*byte, (index as u8).wrapping_mul(37).wrapping_add(19));
                }
                assert!(frame(fields, 0).starts_with("B$2P1000"));
                assert!(frame(fields, 35).starts_with("B$2P100Z"));
            }
            _ => panic!("closed fixture case"),
        }
    }
}

#[test]
fn all_forty_frames_match_encoder_and_standalone_decoder_bytes() {
    let mut observed_frames = 0usize;
    for fields in cases() {
        let payload = decode_hex(field(&fields, "payload_hex"));
        let part_len = parse_usize(&fields, "non_final_part_len");
        let count = parse_usize(&fields, "declared_parts");
        for index in 0..count {
            let expected = frame(&fields, index).as_bytes();
            let mut encoded = [0xa5; MAX_FRAME_TEXT_BYTES];
            let encoded_len = encode_frame(&payload, part_len, index as u16, &mut encoded).unwrap();
            assert_eq!(&encoded[..encoded_len], expected);
            assert!(encoded[encoded_len..].iter().all(|byte| *byte == 0xa5));

            let mut decoded = [0x5a; MAX_PART_DECODED_BYTES];
            let metadata = decode_frame(expected, &mut decoded).unwrap();
            let start = index * part_len;
            let end = payload.len().min(start + part_len);
            assert_eq!(usize::from(metadata.declared_parts), count);
            assert_eq!(usize::from(metadata.part_index), index);
            assert_eq!(metadata.decoded_len, end - start);
            assert_eq!(&decoded[..metadata.decoded_len], &payload[start..end]);
            assert!(decoded[metadata.decoded_len..]
                .iter()
                .all(|byte| *byte == 0x5a));
            observed_frames += 1;
        }
    }
    assert_eq!(observed_frames, 40);
}

#[test]
fn forward_reverse_and_final_first_reassembly_are_byte_exact() {
    for fields in cases() {
        let payload = decode_hex(field(&fields, "payload_hex"));
        let count = parse_usize(&fields, "declared_parts");
        let forward: Vec<_> = (0..count).collect();
        let reverse: Vec<_> = (0..count).rev().collect();
        let mut final_first = Vec::with_capacity(count);
        final_first.push(count - 1);
        final_first.extend(0..count - 1);

        for order in [forward, reverse, final_first] {
            let mut backing = storage();
            let mut reassembler = Reassembler::new(&mut backing);
            for index in order {
                reassembler
                    .submit(frame(&fields, index).as_bytes())
                    .unwrap();
            }
            assert_eq!(reassembler.payload().unwrap(), payload);
        }
    }
}
