//! M17's outside-Git, two-implementation public capsule fixtures.

use qk_a1::{decrypt, encrypt, A1Error};
use std::collections::BTreeMap;

#[path = "../src/sha256.rs"]
mod fixture_sha256;

const FIXTURE: &str = include_str!("fixtures/capsules.txt");
const FIXTURE_SHA256: [u8; 32] = [
    0xb7, 0x7e, 0xa4, 0x8e, 0x2a, 0x3c, 0x4d, 0xf7, 0xe8, 0x6f, 0xd6, 0x6c, 0x89, 0x7f, 0x8a, 0xb3,
    0xc4, 0x4a, 0x7d, 0xd9, 0x45, 0xba, 0xc8, 0x30, 0x00, 0x63, 0x9d, 0x1f, 0x70, 0x5a, 0xfb, 0xca,
];

type Case = BTreeMap<String, String>;

fn blocks(marker: &str) -> Vec<Case> {
    FIXTURE
        .split("\n\n")
        .filter(|block| block.lines().any(|line| line.starts_with(marker)))
        .map(|block| {
            let mut fields = Case::new();
            for line in block.lines().filter(|line| !line.starts_with('#')) {
                let (name, value) = line.split_once('=').expect("fixture field separator");
                assert!(fields.insert(name.to_owned(), value.to_owned()).is_none());
            }
            fields
        })
        .collect()
}

fn positives() -> Vec<Case> {
    blocks("case=")
}

fn rejections() -> Vec<Case> {
    blocks("reject_case=")
}

fn header_field(name: &str) -> &str {
    let prefix = format!("# {name}=");
    FIXTURE
        .lines()
        .take_while(|line| !line.starts_with("case="))
        .find_map(|line| line.strip_prefix(&prefix))
        .expect("fixture header field")
}

fn field<'a>(case: &'a Case, name: &str) -> &'a str {
    case.get(name).map(String::as_str).expect("fixture field")
}

fn decode_hex<const N: usize>(value: &str) -> [u8; N] {
    assert_eq!(value.len(), N * 2);
    let mut output = [0u8; N];
    for (slot, pair) in output.iter_mut().zip(value.as_bytes().chunks(2)) {
        *slot = u8::from_str_radix(core::str::from_utf8(pair).expect("ASCII hex"), 16)
            .expect("valid hex");
    }
    output
}

fn decode_hex_vec(value: &str) -> Vec<u8> {
    assert_eq!(value.len() % 2, 0);
    value
        .as_bytes()
        .chunks(2)
        .map(|pair| {
            u8::from_str_radix(core::str::from_utf8(pair).expect("ASCII hex"), 16)
                .expect("valid hex")
        })
        .collect()
}

fn error(value: &str) -> A1Error {
    match value {
        "InvalidCapsuleLength" => A1Error::InvalidCapsuleLength,
        "InvalidMagic" => A1Error::InvalidMagic,
        "UnsupportedCodingVersion" => A1Error::UnsupportedCodingVersion,
        "UnsupportedCryptoVersion" => A1Error::UnsupportedCryptoVersion,
        "UnsupportedNetwork" => A1Error::UnsupportedNetwork,
        "AuthenticationFailed" => A1Error::AuthenticationFailed,
        _ => panic!("closed fixture error"),
    }
}

fn reject_fixture(case: &Case) {
    let a2 = decode_hex::<32>(field(case, "a2"));
    let wallet_id = decode_hex::<32>(field(case, "wallet_id"));
    let capsule = decode_hex_vec(field(case, "capsule"));
    let mut output = decode_hex::<32>(field(case, "output_sentinel"));
    let before = output;
    assert_eq!(
        decrypt(&a2, &wallet_id, &capsule, &mut output),
        Err(error(field(case, "expected"))),
        "{}",
        field(case, "reject_case")
    );
    assert_eq!(
        output,
        before,
        "{} changed plaintext output",
        field(case, "reject_case")
    );
}

#[test]
fn fixture_inventory_hash_lengths_and_constructed_payloads_are_exact() {
    assert_eq!(FIXTURE.len(), 9_631);
    assert_eq!(FIXTURE.lines().count(), 150);
    assert_eq!(fixture_sha256::sha256(FIXTURE.as_bytes()), FIXTURE_SHA256);
    assert!(FIXTURE.ends_with('\n'));
    assert!(!FIXTURE.contains('\r'));
    assert_eq!(header_field("case_count"), "4");
    assert_eq!(header_field("positive_case_count"), "4");
    assert_eq!(header_field("rejection_case_count"), "11");
    assert_eq!(header_field("wire_length"), "67");
    assert_eq!(header_field("aad_length"), "39");
    assert_eq!(
        FIXTURE
            .lines()
            .filter(|line| line.starts_with("case="))
            .count(),
        4
    );
    assert_eq!(
        FIXTURE
            .lines()
            .filter(|line| line.starts_with("reject_case="))
            .count(),
        11
    );

    let all = positives();
    assert_eq!(all.len(), 4);
    assert_eq!(
        all.iter()
            .map(|case| field(case, "case"))
            .collect::<Vec<_>>(),
        [
            "pattern_zero_and_ones",
            "pattern_ascending_descending",
            "pattern_alternating",
            "pattern_edges",
        ]
    );
    for case in &all {
        assert_eq!(case.len(), 11);
        let wallet_id = decode_hex::<32>(field(case, "wallet_id"));
        let nonce = decode_hex::<12>(field(case, "nonce"));
        let header = decode_hex::<7>(field(case, "header"));
        let aad = decode_hex::<39>(field(case, "aad"));
        let ciphertext = decode_hex::<32>(field(case, "ciphertext"));
        let tag = decode_hex::<16>(field(case, "tag"));
        let capsule = decode_hex::<67>(field(case, "capsule"));
        let _a2 = decode_hex::<32>(field(case, "a2"));
        let _seed_a = decode_hex::<32>(field(case, "seed_a"));
        let _derived_public_test_key = decode_hex::<32>(field(case, "key"));

        assert_eq!(header, [0x51, 0x4b, 0x41, 0x31, 0x01, 0x01, 0x01]);
        assert_eq!(&aad[..7], &header);
        assert_eq!(&aad[7..], &wallet_id);
        assert_eq!(&capsule[..7], &header);
        assert_eq!(&capsule[7..19], &nonce);
        assert_eq!(&capsule[19..51], &ciphertext);
        assert_eq!(&capsule[51..], &tag);
    }

    let rejected = rejections();
    assert_eq!(rejected.len(), 11);
    assert_eq!(
        rejected
            .iter()
            .map(|case| field(case, "reject_case"))
            .collect::<Vec<_>>(),
        [
            "invalid_length_short",
            "invalid_length_long",
            "invalid_magic_precedence",
            "unsupported_coding_precedence",
            "unsupported_crypto_precedence",
            "unsupported_network",
            "nonce_mutation",
            "ciphertext_mutation",
            "tag_mutation",
            "wrong_a2_context",
            "wrong_wallet_context",
        ]
    );
    for case in &rejected {
        assert_eq!(case.len(), 6);
        let _a2 = decode_hex::<32>(field(case, "a2"));
        let _wallet_id = decode_hex::<32>(field(case, "wallet_id"));
        let _capsule = decode_hex_vec(field(case, "capsule"));
        let _sentinel = decode_hex::<32>(field(case, "output_sentinel"));
        let _expected = error(field(case, "expected"));
    }
    assert_eq!(
        rejected
            .iter()
            .map(|case| field(case, "capsule").len() / 2)
            .collect::<Vec<_>>(),
        [66, 68, 67, 67, 67, 67, 67, 67, 67, 67, 67]
    );
}

#[test]
fn all_public_patterns_encrypt_and_decrypt_to_the_exact_capsules() {
    for case in positives() {
        let a2 = decode_hex::<32>(field(&case, "a2"));
        let wallet_id = decode_hex::<32>(field(&case, "wallet_id"));
        let nonce = decode_hex::<12>(field(&case, "nonce"));
        let seed_a = decode_hex::<32>(field(&case, "seed_a"));
        let expected = decode_hex::<67>(field(&case, "capsule"));

        assert_eq!(encrypt(&a2, &wallet_id, &nonce, &seed_a), expected);
        let mut output = [0x5a; 32];
        assert_eq!(decrypt(&a2, &wallet_id, &expected, &mut output), Ok(()));
        assert_eq!(output, seed_a);
    }
}

#[test]
fn structural_rejections_follow_fixture_categories_and_release_nothing() {
    let all = rejections();
    assert_eq!(
        all[..6]
            .iter()
            .map(|case| field(case, "expected"))
            .collect::<Vec<_>>(),
        [
            "InvalidCapsuleLength",
            "InvalidCapsuleLength",
            "InvalidMagic",
            "UnsupportedCodingVersion",
            "UnsupportedCryptoVersion",
            "UnsupportedNetwork",
        ]
    );
    for case in &all[..6] {
        reject_fixture(case);
    }
}

#[test]
fn authenticated_mutations_and_wrong_contexts_release_no_plaintext() {
    let all = rejections();
    assert!(all[6..]
        .iter()
        .all(|case| field(case, "expected") == "AuthenticationFailed"));
    for case in &all[6..] {
        reject_fixture(case);
    }
}
