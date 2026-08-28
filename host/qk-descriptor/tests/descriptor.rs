//! End-to-end tests for the strict paired descriptor profiles.

use qk_bip32::{decode_mainnet_xpub, derive_public_child};
use qk_descriptor::{
    derive_change_script_v2, derive_receive_script, derive_receive_script_v2,
    parse_descriptor_pair, parse_descriptor_pair_v2, DerivedScript, DerivedScriptV2,
    DescriptorDeriveError, DescriptorPair, DescriptorPairV2, DescriptorParseError,
};
use std::collections::{BTreeMap, BTreeSet};

#[path = "../src/sha256.rs"]
mod fixture_sha256;

const PAIRS: &str = include_str!("fixtures/descriptor_pairs.txt");
const PAIRS_V1: &str = include_str!("../../qk-psbt/tests/fixtures/descriptor_pairs_v1.txt");
const NEGATIVES: &str = include_str!("fixtures/descriptor_pair_negatives.txt");
const BIP67: &str = include_str!("fixtures/bip67_sort_vectors.txt");
const XPUB_KATS: &str = include_str!("../../qk-bip32/tests/fixtures/xpub_vectors.txt");
const CKDPUB_KATS: &str = include_str!("../../qk-bip32/tests/fixtures/ckdpub_vectors.txt");
const M24_SIGNING: &str = include_str!("../../qk-host-sim/tests/fixtures/m24_signing.txt");
const M25_EXPORT: &str = include_str!("../../qk-host-sim/tests/fixtures/m25_export.txt");
const SIGNATURE_INSERTION: &str =
    include_str!("../../qk-host-sim/tests/fixtures/signature_insertion.txt");
const M26_PROVISIONING: &str =
    include_str!("../../qk-provisioning/tests/fixtures/m26_provisioning_e2e.txt");
const BIP143_KATS: &str = include_str!("../../qk-psbt/tests/fixtures/bip143-public-kats.txt");
const DESCRIPTOR_OWNERSHIP: &str =
    include_str!("../../qk-psbt/tests/fixtures/descriptor_ownership.txt");
const M24_SECP_BOUNDARY: &str =
    include_str!("../../qk-secp/tests/fixtures/m24_signing_boundary.txt");

const XPUB_STARTS: [usize; 2] = [41, 180];
const BRANCH_POSITIONS: [usize; 2] = [153, 292];
const LEGACY_BIP67_PUBLIC_KEYS: [&str; 6] = [
    "021f2f6e1e50cb6a953935c3601284925decd3fd21bc445712576873fb8c6ebc18",
    "022df8750480ad5b26950b25c7ba79d3e37d75f640f8e5d9bcd5b150a0f85014da",
    "02632b12f4ac5b1d1b72b2a3b508c19172de44f6f46bcee50ba33f3f9291e47ed0",
    "027735a29bae7780a9755fae7a1c4374c656ac6a69ea9f3697fda61bb99a4f3e77",
    "02e2cc6bd5f45edd43bebe7cb9b675f0ce9ed3efe613b177588290ad188d11b404",
    "03e3818b65bcc73a7d64064106a859cc1a5a728c4345ff0b641209fba0d90de6e9",
];
const SCREENING_FIXTURES: [&str; 10] = [
    CKDPUB_KATS,
    XPUB_KATS,
    PAIRS_V1,
    M24_SIGNING,
    M25_EXPORT,
    SIGNATURE_INSERTION,
    M26_PROVISIONING,
    BIP143_KATS,
    DESCRIPTOR_OWNERSHIP,
    M24_SECP_BOUNDARY,
];

fn field<'a>(block: &'a str, name: &str) -> &'a str {
    let prefix = format!("{name}: ");
    block
        .lines()
        .find_map(|line| line.strip_prefix(&prefix))
        .expect("fixture field")
}

fn hex<const N: usize>(value: &str) -> [u8; N] {
    assert_eq!(value.len(), N * 2);
    let mut output = [0u8; N];
    for (slot, pair) in output.iter_mut().zip(value.as_bytes().chunks_exact(2)) {
        *slot = u8::from_str_radix(core::str::from_utf8(pair).unwrap(), 16).unwrap();
    }
    output
}

fn pair_block(fixture: &'static str, name: &str) -> &'static str {
    fixture
        .split("\n\n")
        .find(|block| block.contains(&format!("case: {name}\n")))
        .expect("named pair fixture")
}

fn parse_error(value: &str) -> DescriptorParseError {
    match value {
        "ChecksumMismatch" => DescriptorParseError::ChecksumMismatch,
        "NonCanonicalDescriptor" => DescriptorParseError::NonCanonicalDescriptor,
        "DescriptorPairMismatch" => DescriptorParseError::DescriptorPairMismatch,
        "InvalidAccountXpub" => DescriptorParseError::InvalidAccountXpub,
        "InvalidAccountDepth" => DescriptorParseError::InvalidAccountDepth,
        "InvalidAccountChildNumber" => DescriptorParseError::InvalidAccountChildNumber,
        "DuplicateAccountXpub" => DescriptorParseError::DuplicateAccountXpub,
        _ => panic!("unknown parse error fixture"),
    }
}

fn is_hex_digit(byte: u8) -> bool {
    byte.is_ascii_hexdigit()
}

fn collect_compressed_public_keys(fixture: &str, output: &mut BTreeSet<[u8; 33]>) {
    let bytes = fixture.as_bytes();
    if bytes.len() < 66 {
        return;
    }
    for start in 0..=bytes.len() - 66 {
        let token = &bytes[start..start + 66];
        if token[0] != b'0' || !matches!(token[1], b'2' | b'3') {
            continue;
        }
        if start > 0 && is_hex_digit(bytes[start - 1]) {
            continue;
        }
        if start + 66 < bytes.len() && is_hex_digit(bytes[start + 66]) {
            continue;
        }
        if token.iter().all(|byte| is_hex_digit(*byte)) {
            output.insert(hex(core::str::from_utf8(token).unwrap()));
        }
    }
}

#[test]
fn registered_v2_fixture_bytes_are_exact() {
    for (fixture, byte_count, line_count, digest) in [
        (
            PAIRS,
            6_893,
            72,
            "83aae00d4d780b6475534f99f7590994a67b37c6fcc45ff181e32cba8514f2ba",
        ),
        (
            NEGATIVES,
            17_151,
            128,
            "f3659e62c4050d9fd7f9982636d02d0b8371b8eca33561e29decb3a8e350a814",
        ),
        (
            BIP67,
            2_429,
            29,
            "46803ca1eab135bff85c5760df753bcd838d58cf2045fc0ba6062a14be6fa914",
        ),
    ] {
        assert_eq!(fixture.len(), byte_count);
        assert_eq!(fixture.lines().count(), line_count);
        assert!(fixture.ends_with('\n'));
        assert!(!fixture.contains(['\r', '\0']));
        assert_eq!(
            fixture
                .matches("PERMANENTLY NEVER-FUND PUBLIC PRIVATE MATERIAL")
                .count(),
            1
        );
        assert_eq!(fixture_sha256::sha256(fixture.as_bytes()), hex(digest));
    }
    assert_eq!(BIP67.matches("case: ").count(), 2);
}

#[test]
fn v2_pair_fixture_inventory_wallets_and_scripts_are_exact() {
    assert_eq!(PAIRS.len(), 6_893);
    assert_eq!(PAIRS.lines().count(), 72);
    assert!(PAIRS.ends_with('\n'));
    assert!(!PAIRS.contains('\r'));
    assert_eq!(
        PAIRS
            .matches("PERMANENTLY NEVER-FUND PUBLIC PRIVATE MATERIAL")
            .count(),
        1
    );
    assert_eq!(PAIRS.matches("case: ").count(), 3);
    assert_eq!(PAIRS.matches("derivation: ").count(), 6);

    let golden = pair_block(PAIRS, "GOLDEN");
    let receive = field(golden, "receive");
    let change = field(golden, "change");
    assert_eq!(receive.len(), 306);
    assert_eq!(change.len(), 306);
    for index in 0..297 {
        if BRANCH_POSITIONS.contains(&index) {
            assert_eq!(receive.as_bytes()[index], b'0');
            assert_eq!(change.as_bytes()[index], b'1');
        } else {
            assert_eq!(receive.as_bytes()[index], change.as_bytes()[index]);
        }
    }
    let pair = parse_descriptor_pair_v2(receive.as_bytes(), change.as_bytes()).unwrap();
    assert_eq!(
        pair.origin_fingerprints(),
        [[0x2f, 0xae, 0x97, 0x11], [0x72, 0xa1, 0x4a, 0xb8]]
    );
    assert_eq!(
        pair.wallet_id(),
        hex("d5b7e52f569ae51e7c66af14240d8e4459c6246785ce5c441773995614f60e9e")
    );
    assert_eq!(pair.wallet_id(), hex(field(golden, "wallet_id")));

    let lines: Vec<&str> = golden
        .lines()
        .filter(|line| !line.is_empty() && !line.starts_with('#'))
        .collect();
    assert_eq!(lines.len(), 5 + 6 * 7);
    let derivation_start = lines
        .iter()
        .position(|line| line.starts_with("derivation: "))
        .unwrap();
    let mut route_labels = Vec::new();
    for record in lines[derivation_start..].chunks_exact(7) {
        let label = record[0].strip_prefix("derivation: ").unwrap();
        route_labels.push(label);
        let (side, index) = label.rsplit_once('-').unwrap();
        let index: u32 = index.parse().unwrap();
        let branch = if side == "receive" { 0 } else { 1 };
        let mut role_keys = [[0u8; 33]; 2];
        for role in 0..2 {
            let start = XPUB_STARTS[role];
            let account = decode_mainnet_xpub(&receive.as_bytes()[start..start + 111]).unwrap();
            let branch_node = derive_public_child(&account.public_node, branch).unwrap();
            let child = derive_public_child(&branch_node, index).unwrap();
            role_keys[role] = child.compressed_public_key;
            assert_eq!(
                role_keys[role],
                hex(record[role + 1].split_once(": ").unwrap().1)
            );
        }
        role_keys.sort();
        for role in 0..2 {
            assert_eq!(
                role_keys[role],
                hex(record[role + 3].split_once(": ").unwrap().1)
            );
        }
        let derived = if side == "receive" {
            derive_receive_script_v2(&pair, index)
        } else {
            derive_change_script_v2(&pair, index)
        }
        .unwrap();
        assert_eq!(
            derived.witness_script,
            hex(record[5].strip_prefix("witness_script: ").unwrap())
        );
        assert_eq!(
            derived.script_pubkey,
            hex(record[6].strip_prefix("script_pubkey: ").unwrap())
        );
        assert_eq!(derived.witness_script[0], 0x52);
        assert_eq!(derived.witness_script[1], 0x21);
        assert_eq!(derived.witness_script[35], 0x21);
        assert_eq!(derived.witness_script[69], 0x52);
        assert_eq!(derived.witness_script[70], 0xae);
    }
    assert_eq!(
        route_labels,
        [
            "receive-0",
            "receive-1",
            "receive-2147483647",
            "change-0",
            "change-1",
            "change-2147483647",
        ]
    );
}

#[test]
fn v2_public_lineage_has_exact_fourteen_keys_and_excludes_screened_set() {
    let golden = pair_block(PAIRS, "GOLDEN");
    let receive = field(golden, "receive").as_bytes();
    let authorities = XPUB_STARTS.map(|start| {
        decode_mainnet_xpub(&receive[start..start + 111])
            .unwrap()
            .public_node
            .compressed_public_key
    });
    assert_eq!(
        authorities,
        [
            hex("0261dae51a22707974ee9ad1795b074a8d73d5894e8238f759d0a963f29bf590ee"),
            hex("034be5244dec9c56210ac8efa4c1634dc4a3f4424358a32c8b3175f14f8c920671"),
        ]
    );

    let mut generated = BTreeSet::from(authorities);
    for route in golden.split("derivation: ").skip(1) {
        generated.insert(hex(field(route, "role_a")));
        generated.insert(hex(field(route, "role_b")));
    }
    assert_eq!(generated.len(), 14);

    let mut screened = BTreeSet::new();
    for fixture in SCREENING_FIXTURES {
        collect_compressed_public_keys(fixture, &mut screened);
    }
    for key in LEGACY_BIP67_PUBLIC_KEYS {
        screened.insert(hex(key));
    }
    assert_eq!(screened.len(), 90);
    for key in generated {
        assert!(
            !screened.contains(&key),
            "v2 public key reuses screened material"
        );
    }
}

#[test]
fn v2_equal_fingerprints_are_metadata_and_duplicate_account_nodes_reject() {
    let golden_block = pair_block(PAIRS, "GOLDEN");
    let equal_block = pair_block(PAIRS, "EQUAL_FINGERPRINT");
    let golden = parse_descriptor_pair_v2(
        field(golden_block, "receive").as_bytes(),
        field(golden_block, "change").as_bytes(),
    )
    .unwrap();
    let equal = parse_descriptor_pair_v2(
        field(equal_block, "receive").as_bytes(),
        field(equal_block, "change").as_bytes(),
    )
    .unwrap();
    assert_eq!(equal.wallet_id(), hex(field(equal_block, "wallet_id")));
    assert_ne!(golden.wallet_id(), equal.wallet_id());
    for index in [0, 1, 0x7fff_ffff] {
        assert_eq!(
            derive_receive_script_v2(&golden, index),
            derive_receive_script_v2(&equal, index)
        );
        assert_eq!(
            derive_change_script_v2(&golden, index),
            derive_change_script_v2(&equal, index)
        );
    }

    let duplicate = pair_block(PAIRS, "EQUAL_XPUB");
    assert!(matches!(
        parse_descriptor_pair_v2(
            field(duplicate, "receive").as_bytes(),
            field(duplicate, "change").as_bytes()
        ),
        Err(DescriptorParseError::DuplicateAccountXpub)
    ));
}

#[test]
fn v2_negative_fixture_has_22_checksum_correct_pairs_and_fixed_precedence() {
    assert_eq!(NEGATIVES.len(), 17_151);
    assert_eq!(NEGATIVES.lines().count(), 128);
    assert!(NEGATIVES.ends_with('\n'));
    assert!(!NEGATIVES.contains('\r'));
    assert_eq!(
        NEGATIVES
            .matches("PERMANENTLY NEVER-FUND PUBLIC PRIVATE MATERIAL")
            .count(),
        1
    );
    let fields: Vec<&str> = NEGATIVES
        .lines()
        .filter(|line| !line.is_empty() && !line.starts_with('#'))
        .collect();
    assert_eq!(fields.len(), 23 * 4);
    let mut histogram = BTreeMap::new();
    let mut checksum_correct_pairs = 0usize;
    let mut checksum_mismatch_precedence_pairs = 0usize;
    for block in fields.chunks_exact(4) {
        let name = block[0].strip_prefix("case: ").unwrap();
        let receive = block[1].strip_prefix("receive: ").unwrap();
        let change = block[2].strip_prefix("change: ").unwrap();
        let expected = block[3].strip_prefix("expected: ").unwrap();
        assert_eq!(receive.len(), 306, "{name}");
        assert_eq!(change.len(), 306, "{name}");
        assert!(matches!(
            parse_descriptor_pair_v2(receive.as_bytes(), change.as_bytes()),
            Err(error) if error == parse_error(expected)
        ));
        *histogram.entry(expected).or_insert(0usize) += 1;
        if expected == "ChecksumMismatch" {
            checksum_mismatch_precedence_pairs += 1;
        } else {
            checksum_correct_pairs += 1;
        }
    }
    assert_eq!(checksum_correct_pairs, 22);
    assert_eq!(checksum_mismatch_precedence_pairs, 1);
    assert_eq!(
        histogram,
        BTreeMap::from([
            ("ChecksumMismatch", 1),
            ("DescriptorPairMismatch", 3),
            ("InvalidAccountChildNumber", 2),
            ("InvalidAccountDepth", 2),
            ("InvalidAccountXpub", 2),
            ("NonCanonicalDescriptor", 13),
        ])
    );
}

#[test]
fn v1_and_v2_parser_profiles_are_type_and_length_separated() {
    let v1_block = pair_block(PAIRS_V1, "GOLDEN");
    let v1_receive = field(v1_block, "receive").as_bytes();
    let v1_change = field(v1_block, "change").as_bytes();
    let v2_block = pair_block(PAIRS, "GOLDEN");
    let v2_receive = field(v2_block, "receive").as_bytes();
    let v2_change = field(v2_block, "change").as_bytes();

    let v1_pair: DescriptorPair = parse_descriptor_pair(v1_receive, v1_change).unwrap();
    let v2_pair: DescriptorPairV2 = parse_descriptor_pair_v2(v2_receive, v2_change).unwrap();
    let v1_script: DerivedScript = derive_receive_script(&v1_pair, 0).unwrap();
    let v2_script: DerivedScriptV2 = derive_receive_script_v2(&v2_pair, 0).unwrap();
    assert_eq!(v1_script.witness_script.len(), 105);
    assert_eq!(v2_script.witness_script.len(), 71);
    assert!(matches!(
        parse_descriptor_pair(v2_receive, v2_change),
        Err(DescriptorParseError::InvalidDescriptorLength)
    ));
    assert!(matches!(
        parse_descriptor_pair_v2(v1_receive, v1_change),
        Err(DescriptorParseError::InvalidDescriptorLength)
    ));
}

#[test]
fn v2_lexical_lengths_no_trim_and_stage_precedence_are_fixed() {
    let block = pair_block(PAIRS, "GOLDEN");
    let receive = field(block, "receive").as_bytes();
    let change = field(block, "change").as_bytes();
    assert!(matches!(
        parse_descriptor_pair_v2(&receive[..305], change),
        Err(DescriptorParseError::InvalidDescriptorLength)
    ));
    let mut longer = receive.to_vec();
    longer.push(b'x');
    assert!(matches!(
        parse_descriptor_pair_v2(&longer, change),
        Err(DescriptorParseError::InvalidDescriptorLength)
    ));
    assert!(matches!(
        parse_descriptor_pair_v2(&vec![b'x'; 1_000_000], change),
        Err(DescriptorParseError::InvalidDescriptorLength)
    ));
    let mut newline = receive.to_vec();
    newline.push(b'\n');
    assert!(matches!(
        parse_descriptor_pair_v2(&newline, change),
        Err(DescriptorParseError::InvalidDescriptorLength)
    ));

    let mut delimiter = change.to_vec();
    delimiter[297] = b'x';
    let mut mismatch = receive.to_vec();
    mismatch[305] = if mismatch[305] == b'q' { b'p' } else { b'q' };
    assert!(matches!(
        parse_descriptor_pair_v2(&mismatch, &delimiter),
        Err(DescriptorParseError::InvalidChecksumDelimiter)
    ));

    let mut checksum_character = change.to_vec();
    checksum_character[298] = b'#';
    let mut descriptor_character = receive.to_vec();
    descriptor_character[0] = 0xff;
    assert!(matches!(
        parse_descriptor_pair_v2(&descriptor_character, &checksum_character),
        Err(DescriptorParseError::InvalidChecksumCharacter)
    ));
    assert!(matches!(
        parse_descriptor_pair_v2(&mismatch, &descriptor_character),
        Err(DescriptorParseError::InvalidDescriptorCharacter)
    ));
    assert!(matches!(
        parse_descriptor_pair_v2(receive, &mismatch),
        Err(DescriptorParseError::ChecksumMismatch)
    ));
}

#[test]
fn v2_deterministic_borrowed_inputs_and_index_boundary_are_fixed() {
    let block = pair_block(PAIRS, "GOLDEN");
    let receive = field(block, "receive").as_bytes().to_vec();
    let change = field(block, "change").as_bytes().to_vec();
    let receive_before = receive.clone();
    let change_before = change.clone();
    let first = parse_descriptor_pair_v2(&receive, &change).unwrap();
    let second = parse_descriptor_pair_v2(&receive, &change).unwrap();
    assert_eq!(first.wallet_id(), second.wallet_id());
    assert_eq!(receive, receive_before);
    assert_eq!(change, change_before);
    for index in [0, 1, 0x7fff_ffff] {
        assert_eq!(
            derive_receive_script_v2(&first, index),
            derive_receive_script_v2(&first, index)
        );
        assert_eq!(
            derive_change_script_v2(&first, index),
            derive_change_script_v2(&first, index)
        );
    }
    for index in [0x8000_0000, u32::MAX] {
        assert_eq!(
            derive_receive_script_v2(&first, index),
            Err(DescriptorDeriveError::HardenedIndex)
        );
        assert_eq!(
            derive_change_script_v2(&first, index),
            Err(DescriptorDeriveError::HardenedIndex)
        );
    }
}

#[test]
fn v2_every_single_byte_value_mutation_is_panic_free() {
    let block = pair_block(PAIRS, "GOLDEN");
    let original_receive = field(block, "receive").as_bytes();
    let original_change = field(block, "change").as_bytes();
    for side in 0..2 {
        for offset in 0..306 {
            for value in 0u8..=u8::MAX {
                let mut receive = original_receive.to_vec();
                let mut change = original_change.to_vec();
                if side == 0 {
                    receive[offset] = value;
                } else {
                    change[offset] = value;
                }
                let result = std::panic::catch_unwind(|| {
                    let _ = parse_descriptor_pair_v2(&receive, &change);
                });
                assert!(result.is_ok(), "side={side} offset={offset} value={value}");
            }
        }
    }
}

#[test]
fn error_sets_have_fixed_non_echoing_text() {
    let parse = [
        (
            DescriptorParseError::InvalidDescriptorLength,
            "invalid descriptor length",
        ),
        (
            DescriptorParseError::InvalidChecksumDelimiter,
            "invalid checksum delimiter",
        ),
        (
            DescriptorParseError::InvalidChecksumCharacter,
            "invalid checksum character",
        ),
        (
            DescriptorParseError::InvalidDescriptorCharacter,
            "invalid descriptor character",
        ),
        (
            DescriptorParseError::ChecksumMismatch,
            "descriptor checksum mismatch",
        ),
        (
            DescriptorParseError::NonCanonicalDescriptor,
            "descriptor is not canonical",
        ),
        (
            DescriptorParseError::DescriptorPairMismatch,
            "descriptor pair mismatch",
        ),
        (
            DescriptorParseError::InvalidAccountXpub,
            "invalid account xpub",
        ),
        (
            DescriptorParseError::InvalidAccountDepth,
            "invalid account depth",
        ),
        (
            DescriptorParseError::InvalidAccountChildNumber,
            "invalid account child number",
        ),
        (
            DescriptorParseError::DuplicateAccountXpub,
            "duplicate account xpub",
        ),
        (
            DescriptorParseError::CryptographicBackendInvariant,
            "cryptographic backend invariant",
        ),
    ];
    for (error, text) in parse {
        assert_eq!(error.to_string(), text);
        let as_error: &dyn std::error::Error = &error;
        assert!(as_error.source().is_none());
    }
    let derive = [
        (
            DescriptorDeriveError::HardenedIndex,
            "hardened index rejected",
        ),
        (DescriptorDeriveError::InvalidTweak, "invalid tweak"),
        (DescriptorDeriveError::PointAtInfinity, "point at infinity"),
        (
            DescriptorDeriveError::DuplicateDerivedKey,
            "duplicate derived key",
        ),
        (
            DescriptorDeriveError::InternalInvariant,
            "internal invariant",
        ),
    ];
    for (error, text) in derive {
        assert_eq!(error.to_string(), text);
        let as_error: &dyn std::error::Error = &error;
        assert!(as_error.source().is_none());
    }
}
