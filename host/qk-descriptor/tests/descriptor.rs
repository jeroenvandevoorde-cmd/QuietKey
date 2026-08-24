//! End-to-end tests for the strict paired descriptor profile.

use qk_bip32::{decode_mainnet_xpub, derive_public_child};
use qk_descriptor::{
    derive_change_script, derive_receive_script, parse_descriptor_pair, DescriptorDeriveError,
    DescriptorParseError,
};
use std::collections::BTreeMap;

const PAIRS: &str = include_str!("fixtures/descriptor_pairs.txt");
const NEGATIVES: &str = include_str!("fixtures/descriptor_pair_negatives.txt");
const XPUB_STARTS: [usize; 3] = [41, 180, 319];

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

fn pair_block(name: &str) -> &'static str {
    PAIRS
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

#[test]
fn local_pair_fixture_inventory_wallets_and_scripts_are_exact() {
    assert_eq!(PAIRS.len(), 8_919);
    assert!(PAIRS.ends_with('\n'));
    assert!(!PAIRS.contains('\r'));
    assert_eq!(PAIRS.matches("case: ").count(), 3);
    assert_eq!(PAIRS.matches("derivation: ").count(), 6);

    let golden = pair_block("GOLDEN");
    let receive = field(golden, "receive");
    let change = field(golden, "change");
    assert_eq!(receive.len(), 445);
    assert_eq!(change.len(), 445);
    for index in 0..436 {
        if [153, 292, 431].contains(&index) {
            assert_eq!(receive.as_bytes()[index], b'0');
            assert_eq!(change.as_bytes()[index], b'1');
        } else {
            assert_eq!(receive.as_bytes()[index], change.as_bytes()[index]);
        }
    }
    let pair = parse_descriptor_pair(receive.as_bytes(), change.as_bytes()).unwrap();
    assert_eq!(pair.wallet_id(), hex(field(golden, "wallet_id")));

    let lines: Vec<&str> = golden
        .lines()
        .filter(|line| !line.is_empty() && !line.starts_with('#'))
        .collect();
    assert_eq!(lines.len(), 5 + 6 * 9);
    let derivation_start = lines
        .iter()
        .position(|line| line.starts_with("derivation: "))
        .unwrap();
    for record in lines[derivation_start..].chunks_exact(9) {
        let label = record[0].strip_prefix("derivation: ").unwrap();
        let (side, index) = label.rsplit_once('-').unwrap();
        let index: u32 = index.parse().unwrap();
        let branch = if side == "receive" { 0 } else { 1 };
        let mut role_keys = [[0u8; 33]; 3];
        for role in 0..3 {
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
        for role in 0..3 {
            assert_eq!(
                role_keys[role],
                hex(record[role + 4].split_once(": ").unwrap().1)
            );
        }
        let derived = if side == "receive" {
            derive_receive_script(&pair, index)
        } else {
            derive_change_script(&pair, index)
        }
        .unwrap();
        assert_eq!(
            derived.witness_script,
            hex(record[7].strip_prefix("witness_script: ").unwrap())
        );
        assert_eq!(
            derived.script_pubkey,
            hex(record[8].strip_prefix("script_pubkey: ").unwrap())
        );
    }
}

#[test]
fn equal_fingerprints_are_metadata_and_duplicate_account_nodes_reject() {
    let golden_block = pair_block("GOLDEN");
    let equal_block = pair_block("EQUAL_FINGERPRINT");
    let golden = parse_descriptor_pair(
        field(golden_block, "receive").as_bytes(),
        field(golden_block, "change").as_bytes(),
    )
    .unwrap();
    let equal = parse_descriptor_pair(
        field(equal_block, "receive").as_bytes(),
        field(equal_block, "change").as_bytes(),
    )
    .unwrap();
    assert_eq!(equal.wallet_id(), hex(field(equal_block, "wallet_id")));
    assert_ne!(golden.wallet_id(), equal.wallet_id());
    for index in [0, 1, 0x7fff_ffff] {
        assert_eq!(
            derive_receive_script(&golden, index),
            derive_receive_script(&equal, index)
        );
        assert_eq!(
            derive_change_script(&golden, index),
            derive_change_script(&equal, index)
        );
    }

    let duplicate = pair_block("EQUAL_XPUB");
    assert!(matches!(
        parse_descriptor_pair(
            field(duplicate, "receive").as_bytes(),
            field(duplicate, "change").as_bytes()
        ),
        Err(DescriptorParseError::DuplicateAccountXpub)
    ));
}

#[test]
fn checksum_correct_negative_fixture_is_fully_consumed() {
    assert_eq!(NEGATIVES.len(), 22_900);
    assert!(NEGATIVES.ends_with('\n'));
    assert!(!NEGATIVES.contains('\r'));
    let fields: Vec<&str> = NEGATIVES
        .lines()
        .filter(|line| !line.is_empty() && !line.starts_with('#'))
        .collect();
    assert_eq!(fields.len(), 23 * 4);
    let mut histogram = BTreeMap::new();
    for block in fields.chunks_exact(4) {
        let name = block[0].strip_prefix("case: ").unwrap();
        let receive = block[1].strip_prefix("receive: ").unwrap();
        let change = block[2].strip_prefix("change: ").unwrap();
        let expected = block[3].strip_prefix("expected: ").unwrap();
        assert_eq!(receive.len(), 445, "{name}");
        assert_eq!(change.len(), 445, "{name}");
        assert!(matches!(
            parse_descriptor_pair(receive.as_bytes(), change.as_bytes()),
            Err(error) if error == parse_error(expected)
        ));
        *histogram.entry(expected).or_insert(0usize) += 1;
    }
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
fn lexical_lengths_no_trim_and_stage_precedence_are_fixed() {
    let block = pair_block("GOLDEN");
    let receive = field(block, "receive").as_bytes();
    let change = field(block, "change").as_bytes();
    assert!(matches!(
        parse_descriptor_pair(&receive[..444], change),
        Err(DescriptorParseError::InvalidDescriptorLength)
    ));
    let mut longer = receive.to_vec();
    longer.push(b'x');
    assert!(matches!(
        parse_descriptor_pair(&longer, change),
        Err(DescriptorParseError::InvalidDescriptorLength)
    ));
    assert!(matches!(
        parse_descriptor_pair(&vec![b'x'; 1_000_000], change),
        Err(DescriptorParseError::InvalidDescriptorLength)
    ));
    let mut newline = receive.to_vec();
    newline.push(b'\n');
    assert!(matches!(
        parse_descriptor_pair(&newline, change),
        Err(DescriptorParseError::InvalidDescriptorLength)
    ));

    let mut delimiter = change.to_vec();
    delimiter[436] = b'x';
    let mut mismatch = receive.to_vec();
    mismatch[444] = if mismatch[444] == b'q' { b'p' } else { b'q' };
    assert!(matches!(
        parse_descriptor_pair(&mismatch, &delimiter),
        Err(DescriptorParseError::InvalidChecksumDelimiter)
    ));

    let mut checksum_character = change.to_vec();
    checksum_character[437] = b'#';
    let mut descriptor_character = receive.to_vec();
    descriptor_character[0] = 0xff;
    assert!(matches!(
        parse_descriptor_pair(&descriptor_character, &checksum_character),
        Err(DescriptorParseError::InvalidChecksumCharacter)
    ));
    assert!(matches!(
        parse_descriptor_pair(&mismatch, &descriptor_character),
        Err(DescriptorParseError::InvalidDescriptorCharacter)
    ));
    assert!(matches!(
        parse_descriptor_pair(receive, &mismatch),
        Err(DescriptorParseError::ChecksumMismatch)
    ));
}

#[test]
fn deterministic_borrowed_inputs_and_index_boundary_are_fixed() {
    let block = pair_block("GOLDEN");
    let receive = field(block, "receive").as_bytes().to_vec();
    let change = field(block, "change").as_bytes().to_vec();
    let receive_before = receive.clone();
    let change_before = change.clone();
    let first = parse_descriptor_pair(&receive, &change).unwrap();
    let second = parse_descriptor_pair(&receive, &change).unwrap();
    assert_eq!(first.wallet_id(), second.wallet_id());
    assert_eq!(receive, receive_before);
    assert_eq!(change, change_before);
    for index in [0, 1, 0x7fff_ffff] {
        assert_eq!(
            derive_receive_script(&first, index),
            derive_receive_script(&first, index)
        );
        assert_eq!(
            derive_change_script(&first, index),
            derive_change_script(&first, index)
        );
    }
    for index in [0x8000_0000, u32::MAX] {
        assert_eq!(
            derive_receive_script(&first, index),
            Err(DescriptorDeriveError::HardenedIndex)
        );
        assert_eq!(
            derive_change_script(&first, index),
            Err(DescriptorDeriveError::HardenedIndex)
        );
    }
}

#[test]
fn every_single_byte_value_mutation_is_panic_free() {
    let block = pair_block("GOLDEN");
    let original_receive = field(block, "receive").as_bytes();
    let original_change = field(block, "change").as_bytes();
    for side in 0..2 {
        for offset in 0..445 {
            for value in 0u8..=u8::MAX {
                let mut receive = original_receive.to_vec();
                let mut change = original_change.to_vec();
                if side == 0 {
                    receive[offset] = value;
                } else {
                    change[offset] = value;
                }
                let result = std::panic::catch_unwind(|| {
                    let _ = parse_descriptor_pair(&receive, &change);
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
