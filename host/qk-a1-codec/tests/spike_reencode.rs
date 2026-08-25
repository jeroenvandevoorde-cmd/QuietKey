//! M18 exact current-capsule re-encode corpus and legacy calibration labels.

use qk_a1_codec::{decode, encode, CodecProfile, DecodeReport};
use std::collections::{BTreeMap, BTreeSet};

#[path = "../../qk-a1/src/sha256.rs"]
mod fixture_sha256;

const FIXTURE: &str = include_str!("fixtures/spike_reencode.txt");
const CAPTURE_MANIFEST: &str = include_str!("../../../docs/evidence/M17-A1-SPIKE-CAPTURES.sha256");
const FIXTURE_SHA256: [u8; 32] = [
    0x83, 0x9c, 0xd6, 0xfc, 0x01, 0x6b, 0xcb, 0xc4, 0x7e, 0xb0, 0x2b, 0x4e, 0x99, 0xf4, 0x83, 0x7e,
    0xe5, 0x2c, 0x3c, 0xfe, 0xea, 0x4d, 0xf4, 0x4a, 0x9b, 0x1e, 0x68, 0xfa, 0x2a, 0xda, 0xc9, 0x70,
];
const CAPTURE_MANIFEST_SHA256: [u8; 32] = [
    0xb3, 0x2c, 0xb2, 0x52, 0x41, 0x20, 0x99, 0xf3, 0x39, 0x50, 0xe6, 0x3c, 0x56, 0xae, 0x2c, 0xa9,
    0x86, 0xe7, 0x52, 0xcc, 0xab, 0x8c, 0x36, 0xdf, 0x37, 0x32, 0x15, 0xd2, 0xa2, 0x3f, 0xc6, 0xd1,
];
const HEADER: [u8; 7] = [0x51, 0x4b, 0x41, 0x31, 0x01, 0x01, 0x01];
const ALPHABET: &[u8; 32] = b"23456789abcdefghijkmnpqrstuvwxyz";
const GOLDEN_WALLET_ID_HEX: &str =
    "a79890dcde9c8517ad860ab3a907ff01652bbe200a561028ceb66e22e8c9d543";

type Fields = BTreeMap<String, String>;

fn blocks(marker: &str) -> Vec<Fields> {
    FIXTURE
        .split("\n\n")
        .filter(|block| block.lines().any(|line| line.starts_with(marker)))
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

fn payloads() -> Vec<Fields> {
    blocks("payload=")
}

fn instances() -> Vec<Fields> {
    blocks("instance=")
}

fn header_field(name: &str) -> &str {
    let prefix = format!("# {name}=");
    FIXTURE
        .lines()
        .take_while(|line| !line.starts_with("payload="))
        .find_map(|line| line.strip_prefix(&prefix))
        .expect("fixture header field")
}

fn field<'a>(fields: &'a Fields, name: &str) -> &'a str {
    fields.get(name).map(String::as_str).expect("fixture field")
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

fn profile(name: &str) -> (CodecProfile, usize, usize, usize) {
    match name {
        "Rs72_60" => (CodecProfile::Rs72_60, 12, 116, 4),
        "Rs76_60" => (CodecProfile::Rs76_60, 16, 122, 2),
        "Rs80_60" => (CodecProfile::Rs80_60, 20, 128, 0),
        _ => panic!("closed fixture profile"),
    }
}

fn capture_manifest_entries() -> Vec<(String, String)> {
    CAPTURE_MANIFEST
        .lines()
        .filter(|line| !line.starts_with('#') && !line.is_empty())
        .map(|line| {
            let (hash, path) = line.split_once("  ").expect("capture manifest separator");
            assert_eq!(hash.len(), 64);
            assert!(path.starts_with("captures/"));
            assert!(path.ends_with(".jpeg"));
            (hash.to_owned(), path.to_owned())
        })
        .collect()
}

fn expected_false_pairs() -> BTreeSet<String> {
    [
        "captures/baseline-0-dim-S01.jpeg:T0",
        "captures/baseline-0-dim-S01.jpeg:T1",
        "captures/baseline-0-dim-S01.jpeg:T4",
        "captures/baseline-0-glare-S02.jpeg:T2",
        "captures/coffee-2-std-S04.jpeg:T1",
        "captures/coffee-2-std-S04.jpeg:T4",
        "captures/crumple-1-std-S21.jpeg:T0",
        "captures/crumple-1-std-S21.jpeg:T4",
        "captures/crumple-2-std-S22.jpeg:T1",
        "captures/crumple-2-std-S22.jpeg:T2",
        "captures/crumple-2-std-S22.jpeg:T3",
        "captures/crumple-2-std-S22.jpeg:T4",
        "captures/fold-3-std-S20.jpeg:T1",
        "captures/water-2-std-S07.jpeg:T3",
        "captures/water-2-std-S07.jpeg:T4",
        "captures/water-3-std-S08.jpeg:T1",
        "captures/water-3-std-S08.jpeg:T2",
    ]
    .into_iter()
    .map(str::to_owned)
    .collect()
}

#[test]
fn fixture_inventory_hashes_sources_and_boundaries_are_exact() {
    assert_eq!(FIXTURE.len(), 133_374);
    assert_eq!(FIXTURE.lines().count(), 2_912);
    assert_eq!(fixture_sha256::sha256(FIXTURE.as_bytes()), FIXTURE_SHA256);
    assert!(FIXTURE.ends_with('\n'));
    assert!(!FIXTURE.contains('\r'));
    assert_eq!(CAPTURE_MANIFEST.len(), 4_061);
    assert_eq!(CAPTURE_MANIFEST.lines().count(), 49);
    assert_eq!(
        fixture_sha256::sha256(CAPTURE_MANIFEST.as_bytes()),
        CAPTURE_MANIFEST_SHA256
    );
    assert_eq!(capture_manifest_entries().len(), 29);

    for (name, value) in [
        ("current_capsule_count", "6"),
        ("payload_count", "18"),
        ("capture_record_count", "29"),
        ("verdict_capture_count", "27"),
        ("locate_capture_count", "2"),
        ("legacy_instance_count", "137"),
        ("legacy_verdict_instance_count", "135"),
        ("legacy_verdict_ok_count", "118"),
        ("legacy_verdict_not_ok_count", "17"),
        ("legacy_locate_instance_count", "2"),
        ("legacy_locate_ok_count", "2"),
        ("legacy_locate_not_ok_count", "0"),
        ("legacy_total_ok_count", "120"),
        ("legacy_total_not_ok_count", "17"),
        ("physical_capture_count_with_ratified_alphabet", "0"),
        ("physical_decode_outcome_count", "0"),
        ("retry_bound", "OPEN under OD-04"),
        ("retry_order", "UNDEFINED"),
    ] {
        assert_eq!(header_field(name), value, "header {name}");
    }
    assert_eq!(
        header_field("source_tokens_json_sha256"),
        "241c6eb7accd7d1a68c1991563b74e0875382ec0f935615a2445c12edf5ec9d1"
    );
    assert_eq!(
        header_field("source_verdict_json_sha256"),
        "b6063a2cd6b7b773abce57fe80916841381f2b3a2c9afdd1bec6323833040fd4"
    );
    assert_eq!(
        header_field("source_locate_json_sha256"),
        "58c551bf23d72c85a45ba17c2c334fdf746a73c2efdd7ad5c808440ae4465661"
    );
    assert_eq!(
        header_field("source_capture_manifest_sha256"),
        "b32cb252412099f33950e63c56ae2ca986e752ccab8c36df373215d2a23fc6d1"
    );
    assert!(header_field("legacy_boundary").contains("49-byte legacy"));
    assert!(header_field("legacy_boundary").contains("not padded or relabelled"));
    assert!(header_field("legacy_label_boundary").contains("historical reader outcomes only"));
    assert!(
        header_field("calibration_boundary").contains("do not contain these fresh current tokens")
    );
    assert!(header_field("page_recovery_probability").starts_with("NOT COMPUTABLE"));
    assert_eq!(
        FIXTURE
            .lines()
            .filter(|line| line.starts_with("payload="))
            .count(),
        18
    );
    assert_eq!(
        FIXTURE
            .lines()
            .filter(|line| line.starts_with("instance="))
            .count(),
        137
    );
}

#[test]
fn all_eighteen_constructed_payloads_match_public_codec_bytes() {
    let all = payloads();
    assert_eq!(all.len(), 18);

    for (index, fields) in all.iter().enumerate() {
        assert_eq!(fields.len(), 27);
        assert_eq!(field(fields, "payload"), format!("{index:02}"));
        let expected_token_id = format!("T{}", index / 3);
        assert_eq!(field(fields, "token_id"), expected_token_id);
        let expected_profile = ["Rs72_60", "Rs76_60", "Rs80_60"][index % 3];
        assert_eq!(field(fields, "profile"), expected_profile);
        assert_eq!(
            field(fields, "payload_id"),
            format!("{expected_token_id}-{expected_profile}")
        );

        let (profile, parity_count, symbol_count, pad_bits) = profile(expected_profile);
        let seed_a = decode_hex::<32>(field(fields, "public_seed_a_hex"));
        let a2 = decode_hex::<32>(field(fields, "public_a2_hex"));
        let nonce = decode_hex::<12>(field(fields, "public_nonce_hex"));
        let wallet_id = decode_hex::<32>(field(fields, "wallet_id_hex"));
        let header = decode_hex::<7>(field(fields, "header_hex"));
        let aad = decode_hex::<39>(field(fields, "aad_hex"));
        let document_key = decode_hex::<32>(field(fields, "document_key_hex"));
        let ciphertext = decode_hex::<32>(field(fields, "ciphertext_hex"));
        let tag = decode_hex::<16>(field(fields, "tag_hex"));
        let capsule = decode_hex::<67>(field(fields, "capsule_hex"));
        let body = decode_hex::<60>(field(fields, "body_hex"));
        let parity = decode_hex_vec(field(fields, "parity_hex"));
        let codeword = decode_hex_vec(field(fields, "codeword_hex"));
        let reconstructed = decode_hex::<67>(field(fields, "reconstructed_capsule_hex"));
        let token = field(fields, "token_ascii").as_bytes();

        let lineage_index = index / 3;
        let mut expected_seed_a = [0u8; 32];
        let mut expected_a2 = [0u8; 32];
        let mut expected_nonce = [0u8; 12];
        for (offset, byte) in expected_seed_a.iter_mut().enumerate() {
            *byte = 0x10 * (lineage_index as u8 + 1) + offset as u8;
        }
        for (offset, byte) in expected_a2.iter_mut().enumerate() {
            *byte = 0xa0 + 8 * lineage_index as u8 + offset as u8;
        }
        for (offset, byte) in expected_nonce.iter_mut().enumerate() {
            *byte = 0x10 * lineage_index as u8 + offset as u8;
        }
        assert_eq!(seed_a, expected_seed_a);
        assert_eq!(a2, expected_a2);
        assert_eq!(nonce, expected_nonce);
        assert_eq!(wallet_id, decode_hex::<32>(GOLDEN_WALLET_ID_HEX));
        assert_ne!(document_key, [0u8; 32]);

        let first_profile = &all[lineage_index * 3];
        for name in [
            "public_seed_a_hex",
            "public_a2_hex",
            "public_nonce_hex",
            "wallet_id_hex",
            "document_key_hex",
            "ciphertext_hex",
            "tag_hex",
            "capsule_hex",
        ] {
            assert_eq!(field(fields, name), field(first_profile, name));
        }
        assert_eq!(header, HEADER);
        assert_eq!(&aad[..7], &header);
        assert_eq!(&aad[7..], &wallet_id);
        assert_eq!(&capsule[..7], &header);
        assert_eq!(&capsule[7..19], &nonce);
        assert_eq!(&capsule[19..51], &ciphertext);
        assert_eq!(&capsule[51..], &tag);
        assert_eq!(&capsule[7..], &body);
        assert_eq!(parity.len(), parity_count);
        assert_eq!(codeword.len(), 60 + parity_count);
        assert_eq!(&codeword[..60], &body);
        assert_eq!(&codeword[60..], &parity);
        assert_eq!(reconstructed, capsule);
        assert_eq!(field(fields, "parity_bytes"), parity_count.to_string());
        assert_eq!(field(fields, "token_length"), symbol_count.to_string());
        assert_eq!(field(fields, "pad_bits"), pad_bits.to_string());
        assert_eq!(token.len(), symbol_count);
        assert!(token.iter().all(|symbol| ALPHABET.contains(symbol)));

        assert_eq!(
            fixture_sha256::sha256(&capsule),
            decode_hex::<32>(field(fields, "capsule_sha256"))
        );
        assert_eq!(
            fixture_sha256::sha256(&body),
            decode_hex::<32>(field(fields, "body_sha256"))
        );
        assert_eq!(
            fixture_sha256::sha256(&codeword),
            decode_hex::<32>(field(fields, "codeword_sha256"))
        );
        assert_eq!(
            fixture_sha256::sha256(token),
            decode_hex::<32>(field(fields, "token_sha256"))
        );
        assert_eq!(
            fixture_sha256::sha256(&reconstructed),
            decode_hex::<32>(field(fields, "reconstructed_capsule_sha256"))
        );

        let mut encoded = [0xa5; 128];
        encode(profile, &capsule, &mut encoded[..symbol_count]).unwrap();
        assert_eq!(&encoded[..symbol_count], token);
        assert!(encoded[symbol_count..].iter().all(|byte| *byte == 0xa5));

        let erasures = [0u8; 128];
        let mut decoded = [0xa5; 67];
        assert_eq!(
            decode(profile, token, &erasures[..symbol_count], &mut decoded,),
            Ok(DecodeReport {
                corrected_errors: 0,
                erased_bytes: 0,
            })
        );
        assert_eq!(decoded, capsule);
    }
}

#[test]
fn all_137_legacy_labels_map_to_exact_current_payloads_and_capture_hashes() {
    let all_payloads = payloads();
    let payload_hashes: BTreeMap<&str, &str> = all_payloads
        .iter()
        .map(|fields| (field(fields, "payload_id"), field(fields, "token_sha256")))
        .collect();
    assert_eq!(payload_hashes.len(), 18);

    let manifest = capture_manifest_entries();
    let mut expected = Vec::new();
    for (ordinal, (capture_hash, capture_path)) in manifest.iter().enumerate() {
        let token_ids: &[&str] = if capture_path.contains("/locate-") {
            &["T5"]
        } else {
            &["T0", "T1", "T2", "T3", "T4"]
        };
        for token_id in token_ids {
            expected.push((
                ordinal,
                capture_hash.as_str(),
                capture_path.as_str(),
                *token_id,
            ));
        }
    }
    assert_eq!(expected.len(), 137);

    let false_expected = expected_false_pairs();
    assert_eq!(false_expected.len(), 17);
    let mut false_observed = BTreeSet::new();
    let mut verdict_instances = 0usize;
    let mut locate_instances = 0usize;
    let mut true_count = 0usize;
    let mut false_count = 0usize;

    let all_instances = instances();
    assert_eq!(all_instances.len(), 137);
    for (index, (fields, (ordinal, capture_hash, capture_path, token_id))) in
        all_instances.iter().zip(expected).enumerate()
    {
        assert_eq!(fields.len(), 16);
        assert_eq!(field(fields, "instance"), format!("{index:03}"));
        assert_eq!(field(fields, "capture_ordinal"), format!("{ordinal:02}"));
        assert_eq!(field(fields, "capture_path"), capture_path);
        assert_eq!(field(fields, "capture_sha256"), capture_hash);
        assert_eq!(field(fields, "legacy_token_id"), token_id);
        assert_eq!(field(fields, "current_lineage_id"), token_id);
        let sample_start = capture_path.len() - "S00.jpeg".len();
        assert_eq!(
            field(fields, "sample_id"),
            &capture_path[sample_start..sample_start + 3]
        );

        let is_locate = capture_path.contains("/locate-");
        let (source, source_hash) = if is_locate {
            locate_instances += 1;
            (
                "locate_results.json",
                "58c551bf23d72c85a45ba17c2c334fdf746a73c2efdd7ad5c808440ae4465661",
            )
        } else {
            verdict_instances += 1;
            (
                "verdict_tokens.json",
                "b6063a2cd6b7b773abce57fe80916841381f2b3a2c9afdd1bec6323833040fd4",
            )
        };
        assert_eq!(field(fields, "legacy_source"), source);
        assert_eq!(field(fields, "legacy_source_sha256"), source_hash);

        let pair = format!("{capture_path}:{token_id}");
        let expected_ok = !false_expected.contains(&pair);
        assert_eq!(field(fields, "legacy_ok"), expected_ok.to_string());
        if expected_ok {
            true_count += 1;
        } else {
            false_count += 1;
            assert!(false_observed.insert(pair));
        }

        for (prefix, profile_name) in [
            ("rs72", "Rs72_60"),
            ("rs76", "Rs76_60"),
            ("rs80", "Rs80_60"),
        ] {
            let payload_id = format!("{token_id}-{profile_name}");
            assert_eq!(field(fields, &format!("{prefix}_payload_id")), payload_id);
            assert_eq!(
                field(fields, &format!("{prefix}_token_sha256")),
                payload_hashes[payload_id.as_str()]
            );
        }
    }

    assert_eq!(verdict_instances, 135);
    assert_eq!(locate_instances, 2);
    assert_eq!(true_count, 120);
    assert_eq!(false_count, 17);
    assert_eq!(false_observed, false_expected);
}
