//! V2 slice-6 exact public fixture and four-line construction oracles.

#[path = "support/v2_s6.rs"]
mod support;

use qk_host_sim::{WatchOnlyCoordinatorTierV2, WatchOnlyExportErrorV2, BSMS_RECORD_BYTES_V2};
use support::{
    bsms_bytes, field, hex_array, owner, provisioning, sha256, FIXTURE, FIXTURE_BYTES, FIXTURE_LF,
    FIXTURE_SHA256,
};

#[test]
fn fixture_identity_and_public_v2_lineage_are_exact() {
    assert_eq!(FIXTURE.len(), FIXTURE_BYTES);
    assert_eq!(
        FIXTURE.iter().filter(|byte| **byte == b'\n').count(),
        FIXTURE_LF
    );
    assert_eq!(FIXTURE.last(), Some(&b'\n'));
    assert!(!FIXTURE.contains(&b'\r'));
    assert_eq!(sha256(FIXTURE), hex_array::<32>(FIXTURE_SHA256));

    let text = core::str::from_utf8(FIXTURE).expect("fixture ASCII");
    assert!(text.contains("PERMANENTLY NEVER-FUND PUBLIC PRIVATE MATERIAL"));
    assert!(text.contains("this aggregate adds zero new key or authority"));
    assert!(text.contains("Constructor sources, duplicate output"));
    for forbidden in [
        "private_scalar_hex:",
        "private_key_hex:",
        "secret_key_hex:",
        "nonce_scalar_hex:",
        "mnemonic:",
        "bip39_seed:",
    ] {
        assert!(!text.contains(forbidden), "forbidden field {forbidden}");
    }
}

#[test]
fn both_served_tiers_emit_the_exact_two_key_record_and_bound_facts() {
    let expected = bsms_bytes();
    assert_eq!(expected.len(), BSMS_RECORD_BYTES_V2);
    assert_eq!(
        expected.len(),
        field("bsms_length").parse::<usize>().unwrap()
    );
    assert_eq!(sha256(&expected), hex_array::<32>(field("bsms_sha256")));

    let lines: Vec<&[u8]> = expected.split(|byte| *byte == b'\n').collect();
    assert_eq!(lines.len(), 5);
    assert_eq!(lines[0], b"BSMS 1.0");
    assert_eq!(lines[1], field("multipath_descriptor").as_bytes());
    assert_eq!(lines[2], b"No path restrictions");
    assert_eq!(lines[3], field("receive_0_address").as_bytes());
    assert!(lines[4].is_empty());
    assert!(expected.iter().all(u8::is_ascii));
    assert!(!expected.contains(&b'\r'));
    assert!(!expected.contains(&0));
    assert!(!expected.starts_with(&[0xef, 0xbb, 0xbf]));

    for tier in [
        WatchOnlyCoordinatorTierV2::SimpleRecovery,
        WatchOnlyCoordinatorTierV2::Inheritance,
    ] {
        let owner = owner(tier).expect("served v2 coordinator tier");
        assert_eq!(owner.tier(), tier);
        let artifact = owner.artifact();
        assert_eq!(artifact.bytes().as_slice(), expected);
        assert_eq!(artifact.metadata().serialized_len(), BSMS_RECORD_BYTES_V2);
        assert_eq!(artifact.metadata().sha256(), sha256(&expected));
        assert_eq!(
            artifact.metadata().wallet_id(),
            hex_array(field("wallet_id"))
        );
        assert_eq!(
            artifact.metadata().first_receive_address().as_slice(),
            field("receive_0_address").as_bytes()
        );
        assert_eq!(
            artifact.metadata().first_change_address().as_slice(),
            field("change_0_address").as_bytes()
        );
        assert_eq!(artifact.verify_reopened(&expected), Ok(()));
    }
}

#[test]
fn multipath_descriptor_expands_to_both_authoritative_two_key_d_strings() {
    let combined = field("multipath_descriptor");
    assert_eq!(combined.len(), 314);
    assert_eq!(combined.matches("/<0;1>/*").count(), 2);
    assert!(combined.ends_with("#vnpen3f9"));

    let receive_body = combined[..305].replace("/<0;1>/*", "/0/*");
    let change_body = combined[..305].replace("/<0;1>/*", "/1/*");
    assert_eq!(&field("receive_descriptor")[..297], receive_body);
    assert_eq!(&field("change_descriptor")[..297], change_body);
    assert!(field("receive_descriptor").ends_with("#0kuawcud"));
    assert!(field("change_descriptor").ends_with("#k90eqtfc"));

    let artifacts = provisioning();
    assert_eq!(
        artifacts.first_scripts[0],
        hex_array(field("receive_0_script_pubkey"))
    );
    assert_eq!(
        artifacts.first_scripts[1],
        hex_array(field("change_0_script_pubkey"))
    );
}

#[test]
fn quantum_shelter_has_no_v2_descriptor_artifact() {
    assert!(matches!(
        owner(WatchOnlyCoordinatorTierV2::QuantumShelter),
        Err(WatchOnlyExportErrorV2::QuantumShelterDescriptorExport)
    ));
}
