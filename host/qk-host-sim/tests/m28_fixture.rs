//! M28 exact public fixture and four-line construction oracles.

#[path = "support/m28.rs"]
mod support;

use qk_host_sim::{KitTier, WatchOnlyExportError, BSMS_RECORD_BYTES};
use support::{
    bsms_bytes, field, hex_array, owner, provisioning, sha256, FIXTURE, FIXTURE_BYTES, FIXTURE_LF,
    FIXTURE_SHA256,
};

#[test]
fn fixture_identity_and_public_nums_boundary_are_exact() {
    assert_eq!(FIXTURE.len(), FIXTURE_BYTES);
    assert_eq!(
        FIXTURE.iter().filter(|byte| **byte == b'\n').count(),
        FIXTURE_LF
    );
    assert_eq!(FIXTURE.last(), Some(&b'\n'));
    assert!(!FIXTURE.contains(&b'\r'));
    assert_eq!(sha256(FIXTURE), hex_array::<32>(FIXTURE_SHA256));

    let text = core::str::from_utf8(FIXTURE).expect("fixture ASCII");
    assert!(text.contains("PERMANENTLY NEVER-FUND"));
    assert!(text.contains("no known or derivable private counterpart"));
    assert!(text.contains("no M26 authority or output is reused"));
    for forbidden in [
        "private_scalar_hex:",
        "private_key_hex:",
        "secret_key_hex:",
        "nonce_scalar_hex:",
        "mnemonic:",
    ] {
        assert!(!text.contains(forbidden), "forbidden field {forbidden}");
    }
}

#[test]
fn both_served_tiers_emit_the_exact_four_line_record_and_bound_facts() {
    let expected = bsms_bytes();
    assert_eq!(expected.len(), BSMS_RECORD_BYTES);
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

    for tier in [KitTier::SimpleRecovery, KitTier::Inheritance] {
        let owner = owner(tier).expect("served M28 tier");
        assert_eq!(owner.tier(), tier);
        let artifact = owner.artifact();
        assert_eq!(artifact.bytes().as_slice(), expected);
        assert_eq!(artifact.metadata().serialized_len(), BSMS_RECORD_BYTES);
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
fn descriptor_line_expands_to_both_authoritative_d_strings() {
    let combined = field("multipath_descriptor");
    assert_eq!(combined.len(), 457);
    assert_eq!(combined.matches("/<0;1>/*").count(), 3);
    assert!(combined.ends_with("#p6vh0ugf"));

    let receive_body = combined[..448].replace("/<0;1>/*", "/0/*");
    let change_body = combined[..448].replace("/<0;1>/*", "/1/*");
    assert_eq!(&field("receive_descriptor")[..436], receive_body);
    assert_eq!(&field("change_descriptor")[..436], change_body);
    assert!(field("receive_descriptor").ends_with("#jngv6ayj"));
    assert!(field("change_descriptor").ends_with("#hxrkym56"));

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
fn quantum_shelter_has_no_descriptor_artifact() {
    assert!(matches!(
        owner(KitTier::QuantumShelter),
        Err(WatchOnlyExportError::QuantumShelterDescriptorExport)
    ));
}
