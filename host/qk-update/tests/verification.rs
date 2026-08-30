//! Production-policy and hostile-field verification locks for QK-DEC-136.

use qk_update::{
    stage_from_media, verify_staged_package, CompiledTrust, MockMediaCandidate, MockReadOnlyMedia,
    ReleaseVersion, UpdateError, UpdatePresence, REGISTERED_TEST_ANCHORS,
};

const FIXTURE: &str = include_str!("fixtures/firmware_package_v1.txt");
const MANIFEST_START: usize = 7;

fn field(name: &str) -> &str {
    let prefix = format!("{name}: ");
    FIXTURE
        .lines()
        .find_map(|line| line.strip_prefix(&prefix))
        .unwrap_or_else(|| panic!("missing fixture field {name}"))
}

fn package() -> Vec<u8> {
    field("package_roles_1_3_hex")
        .as_bytes()
        .as_chunks::<2>()
        .0
        .iter()
        .map(|pair| {
            let text = core::str::from_utf8(pair).unwrap();
            u8::from_str_radix(text, 16).unwrap()
        })
        .collect()
}

fn production_result(bytes: Vec<u8>) -> Result<qk_update::VerifiedPackage, UpdateError> {
    let mut media = MockReadOnlyMedia::new(vec![MockMediaCandidate::canonical(bytes)]);
    let staged = stage_from_media(&mut media, UpdatePresence::clear()).unwrap();
    verify_staged_package(
        staged,
        REGISTERED_TEST_ANCHORS,
        ReleaseVersion::new(1, 41),
        UpdatePresence::clear(),
    )
}

#[test]
fn valid_public_fixture_is_mechanically_refused_by_production_policy() {
    assert!(matches!(
        production_result(package()),
        Err(UpdateError::TestAnchorInProduction)
    ));
}

#[test]
fn package_header_rejections_precede_compiled_trust() {
    for (offset, value, expected) in [
        (0, b'X', UpdateError::PackageMagicMismatch),
        (4, 2, UpdateError::PackageVersionMismatch),
        (5, 0, UpdateError::ManifestLengthFieldMismatch),
    ] {
        let mut bytes = package();
        bytes[offset] = value;
        assert!(matches!(production_result(bytes), Err(error) if error == expected));
    }
}

#[test]
fn manifest_field_rejections_follow_wire_order() {
    let cases = [
        (0, b'X', UpdateError::ManifestMagicMismatch),
        (4, 2, UpdateError::ManifestSchemaVersionMismatch),
        (5, b'X', UpdateError::TargetPlatformMismatch),
        (9, 2, UpdateError::CompatibilityEpochMismatch),
        (13, 0, UpdateError::ReleaseSequenceZero),
        (105, 5, UpdateError::ArtifactCountMismatch),
        (106, 2, UpdateError::ArtifactKindMismatch),
    ];
    for (relative, value, expected) in cases {
        let mut bytes = package();
        bytes[MANIFEST_START + relative] = value;
        if relative == 13 {
            bytes[MANIFEST_START + 13..MANIFEST_START + 21].fill(0);
        }
        assert!(matches!(production_result(bytes), Err(error) if error == expected));
    }
}

#[test]
fn compiled_anchor_failures_are_distinct_and_ordered() {
    let [role1, role2, role3] = REGISTERED_TEST_ANCHORS;
    assert!(matches!(
        CompiledTrust::production([role1, role1, role3]),
        Err(UpdateError::DuplicateCompiledAnchor)
    ));
    let mut malformed = role2;
    malformed[0] = 4;
    assert!(matches!(
        CompiledTrust::production([role1, malformed, role3]),
        Err(UpdateError::CompiledAnchorMalformed)
    ));
    assert!(matches!(
        CompiledTrust::production([role1, role2, role3]),
        Err(UpdateError::TestAnchorInProduction)
    ));
}
