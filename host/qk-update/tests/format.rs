//! QKFM/QKUP v1 constants, parser precedence, trust policy, and errors.

use qk_update::{
    stage_from_media, verify_staged_package, ArtifactKind, CompiledTrust, MockMediaCandidate,
    MockReadOnlyMedia, ReleaseVersion, UpdateError, UpdatePresence, ARTIFACT_COUNT,
    ARTIFACT_RECORD_BYTES, COMPATIBILITY_EPOCH, FINGERPRINT_DOMAIN, KEYSET_DOMAIN, MANIFEST_BYTES,
    MANIFEST_MAGIC, MANIFEST_SCHEMA, MAX_DETACHED_ARTIFACT_BYTES, MAX_FIRMWARE_IMAGE_BYTES,
    MAX_LOW_S_DER_BYTES, MAX_PACKAGE_BYTES, MAX_PACKAGE_ENVELOPE_BYTES, MIN_DER_BYTES,
    MIN_PACKAGE_BYTES, PACKAGE_MAGIC, PACKAGE_VERSION, REGISTERED_TEST_ANCHORS,
    REGISTERED_TEST_FINGERPRINTS, REGISTERED_TEST_KEYSET_ID, SECP256K1_HALF_ORDER,
    SIGNATURE_DOMAIN, TARGET_PLATFORM, UPDATE_FILE_NAME,
};

const MANIFEST_START: usize = 7;
const ARTIFACTS_OFFSET: usize = 106;

fn nibble(byte: u8) -> u8 {
    match byte {
        b'0'..=b'9' => byte - b'0',
        b'a'..=b'f' => byte - b'a' + 10,
        _ => panic!("lowercase hex fixture"),
    }
}

fn hex<const N: usize>(text: &str) -> [u8; N] {
    assert_eq!(text.len(), N * 2, "fixed hex width");
    let mut output = [0u8; N];
    for (slot, pair) in output.iter_mut().zip(text.as_bytes().as_chunks::<2>().0) {
        *slot = (nibble(pair[0]) << 4) | nibble(pair[1]);
    }
    output
}

fn non_test_anchors() -> [[u8; 33]; 3] {
    [
        hex("0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798"),
        hex("02c6047f9441ed7d6d3045406e95c07cd85aebb16b39f7a3c5e5317f19e63c6a9c"),
        hex("02f9308a019258c31049344f85f89d5229b531c845836f99b08601f113bce036f9"),
    ]
}

fn canonical_manifest() -> [u8; MANIFEST_BYTES] {
    let mut manifest = [0u8; MANIFEST_BYTES];
    manifest[..4].copy_from_slice(&MANIFEST_MAGIC);
    manifest[4] = MANIFEST_SCHEMA;
    manifest[5..9].copy_from_slice(&TARGET_PLATFORM);
    manifest[9..13].copy_from_slice(&COMPATIBILITY_EPOCH.to_le_bytes());
    manifest[13..21].copy_from_slice(&1u64.to_le_bytes());
    manifest[21..41].fill(0x11);
    manifest[41..73].copy_from_slice(&REGISTERED_TEST_KEYSET_ID);
    manifest[73..105].fill(0x22);
    manifest[105] = u8::try_from(ARTIFACT_COUNT).expect("artifact count fits");
    for position in 0..ARTIFACT_COUNT {
        let start = ARTIFACTS_OFFSET + position * ARTIFACT_RECORD_BYTES;
        manifest[start] = u8::try_from(position + 1).expect("kind fits");
        manifest[start + 1..start + 5].copy_from_slice(&1u32.to_le_bytes());
        manifest[start + 5..start + ARTIFACT_RECORD_BYTES]
            .fill(u8::try_from(position + 1).expect("hash pattern fits"));
    }
    manifest
}

fn package_with_manifest(manifest: [u8; MANIFEST_BYTES]) -> Vec<u8> {
    let mut package = vec![0u8; MIN_PACKAGE_BYTES];
    package[..4].copy_from_slice(&PACKAGE_MAGIC);
    package[4] = PACKAGE_VERSION;
    package[5..7].copy_from_slice(
        &u16::try_from(MANIFEST_BYTES)
            .expect("manifest length fits")
            .to_le_bytes(),
    );
    package[MANIFEST_START..MANIFEST_START + MANIFEST_BYTES].copy_from_slice(&manifest);
    package
}

fn verification_error(package: Vec<u8>) -> UpdateError {
    let mut media = MockReadOnlyMedia::new(vec![MockMediaCandidate::canonical(package)]);
    let staged = stage_from_media(&mut media, UpdatePresence::clear()).expect("staging succeeds");
    match verify_staged_package(
        staged,
        ReleaseVersion::new(COMPATIBILITY_EPOCH, 0),
        UpdatePresence::clear(),
    ) {
        Ok(_) => panic!("unsigned test package must reject"),
        Err(error) => error,
    }
}

#[test]
fn fixed_wire_constants_and_geometry_are_exact() {
    assert_eq!(MANIFEST_MAGIC, *b"QKFM");
    assert_eq!(MANIFEST_SCHEMA, 1);
    assert_eq!(TARGET_PLATFORM, *b"QKT1");
    assert_eq!(COMPATIBILITY_EPOCH, 1);
    assert_eq!(PACKAGE_MAGIC, *b"QKUP");
    assert_eq!(PACKAGE_VERSION, 1);
    assert_eq!(UPDATE_FILE_NAME, "quietkey-update.qkup");
    assert_eq!(SIGNATURE_DOMAIN, b"QuietKey/FirmwarePackage/v1");
    assert_eq!(KEYSET_DOMAIN, b"QuietKey/FirmwareKeySet/v1");
    assert_eq!(FINGERPRINT_DOMAIN, b"QuietKey/FirmwareAnchorFingerprint/v1");

    assert_eq!(MANIFEST_BYTES, 328);
    assert_eq!(ARTIFACT_RECORD_BYTES, 37);
    assert_eq!(ARTIFACT_COUNT, 6);
    assert_eq!(MANIFEST_BYTES, 106 + ARTIFACT_COUNT * ARTIFACT_RECORD_BYTES);
    assert_eq!(MAX_FIRMWARE_IMAGE_BYTES, 268_435_456);
    assert_eq!(MAX_DETACHED_ARTIFACT_BYTES, 1_073_741_824);
    assert_eq!(MAX_PACKAGE_ENVELOPE_BYTES, 482);
    assert_eq!(MAX_PACKAGE_BYTES, 268_435_938);
    assert_eq!(MIN_PACKAGE_BYTES, 357);
    assert_eq!(MIN_DER_BYTES, 8);
    assert_eq!(MAX_LOW_S_DER_BYTES, 71);
    assert_eq!(
        SECP256K1_HALF_ORDER,
        hex("7fffffffffffffffffffffffffffffff5d576e7357a4501ddfe92f46681b20a0")
    );
}

#[test]
fn artifact_order_and_version_order_are_exact() {
    assert_eq!(
        [
            ArtifactKind::FirmwareImage.code(),
            ArtifactKind::Sbom.code(),
            ArtifactKind::BuildProvenanceAndToolchain.code(),
            ArtifactKind::SourceArchive.code(),
            ArtifactKind::CardProtocol.code(),
            ArtifactKind::RescueTooling.code(),
        ],
        [1, 2, 3, 4, 5, 6]
    );

    let floor = ReleaseVersion::new(1, 9);
    assert_eq!(floor.epoch(), 1);
    assert_eq!(floor.sequence(), 9);
    assert!(ReleaseVersion::new(1, 10) > floor);
    assert!(ReleaseVersion::new(2, 1) > ReleaseVersion::new(1, u64::MAX));
    assert!(ReleaseVersion::new(0, u64::MAX) < ReleaseVersion::new(1, 0));
}

#[test]
fn package_and_manifest_parser_rejection_precedence_is_exact() {
    let mut package = package_with_manifest(canonical_manifest());
    package[0] = b'X';
    package[4] = 2;
    assert_eq!(
        verification_error(package),
        UpdateError::PackageMagicMismatch
    );

    let mut package = package_with_manifest(canonical_manifest());
    package[4] = 2;
    package[5..7].copy_from_slice(&0u16.to_le_bytes());
    assert_eq!(
        verification_error(package),
        UpdateError::PackageVersionMismatch
    );

    let mut package = package_with_manifest(canonical_manifest());
    package[5..7].copy_from_slice(&327u16.to_le_bytes());
    package[MANIFEST_START] = b'X';
    assert_eq!(
        verification_error(package),
        UpdateError::ManifestLengthFieldMismatch
    );

    let cases: &[(usize, u8, UpdateError)] = &[
        (0, b'X', UpdateError::ManifestMagicMismatch),
        (4, 2, UpdateError::ManifestSchemaVersionMismatch),
        (5, b'X', UpdateError::TargetPlatformMismatch),
        (9, 2, UpdateError::CompatibilityEpochMismatch),
        (13, 0, UpdateError::ReleaseSequenceZero),
        (105, 5, UpdateError::ArtifactCountMismatch),
        (ARTIFACTS_OFFSET, 2, UpdateError::ArtifactKindMismatch),
    ];
    for &(manifest_offset, replacement, expected) in cases {
        let mut manifest = canonical_manifest();
        manifest[manifest_offset] = replacement;
        assert_eq!(
            verification_error(package_with_manifest(manifest)),
            expected,
            "manifest offset {manifest_offset}"
        );
    }

    let mut manifest = canonical_manifest();
    manifest[ARTIFACTS_OFFSET + 1..ARTIFACTS_OFFSET + 5].copy_from_slice(&0u32.to_le_bytes());
    assert_eq!(
        verification_error(package_with_manifest(manifest)),
        UpdateError::FirmwareImageLengthOutOfBounds
    );

    let detached = ARTIFACTS_OFFSET + ARTIFACT_RECORD_BYTES;
    let mut manifest = canonical_manifest();
    manifest[detached + 1..detached + 5].copy_from_slice(&0u32.to_le_bytes());
    assert_eq!(
        verification_error(package_with_manifest(manifest)),
        UpdateError::DetachedArtifactLengthOutOfBounds
    );
}

#[test]
fn trust_constructions_and_production_test_anchor_refusal_are_exact() {
    assert_eq!(REGISTERED_TEST_ANCHORS.len(), 3);
    assert_eq!(
        REGISTERED_TEST_FINGERPRINTS,
        [
            hex("6a51296ff5f038195800204284d623c2297df2dd16a3a3815b5dbff59a98bf13"),
            hex("15b6089b82d3ab8affd1cb39b8d00f91b1691c19be70fb20699cd9b74204d45f"),
            hex("7031d4e8a061795a8f8f0f6375ad9287a547577ebdfd7c3a90d56da024c130ac"),
        ]
    );
    assert_eq!(
        REGISTERED_TEST_KEYSET_ID,
        hex("b3a73044f0baac9ba8df8975adba87714d896302586f645531fa308f8f1ee519")
    );

    assert!(matches!(
        CompiledTrust::production(REGISTERED_TEST_ANCHORS),
        Err(UpdateError::TestAnchorInProduction)
    ));
    let [registered, _, _] = REGISTERED_TEST_ANCHORS;
    let [safe1, safe2, safe3] = non_test_anchors();
    assert!(matches!(
        CompiledTrust::production([safe1, registered, safe3]),
        Err(UpdateError::TestAnchorInProduction)
    ));
    assert!(matches!(
        CompiledTrust::production([safe1, safe1, safe3]),
        Err(UpdateError::DuplicateCompiledAnchor)
    ));
    let mut malformed = safe2;
    malformed[0] = 0x04;
    assert!(matches!(
        CompiledTrust::production([safe1, malformed, safe3]),
        Err(UpdateError::CompiledAnchorMalformed)
    ));

    let trust = CompiledTrust::production([safe1, safe2, safe3]).expect("non-test anchors");
    assert_eq!(trust.anchor_bytes(), [safe1, safe2, safe3]);
    assert_eq!(
        trust.fingerprints(),
        [
            hex("50c1f0dd4cbfcc6a80906b98044afd6923f9359565c76bfbb702605a98fe8d57"),
            hex("a10f039cb189c5205dbcb2ef81fbd70709532b6ea5a20f6458ec523f987f9882"),
            hex("00436177877c8160b3a5e3eb29c29b51fdc904262b2f5a3099d791e18658a208"),
        ]
    );
    assert_eq!(
        trust.keyset_id(),
        hex("b12a02f523dc7efd6344179497acf9337932542d07a8952edec8dac19578b03c")
    );

    let valid_manifest_package = package_with_manifest(canonical_manifest());
    assert_eq!(
        verification_error(valid_manifest_package),
        UpdateError::TestAnchorInProduction,
        "production refusal precedes signature parsing"
    );
}

#[test]
fn every_named_error_has_stable_text() {
    let cases = [
        (UpdateError::WalletSessionActive, "wallet session active"),
        (UpdateError::CardPresent, "card present"),
        (UpdateError::MediaAlreadyRead, "update media already read"),
        (
            UpdateError::UpdateCandidateMissing,
            "update candidate missing",
        ),
        (
            UpdateError::SecondUpdateCandidate,
            "second update candidate present",
        ),
        (UpdateError::MediaReadFailed, "update media read failed"),
        (
            UpdateError::StagingAllocationFailed,
            "staging allocation failed",
        ),
        (UpdateError::StagingCopyFailed, "staging copy failed"),
        (
            UpdateError::PackageLengthOutOfBounds,
            "package length out of bounds",
        ),
        (UpdateError::PackageMagicMismatch, "package magic mismatch"),
        (
            UpdateError::PackageVersionMismatch,
            "package version mismatch",
        ),
        (
            UpdateError::ManifestLengthFieldMismatch,
            "manifest length field mismatch",
        ),
        (UpdateError::ManifestTruncated, "manifest truncated"),
        (
            UpdateError::ManifestMagicMismatch,
            "manifest magic mismatch",
        ),
        (
            UpdateError::ManifestSchemaVersionMismatch,
            "manifest schema version mismatch",
        ),
        (
            UpdateError::TargetPlatformMismatch,
            "target platform mismatch",
        ),
        (
            UpdateError::CompatibilityEpochMismatch,
            "compatibility epoch mismatch",
        ),
        (UpdateError::ReleaseSequenceZero, "release sequence is zero"),
        (
            UpdateError::ArtifactCountMismatch,
            "artifact count mismatch",
        ),
        (UpdateError::ArtifactKindMismatch, "artifact kind mismatch"),
        (
            UpdateError::FirmwareImageLengthOutOfBounds,
            "firmware image length out of bounds",
        ),
        (
            UpdateError::DetachedArtifactLengthOutOfBounds,
            "detached artifact length out of bounds",
        ),
        (
            UpdateError::CompiledAnchorMalformed,
            "compiled anchor malformed",
        ),
        (
            UpdateError::DuplicateCompiledAnchor,
            "duplicate compiled anchor",
        ),
        (
            UpdateError::TestAnchorInProduction,
            "test anchor present in production",
        ),
        (
            UpdateError::SigningKeysetMismatch,
            "signing key set mismatch",
        ),
        (
            UpdateError::SignatureCountMismatch,
            "signature count mismatch",
        ),
        (
            UpdateError::SignatureRoleOutOfRange,
            "signature role out of range",
        ),
        (
            UpdateError::DuplicateSignatureRole,
            "duplicate signature role",
        ),
        (
            UpdateError::SignatureRoleNotAscending,
            "signature roles not ascending",
        ),
        (
            UpdateError::SignatureLengthOutOfBounds,
            "signature length out of bounds",
        ),
        (UpdateError::SignatureTruncated, "signature truncated"),
        (
            UpdateError::MalformedDerSignature,
            "malformed der signature",
        ),
        (UpdateError::HighSSignature, "high-s signature"),
        (
            UpdateError::FirmwareImageTruncated,
            "firmware image truncated",
        ),
        (UpdateError::TrailingByte, "trailing package byte"),
        (
            UpdateError::FirmwareImageHashMismatch,
            "firmware image hash mismatch",
        ),
        (UpdateError::InvalidSignature, "invalid firmware signature"),
        (
            UpdateError::NotStrictlyNewer,
            "firmware version is not strictly newer",
        ),
        (
            UpdateError::InstallerNotStrictlyNewer,
            "installer version is not strictly newer",
        ),
        (
            UpdateError::InstallerKeysetMismatch,
            "installer key set mismatch",
        ),
        (UpdateError::InvalidSlotDecision, "invalid slot decision"),
        (UpdateError::BootReportMismatch, "boot report mismatch"),
        (
            UpdateError::BootNotConfirmed,
            "successful first boot not confirmed",
        ),
        (UpdateError::InvalidTransition, "invalid update transition"),
    ];
    assert_eq!(cases.len(), 45, "complete closed vocabulary");
    for (error, expected) in cases {
        assert_eq!(error.to_string(), expected, "{error:?}");
    }
}
