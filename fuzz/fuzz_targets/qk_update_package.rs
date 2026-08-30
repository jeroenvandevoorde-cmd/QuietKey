#![no_main]

use libfuzzer_sys::fuzz_target;
use qk_update::{
    stage_from_media, verify_staged_fixture_package, verify_staged_package, ArtifactKind,
    MockMediaCandidate, MockMediaFaults, MockReadOnlyMedia, ReleaseVersion, UpdateError,
    UpdatePresence,
};
use std::sync::OnceLock;

const MAX_PRESENTED_BYTES: usize = 4_096;
const MAX_MUTATIONS: usize = 128;
const FIXTURE: &[u8] =
    include_bytes!("../../host/qk-update/tests/fixtures/firmware_package_v1.txt");

static PACKAGE_1_2: OnceLock<Vec<u8>> = OnceLock::new();
static PACKAGE_1_3: OnceLock<Vec<u8>> = OnceLock::new();
static PACKAGE_2_3: OnceLock<Vec<u8>> = OnceLock::new();
static ROTATION_PACKAGE: OnceLock<Vec<u8>> = OnceLock::new();
static HIGH_S_PACKAGE: OnceLock<Vec<u8>> = OnceLock::new();

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Stage {
    Staging,
    Verification,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Policy {
    Fixture,
    Production,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum ControlledCandidate {
    Pristine,
    Rotation,
    HighS,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum ExpectedOutcome {
    Rejected {
        stage: Stage,
        error: UpdateError,
        consumed: bool,
        read_attempts: u8,
    },
    Verified {
        rotation: bool,
    },
}

#[derive(Clone, Debug, Eq, PartialEq)]
enum Outcome {
    Rejected {
        stage: Stage,
        error: UpdateError,
        consumed: bool,
        read_attempts: u8,
    },
    Verified {
        publication_hash: [u8; 32],
        signature_digest: [u8; 32],
        firmware_image_sha256: [u8; 32],
        firmware_image_length: usize,
        version: ReleaseVersion,
        source_commit: [u8; 20],
        signing_keyset_id: [u8; 32],
        target_keyset_id: [u8; 32],
        artifacts: Vec<(u8, u32, [u8; 32])>,
        signature_checks: u8,
        consumed: bool,
        read_attempts: u8,
    },
}

fn fixture_value(prefix: &[u8]) -> &'static [u8] {
    FIXTURE
        .split(|byte| *byte == b'\n')
        .find_map(|line| line.strip_prefix(prefix))
        .expect("registered firmware fixture field")
}

fn hex_nibble(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        _ => None,
    }
}

fn decode_hex(encoded: &[u8]) -> Vec<u8> {
    assert_eq!(encoded.len() % 2, 0, "registered fixture hex width");
    encoded
        .chunks_exact(2)
        .map(|pair| {
            let high = hex_nibble(pair[0]).expect("registered fixture high hex");
            let low = hex_nibble(pair[1]).expect("registered fixture low hex");
            (high << 4) | low
        })
        .collect()
}

fn decode_fixed<const N: usize>(prefix: &[u8]) -> [u8; N] {
    decode_hex(fixture_value(prefix))
        .try_into()
        .expect("registered firmware fixture fixed width")
}

fn fixture_package(cell: &'static OnceLock<Vec<u8>>, prefix: &[u8]) -> &'static [u8] {
    cell.get_or_init(|| decode_hex(fixture_value(prefix)))
        .as_slice()
}

fn package_1_2() -> &'static [u8] {
    fixture_package(&PACKAGE_1_2, b"package_roles_1_2_hex: ")
}

fn package_1_3() -> &'static [u8] {
    fixture_package(&PACKAGE_1_3, b"package_roles_1_3_hex: ")
}

fn package_2_3() -> &'static [u8] {
    fixture_package(&PACKAGE_2_3, b"package_roles_2_3_hex: ")
}

fn rotation_package() -> &'static [u8] {
    fixture_package(&ROTATION_PACKAGE, b"rotation_package_hex: ")
}

fn high_s_package() -> &'static [u8] {
    fixture_package(&HIGH_S_PACKAGE, b"high_s_package_hex: ")
}

fn control(data: &[u8], position: usize) -> u8 {
    match data.get(position).copied().unwrap_or(0) {
        byte @ b'0'..=b'9' => byte - b'0',
        byte @ b'a'..=b'f' => byte - b'a' + 10,
        byte => byte,
    }
}

fn mutation_position(high: u8, low: u8, modulus: usize) -> usize {
    ((usize::from(high) << 8) | usize::from(low)) % modulus
}

fn mutate_golden(commands: &[u8]) -> Vec<u8> {
    let mut candidate = package_1_3().to_vec();
    for command in commands.chunks_exact(4).take(MAX_MUTATIONS) {
        let [operation, high, low, value] = command else {
            unreachable!("chunks_exact(4) yields four bytes")
        };
        match operation % 4 {
            0 if !candidate.is_empty() => {
                let position = mutation_position(*high, *low, candidate.len());
                candidate[position] ^= *value | 1;
            }
            1 if !candidate.is_empty() => {
                let position = mutation_position(*high, *low, candidate.len());
                candidate[position] = *value;
            }
            2 if !candidate.is_empty() => {
                let position = mutation_position(*high, *low, candidate.len());
                candidate.remove(position);
            }
            3 if candidate.len() < MAX_PRESENTED_BYTES => {
                let position = mutation_position(*high, *low, candidate.len() + 1);
                candidate.insert(position, *value);
            }
            _ => {}
        }
    }
    candidate
}

fn candidate(data: &[u8]) -> Vec<u8> {
    let payload = data.get(6..).unwrap_or_default();
    match control(data, 0) % 8 {
        0 => payload
            .get(..payload.len().min(MAX_PRESENTED_BYTES))
            .unwrap_or_default()
            .to_vec(),
        1 => package_1_3().to_vec(),
        2 => mutate_golden(payload),
        3 => {
            let requested = u16::from_le_bytes([control(data, 4), control(data, 5)]);
            let length = usize::from(requested).min(package_1_3().len());
            package_1_3()[..length].to_vec()
        }
        4 => {
            let mut bytes = package_1_3().to_vec();
            let available = MAX_PRESENTED_BYTES.saturating_sub(bytes.len());
            bytes.extend_from_slice(
                payload
                    .get(..payload.len().min(available))
                    .unwrap_or_default(),
            );
            bytes
        }
        5 => high_s_package().to_vec(),
        6 => rotation_package().to_vec(),
        7 if control(data, 5) & 1 == 0 => package_1_2().to_vec(),
        7 => package_2_3().to_vec(),
        _ => unreachable!("modulo eight is exhaustive"),
    }
}

fn presence(selector: u8) -> UpdatePresence {
    match selector % 4 {
        0 => UpdatePresence::clear(),
        1 => UpdatePresence::new(true, false),
        2 => UpdatePresence::new(false, true),
        3 => UpdatePresence::new(true, true),
        _ => unreachable!("modulo four is exhaustive"),
    }
}

fn floor_and_policy(selector: u8) -> (ReleaseVersion, Policy) {
    match selector % 8 {
        0 => (ReleaseVersion::new(1, 41), Policy::Fixture),
        1 => (ReleaseVersion::new(1, 42), Policy::Fixture),
        2 => (ReleaseVersion::new(1, 43), Policy::Fixture),
        3 => (ReleaseVersion::new(2, 0), Policy::Fixture),
        4 => (ReleaseVersion::new(0, u64::MAX), Policy::Fixture),
        5 => (ReleaseVersion::new(1, 0), Policy::Production),
        6 => (ReleaseVersion::new(1, 41), Policy::Production),
        7 => (ReleaseVersion::new(1, 0), Policy::Fixture),
        _ => unreachable!("modulo eight is exhaustive"),
    }
}

fn controlled_candidate(data: &[u8]) -> Option<ControlledCandidate> {
    match control(data, 0) % 8 {
        1 | 7 => Some(ControlledCandidate::Pristine),
        5 => Some(ControlledCandidate::HighS),
        6 => Some(ControlledCandidate::Rotation),
        0 | 2 | 3 | 4 => None,
        _ => unreachable!("modulo eight is exhaustive"),
    }
}

fn presence_error(selector: u8) -> Option<UpdateError> {
    match selector % 4 {
        0 => None,
        1 | 3 => Some(UpdateError::WalletSessionActive),
        2 => Some(UpdateError::CardPresent),
        _ => unreachable!("modulo four is exhaustive"),
    }
}

fn expected_controlled(data: &[u8]) -> Option<ExpectedOutcome> {
    let candidate = controlled_candidate(data)?;
    if let Some(error) = presence_error(control(data, 2)) {
        return Some(ExpectedOutcome::Rejected {
            stage: Stage::Staging,
            error,
            consumed: false,
            read_attempts: 0,
        });
    }
    let staging_error = match control(data, 1) % 8 {
        0 | 7 => None,
        1 | 3 => Some(UpdateError::UpdateCandidateMissing),
        2 => Some(UpdateError::SecondUpdateCandidate),
        4 => Some(UpdateError::MediaReadFailed),
        5 | 6 => Some(UpdateError::StagingCopyFailed),
        _ => unreachable!("modulo eight is exhaustive"),
    };
    if let Some(error) = staging_error {
        return Some(ExpectedOutcome::Rejected {
            stage: Stage::Staging,
            error,
            consumed: true,
            read_attempts: 1,
        });
    }
    if let Some(error) = presence_error(control(data, 4)) {
        return Some(ExpectedOutcome::Rejected {
            stage: Stage::Verification,
            error,
            consumed: true,
            read_attempts: 1,
        });
    }
    let (_, policy) = floor_and_policy(control(data, 3));
    if policy == Policy::Production {
        return Some(ExpectedOutcome::Rejected {
            stage: Stage::Verification,
            error: UpdateError::TestAnchorInProduction,
            consumed: true,
            read_attempts: 1,
        });
    }
    if candidate == ControlledCandidate::HighS {
        return Some(ExpectedOutcome::Rejected {
            stage: Stage::Verification,
            error: UpdateError::HighSSignature,
            consumed: true,
            read_attempts: 1,
        });
    }
    match control(data, 3) % 8 {
        1 | 2 | 3 => Some(ExpectedOutcome::Rejected {
            stage: Stage::Verification,
            error: UpdateError::NotStrictlyNewer,
            consumed: true,
            read_attempts: 1,
        }),
        0 | 4 | 7 => Some(ExpectedOutcome::Verified {
            rotation: candidate == ControlledCandidate::Rotation,
        }),
        5 | 6 => unreachable!("production policy returned above"),
        _ => unreachable!("modulo eight is exhaustive"),
    }
}

fn assert_controlled_outcome(expected: Option<ExpectedOutcome>, outcome: &Outcome) {
    let Some(expected) = expected else {
        return;
    };
    match (expected, outcome) {
        (
            ExpectedOutcome::Rejected {
                stage: expected_stage,
                error: expected_error,
                consumed: expected_consumed,
                read_attempts: expected_attempts,
            },
            Outcome::Rejected {
                stage,
                error,
                consumed,
                read_attempts,
            },
        ) => {
            assert_eq!(*stage, expected_stage);
            assert_eq!(*error, expected_error);
            assert_eq!(*consumed, expected_consumed);
            assert_eq!(*read_attempts, expected_attempts);
        }
        (
            ExpectedOutcome::Verified {
                rotation: expected_rotation,
            },
            Outcome::Verified {
                signing_keyset_id,
                target_keyset_id,
                consumed,
                read_attempts,
                ..
            },
        ) => {
            assert_eq!(*target_keyset_id != *signing_keyset_id, expected_rotation);
            assert!(*consumed);
            assert_eq!(*read_attempts, 1);
        }
        (expected, actual) => panic!("controlled outcome mismatch: {expected:?} != {actual:?}"),
    }
}

fn media(bytes: Vec<u8>, selector: u8, fault_position: usize) -> MockReadOnlyMedia {
    match selector % 8 {
        0 | 7 => MockReadOnlyMedia::new(vec![MockMediaCandidate::canonical(bytes)]),
        1 => MockReadOnlyMedia::new(Vec::new()),
        2 => MockReadOnlyMedia::new(vec![
            MockMediaCandidate::canonical(bytes.clone()),
            MockMediaCandidate::new("second.qkup", bytes),
        ]),
        3 => MockReadOnlyMedia::new(vec![MockMediaCandidate::new("wrong.qkup", bytes)]),
        4 => MockReadOnlyMedia::with_faults(
            vec![MockMediaCandidate::canonical(bytes)],
            MockMediaFaults::read_failure(),
        ),
        5 | 6 => MockReadOnlyMedia::with_faults(
            vec![MockMediaCandidate::canonical(bytes)],
            MockMediaFaults::copy_failure_after(fault_position),
        ),
        _ => unreachable!("modulo eight is exhaustive"),
    }
}

fn error_text(error: UpdateError) -> &'static str {
    match error {
        UpdateError::WalletSessionActive => "wallet session active",
        UpdateError::CardPresent => "card present",
        UpdateError::MediaAlreadyRead => "update media already read",
        UpdateError::UpdateCandidateMissing => "update candidate missing",
        UpdateError::SecondUpdateCandidate => "second update candidate present",
        UpdateError::MediaReadFailed => "update media read failed",
        UpdateError::StagingAllocationFailed => "staging allocation failed",
        UpdateError::StagingCopyFailed => "staging copy failed",
        UpdateError::PackageLengthOutOfBounds => "package length out of bounds",
        UpdateError::PackageMagicMismatch => "package magic mismatch",
        UpdateError::PackageVersionMismatch => "package version mismatch",
        UpdateError::ManifestLengthFieldMismatch => "manifest length field mismatch",
        UpdateError::ManifestTruncated => "manifest truncated",
        UpdateError::ManifestMagicMismatch => "manifest magic mismatch",
        UpdateError::ManifestSchemaVersionMismatch => "manifest schema version mismatch",
        UpdateError::TargetPlatformMismatch => "target platform mismatch",
        UpdateError::CompatibilityEpochMismatch => "compatibility epoch mismatch",
        UpdateError::ReleaseSequenceZero => "release sequence is zero",
        UpdateError::ArtifactCountMismatch => "artifact count mismatch",
        UpdateError::ArtifactKindMismatch => "artifact kind mismatch",
        UpdateError::FirmwareImageLengthOutOfBounds => "firmware image length out of bounds",
        UpdateError::DetachedArtifactLengthOutOfBounds => "detached artifact length out of bounds",
        UpdateError::CompiledAnchorMalformed => "compiled anchor malformed",
        UpdateError::DuplicateCompiledAnchor => "duplicate compiled anchor",
        UpdateError::TestAnchorInProduction => "test anchor present in production",
        UpdateError::SigningKeysetMismatch => "signing key set mismatch",
        UpdateError::SignatureCountMismatch => "signature count mismatch",
        UpdateError::SignatureRoleOutOfRange => "signature role out of range",
        UpdateError::DuplicateSignatureRole => "duplicate signature role",
        UpdateError::SignatureRoleNotAscending => "signature roles not ascending",
        UpdateError::SignatureLengthOutOfBounds => "signature length out of bounds",
        UpdateError::SignatureTruncated => "signature truncated",
        UpdateError::MalformedDerSignature => "malformed der signature",
        UpdateError::HighSSignature => "high-s signature",
        UpdateError::FirmwareImageTruncated => "firmware image truncated",
        UpdateError::TrailingByte => "trailing package byte",
        UpdateError::FirmwareImageHashMismatch => "firmware image hash mismatch",
        UpdateError::InvalidSignature => "invalid firmware signature",
        UpdateError::NotStrictlyNewer => "firmware version is not strictly newer",
        UpdateError::InstallerNotStrictlyNewer => "installer version is not strictly newer",
        UpdateError::InstallerKeysetMismatch => "installer key set mismatch",
        UpdateError::InvalidSlotDecision => "invalid slot decision",
        UpdateError::BootReportMismatch => "boot report mismatch",
        UpdateError::BootNotConfirmed => "successful first boot not confirmed",
        UpdateError::InvalidTransition => "invalid update transition",
    }
}

fn assert_named_error(error: UpdateError) {
    assert_eq!(error.to_string(), error_text(error));
}

fn exercise(data: &[u8]) -> Outcome {
    let expected = expected_controlled(data);
    let candidate = candidate(data);
    let media_selector = control(data, 1);
    let candidate_length = candidate.len();
    let fault_position = if candidate_length == 0 {
        0
    } else {
        usize::from(control(data, 5)) % (candidate_length + 1)
    };
    let mut media = media(candidate, media_selector, fault_position);
    let update_presence = presence(control(data, 2));
    let staged = match stage_from_media(&mut media, update_presence) {
        Ok(staged) => staged,
        Err(error) => {
            assert_named_error(error);
            let consumed = media.consumed();
            let read_attempts = media.read_attempts();
            if matches!(
                error,
                UpdateError::WalletSessionActive | UpdateError::CardPresent
            ) {
                assert!(!consumed);
                assert_eq!(read_attempts, 0);
            } else {
                assert!(consumed);
                assert_eq!(read_attempts, 1);
                assert!(matches!(
                    stage_from_media(&mut media, UpdatePresence::clear()),
                    Err(UpdateError::MediaAlreadyRead)
                ));
            }
            let outcome = Outcome::Rejected {
                stage: Stage::Staging,
                error,
                consumed,
                read_attempts,
            };
            assert_controlled_outcome(expected, &outcome);
            return outcome;
        }
    };
    assert!(media.consumed());
    assert_eq!(media.read_attempts(), 1);
    assert_eq!(staged.byte_length(), candidate_length);
    assert!(matches!(
        stage_from_media(&mut media, UpdatePresence::clear()),
        Err(UpdateError::MediaAlreadyRead)
    ));

    let (floor, policy) = floor_and_policy(control(data, 3));
    let verification_presence = presence(control(data, 4));
    let result = match policy {
        Policy::Fixture => verify_staged_fixture_package(staged, floor, verification_presence),
        Policy::Production => verify_staged_package(staged, floor, verification_presence),
    };
    let outcome = match result {
        Err(error) => {
            assert_named_error(error);
            Outcome::Rejected {
                stage: Stage::Verification,
                error,
                consumed: media.consumed(),
                read_attempts: media.read_attempts(),
            }
        }
        Ok(verified) => {
            assert_eq!(policy, Policy::Fixture);
            assert_eq!(verification_presence, UpdatePresence::clear());
            assert_eq!(verified.signature_checks(), 2);
            assert_eq!(verified.manifest().version(), ReleaseVersion::new(1, 42));
            assert_eq!(verified.manifest().artifacts().len(), 6);
            let rotation =
                verified.manifest().target_keyset_id() != verified.manifest().signing_keyset_id();
            let expected_publication = if rotation {
                decode_fixed(b"rotation_publication_hash: ")
            } else {
                decode_fixed(b"publication_hash: ")
            };
            let expected_digest = if rotation {
                decode_fixed(b"rotation_signature_digest: ")
            } else {
                decode_fixed(b"signature_digest: ")
            };
            assert_eq!(verified.publication_hash(), expected_publication);
            assert_eq!(verified.signature_digest(), expected_digest);
            assert_eq!(
                verified.firmware_image_sha256(),
                decode_fixed(b"artifact_1_sha256: ")
            );
            assert_eq!(
                verified.manifest().source_commit(),
                decode_fixed(b"source_commit: ")
            );
            assert_eq!(
                verified.manifest().signing_keyset_id(),
                decode_fixed(b"signing_keyset_id: ")
            );
            assert_eq!(
                verified.manifest().target_keyset_id(),
                if rotation {
                    decode_fixed(b"target_keyset_id_rotation: ")
                } else {
                    decode_fixed(b"target_keyset_id_no_rotation: ")
                }
            );
            assert_eq!(
                verified.firmware_image_length(),
                usize::try_from(verified.manifest().firmware_image().byte_length())
                    .expect("firmware length fits")
            );
            let expected_kinds = [
                ArtifactKind::FirmwareImage,
                ArtifactKind::Sbom,
                ArtifactKind::BuildProvenanceAndToolchain,
                ArtifactKind::SourceArchive,
                ArtifactKind::CardProtocol,
                ArtifactKind::RescueTooling,
            ];
            let artifacts: Vec<_> = verified
                .manifest()
                .artifacts()
                .iter()
                .zip(expected_kinds)
                .map(|(fact, expected)| {
                    assert_eq!(fact.kind(), expected);
                    assert!(fact.byte_length() > 0);
                    (fact.kind().code(), fact.byte_length(), fact.sha256())
                })
                .collect();
            Outcome::Verified {
                publication_hash: verified.publication_hash(),
                signature_digest: verified.signature_digest(),
                firmware_image_sha256: verified.firmware_image_sha256(),
                firmware_image_length: verified.firmware_image_length(),
                version: verified.manifest().version(),
                source_commit: verified.manifest().source_commit(),
                signing_keyset_id: verified.manifest().signing_keyset_id(),
                target_keyset_id: verified.manifest().target_keyset_id(),
                artifacts,
                signature_checks: verified.signature_checks(),
                consumed: media.consumed(),
                read_attempts: media.read_attempts(),
            }
        }
    };
    assert_controlled_outcome(expected, &outcome);
    outcome
}

fuzz_target!(|data: &[u8]| {
    if data.len() > MAX_PRESENTED_BYTES {
        return;
    }
    let first = exercise(data);
    let second = exercise(data);
    assert_eq!(first, second);
});
