#![no_main]

use libfuzzer_sys::fuzz_target;
use qk_update::{
    stage_from_media, verify_staged_fixture_package, BootVersionDisplay, CommittedInstallerState,
    FirstBootReport, MockMediaCandidate, MockPrivilegedInstaller, MockReadOnlyMedia,
    ReleaseVersion, SlotId, UpdateError, UpdatePresence, REGISTERED_TEST_KEYSET_ID,
};
use std::sync::OnceLock;

const MAX_PRESENTED_BYTES: usize = 512;
const FIXTURE: &[u8] =
    include_bytes!("../../host/qk-update/tests/fixtures/firmware_package_v1.txt");

static PACKAGE: OnceLock<Vec<u8>> = OnceLock::new();
static ROTATION_PACKAGE: OnceLock<Vec<u8>> = OnceLock::new();

#[derive(Clone, Debug, Eq, PartialEq)]
struct Outcome {
    preparation: Result<SlotId, UpdateError>,
    operations: Vec<ResultTag>,
    committed: CommittedInstallerState,
    has_trial: bool,
    boot_attempts: u32,
    last_display: Option<BootVersionDisplay>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
enum ResultTag {
    Error(UpdateError),
    Display(BootVersionDisplay),
    Committed(CommittedInstallerState),
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum ExpectedOperation {
    Error(UpdateError),
    Display(ReleaseVersion),
    Committed(CommittedInstallerState),
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct ExpectedSuccess {
    operations: Vec<ExpectedOperation>,
    committed: CommittedInstallerState,
    has_trial: bool,
    boot_attempts: u32,
    last_display_version: Option<ReleaseVersion>,
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

fn fixture_package(rotation: bool) -> &'static [u8] {
    if rotation {
        ROTATION_PACKAGE
            .get_or_init(|| decode_hex(fixture_value(b"rotation_package_hex: ")))
            .as_slice()
    } else {
        PACKAGE
            .get_or_init(|| decode_hex(fixture_value(b"package_roles_1_3_hex: ")))
            .as_slice()
    }
}

fn control(data: &[u8], position: usize) -> u8 {
    match data.get(position).copied().unwrap_or(0) {
        byte @ b'0'..=b'9' => byte - b'0',
        byte @ b'a'..=b'f' => byte - b'a' + 10,
        byte => byte,
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

fn presence(selector: u8) -> UpdatePresence {
    match selector % 4 {
        0 => UpdatePresence::clear(),
        1 => UpdatePresence::new(true, false),
        2 => UpdatePresence::new(false, true),
        3 => UpdatePresence::new(true, true),
        _ => unreachable!("modulo four is exhaustive"),
    }
}

fn expected_presence_error(selector: u8) -> Option<UpdateError> {
    match selector % 4 {
        0 => None,
        1 | 3 => Some(UpdateError::WalletSessionActive),
        2 => Some(UpdateError::CardPresent),
        _ => unreachable!("modulo four is exhaustive"),
    }
}

fn verified(rotation: bool) -> qk_update::VerifiedPackage {
    let bytes = fixture_package(rotation).to_vec();
    let mut media = MockReadOnlyMedia::new(vec![MockMediaCandidate::canonical(bytes)]);
    let staged =
        stage_from_media(&mut media, UpdatePresence::clear()).expect("registered package stages");
    assert!(media.consumed());
    assert_eq!(media.read_attempts(), 1);
    let verified =
        verify_staged_fixture_package(staged, ReleaseVersion::new(1, 0), UpdatePresence::clear())
            .expect("registered package verifies");
    assert_eq!(verified.signature_checks(), 2);
    assert_eq!(verified.manifest().version(), ReleaseVersion::new(1, 42));
    verified
}

fn old_floor(selector: u8) -> ReleaseVersion {
    match selector % 5 {
        0 => ReleaseVersion::new(1, 41),
        1 => ReleaseVersion::new(1, 42),
        2 => ReleaseVersion::new(1, 43),
        3 => ReleaseVersion::new(2, 0),
        4 => ReleaseVersion::new(0, u64::MAX),
        _ => unreachable!("modulo five is exhaustive"),
    }
}

fn report(
    slot: SlotId,
    version: ReleaseVersion,
    image: [u8; 32],
    target_keyset: [u8; 32],
    confirmed: bool,
) -> FirstBootReport {
    FirstBootReport::new(slot, version, image, target_keyset, confirmed)
}

fn record<T>(result: Result<T, UpdateError>, map: impl FnOnce(T) -> ResultTag) -> ResultTag {
    match result {
        Ok(value) => map(value),
        Err(error) => {
            assert_named_error(error);
            ResultTag::Error(error)
        }
    }
}

fn assert_display(display: &BootVersionDisplay, expected_version: ReleaseVersion) {
    assert_eq!(display.target(), *b"QKT1");
    assert_eq!(display.version(), expected_version);
    assert_eq!(
        expected_version.sequence().to_string(),
        display.sequence_decimal()
    );
}

fn expected_success(
    scenario: u8,
    original: CommittedInstallerState,
    trial_slot: SlotId,
    candidate_version: ReleaseVersion,
    candidate_image: [u8; 32],
    target_keyset: [u8; 32],
) -> ExpectedSuccess {
    let candidate_committed = CommittedInstallerState::new(
        trial_slot,
        candidate_version,
        target_keyset,
        candidate_image,
    );
    let fallback = ExpectedOperation::Display(original.floor());
    let candidate_display = ExpectedOperation::Display(candidate_version);
    let candidate_commit = ExpectedOperation::Committed(candidate_committed);
    let (operations, committed, boot_attempts, last_display_version) = match scenario {
        0 => (vec![fallback], original, 1, Some(original.floor())),
        1 => (
            vec![
                ExpectedOperation::Error(UpdateError::BootNotConfirmed),
                fallback,
            ],
            original,
            1,
            Some(original.floor()),
        ),
        2 => (
            vec![candidate_display, candidate_commit],
            candidate_committed,
            1,
            Some(candidate_version),
        ),
        3..=6 => (
            vec![
                ExpectedOperation::Error(UpdateError::BootReportMismatch),
                fallback,
            ],
            original,
            2,
            Some(original.floor()),
        ),
        7 => (
            vec![
                ExpectedOperation::Error(UpdateError::BootNotConfirmed),
                ExpectedOperation::Error(UpdateError::InvalidTransition),
                fallback,
            ],
            original,
            2,
            Some(original.floor()),
        ),
        8 => (
            vec![candidate_display, fallback],
            original,
            2,
            Some(original.floor()),
        ),
        9 => (
            vec![
                candidate_display,
                ExpectedOperation::Error(UpdateError::InvalidTransition),
                candidate_commit,
            ],
            candidate_committed,
            1,
            Some(candidate_version),
        ),
        10 => (
            vec![
                ExpectedOperation::Error(UpdateError::WalletSessionActive),
                candidate_display,
                candidate_commit,
            ],
            candidate_committed,
            1,
            Some(candidate_version),
        ),
        11 => (
            vec![
                candidate_display,
                ExpectedOperation::Error(UpdateError::CardPresent),
                candidate_commit,
            ],
            candidate_committed,
            1,
            Some(candidate_version),
        ),
        _ => unreachable!("modulo twelve is exhaustive"),
    };
    ExpectedSuccess {
        operations,
        committed,
        has_trial: false,
        boot_attempts,
        last_display_version,
    }
}

fn assert_success_model(
    operations: &[ResultTag],
    installer: &MockPrivilegedInstaller,
    expected: &ExpectedSuccess,
) {
    assert_eq!(operations.len(), expected.operations.len());
    for (actual, expected_operation) in operations.iter().zip(&expected.operations) {
        match (actual, expected_operation) {
            (ResultTag::Error(actual), ExpectedOperation::Error(expected_error)) => {
                assert_eq!(actual, expected_error);
                assert_named_error(*actual);
            }
            (ResultTag::Display(actual), ExpectedOperation::Display(expected_version)) => {
                assert_display(actual, *expected_version);
            }
            (ResultTag::Committed(actual), ExpectedOperation::Committed(expected_state)) => {
                assert_eq!(actual, expected_state);
            }
            _ => panic!("operation differs from the closed lifecycle model"),
        }
    }
    assert_eq!(installer.committed(), expected.committed);
    assert_eq!(installer.has_trial(), expected.has_trial);
    assert_eq!(installer.boot_attempts(), expected.boot_attempts);
    match (installer.last_display(), expected.last_display_version) {
        (Some(actual), Some(expected_version)) => assert_display(&actual, expected_version),
        (None, None) => {}
        _ => panic!("display state differs from the closed lifecycle model"),
    }
}

fn exercise(data: &[u8]) -> Outcome {
    let rotation = control(data, 0) & 1 != 0;
    let package = verified(rotation);
    let candidate_version = package.manifest().version();
    let candidate_image = package.firmware_image_sha256();
    let target_keyset = package.manifest().target_keyset_id();
    let active_slot = if control(data, 1) & 1 == 0 {
        SlotId::A
    } else {
        SlotId::B
    };
    let floor = old_floor(control(data, 2));
    let wrong_keyset = control(data, 3) & 1 != 0;
    let invalid_slot = control(data, 3) & 2 != 0;
    let committed_keyset = if wrong_keyset {
        [0x5a; 32]
    } else {
        REGISTERED_TEST_KEYSET_ID
    };
    let original = CommittedInstallerState::new(active_slot, floor, committed_keyset, [0xa5; 32]);
    let mut installer = if invalid_slot {
        MockPrivilegedInstaller::with_invalid_slot_fault(original)
    } else {
        MockPrivilegedInstaller::new(original)
    };
    let prepare_presence_selector = control(data, 4);
    let preparation = installer.prepare_trial(package, presence(prepare_presence_selector));

    let expected_prepare = expected_presence_error(prepare_presence_selector).or_else(|| {
        if candidate_version <= floor {
            Some(UpdateError::InstallerNotStrictlyNewer)
        } else if wrong_keyset {
            Some(UpdateError::InstallerKeysetMismatch)
        } else if invalid_slot {
            Some(UpdateError::InvalidSlotDecision)
        } else {
            None
        }
    });
    match (preparation, expected_prepare) {
        (Err(error), Some(expected)) => {
            assert_eq!(error, expected);
            assert_named_error(error);
            assert_eq!(installer.committed(), original);
            assert!(!installer.has_trial());
            assert_eq!(installer.boot_attempts(), 0);
            assert_eq!(installer.last_display(), None);
            Outcome {
                preparation: Err(error),
                operations: Vec::new(),
                committed: installer.committed(),
                has_trial: installer.has_trial(),
                boot_attempts: installer.boot_attempts(),
                last_display: installer.last_display(),
            }
        }
        (Ok(trial_slot), None) => {
            let expected_trial_slot = match active_slot {
                SlotId::A => SlotId::B,
                SlotId::B => SlotId::A,
            };
            assert_eq!(trial_slot, expected_trial_slot);
            assert!(installer.has_trial());
            assert_eq!(installer.committed(), original);
            let good = report(
                trial_slot,
                candidate_version,
                candidate_image,
                target_keyset,
                true,
            );
            let mut operations = Vec::new();
            let scenario = control(data, 5) % 12;
            let expected = expected_success(
                scenario,
                original,
                trial_slot,
                candidate_version,
                candidate_image,
                target_keyset,
            );
            match scenario {
                0 => {
                    let result = installer.fallback_to_committed(UpdatePresence::clear());
                    let tagged = record(result, ResultTag::Display);
                    assert!(matches!(tagged, ResultTag::Display(_)));
                    operations.push(tagged);
                }
                1 => {
                    let result = installer.commit_confirmed_boot(UpdatePresence::clear());
                    let tagged = record(result, ResultTag::Committed);
                    assert_eq!(tagged, ResultTag::Error(UpdateError::BootNotConfirmed));
                    operations.push(tagged);
                    operations.push(record(
                        installer.fallback_to_committed(UpdatePresence::clear()),
                        ResultTag::Display,
                    ));
                }
                2 => {
                    operations.push(record(
                        installer.attempt_first_boot(good, UpdatePresence::clear()),
                        ResultTag::Display,
                    ));
                    operations.push(record(
                        installer.commit_confirmed_boot(UpdatePresence::clear()),
                        ResultTag::Committed,
                    ));
                }
                3 => {
                    let bad = report(
                        active_slot,
                        candidate_version,
                        candidate_image,
                        target_keyset,
                        true,
                    );
                    let tagged = record(
                        installer.attempt_first_boot(bad, UpdatePresence::clear()),
                        ResultTag::Display,
                    );
                    assert_eq!(tagged, ResultTag::Error(UpdateError::BootReportMismatch));
                    operations.push(tagged);
                    operations.push(record(
                        installer.fallback_to_committed(UpdatePresence::clear()),
                        ResultTag::Display,
                    ));
                }
                4 => {
                    let bad = report(
                        trial_slot,
                        ReleaseVersion::new(1, 43),
                        candidate_image,
                        target_keyset,
                        true,
                    );
                    let tagged = record(
                        installer.attempt_first_boot(bad, UpdatePresence::clear()),
                        ResultTag::Display,
                    );
                    assert_eq!(tagged, ResultTag::Error(UpdateError::BootReportMismatch));
                    operations.push(tagged);
                    operations.push(record(
                        installer.fallback_to_committed(UpdatePresence::clear()),
                        ResultTag::Display,
                    ));
                }
                5 => {
                    let bad = report(
                        trial_slot,
                        candidate_version,
                        [0x33; 32],
                        target_keyset,
                        true,
                    );
                    let tagged = record(
                        installer.attempt_first_boot(bad, UpdatePresence::clear()),
                        ResultTag::Display,
                    );
                    assert_eq!(tagged, ResultTag::Error(UpdateError::BootReportMismatch));
                    operations.push(tagged);
                    operations.push(record(
                        installer.fallback_to_committed(UpdatePresence::clear()),
                        ResultTag::Display,
                    ));
                }
                6 => {
                    let bad = report(
                        trial_slot,
                        candidate_version,
                        candidate_image,
                        [0x44; 32],
                        true,
                    );
                    let tagged = record(
                        installer.attempt_first_boot(bad, UpdatePresence::clear()),
                        ResultTag::Display,
                    );
                    assert_eq!(tagged, ResultTag::Error(UpdateError::BootReportMismatch));
                    operations.push(tagged);
                    operations.push(record(
                        installer.fallback_to_committed(UpdatePresence::clear()),
                        ResultTag::Display,
                    ));
                }
                7 => {
                    let unconfirmed = report(
                        trial_slot,
                        candidate_version,
                        candidate_image,
                        target_keyset,
                        false,
                    );
                    let first = record(
                        installer.attempt_first_boot(unconfirmed, UpdatePresence::clear()),
                        ResultTag::Display,
                    );
                    assert_eq!(first, ResultTag::Error(UpdateError::BootNotConfirmed));
                    operations.push(first);
                    let second = record(
                        installer.attempt_first_boot(unconfirmed, UpdatePresence::clear()),
                        ResultTag::Display,
                    );
                    assert_eq!(second, ResultTag::Error(UpdateError::InvalidTransition));
                    operations.push(second);
                    operations.push(record(
                        installer.fallback_to_committed(UpdatePresence::clear()),
                        ResultTag::Display,
                    ));
                }
                8 => {
                    operations.push(record(
                        installer.attempt_first_boot(good, UpdatePresence::clear()),
                        ResultTag::Display,
                    ));
                    operations.push(record(
                        installer.fallback_to_committed(UpdatePresence::clear()),
                        ResultTag::Display,
                    ));
                }
                9 => {
                    let first = record(
                        installer.attempt_first_boot(good, UpdatePresence::clear()),
                        ResultTag::Display,
                    );
                    assert!(matches!(first, ResultTag::Display(_)));
                    operations.push(first);
                    let second = record(
                        installer.attempt_first_boot(good, UpdatePresence::clear()),
                        ResultTag::Display,
                    );
                    assert_eq!(second, ResultTag::Error(UpdateError::InvalidTransition));
                    operations.push(second);
                    operations.push(record(
                        installer.commit_confirmed_boot(UpdatePresence::clear()),
                        ResultTag::Committed,
                    ));
                }
                10 => {
                    let blocked = record(
                        installer.attempt_first_boot(good, UpdatePresence::new(true, true)),
                        ResultTag::Display,
                    );
                    assert_eq!(blocked, ResultTag::Error(UpdateError::WalletSessionActive));
                    operations.push(blocked);
                    operations.push(record(
                        installer.attempt_first_boot(good, UpdatePresence::clear()),
                        ResultTag::Display,
                    ));
                    operations.push(record(
                        installer.commit_confirmed_boot(UpdatePresence::clear()),
                        ResultTag::Committed,
                    ));
                }
                11 => {
                    operations.push(record(
                        installer.attempt_first_boot(good, UpdatePresence::clear()),
                        ResultTag::Display,
                    ));
                    let blocked = record(
                        installer.commit_confirmed_boot(UpdatePresence::new(false, true)),
                        ResultTag::Committed,
                    );
                    assert_eq!(blocked, ResultTag::Error(UpdateError::CardPresent));
                    operations.push(blocked);
                    operations.push(record(
                        installer.commit_confirmed_boot(UpdatePresence::clear()),
                        ResultTag::Committed,
                    ));
                }
                _ => unreachable!("modulo twelve is exhaustive"),
            }

            assert_success_model(&operations, &installer, &expected);
            Outcome {
                preparation: Ok(trial_slot),
                operations,
                committed: installer.committed(),
                has_trial: installer.has_trial(),
                boot_attempts: installer.boot_attempts(),
                last_display: installer.last_display(),
            }
        }
        (Err(error), None) => panic!("unexpected preparation rejection: {error}"),
        (Ok(_), Some(error)) => panic!("expected preparation rejection: {error}"),
    }
}

fuzz_target!(|data: &[u8]| {
    if data.len() > MAX_PRESENTED_BYTES {
        return;
    }
    let first = exercise(data);
    let second = exercise(data);
    assert_eq!(first, second);
});
