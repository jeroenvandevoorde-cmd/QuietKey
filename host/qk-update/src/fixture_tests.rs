//! Byte-verbatim QK-DEC-136 GOLDEN and mock-lifecycle tests.

#![allow(
    clippy::arithmetic_side_effects,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::panic,
    clippy::unwrap_used
)]

use crate::{
    stage_from_media, verify_staged_fixture_package, verify_staged_package,
    wipe::{reset_wiped_bytes, wiped_bytes},
    CommittedInstallerState, FirstBootReport, MockMediaCandidate, MockPrivilegedInstaller,
    MockReadOnlyMedia, ReleaseVersion, SlotId, UpdateError, UpdatePresence,
    REGISTERED_TEST_KEYSET_ID,
};
use std::panic::{catch_unwind, AssertUnwindSafe};

const FIXTURE: &str = include_str!("../tests/fixtures/firmware_package_v1.txt");

fn field(name: &str) -> &'static str {
    let prefix = format!("{name}: ");
    FIXTURE
        .lines()
        .find_map(|line| line.strip_prefix(&prefix))
        .unwrap_or_else(|| panic!("missing fixture field {name}"))
}

fn hex(name: &str) -> Vec<u8> {
    let source = field(name).as_bytes();
    assert_eq!(source.len() % 2, 0, "hex width for {name}");
    source
        .as_chunks::<2>()
        .0
        .iter()
        .map(|pair| {
            let text = core::str::from_utf8(pair).unwrap();
            u8::from_str_radix(text, 16).unwrap()
        })
        .collect()
}

fn fixed<const N: usize>(name: &str) -> [u8; N] {
    hex(name).try_into().unwrap()
}

fn stage(name: &str) -> crate::StagedPackage {
    let mut media = MockReadOnlyMedia::new(vec![MockMediaCandidate::canonical(hex(name))]);
    let staged = stage_from_media(&mut media, UpdatePresence::clear()).unwrap();
    assert!(media.consumed());
    assert_eq!(media.read_attempts(), 1);
    staged
}

fn verify(name: &str, floor: u64) -> crate::VerifiedPackage {
    verify_staged_fixture_package(
        stage(name),
        ReleaseVersion::new(1, floor),
        UpdatePresence::clear(),
    )
    .unwrap()
}

#[test]
fn every_signer_pair_verifies_the_same_manifest_and_image() {
    let publication: [u8; 32] = fixed("publication_hash");
    let digest: [u8; 32] = fixed("signature_digest");
    let source_commit: [u8; 20] = fixed("source_commit");
    let image_hash: [u8; 32] = fixed("artifact_1_sha256");
    for package in [
        "package_roles_1_2_hex",
        "package_roles_1_3_hex",
        "package_roles_2_3_hex",
    ] {
        let verified = verify(package, 41);
        assert_eq!(verified.publication_hash(), publication);
        assert_eq!(verified.signature_digest(), digest);
        assert_eq!(verified.firmware_image_sha256(), image_hash);
        assert_eq!(verified.firmware_image_length(), 35);
        assert_eq!(verified.signature_checks(), 2);
        assert_eq!(verified.manifest().source_commit(), source_commit);
        assert_eq!(verified.manifest().version(), ReleaseVersion::new(1, 42));
        assert_eq!(
            verified.manifest().signing_keyset_id(),
            REGISTERED_TEST_KEYSET_ID
        );
        assert_eq!(
            verified.manifest().target_keyset_id(),
            REGISTERED_TEST_KEYSET_ID
        );
        assert_eq!(verified.manifest().artifacts().len(), 6);
    }
}

#[test]
fn production_refusal_and_high_s_are_distinct() {
    assert!(matches!(
        verify_staged_package(
            stage("package_roles_1_3_hex"),
            ReleaseVersion::new(1, 41),
            UpdatePresence::clear(),
        ),
        Err(UpdateError::TestAnchorInProduction)
    ));
    assert!(matches!(
        verify_staged_fixture_package(
            stage("high_s_package_hex"),
            ReleaseVersion::new(1, 41),
            UpdatePresence::clear(),
        ),
        Err(UpdateError::HighSSignature)
    ));
}

#[test]
fn defense_floor_is_lexicographic_and_runs_after_signatures() {
    for floor in [
        ReleaseVersion::new(1, 42),
        ReleaseVersion::new(1, 43),
        ReleaseVersion::new(2, 0),
    ] {
        assert!(matches!(
            verify_staged_fixture_package(
                stage("package_roles_1_3_hex"),
                floor,
                UpdatePresence::clear(),
            ),
            Err(UpdateError::NotStrictlyNewer)
        ));
    }
    assert!(verify_staged_fixture_package(
        stage("package_roles_1_3_hex"),
        ReleaseVersion::new(0, u64::MAX),
        UpdatePresence::clear(),
    )
    .is_ok());
}

#[test]
fn confirmed_rotation_commits_all_and_only_candidate_facts() {
    let verified = verify("rotation_package_hex", 41);
    let rotation_target: [u8; 32] = fixed("target_keyset_id_rotation");
    let image_hash: [u8; 32] = fixed("artifact_1_sha256");
    let original = CommittedInstallerState::new(
        SlotId::A,
        ReleaseVersion::new(1, 41),
        REGISTERED_TEST_KEYSET_ID,
        [0x41; 32],
    );
    let mut installer = MockPrivilegedInstaller::new(original);
    assert_eq!(
        installer.prepare_trial(verified, UpdatePresence::clear()),
        Ok(SlotId::B)
    );
    assert_eq!(installer.committed(), original);
    let display = installer
        .attempt_first_boot(
            FirstBootReport::new(
                SlotId::B,
                ReleaseVersion::new(1, 42),
                image_hash,
                rotation_target,
                true,
            ),
            UpdatePresence::clear(),
        )
        .unwrap();
    assert_eq!(display.target(), *b"QKT1");
    assert_eq!(display.sequence_decimal(), "42");
    assert_eq!(installer.committed(), original);
    let committed = installer
        .commit_confirmed_boot(UpdatePresence::clear())
        .unwrap();
    assert_eq!(committed.active_slot(), SlotId::B);
    assert_eq!(committed.floor(), ReleaseVersion::new(1, 42));
    assert_eq!(committed.keyset_id(), rotation_target);
    assert_eq!(committed.active_image_sha256(), image_hash);
    assert!(!installer.has_trial());
    assert!(matches!(
        installer.fallback_to_committed(UpdatePresence::clear()),
        Err(UpdateError::InvalidTransition)
    ));
}

#[test]
fn failed_first_boot_is_single_use_and_falls_back_without_commit() {
    let verified = verify("package_roles_1_3_hex", 40);
    let original = CommittedInstallerState::new(
        SlotId::B,
        ReleaseVersion::new(1, 41),
        REGISTERED_TEST_KEYSET_ID,
        [0x52; 32],
    );
    let mut installer = MockPrivilegedInstaller::new(original);
    assert_eq!(
        installer.prepare_trial(verified, UpdatePresence::clear()),
        Ok(SlotId::A)
    );
    let rejected = FirstBootReport::new(
        SlotId::A,
        ReleaseVersion::new(1, 42),
        fixed("artifact_1_sha256"),
        REGISTERED_TEST_KEYSET_ID,
        false,
    );
    assert!(matches!(
        installer.attempt_first_boot(rejected, UpdatePresence::clear()),
        Err(UpdateError::BootNotConfirmed)
    ));
    assert!(matches!(
        installer.attempt_first_boot(rejected, UpdatePresence::clear()),
        Err(UpdateError::InvalidTransition)
    ));
    assert!(matches!(
        installer.commit_confirmed_boot(UpdatePresence::clear()),
        Err(UpdateError::BootNotConfirmed)
    ));
    let fallback = installer
        .fallback_to_committed(UpdatePresence::clear())
        .unwrap();
    assert_eq!(fallback.version(), ReleaseVersion::new(1, 41));
    assert_eq!(fallback.sequence_decimal(), "41");
    assert_eq!(installer.committed(), original);
    assert_eq!(installer.boot_attempts(), 2);
}

#[test]
fn installer_authority_and_presence_fail_closed() {
    let base = CommittedInstallerState::new(
        SlotId::A,
        ReleaseVersion::new(1, 42),
        REGISTERED_TEST_KEYSET_ID,
        [0; 32],
    );
    let mut old = MockPrivilegedInstaller::new(base);
    assert!(matches!(
        old.prepare_trial(verify("package_roles_1_3_hex", 0), UpdatePresence::clear()),
        Err(UpdateError::InstallerNotStrictlyNewer)
    ));

    let wrong_keyset =
        CommittedInstallerState::new(SlotId::A, ReleaseVersion::new(1, 40), [0x99; 32], [0; 32]);
    let mut wrong = MockPrivilegedInstaller::new(wrong_keyset);
    assert!(matches!(
        wrong.prepare_trial(verify("package_roles_1_3_hex", 0), UpdatePresence::clear()),
        Err(UpdateError::InstallerKeysetMismatch)
    ));

    let fault_base = CommittedInstallerState::new(
        SlotId::A,
        ReleaseVersion::new(1, 40),
        REGISTERED_TEST_KEYSET_ID,
        [0; 32],
    );
    let mut fault = MockPrivilegedInstaller::with_invalid_slot_fault(fault_base);
    assert!(matches!(
        fault.prepare_trial(verify("package_roles_1_3_hex", 0), UpdatePresence::clear()),
        Err(UpdateError::InvalidSlotDecision)
    ));

    let mut presence = MockPrivilegedInstaller::new(fault_base);
    assert!(matches!(
        presence.prepare_trial(
            verify("package_roles_1_3_hex", 0),
            UpdatePresence::new(true, false),
        ),
        Err(UpdateError::WalletSessionActive)
    ));
}

#[test]
fn every_boot_report_field_is_load_bearing() {
    let image_hash: [u8; 32] = fixed("artifact_1_sha256");
    let good = FirstBootReport::new(
        SlotId::B,
        ReleaseVersion::new(1, 42),
        image_hash,
        REGISTERED_TEST_KEYSET_ID,
        true,
    );
    let reports = [
        FirstBootReport::new(
            SlotId::A,
            ReleaseVersion::new(1, 42),
            image_hash,
            REGISTERED_TEST_KEYSET_ID,
            true,
        ),
        FirstBootReport::new(
            SlotId::B,
            ReleaseVersion::new(1, 43),
            image_hash,
            REGISTERED_TEST_KEYSET_ID,
            true,
        ),
        FirstBootReport::new(
            SlotId::B,
            ReleaseVersion::new(1, 42),
            [0x33; 32],
            REGISTERED_TEST_KEYSET_ID,
            true,
        ),
        FirstBootReport::new(
            SlotId::B,
            ReleaseVersion::new(1, 42),
            image_hash,
            [0x44; 32],
            true,
        ),
    ];
    for report in reports {
        let committed = CommittedInstallerState::new(
            SlotId::A,
            ReleaseVersion::new(1, 41),
            REGISTERED_TEST_KEYSET_ID,
            [0; 32],
        );
        let mut installer = MockPrivilegedInstaller::new(committed);
        installer
            .prepare_trial(verify("package_roles_1_3_hex", 40), UpdatePresence::clear())
            .unwrap();
        assert!(matches!(
            installer.attempt_first_boot(report, UpdatePresence::clear()),
            Err(UpdateError::BootReportMismatch)
        ));
        assert_eq!(installer.committed(), committed);
        installer
            .fallback_to_committed(UpdatePresence::clear())
            .unwrap();
    }

    let mut installer = MockPrivilegedInstaller::new(CommittedInstallerState::new(
        SlotId::A,
        ReleaseVersion::new(1, 41),
        REGISTERED_TEST_KEYSET_ID,
        [0; 32],
    ));
    installer
        .prepare_trial(verify("package_roles_1_3_hex", 40), UpdatePresence::clear())
        .unwrap();
    assert!(installer
        .attempt_first_boot(good, UpdatePresence::clear())
        .is_ok());
}

#[test]
fn staging_allocation_wipes_on_rejection_commit_and_unwind() {
    let high_s_length = hex("high_s_package_hex").len();
    reset_wiped_bytes();
    assert!(verify_staged_fixture_package(
        stage("high_s_package_hex"),
        ReleaseVersion::new(1, 41),
        UpdatePresence::clear(),
    )
    .is_err());
    assert!(wiped_bytes() >= high_s_length);

    let staged = stage("package_roles_1_3_hex");
    let staged_length = staged.byte_length();
    reset_wiped_bytes();
    let result = catch_unwind(AssertUnwindSafe(move || {
        let _owned = staged;
        panic!("test-only caught unwind");
    }));
    assert!(result.is_err());
    assert!(wiped_bytes() >= staged_length);

    let verified = verify("package_roles_1_3_hex", 40);
    let package_length = hex("package_roles_1_3_hex").len();
    let mut installer = MockPrivilegedInstaller::new(CommittedInstallerState::new(
        SlotId::A,
        ReleaseVersion::new(1, 41),
        REGISTERED_TEST_KEYSET_ID,
        [0; 32],
    ));
    installer
        .prepare_trial(verified, UpdatePresence::clear())
        .unwrap();
    installer
        .attempt_first_boot(
            FirstBootReport::new(
                SlotId::B,
                ReleaseVersion::new(1, 42),
                fixed("artifact_1_sha256"),
                REGISTERED_TEST_KEYSET_ID,
                true,
            ),
            UpdatePresence::clear(),
        )
        .unwrap();
    reset_wiped_bytes();
    installer
        .commit_confirmed_boot(UpdatePresence::clear())
        .unwrap();
    assert!(wiped_bytes() >= package_length);
}
