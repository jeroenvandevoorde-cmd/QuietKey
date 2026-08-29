//! V2 slice-6 mock-SD lifecycle integration against the exact BSMS fixture.

#[path = "support/v2_s6.rs"]
mod support;

use qk_host_sim::{
    WatchOnlyCoordinatorTierV2, WatchOnlyMockFileKindV2, WatchOnlyMockSdFilesystemV2,
    WatchOnlySdArtifactNamesV2, WatchOnlySdExportErrorV2, WatchOnlySdExportFaultV2,
    WatchOnlySdLifecycleEventV2, WatchOnlySdPublishedArtifactV2,
};
use support::{bsms_bytes, field, nonce, owner};

const INPUT_NAME: &str = "provisioning-input.bin";
const INPUT_BYTES: &[u8] = b"immutable provisioning input";

fn success_events() -> Vec<WatchOnlySdLifecycleEventV2> {
    vec![
        WatchOnlySdLifecycleEventV2::TemporaryCreated,
        WatchOnlySdLifecycleEventV2::BytesWritten {
            bytes: bsms_bytes().len(),
            complete: true,
        },
        WatchOnlySdLifecycleEventV2::FileSynced,
        WatchOnlySdLifecycleEventV2::Closed,
        WatchOnlySdLifecycleEventV2::Reopened,
        WatchOnlySdLifecycleEventV2::Verified,
        WatchOnlySdLifecycleEventV2::Renamed,
    ]
}

fn public_names() -> WatchOnlySdArtifactNamesV2 {
    let artifacts =
        owner(WatchOnlyCoordinatorTierV2::SimpleRecovery).expect("served v2 coordinator tier");
    let mut filesystem = WatchOnlyMockSdFilesystemV2::new();
    artifacts
        .artifact()
        .write_mock_sd(nonce(), &mut filesystem, None)
        .expect("derive public names through successful publication")
        .names()
        .clone()
}

fn write_with_fault(
    fault: Option<WatchOnlySdExportFaultV2>,
    filesystem: &mut WatchOnlyMockSdFilesystemV2,
) -> Result<WatchOnlySdPublishedArtifactV2, WatchOnlySdExportErrorV2> {
    let artifacts =
        owner(WatchOnlyCoordinatorTierV2::SimpleRecovery).expect("served v2 coordinator tier");
    artifacts
        .artifact()
        .write_mock_sd(nonce(), filesystem, fault)
}

fn expected_events(fault: WatchOnlySdExportFaultV2) -> Vec<WatchOnlySdLifecycleEventV2> {
    let success = success_events();
    match fault {
        WatchOnlySdExportFaultV2::TemporaryCreateFailed => Vec::new(),
        WatchOnlySdExportFaultV2::FullMedia => success[..1].to_vec(),
        WatchOnlySdExportFaultV2::WriteFailed => vec![
            WatchOnlySdLifecycleEventV2::TemporaryCreated,
            WatchOnlySdLifecycleEventV2::BytesWritten {
                bytes: bsms_bytes().len() / 2,
                complete: false,
            },
        ],
        WatchOnlySdExportFaultV2::SyncFailed => success[..2].to_vec(),
        WatchOnlySdExportFaultV2::CloseFailed => success[..3].to_vec(),
        WatchOnlySdExportFaultV2::ReopenFailed => success[..4].to_vec(),
        WatchOnlySdExportFaultV2::VerificationMismatch => success[..5].to_vec(),
        WatchOnlySdExportFaultV2::RenameFailed => success[..6].to_vec(),
    }
}

#[test]
fn exact_names_success_order_and_bytes_preserve_the_input_namespace() {
    let expected = bsms_bytes();
    for tier in [
        WatchOnlyCoordinatorTierV2::SimpleRecovery,
        WatchOnlyCoordinatorTierV2::Inheritance,
    ] {
        let artifacts = owner(tier).expect("served v2 coordinator tier");
        let artifact = artifacts.artifact();
        let mut filesystem = WatchOnlyMockSdFilesystemV2::new();
        assert!(filesystem.insert_existing(INPUT_NAME, INPUT_BYTES));

        let published = artifact
            .write_mock_sd(nonce(), &mut filesystem, None)
            .expect("successful mock-SD publication");
        let names = published.names();
        assert_eq!(names.final_name().as_str(), field("final_name"));
        assert_eq!(names.temporary_name().as_str(), field("temporary_name"));
        assert_eq!(published.metadata(), artifact.metadata());
        assert_eq!(
            filesystem.file_bytes(names.final_name()),
            Some(expected.as_slice())
        );
        assert_eq!(
            filesystem.file_kind(names.final_name()),
            Some(WatchOnlyMockFileKindV2::Final)
        );
        assert_eq!(filesystem.file_bytes(names.temporary_name()), None);
        assert_eq!(
            filesystem.existing_file_bytes(INPUT_NAME),
            Some(INPUT_BYTES)
        );
        assert_eq!(filesystem.events(), success_events());
    }
}

#[test]
fn every_injected_failure_preserves_final_namespace_input_and_exact_residue() {
    let names = public_names();
    let expected = bsms_bytes();
    let cases = [
        (
            WatchOnlySdExportFaultV2::TemporaryCreateFailed,
            WatchOnlySdExportErrorV2::TemporaryCreateFailed,
            None,
        ),
        (
            WatchOnlySdExportFaultV2::FullMedia,
            WatchOnlySdExportErrorV2::FullMedia,
            Some(&expected[..0]),
        ),
        (
            WatchOnlySdExportFaultV2::WriteFailed,
            WatchOnlySdExportErrorV2::WriteFailed,
            Some(&expected[..expected.len() / 2]),
        ),
        (
            WatchOnlySdExportFaultV2::SyncFailed,
            WatchOnlySdExportErrorV2::SyncFailed,
            Some(expected.as_slice()),
        ),
        (
            WatchOnlySdExportFaultV2::CloseFailed,
            WatchOnlySdExportErrorV2::CloseFailed,
            Some(expected.as_slice()),
        ),
        (
            WatchOnlySdExportFaultV2::ReopenFailed,
            WatchOnlySdExportErrorV2::ReopenFailed,
            Some(expected.as_slice()),
        ),
        (
            WatchOnlySdExportFaultV2::VerificationMismatch,
            WatchOnlySdExportErrorV2::VerificationMismatch,
            Some(expected.as_slice()),
        ),
        (
            WatchOnlySdExportFaultV2::RenameFailed,
            WatchOnlySdExportErrorV2::RenameFailed,
            Some(expected.as_slice()),
        ),
    ];

    for (fault, error, residue) in cases {
        let mut filesystem = WatchOnlyMockSdFilesystemV2::new();
        assert!(filesystem.insert_existing(INPUT_NAME, INPUT_BYTES));
        assert_eq!(write_with_fault(Some(fault), &mut filesystem), Err(error));
        assert_eq!(filesystem.file_bytes(names.final_name()), None);
        assert_eq!(filesystem.file_bytes(names.temporary_name()), residue);
        assert_eq!(
            filesystem.file_kind(names.temporary_name()),
            residue.map(|_| WatchOnlyMockFileKindV2::Temporary)
        );
        assert_eq!(
            filesystem.existing_file_bytes(INPUT_NAME),
            Some(INPUT_BYTES)
        );
        assert_eq!(filesystem.events(), expected_events(fault));
        assert_ne!(
            filesystem.events().last(),
            Some(&WatchOnlySdLifecycleEventV2::Renamed)
        );
    }
}

#[test]
fn final_and_temporary_name_collisions_never_overwrite() {
    let names = public_names();

    let mut final_collision = WatchOnlyMockSdFilesystemV2::new();
    assert!(final_collision.insert_existing(INPUT_NAME, INPUT_BYTES));
    assert!(final_collision.insert_existing(names.final_name().as_str(), b"occupied final"));
    assert_eq!(
        write_with_fault(None, &mut final_collision),
        Err(WatchOnlySdExportErrorV2::FilenameCollision)
    );
    assert_eq!(
        final_collision.file_bytes(names.final_name()),
        Some(&b"occupied final"[..])
    );
    assert_eq!(final_collision.file_bytes(names.temporary_name()), None);
    assert!(final_collision.events().is_empty());
    assert_eq!(
        final_collision.existing_file_bytes(INPUT_NAME),
        Some(INPUT_BYTES)
    );

    let mut temporary_collision = WatchOnlyMockSdFilesystemV2::new();
    assert!(temporary_collision.insert_existing(INPUT_NAME, INPUT_BYTES));
    assert!(
        temporary_collision.insert_existing(names.temporary_name().as_str(), b"occupied temporary")
    );
    assert_eq!(
        write_with_fault(None, &mut temporary_collision),
        Err(WatchOnlySdExportErrorV2::TemporaryCreateFailed)
    );
    assert_eq!(temporary_collision.file_bytes(names.final_name()), None);
    assert_eq!(
        temporary_collision.file_bytes(names.temporary_name()),
        Some(&b"occupied temporary"[..])
    );
    assert!(temporary_collision.events().is_empty());
    assert_eq!(
        temporary_collision.existing_file_bytes(INPUT_NAME),
        Some(INPUT_BYTES)
    );
}

#[test]
fn retries_reuse_exact_names_without_promoting_residue_or_replacing_final_output() {
    let names = public_names();
    let expected = bsms_bytes();

    let mut clean_retry = WatchOnlyMockSdFilesystemV2::new();
    assert_eq!(
        write_with_fault(
            Some(WatchOnlySdExportFaultV2::TemporaryCreateFailed),
            &mut clean_retry
        ),
        Err(WatchOnlySdExportErrorV2::TemporaryCreateFailed)
    );
    let published = write_with_fault(None, &mut clean_retry).expect("clean retry");
    assert_eq!(published.names(), &names);
    assert_eq!(
        clean_retry.file_bytes(names.final_name()),
        Some(expected.as_slice())
    );
    assert_eq!(clean_retry.file_bytes(names.temporary_name()), None);

    let events_before_collision = clean_retry.events().to_vec();
    assert_eq!(
        write_with_fault(None, &mut clean_retry),
        Err(WatchOnlySdExportErrorV2::FilenameCollision)
    );
    assert_eq!(
        clean_retry.file_bytes(names.final_name()),
        Some(expected.as_slice())
    );
    assert_eq!(clean_retry.file_bytes(names.temporary_name()), None);
    assert_eq!(clean_retry.events(), events_before_collision);

    let mut residue_retry = WatchOnlyMockSdFilesystemV2::new();
    assert_eq!(
        write_with_fault(
            Some(WatchOnlySdExportFaultV2::SyncFailed),
            &mut residue_retry
        ),
        Err(WatchOnlySdExportErrorV2::SyncFailed)
    );
    let residue = residue_retry
        .file_bytes(names.temporary_name())
        .expect("temporary residue")
        .to_vec();
    let events_before_retry = residue_retry.events().to_vec();
    assert_eq!(
        write_with_fault(None, &mut residue_retry),
        Err(WatchOnlySdExportErrorV2::TemporaryCreateFailed)
    );
    assert_eq!(residue_retry.file_bytes(names.final_name()), None);
    assert_eq!(
        residue_retry.file_bytes(names.temporary_name()),
        Some(residue.as_slice())
    );
    assert_eq!(residue_retry.events(), events_before_retry);
}
