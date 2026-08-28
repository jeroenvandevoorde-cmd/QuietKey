//! M28 mock-SD lifecycle integration against the exact BSMS fixture.

#[path = "support/m28.rs"]
mod support;

use qk_host_sim::{
    KitTier, WatchOnlyMockFileKind, WatchOnlyMockSdFilesystem, WatchOnlySdArtifactNames,
    WatchOnlySdExportError, WatchOnlySdExportFault, WatchOnlySdLifecycleEvent,
    WatchOnlySdPublishedArtifact,
};
use support::{bsms_bytes, field, nonce, owner};

const INPUT_NAME: &str = "provisioning-input.bin";
const INPUT_BYTES: &[u8] = b"immutable provisioning input";

fn success_events() -> Vec<WatchOnlySdLifecycleEvent> {
    vec![
        WatchOnlySdLifecycleEvent::TemporaryCreated,
        WatchOnlySdLifecycleEvent::BytesWritten {
            bytes: bsms_bytes().len(),
            complete: true,
        },
        WatchOnlySdLifecycleEvent::FileSynced,
        WatchOnlySdLifecycleEvent::Closed,
        WatchOnlySdLifecycleEvent::Reopened,
        WatchOnlySdLifecycleEvent::Verified,
        WatchOnlySdLifecycleEvent::Renamed,
    ]
}

fn public_names() -> WatchOnlySdArtifactNames {
    let artifacts = owner(KitTier::SimpleRecovery).expect("served M28 tier");
    let mut filesystem = WatchOnlyMockSdFilesystem::new();
    artifacts
        .artifact()
        .write_mock_sd(nonce(), &mut filesystem, None)
        .expect("derive public names through successful publication")
        .names()
        .clone()
}

fn write_with_fault(
    fault: Option<WatchOnlySdExportFault>,
    filesystem: &mut WatchOnlyMockSdFilesystem,
) -> Result<WatchOnlySdPublishedArtifact, WatchOnlySdExportError> {
    let artifacts = owner(KitTier::SimpleRecovery).expect("served M28 tier");
    artifacts
        .artifact()
        .write_mock_sd(nonce(), filesystem, fault)
}

fn expected_events(fault: WatchOnlySdExportFault) -> Vec<WatchOnlySdLifecycleEvent> {
    let success = success_events();
    match fault {
        WatchOnlySdExportFault::TemporaryCreateFailed => Vec::new(),
        WatchOnlySdExportFault::FullMedia => success[..1].to_vec(),
        WatchOnlySdExportFault::WriteFailed => vec![
            WatchOnlySdLifecycleEvent::TemporaryCreated,
            WatchOnlySdLifecycleEvent::BytesWritten {
                bytes: bsms_bytes().len() / 2,
                complete: false,
            },
        ],
        WatchOnlySdExportFault::SyncFailed => success[..2].to_vec(),
        WatchOnlySdExportFault::CloseFailed => success[..3].to_vec(),
        WatchOnlySdExportFault::ReopenFailed => success[..4].to_vec(),
        WatchOnlySdExportFault::VerificationMismatch => success[..5].to_vec(),
        WatchOnlySdExportFault::RenameFailed => success[..6].to_vec(),
    }
}

#[test]
fn exact_names_success_order_and_bytes_preserve_the_input_namespace() {
    let expected = bsms_bytes();
    for tier in [KitTier::SimpleRecovery, KitTier::Inheritance] {
        let artifacts = owner(tier).expect("served M28 tier");
        let artifact = artifacts.artifact();
        let mut filesystem = WatchOnlyMockSdFilesystem::new();
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
            Some(WatchOnlyMockFileKind::Final)
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
            WatchOnlySdExportFault::TemporaryCreateFailed,
            WatchOnlySdExportError::TemporaryCreateFailed,
            None,
        ),
        (
            WatchOnlySdExportFault::FullMedia,
            WatchOnlySdExportError::FullMedia,
            Some(&expected[..0]),
        ),
        (
            WatchOnlySdExportFault::WriteFailed,
            WatchOnlySdExportError::WriteFailed,
            Some(&expected[..expected.len() / 2]),
        ),
        (
            WatchOnlySdExportFault::SyncFailed,
            WatchOnlySdExportError::SyncFailed,
            Some(expected.as_slice()),
        ),
        (
            WatchOnlySdExportFault::CloseFailed,
            WatchOnlySdExportError::CloseFailed,
            Some(expected.as_slice()),
        ),
        (
            WatchOnlySdExportFault::ReopenFailed,
            WatchOnlySdExportError::ReopenFailed,
            Some(expected.as_slice()),
        ),
        (
            WatchOnlySdExportFault::VerificationMismatch,
            WatchOnlySdExportError::VerificationMismatch,
            Some(expected.as_slice()),
        ),
        (
            WatchOnlySdExportFault::RenameFailed,
            WatchOnlySdExportError::RenameFailed,
            Some(expected.as_slice()),
        ),
    ];

    for (fault, error, residue) in cases {
        let mut filesystem = WatchOnlyMockSdFilesystem::new();
        assert!(filesystem.insert_existing(INPUT_NAME, INPUT_BYTES));
        assert_eq!(write_with_fault(Some(fault), &mut filesystem), Err(error));
        assert_eq!(filesystem.file_bytes(names.final_name()), None);
        assert_eq!(filesystem.file_bytes(names.temporary_name()), residue);
        assert_eq!(
            filesystem.file_kind(names.temporary_name()),
            residue.map(|_| WatchOnlyMockFileKind::Temporary)
        );
        assert_eq!(
            filesystem.existing_file_bytes(INPUT_NAME),
            Some(INPUT_BYTES)
        );
        assert_eq!(filesystem.events(), expected_events(fault));
        assert_ne!(
            filesystem.events().last(),
            Some(&WatchOnlySdLifecycleEvent::Renamed)
        );
    }
}

#[test]
fn final_and_temporary_name_collisions_never_overwrite() {
    let names = public_names();

    let mut final_collision = WatchOnlyMockSdFilesystem::new();
    assert!(final_collision.insert_existing(INPUT_NAME, INPUT_BYTES));
    assert!(final_collision.insert_existing(names.final_name().as_str(), b"occupied final"));
    assert_eq!(
        write_with_fault(None, &mut final_collision),
        Err(WatchOnlySdExportError::FilenameCollision)
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

    let mut temporary_collision = WatchOnlyMockSdFilesystem::new();
    assert!(temporary_collision.insert_existing(INPUT_NAME, INPUT_BYTES));
    assert!(
        temporary_collision.insert_existing(names.temporary_name().as_str(), b"occupied temporary")
    );
    assert_eq!(
        write_with_fault(None, &mut temporary_collision),
        Err(WatchOnlySdExportError::TemporaryCreateFailed)
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

    let mut clean_retry = WatchOnlyMockSdFilesystem::new();
    assert_eq!(
        write_with_fault(
            Some(WatchOnlySdExportFault::TemporaryCreateFailed),
            &mut clean_retry
        ),
        Err(WatchOnlySdExportError::TemporaryCreateFailed)
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
        Err(WatchOnlySdExportError::FilenameCollision)
    );
    assert_eq!(
        clean_retry.file_bytes(names.final_name()),
        Some(expected.as_slice())
    );
    assert_eq!(clean_retry.file_bytes(names.temporary_name()), None);
    assert_eq!(clean_retry.events(), events_before_collision);

    let mut residue_retry = WatchOnlyMockSdFilesystem::new();
    assert_eq!(
        write_with_fault(Some(WatchOnlySdExportFault::SyncFailed), &mut residue_retry),
        Err(WatchOnlySdExportError::SyncFailed)
    );
    let residue = residue_retry
        .file_bytes(names.temporary_name())
        .expect("temporary residue")
        .to_vec();
    let events_before_retry = residue_retry.events().to_vec();
    assert_eq!(
        write_with_fault(None, &mut residue_retry),
        Err(WatchOnlySdExportError::TemporaryCreateFailed)
    );
    assert_eq!(residue_retry.file_bytes(names.final_name()), None);
    assert_eq!(
        residue_retry.file_bytes(names.temporary_name()),
        Some(residue.as_slice())
    );
    assert_eq!(residue_retry.events(), events_before_retry);
}
