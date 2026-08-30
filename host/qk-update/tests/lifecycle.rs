//! Public HOST mock lifecycle boundary locks for QK-DEC-136.

use qk_update::{
    CommittedInstallerState, FirstBootReport, MockPrivilegedInstaller, ReleaseVersion, SlotId,
    UpdateError, UpdatePresence, TARGET_PLATFORM,
};

fn state() -> CommittedInstallerState {
    CommittedInstallerState::new(SlotId::A, ReleaseVersion::new(1, 9), [0x31; 32], [0x41; 32])
}

fn report() -> FirstBootReport {
    FirstBootReport::new(
        SlotId::B,
        ReleaseVersion::new(1, 10),
        [0x42; 32],
        [0x32; 32],
        true,
    )
}

#[test]
fn committed_state_is_typed_and_immutable_through_accessors() {
    let committed = state();
    assert_eq!(committed.active_slot(), SlotId::A);
    assert_eq!(committed.floor(), ReleaseVersion::new(1, 9));
    assert_eq!(committed.keyset_id(), [0x31; 32]);
    assert_eq!(committed.active_image_sha256(), [0x41; 32]);
    assert!(ReleaseVersion::new(2, 0) > ReleaseVersion::new(1, u64::MAX));
    assert_eq!(TARGET_PLATFORM, *b"QKT1");
}

#[test]
fn absent_trial_operations_are_named_invalid_transitions() {
    let mut installer = MockPrivilegedInstaller::new(state());
    assert!(matches!(
        installer.attempt_first_boot(report(), UpdatePresence::clear()),
        Err(UpdateError::InvalidTransition)
    ));
    assert!(matches!(
        installer.commit_confirmed_boot(UpdatePresence::clear()),
        Err(UpdateError::InvalidTransition)
    ));
    assert!(matches!(
        installer.fallback_to_committed(UpdatePresence::clear()),
        Err(UpdateError::InvalidTransition)
    ));
    assert_eq!(installer.committed(), state());
    assert_eq!(installer.boot_attempts(), 0);
    assert_eq!(installer.last_display(), None);
}

#[test]
fn wallet_and_card_presence_precede_lifecycle_state() {
    let mut installer = MockPrivilegedInstaller::new(state());
    assert!(matches!(
        installer.attempt_first_boot(report(), UpdatePresence::new(true, false)),
        Err(UpdateError::WalletSessionActive)
    ));
    assert!(matches!(
        installer.commit_confirmed_boot(UpdatePresence::new(false, true)),
        Err(UpdateError::CardPresent)
    ));
    assert!(matches!(
        installer.fallback_to_committed(UpdatePresence::new(true, true)),
        Err(UpdateError::WalletSessionActive)
    ));
    assert_eq!(installer.committed(), state());
    assert_eq!(installer.boot_attempts(), 0);
}

#[test]
fn invalid_slot_fault_is_explicitly_host_mock_only() {
    let installer = MockPrivilegedInstaller::with_invalid_slot_fault(state());
    assert_eq!(installer.committed(), state());
    assert!(!installer.has_trial());
    assert_eq!(installer.boot_attempts(), 0);
}
