use qk_supervisor::{
    Child, Device, MockGrantSet, ProcessRole, Supervisor, SupervisorAction, SupervisorError,
    SupervisorEvent, SupervisorOutcome, SupervisorState,
};

fn advanced(outcome: SupervisorOutcome) -> SupervisorAction {
    match outcome {
        SupervisorOutcome::Advanced(action) => action,
        SupervisorOutcome::FailedClosed(error) => panic!("unexpected failure: {error}"),
    }
}

fn reach_active(supervisor: &mut Supervisor) {
    assert_eq!(
        advanced(supervisor.apply(SupervisorEvent::WalletSessionRequested)),
        SupervisorAction::StopDecoy
    );
    assert_eq!(
        advanced(supervisor.apply(SupervisorEvent::DecoyReaped)),
        SupervisorAction::PrepareRuntime
    );
    assert_eq!(
        advanced(supervisor.apply(SupervisorEvent::RuntimePrepared)),
        SupervisorAction::InstallProductGrants
    );
    assert_eq!(
        advanced(supervisor.apply(SupervisorEvent::ProductGrantsInstalled(
            MockGrantSet::product(),
        ))),
        SupervisorAction::StartCoreAndIo
    );
    assert_eq!(
        advanced(supervisor.apply(SupervisorEvent::ProductChildrenStarted)),
        SupervisorAction::EstablishConnection
    );
    assert_eq!(
        advanced(supervisor.apply(SupervisorEvent::ConnectionEstablished)),
        SupervisorAction::None
    );
}

#[test]
fn exact_lifecycle_reaps_decoy_before_product_work_and_closes_once() {
    let mut supervisor = Supervisor::new();
    assert_eq!(supervisor.state(), SupervisorState::DecoyRunning);
    assert_eq!(
        supervisor.grants().owner(Device::Display),
        Some(ProcessRole::Decoy)
    );
    assert_eq!(
        supervisor.grants().owner(Device::Keypad),
        Some(ProcessRole::Decoy)
    );
    assert_eq!(supervisor.grants().owner(Device::CardSlot), None);

    reach_active(&mut supervisor);
    assert_eq!(supervisor.state(), SupervisorState::SessionActive);
    assert_eq!(
        supervisor.grants().owner(Device::Display),
        Some(ProcessRole::Core)
    );
    assert_eq!(
        supervisor.grants().owner(Device::Keypad),
        Some(ProcessRole::Core)
    );
    assert_eq!(
        supervisor.grants().owner(Device::CardSlot),
        Some(ProcessRole::Core)
    );
    assert_eq!(
        supervisor.grants().owner(Device::Camera),
        Some(ProcessRole::Io)
    );
    assert_eq!(
        supervisor.grants().owner(Device::RemovableMedia),
        Some(ProcessRole::Io)
    );

    assert_eq!(
        advanced(supervisor.apply(SupervisorEvent::NormalClosureRequested)),
        SupervisorAction::TerminateProductChildren
    );
    assert_eq!(supervisor.grants(), MockGrantSet::empty());
    assert_eq!(
        advanced(supervisor.apply(SupervisorEvent::ProductChildrenReaped)),
        SupervisorAction::RemoveRuntime
    );
    assert_eq!(
        advanced(supervisor.apply(SupervisorEvent::RuntimeRemoved)),
        SupervisorAction::None
    );
    assert_eq!(supervisor.state(), SupervisorState::Terminated);
    assert_eq!(
        supervisor.apply(SupervisorEvent::WalletSessionRequested),
        SupervisorOutcome::FailedClosed(SupervisorError::SessionTerminated)
    );
}

#[test]
fn product_work_before_decoy_reap_fails_closed() {
    for event in [
        SupervisorEvent::RuntimePrepared,
        SupervisorEvent::ProductGrantsInstalled(MockGrantSet::product()),
        SupervisorEvent::ProductChildrenStarted,
        SupervisorEvent::ConnectionEstablished,
    ] {
        let mut supervisor = Supervisor::new();
        assert_eq!(
            supervisor.apply(event),
            SupervisorOutcome::FailedClosed(SupervisorError::DecoyNotReaped)
        );
        assert_eq!(supervisor.state(), SupervisorState::Terminated);
        assert_eq!(supervisor.grants(), MockGrantSet::empty());
    }
}

#[test]
fn conflicts_losses_and_failures_are_absorbing() {
    let bad_grants = MockGrantSet::from_masks(1, 1, 0);
    let mut supervisor = Supervisor::new();
    supervisor.apply(SupervisorEvent::WalletSessionRequested);
    supervisor.apply(SupervisorEvent::DecoyReaped);
    supervisor.apply(SupervisorEvent::RuntimePrepared);
    assert_eq!(
        supervisor.apply(SupervisorEvent::ProductGrantsInstalled(bad_grants)),
        SupervisorOutcome::FailedClosed(SupervisorError::GrantConflict)
    );

    for (event, error) in [
        (
            SupervisorEvent::ChildLost(Child::Decoy),
            SupervisorError::ChildLost,
        ),
        (
            SupervisorEvent::ChildLost(Child::Core),
            SupervisorError::ChildLost,
        ),
        (
            SupervisorEvent::ChildLost(Child::Io),
            SupervisorError::ChildLost,
        ),
        (
            SupervisorEvent::ConnectionLost,
            SupervisorError::ConnectionLost,
        ),
        (SupervisorEvent::StepFailed, SupervisorError::StepFailed),
        (
            SupervisorEvent::CleanupFailed,
            SupervisorError::CleanupFailed,
        ),
    ] {
        let mut supervisor = Supervisor::new();
        assert_eq!(
            supervisor.apply(event),
            SupervisorOutcome::FailedClosed(error)
        );
        assert_eq!(supervisor.grants(), MockGrantSet::empty());
        assert_eq!(supervisor.state(), SupervisorState::Terminated);
        assert_eq!(
            supervisor.apply(SupervisorEvent::RuntimeRemoved),
            SupervisorOutcome::FailedClosed(SupervisorError::SessionTerminated)
        );
    }
}

#[test]
fn every_named_error_has_only_its_fixed_name() {
    for error in [
        SupervisorError::InvalidTransition,
        SupervisorError::DecoyNotReaped,
        SupervisorError::GrantConflict,
        SupervisorError::ChildLost,
        SupervisorError::ConnectionLost,
        SupervisorError::StepFailed,
        SupervisorError::CleanupFailed,
        SupervisorError::SessionTerminated,
    ] {
        assert_eq!(error.to_string(), format!("{error:?}"));
    }
}
