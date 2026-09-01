#![no_main]

use libfuzzer_sys::fuzz_target;
use qk_supervisor::{
    Child, Device, MockGrantSet, ProcessLifecycle, ProcessLifecycleAction, ProcessLifecycleError,
    ProcessLifecycleEvent, ProcessLifecycleOutcome, ProcessLifecycleState, ProcessRole,
};

const MAX_PRESENTED_BYTES: usize = 4_096;
const DEVICES: [Device; 5] = [
    Device::Display,
    Device::Keypad,
    Device::CardSlot,
    Device::Camera,
    Device::RemovableMedia,
];

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Grants {
    Decoy,
    Product,
    Empty,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct Model {
    state: ProcessLifecycleState,
    grants: Grants,
    failure: Option<ProcessLifecycleError>,
}

impl Model {
    const fn new() -> Self {
        Self {
            state: ProcessLifecycleState::DecoyRunning,
            grants: Grants::Decoy,
            failure: None,
        }
    }

    fn begin_failure(&mut self, error: ProcessLifecycleError) -> ProcessLifecycleOutcome {
        if self.failure.is_none() {
            self.failure = Some(error);
        }
        self.state = ProcessLifecycleState::Terminating;
        self.grants = Grants::Empty;
        ProcessLifecycleOutcome::FailedClosed(
            self.failure.unwrap_or(error),
            ProcessLifecycleAction::TerminateChildren,
        )
    }

    fn cleanup(&self, action: ProcessLifecycleAction) -> ProcessLifecycleOutcome {
        match self.failure {
            Some(error) => ProcessLifecycleOutcome::FailedClosed(error, action),
            None => ProcessLifecycleOutcome::Advanced(action),
        }
    }

    fn apply(&mut self, event: ProcessLifecycleEvent) -> ProcessLifecycleOutcome {
        if self.state == ProcessLifecycleState::Terminated {
            return ProcessLifecycleOutcome::FailedClosed(
                self.failure
                    .unwrap_or(ProcessLifecycleError::SessionTerminated),
                ProcessLifecycleAction::None,
            );
        }

        // Cleanup is the last operation after the product children have been
        // reaped. A cleanup fault therefore terminates without attempting to
        // terminate those children a second time or regressing the model.
        if self.state == ProcessLifecycleState::ProductChildrenReaped
            && event == ProcessLifecycleEvent::CleanupFailed
        {
            if self.failure.is_none() {
                self.failure = Some(ProcessLifecycleError::CleanupFailed);
            }
            self.state = ProcessLifecycleState::Terminated;
            self.grants = Grants::Empty;
            return ProcessLifecycleOutcome::FailedClosed(
                self.failure.unwrap_or(ProcessLifecycleError::CleanupFailed),
                ProcessLifecycleAction::None,
            );
        }

        let failure = match event {
            ProcessLifecycleEvent::ChildLost(_) => Some(ProcessLifecycleError::ChildLost),
            ProcessLifecycleEvent::ConnectionLost => Some(ProcessLifecycleError::ConnectionLost),
            ProcessLifecycleEvent::StepFailed => Some(ProcessLifecycleError::StepFailed),
            ProcessLifecycleEvent::CleanupFailed => Some(ProcessLifecycleError::CleanupFailed),
            _ => None,
        };
        if let Some(error) = failure {
            return self.begin_failure(error);
        }

        match (self.state, event) {
            (
                ProcessLifecycleState::DecoyRunning,
                ProcessLifecycleEvent::WalletSessionRequested,
            ) => {
                self.state = ProcessLifecycleState::DecoyStopRequested;
                ProcessLifecycleOutcome::Advanced(ProcessLifecycleAction::TerminateDecoy)
            }
            (ProcessLifecycleState::DecoyStopRequested, ProcessLifecycleEvent::DecoyReaped) => {
                self.state = ProcessLifecycleState::DecoyReaped;
                self.grants = Grants::Empty;
                ProcessLifecycleOutcome::Advanced(ProcessLifecycleAction::PrepareRuntime)
            }
            (ProcessLifecycleState::DecoyReaped, ProcessLifecycleEvent::RuntimePrepared) => {
                self.state = ProcessLifecycleState::RuntimePrepared;
                ProcessLifecycleOutcome::Advanced(ProcessLifecycleAction::InstallProductGrants)
            }
            (
                ProcessLifecycleState::RuntimePrepared,
                ProcessLifecycleEvent::ProductGrantsInstalled(grants),
            ) => {
                if grants != MockGrantSet::product() {
                    self.begin_failure(ProcessLifecycleError::GrantConflict)
                } else {
                    self.state = ProcessLifecycleState::ProductGrantsInstalled;
                    self.grants = Grants::Product;
                    ProcessLifecycleOutcome::Advanced(ProcessLifecycleAction::EstablishConnection)
                }
            }
            (
                ProcessLifecycleState::ProductGrantsInstalled,
                ProcessLifecycleEvent::ConnectionAcceptedAndUnlinked,
            ) => {
                self.state = ProcessLifecycleState::ConnectionAcceptedAndUnlinked;
                ProcessLifecycleOutcome::Advanced(ProcessLifecycleAction::StartProductChildren)
            }
            (
                ProcessLifecycleState::ConnectionAcceptedAndUnlinked,
                ProcessLifecycleEvent::ProductChildrenStartedAndParentEndpointsClosed,
            ) => {
                self.state = ProcessLifecycleState::SessionActive;
                ProcessLifecycleOutcome::Advanced(ProcessLifecycleAction::WaitForSession)
            }
            (ProcessLifecycleState::SessionActive, ProcessLifecycleEvent::SessionCompleted) => {
                self.state = ProcessLifecycleState::Terminating;
                self.grants = Grants::Empty;
                ProcessLifecycleOutcome::Advanced(ProcessLifecycleAction::ReapProductChildren)
            }
            (ProcessLifecycleState::Terminating, ProcessLifecycleEvent::ProductChildrenReaped) => {
                self.state = ProcessLifecycleState::ProductChildrenReaped;
                self.cleanup(ProcessLifecycleAction::RemoveRuntime)
            }
            (
                ProcessLifecycleState::ProductChildrenReaped,
                ProcessLifecycleEvent::RuntimeRemoved,
            ) => {
                self.state = ProcessLifecycleState::Terminated;
                self.cleanup(ProcessLifecycleAction::None)
            }
            (
                ProcessLifecycleState::DecoyRunning | ProcessLifecycleState::DecoyStopRequested,
                ProcessLifecycleEvent::RuntimePrepared
                | ProcessLifecycleEvent::ProductGrantsInstalled(_)
                | ProcessLifecycleEvent::ConnectionAcceptedAndUnlinked
                | ProcessLifecycleEvent::ProductChildrenStartedAndParentEndpointsClosed,
            ) => self.begin_failure(ProcessLifecycleError::DecoyNotReaped),
            _ => self.begin_failure(ProcessLifecycleError::InvalidTransition),
        }
    }
}

fn error_name(error: ProcessLifecycleError) -> &'static str {
    match error {
        ProcessLifecycleError::InvalidTransition => "InvalidTransition",
        ProcessLifecycleError::DecoyNotReaped => "DecoyNotReaped",
        ProcessLifecycleError::GrantConflict => "GrantConflict",
        ProcessLifecycleError::ChildLost => "ChildLost",
        ProcessLifecycleError::ConnectionLost => "ConnectionLost",
        ProcessLifecycleError::StepFailed => "StepFailed",
        ProcessLifecycleError::CleanupFailed => "CleanupFailed",
        ProcessLifecycleError::SessionTerminated => "SessionTerminated",
    }
}

fn event(command: &[u8]) -> ProcessLifecycleEvent {
    match command.first().copied().unwrap_or(0) % 15 {
        0 => ProcessLifecycleEvent::WalletSessionRequested,
        1 => ProcessLifecycleEvent::DecoyReaped,
        2 => ProcessLifecycleEvent::RuntimePrepared,
        3 => ProcessLifecycleEvent::ProductGrantsInstalled(MockGrantSet::from_masks(
            command.get(1).copied().unwrap_or(0),
            command.get(2).copied().unwrap_or(0),
            command.get(3).copied().unwrap_or(0),
        )),
        4 => ProcessLifecycleEvent::ConnectionAcceptedAndUnlinked,
        5 => ProcessLifecycleEvent::ProductChildrenStartedAndParentEndpointsClosed,
        6 => ProcessLifecycleEvent::SessionCompleted,
        7 => ProcessLifecycleEvent::ProductChildrenReaped,
        8 => ProcessLifecycleEvent::RuntimeRemoved,
        9 => ProcessLifecycleEvent::ChildLost(Child::Decoy),
        10 => ProcessLifecycleEvent::ChildLost(Child::Core),
        11 => ProcessLifecycleEvent::ChildLost(Child::Io),
        12 => ProcessLifecycleEvent::ConnectionLost,
        13 => ProcessLifecycleEvent::StepFailed,
        14 => ProcessLifecycleEvent::CleanupFailed,
        _ => unreachable!("modulo fifteen is exhaustive"),
    }
}

fn expected_owner(grants: Grants, device: Device) -> Option<ProcessRole> {
    match (grants, device) {
        (Grants::Decoy, Device::Display | Device::Keypad) => Some(ProcessRole::Decoy),
        (Grants::Product, Device::Display | Device::Keypad | Device::CardSlot) => {
            Some(ProcessRole::Core)
        }
        (Grants::Product, Device::Camera | Device::RemovableMedia) => Some(ProcessRole::Io),
        _ => None,
    }
}

fn assert_state(actual: &ProcessLifecycle, expected: Model) {
    assert_eq!(actual.state(), expected.state);
    assert_eq!(actual.failure(), expected.failure);
    for device in DEVICES {
        assert_eq!(
            actual.grants().owner(device),
            expected_owner(expected.grants, device)
        );
    }
}

fn drive(data: &[u8]) -> Vec<ProcessLifecycleOutcome> {
    let mut actual = ProcessLifecycle::new();
    let mut expected = Model::new();
    assert_state(&actual, expected);
    let mut outcomes = Vec::with_capacity(data.len().div_ceil(4));
    for command in data.chunks(4) {
        let presented = event(command);
        let expected_outcome = expected.apply(presented);
        let actual_outcome = actual.apply(presented);
        assert_eq!(actual_outcome, expected_outcome);
        if let ProcessLifecycleOutcome::FailedClosed(error, _) = actual_outcome {
            assert_eq!(error.to_string(), error_name(error));
        }
        assert_state(&actual, expected);
        outcomes.push(actual_outcome);
    }
    outcomes
}

fn assert_complete_success_path() {
    let mut lifecycle = ProcessLifecycle::new();
    for (event, outcome, state) in [
        (
            ProcessLifecycleEvent::WalletSessionRequested,
            ProcessLifecycleOutcome::Advanced(ProcessLifecycleAction::TerminateDecoy),
            ProcessLifecycleState::DecoyStopRequested,
        ),
        (
            ProcessLifecycleEvent::DecoyReaped,
            ProcessLifecycleOutcome::Advanced(ProcessLifecycleAction::PrepareRuntime),
            ProcessLifecycleState::DecoyReaped,
        ),
        (
            ProcessLifecycleEvent::RuntimePrepared,
            ProcessLifecycleOutcome::Advanced(ProcessLifecycleAction::InstallProductGrants),
            ProcessLifecycleState::RuntimePrepared,
        ),
        (
            ProcessLifecycleEvent::ProductGrantsInstalled(MockGrantSet::product()),
            ProcessLifecycleOutcome::Advanced(ProcessLifecycleAction::EstablishConnection),
            ProcessLifecycleState::ProductGrantsInstalled,
        ),
        (
            ProcessLifecycleEvent::ConnectionAcceptedAndUnlinked,
            ProcessLifecycleOutcome::Advanced(ProcessLifecycleAction::StartProductChildren),
            ProcessLifecycleState::ConnectionAcceptedAndUnlinked,
        ),
        (
            ProcessLifecycleEvent::ProductChildrenStartedAndParentEndpointsClosed,
            ProcessLifecycleOutcome::Advanced(ProcessLifecycleAction::WaitForSession),
            ProcessLifecycleState::SessionActive,
        ),
        (
            ProcessLifecycleEvent::SessionCompleted,
            ProcessLifecycleOutcome::Advanced(ProcessLifecycleAction::ReapProductChildren),
            ProcessLifecycleState::Terminating,
        ),
        (
            ProcessLifecycleEvent::ProductChildrenReaped,
            ProcessLifecycleOutcome::Advanced(ProcessLifecycleAction::RemoveRuntime),
            ProcessLifecycleState::ProductChildrenReaped,
        ),
        (
            ProcessLifecycleEvent::RuntimeRemoved,
            ProcessLifecycleOutcome::Advanced(ProcessLifecycleAction::None),
            ProcessLifecycleState::Terminated,
        ),
    ] {
        assert_eq!(lifecycle.apply(event), outcome);
        assert_eq!(lifecycle.state(), state);
    }
    assert_eq!(lifecycle.grants(), MockGrantSet::empty());
    assert_eq!(lifecycle.failure(), None);
    assert_eq!(
        lifecycle.apply(ProcessLifecycleEvent::WalletSessionRequested),
        ProcessLifecycleOutcome::FailedClosed(
            ProcessLifecycleError::SessionTerminated,
            ProcessLifecycleAction::None,
        )
    );
}

fn assert_cleanup_failure_after_reap() {
    let mut lifecycle = ProcessLifecycle::new();
    for event in [
        ProcessLifecycleEvent::WalletSessionRequested,
        ProcessLifecycleEvent::DecoyReaped,
        ProcessLifecycleEvent::RuntimePrepared,
        ProcessLifecycleEvent::ProductGrantsInstalled(MockGrantSet::product()),
        ProcessLifecycleEvent::ConnectionAcceptedAndUnlinked,
        ProcessLifecycleEvent::ProductChildrenStartedAndParentEndpointsClosed,
        ProcessLifecycleEvent::SessionCompleted,
        ProcessLifecycleEvent::ProductChildrenReaped,
    ] {
        let _ = lifecycle.apply(event);
    }
    assert_eq!(
        lifecycle.state(),
        ProcessLifecycleState::ProductChildrenReaped
    );
    assert_eq!(
        lifecycle.apply(ProcessLifecycleEvent::CleanupFailed),
        ProcessLifecycleOutcome::FailedClosed(
            ProcessLifecycleError::CleanupFailed,
            ProcessLifecycleAction::None,
        )
    );
    assert_eq!(lifecycle.state(), ProcessLifecycleState::Terminated);
    assert_eq!(lifecycle.grants(), MockGrantSet::empty());
    assert_eq!(
        lifecycle.apply(ProcessLifecycleEvent::RuntimeRemoved),
        ProcessLifecycleOutcome::FailedClosed(
            ProcessLifecycleError::CleanupFailed,
            ProcessLifecycleAction::None,
        )
    );

    let mut after_prior_failure = ProcessLifecycle::new();
    assert_eq!(
        after_prior_failure.apply(ProcessLifecycleEvent::ConnectionLost),
        ProcessLifecycleOutcome::FailedClosed(
            ProcessLifecycleError::ConnectionLost,
            ProcessLifecycleAction::TerminateChildren,
        )
    );
    assert_eq!(
        after_prior_failure.apply(ProcessLifecycleEvent::ProductChildrenReaped),
        ProcessLifecycleOutcome::FailedClosed(
            ProcessLifecycleError::ConnectionLost,
            ProcessLifecycleAction::RemoveRuntime,
        )
    );
    assert_eq!(
        after_prior_failure.apply(ProcessLifecycleEvent::CleanupFailed),
        ProcessLifecycleOutcome::FailedClosed(
            ProcessLifecycleError::ConnectionLost,
            ProcessLifecycleAction::None,
        )
    );
    assert_eq!(
        after_prior_failure.state(),
        ProcessLifecycleState::Terminated
    );
}

fuzz_target!(|data: &[u8]| {
    assert_complete_success_path();
    assert_cleanup_failure_after_reap();
    let bounded = &data[..data.len().min(MAX_PRESENTED_BYTES)];
    assert_eq!(drive(bounded), drive(bounded));
});
