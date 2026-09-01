#![no_main]

use libfuzzer_sys::fuzz_target;
use qk_supervisor::{
    Child, Device, MockGrantSet, ProcessRole, Supervisor, SupervisorAction, SupervisorError,
    SupervisorEvent, SupervisorOutcome, SupervisorState,
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
enum TerminationStage {
    ProductReap,
    RuntimeRemoval,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct Model {
    state: SupervisorState,
    grants: Grants,
    termination: Option<TerminationStage>,
}

impl Model {
    const fn new() -> Self {
        Self {
            state: SupervisorState::DecoyRunning,
            grants: Grants::Decoy,
            termination: None,
        }
    }

    fn fail(&mut self, error: SupervisorError) -> SupervisorOutcome {
        self.state = SupervisorState::Terminated;
        self.grants = Grants::Empty;
        self.termination = None;
        SupervisorOutcome::FailedClosed(error)
    }

    fn step(&mut self, event: SupervisorEvent) -> SupervisorOutcome {
        if self.state == SupervisorState::Terminated {
            return SupervisorOutcome::FailedClosed(SupervisorError::SessionTerminated);
        }
        match event {
            SupervisorEvent::ChildLost(_) => return self.fail(SupervisorError::ChildLost),
            SupervisorEvent::ConnectionLost => return self.fail(SupervisorError::ConnectionLost),
            SupervisorEvent::StepFailed => return self.fail(SupervisorError::StepFailed),
            SupervisorEvent::CleanupFailed => return self.fail(SupervisorError::CleanupFailed),
            _ => {}
        }
        match (self.state, event) {
            (SupervisorState::DecoyRunning, SupervisorEvent::WalletSessionRequested) => {
                self.state = SupervisorState::DecoyStopRequested;
                SupervisorOutcome::Advanced(SupervisorAction::StopDecoy)
            }
            (SupervisorState::DecoyStopRequested, SupervisorEvent::DecoyReaped) => {
                self.state = SupervisorState::DecoyReaped;
                self.grants = Grants::Empty;
                SupervisorOutcome::Advanced(SupervisorAction::PrepareRuntime)
            }
            (SupervisorState::DecoyReaped, SupervisorEvent::RuntimePrepared) => {
                self.state = SupervisorState::RuntimePrepared;
                SupervisorOutcome::Advanced(SupervisorAction::InstallProductGrants)
            }
            (SupervisorState::RuntimePrepared, SupervisorEvent::ProductGrantsInstalled(grants)) => {
                if grants != MockGrantSet::product() {
                    self.fail(SupervisorError::GrantConflict)
                } else {
                    self.state = SupervisorState::ProductGrantsInstalled;
                    self.grants = Grants::Product;
                    SupervisorOutcome::Advanced(SupervisorAction::StartCoreAndIo)
                }
            }
            (SupervisorState::ProductGrantsInstalled, SupervisorEvent::ProductChildrenStarted) => {
                self.state = SupervisorState::ProductChildrenStarted;
                SupervisorOutcome::Advanced(SupervisorAction::EstablishConnection)
            }
            (SupervisorState::ProductChildrenStarted, SupervisorEvent::ConnectionEstablished) => {
                self.state = SupervisorState::SessionActive;
                SupervisorOutcome::Advanced(SupervisorAction::None)
            }
            (SupervisorState::SessionActive, SupervisorEvent::NormalClosureRequested) => {
                self.state = SupervisorState::Terminating;
                self.grants = Grants::Empty;
                self.termination = Some(TerminationStage::ProductReap);
                SupervisorOutcome::Advanced(SupervisorAction::TerminateProductChildren)
            }
            (SupervisorState::Terminating, SupervisorEvent::ProductChildrenReaped)
                if self.termination == Some(TerminationStage::ProductReap) =>
            {
                self.termination = Some(TerminationStage::RuntimeRemoval);
                SupervisorOutcome::Advanced(SupervisorAction::RemoveRuntime)
            }
            (SupervisorState::Terminating, SupervisorEvent::RuntimeRemoved)
                if self.termination == Some(TerminationStage::RuntimeRemoval) =>
            {
                self.state = SupervisorState::Terminated;
                self.termination = None;
                SupervisorOutcome::Advanced(SupervisorAction::None)
            }
            (
                SupervisorState::DecoyRunning | SupervisorState::DecoyStopRequested,
                SupervisorEvent::RuntimePrepared
                | SupervisorEvent::ProductGrantsInstalled(_)
                | SupervisorEvent::ProductChildrenStarted
                | SupervisorEvent::ConnectionEstablished,
            ) => self.fail(SupervisorError::DecoyNotReaped),
            _ => self.fail(SupervisorError::InvalidTransition),
        }
    }
}

fn error_name(error: SupervisorError) -> &'static str {
    match error {
        SupervisorError::InvalidTransition => "InvalidTransition",
        SupervisorError::DecoyNotReaped => "DecoyNotReaped",
        SupervisorError::GrantConflict => "GrantConflict",
        SupervisorError::ChildLost => "ChildLost",
        SupervisorError::ConnectionLost => "ConnectionLost",
        SupervisorError::StepFailed => "StepFailed",
        SupervisorError::CleanupFailed => "CleanupFailed",
        SupervisorError::SessionTerminated => "SessionTerminated",
    }
}

fn event(command: &[u8]) -> SupervisorEvent {
    let selector = command.first().copied().unwrap_or(0) % 15;
    match selector {
        0 => SupervisorEvent::WalletSessionRequested,
        1 => SupervisorEvent::DecoyReaped,
        2 => SupervisorEvent::RuntimePrepared,
        3 => SupervisorEvent::ProductGrantsInstalled(MockGrantSet::from_masks(
            command.get(1).copied().unwrap_or(0),
            command.get(2).copied().unwrap_or(0),
            command.get(3).copied().unwrap_or(0),
        )),
        4 => SupervisorEvent::ProductChildrenStarted,
        5 => SupervisorEvent::ConnectionEstablished,
        6 => SupervisorEvent::NormalClosureRequested,
        7 => SupervisorEvent::ProductChildrenReaped,
        8 => SupervisorEvent::RuntimeRemoved,
        9 => SupervisorEvent::ChildLost(Child::Decoy),
        10 => SupervisorEvent::ChildLost(Child::Core),
        11 => SupervisorEvent::ChildLost(Child::Io),
        12 => SupervisorEvent::ConnectionLost,
        13 => SupervisorEvent::StepFailed,
        14 => SupervisorEvent::CleanupFailed,
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

fn assert_state(supervisor: &Supervisor, model: Model) {
    assert_eq!(supervisor.state(), model.state);
    for device in DEVICES {
        assert_eq!(
            supervisor.grants().owner(device),
            expected_owner(model.grants, device)
        );
    }
}

fn drive(data: &[u8]) -> Vec<SupervisorOutcome> {
    let mut supervisor = Supervisor::new();
    let mut model = Model::new();
    assert_state(&supervisor, model);
    let mut outcomes = Vec::with_capacity(data.len().div_ceil(4));
    for command in data.chunks(4) {
        let event = event(command);
        let expected = model.step(event);
        let actual = supervisor.apply(event);
        assert_eq!(actual, expected);
        if let SupervisorOutcome::FailedClosed(error) = actual {
            assert_eq!(error.to_string(), error_name(error));
        }
        assert_state(&supervisor, model);
        outcomes.push(actual);
    }
    outcomes
}

fuzz_target!(|data: &[u8]| {
    let bounded = &data[..data.len().min(MAX_PRESENTED_BYTES)];
    assert_eq!(drive(bounded), drive(bounded));
});
