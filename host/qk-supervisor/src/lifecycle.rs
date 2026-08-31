//! Total typed lifecycle and mock-device-grant state.

use core::fmt;

/// Exact public lifecycle states fixed by QK-DEC-142.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SupervisorState {
    DecoyRunning,
    DecoyStopRequested,
    DecoyReaped,
    RuntimePrepared,
    ProductGrantsInstalled,
    ProductChildrenStarted,
    SessionActive,
    Terminating,
    Terminated,
}

/// Child roles known to the lifecycle owner.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Child {
    Decoy,
    Core,
    Io,
}

/// Mock-only device capabilities.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Device {
    Display,
    Keypad,
    CardSlot,
    Camera,
    RemovableMedia,
}

impl Device {
    const fn mask(self) -> u8 {
        match self {
            Self::Display => 1 << 0,
            Self::Keypad => 1 << 1,
            Self::CardSlot => 1 << 2,
            Self::Camera => 1 << 3,
            Self::RemovableMedia => 1 << 4,
        }
    }
}

const ALL_DEVICE_MASK: u8 = (1 << 5) - 1;
const DECOY_MASK: u8 = Device::Display.mask() | Device::Keypad.mask();
const CORE_MASK: u8 = DECOY_MASK | Device::CardSlot.mask();
const IO_MASK: u8 = Device::Camera.mask() | Device::RemovableMedia.mask();

/// The only possible mock grant owners.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ProcessRole {
    Decoy,
    Core,
    Io,
}

/// Three fixed-size mock capability masks.
///
/// Raw construction exists so hostile and fuzz tests can present conflicts;
/// the supervisor accepts only the exact ratified sets at their exact phase.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct MockGrantSet {
    decoy: u8,
    core: u8,
    io: u8,
}

impl MockGrantSet {
    /// Construct a presented mock set from three raw masks.
    pub const fn from_masks(decoy: u8, core: u8, io: u8) -> Self {
        Self { decoy, core, io }
    }

    /// Initial exact Display-plus-Keypad decoy set.
    pub const fn decoy() -> Self {
        Self::from_masks(DECOY_MASK, 0, 0)
    }

    /// Exact post-reap product set.
    pub const fn product() -> Self {
        Self::from_masks(0, CORE_MASK, IO_MASK)
    }

    /// Empty grant set.
    pub const fn empty() -> Self {
        Self::from_masks(0, 0, 0)
    }

    /// Return the sole owner of one device, or `None` when ungranted or when
    /// the presented set conflicts.
    pub const fn owner(&self, device: Device) -> Option<ProcessRole> {
        let bit = device.mask();
        let decoy = self.decoy & bit != 0;
        let core = self.core & bit != 0;
        let io = self.io & bit != 0;
        match (decoy, core, io) {
            (true, false, false) => Some(ProcessRole::Decoy),
            (false, true, false) => Some(ProcessRole::Core),
            (false, false, true) => Some(ProcessRole::Io),
            _ => None,
        }
    }

    const fn is_well_formed(&self) -> bool {
        let known = self.decoy | self.core | self.io;
        known & !ALL_DEVICE_MASK == 0
            && self.decoy & self.core == 0
            && self.decoy & self.io == 0
            && self.core & self.io == 0
    }
}

/// Exact externally confirmed lifecycle facts.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SupervisorEvent {
    WalletSessionRequested,
    DecoyReaped,
    RuntimePrepared,
    ProductGrantsInstalled(MockGrantSet),
    ProductChildrenStarted,
    ConnectionEstablished,
    NormalClosureRequested,
    ProductChildrenReaped,
    RuntimeRemoved,
    ChildLost(Child),
    ConnectionLost,
    StepFailed,
    CleanupFailed,
}

/// Commands emitted to the later HOST harness or its mock boundary.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SupervisorAction {
    StopDecoy,
    PrepareRuntime,
    InstallProductGrants,
    StartCoreAndIo,
    EstablishConnection,
    TerminateProductChildren,
    RemoveRuntime,
    None,
}

/// Closed supervisor rejection vocabulary.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SupervisorError {
    InvalidTransition,
    DecoyNotReaped,
    GrantConflict,
    ChildLost,
    ConnectionLost,
    StepFailed,
    CleanupFailed,
    SessionTerminated,
}

impl fmt::Display for SupervisorError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::InvalidTransition => "InvalidTransition",
            Self::DecoyNotReaped => "DecoyNotReaped",
            Self::GrantConflict => "GrantConflict",
            Self::ChildLost => "ChildLost",
            Self::ConnectionLost => "ConnectionLost",
            Self::StepFailed => "StepFailed",
            Self::CleanupFailed => "CleanupFailed",
            Self::SessionTerminated => "SessionTerminated",
        })
    }
}

impl std::error::Error for SupervisorError {}

/// One total transition outcome.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SupervisorOutcome {
    Advanced(SupervisorAction),
    FailedClosed(SupervisorError),
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum TerminationStage {
    AwaitingProductReap,
    AwaitingRuntimeRemoval,
}

/// HOST-only lifecycle and exact mock-grant owner.
pub struct Supervisor {
    state: SupervisorState,
    grants: MockGrantSet,
    termination_stage: Option<TerminationStage>,
}

impl Supervisor {
    /// Start in calculator decoy mode with only Display and Keypad granted.
    pub const fn new() -> Self {
        Self {
            state: SupervisorState::DecoyRunning,
            grants: MockGrantSet::decoy(),
            termination_stage: None,
        }
    }

    /// Current public lifecycle state.
    pub const fn state(&self) -> SupervisorState {
        self.state
    }

    /// Current mock grants.
    pub const fn grants(&self) -> MockGrantSet {
        self.grants
    }

    /// Apply exactly one confirmed fact and return exactly one action or one
    /// fail-closed named outcome.
    pub fn apply(&mut self, event: SupervisorEvent) -> SupervisorOutcome {
        if self.state == SupervisorState::Terminated {
            return SupervisorOutcome::FailedClosed(SupervisorError::SessionTerminated);
        }

        let failure = match event {
            SupervisorEvent::ChildLost(_) => Some(SupervisorError::ChildLost),
            SupervisorEvent::ConnectionLost => Some(SupervisorError::ConnectionLost),
            SupervisorEvent::StepFailed => Some(SupervisorError::StepFailed),
            SupervisorEvent::CleanupFailed => Some(SupervisorError::CleanupFailed),
            _ => None,
        };
        if let Some(error) = failure {
            return self.fail_closed(error);
        }

        match (self.state, event) {
            (SupervisorState::DecoyRunning, SupervisorEvent::WalletSessionRequested) => {
                self.state = SupervisorState::DecoyStopRequested;
                SupervisorOutcome::Advanced(SupervisorAction::StopDecoy)
            }
            (SupervisorState::DecoyStopRequested, SupervisorEvent::DecoyReaped) => {
                self.grants = MockGrantSet::empty();
                self.state = SupervisorState::DecoyReaped;
                SupervisorOutcome::Advanced(SupervisorAction::PrepareRuntime)
            }
            (SupervisorState::DecoyReaped, SupervisorEvent::RuntimePrepared) => {
                self.state = SupervisorState::RuntimePrepared;
                SupervisorOutcome::Advanced(SupervisorAction::InstallProductGrants)
            }
            (SupervisorState::RuntimePrepared, SupervisorEvent::ProductGrantsInstalled(grants)) => {
                if !grants.is_well_formed() || grants != MockGrantSet::product() {
                    return self.fail_closed(SupervisorError::GrantConflict);
                }
                self.grants = grants;
                self.state = SupervisorState::ProductGrantsInstalled;
                SupervisorOutcome::Advanced(SupervisorAction::StartCoreAndIo)
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
                self.grants = MockGrantSet::empty();
                self.termination_stage = Some(TerminationStage::AwaitingProductReap);
                self.state = SupervisorState::Terminating;
                SupervisorOutcome::Advanced(SupervisorAction::TerminateProductChildren)
            }
            (SupervisorState::Terminating, SupervisorEvent::ProductChildrenReaped)
                if self.termination_stage == Some(TerminationStage::AwaitingProductReap) =>
            {
                self.termination_stage = Some(TerminationStage::AwaitingRuntimeRemoval);
                SupervisorOutcome::Advanced(SupervisorAction::RemoveRuntime)
            }
            (SupervisorState::Terminating, SupervisorEvent::RuntimeRemoved)
                if self.termination_stage == Some(TerminationStage::AwaitingRuntimeRemoval) =>
            {
                self.termination_stage = None;
                self.state = SupervisorState::Terminated;
                SupervisorOutcome::Advanced(SupervisorAction::None)
            }
            (state, event) if Self::attempts_product_work_before_reap(state, event) => {
                self.fail_closed(SupervisorError::DecoyNotReaped)
            }
            _ => self.fail_closed(SupervisorError::InvalidTransition),
        }
    }

    const fn attempts_product_work_before_reap(
        state: SupervisorState,
        event: SupervisorEvent,
    ) -> bool {
        matches!(
            state,
            SupervisorState::DecoyRunning | SupervisorState::DecoyStopRequested
        ) && matches!(
            event,
            SupervisorEvent::RuntimePrepared
                | SupervisorEvent::ProductGrantsInstalled(_)
                | SupervisorEvent::ProductChildrenStarted
                | SupervisorEvent::ConnectionEstablished
        )
    }

    fn fail_closed(&mut self, error: SupervisorError) -> SupervisorOutcome {
        self.grants = MockGrantSet::empty();
        self.termination_stage = None;
        self.state = SupervisorState::Terminated;
        SupervisorOutcome::FailedClosed(error)
    }
}

impl Default for Supervisor {
    fn default() -> Self {
        Self::new()
    }
}
