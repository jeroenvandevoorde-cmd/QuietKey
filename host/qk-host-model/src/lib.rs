//! Disposable host-only workflow policy model.
//!
//! HOST SCAFFOLD ONLY — NOT PRODUCT CODE — NOT A WALLET — NO TARGET CLAIM.
//! HOST policy model only.
//!
//! This crate defines opaque, payload-free workflow states, deterministic
//! public events, structured transition errors, and a total transition
//! function whose outcome type always exposes the security result and
//! which is fail-closed over the currently declared state/event
//! semantics only, assuming successful host execution: allocation
//! failure, panic or abort, process termination, persistence, boot
//! recovery, and target behavior are out of scope.
//! It contains no secret bytes, wallet data, cryptography,
//! parsing, file or device access, clocks, randomness, logging, network,
//! environment access, threads, processes, FFI, persistence, or hardware
//! code.
//!
//! `Restart`, `PowerLoss`, and `MediaRemoved` are SYMBOLIC HOST policy
//! events only. They model the policy decision "any such interruption
//! must terminate the workflow locked". They provide NO evidence about
//! target runtime or target-runtime integration, persistence, boot
//! recovery, removable-media handling, target hardware, or real power
//! loss.

#![forbid(unsafe_code)]

pub mod transaction_policy;

/// Opaque, payload-free workflow states. `Locked` is the safe state.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum State {
    /// The locked/safe state. Every terminal outcome ends here.
    Locked,
    /// Awake and idle; no activity in progress.
    Ready,
    /// A generic host workflow activity is in progress, before any
    /// confirmation has been requested.
    Working,
    /// The workflow is waiting for an explicit approval decision.
    Confirming,
    /// An explicit approval has been given. Distinct from `Working` so
    /// approval can never be confused with pre-confirmation activity.
    Approved,
}

/// All states — the current explicit 5-state constant enumeration
/// only; host tests iterating it are exhaustive over this declared
/// list, with no future-enum completeness claim.
pub const ALL_STATES: [State; 5] = [
    State::Locked,
    State::Ready,
    State::Working,
    State::Confirming,
    State::Approved,
];

impl State {
    /// True only for the locked/safe state.
    pub fn is_safe(self) -> bool {
        matches!(self, State::Locked)
    }
}

/// Deterministic public events.
///
/// The interruption events are symbolic HOST policy events only; see the
/// crate-level disclaimer.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Event {
    /// Leave the locked state into `Ready`.
    Wake,
    /// Begin a generic workflow activity from `Ready`.
    Begin,
    /// Ask for an explicit approval decision while `Working`.
    RequestConfirm,
    /// Approve while `Confirming`, entering `Approved`.
    Approve,
    /// Finish the approved activity from `Approved`, returning to `Ready`.
    Finish,
    /// Terminal: go to the locked state, from every state.
    Sleep,
    /// Interruption (symbolic HOST policy event): user cancellation.
    Cancel,
    /// Interruption (symbolic HOST policy event): timeout.
    Timeout,
    /// Interruption (symbolic HOST policy event): removable media removed.
    MediaRemoved,
    /// Interruption (symbolic HOST policy event): restart.
    Restart,
    /// Interruption (symbolic HOST policy event): power loss.
    PowerLoss,
}

/// All events — the current explicit 11-event constant enumeration
/// only; host tests iterating it are exhaustive over this declared
/// list, with no future-enum completeness claim.
pub const ALL_EVENTS: [Event; 11] = [
    Event::Wake,
    Event::Begin,
    Event::RequestConfirm,
    Event::Approve,
    Event::Finish,
    Event::Sleep,
    Event::Cancel,
    Event::Timeout,
    Event::MediaRemoved,
    Event::Restart,
    Event::PowerLoss,
];

impl Event {
    /// True for the interruption events. All of them are terminal.
    pub fn is_interruption(self) -> bool {
        matches!(
            self,
            Event::Cancel
                | Event::Timeout
                | Event::MediaRemoved
                | Event::Restart
                | Event::PowerLoss
        )
    }

    /// True for every terminal event: `Sleep` and each interruption.
    /// A terminal event produces a locked terminal outcome from every
    /// state.
    pub fn is_terminal(self) -> bool {
        matches!(self, Event::Sleep) || self.is_interruption()
    }
}

/// Structured transition error.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TransitionError {
    /// The event is not valid in the given state.
    InvalidTransition { state: State, event: Event },
}

/// Total transition outcome. Every variant exposes the security result:
/// either the workflow continues in an explicit state, or it has
/// terminated locked.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TransitionOutcome {
    /// The workflow continues in the given state.
    Continue(State),
    /// A terminal event (`Sleep` or any interruption) ended the workflow.
    /// The resulting state is `Locked`.
    HaltLocked,
    /// The state/event pair is invalid. The workflow is terminated and
    /// the resulting state is `Locked` — an invalid event never preserves
    /// `Working`, `Confirming`, or `Approved`.
    RejectLocked(TransitionError),
}

impl TransitionOutcome {
    /// The state after this outcome. `HaltLocked` and `RejectLocked`
    /// always resolve to `Locked`.
    pub fn resulting_state(self) -> State {
        match self {
            TransitionOutcome::Continue(next) => next,
            TransitionOutcome::HaltLocked => State::Locked,
            TransitionOutcome::RejectLocked(_) => State::Locked,
        }
    }

    /// True for `HaltLocked` and `RejectLocked`: the workflow has ended
    /// and no further events may be consumed.
    pub fn is_terminal(self) -> bool {
        !matches!(self, TransitionOutcome::Continue(_))
    }
}

/// Total, deterministic transition function, fail-closed over the
/// currently declared state/event semantics only, assuming successful
/// host execution (allocation failure, panic or abort, process
/// termination, persistence, boot recovery, and target behavior are
/// out of scope).
///
/// The only continuing transitions are the exact successful workflow:
/// `Locked+Wake→Ready`, `Ready+Begin→Working`,
/// `Working+RequestConfirm→Confirming`, `Confirming+Approve→Approved`,
/// `Approved+Finish→Ready`. `Sleep` and every interruption halt locked
/// from every state. Every other state/event pair rejects locked.
pub fn transition(state: State, event: Event) -> TransitionOutcome {
    if event.is_terminal() {
        return TransitionOutcome::HaltLocked;
    }
    match (state, event) {
        (State::Locked, Event::Wake) => TransitionOutcome::Continue(State::Ready),
        (State::Ready, Event::Begin) => TransitionOutcome::Continue(State::Working),
        (State::Working, Event::RequestConfirm) => TransitionOutcome::Continue(State::Confirming),
        (State::Confirming, Event::Approve) => TransitionOutcome::Continue(State::Approved),
        (State::Approved, Event::Finish) => TransitionOutcome::Continue(State::Ready),
        (state, event) => {
            TransitionOutcome::RejectLocked(TransitionError::InvalidTransition { state, event })
        }
    }
}
