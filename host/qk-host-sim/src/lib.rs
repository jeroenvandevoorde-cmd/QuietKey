//! Library-only deterministic scenario runner over `qk-host-model`.
//!
//! HOST SCAFFOLD ONLY — NOT PRODUCT CODE — NOT A WALLET SIMULATOR —
//! NO TARGET CLAIM. HOST policy model only: interruption events are
//! symbolic; no target runtime or target-runtime integration, and no
//! persistence, boot-recovery, removable-media,
//! target, or real power-loss evidence is produced.
//!
//! No binary, server, UI, REPL, stdin, files, environment, network,
//! database, service, port, preview, deployment, or background process.

#![forbid(unsafe_code)]

use qk_host_model::transaction_policy::{
    transaction_transition, TransactionEvent, TransactionState, TransactionTransitionOutcome,
};
use qk_host_model::{transition, Event, State, TransitionOutcome};

/// Result of applying one event during a scenario.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Step {
    /// State before the event was applied.
    pub before: State,
    /// The event that was applied.
    pub event: Event,
    /// The transition outcome, always exposing the security result.
    pub outcome: TransitionOutcome,
}

/// Deterministic outcome of running a whole scenario.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ScenarioOutcome {
    /// The state after the last processed event. After a `HaltLocked`
    /// or `RejectLocked` outcome this is always `Locked`.
    pub final_state: State,
    /// One record per PROCESSED event, in order. Events queued after a
    /// terminal outcome are never processed and never appear here.
    pub steps: Vec<Step>,
    /// Count of queued events left unprocessed because a terminal
    /// outcome ended the scenario first.
    pub unprocessed: usize,
    /// Count of processed events whose outcome was `RejectLocked`.
    /// Because rejection is terminal, this is always 0 or 1.
    pub rejected: usize,
}

/// Run a scenario: apply each event in order. Fail-closed over the
/// declared state/event semantics only, assuming successful host
/// execution: allocation failure, panic or abort, process
/// termination, persistence, boot recovery, and target behavior are
/// out of scope, and the returned `Vec` of steps is host-test
/// plumbing, so no resource-failure behavior is claimed.
///
/// On `HaltLocked` or `RejectLocked` the scenario state is set to
/// `Locked` and the runner STOPS consuming queued events; the remaining
/// events are counted as unprocessed. A later `Wake` can only ever be
/// the beginning of a NEW scenario started from `Locked`; it is never
/// consumed as a stale suffix of an interrupted scenario.
pub fn run_scenario(start: State, events: &[Event]) -> ScenarioOutcome {
    let mut state = start;
    let mut steps = Vec::with_capacity(events.len());
    let mut rejected = 0;
    let mut processed = 0;
    for &event in events {
        let outcome = transition(state, event);
        steps.push(Step {
            before: state,
            event,
            outcome,
        });
        processed += 1;
        state = outcome.resulting_state();
        if outcome.is_terminal() {
            if matches!(outcome, TransitionOutcome::RejectLocked(_)) {
                rejected += 1;
            }
            break;
        }
    }
    ScenarioOutcome {
        final_state: state,
        steps,
        unprocessed: events.len() - processed,
        rejected,
    }
}

/// Result of applying one transaction event during a scenario.
/// Records the triggering event and its result.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TransactionStep {
    /// State before the event was applied.
    pub before: TransactionState,
    /// The event that was applied.
    pub event: TransactionEvent,
    /// The transition outcome, always exposing the security result.
    pub outcome: TransactionTransitionOutcome,
}

/// Deterministic outcome of running a whole transaction scenario.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TransactionScenarioOutcome {
    /// The state after the last processed event. After a `HaltLocked`
    /// or `RejectLocked` outcome this is always `Locked`.
    pub final_state: TransactionState,
    /// One record per PROCESSED event, in order. Events queued after a
    /// terminal outcome are never processed and never appear here.
    pub steps: Vec<TransactionStep>,
    /// Count of queued events left unprocessed because a terminal
    /// outcome ended the scenario first.
    pub unprocessed: usize,
    /// Count of processed events whose outcome was `RejectLocked`.
    /// Because rejection is terminal, this is always 0 or 1.
    pub rejected: usize,
}

/// Run the INTENDED transaction authorization workflow: accepts only
/// events and ALWAYS begins at `TransactionState::Locked`. No
/// caller-supplied start state exists in this API.
///
/// Deterministic, with no I/O and no hidden mutable or global state;
/// fail-closed over the declared state/event semantics, assuming
/// successful host execution. Allocation exhaustion, panic/abort,
/// process termination, persistence, boot recovery, and target
/// behavior are outside this model. This wrapper is a HOST policy
/// model and test harness, NOT an authorization boundary.
///
/// Approval property (within one correctly outcome-threaded invocation
/// of this function, which begins `Locked`; single-use PER
/// AUTHORIZATION CYCLE, not per function invocation): `Approve`
/// continues only from `Confirming`. An immediate duplicate `Approve`,
/// or any stale `Approve` before a fresh symbolic `BeginValidation` ->
/// `ValidationPassed` -> `ReviewConstructed` -> `RequestApproval`
/// sequence reaches `Confirming`, rejects locked and the remaining
/// suffix is not consumed. After a completed cycle returns to `Ready`
/// through the signed completion path, an `Approve` following a new
/// full validation/review/request sequence begins a NEW authorization
/// cycle in the SAME invocation and is not replay. This is symbolic
/// order only; no payload, freshness, or identity fact is proven. No
/// cross-call guarantee exists.
///
/// The returned `Vec` of steps is host-test plumbing, not a bounded
/// production mechanism; no resource-failure behavior is claimed.
///
/// On `HaltLocked` or `RejectLocked` the scenario state resolves to
/// `Locked` and the runner STOPS consuming queued events; the
/// remaining suffix events are counted as unprocessed. Any failure or
/// interruption invalidates the entire authorization: a later `Wake`
/// can only ever be the beginning of a completely NEW workflow
/// invocation (which itself begins at `Locked`); it is never consumed
/// as a stale suffix of an interrupted scenario.
pub fn run_transaction_workflow(events: &[TransactionEvent]) -> TransactionScenarioOutcome {
    let mut state = TransactionState::Locked;
    let mut steps = Vec::with_capacity(events.len());
    let mut rejected = 0;
    let mut processed = 0;
    for &event in events {
        let outcome = transaction_transition(state, event);
        steps.push(TransactionStep {
            before: state,
            event,
            outcome,
        });
        processed += 1;
        state = outcome.resulting_state();
        if outcome.is_terminal() {
            if matches!(outcome, TransactionTransitionOutcome::RejectLocked(_)) {
                rejected += 1;
            }
            break;
        }
    }
    TransactionScenarioOutcome {
        final_state: state,
        steps,
        unprocessed: events.len() - processed,
        rejected,
    }
}
