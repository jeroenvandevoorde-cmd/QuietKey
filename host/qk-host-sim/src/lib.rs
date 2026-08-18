//! Library-only deterministic scenario runner over `qk-host-model`.
//!
//! HOST SCAFFOLD ONLY — NOT PRODUCT CODE — NOT A WALLET SIMULATOR —
//! NO TARGET CLAIM. HOST policy model only: interruption events are
//! symbolic; no runtime, persistence, boot-recovery, removable-media,
//! target, or real power-loss evidence is produced.
//!
//! No binary, server, UI, REPL, stdin, files, environment, network,
//! database, service, port, preview, deployment, or background process.

#![forbid(unsafe_code)]

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

/// Run a scenario: apply each event in order, fail-closed.
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
