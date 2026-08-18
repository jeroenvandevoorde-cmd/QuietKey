//! Host-only deterministic tests over the disposable HOST policy model.
//! HOST evidence only — no target claim, no wallet data, no secrets.
//! HOST policy model only: no claim is made about real restart,
//! power-loss, or removable-media behavior; those events are symbolic.

use qk_host_model::{
    transition, Event, State, TransitionError, TransitionOutcome, ALL_EVENTS, ALL_STATES,
};
use qk_host_sim::run_scenario;

/// The five terminal events: Sleep plus every interruption.
const TERMINAL_EVENTS: [Event; 6] = [
    Event::Sleep,
    Event::Cancel,
    Event::Timeout,
    Event::MediaRemoved,
    Event::Restart,
    Event::PowerLoss,
];

/// The single authoritative expected-outcome table for every
/// state/event pair of the HOST policy model.
fn expected_outcome(state: State, event: Event) -> TransitionOutcome {
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

/// Test 1 — happy path of the HOST policy model, exact intermediate
/// states, zero rejection, final Locked.
#[test]
fn host_policy_happy_path_exact_states() {
    let events = [
        Event::Wake,
        Event::Begin,
        Event::RequestConfirm,
        Event::Approve,
        Event::Finish,
        Event::Sleep,
    ];
    let outcome = run_scenario(State::Locked, &events);
    assert_eq!(outcome.rejected, 0);
    assert_eq!(outcome.unprocessed, 0);
    assert_eq!(outcome.final_state, State::Locked);
    assert_eq!(outcome.steps.len(), 6);
    let expected = [
        (State::Locked, TransitionOutcome::Continue(State::Ready)),
        (State::Ready, TransitionOutcome::Continue(State::Working)),
        (
            State::Working,
            TransitionOutcome::Continue(State::Confirming),
        ),
        (
            State::Confirming,
            TransitionOutcome::Continue(State::Approved),
        ),
        (State::Approved, TransitionOutcome::Continue(State::Ready)),
        (State::Ready, TransitionOutcome::HaltLocked),
    ];
    for (i, (before, out)) in expected.iter().enumerate() {
        assert_eq!(outcome.steps[i].before, *before);
        assert_eq!(outcome.steps[i].event, events[i]);
        assert_eq!(outcome.steps[i].outcome, *out);
    }
}

/// Test 2 — Finish from Working is removed: RejectLocked, final Locked,
/// and every later queued event remains unprocessed.
#[test]
fn host_policy_finish_from_working_rejects_locked_and_stops() {
    let events = [
        Event::Wake,
        Event::Begin,
        Event::Finish,
        Event::RequestConfirm,
        Event::Approve,
    ];
    let outcome = run_scenario(State::Locked, &events);
    assert_eq!(outcome.steps.len(), 3);
    assert_eq!(
        outcome.steps[2].outcome,
        TransitionOutcome::RejectLocked(TransitionError::InvalidTransition {
            state: State::Working,
            event: Event::Finish,
        })
    );
    assert_eq!(outcome.rejected, 1);
    assert_eq!(outcome.final_state, State::Locked);
    assert_eq!(outcome.unprocessed, 2);
}

/// Tests 3 and 6 — explicit expected-table assertion for EVERY
/// state/event pair (not merely totality): the exact allowed table
/// continues, every terminal event halts locked, and every other pair
/// rejects locked with the matching structured error.
#[test]
fn host_policy_every_pair_matches_expected_table() {
    let mut allowed = 0;
    let mut halted = 0;
    let mut rejected = 0;
    for state in ALL_STATES {
        for event in ALL_EVENTS {
            let actual = transition(state, event);
            assert_eq!(
                actual,
                expected_outcome(state, event),
                "pair ({state:?}, {event:?})"
            );
            match actual {
                TransitionOutcome::Continue(next) => {
                    allowed += 1;
                    assert!(ALL_STATES.contains(&next));
                }
                TransitionOutcome::HaltLocked => {
                    halted += 1;
                    assert_eq!(actual.resulting_state(), State::Locked);
                }
                TransitionOutcome::RejectLocked(TransitionError::InvalidTransition {
                    state: s,
                    event: e,
                }) => {
                    rejected += 1;
                    assert_eq!(s, state);
                    assert_eq!(e, event);
                    assert_eq!(actual.resulting_state(), State::Locked);
                }
            }
        }
    }
    // 5 states x 11 events = 55 pairs: 5 allowed, 5 x 6 terminal halts,
    // 20 rejections. No pair ever preserves Working/Confirming/Approved.
    assert_eq!(allowed, 5);
    assert_eq!(halted, 30);
    assert_eq!(rejected, 20);
    assert_eq!(allowed + halted + rejected, 55);
}

/// Test 4 — for every state and every terminal event, a queued
/// [Wake, Begin] suffix is NEVER consumed: exactly one processed step,
/// final Locked, suffix unprocessed. A later Wake is only ever a new
/// scenario beginning from Locked.
#[test]
fn host_policy_terminal_events_stop_consuming_queued_events() {
    for state in ALL_STATES {
        for terminal in TERMINAL_EVENTS {
            assert!(terminal.is_terminal());
            let events = [terminal, Event::Wake, Event::Begin];
            let outcome = run_scenario(state, &events);
            assert_eq!(outcome.steps.len(), 1, "({state:?}, {terminal:?})");
            assert_eq!(outcome.steps[0].outcome, TransitionOutcome::HaltLocked);
            assert_eq!(outcome.final_state, State::Locked);
            assert!(outcome.final_state.is_safe());
            assert_eq!(outcome.unprocessed, 2);
            // The stale suffix must instead be run as a NEW scenario
            // starting from Locked.
            let fresh = run_scenario(State::Locked, &[Event::Wake, Event::Begin]);
            assert_eq!(fresh.final_state, State::Working);
            assert_eq!(fresh.unprocessed, 0);
        }
    }
}

/// Test 5 — determinism: identical start state and event sequence give
/// an identical outcome and identical step trace.
#[test]
fn host_policy_identical_runs_are_identical() {
    let scenarios: [(State, &[Event]); 4] = [
        (
            State::Locked,
            &[
                Event::Wake,
                Event::Begin,
                Event::RequestConfirm,
                Event::Approve,
                Event::Finish,
                Event::Sleep,
            ],
        ),
        (State::Locked, &[Event::Wake, Event::Begin, Event::Finish]),
        (State::Confirming, &[Event::PowerLoss, Event::Wake]),
        (State::Approved, &[Event::Approve, Event::Begin]),
    ];
    for (start, events) in scenarios {
        let a = run_scenario(start, events);
        let b = run_scenario(start, events);
        assert_eq!(a, b);
        assert_eq!(a.steps, b.steps);
    }
}
