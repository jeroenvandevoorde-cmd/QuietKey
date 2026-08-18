//! Tests for the HOST policy model of transaction authorization
//! ordering — exhaustive ONLY over the current explicit 11-state and
//! 23-event constants (a single test iterates all 253 declared pairs;
//! there are not 253 tests, and no future-enum completeness is
//! claimed).
//!
//! HOST policy model only — HOST SCAFFOLD ONLY — NOT PRODUCT CODE —
//! NO TARGET CLAIM. These tests exercise a payload-free symbolic
//! policy model. They do NOT execute any canonical QK-TST row and do
//! NOT constitute Gate C evidence or evidence of any real validation,
//! review, physical approval, revalidation, signing, signature
//! verification, or output parsing.

use qk_host_model::transaction_policy::{
    transaction_transition, TransactionEvent, TransactionState, TransactionTransitionError,
    TransactionTransitionOutcome, ALL_TRANSACTION_EVENTS, ALL_TRANSACTION_STATES,
};
use qk_host_sim::{run_transaction_workflow, TransactionScenarioOutcome, TransactionStep};

use TransactionEvent as E;
use TransactionState as S;
use TransactionTransitionOutcome as O;

/// PRIVATE TEST-ONLY arbitrary-start runner, local to this test file.
/// It exists solely for the explicitly exhaustive every-state coverage
/// below (exhaustive only over the current declared constants); the
/// caller-supplied start state's provenance is unchecked, so it proves
/// no replay or provenance property. The normal library exports no
/// arbitrary-start workflow/scenario API; intended workflows use the
/// Locked-start `run_transaction_workflow`.
fn run_from_state_test_only(
    start: TransactionState,
    events: &[TransactionEvent],
) -> TransactionScenarioOutcome {
    let mut state = start;
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

/// The exact happy-path event sequence from `Locked`.
const HAPPY_PATH: [E; 11] = [
    E::Wake,
    E::BeginValidation,
    E::ValidationPassed,
    E::ReviewConstructed,
    E::RequestApproval,
    E::Approve,
    E::BeginRevalidation,
    E::RevalidationPassed,
    E::SignatureProduced,
    E::SignatureVerified,
    E::OutputReparsed,
];

/// The state expected AFTER each happy-path event, in order.
const HAPPY_STATES: [S; 11] = [
    S::Ready,
    S::Validating,
    S::ConstructingReview,
    S::ReviewReady,
    S::Confirming,
    S::Approved,
    S::Revalidating,
    S::SignPermitted,
    S::VerifyingSignature,
    S::ReparsingOutput,
    S::Ready,
];

/// The exact 11 continuing (state, event, next-state) cells.
const CONTINUING: [(S, E, S); 11] = [
    (S::Locked, E::Wake, S::Ready),
    (S::Ready, E::BeginValidation, S::Validating),
    (S::Validating, E::ValidationPassed, S::ConstructingReview),
    (S::ConstructingReview, E::ReviewConstructed, S::ReviewReady),
    (S::ReviewReady, E::RequestApproval, S::Confirming),
    (S::Confirming, E::Approve, S::Approved),
    (S::Approved, E::BeginRevalidation, S::Revalidating),
    (S::Revalidating, E::RevalidationPassed, S::SignPermitted),
    (
        S::SignPermitted,
        E::SignatureProduced,
        S::VerifyingSignature,
    ),
    (
        S::VerifyingSignature,
        E::SignatureVerified,
        S::ReparsingOutput,
    ),
    (S::ReparsingOutput, E::OutputReparsed, S::Ready),
];

/// The 12 terminal events: Sleep, 5 interruptions, 6 explicit failures.
const TERMINAL_EVENTS: [E; 12] = [
    E::Sleep,
    E::Cancel,
    E::Timeout,
    E::MediaRemoved,
    E::Restart,
    E::PowerLoss,
    E::ValidationFailed,
    E::ReviewConstructionFailed,
    E::ApprovalRejected,
    E::RevalidationFailed,
    E::SignatureInvalid,
    E::OutputInvalid,
];

fn continuing_next(state: S, event: E) -> Option<S> {
    CONTINUING
        .iter()
        .find(|(s, e, _)| *s == state && *e == event)
        .map(|(_, _, n)| *n)
}

/// Test 1: exact happy path — every intermediate state asserted, zero
/// rejection, final `Ready`.
#[test]
fn happy_path_exact_intermediate_states() {
    let out = run_transaction_workflow(&HAPPY_PATH);
    assert_eq!(out.steps.len(), 11);
    assert_eq!(out.unprocessed, 0);
    assert_eq!(out.rejected, 0);
    let mut before = S::Locked;
    for (i, step) in out.steps.iter().enumerate() {
        assert_eq!(step.before, before);
        assert_eq!(step.event, HAPPY_PATH[i]);
        assert_eq!(step.outcome, O::Continue(HAPPY_STATES[i]));
        before = HAPPY_STATES[i];
    }
    assert_eq!(out.final_state, S::Ready);
}

/// Test 2: `SignatureProduced` before approval -> `RejectLocked`,
/// final `Locked`, suffix unprocessed.
#[test]
fn signature_before_approval_rejects() {
    let events = [
        E::Wake,
        E::BeginValidation,
        E::ValidationPassed,
        E::ReviewConstructed,
        E::SignatureProduced, // premature: state is ReviewReady, no approval
        E::SignatureVerified,
        E::OutputReparsed,
    ];
    let out = run_transaction_workflow(&events);
    assert_eq!(out.steps.len(), 5);
    assert_eq!(
        out.steps[4].outcome,
        O::RejectLocked(TransactionTransitionError::InvalidTransition {
            state: S::ReviewReady,
            event: E::SignatureProduced,
        })
    );
    assert_eq!(out.final_state, S::Locked);
    assert_eq!(out.unprocessed, 2);
    assert_eq!(out.rejected, 1);
}

/// Test 3: `SignatureProduced` after approval but before revalidation
/// -> `RejectLocked`, final `Locked`, suffix unprocessed.
#[test]
fn signature_after_approval_before_revalidation_rejects() {
    let events = [
        E::Wake,
        E::BeginValidation,
        E::ValidationPassed,
        E::ReviewConstructed,
        E::RequestApproval,
        E::Approve,
        E::SignatureProduced, // premature: state is Approved, not SignPermitted
        E::SignatureVerified,
        E::OutputReparsed,
    ];
    let out = run_transaction_workflow(&events);
    assert_eq!(out.steps.len(), 7);
    assert_eq!(
        out.steps[6].outcome,
        O::RejectLocked(TransactionTransitionError::InvalidTransition {
            state: S::Approved,
            event: E::SignatureProduced,
        })
    );
    assert_eq!(out.final_state, S::Locked);
    assert_eq!(out.unprocessed, 2);
    assert_eq!(out.rejected, 1);
}

/// Test 4: `SignatureVerified` before `SignatureProduced` ->
/// `RejectLocked`.
#[test]
fn signature_verified_before_produced_rejects() {
    let events = [
        E::Wake,
        E::BeginValidation,
        E::ValidationPassed,
        E::ReviewConstructed,
        E::RequestApproval,
        E::Approve,
        E::BeginRevalidation,
        E::RevalidationPassed,
        E::SignatureVerified, // premature: state is SignPermitted, nothing produced
        E::OutputReparsed,
    ];
    let out = run_transaction_workflow(&events);
    assert_eq!(out.steps.len(), 9);
    assert_eq!(
        out.steps[8].outcome,
        O::RejectLocked(TransactionTransitionError::InvalidTransition {
            state: S::SignPermitted,
            event: E::SignatureVerified,
        })
    );
    assert_eq!(out.final_state, S::Locked);
    assert_eq!(out.unprocessed, 1);
}

/// Test 5: `OutputReparsed` before `SignatureVerified` ->
/// `RejectLocked`.
#[test]
fn output_reparsed_before_verified_rejects() {
    let events = [
        E::Wake,
        E::BeginValidation,
        E::ValidationPassed,
        E::ReviewConstructed,
        E::RequestApproval,
        E::Approve,
        E::BeginRevalidation,
        E::RevalidationPassed,
        E::SignatureProduced,
        E::OutputReparsed, // premature: state is VerifyingSignature
    ];
    let out = run_transaction_workflow(&events);
    assert_eq!(out.steps.len(), 10);
    assert_eq!(
        out.steps[9].outcome,
        O::RejectLocked(TransactionTransitionError::InvalidTransition {
            state: S::VerifyingSignature,
            event: E::OutputReparsed,
        })
    );
    assert_eq!(out.final_state, S::Locked);
    assert_eq!(out.unprocessed, 0);
}

/// Stale `Approve` after a completed cycle has returned `Ready`, but
/// BEFORE a fresh symbolic BeginValidation -> ValidationPassed ->
/// ReviewConstructed -> RequestApproval sequence reaches `Confirming`,
/// rejects locked and stops the suffix. Per-cycle symbolic order only.
#[test]
fn stale_approve_after_cycle_before_fresh_sequence_rejects() {
    let mut events: Vec<E> = HAPPY_PATH.to_vec();
    events.push(E::Approve); // stale: state is Ready, no fresh sequence
    events.push(E::BeginRevalidation); // suffix must not be consumed
    let out = run_transaction_workflow(&events);
    assert_eq!(out.steps.len(), 12);
    assert_eq!(
        out.steps[11].outcome,
        O::RejectLocked(TransactionTransitionError::InvalidTransition {
            state: S::Ready,
            event: E::Approve,
        })
    );
    assert_eq!(out.final_state, S::Locked);
    assert_eq!(out.unprocessed, 1);
    assert_eq!(out.rejected, 1);
}

/// Two complete consecutive successful transaction cycles in ONE
/// Locked-start `run_transaction_workflow` invocation are valid: the
/// first cycle includes `Wake`; the second starts from the returned
/// `Ready` without `Wake`; exactly one `Approve` continues in each
/// cycle; final state `Ready`. Approval is single-use per
/// authorization cycle, not per function invocation.
#[test]
fn two_consecutive_cycles_one_invocation_valid() {
    let mut events: Vec<E> = HAPPY_PATH.to_vec();
    events.extend_from_slice(&HAPPY_PATH[1..]); // second cycle, no Wake
    assert_eq!(events.len(), 21);
    let out = run_transaction_workflow(&events);
    assert_eq!(out.steps.len(), 21);
    assert_eq!(out.unprocessed, 0);
    assert_eq!(out.rejected, 0);
    assert_eq!(out.final_state, S::Ready);
    let continuing_approves = out
        .steps
        .iter()
        .filter(|st| st.event == E::Approve && matches!(st.outcome, O::Continue(_)))
        .count();
    assert_eq!(continuing_approves, 2); // exactly one per cycle
    assert!(matches!(out.steps[5].outcome, O::Continue(S::Approved)));
    assert!(matches!(out.steps[15].outcome, O::Continue(S::Approved)));
    // Cycle boundary: step 10 returns Ready via the signed path, and
    // the second cycle's BeginValidation continues from that Ready.
    assert!(matches!(out.steps[10].outcome, O::Continue(S::Ready)));
    assert_eq!(out.steps[11].before, S::Ready);
    assert_eq!(out.steps[11].event, E::BeginValidation);
}

/// Test 6: immediate duplicate `Approve` within one authorization
/// cycle -> `RejectLocked`, suffix stops. Approval is single-use PER
/// AUTHORIZATION CYCLE, not per function invocation. No cross-call
/// claim is made; the public pure transition function accepts
/// caller-supplied states for model/table use only.
#[test]
fn immediate_duplicate_approve_rejects() {
    let events = [
        E::Wake,
        E::BeginValidation,
        E::ValidationPassed,
        E::ReviewConstructed,
        E::RequestApproval,
        E::Approve,
        E::Approve, // immediate duplicate within the same cycle
        E::BeginRevalidation,
    ];
    let out = run_transaction_workflow(&events);
    assert_eq!(out.steps.len(), 7);
    assert_eq!(
        out.steps[6].outcome,
        O::RejectLocked(TransactionTransitionError::InvalidTransition {
            state: S::Approved,
            event: E::Approve,
        })
    );
    assert_eq!(out.final_state, S::Locked);
    assert_eq!(out.unprocessed, 1);
    // Approve is also rejected from every other non-Confirming state.
    for &state in ALL_TRANSACTION_STATES.iter() {
        if state == S::Confirming {
            continue;
        }
        assert_eq!(
            transaction_transition(state, E::Approve),
            O::RejectLocked(TransactionTransitionError::InvalidTransition {
                state,
                event: E::Approve,
            })
        );
    }
}

/// Test 7: every interruption and explicit failure event from every
/// state -> `HaltLocked` (11 states x 12 terminal events = 132 pairs).
#[test]
fn every_terminal_event_halts_locked_from_every_state() {
    let mut pairs = 0;
    for &state in ALL_TRANSACTION_STATES.iter() {
        for &event in TERMINAL_EVENTS.iter() {
            let outcome = transaction_transition(state, event);
            assert_eq!(outcome, O::HaltLocked, "{state:?} + {event:?}");
            assert_eq!(outcome.resulting_state(), S::Locked);
            pairs += 1;
        }
    }
    assert_eq!(pairs, 132);
}

/// Test 8: every unspecified state/event pair -> `RejectLocked` with a
/// structured error naming exactly that pair, and the resulting state
/// is always `Locked` — never a preserved working state.
#[test]
fn every_unspecified_pair_rejects_locked() {
    let mut rejected_pairs = 0;
    for &state in ALL_TRANSACTION_STATES.iter() {
        for &event in ALL_TRANSACTION_EVENTS.iter() {
            if event.is_terminal() || continuing_next(state, event).is_some() {
                continue;
            }
            let outcome = transaction_transition(state, event);
            assert_eq!(
                outcome,
                O::RejectLocked(TransactionTransitionError::InvalidTransition { state, event }),
                "{state:?} + {event:?}"
            );
            assert_eq!(outcome.resulting_state(), S::Locked);
            rejected_pairs += 1;
        }
    }
    assert_eq!(rejected_pairs, 110);
}

/// Test 9: exact declared state x event table — exhaustive ONLY over
/// the current explicitly enumerated 11-state and 23-event constants —
/// expected category and next state for every cell, with exact counts:
/// 11 states x 23 events = 253 cells = 11 Continue + 132 HaltLocked
/// + 110 RejectLocked. This is ONE Rust test that iterates all 253
/// declared pairs (not 253 tests). It proves table consistency and the
/// declared ordering, not independent protocol correctness or future
/// enum completeness.
#[test]
fn exhaustive_state_event_table() {
    let mut total = 0;
    let mut continues = 0;
    let mut halts = 0;
    let mut rejects = 0;
    for &state in ALL_TRANSACTION_STATES.iter() {
        for &event in ALL_TRANSACTION_EVENTS.iter() {
            total += 1;
            let expected = if event.is_terminal() {
                halts += 1;
                O::HaltLocked
            } else if let Some(next) = continuing_next(state, event) {
                continues += 1;
                O::Continue(next)
            } else {
                rejects += 1;
                O::RejectLocked(TransactionTransitionError::InvalidTransition { state, event })
            };
            let actual = transaction_transition(state, event);
            assert_eq!(actual, expected, "{state:?} + {event:?}");
            let expected_next = match expected {
                O::Continue(next) => next,
                _ => S::Locked,
            };
            assert_eq!(actual.resulting_state(), expected_next);
        }
    }
    assert_eq!(total, 253);
    assert_eq!(continues, 11);
    assert_eq!(halts, 132);
    assert_eq!(rejects, 110);
}

/// Test 10: the runner stops at the first `HaltLocked` for every
/// terminal event/state pair with the stale suffix
/// `[Wake, BeginValidation]` appended — the suffix is never consumed.
#[test]
fn runner_stops_at_first_halt_for_every_terminal_pair() {
    let mut combos = 0;
    for &state in ALL_TRANSACTION_STATES.iter() {
        for &event in TERMINAL_EVENTS.iter() {
            let events = [event, E::Wake, E::BeginValidation];
            let out = run_from_state_test_only(state, &events);
            assert_eq!(out.steps.len(), 1, "{state:?} + {event:?}");
            assert_eq!(out.steps[0].outcome, O::HaltLocked);
            assert_eq!(out.final_state, S::Locked);
            assert_eq!(out.unprocessed, 2);
            assert_eq!(out.rejected, 0);
            combos += 1;
        }
    }
    assert_eq!(combos, 132);
}

/// Test 11: the runner stops at `RejectLocked` and ignores the stale
/// suffix.
#[test]
fn runner_stops_at_reject_and_ignores_stale_suffix() {
    let events = [
        E::Wake,
        E::SignatureProduced, // invalid from Ready -> RejectLocked
        E::Wake,              // stale suffix, must never be consumed
        E::BeginValidation,
        E::ValidationPassed,
    ];
    let out = run_transaction_workflow(&events);
    assert_eq!(out.steps.len(), 2);
    assert_eq!(
        out.steps[1].outcome,
        O::RejectLocked(TransactionTransitionError::InvalidTransition {
            state: S::Ready,
            event: E::SignatureProduced,
        })
    );
    assert_eq!(out.final_state, S::Locked);
    assert_eq!(out.unprocessed, 3);
    assert_eq!(out.rejected, 1);
}

/// Test 12: a post-failure workflow works only as a completely
/// separate scenario starting from `Locked`.
#[test]
fn post_failure_workflow_requires_new_scenario_from_locked() {
    // First scenario fails mid-way; its appended continuation suffix
    // is never processed.
    let failing = [
        E::Wake,
        E::BeginValidation,
        E::ValidationFailed, // explicit failure -> HaltLocked
        E::Wake,
        E::BeginValidation,
        E::ValidationPassed,
    ];
    let first = run_transaction_workflow(&failing);
    assert_eq!(first.final_state, S::Locked);
    assert_eq!(first.steps.len(), 3);
    assert_eq!(first.unprocessed, 3);
    // Only a NEW scenario, started from Locked, may proceed — and the
    // full mandatory order still applies from the beginning.
    let second = run_transaction_workflow(&HAPPY_PATH);
    assert_eq!(second.final_state, S::Ready);
    assert_eq!(second.rejected, 0);
    assert_eq!(second.unprocessed, 0);
}

/// The intended workflow wrapper begins at `Locked` and accepts no
/// caller-supplied start state: its first processed step always has
/// `before == Locked`, and its API takes only events.
#[test]
fn workflow_wrapper_always_begins_locked() {
    let out = run_transaction_workflow(&[E::Wake]);
    assert_eq!(out.steps.len(), 1);
    assert_eq!(out.steps[0].before, S::Locked);
    assert_eq!(out.steps[0].outcome, O::Continue(S::Ready));
    // An event that is invalid from Locked is rejected immediately,
    // proving the wrapper did not start anywhere else.
    let premature = run_transaction_workflow(&[E::SignatureProduced]);
    assert_eq!(
        premature.steps[0].outcome,
        O::RejectLocked(TransactionTransitionError::InvalidTransition {
            state: S::Locked,
            event: E::SignatureProduced,
        })
    );
    assert_eq!(premature.final_state, S::Locked);
}

/// `SignPermitted` is reachable in a Locked-start workflow only through
/// the binding-representing `RevalidationPassed` event. That event is
/// DEFINED as a symbolic assertion that a future trusted component
/// proved byte-exact/canonical commitment equality between the
/// revalidated candidate and the exact review object and policy
/// context physically approved in this same workflow. This payload-free
/// test proves only the ordering (no path to `SignPermitted` skips
/// `RevalidationPassed`); it does NOT test payload equality, which this
/// model cannot represent.
#[test]
fn sign_permitted_requires_binding_assertion_event() {
    // Ordering proof over the declared table: the only continuing edge
    // INTO SignPermitted is Revalidating + RevalidationPassed.
    for &state in ALL_TRANSACTION_STATES.iter() {
        for &event in ALL_TRANSACTION_EVENTS.iter() {
            let outcome = transaction_transition(state, event);
            if outcome == O::Continue(S::SignPermitted) {
                assert_eq!(state, S::Revalidating);
                assert_eq!(event, E::RevalidationPassed);
            }
        }
    }
    // And a Locked-start workflow that omits RevalidationPassed can
    // never reach SignPermitted.
    let skipping = [
        E::Wake,
        E::BeginValidation,
        E::ValidationPassed,
        E::ReviewConstructed,
        E::RequestApproval,
        E::Approve,
        E::BeginRevalidation,
        E::SignatureProduced, // no binding-representing RevalidationPassed
    ];
    let out = run_transaction_workflow(&skipping);
    assert!(out
        .steps
        .iter()
        .all(|s| s.outcome != O::Continue(S::SignPermitted)));
    assert_eq!(out.final_state, S::Locked);
}

/// Test 13: determinism — identical start state and event sequence
/// always produce identical outcomes.
#[test]
fn determinism_for_identical_inputs() {
    let sequences: [&[E]; 4] = [
        &HAPPY_PATH,
        &[E::Wake, E::SignatureProduced, E::Wake],
        &[E::Wake, E::BeginValidation, E::PowerLoss, E::Wake],
        &[E::Sleep],
    ];
    for events in sequences.iter() {
        let a = run_transaction_workflow(events);
        let b = run_transaction_workflow(events);
        assert_eq!(a, b);
    }
    for &state in ALL_TRANSACTION_STATES.iter() {
        for &event in ALL_TRANSACTION_EVENTS.iter() {
            assert_eq!(
                transaction_transition(state, event),
                transaction_transition(state, event)
            );
        }
    }
}
