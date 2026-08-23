//! Tests for the HOST policy model of transaction authorization
//! ordering and for the token-binding workflow runner — exhaustive
//! ONLY over the current explicit 11-state and 23-event constants (a
//! single test iterates all 253 declared pairs; there are not 253
//! tests, and no future-enum completeness is claimed).
//!
//! HOST SCAFFOLD ONLY — NOT PRODUCT CODE — NO TARGET CLAIM. Scope:
//! see the canonical scope disclaimer in
//! `qk_host_model::transaction_policy`. These tests do NOT execute
//! any canonical QK-TST row and do NOT constitute Gate C evidence.

use qk_host_model::transaction_policy::{
    transaction_state_index, transaction_transition, TransactionEvent, TransactionState,
    TransactionTransitionError, TransactionTransitionOutcome, ALL_TRANSACTION_EVENTS,
    ALL_TRANSACTION_STATES,
};
use qk_host_sim::{
    ApplyOutcome, TransactionWorkflow, WorkflowEvent, WorkflowFinished, WorkflowRejection,
};

use ApplyOutcome as AO;
use TransactionEvent as E;
use TransactionState as S;
use TransactionTransitionOutcome as O;
use WorkflowRejection as R;

/// THE single authoritative oracle table of continuing
/// (state, event, next-state) tuples, written down once as plain data
/// from the mandatory QK-DEC-009/QK-DEC-010 authorization order:
/// validate -> construct review -> physical approval -> revalidate ->
/// permit signature -> verify signature -> reparse output.
/// Every continue oracle below (happy path, per-cell lookups) is
/// DERIVED from this table; every declared cell not in it is expected
/// to halt (terminal events) or reject (everything else).
const CONTINUE_TABLE: [(S, E, S); 11] = [
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

const _: () = {
    // The table must chain: row 0 starts at Locked and each later row
    // starts exactly where the previous row ended, so the derived
    // happy path below is the table itself, not a second declaration.
    assert!(transaction_state_index(CONTINUE_TABLE[0].0) == transaction_state_index(S::Locked));
    let mut i = 1;
    while i < CONTINUE_TABLE.len() {
        assert!(
            transaction_state_index(CONTINUE_TABLE[i].0)
                == transaction_state_index(CONTINUE_TABLE[i - 1].2)
        );
        i += 1;
    }
};

const fn derive_happy_path() -> [E; 11] {
    let mut events = [CONTINUE_TABLE[0].1; 11];
    let mut i = 0;
    while i < CONTINUE_TABLE.len() {
        events[i] = CONTINUE_TABLE[i].1;
        i += 1;
    }
    events
}

const fn derive_happy_states() -> [S; 11] {
    let mut states = [CONTINUE_TABLE[0].2; 11];
    let mut i = 0;
    while i < CONTINUE_TABLE.len() {
        states[i] = CONTINUE_TABLE[i].2;
        i += 1;
    }
    states
}

/// The happy-path event sequence from `Locked`: the event column of
/// the authoritative table, in row order (derived, not re-declared).
const HAPPY_PATH: [E; 11] = derive_happy_path();

/// The state expected AFTER each happy-path event: the next-state
/// column of the authoritative table (derived, not re-declared).
const HAPPY_STATES: [S; 11] = derive_happy_states();

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

/// Continue-oracle lookup, derived from the authoritative table.
fn continuing_next(state: S, event: E) -> Option<S> {
    CONTINUE_TABLE
        .iter()
        .find(|(s, e, _)| *s == state && *e == event)
        .map(|(_, _, n)| *n)
}

/// Attach the currently minted token to the token-required events; all
/// other events pass through plain. When no token is minted, the
/// token-required events are passed tokenless (a missing-token
/// rejection).
fn with_minted(workflow: &TransactionWorkflow, event: E) -> WorkflowEvent {
    match event {
        E::RevalidationPassed => match workflow.minted_token() {
            Some(token) => WorkflowEvent::RevalidationPassed(token),
            None => WorkflowEvent::Plain(E::RevalidationPassed),
        },
        E::SignatureProduced => match workflow.minted_token() {
            Some(token) => WorkflowEvent::SignatureProduced(token),
            None => WorkflowEvent::Plain(E::SignatureProduced),
        },
        other => WorkflowEvent::Plain(other),
    }
}

/// Drive an existing runner through model events, attaching the minted
/// token where required. Returns the apply outcomes; stops (without
/// consuming) once the workflow has ended.
fn drive_into(workflow: &mut TransactionWorkflow, events: &[E]) -> Vec<ApplyOutcome> {
    let mut outcomes = Vec::with_capacity(events.len());
    for &event in events {
        match workflow.apply(with_minted(workflow, event)) {
            Ok(outcome) => outcomes.push(outcome),
            Err(WorkflowFinished) => break,
        }
    }
    outcomes
}

/// Drive a fresh Locked-start runner through model events.
fn drive(events: &[E]) -> (TransactionWorkflow, Vec<ApplyOutcome>) {
    let mut workflow = TransactionWorkflow::new();
    let outcomes = drive_into(&mut workflow, events);
    (workflow, outcomes)
}

/// Test 1: exact happy path — every intermediate state asserted, zero
/// rejection, final `Ready`, minted token cleared at cycle end.
#[test]
fn happy_path_exact_intermediate_states() {
    let (workflow, outcomes) = drive(&HAPPY_PATH);
    assert_eq!(outcomes.len(), 11);
    for (i, outcome) in outcomes.iter().enumerate() {
        assert_eq!(*outcome, AO::Continue(HAPPY_STATES[i]));
    }
    assert_eq!(workflow.state(), S::Ready);
    assert_eq!(workflow.rejected(), 0);
    assert!(!workflow.is_finished());
    assert_eq!(workflow.minted_token(), None);
}

/// Test 2: `SignatureProduced` before approval — no token has been
/// minted, so the assertion arrives tokenless and is rejected
/// missing-token; final `Locked`, suffix unconsumed.
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
    let (workflow, outcomes) = drive(&events);
    assert_eq!(outcomes.len(), 5);
    assert_eq!(
        outcomes[4],
        AO::RejectLocked(R::MissingToken {
            state: S::ReviewReady,
            event: E::SignatureProduced,
        })
    );
    assert_eq!(workflow.state(), S::Locked);
    assert!(workflow.is_finished());
    assert_eq!(workflow.rejected(), 1);
}

/// Test 3: `SignatureProduced` after approval but before revalidation
/// carries the freshly minted token, so the token gate passes and the
/// model table rejects the out-of-order pair; final `Locked`.
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
    let (workflow, outcomes) = drive(&events);
    assert_eq!(outcomes.len(), 7);
    assert_eq!(
        outcomes[6],
        AO::RejectLocked(R::InvalidTransition(
            TransactionTransitionError::InvalidTransition {
                state: S::Approved,
                event: E::SignatureProduced,
            }
        ))
    );
    assert_eq!(workflow.state(), S::Locked);
    assert_eq!(workflow.rejected(), 1);
}

/// Test 4: `SignatureVerified` before `SignatureProduced` ->
/// rejected out of order.
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
    let (workflow, outcomes) = drive(&events);
    assert_eq!(outcomes.len(), 9);
    assert_eq!(
        outcomes[8],
        AO::RejectLocked(R::InvalidTransition(
            TransactionTransitionError::InvalidTransition {
                state: S::SignPermitted,
                event: E::SignatureVerified,
            }
        ))
    );
    assert_eq!(workflow.state(), S::Locked);
}

/// Test 5: `OutputReparsed` before `SignatureVerified` -> rejected out
/// of order.
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
    let (workflow, outcomes) = drive(&events);
    assert_eq!(outcomes.len(), 10);
    assert_eq!(
        outcomes[9],
        AO::RejectLocked(R::InvalidTransition(
            TransactionTransitionError::InvalidTransition {
                state: S::VerifyingSignature,
                event: E::OutputReparsed,
            }
        ))
    );
    assert_eq!(workflow.state(), S::Locked);
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
    let (workflow, outcomes) = drive(&events);
    assert_eq!(outcomes.len(), 12);
    assert_eq!(
        outcomes[11],
        AO::RejectLocked(R::InvalidTransition(
            TransactionTransitionError::InvalidTransition {
                state: S::Ready,
                event: E::Approve,
            }
        ))
    );
    assert_eq!(workflow.state(), S::Locked);
    assert_eq!(workflow.rejected(), 1);
}

/// Two complete consecutive successful transaction cycles in ONE
/// Locked-start runner are valid: the first cycle includes `Wake`; the
/// second starts from the returned `Ready` without `Wake`; exactly one
/// `Approve` continues in each cycle; final state `Ready`. Each cycle
/// mints a distinct token and the second is strictly greater
/// (monotonic).
#[test]
fn two_consecutive_cycles_one_invocation_valid() {
    let mut events: Vec<E> = HAPPY_PATH.to_vec();
    events.extend_from_slice(&HAPPY_PATH[1..]); // second cycle, no Wake
    assert_eq!(events.len(), 21);
    let mut workflow = TransactionWorkflow::new();
    let mut tokens = Vec::new();
    for &event in &events {
        let outcome = workflow
            .apply(with_minted(&workflow, event))
            .expect("workflow must not end during two valid cycles");
        if event == E::Approve && outcome == AO::Continue(S::Approved) {
            tokens.push(
                workflow
                    .minted_token()
                    .expect("accepted Approve must mint a token"),
            );
        }
        assert!(matches!(outcome, AO::Continue(_)));
    }
    assert_eq!(workflow.state(), S::Ready);
    assert_eq!(workflow.rejected(), 0);
    assert_eq!(tokens.len(), 2); // exactly one continuing Approve per cycle
    assert!(tokens[1] > tokens[0]); // opaque monotonicity
    assert_eq!(workflow.minted_token(), None);
}

/// Test 6: immediate duplicate `Approve` within one authorization
/// cycle -> rejected, suffix stops. Approval is single-use PER
/// AUTHORIZATION CYCLE. The pure transition function also rejects
/// `Approve` from every non-`Confirming` state.
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
    let (workflow, outcomes) = drive(&events);
    assert_eq!(outcomes.len(), 7);
    assert_eq!(
        outcomes[6],
        AO::RejectLocked(R::InvalidTransition(
            TransactionTransitionError::InvalidTransition {
                state: S::Approved,
                event: E::Approve,
            }
        ))
    );
    assert_eq!(workflow.state(), S::Locked);
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
/// 11 states x 23 events = 253 cells = 11 Continue plus 132 HaltLocked
/// plus 110 RejectLocked. This is ONE Rust test that iterates all 253
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

/// Test 10: for every reachable state (via happy-path prefixes) and
/// every terminal event, the runner halts locked and then consumes
/// NOTHING further: a stale `[Wake, BeginValidation]` suffix returns
/// `WorkflowFinished` untouched (11 states x 12 terminal events = 132
/// combos).
#[test]
fn runner_stops_at_first_halt_for_every_terminal_pair() {
    let mut combos = 0;
    for prefix_len in 0..=10 {
        for &event in TERMINAL_EVENTS.iter() {
            let mut workflow = TransactionWorkflow::new();
            let outcomes = drive_into(&mut workflow, &HAPPY_PATH[..prefix_len]);
            assert_eq!(outcomes.len(), prefix_len);
            let halted = workflow.apply(WorkflowEvent::Plain(event));
            assert_eq!(halted, Ok(AO::HaltLocked));
            assert_eq!(workflow.state(), S::Locked);
            assert!(workflow.is_finished());
            assert_eq!(workflow.rejected(), 0);
            assert_eq!(
                workflow.apply(WorkflowEvent::Plain(E::Wake)),
                Err(WorkflowFinished)
            );
            assert_eq!(
                workflow.apply(WorkflowEvent::Plain(E::BeginValidation)),
                Err(WorkflowFinished)
            );
            assert_eq!(workflow.state(), S::Locked);
            combos += 1;
        }
    }
    assert_eq!(combos, 132);
}

/// Test 11: the runner stops at a rejection and returns
/// `WorkflowFinished` for the stale suffix.
#[test]
fn runner_stops_at_reject_and_ignores_stale_suffix() {
    let events = [
        E::Wake,
        E::SignatureProduced, // tokenless from Ready -> rejected
        E::Wake,              // stale suffix, must never be consumed
        E::BeginValidation,
        E::ValidationPassed,
    ];
    let (workflow, outcomes) = drive(&events);
    assert_eq!(outcomes.len(), 2);
    assert_eq!(
        outcomes[1],
        AO::RejectLocked(R::MissingToken {
            state: S::Ready,
            event: E::SignatureProduced,
        })
    );
    assert_eq!(workflow.state(), S::Locked);
    assert_eq!(workflow.rejected(), 1);
}

/// Test 12: a post-failure workflow works only as a completely
/// separate runner starting from `Locked`.
#[test]
fn post_failure_workflow_requires_new_scenario_from_locked() {
    let failing = [
        E::Wake,
        E::BeginValidation,
        E::ValidationFailed, // explicit failure -> HaltLocked
        E::Wake,
        E::BeginValidation,
        E::ValidationPassed,
    ];
    let (first, outcomes) = drive(&failing);
    assert_eq!(first.state(), S::Locked);
    assert!(first.is_finished());
    assert_eq!(outcomes.len(), 3);
    // Only a NEW runner, started from Locked, may proceed — and the
    // full mandatory order still applies from the beginning.
    let (second, second_outcomes) = drive(&HAPPY_PATH);
    assert_eq!(second.state(), S::Ready);
    assert_eq!(second.rejected(), 0);
    assert_eq!(second_outcomes.len(), 11);
}

/// The runner begins at `Locked` and accepts no caller-supplied start
/// state: its API takes only events, and an event invalid from
/// `Locked` is rejected immediately.
#[test]
fn runner_always_begins_locked() {
    let workflow = TransactionWorkflow::new();
    assert_eq!(workflow.state(), S::Locked);
    assert_eq!(workflow.minted_token(), None);
    let (woken, outcomes) = drive(&[E::Wake]);
    assert_eq!(outcomes, vec![AO::Continue(S::Ready)]);
    assert_eq!(woken.state(), S::Ready);
    // A tokenless signature assertion from Locked is rejected
    // immediately, proving the runner did not start anywhere else.
    let (premature, premature_outcomes) = drive(&[E::SignatureProduced]);
    assert_eq!(
        premature_outcomes[0],
        AO::RejectLocked(R::MissingToken {
            state: S::Locked,
            event: E::SignatureProduced,
        })
    );
    assert_eq!(premature.state(), S::Locked);
}

/// `SignPermitted` is reachable in a Locked-start workflow only through
/// the binding-representing `RevalidationPassed` event carrying the
/// minted cycle token. The pure-model part proves the ordering over
/// the declared table; the runner part proves a workflow that skips
/// the tokened `RevalidationPassed` never reaches `SignPermitted`.
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
    let (workflow, outcomes) = drive(&skipping);
    assert!(outcomes
        .iter()
        .all(|o| *o != AO::Continue(S::SignPermitted)));
    assert_eq!(workflow.state(), S::Locked);
}

/// Test 13: determinism — identical event sequences always produce
/// identical outcomes, runner states, and minted tokens.
#[test]
fn determinism_for_identical_inputs() {
    let sequences: [&[E]; 4] = [
        &HAPPY_PATH,
        &[E::Wake, E::SignatureProduced, E::Wake],
        &[E::Wake, E::BeginValidation, E::PowerLoss, E::Wake],
        &[E::Sleep],
    ];
    for events in sequences.iter() {
        let (workflow_a, outcomes_a) = drive(events);
        let (workflow_b, outcomes_b) = drive(events);
        assert_eq!(outcomes_a, outcomes_b);
        // Token identity is intentionally per-instance (provenance),
        // so compare observable behavior, not whole-runner equality.
        assert_eq!(workflow_a.state(), workflow_b.state());
        assert_eq!(workflow_a.is_finished(), workflow_b.is_finished());
        assert_eq!(workflow_a.rejected(), workflow_b.rejected());
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

/// A token is minted exactly when `Approve` is accepted, stays minted
/// through the signature path, and is cleared when the cycle returns
/// `Ready`.
#[test]
fn token_minted_only_on_accepted_approve() {
    let mut workflow = TransactionWorkflow::new();
    for (i, &event) in HAPPY_PATH.iter().enumerate() {
        assert_eq!(
            workflow.minted_token().is_some(),
            (6..=10).contains(&i), // after Approve (index 5) until cycle end
            "before event index {i}"
        );
        workflow
            .apply(with_minted(&workflow, event))
            .expect("happy path");
    }
    assert_eq!(workflow.minted_token(), None);
}

/// A token minted by a DIFFERENT runner instance is rejected as a
/// mismatch even when both fresh runners are in their FIRST cycle
/// (same cycle counter value): tokens carry per-runner provenance, so
/// the binding is structural, per runner, per cycle.
#[test]
fn foreign_token_rejected_as_mismatch() {
    let mut foreign = TransactionWorkflow::new();
    drive_into(&mut foreign, &HAPPY_PATH[..6]); // through Approve, cycle 1
    let foreign_token = foreign.minted_token().expect("foreign mint");

    let mut workflow = TransactionWorkflow::new();
    drive_into(&mut workflow, &HAPPY_PATH[..7]); // through BeginRevalidation, cycle 1
    assert_eq!(workflow.state(), S::Revalidating);
    assert_ne!(workflow.minted_token(), Some(foreign_token));
    let outcome = workflow.apply(WorkflowEvent::RevalidationPassed(foreign_token));
    assert_eq!(
        outcome,
        Ok(AO::RejectLocked(R::TokenMismatch {
            state: S::Revalidating,
            event: E::RevalidationPassed,
        }))
    );
    assert_eq!(workflow.state(), S::Locked);
    assert_eq!(workflow.rejected(), 1);

    // Same for the signature assertion: a runner at SignPermitted
    // rejects a foreign first-cycle token.
    let mut signer = TransactionWorkflow::new();
    drive_into(&mut signer, &HAPPY_PATH[..8]); // through RevalidationPassed
    assert_eq!(signer.state(), S::SignPermitted);
    let mut donor = TransactionWorkflow::new();
    drive_into(&mut donor, &HAPPY_PATH[..6]); // through Approve, cycle 1
    let donor_token = donor.minted_token().expect("donor mint");
    let outcome = signer.apply(WorkflowEvent::SignatureProduced(donor_token));
    assert_eq!(
        outcome,
        Ok(AO::RejectLocked(R::TokenMismatch {
            state: S::SignPermitted,
            event: E::SignatureProduced,
        }))
    );
    assert_eq!(signer.state(), S::Locked);
}

/// A token from an EARLIER cycle of the same runner is stale and
/// rejected once a later cycle has minted a new token.
#[test]
fn stale_cycle_token_rejected() {
    let mut workflow = TransactionWorkflow::new();
    drive_into(&mut workflow, &HAPPY_PATH[..6]); // cycle 1 through Approve
    let first_token = workflow.minted_token().expect("cycle 1 mint");
    drive_into(&mut workflow, &HAPPY_PATH[6..]); // complete cycle 1
    assert_eq!(workflow.state(), S::Ready);
    drive_into(&mut workflow, &HAPPY_PATH[1..7]); // cycle 2 through BeginRevalidation
    assert_eq!(workflow.state(), S::Revalidating);
    let second_token = workflow.minted_token().expect("cycle 2 mint");
    assert!(second_token > first_token); // monotonic across cycles
    let outcome = workflow.apply(WorkflowEvent::RevalidationPassed(first_token));
    assert_eq!(
        outcome,
        Ok(AO::RejectLocked(R::TokenMismatch {
            state: S::Revalidating,
            event: E::RevalidationPassed,
        }))
    );
    assert_eq!(workflow.state(), S::Locked);
}

/// A token-required event without any token is rejected even in the
/// exactly right state.
#[test]
fn missing_token_rejected_in_right_state() {
    let mut workflow = TransactionWorkflow::new();
    drive_into(&mut workflow, &HAPPY_PATH[..7]);
    assert_eq!(workflow.state(), S::Revalidating);
    let outcome = workflow.apply(WorkflowEvent::Plain(E::RevalidationPassed));
    assert_eq!(
        outcome,
        Ok(AO::RejectLocked(R::MissingToken {
            state: S::Revalidating,
            event: E::RevalidationPassed,
        }))
    );
    assert_eq!(workflow.state(), S::Locked);
}

/// Delivery retry never re-runs signing: after `SignatureProduced` is
/// accepted once, replaying it — even with the still-active cycle
/// token — is rejected out of order. (Re-delivering the frozen signed
/// artifact is outside this model; only re-SIGNING is modeled, and it
/// is forbidden.)
#[test]
fn no_signing_rerun_on_delivery_retry() {
    let mut workflow = TransactionWorkflow::new();
    drive_into(&mut workflow, &HAPPY_PATH[..9]); // through SignatureProduced
    assert_eq!(workflow.state(), S::VerifyingSignature);
    let token = workflow.minted_token().expect("token active");
    let outcome = workflow.apply(WorkflowEvent::SignatureProduced(token));
    assert_eq!(
        outcome,
        Ok(AO::RejectLocked(R::InvalidTransition(
            TransactionTransitionError::InvalidTransition {
                state: S::VerifyingSignature,
                event: E::SignatureProduced,
            }
        )))
    );
    assert_eq!(workflow.state(), S::Locked);
}

/// New signing requires a NEW approval cycle: after a completed cycle
/// the old token is cleared and rejected, and only a full fresh
/// sequence through `Approve` (minting a strictly greater token)
/// reaches `SignPermitted` again.
#[test]
fn new_signing_requires_new_approval_cycle() {
    let mut workflow = TransactionWorkflow::new();
    drive_into(&mut workflow, &HAPPY_PATH[..6]);
    let first_token = workflow.minted_token().expect("cycle 1 mint");
    drive_into(&mut workflow, &HAPPY_PATH[6..]);
    assert_eq!(workflow.state(), S::Ready);
    assert_eq!(workflow.minted_token(), None);
    // Old token after cycle completion: rejected, no signing.
    let mut replay = workflow.clone();
    let outcome = replay.apply(WorkflowEvent::SignatureProduced(first_token));
    assert_eq!(
        outcome,
        Ok(AO::RejectLocked(R::TokenMismatch {
            state: S::Ready,
            event: E::SignatureProduced,
        }))
    );
    // Fresh full cycle: new Approve mints a strictly greater token and
    // signing is permitted again only through it.
    let outcomes = drive_into(&mut workflow, &HAPPY_PATH[1..8]);
    assert!(outcomes.iter().all(|o| matches!(o, AO::Continue(_))));
    assert_eq!(workflow.state(), S::SignPermitted);
    let second_token = workflow.minted_token().expect("cycle 2 mint");
    assert!(second_token > first_token);
    let outcome = workflow.apply(WorkflowEvent::SignatureProduced(second_token));
    assert_eq!(outcome, Ok(AO::Continue(S::VerifyingSignature)));
}

/// Counter exhaustion fails closed without panic: when the monotonic
/// counter has no fresh value left, `Approve` is rejected locked and
/// nothing is minted.
#[test]
fn cycle_counter_exhaustion_fails_closed() {
    // Immediately exhausted counter.
    let mut workflow = TransactionWorkflow::with_first_cycle(u64::MAX);
    drive_into(&mut workflow, &HAPPY_PATH[..5]); // to Confirming
    assert_eq!(workflow.state(), S::Confirming);
    let outcome = workflow.apply(WorkflowEvent::Plain(E::Approve));
    assert_eq!(outcome, Ok(AO::RejectLocked(R::CycleCounterExhausted)));
    assert_eq!(workflow.state(), S::Locked);
    assert!(workflow.is_finished());
    assert_eq!(workflow.minted_token(), None);
    assert_eq!(workflow.rejected(), 1);
    // Last mintable value works; the next cycle then fails closed.
    let mut nearly = TransactionWorkflow::with_first_cycle(u64::MAX - 1);
    let outcomes = drive_into(&mut nearly, &HAPPY_PATH);
    assert_eq!(outcomes.len(), 11);
    assert_eq!(nearly.state(), S::Ready);
    let outcomes = drive_into(&mut nearly, &HAPPY_PATH[1..5]);
    assert!(outcomes.iter().all(|o| matches!(o, AO::Continue(_))));
    let outcome = nearly.apply(WorkflowEvent::Plain(E::Approve));
    assert_eq!(outcome, Ok(AO::RejectLocked(R::CycleCounterExhausted)));
    assert_eq!(nearly.state(), S::Locked);
}

/// A finished runner consumes nothing: every apply returns
/// `WorkflowFinished` and observable state never changes.
#[test]
fn finished_runner_consumes_nothing() {
    let (mut workflow, _) = drive(&[E::Wake, E::Approve]); // reject: Approve from Ready
    assert!(workflow.is_finished());
    assert_eq!(workflow.rejected(), 1);
    let snapshot = workflow.clone();
    for &event in ALL_TRANSACTION_EVENTS.iter() {
        assert_eq!(
            workflow.apply(with_minted(&snapshot, event)),
            Err(WorkflowFinished)
        );
    }
    assert_eq!(workflow, snapshot);
}
