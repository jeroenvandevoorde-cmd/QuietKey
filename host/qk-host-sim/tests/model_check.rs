//! Dependency-free breadth-first reachability/model check over
//! `transaction_transition` and the token-binding runner.
//!
//! HOST policy model only — HOST SCAFFOLD ONLY — NOT PRODUCT CODE —
//! NO TARGET CLAIM. Everything proven here is about the declared
//! symbolic transition table and runner, not about real validation,
//! approval, revalidation, signing, or hardware.

use qk_host_model::transaction_policy::{
    transaction_state_index, transaction_transition, TransactionEvent, TransactionState,
    TransactionTransitionOutcome, ALL_TRANSACTION_EVENTS, ALL_TRANSACTION_STATES,
};
use qk_host_sim::{ApplyOutcome, TransactionWorkflow, WorkflowEvent};

use TransactionEvent as E;
use TransactionState as S;
use TransactionTransitionOutcome as O;

const STATE_COUNT: usize = ALL_TRANSACTION_STATES.len();

/// All continuing edges of the declared model, as
/// (from-index, event, to-index), read directly off
/// `transaction_transition` — not off any test-local table.
fn continue_edges() -> Vec<(usize, E, usize)> {
    let mut edges = Vec::new();
    for &state in ALL_TRANSACTION_STATES.iter() {
        for &event in ALL_TRANSACTION_EVENTS.iter() {
            if let O::Continue(next) = transaction_transition(state, event) {
                edges.push((
                    transaction_state_index(state),
                    event,
                    transaction_state_index(next),
                ));
            }
        }
    }
    edges
}

/// Breadth-first search over the continue edges from `start`,
/// returning the reachable-set membership per state index.
fn bfs_reachable(edges: &[(usize, E, usize)], start: usize) -> [bool; STATE_COUNT] {
    let mut reachable = [false; STATE_COUNT];
    let mut queue = vec![start];
    reachable[start] = true;
    while let Some(node) = queue.pop() {
        for &(from, _, to) in edges {
            if from == node && !reachable[to] {
                reachable[to] = true;
                queue.push(to);
            }
        }
    }
    reachable
}

/// Every state is reachable from `Locked` in the continue graph, and
/// `SignPermitted` is reachable ONLY through `Confirming`+`Approve`
/// then `Revalidating`+`RevalidationPassed`: the sole continue edge
/// into `SignPermitted` is from `Revalidating` on
/// `RevalidationPassed`, the sole edge into `Revalidating` is from
/// `Approved` on `BeginRevalidation`, and the sole edge into
/// `Approved` is from `Confirming` on `Approve`, so every continue
/// path from `Locked` to `SignPermitted` must traverse exactly that
/// approval-then-matching-revalidation segment.
#[test]
fn sign_permitted_reachable_only_through_approval_then_revalidation() {
    let edges = continue_edges();
    let reachable = bfs_reachable(&edges, transaction_state_index(S::Locked));
    assert!(reachable.iter().all(|&r| r), "all states reachable");

    let incoming = |target: S| -> Vec<(usize, E)> {
        edges
            .iter()
            .filter(|(_, _, to)| *to == transaction_state_index(target))
            .map(|(from, event, _)| (*from, *event))
            .collect()
    };
    assert_eq!(
        incoming(S::SignPermitted),
        vec![(
            transaction_state_index(S::Revalidating),
            E::RevalidationPassed
        )]
    );
    assert_eq!(
        incoming(S::Revalidating),
        vec![(transaction_state_index(S::Approved), E::BeginRevalidation)]
    );
    assert_eq!(
        incoming(S::Approved),
        vec![(transaction_state_index(S::Confirming), E::Approve)]
    );
}

/// Every terminal outcome of every declared cell resolves to `Locked`:
/// no halt or rejection can leave the model in any other state.
#[test]
fn every_terminal_outcome_resolves_to_locked() {
    let mut terminal_cells = 0;
    for &state in ALL_TRANSACTION_STATES.iter() {
        for &event in ALL_TRANSACTION_EVENTS.iter() {
            let outcome = transaction_transition(state, event);
            match outcome {
                O::Continue(_) => {}
                O::HaltLocked | O::RejectLocked(_) => {
                    assert_eq!(outcome.resulting_state(), S::Locked, "{state:?}+{event:?}");
                    terminal_cells += 1;
                }
            }
        }
    }
    assert_eq!(terminal_cells, 253 - 11);
}

/// Every cycle in the continue graph passes through `Ready`: removing
/// `Ready` leaves an acyclic graph (proved by Kahn's algorithm — all
/// remaining nodes can be topologically eliminated).
#[test]
fn every_continue_cycle_passes_through_ready() {
    let ready = transaction_state_index(S::Ready);
    let edges: Vec<(usize, usize)> = continue_edges()
        .iter()
        .filter(|(from, _, to)| *from != ready && *to != ready)
        .map(|(from, _, to)| (*from, *to))
        .collect();
    let mut in_degree = [0usize; STATE_COUNT];
    for &(_, to) in &edges {
        in_degree[to] += 1;
    }
    let mut removed = [false; STATE_COUNT];
    removed[ready] = true; // excluded from the subgraph
    let mut eliminated = 1;
    loop {
        let mut progressed = false;
        for node in 0..STATE_COUNT {
            if !removed[node] && in_degree[node] == 0 {
                removed[node] = true;
                eliminated += 1;
                progressed = true;
                for &(from, to) in &edges {
                    if from == node {
                        in_degree[to] -= 1;
                    }
                }
            }
        }
        if !progressed {
            break;
        }
    }
    assert_eq!(
        eliminated, STATE_COUNT,
        "continue graph minus Ready must be acyclic"
    );
}

/// Token adaptation, without weakening the model proof: the runner's
/// token gate only RESTRICTS the model's continue edges. From every
/// state on the single-outgoing-edge walk from `Locked`, applying
/// `RevalidationPassed` (tokenless, and with the minted token when one
/// exists) continues ONLY from `Revalidating` and ONLY with the token
/// minted by this cycle's accepted `Approve` — every other combination
/// ends locked. So the model-level reachability proof above carries
/// over: the runner adds the matching-token requirement and removes
/// nothing else.
#[test]
fn runner_token_gate_only_restricts_model_edges() {
    // Derive the Locked-start walk from the model itself: each state
    // has exactly one outgoing continue edge.
    let edges = continue_edges();
    let mut walk_events = Vec::new();
    let mut cursor = S::Locked;
    for _ in 0..11 {
        let outgoing: Vec<&(usize, E, usize)> = edges
            .iter()
            .filter(|(from, _, _)| *from == transaction_state_index(cursor))
            .collect();
        assert_eq!(outgoing.len(), 1, "single continue edge from {cursor:?}");
        let &(_, event, to) = outgoing[0];
        walk_events.push(event);
        cursor = ALL_TRANSACTION_STATES[to];
    }
    assert_eq!(cursor, S::Ready);

    for prefix_len in 0..=10 {
        for use_minted in [false, true] {
            let mut workflow = TransactionWorkflow::new();
            for &event in &walk_events[..prefix_len] {
                let input = match (event, workflow.minted_token()) {
                    (E::RevalidationPassed, Some(token)) => {
                        WorkflowEvent::RevalidationPassed(token)
                    }
                    (E::SignatureProduced, Some(token)) => WorkflowEvent::SignatureProduced(token),
                    (other, _) => WorkflowEvent::Plain(other),
                };
                workflow.apply(input).expect("walk prefix stays live");
            }
            let state = workflow.state();
            let minted = workflow.minted_token();
            let input = match (use_minted, minted) {
                (true, Some(token)) => WorkflowEvent::RevalidationPassed(token),
                _ => WorkflowEvent::Plain(E::RevalidationPassed),
            };
            let outcome = workflow.apply(input).expect("workflow was live");
            let should_continue = state == S::Revalidating && use_minted && minted.is_some();
            if should_continue {
                assert_eq!(outcome, ApplyOutcome::Continue(S::SignPermitted));
            } else {
                assert!(
                    matches!(outcome, ApplyOutcome::RejectLocked(_)),
                    "{state:?} use_minted={use_minted} must end locked"
                );
                assert_eq!(workflow.state(), S::Locked);
            }
        }
    }
}
