//! Deterministic, dependency-free event fuzzing of the token-binding
//! workflow runner: fixed-seed SplitMix64 sequences of random events
//! (including missing, stale, and foreign tokens) checked against the
//! runner's declared invariants.
//!
//! HOST SCAFFOLD ONLY — NOT PRODUCT CODE — NO TARGET CLAIM. Scope:
//! see the canonical scope disclaimer in
//! `qk_host_model::transaction_policy`. Fuzzing symbolic assertions
//! proves runner fail-closed behavior over the declared semantics.

use qk_host_model::transaction_policy::{
    transaction_transition, TransactionEvent, TransactionState, TransactionTransitionOutcome,
    ALL_TRANSACTION_EVENTS,
};
use qk_host_sim::{ApplyOutcome, CycleToken, TransactionWorkflow, WorkflowEvent, WorkflowFinished};

use TransactionEvent as E;
use TransactionState as S;

/// Inline SplitMix64: tiny, deterministic, no external crates.
struct SplitMix64(u64);

impl SplitMix64 {
    fn next(&mut self) -> u64 {
        self.0 = self.0.wrapping_add(0x9E37_79B9_7F4A_7C15);
        let mut z = self.0;
        z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
        z ^ (z >> 31)
    }

    fn below(&mut self, bound: u64) -> u64 {
        self.next() % bound
    }
}

/// Fixed seeds: the fuzz corpus is fully reproducible.
const SEEDS: [u64; 4] = [
    0x0000_0000_0000_0001,
    0xDEAD_BEEF_CAFE_F00D,
    0x1234_5678_9ABC_DEF0,
    0xFFFF_FFFF_FFFF_FFFE,
];

const SEQUENCES_PER_SEED: usize = 250;
const MAX_SEQUENCE_LEN: usize = 40;

/// The unique continuing model event from `state`, if any.
fn continuing_event(state: S) -> Option<E> {
    ALL_TRANSACTION_EVENTS.iter().copied().find(|&event| {
        matches!(
            transaction_transition(state, event),
            TransactionTransitionOutcome::Continue(_)
        )
    })
}

/// A token minted by a completely separate runner instance.
fn foreign_token() -> CycleToken {
    let mut foreign = TransactionWorkflow::new();
    for event in [
        E::Wake,
        E::BeginValidation,
        E::ValidationPassed,
        E::ReviewConstructed,
        E::RequestApproval,
        E::Approve,
    ] {
        foreign
            .apply(WorkflowEvent::Plain(event))
            .expect("foreign runner setup");
    }
    foreign.minted_token().expect("foreign mint")
}

/// Choose the runner input for a model event: token-required events
/// randomly carry the minted token, no token, a stale token from an
/// earlier cycle of the same runner, or a foreign runner's token.
fn tokenize(
    rng: &mut SplitMix64,
    event: E,
    minted: Option<CycleToken>,
    stale: &[CycleToken],
    foreign: CycleToken,
) -> WorkflowEvent {
    if !matches!(event, E::RevalidationPassed | E::SignatureProduced) {
        return WorkflowEvent::Plain(event);
    }
    let token = match rng.below(4) {
        0 => None,                                                 // missing
        1 => minted,                                               // current (if any)
        2 => stale.last().copied().filter(|t| Some(*t) != minted), // stale
        _ => Some(foreign),                                        // foreign
    };
    match (event, token) {
        (E::RevalidationPassed, Some(t)) => WorkflowEvent::RevalidationPassed(t),
        (E::SignatureProduced, Some(t)) => WorkflowEvent::SignatureProduced(t),
        (other, None) => WorkflowEvent::Plain(other),
        _ => unreachable!("tokenize only reaches token-required events"),
    }
}

/// Fuzz invariants, checked on every random sequence:
/// 1. the runner never consumes an event after a terminal outcome
///    (`WorkflowFinished`, state pinned at `Locked`);
/// 2. `rejected()` is always 0 or 1;
/// 3. the final state is `Locked` (finished) or a live continuing
///    state (not finished);
/// 4. `SignPermitted` is entered only from `Revalidating` via
///    `RevalidationPassed` carrying exactly the token minted by this
///    cycle's accepted `Approve`;
/// 5. minted tokens are strictly monotonic within one runner.
#[test]
fn fuzz_runner_invariants_hold_for_random_event_sequences() {
    let foreign = foreign_token();
    for seed in SEEDS {
        let mut rng = SplitMix64(seed);
        for _ in 0..SEQUENCES_PER_SEED {
            let mut workflow = TransactionWorkflow::new();
            let mut stale: Vec<CycleToken> = Vec::new();
            let length = 1 + rng.below(MAX_SEQUENCE_LEN as u64) as usize;
            for _ in 0..length {
                // Bias half the picks toward the continuing event so
                // deep states and token paths are actually exercised.
                let event = if rng.below(2) == 0 {
                    continuing_event(workflow.state()).unwrap_or(E::Wake)
                } else {
                    ALL_TRANSACTION_EVENTS[rng.below(23) as usize]
                };
                let prev_state = workflow.state();
                let prev_minted = workflow.minted_token();
                let input = tokenize(&mut rng, event, prev_minted, &stale, foreign);
                match workflow.apply(input) {
                    Ok(ApplyOutcome::Continue(next)) => {
                        assert!(!workflow.is_finished());
                        assert_eq!(workflow.state(), next);
                        if next == S::SignPermitted {
                            // Invariant 4: only the bound assertion
                            // with the active cycle token continues
                            // into SignPermitted.
                            assert_eq!(prev_state, S::Revalidating);
                            let active = prev_minted.expect("cycle token was active");
                            assert_eq!(input, WorkflowEvent::RevalidationPassed(active));
                        }
                        if event == E::Approve && next == S::Approved {
                            let token = workflow.minted_token().expect("mint on Approve");
                            // Invariant 5: strict monotonicity.
                            assert!(stale.iter().all(|&t| token > t));
                            stale.push(token);
                        }
                    }
                    Ok(ApplyOutcome::HaltLocked) | Ok(ApplyOutcome::RejectLocked(_)) => {
                        assert!(workflow.is_finished());
                        assert_eq!(workflow.state(), S::Locked);
                        assert_eq!(workflow.minted_token(), None);
                        break;
                    }
                    Err(WorkflowFinished) => {
                        unreachable!("loop breaks at the terminal outcome")
                    }
                }
            }
            // Invariant 2.
            assert!(workflow.rejected() <= 1);
            // Invariant 3.
            if workflow.is_finished() {
                assert_eq!(workflow.state(), S::Locked);
            } else {
                assert_ne!(workflow.state(), S::Locked);
            }
            // Invariant 1: a finished runner consumes nothing more,
            // whatever tokens the events carry.
            if workflow.is_finished() {
                let rejected_before = workflow.rejected();
                for _ in 0..3 {
                    let event = ALL_TRANSACTION_EVENTS[rng.below(23) as usize];
                    let input = tokenize(&mut rng, event, None, &stale, foreign);
                    assert_eq!(workflow.apply(input), Err(WorkflowFinished));
                    assert_eq!(workflow.state(), S::Locked);
                    assert_eq!(workflow.rejected(), rejected_before);
                }
            }
        }
    }
}
