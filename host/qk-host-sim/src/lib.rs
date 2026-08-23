//! Library-only deterministic transaction workflow runner over
//! `qk-host-model`.
//!
//! HOST SCAFFOLD ONLY — NOT PRODUCT CODE — NOT A WALLET SIMULATOR —
//! NO TARGET CLAIM. Scope: see the canonical scope disclaimer in
//! `qk_host_model::transaction_policy`.
//!
//! No binary, server, UI, REPL, stdin, files, environment, network,
//! database, service, port, preview, deployment, or background process.
//!
//! Beyond the model's mandatory event order, the runner makes the
//! approval→revalidation→signature binding STRUCTURAL: accepting
//! `Approve` mints an opaque, monotonic per-cycle [`CycleToken`], and
//! the `RevalidationPassed` and `SignatureProduced` assertions are
//! accepted only when they carry exactly the token minted for the
//! active cycle. The token carries no wallet or transaction data; it
//! binds symbolic order only (see the canonical disclaimer's BINDING
//! REQUIREMENT for what real implementations must still enforce).

#![forbid(unsafe_code)]

use qk_host_model::transaction_policy::{
    transaction_transition, TransactionEvent, TransactionState, TransactionTransitionError,
    TransactionTransitionOutcome,
};
use std::sync::atomic::{AtomicU64, Ordering};

/// Process-wide source of distinct runner provenance ids, so tokens
/// minted by different runner instances never compare equal.
static NEXT_RUNNER_ID: AtomicU64 = AtomicU64::new(0);

/// Opaque, monotonic per-cycle approval token minted by
/// [`TransactionWorkflow`] when an `Approve` event is accepted from
/// `Confirming`. It has no public constructor and exposes no value.
/// A token carries the minting runner's process-unique provenance id
/// plus that runner's cycle counter, so a token minted by a DIFFERENT
/// runner instance never matches — even at the same cycle counter
/// value. (Clones of a runner share its provenance: they are forks of
/// the same logical workflow.) `Ord` exists only so hosts and tests
/// can prove monotonicity between two tokens minted by the SAME
/// runner without reading either one; ordering across runners is
/// meaningless. It carries no wallet or transaction data.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct CycleToken {
    runner: u64,
    cycle: u64,
}

/// Runner input: a model event, with the two signature-path assertions
/// required to carry the minted cycle token.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WorkflowEvent {
    /// Any model event that does not carry a token. Passing the
    /// token-required model events (`RevalidationPassed`,
    /// `SignatureProduced`) through this variant is a missing-token
    /// rejection.
    Plain(TransactionEvent),
    /// Symbolic revalidation-passed assertion carrying a cycle token.
    RevalidationPassed(CycleToken),
    /// Symbolic signature-produced assertion carrying a cycle token.
    SignatureProduced(CycleToken),
}

/// Why the runner rejected an event. Every rejection is terminal and
/// resolves to `Locked`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WorkflowRejection {
    /// The state/event pair is invalid in the model transition table.
    InvalidTransition(TransactionTransitionError),
    /// A token-required event arrived without a token.
    MissingToken {
        /// State when the tokenless event arrived.
        state: TransactionState,
        /// The token-required model event that arrived tokenless.
        event: TransactionEvent,
    },
    /// The carried token is not the token minted for the active
    /// approval cycle: mismatched, stale from an earlier cycle, or no
    /// cycle is active.
    TokenMismatch {
        /// State when the wrongly-tokened event arrived.
        state: TransactionState,
        /// The token-required model event that carried the wrong token.
        event: TransactionEvent,
    },
    /// The monotonic cycle counter is exhausted; the approval fails
    /// closed instead of minting a reused or wrapped token.
    CycleCounterExhausted,
}

/// Result of applying one event to a live workflow.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ApplyOutcome {
    /// The workflow continues in the given state.
    Continue(TransactionState),
    /// A terminal model event ended the workflow; the state is
    /// `Locked`.
    HaltLocked,
    /// The event was rejected; the workflow is terminated and the
    /// state is `Locked`.
    RejectLocked(WorkflowRejection),
}

/// Error: the workflow already ended. The event was NOT consumed and
/// the runner state is unchanged (`Locked`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct WorkflowFinished;

/// Deterministic Locked-start transaction workflow runner.
///
/// Enforces the model's mandatory order and, structurally, the
/// approval→revalidation→signature binding: `RevalidationPassed` and
/// `SignatureProduced` are accepted only with the token minted for the
/// active approval cycle. Fail-closed over the declared semantics,
/// assuming successful host execution; allocation exhaustion,
/// panic/abort, process termination, persistence, boot recovery, and
/// target behavior are outside this model. This runner is a HOST
/// policy model and test harness, NOT an authorization boundary.
///
/// After a `HaltLocked` or `RejectLocked` outcome the workflow is
/// finished: every later [`TransactionWorkflow::apply`] returns
/// [`WorkflowFinished`] without consuming the event. A completed cycle
/// (`OutputReparsed` returning `Ready`) clears the minted token, so
/// new signing always requires a fresh `Approve` in a fresh cycle.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TransactionWorkflow {
    state: TransactionState,
    finished: bool,
    rejected: usize,
    runner_id: u64,
    next_cycle: u64,
    minted: Option<CycleToken>,
}

impl Default for TransactionWorkflow {
    fn default() -> Self {
        Self::new()
    }
}

impl TransactionWorkflow {
    /// New workflow, beginning at `Locked` with a fresh cycle counter.
    pub fn new() -> Self {
        Self::with_first_cycle(0)
    }

    /// Host-test plumbing: start the monotonic cycle counter at a
    /// chosen value so counter exhaustion is provable without 2^64
    /// approvals. Behavior is otherwise identical to [`Self::new`].
    ///
    /// Every construction draws a fresh process-unique provenance id
    /// for token binding. In the unreachable case that the provenance
    /// id space is exhausted, the runner is created already finished
    /// at `Locked` (fail closed) instead of reusing an id.
    pub fn with_first_cycle(first_cycle: u64) -> Self {
        let provenance = NEXT_RUNNER_ID
            .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |id| id.checked_add(1))
            .ok();
        match provenance {
            Some(runner_id) => TransactionWorkflow {
                state: TransactionState::Locked,
                finished: false,
                rejected: 0,
                runner_id,
                next_cycle: first_cycle,
                minted: None,
            },
            None => TransactionWorkflow {
                state: TransactionState::Locked,
                finished: true,
                rejected: 0,
                runner_id: u64::MAX,
                next_cycle: first_cycle,
                minted: None,
            },
        }
    }

    /// Current state. `Locked` after any terminal outcome.
    pub fn state(&self) -> TransactionState {
        self.state
    }

    /// True once a terminal outcome ended the workflow.
    pub fn is_finished(&self) -> bool {
        self.finished
    }

    /// Count of rejected events. Rejection is terminal, so this is
    /// always 0 or 1.
    pub fn rejected(&self) -> usize {
        self.rejected
    }

    /// The token minted for the active approval cycle, if one is
    /// active. `None` before `Approve` is accepted, after the cycle
    /// completes back to `Ready`, and after any terminal outcome.
    pub fn minted_token(&self) -> Option<CycleToken> {
        self.minted
    }

    /// Apply one event. Returns the outcome, or [`WorkflowFinished`]
    /// (without consuming the event) if the workflow already ended.
    pub fn apply(&mut self, event: WorkflowEvent) -> Result<ApplyOutcome, WorkflowFinished> {
        if self.finished {
            return Err(WorkflowFinished);
        }
        let model_event = match event {
            WorkflowEvent::Plain(inner) => {
                if matches!(
                    inner,
                    TransactionEvent::RevalidationPassed | TransactionEvent::SignatureProduced
                ) {
                    return Ok(self.reject(WorkflowRejection::MissingToken {
                        state: self.state,
                        event: inner,
                    }));
                }
                inner
            }
            WorkflowEvent::RevalidationPassed(token) => {
                if self.minted != Some(token) {
                    return Ok(self.reject(WorkflowRejection::TokenMismatch {
                        state: self.state,
                        event: TransactionEvent::RevalidationPassed,
                    }));
                }
                TransactionEvent::RevalidationPassed
            }
            WorkflowEvent::SignatureProduced(token) => {
                if self.minted != Some(token) {
                    return Ok(self.reject(WorkflowRejection::TokenMismatch {
                        state: self.state,
                        event: TransactionEvent::SignatureProduced,
                    }));
                }
                TransactionEvent::SignatureProduced
            }
        };
        if self.state == TransactionState::Confirming
            && model_event == TransactionEvent::Approve
            && self.next_cycle == u64::MAX
        {
            // Fail closed without panic: the reserved final counter
            // value is never minted, so an approval that cannot get a
            // fresh token never enters `Approved`.
            return Ok(self.reject(WorkflowRejection::CycleCounterExhausted));
        }
        match transaction_transition(self.state, model_event) {
            TransactionTransitionOutcome::Continue(next) => {
                if model_event == TransactionEvent::Approve {
                    // Accepted Approve implies the state was
                    // `Confirming`; the counter is below MAX (checked
                    // above), so the increment cannot overflow.
                    self.minted = Some(CycleToken {
                        runner: self.runner_id,
                        cycle: self.next_cycle,
                    });
                    self.next_cycle += 1;
                }
                if next == TransactionState::Ready {
                    // Cycle boundary: any minted token is now stale.
                    self.minted = None;
                }
                self.state = next;
                Ok(ApplyOutcome::Continue(next))
            }
            TransactionTransitionOutcome::HaltLocked => {
                self.end_locked();
                Ok(ApplyOutcome::HaltLocked)
            }
            TransactionTransitionOutcome::RejectLocked(error) => {
                Ok(self.reject(WorkflowRejection::InvalidTransition(error)))
            }
        }
    }

    fn end_locked(&mut self) {
        self.state = TransactionState::Locked;
        self.finished = true;
        self.minted = None;
    }

    fn reject(&mut self, rejection: WorkflowRejection) -> ApplyOutcome {
        self.end_locked();
        self.rejected += 1;
        ApplyOutcome::RejectLocked(rejection)
    }
}
