//! HOST-only transaction authority policy model.
//!
//! # Canonical scope disclaimer
//!
//! This section is THE single canonical statement of scope for this
//! policy model, the workflow runner in `qk-host-sim`, and their
//! tests. Other doc comments point here instead of restating it.
//!
//! HOST SCAFFOLD ONLY — NOT PRODUCT CODE — NOT A WALLET — NO TARGET CLAIM.
//! HOST policy model only. PAYLOAD-FREE: no transaction bytes, no
//! partially-signed transaction data, no amounts, fees, addresses, scripts, descriptors, networks, seeds,
//! keys, hashes, signatures, or any wallet data exist anywhere in this
//! module.
//!
//! This module encodes ONLY the mandatory transaction authorization
//! ORDER established by QK-DEC-009/QK-DEC-010:
//!
//! validate -> construct review -> physical approval -> revalidate ->
//! permit signature -> verify signature -> reparse output
//!
//! Every input event is a SYMBOLIC ASSERTION from a hypothetical future
//! component. `ValidationPassed`, `ReviewConstructed`, `Approve`,
//! `RevalidationPassed`, `SignatureProduced`, `SignatureVerified`, and
//! `OutputReparsed` are NOT authenticated and NOT proven by this model.
//! The model makes no claim that validation, review correctness,
//! physical approval, revalidation, signature production or
//! verification, or output parsing actually occurred. `Restart`,
//! `PowerLoss`, and `MediaRemoved` are symbolic HOST policy events only;
//! no target runtime, persistence, boot-recovery, removable-media,
//! signing, parser, physical-button, or power-loss evidence is claimed.
//!
//! NO CROSS-CALL GUARANTEE: the pure transition function accepts
//! caller-supplied states for model/table use, so by itself it claims
//! no global single-use or provenance property. Ordering claims such
//! as "approval is single-use per authorization cycle" and
//! "`SignPermitted` is entered only after `Approve` followed by the
//! binding-representing `RevalidationPassed`" hold within one
//! correctly outcome-threaded invocation of a Locked-start workflow
//! runner, not across separate calls to the pure function.
//!
//! BINDING REQUIREMENT: transaction/intent binding is REPRESENTED by
//! the unauthenticated symbolic `RevalidationPassed` assertion — it is
//! not carried by, and cannot be proven by, a payload-free event. The
//! represented assertion is that a future trusted component reparsed
//! and revalidated the candidate transaction and proved
//! byte-exact/canonical commitment equality to the exact review object
//! and policy context that were physically approved in this same
//! workflow. This payload-free model cannot perform or check that
//! equality; a future implementation MUST enforce it before emitting
//! `RevalidationPassed`. Treating a review/approval of one candidate
//! followed by revalidation/signing of another as valid is forbidden.

/// Opaque, payload-free transaction authorization states.
/// `Locked` is the safe state; every terminal outcome resolves to it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TransactionState {
    /// The locked/safe state. Every terminal outcome ends here.
    Locked,
    /// Awake and idle; no transaction authorization in progress.
    Ready,
    /// Symbolically validating a proposed transaction.
    Validating,
    /// Symbolically constructing the human review material.
    ConstructingReview,
    /// Review material symbolically constructed; approval not yet
    /// requested.
    ReviewReady,
    /// Waiting for the symbolic physical approval decision.
    Confirming,
    /// A symbolic physical approval was asserted. The only continuing
    /// exit declared in the table is `BeginRevalidation`. Scope: see
    /// NO CROSS-CALL GUARANTEE in the module-level canonical
    /// disclaimer.
    Approved,
    /// Symbolically revalidating after approval.
    Revalidating,
    /// Signature production is symbolically permitted; the only
    /// continuing edge into this state is `Revalidating` +
    /// `RevalidationPassed`. Scope: see NO CROSS-CALL GUARANTEE in
    /// the module-level canonical disclaimer.
    SignPermitted,
    /// Symbolically verifying the produced signature.
    VerifyingSignature,
    /// Symbolically reparsing the final output before returning `Ready`.
    ReparsingOutput,
}

/// All transaction states — the current explicit 11-state constant
/// enumeration only; host tests iterating it are exhaustive over this
/// declared list, with no future-enum completeness claim.
pub const ALL_TRANSACTION_STATES: [TransactionState; 11] = [
    TransactionState::Locked,
    TransactionState::Ready,
    TransactionState::Validating,
    TransactionState::ConstructingReview,
    TransactionState::ReviewReady,
    TransactionState::Confirming,
    TransactionState::Approved,
    TransactionState::Revalidating,
    TransactionState::SignPermitted,
    TransactionState::VerifyingSignature,
    TransactionState::ReparsingOutput,
];

/// Compile-time exhaustiveness guard for [`TransactionState`]: a
/// wildcard-free match mapping every variant to its position in
/// [`ALL_TRANSACTION_STATES`]. Adding a variant fails compilation at
/// this match until the guard is extended, and the const block below
/// then fails until [`ALL_TRANSACTION_STATES`] lists the new variant
/// at the matching position.
pub const fn transaction_state_index(state: TransactionState) -> usize {
    match state {
        TransactionState::Locked => 0,
        TransactionState::Ready => 1,
        TransactionState::Validating => 2,
        TransactionState::ConstructingReview => 3,
        TransactionState::ReviewReady => 4,
        TransactionState::Confirming => 5,
        TransactionState::Approved => 6,
        TransactionState::Revalidating => 7,
        TransactionState::SignPermitted => 8,
        TransactionState::VerifyingSignature => 9,
        TransactionState::ReparsingOutput => 10,
    }
}

const _: () = {
    assert!(ALL_TRANSACTION_STATES.len() == 11);
    let mut i = 0;
    while i < ALL_TRANSACTION_STATES.len() {
        assert!(transaction_state_index(ALL_TRANSACTION_STATES[i]) == i);
        i += 1;
    }
};

impl TransactionState {
    /// True only for the locked/safe state.
    pub fn is_safe(self) -> bool {
        matches!(self, TransactionState::Locked)
    }
}

/// Deterministic public transaction events.
///
/// The `*Passed`, `*Constructed`, `Approve`, `*Produced`, `*Verified`,
/// and `*Reparsed` events are unauthenticated symbolic assertions from
/// hypothetical future components; the interruption events are symbolic
/// HOST policy events only. See the module-level disclaimer.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TransactionEvent {
    /// Leave the locked state into `Ready`.
    Wake,
    /// Begin symbolic validation from `Ready`.
    BeginValidation,
    /// Symbolic assertion: validation passed.
    ValidationPassed,
    /// Symbolic assertion: review material constructed.
    ReviewConstructed,
    /// Request the symbolic physical approval decision.
    RequestApproval,
    /// Symbolic assertion: physically approved. `Approve` continues
    /// only from `Confirming` and is single-use PER AUTHORIZATION
    /// CYCLE: an immediate duplicate or any stale `Approve` before a
    /// fresh validation/review/request sequence reaches `Confirming`
    /// rejects locked, while an `Approve` after a completed cycle and
    /// a new full sequence begins a NEW cycle and is not replay.
    /// Scope: see NO CROSS-CALL GUARANTEE in the module-level
    /// canonical disclaimer.
    Approve,
    /// Begin symbolic revalidation from `Approved`.
    BeginRevalidation,
    /// Symbolic assertion: revalidation passed. This is the
    /// binding-representing event: see BINDING REQUIREMENT in the
    /// module-level canonical disclaimer.
    RevalidationPassed,
    /// Symbolic assertion: a signature was produced. Continues only
    /// from `SignPermitted`.
    SignatureProduced,
    /// Symbolic assertion: the signature was verified.
    SignatureVerified,
    /// Symbolic assertion: the final output was reparsed.
    OutputReparsed,
    /// Terminal: go to the locked state, from every state.
    Sleep,
    /// Interruption (symbolic HOST policy event): user cancellation.
    Cancel,
    /// Interruption (symbolic HOST policy event): timeout.
    Timeout,
    /// Interruption (symbolic HOST policy event): removable media
    /// removed.
    MediaRemoved,
    /// Interruption (symbolic HOST policy event): restart.
    Restart,
    /// Interruption (symbolic HOST policy event): power loss.
    PowerLoss,
    /// Explicit failure assertion: validation failed.
    ValidationFailed,
    /// Explicit failure assertion: review construction failed.
    ReviewConstructionFailed,
    /// Explicit failure assertion: approval rejected.
    ApprovalRejected,
    /// Explicit failure assertion: revalidation failed.
    RevalidationFailed,
    /// Explicit failure assertion: signature invalid.
    SignatureInvalid,
    /// Explicit failure assertion: output invalid.
    OutputInvalid,
}

/// All transaction events — the current explicit 23-event constant
/// enumeration only; host tests iterating it are exhaustive over this
/// declared list, with no future-enum completeness claim.
pub const ALL_TRANSACTION_EVENTS: [TransactionEvent; 23] = [
    TransactionEvent::Wake,
    TransactionEvent::BeginValidation,
    TransactionEvent::ValidationPassed,
    TransactionEvent::ReviewConstructed,
    TransactionEvent::RequestApproval,
    TransactionEvent::Approve,
    TransactionEvent::BeginRevalidation,
    TransactionEvent::RevalidationPassed,
    TransactionEvent::SignatureProduced,
    TransactionEvent::SignatureVerified,
    TransactionEvent::OutputReparsed,
    TransactionEvent::Sleep,
    TransactionEvent::Cancel,
    TransactionEvent::Timeout,
    TransactionEvent::MediaRemoved,
    TransactionEvent::Restart,
    TransactionEvent::PowerLoss,
    TransactionEvent::ValidationFailed,
    TransactionEvent::ReviewConstructionFailed,
    TransactionEvent::ApprovalRejected,
    TransactionEvent::RevalidationFailed,
    TransactionEvent::SignatureInvalid,
    TransactionEvent::OutputInvalid,
];

/// Compile-time exhaustiveness guard for [`TransactionEvent`]: a
/// wildcard-free match mapping every variant to its position in
/// [`ALL_TRANSACTION_EVENTS`]. Adding a variant fails compilation at
/// this match until the guard is extended, and the const block below
/// then fails until [`ALL_TRANSACTION_EVENTS`] lists the new variant
/// at the matching position.
pub const fn transaction_event_index(event: TransactionEvent) -> usize {
    match event {
        TransactionEvent::Wake => 0,
        TransactionEvent::BeginValidation => 1,
        TransactionEvent::ValidationPassed => 2,
        TransactionEvent::ReviewConstructed => 3,
        TransactionEvent::RequestApproval => 4,
        TransactionEvent::Approve => 5,
        TransactionEvent::BeginRevalidation => 6,
        TransactionEvent::RevalidationPassed => 7,
        TransactionEvent::SignatureProduced => 8,
        TransactionEvent::SignatureVerified => 9,
        TransactionEvent::OutputReparsed => 10,
        TransactionEvent::Sleep => 11,
        TransactionEvent::Cancel => 12,
        TransactionEvent::Timeout => 13,
        TransactionEvent::MediaRemoved => 14,
        TransactionEvent::Restart => 15,
        TransactionEvent::PowerLoss => 16,
        TransactionEvent::ValidationFailed => 17,
        TransactionEvent::ReviewConstructionFailed => 18,
        TransactionEvent::ApprovalRejected => 19,
        TransactionEvent::RevalidationFailed => 20,
        TransactionEvent::SignatureInvalid => 21,
        TransactionEvent::OutputInvalid => 22,
    }
}

const _: () = {
    assert!(ALL_TRANSACTION_EVENTS.len() == 23);
    let mut i = 0;
    while i < ALL_TRANSACTION_EVENTS.len() {
        assert!(transaction_event_index(ALL_TRANSACTION_EVENTS[i]) == i);
        i += 1;
    }
};

impl TransactionEvent {
    /// True for the interruption events. All of them are terminal.
    pub fn is_interruption(self) -> bool {
        matches!(
            self,
            TransactionEvent::Cancel
                | TransactionEvent::Timeout
                | TransactionEvent::MediaRemoved
                | TransactionEvent::Restart
                | TransactionEvent::PowerLoss
        )
    }

    /// True for the explicit failure assertions. All of them are
    /// terminal.
    pub fn is_explicit_failure(self) -> bool {
        matches!(
            self,
            TransactionEvent::ValidationFailed
                | TransactionEvent::ReviewConstructionFailed
                | TransactionEvent::ApprovalRejected
                | TransactionEvent::RevalidationFailed
                | TransactionEvent::SignatureInvalid
                | TransactionEvent::OutputInvalid
        )
    }

    /// True for every terminal event: `Sleep`, each interruption, and
    /// each explicit failure. A terminal event produces a locked
    /// terminal outcome from every state, invalidating the entire
    /// authorization.
    pub fn is_terminal(self) -> bool {
        matches!(self, TransactionEvent::Sleep)
            || self.is_interruption()
            || self.is_explicit_failure()
    }
}

/// Structured transaction transition error.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TransactionTransitionError {
    /// The event is not valid in the given state.
    InvalidTransition {
        state: TransactionState,
        event: TransactionEvent,
    },
}

/// Total transaction transition outcome. Every variant exposes the
/// security result: either the authorization continues in an explicit
/// state, or it has terminated locked.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TransactionTransitionOutcome {
    /// The authorization continues in the given state.
    Continue(TransactionState),
    /// A terminal event (`Sleep`, any interruption, or any explicit
    /// failure) ended the authorization. The resulting state is
    /// `Locked`.
    HaltLocked,
    /// The state/event pair is invalid. The authorization is
    /// terminated and the resulting state is `Locked` — an invalid
    /// event never preserves `Ready`, `Validating`, `ReviewReady`,
    /// `Confirming`, `Approved`, `Revalidating`, `SignPermitted`,
    /// `VerifyingSignature`, or `ReparsingOutput`.
    RejectLocked(TransactionTransitionError),
}

/// Compile-time exhaustiveness guard for [`TransactionTransitionError`]:
/// a wildcard-free match over every variant, so adding a variant fails
/// compilation here until the guard is updated.
pub const fn transaction_error_index(error: TransactionTransitionError) -> usize {
    match error {
        TransactionTransitionError::InvalidTransition { .. } => 0,
    }
}

/// Compile-time exhaustiveness guard for
/// [`TransactionTransitionOutcome`]: a wildcard-free match over every
/// variant, so adding a variant fails compilation here until the guard
/// is updated.
pub const fn transaction_outcome_index(outcome: TransactionTransitionOutcome) -> usize {
    match outcome {
        TransactionTransitionOutcome::Continue(_) => 0,
        TransactionTransitionOutcome::HaltLocked => 1,
        TransactionTransitionOutcome::RejectLocked(_) => 2,
    }
}

impl TransactionTransitionOutcome {
    /// The state after this outcome. `HaltLocked` and `RejectLocked`
    /// always resolve to `Locked`.
    pub fn resulting_state(self) -> TransactionState {
        match self {
            TransactionTransitionOutcome::Continue(next) => next,
            TransactionTransitionOutcome::HaltLocked => TransactionState::Locked,
            TransactionTransitionOutcome::RejectLocked(_) => TransactionState::Locked,
        }
    }

    /// True for `HaltLocked` and `RejectLocked`: the authorization has
    /// ended and no further events may be consumed.
    pub fn is_terminal(self) -> bool {
        !matches!(self, TransactionTransitionOutcome::Continue(_))
    }
}

/// Total, deterministic transaction transition function, fail-closed
/// over the declared state/event semantics, assuming successful host
/// execution. Allocation exhaustion, panic/abort, process termination,
/// persistence, boot recovery, and target behavior are outside this
/// model.
///
/// The only continuing transitions are the exact mandatory
/// authorization order:
/// `Locked+Wake→Ready`,
/// `Ready+BeginValidation→Validating`,
/// `Validating+ValidationPassed→ConstructingReview`,
/// `ConstructingReview+ReviewConstructed→ReviewReady`,
/// `ReviewReady+RequestApproval→Confirming`,
/// `Confirming+Approve→Approved`,
/// `Approved+BeginRevalidation→Revalidating`,
/// `Revalidating+RevalidationPassed→SignPermitted`,
/// `SignPermitted+SignatureProduced→VerifyingSignature`,
/// `VerifyingSignature+SignatureVerified→ReparsingOutput`,
/// `ReparsingOutput+OutputReparsed→Ready`.
///
/// `Sleep`, every interruption, and every explicit failure halt locked
/// from every state, invalidating the entire authorization. Every
/// other state/event pair rejects locked with a structured error.
pub fn transaction_transition(
    state: TransactionState,
    event: TransactionEvent,
) -> TransactionTransitionOutcome {
    if event.is_terminal() {
        return TransactionTransitionOutcome::HaltLocked;
    }
    match (state, event) {
        (TransactionState::Locked, TransactionEvent::Wake) => {
            TransactionTransitionOutcome::Continue(TransactionState::Ready)
        }
        (TransactionState::Ready, TransactionEvent::BeginValidation) => {
            TransactionTransitionOutcome::Continue(TransactionState::Validating)
        }
        (TransactionState::Validating, TransactionEvent::ValidationPassed) => {
            TransactionTransitionOutcome::Continue(TransactionState::ConstructingReview)
        }
        (TransactionState::ConstructingReview, TransactionEvent::ReviewConstructed) => {
            TransactionTransitionOutcome::Continue(TransactionState::ReviewReady)
        }
        (TransactionState::ReviewReady, TransactionEvent::RequestApproval) => {
            TransactionTransitionOutcome::Continue(TransactionState::Confirming)
        }
        (TransactionState::Confirming, TransactionEvent::Approve) => {
            TransactionTransitionOutcome::Continue(TransactionState::Approved)
        }
        (TransactionState::Approved, TransactionEvent::BeginRevalidation) => {
            TransactionTransitionOutcome::Continue(TransactionState::Revalidating)
        }
        (TransactionState::Revalidating, TransactionEvent::RevalidationPassed) => {
            TransactionTransitionOutcome::Continue(TransactionState::SignPermitted)
        }
        (TransactionState::SignPermitted, TransactionEvent::SignatureProduced) => {
            TransactionTransitionOutcome::Continue(TransactionState::VerifyingSignature)
        }
        (TransactionState::VerifyingSignature, TransactionEvent::SignatureVerified) => {
            TransactionTransitionOutcome::Continue(TransactionState::ReparsingOutput)
        }
        (TransactionState::ReparsingOutput, TransactionEvent::OutputReparsed) => {
            TransactionTransitionOutcome::Continue(TransactionState::Ready)
        }
        (state, event) => TransactionTransitionOutcome::RejectLocked(
            TransactionTransitionError::InvalidTransition { state, event },
        ),
    }
}
