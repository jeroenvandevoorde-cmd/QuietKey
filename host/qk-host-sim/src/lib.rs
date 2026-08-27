//! Library-only HOST scaffolds over `qk-host-model`.
//!
//! HOST SCAFFOLD ONLY — NOT PRODUCT CODE — NOT A WALLET — NO TARGET
//! CLAIM. [`TransactionWorkflow`] is the legacy payload-free symbolic
//! HOST scaffold: it models event order and opaque runner tokens only.
//! [`ReviewBoundWorkflow`] is the distinct production HOST D-09 seam:
//! it retains and reparses S0, then gates revalidation on the exact
//! review hash and current runner token, then performs M15 final-only
//! signature insertion and canonical PSBT emission. The resulting
//! capability is the sole M16 entry for exact native-P2WSH witness
//! finalization and raw-transaction extraction. Scope: see the
//! canonical disclaimer in `qk_host_model::transaction_policy`.
//! [`ReviewReadyWorkflow`] begins as the separate M23 owned-S0 slice. It
//! reaches an immutable D-09 schema-v2 [`ReviewReady`] fact, which M24
//! may consume for bounded terminal-role signing, verified mock-card
//! insertion, M16 finalization, and a fresh final-transaction check.
//! M25 consumes only that checked finalization capability, binds exact
//! immutable export facts, models each mock-SD artifact lifecycle, and
//! exposes file-type-P BBQr framing only for the finalized PSBT.
//! M27 adds a separate deterministic typed screen-flow seam over the
//! already-frozen provisioning, review-v2, finalization, and export facts.
//! It models ceremony/review order, interruptions, an opaque review-bound
//! hold identity, post-hold no-yield, and logical cleanup only.
//!
//! No binary, server, renderer, display driver, UI layout, REPL, stdin,
//! files, environment, network, database, service, port, preview,
//! deployment, or background process.
//! No approval authority, real card session, arbitrary finalizer,
//! transaction parser API, real media I/O, persistence, RPC, network, or
//! broadcast, or M27-to-M24 signer integration. The M25 filesystem is a
//! deterministic in-memory model and makes no physical-media claim. M15
//! only inserts supplied signatures;
//! M24 is a separate non-authorizing HOST evidence path whose terminal
//! key remains opaque inside qk-secp, and M16 can consume only a
//! threshold-complete capability and returns no intermediate artifact.
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

mod export;
mod finalization;
mod insertion;
mod m24_signing;
mod review_ready;
pub mod screen_flow;

#[path = "../../qk-psbt/src/sha256.rs"]
mod transaction_sha256;

pub use export::{
    ArtifactBindingError, ExportArtifactKind, ExportArtifacts, ExportNonce, FinalizedPsbtArtifact,
    KitTier, MockFileKind, MockSdFilesystem, RawTransactionArtifact, SdArtifactMetadata,
    SdArtifactNames, SdBbqrFrame, SdExportError, SdExportFault, SdFileName, SdLifecycleEvent,
    SdPublishedArtifact, SequentialPsbtBbqr, TierArtifacts,
};
pub use finalization::{FinalizationError, FinalizedTransaction};
pub use insertion::{
    DescriptorRole, SignatureInsertionError, SubmittedSignature, ThresholdCompletePsbt,
};
pub use m24_signing::{M24SigningError, MockCardRole, MockCardSignature, TerminalInputKey};
pub use review_ready::{ReviewReady, ReviewReadyError, ReviewReadyWorkflow};
pub use screen_flow::{
    ApprovalIdentity, ApprovalToken, CeremonyCommitmentView, CeremonyPurpose, CeremonySession,
    CeremonySessionOutcome, CeremonyUnitView, CompletedOperation, FactorRole, FinalApprovalView,
    FlowApplyOutcome, FlowEvent, FlowFinished, FlowKind, FlowTerminal, KeypadKey,
    ProvisioningResultSession, ProvisioningResultView, RecipientFactView, ReviewArithmeticView,
    ReviewChangeView, ReviewFeePolicyView, ReviewLocktimeView, ReviewOpReturnView,
    ReviewOverviewView, ReviewRecipientView, ReviewSequenceView, ReviewSession,
    ReviewSessionOutcome, ScopedApplyOutcome, Screen, ScreenFlow, ScreenKind,
    TransactionResultSession, TransactionResultView, WipingReason,
};

use qk_descriptor::DescriptorPair;
use qk_host_model::transaction_policy::{
    transaction_transition, TransactionEvent, TransactionState, TransactionTransitionError,
    TransactionTransitionOutcome,
};
use qk_psbt::{
    build_review, parse, InputSource, ParseError, PsbtView, Review, ReviewContext, ReviewError,
    ReviewHash, ReviewNetwork,
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

/// Legacy payload-free symbolic HOST workflow scaffold, starting Locked.
///
/// It receives no S0, descriptor, review data, or review hash. It
/// enforces the model's mandatory order and, structurally, the
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

/// Events accepted by [`ReviewBoundWorkflow`].
///
/// The binding assertions are deliberately absent: validation and review
/// construction are performed from the retained S0 internally, and
/// revalidation is performed by [`ReviewBoundWorkflow::revalidate`].
/// `SignatureProduced` is not caller-accessible through this seam; M15
/// emits it internally only after the live review/token gate succeeds.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReviewWorkflowEvent {
    Wake,
    BeginValidation,
    RequestApproval,
    Approve,
    BeginRevalidation,
    SignatureVerified,
    OutputReparsed,
    Sleep,
    Cancel,
    Timeout,
    MediaRemoved,
    Restart,
    PowerLoss,
    ValidationFailed,
    ReviewConstructionFailed,
    ApprovalRejected,
    RevalidationFailed,
    SignatureInvalid,
    OutputInvalid,
}

impl ReviewWorkflowEvent {
    fn model_event(self) -> TransactionEvent {
        match self {
            Self::Wake => TransactionEvent::Wake,
            Self::BeginValidation => TransactionEvent::BeginValidation,
            Self::RequestApproval => TransactionEvent::RequestApproval,
            Self::Approve => TransactionEvent::Approve,
            Self::BeginRevalidation => TransactionEvent::BeginRevalidation,
            Self::SignatureVerified => TransactionEvent::SignatureVerified,
            Self::OutputReparsed => TransactionEvent::OutputReparsed,
            Self::Sleep => TransactionEvent::Sleep,
            Self::Cancel => TransactionEvent::Cancel,
            Self::Timeout => TransactionEvent::Timeout,
            Self::MediaRemoved => TransactionEvent::MediaRemoved,
            Self::Restart => TransactionEvent::Restart,
            Self::PowerLoss => TransactionEvent::PowerLoss,
            Self::ValidationFailed => TransactionEvent::ValidationFailed,
            Self::ReviewConstructionFailed => TransactionEvent::ReviewConstructionFailed,
            Self::ApprovalRejected => TransactionEvent::ApprovalRejected,
            Self::RevalidationFailed => TransactionEvent::RevalidationFailed,
            Self::SignatureInvalid => TransactionEvent::SignatureInvalid,
            Self::OutputInvalid => TransactionEvent::OutputInvalid,
        }
    }
}

/// Errors specific to the closed review-binding seam.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReviewBindingError {
    /// The underlying workflow had already reached its terminal state.
    Finished,
    /// Revalidation was requested without a stored review commitment.
    MissingReviewHash,
    /// Revalidation was requested without its approved cycle token.
    MissingApprovedToken,
    /// The runner's active token no longer equals the approved token.
    TokenMismatch,
    /// Rebuilding the D-09 review changed its exact commitment.
    ReviewHashMismatch,
    /// The retained S0 could not be parsed during revalidation.
    ReparseFailed,
    /// Semantic review construction failed during revalidation.
    RebuildFailed(ReviewError),
    /// Computing the rebuilt review commitment failed.
    RehashFailed,
}

/// Distinct production HOST D-09 seam binding immutable exact S0 and
/// authenticated provenance/descriptor to the unchanged symbolic workflow.
///
/// It reparses retained S0 and gates revalidation on exact review-hash
/// equality plus the current runner token. This type intentionally has no
/// API accepting review bytes, a hash, a token, or any critical model event.
/// It neither generates signatures, finalizes or extracts transactions,
/// nor performs persistence or media export.
pub struct ReviewBoundWorkflow<'a> {
    s0: &'a [u8],
    source: InputSource,
    descriptor: &'a DescriptorPair,
    inner: TransactionWorkflow,
    approved_hash: Option<ReviewHash>,
    approved_review: Option<Review<'a>>,
    approved_token: Option<CycleToken>,
    #[cfg(test)]
    last_parse_identity: Option<(*const u8, usize)>,
}

impl<'a> ReviewBoundWorkflow<'a> {
    /// Borrow exact S0 bytes and the authenticated descriptor pair for
    /// the wrapper's full lifetime, while retaining source provenance.
    /// Safe Rust prevents mutable access to S0 while this wrapper lives.
    pub fn new(s0: &'a [u8], descriptor: &'a DescriptorPair, source: InputSource) -> Self {
        Self {
            s0,
            source,
            descriptor,
            inner: TransactionWorkflow::new(),
            approved_hash: None,
            approved_review: None,
            approved_token: None,
            #[cfg(test)]
            last_parse_identity: None,
        }
    }

    /// Current symbolic state.
    pub fn state(&self) -> TransactionState {
        self.inner.state()
    }

    /// Whether the underlying workflow has terminated.
    pub fn is_finished(&self) -> bool {
        self.inner.is_finished()
    }

    /// Whether a constructed review hash is currently retained.
    pub fn has_review_binding(&self) -> bool {
        self.approved_hash.is_some()
    }

    /// Whether the approval token currently retained by this seam exists.
    pub fn has_approved_token(&self) -> bool {
        self.approved_token.is_some()
    }

    /// Apply an ordinary event. Beginning validation performs the two
    /// critical construction transitions internally before returning.
    pub fn apply(
        &mut self,
        event: ReviewWorkflowEvent,
    ) -> Result<ApplyOutcome, ReviewBindingError> {
        let model_event = event.model_event();
        let outcome = self
            .inner
            .apply(WorkflowEvent::Plain(model_event))
            .map_err(|_| ReviewBindingError::Finished)?;
        self.clean_after(&outcome);
        if model_event == TransactionEvent::BeginValidation
            && matches!(
                outcome,
                ApplyOutcome::Continue(TransactionState::Validating)
            )
        {
            return Ok(self.validate_and_construct());
        }
        if model_event == TransactionEvent::Approve
            && matches!(outcome, ApplyOutcome::Continue(TransactionState::Approved))
        {
            self.approved_token = self.inner.minted_token();
            if self.approved_token.is_none() {
                return Ok(self.fail(TransactionEvent::ApprovalRejected));
            }
        }
        Ok(outcome)
    }

    /// Reparse retained S0 and internally assert revalidation only after
    /// exact hash and token binding checks succeed.
    pub fn revalidate(&mut self) -> Result<ApplyOutcome, ReviewBindingError> {
        let hash = match self.approved_hash {
            Some(hash) => hash,
            None => return Err(self.binding_failure(ReviewBindingError::MissingReviewHash)),
        };
        let token = match self.approved_token {
            Some(token) => token,
            None => return Err(self.binding_failure(ReviewBindingError::MissingApprovedToken)),
        };
        if self.inner.minted_token() != Some(token) {
            return Err(self.binding_failure(ReviewBindingError::TokenMismatch));
        }
        let view = match self.parse_retained() {
            Ok(view) => view,
            Err(_) => return Err(self.binding_failure(ReviewBindingError::ReparseFailed)),
        };
        let review = match build_review(
            &view,
            self.descriptor,
            ReviewContext {
                network: ReviewNetwork::BitcoinMainnet,
                input_source: self.source,
            },
        ) {
            Ok(review) => review,
            Err(error) => {
                return Err(self.binding_failure(ReviewBindingError::RebuildFailed(error)))
            }
        };
        let rebuilt = match review.review_hash() {
            Ok(hash) => hash,
            Err(_) => return Err(self.binding_failure(ReviewBindingError::RehashFailed)),
        };
        if rebuilt != hash {
            return Err(self.binding_failure(ReviewBindingError::ReviewHashMismatch));
        }
        let outcome = self
            .inner
            .apply(WorkflowEvent::RevalidationPassed(token))
            .map_err(|_| ReviewBindingError::Finished)?;
        self.clean_after(&outcome);
        Ok(outcome)
    }

    fn validate_and_construct(&mut self) -> ApplyOutcome {
        if self.parse_retained().is_err() {
            return self.fail(TransactionEvent::ValidationFailed);
        }
        let validated = match self
            .inner
            .apply(WorkflowEvent::Plain(TransactionEvent::ValidationPassed))
        {
            Ok(outcome) => outcome,
            Err(_) => return self.fail(TransactionEvent::ValidationFailed),
        };
        if !matches!(
            validated,
            ApplyOutcome::Continue(TransactionState::ConstructingReview)
        ) {
            self.clean_after(&validated);
            return validated;
        }
        let view = match self.parse_retained() {
            Ok(view) => view,
            Err(_) => return self.fail(TransactionEvent::ValidationFailed),
        };
        let review = match build_review(
            &view,
            self.descriptor,
            ReviewContext {
                network: ReviewNetwork::BitcoinMainnet,
                input_source: self.source,
            },
        ) {
            Ok(review) => review,
            Err(_) => return self.fail(TransactionEvent::ReviewConstructionFailed),
        };
        let constructed = match self
            .inner
            .apply(WorkflowEvent::Plain(TransactionEvent::ReviewConstructed))
        {
            Ok(outcome) => outcome,
            Err(_) => return self.fail(TransactionEvent::ReviewConstructionFailed),
        };
        if matches!(
            constructed,
            ApplyOutcome::Continue(TransactionState::ReviewReady)
        ) {
            self.approved_hash = match review.review_hash() {
                Ok(hash) => {
                    self.approved_review = Some(review);
                    Some(hash)
                }
                Err(_) => {
                    return self.fail(TransactionEvent::ReviewConstructionFailed);
                }
            };
        }
        self.clean_after(&constructed);
        constructed
    }

    fn binding_failure(&mut self, error: ReviewBindingError) -> ReviewBindingError {
        self.fail(TransactionEvent::RevalidationFailed);
        error
    }

    fn fail(&mut self, event: TransactionEvent) -> ApplyOutcome {
        let outcome = self
            .inner
            .apply(WorkflowEvent::Plain(event))
            .unwrap_or(ApplyOutcome::HaltLocked);
        self.clear_binding();
        outcome
    }

    fn clean_after(&mut self, outcome: &ApplyOutcome) {
        if matches!(
            outcome,
            ApplyOutcome::HaltLocked
                | ApplyOutcome::RejectLocked(_)
                | ApplyOutcome::Continue(TransactionState::Ready)
        ) {
            self.clear_binding();
        }
    }

    fn clear_binding(&mut self) {
        self.approved_hash = None;
        self.approved_review = None;
        self.approved_token = None;
    }

    fn parse_retained(&mut self) -> Result<PsbtView<'a>, ParseError> {
        #[cfg(test)]
        {
            self.last_parse_identity = Some((self.s0.as_ptr(), self.s0.len()));
        }
        parse(self.s0, self.source)
    }
}

#[cfg(test)]
mod review_bound_tests {
    use super::*;
    use qk_descriptor::parse_descriptor_pair;

    const REVIEW_FIXTURE: &str = include_str!("../../qk-psbt/tests/fixtures/review_binding.txt");
    const DESCRIPTOR_FIXTURE: &str =
        include_str!("../../qk-psbt/tests/fixtures/descriptor_ownership.txt");

    fn field<'a>(text: &'a str, name: &str) -> &'a str {
        text.lines()
            .find_map(|line| line.strip_prefix(name))
            .expect("fixture field must exist")
    }

    fn decode_hex(value: &str) -> Vec<u8> {
        value
            .as_bytes()
            .chunks_exact(2)
            .map(|pair| {
                u8::from_str_radix(
                    core::str::from_utf8(pair).expect("fixture hex is ASCII"),
                    16,
                )
                .expect("fixture hex is valid")
            })
            .collect()
    }

    fn descriptor() -> DescriptorPair {
        parse_descriptor_pair(
            field(DESCRIPTOR_FIXTURE, "receive: ").as_bytes(),
            field(DESCRIPTOR_FIXTURE, "change: ").as_bytes(),
        )
        .expect("descriptor fixture is valid")
    }

    fn reach_revalidating<'a>(
        s0: &'a [u8],
        descriptor: &'a DescriptorPair,
    ) -> ReviewBoundWorkflow<'a> {
        let mut workflow = ReviewBoundWorkflow::new(s0, descriptor, InputSource::MicroSd);
        assert!(matches!(
            workflow.apply(ReviewWorkflowEvent::Wake),
            Ok(ApplyOutcome::Continue(TransactionState::Ready))
        ));
        assert!(matches!(
            workflow.apply(ReviewWorkflowEvent::BeginValidation),
            Ok(ApplyOutcome::Continue(TransactionState::ReviewReady))
        ));
        assert!(matches!(
            workflow.apply(ReviewWorkflowEvent::RequestApproval),
            Ok(ApplyOutcome::Continue(TransactionState::Confirming))
        ));
        assert!(matches!(
            workflow.apply(ReviewWorkflowEvent::Approve),
            Ok(ApplyOutcome::Continue(TransactionState::Approved))
        ));
        assert!(matches!(
            workflow.apply(ReviewWorkflowEvent::BeginRevalidation),
            Ok(ApplyOutcome::Continue(TransactionState::Revalidating))
        ));
        workflow
    }

    fn assert_clean_locked(workflow: &ReviewBoundWorkflow<'_>) {
        assert_eq!(workflow.state(), TransactionState::Locked);
        assert!(workflow.is_finished());
        assert!(!workflow.has_review_binding());
        assert!(!workflow.has_approved_token());
    }

    #[test]
    fn retained_slice_pointer_and_length_are_identical_through_revalidation() {
        let s0 = decode_hex(field(REVIEW_FIXTURE, "s0_hex: "));
        let descriptor = descriptor();
        let pointer = s0.as_ptr();
        let length = s0.len();
        let mut workflow = reach_revalidating(&s0, &descriptor);
        assert_eq!(workflow.last_parse_identity, Some((pointer, length)));
        assert_eq!(workflow.s0.as_ptr(), pointer);
        assert_eq!(workflow.s0.len(), length);
        assert!(matches!(
            workflow.revalidate(),
            Ok(ApplyOutcome::Continue(TransactionState::SignPermitted))
        ));
        assert_eq!(workflow.last_parse_identity, Some((pointer, length)));
        assert_eq!(workflow.s0.as_ptr(), pointer);
        assert_eq!(workflow.s0.len(), length);
    }

    #[test]
    fn missing_or_wrong_binding_and_token_fail_closed() {
        let s0 = decode_hex(field(REVIEW_FIXTURE, "s0_hex: "));
        let descriptor = descriptor();

        let mut missing_hash = reach_revalidating(&s0, &descriptor);
        missing_hash.approved_hash = None;
        assert_eq!(
            missing_hash.revalidate(),
            Err(ReviewBindingError::MissingReviewHash)
        );
        assert_clean_locked(&missing_hash);

        let mut missing_token = reach_revalidating(&s0, &descriptor);
        missing_token.approved_token = None;
        assert_eq!(
            missing_token.revalidate(),
            Err(ReviewBindingError::MissingApprovedToken)
        );
        assert_clean_locked(&missing_token);

        let mut wrong_hash = reach_revalidating(&s0, &descriptor);
        wrong_hash.approved_hash.as_mut().expect("hash exists")[0] ^= 1;
        assert_eq!(
            wrong_hash.revalidate(),
            Err(ReviewBindingError::ReviewHashMismatch)
        );
        assert_clean_locked(&wrong_hash);

        let foreign = reach_revalidating(&s0, &descriptor)
            .approved_token
            .expect("foreign token exists");
        let mut wrong_token = reach_revalidating(&s0, &descriptor);
        wrong_token.approved_token = Some(foreign);
        assert_eq!(
            wrong_token.revalidate(),
            Err(ReviewBindingError::TokenMismatch)
        );
        assert_clean_locked(&wrong_token);

        let mut stale_token = reach_revalidating(&s0, &descriptor);
        let stale = stale_token.approved_token.expect("approved token exists");
        assert!(matches!(
            stale_token.revalidate(),
            Ok(ApplyOutcome::Continue(TransactionState::SignPermitted))
        ));
        assert_eq!(
            stale_token
                .inner
                .apply(WorkflowEvent::SignatureProduced(stale)),
            Ok(ApplyOutcome::Continue(TransactionState::VerifyingSignature))
        );
        assert!(matches!(
            stale_token.apply(ReviewWorkflowEvent::SignatureVerified),
            Ok(ApplyOutcome::Continue(TransactionState::ReparsingOutput))
        ));
        assert!(matches!(
            stale_token.apply(ReviewWorkflowEvent::OutputReparsed),
            Ok(ApplyOutcome::Continue(TransactionState::Ready))
        ));
        assert!(matches!(
            stale_token.apply(ReviewWorkflowEvent::BeginValidation),
            Ok(ApplyOutcome::Continue(TransactionState::ReviewReady))
        ));
        assert!(matches!(
            stale_token.apply(ReviewWorkflowEvent::RequestApproval),
            Ok(ApplyOutcome::Continue(TransactionState::Confirming))
        ));
        assert!(matches!(
            stale_token.apply(ReviewWorkflowEvent::Approve),
            Ok(ApplyOutcome::Continue(TransactionState::Approved))
        ));
        assert!(matches!(
            stale_token.apply(ReviewWorkflowEvent::BeginRevalidation),
            Ok(ApplyOutcome::Continue(TransactionState::Revalidating))
        ));
        assert_ne!(stale_token.approved_token, Some(stale));
        stale_token.approved_token = Some(stale);
        assert_eq!(
            stale_token.revalidate(),
            Err(ReviewBindingError::TokenMismatch)
        );
        assert_clean_locked(&stale_token);
    }

    #[test]
    fn retained_raw_substitution_and_reparse_failure_fail_closed() {
        let s0 = decode_hex(field(REVIEW_FIXTURE, "s0_hex: "));
        let changed = decode_hex(field(
            REVIEW_FIXTURE
                .split("case: M14-RAW-MUTATION")
                .nth(1)
                .expect("mutation case exists"),
            "s0_hex: ",
        ));
        let descriptor = descriptor();

        let mut substituted = reach_revalidating(&s0, &descriptor);
        substituted.s0 = &changed;
        assert_eq!(
            substituted.revalidate(),
            Err(ReviewBindingError::ReviewHashMismatch)
        );
        assert_clean_locked(&substituted);

        let corrupt = &s0[..20];
        let mut invalid = reach_revalidating(&s0, &descriptor);
        invalid.s0 = corrupt;
        assert_eq!(invalid.revalidate(), Err(ReviewBindingError::ReparseFailed));
        assert_clean_locked(&invalid);
    }

    #[test]
    fn ordinary_rejection_approval_rejection_and_interruptions_clear() {
        let s0 = decode_hex(field(REVIEW_FIXTURE, "s0_hex: "));
        let descriptor = descriptor();

        let mut invalid = reach_revalidating(&s0, &descriptor);
        assert!(matches!(
            invalid.apply(ReviewWorkflowEvent::Wake),
            Ok(ApplyOutcome::RejectLocked(_))
        ));
        assert_clean_locked(&invalid);

        let terminal_events = [
            ReviewWorkflowEvent::Sleep,
            ReviewWorkflowEvent::Cancel,
            ReviewWorkflowEvent::Timeout,
            ReviewWorkflowEvent::MediaRemoved,
            ReviewWorkflowEvent::Restart,
            ReviewWorkflowEvent::PowerLoss,
            ReviewWorkflowEvent::ValidationFailed,
            ReviewWorkflowEvent::ReviewConstructionFailed,
            ReviewWorkflowEvent::ApprovalRejected,
            ReviewWorkflowEvent::RevalidationFailed,
            ReviewWorkflowEvent::SignatureInvalid,
            ReviewWorkflowEvent::OutputInvalid,
        ];
        for event in terminal_events {
            let mut workflow = reach_revalidating(&s0, &descriptor);
            assert_eq!(workflow.apply(event), Ok(ApplyOutcome::HaltLocked));
            assert_clean_locked(&workflow);
        }

        let mut rejected = ReviewBoundWorkflow::new(&s0, &descriptor, InputSource::MicroSd);
        rejected.apply(ReviewWorkflowEvent::Wake).expect("live");
        rejected
            .apply(ReviewWorkflowEvent::BeginValidation)
            .expect("valid");
        rejected
            .apply(ReviewWorkflowEvent::RequestApproval)
            .expect("live");
        assert_eq!(
            rejected.apply(ReviewWorkflowEvent::ApprovalRejected),
            Ok(ApplyOutcome::HaltLocked)
        );
        assert_clean_locked(&rejected);
    }

    #[test]
    fn completed_inner_cycle_clears_wrapper_binding_without_public_signature_event() {
        let s0 = decode_hex(field(REVIEW_FIXTURE, "s0_hex: "));
        let descriptor = descriptor();
        let mut workflow = reach_revalidating(&s0, &descriptor);
        assert!(matches!(
            workflow.revalidate(),
            Ok(ApplyOutcome::Continue(TransactionState::SignPermitted))
        ));

        // Private test-only access proves cleanup after the unchanged
        // runner's completed cycle. Production callers have no event
        // capable of making this transition.
        let token = workflow
            .inner
            .minted_token()
            .expect("approved cycle token exists");
        assert_eq!(
            workflow
                .inner
                .apply(WorkflowEvent::SignatureProduced(token)),
            Ok(ApplyOutcome::Continue(TransactionState::VerifyingSignature))
        );
        assert_eq!(
            workflow.apply(ReviewWorkflowEvent::SignatureVerified),
            Ok(ApplyOutcome::Continue(TransactionState::ReparsingOutput))
        );
        assert_eq!(
            workflow.apply(ReviewWorkflowEvent::OutputReparsed),
            Ok(ApplyOutcome::Continue(TransactionState::Ready))
        );
        assert!(!workflow.has_review_binding());
        assert!(!workflow.has_approved_token());
        assert_eq!(workflow.inner.minted_token(), None);
    }
}
