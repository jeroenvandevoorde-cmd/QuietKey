//! V2 slice-3 owned-S0 workflow ending at an immutable review-v3 fact.

use crate::{
    ApplyOutcome, TransactionWorkflow, WorkflowEvent, WorkflowFinished, WorkflowRejection,
};
use core::fmt;
use qk_descriptor::DescriptorPairV2;
use qk_host_model::transaction_policy::{TransactionEvent, TransactionState};
use qk_psbt::{
    build_review_v3, InputSource, IntakeError, OwnedS0, ParseError, ReviewContext, ReviewNetwork,
    ReviewV3, ReviewV3Error, ReviewV3Hash,
};

/// Stable failure from the schema-v3 review-ready workflow.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReviewReadyV3Error {
    /// Exact S0 ownership failed.
    Intake(IntakeError),
    /// The process-wide workflow provenance source was unavailable.
    WorkflowUnavailable,
    /// A method was invoked after the workflow terminated.
    Finished,
    /// The requested transition was rejected by the closed workflow.
    WorkflowRejected(WorkflowRejection),
    /// A supposedly continuing transition produced an unexpected outcome.
    WorkflowInvariant,
    /// Initial validation could not parse retained S0.
    ValidationParse(ParseError),
    /// Review construction could not parse retained S0.
    ConstructionParse(ParseError),
    /// Initial schema-v3 construction rejected.
    Build(ReviewV3Error),
    /// The binding pass could not reparse retained S0.
    Reparse(ParseError),
    /// The binding pass could not rebuild schema v3.
    Rebuild(ReviewV3Error),
    /// The first review hash could not be computed.
    Hash(ReviewV3Error),
    /// The rebuilt review hash could not be computed.
    Rehash(ReviewV3Error),
    /// Rebuilding from retained S0 changed the typed review.
    ReviewMismatch,
    /// Rebuilding from retained S0 changed the review hash.
    ReviewHashMismatch,
    /// A retained-S0 identity invariant did not hold.
    RetainedS0Mismatch,
}

impl fmt::Display for ReviewReadyV3Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Intake(error) => write!(f, "S0 intake failed: {error}"),
            Self::WorkflowUnavailable => f.write_str("workflow provenance unavailable"),
            Self::Finished => f.write_str("review-v3 workflow already finished"),
            Self::WorkflowRejected(_) => f.write_str("review-v3 workflow transition rejected"),
            Self::WorkflowInvariant => f.write_str("review-v3 workflow invariant failed"),
            Self::ValidationParse(_) => f.write_str("retained S0 validation parse failed"),
            Self::ConstructionParse(_) => {
                f.write_str("retained S0 review-v3 construction parse failed")
            }
            Self::Build(error) => write!(f, "review-v3 construction failed: {error}"),
            Self::Reparse(_) => f.write_str("retained S0 binding reparse failed"),
            Self::Rebuild(error) => write!(f, "review-v3 binding rebuild failed: {error}"),
            Self::Hash(error) => write!(f, "review-v3 hash failed: {error}"),
            Self::Rehash(error) => write!(f, "rebuilt review-v3 hash failed: {error}"),
            Self::ReviewMismatch => f.write_str("rebuilt review-v3 differs"),
            Self::ReviewHashMismatch => f.write_str("rebuilt review-v3 hash differs"),
            Self::RetainedS0Mismatch => f.write_str("retained S0 identity mismatch"),
        }
    }
}

impl std::error::Error for ReviewReadyV3Error {}

impl From<IntakeError> for ReviewReadyV3Error {
    fn from(value: IntakeError) -> Self {
        Self::Intake(value)
    }
}

impl From<WorkflowFinished> for ReviewReadyV3Error {
    fn from(_: WorkflowFinished) -> Self {
        Self::Finished
    }
}

/// Immutable schema-v3 result with its exact retained S0 owner.
pub struct ReviewReadyV3 {
    s0: OwnedS0,
    review: ReviewV3,
    review_hash: ReviewV3Hash,
}

impl ReviewReadyV3 {
    /// Fully owned D-09 schema-v3 review.
    #[must_use]
    pub const fn review(&self) -> &ReviewV3 {
        &self.review
    }

    /// Exact domain-separated hash of the review.
    #[must_use]
    pub const fn review_hash(&self) -> ReviewV3Hash {
        self.review_hash
    }

    /// SHA-256 of exact retained S0 bytes.
    #[must_use]
    pub const fn s0_sha256(&self) -> [u8; 32] {
        self.s0.sha256()
    }

    /// Exact retained S0 byte length.
    #[must_use]
    pub fn s0_len(&self) -> usize {
        self.s0.bytes().len()
    }

    /// Intake provenance fixed when S0 was owned.
    #[must_use]
    pub const fn input_source(&self) -> InputSource {
        self.s0.source()
    }

    pub(super) fn into_signing_parts(self) -> (OwnedS0, ReviewV3, ReviewV3Hash) {
        (self.s0, self.review, self.review_hash)
    }
}

/// Closed HOST workflow from exact S0 ownership through schema-v3 ReviewReady.
pub struct ReviewReadyV3Workflow {
    descriptor: DescriptorPairV2,
    inner: TransactionWorkflow,
    s0: Option<OwnedS0>,
    ready: Option<ReviewReadyV3>,
}

impl ReviewReadyV3Workflow {
    /// Own caller-authenticated two-key D and start at `Locked`.
    pub fn new(descriptor: DescriptorPairV2) -> Result<Self, ReviewReadyV3Error> {
        let inner = TransactionWorkflow::new();
        if inner.is_finished() {
            return Err(ReviewReadyV3Error::WorkflowUnavailable);
        }
        Ok(Self {
            descriptor,
            inner,
            s0: None,
            ready: None,
        })
    }

    /// Own exactly one bounded immutable S0 copy.
    pub fn intake(&mut self, bytes: &[u8], source: InputSource) -> Result<(), ReviewReadyV3Error> {
        if self.inner.is_finished() {
            return Err(ReviewReadyV3Error::Finished);
        }
        if self.inner.state() != TransactionState::Locked || self.s0.is_some() {
            return self.fail(
                TransactionEvent::ValidationFailed,
                ReviewReadyV3Error::WorkflowInvariant,
            );
        }
        match OwnedS0::new(bytes, source) {
            Ok(s0) => {
                self.s0 = Some(s0);
                Ok(())
            }
            Err(error) => self.fail(
                TransactionEvent::ValidationFailed,
                ReviewReadyV3Error::Intake(error),
            ),
        }
    }

    /// Current transaction-workflow state.
    #[must_use]
    pub fn state(&self) -> TransactionState {
        self.inner.state()
    }

    /// Whether this workflow has terminated.
    #[must_use]
    pub fn is_finished(&self) -> bool {
        self.inner.is_finished()
    }

    /// Immutable result, present only at `ReviewReady`.
    #[must_use]
    pub fn review_ready(&self) -> Option<&ReviewReadyV3> {
        self.ready.as_ref()
    }

    /// `Locked -> Ready`.
    pub fn wake(&mut self) -> Result<(), ReviewReadyV3Error> {
        if self.inner.is_finished() {
            return Err(ReviewReadyV3Error::Finished);
        }
        if self.s0.is_none() {
            return self.fail(
                TransactionEvent::ValidationFailed,
                ReviewReadyV3Error::RetainedS0Mismatch,
            );
        }
        self.advance(TransactionEvent::Wake, TransactionState::Ready)
    }

    /// `Ready -> Validating`.
    pub fn begin_validation(&mut self) -> Result<(), ReviewReadyV3Error> {
        self.advance(
            TransactionEvent::BeginValidation,
            TransactionState::Validating,
        )
    }

    /// Parse only retained S0 and enter review construction.
    pub fn validate(&mut self) -> Result<(), ReviewReadyV3Error> {
        self.require_state(
            TransactionState::Validating,
            TransactionEvent::ValidationPassed,
        )?;
        let parsed = self
            .s0
            .as_ref()
            .ok_or(ReviewReadyV3Error::RetainedS0Mismatch)
            .and_then(|s0| s0.parse().map_err(ReviewReadyV3Error::ValidationParse));
        if let Err(error) = parsed {
            return self.fail(TransactionEvent::ValidationFailed, error);
        }
        self.advance(
            TransactionEvent::ValidationPassed,
            TransactionState::ConstructingReview,
        )
    }

    /// Build, reparse, and rebuild exact schema v3 from retained S0.
    pub fn construct_review(&mut self) -> Result<(), ReviewReadyV3Error> {
        self.require_state(
            TransactionState::ConstructingReview,
            TransactionEvent::ReviewConstructed,
        )?;
        let (review, review_hash) = match self.build_once(false) {
            Ok(value) => value,
            Err(error) => {
                return self.fail(TransactionEvent::ReviewConstructionFailed, error);
            }
        };
        let (rebuilt, rebuilt_hash) = match self.build_once(true) {
            Ok(value) => value,
            Err(error) => {
                return self.fail(TransactionEvent::ReviewConstructionFailed, error);
            }
        };
        if review != rebuilt {
            return self.fail(
                TransactionEvent::ReviewConstructionFailed,
                ReviewReadyV3Error::ReviewMismatch,
            );
        }
        if review_hash != rebuilt_hash {
            return self.fail(
                TransactionEvent::ReviewConstructionFailed,
                ReviewReadyV3Error::ReviewHashMismatch,
            );
        }
        let s0 = match self.s0.take() {
            Some(s0) if s0.sha256() == review.s0_sha256() => s0,
            _ => {
                return self.fail(
                    TransactionEvent::ReviewConstructionFailed,
                    ReviewReadyV3Error::RetainedS0Mismatch,
                );
            }
        };
        self.advance(
            TransactionEvent::ReviewConstructed,
            TransactionState::ReviewReady,
        )?;
        self.ready = Some(ReviewReadyV3 {
            s0,
            review,
            review_hash,
        });
        Ok(())
    }

    pub(super) fn into_signing_parts(mut self) -> Option<(DescriptorPairV2, ReviewReadyV3)> {
        if self.inner.is_finished() || self.inner.state() != TransactionState::ReviewReady {
            return None;
        }
        Some((self.descriptor, self.ready.take()?))
    }

    fn build_once(&self, rebuilding: bool) -> Result<(ReviewV3, ReviewV3Hash), ReviewReadyV3Error> {
        let s0 = self
            .s0
            .as_ref()
            .ok_or(ReviewReadyV3Error::RetainedS0Mismatch)?;
        let view = s0.parse().map_err(|error| {
            if rebuilding {
                ReviewReadyV3Error::Reparse(error)
            } else {
                ReviewReadyV3Error::ConstructionParse(error)
            }
        })?;
        if view.buffer().as_ptr() != s0.bytes().as_ptr()
            || view.buffer().len() != s0.bytes().len()
            || view.source() != s0.source()
        {
            return Err(ReviewReadyV3Error::RetainedS0Mismatch);
        }
        let review = build_review_v3(
            &view,
            &self.descriptor,
            ReviewContext {
                network: ReviewNetwork::BitcoinMainnet,
                input_source: s0.source(),
            },
        )
        .map_err(|error| {
            if rebuilding {
                ReviewReadyV3Error::Rebuild(error)
            } else {
                ReviewReadyV3Error::Build(error)
            }
        })?;
        if review.s0_sha256() != s0.sha256() {
            return Err(ReviewReadyV3Error::RetainedS0Mismatch);
        }
        let hash = review.review_hash().map_err(|error| {
            if rebuilding {
                ReviewReadyV3Error::Rehash(error)
            } else {
                ReviewReadyV3Error::Hash(error)
            }
        })?;
        Ok((review, hash))
    }

    fn require_state(
        &mut self,
        expected: TransactionState,
        attempted_event: TransactionEvent,
    ) -> Result<(), ReviewReadyV3Error> {
        if self.inner.is_finished() {
            return Err(ReviewReadyV3Error::Finished);
        }
        if self.inner.state() == expected {
            return Ok(());
        }
        match self.inner.apply(WorkflowEvent::Plain(attempted_event)) {
            Ok(ApplyOutcome::RejectLocked(rejection)) => {
                self.clear();
                Err(ReviewReadyV3Error::WorkflowRejected(rejection))
            }
            Ok(_) => {
                self.lock(TransactionEvent::ReviewConstructionFailed);
                Err(ReviewReadyV3Error::WorkflowInvariant)
            }
            Err(_) => {
                self.clear();
                Err(ReviewReadyV3Error::Finished)
            }
        }
    }

    fn advance(
        &mut self,
        event: TransactionEvent,
        expected: TransactionState,
    ) -> Result<(), ReviewReadyV3Error> {
        match self.inner.apply(WorkflowEvent::Plain(event))? {
            ApplyOutcome::Continue(state) if state == expected => Ok(()),
            ApplyOutcome::RejectLocked(rejection) => {
                self.clear();
                Err(ReviewReadyV3Error::WorkflowRejected(rejection))
            }
            ApplyOutcome::HaltLocked | ApplyOutcome::Continue(_) => {
                self.lock(TransactionEvent::ReviewConstructionFailed);
                Err(ReviewReadyV3Error::WorkflowInvariant)
            }
        }
    }

    fn fail<T>(
        &mut self,
        event: TransactionEvent,
        error: ReviewReadyV3Error,
    ) -> Result<T, ReviewReadyV3Error> {
        self.lock(event);
        Err(error)
    }

    fn lock(&mut self, event: TransactionEvent) {
        let _ = self.inner.apply(WorkflowEvent::Plain(event));
        self.clear();
    }

    fn clear(&mut self) {
        self.s0 = None;
        self.ready = None;
    }
}
