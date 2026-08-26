//! M23 owned-S0 workflow ending at an immutable review-v2 fact.

use crate::{
    ApplyOutcome, TransactionWorkflow, WorkflowEvent, WorkflowFinished, WorkflowRejection,
};
use core::fmt;
use qk_descriptor::DescriptorPair;
use qk_host_model::transaction_policy::{TransactionEvent, TransactionState};
use qk_psbt::{
    build_review_v2, InputSource, IntakeError, OwnedS0, ParseError, ReviewContext, ReviewNetwork,
    ReviewV2, ReviewV2Error, ReviewV2Hash,
};

/// Stable failure from the M23 review-ready workflow.
///
/// Every error returned after construction leaves the workflow terminal at
/// [`TransactionState::Locked`] and clears its retained S0 and partial review.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReviewReadyError {
    /// Exact S0 ownership failed and left the workflow terminal Locked.
    Intake(IntakeError),
    /// The process-wide workflow provenance source was unavailable.
    WorkflowUnavailable,
    /// A method was invoked after the workflow had already terminated.
    Finished,
    /// The requested forward transition was invalid in the current state.
    WorkflowRejected(WorkflowRejection),
    /// A supposedly continuing transition produced an unexpected outcome.
    WorkflowInvariant,
    /// Initial validation could not parse the retained exact S0.
    ValidationParse(ParseError),
    /// Review construction could not reparse the retained exact S0.
    ConstructionParse(ParseError),
    /// The first review-v2 construction rejected.
    Build(ReviewV2Error),
    /// The binding pass could not reparse the retained exact S0.
    Reparse(ParseError),
    /// The binding pass could not rebuild review v2.
    Rebuild(ReviewV2Error),
    /// The first review hash could not be computed.
    Hash(ReviewV2Error),
    /// The rebuilt review hash could not be computed.
    Rehash(ReviewV2Error),
    /// Rebuilding from retained S0 changed the exact typed review.
    ReviewMismatch,
    /// Rebuilding from retained S0 changed the exact review hash.
    ReviewHashMismatch,
    /// A retained-S0 identity invariant did not hold.
    RetainedS0Mismatch,
}

impl fmt::Display for ReviewReadyError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Intake(error) => write!(f, "S0 intake failed: {error}"),
            Self::WorkflowUnavailable => f.write_str("workflow provenance unavailable"),
            Self::Finished => f.write_str("review-ready workflow already finished"),
            Self::WorkflowRejected(_) => f.write_str("review-ready workflow transition rejected"),
            Self::WorkflowInvariant => f.write_str("review-ready workflow invariant failed"),
            Self::ValidationParse(_) => f.write_str("retained S0 validation parse failed"),
            Self::ConstructionParse(_) => {
                f.write_str("retained S0 review-construction parse failed")
            }
            Self::Build(error) => write!(f, "review-v2 construction failed: {error}"),
            Self::Reparse(_) => f.write_str("retained S0 binding reparse failed"),
            Self::Rebuild(error) => write!(f, "review-v2 binding rebuild failed: {error}"),
            Self::Hash(error) => write!(f, "review-v2 hash failed: {error}"),
            Self::Rehash(error) => write!(f, "rebuilt review-v2 hash failed: {error}"),
            Self::ReviewMismatch => f.write_str("rebuilt review-v2 differs"),
            Self::ReviewHashMismatch => f.write_str("rebuilt review-v2 hash differs"),
            Self::RetainedS0Mismatch => f.write_str("retained S0 identity mismatch"),
        }
    }
}

impl std::error::Error for ReviewReadyError {}

impl From<IntakeError> for ReviewReadyError {
    fn from(value: IntakeError) -> Self {
        Self::Intake(value)
    }
}

impl From<WorkflowFinished> for ReviewReadyError {
    fn from(_: WorkflowFinished) -> Self {
        Self::Finished
    }
}

/// Immutable M23 result. It privately retains the exact owned S0 alongside
/// the fully owned, session-free review and its exact domain-separated hash.
///
/// There is intentionally no approval, token, signature, insertion,
/// finalization, extraction, serialization, or export operation on this type.
pub struct ReviewReady {
    s0: OwnedS0,
    review: ReviewV2,
    review_hash: ReviewV2Hash,
}

impl ReviewReady {
    /// Fully owned D-09 schema-v2 review.
    #[must_use]
    pub const fn review(&self) -> &ReviewV2 {
        &self.review
    }

    /// Exact domain-separated hash of [`Self::review`].
    #[must_use]
    pub const fn review_hash(&self) -> ReviewV2Hash {
        self.review_hash
    }

    /// SHA-256 of the exact privately retained S0 artifact.
    #[must_use]
    pub const fn s0_sha256(&self) -> [u8; 32] {
        self.s0.sha256()
    }

    /// Byte length of the exact privately retained S0 artifact.
    #[must_use]
    pub fn s0_len(&self) -> usize {
        self.s0.bytes().len()
    }

    /// Intake provenance fixed when S0 was owned.
    #[must_use]
    pub const fn input_source(&self) -> InputSource {
        self.s0.source()
    }
}

/// Closed M23 HOST workflow from exact S0 ownership through ReviewReady.
///
/// Only the bounded M23 forward operations are exposed. Construction owns
/// the authenticated descriptor by value, then owns one immutable S0 copy
/// through [`OwnedS0`]; success moves that S0 owner into [`ReviewReady`].
/// Every failure is terminal, returns the state to `Locked`, and drops S0
/// plus any partially constructed review.
pub struct ReviewReadyWorkflow {
    descriptor: DescriptorPair,
    inner: TransactionWorkflow,
    s0: Option<OwnedS0>,
    ready: Option<ReviewReady>,
}

impl ReviewReadyWorkflow {
    /// Own caller-authenticated D and create an empty workflow at `Locked`.
    pub fn new(descriptor: DescriptorPair) -> Result<Self, ReviewReadyError> {
        let inner = TransactionWorkflow::new();
        if inner.is_finished() {
            return Err(ReviewReadyError::WorkflowUnavailable);
        }
        Ok(Self {
            descriptor,
            inner,
            s0: None,
            ready: None,
        })
    }

    /// Compare the caller slice against its source cap, then own exactly one
    /// immutable S0 copy while remaining at `Locked`.
    ///
    /// Any intake rejection is named, terminal, and leaves no retained S0.
    pub fn intake(&mut self, bytes: &[u8], source: InputSource) -> Result<(), ReviewReadyError> {
        if self.inner.is_finished() {
            return Err(ReviewReadyError::Finished);
        }
        if self.inner.state() != TransactionState::Locked || self.s0.is_some() {
            return self.fail(
                TransactionEvent::ValidationFailed,
                ReviewReadyError::WorkflowInvariant,
            );
        }
        match OwnedS0::new(bytes, source) {
            Ok(s0) => {
                self.s0 = Some(s0);
                Ok(())
            }
            Err(error) => self.fail(
                TransactionEvent::ValidationFailed,
                ReviewReadyError::Intake(error),
            ),
        }
    }

    /// Current state; every failure leaves this at `Locked`.
    #[must_use]
    pub fn state(&self) -> TransactionState {
        self.inner.state()
    }

    /// Whether the workflow has terminated.
    #[must_use]
    pub fn is_finished(&self) -> bool {
        self.inner.is_finished()
    }

    /// Immutable result, present only in `ReviewReady`.
    #[must_use]
    pub fn review_ready(&self) -> Option<&ReviewReady> {
        self.ready.as_ref()
    }

    /// `Locked -> Ready`.
    pub fn wake(&mut self) -> Result<(), ReviewReadyError> {
        if self.inner.is_finished() {
            return Err(ReviewReadyError::Finished);
        }
        if self.s0.is_none() {
            return self.fail(
                TransactionEvent::ValidationFailed,
                ReviewReadyError::RetainedS0Mismatch,
            );
        }
        self.advance(TransactionEvent::Wake, TransactionState::Ready)
    }

    /// `Ready -> Validating`.
    pub fn begin_validation(&mut self) -> Result<(), ReviewReadyError> {
        self.advance(
            TransactionEvent::BeginValidation,
            TransactionState::Validating,
        )
    }

    /// Parse only the retained exact S0, then `Validating -> ConstructingReview`.
    pub fn validate(&mut self) -> Result<(), ReviewReadyError> {
        self.require_state(
            TransactionState::Validating,
            TransactionEvent::ValidationPassed,
        )?;
        let parsed = self
            .s0
            .as_ref()
            .ok_or(ReviewReadyError::RetainedS0Mismatch)
            .and_then(|s0| s0.parse().map_err(ReviewReadyError::ValidationParse));
        if let Err(error) = parsed {
            return self.fail(TransactionEvent::ValidationFailed, error);
        }
        self.advance(
            TransactionEvent::ValidationPassed,
            TransactionState::ConstructingReview,
        )
    }

    /// Build, reparse, and rebuild from the same retained exact S0; require
    /// exact typed-review and hash equality, then enter `ReviewReady`.
    pub fn construct_review(&mut self) -> Result<(), ReviewReadyError> {
        self.require_state(
            TransactionState::ConstructingReview,
            TransactionEvent::ReviewConstructed,
        )?;

        let first = self.build_once(false);
        let (review, review_hash) = match first {
            Ok(value) => value,
            Err(error) => {
                return self.fail(TransactionEvent::ReviewConstructionFailed, error);
            }
        };
        let second = self.build_once(true);
        let (rebuilt, rebuilt_hash) = match second {
            Ok(value) => value,
            Err(error) => {
                return self.fail(TransactionEvent::ReviewConstructionFailed, error);
            }
        };
        if let Err(error) = require_exact_rebuild(&review, review_hash, &rebuilt, rebuilt_hash) {
            return self.fail(TransactionEvent::ReviewConstructionFailed, error);
        }

        let s0 = match self.s0.take() {
            Some(s0) if s0.sha256() == review.s0_sha256() => s0,
            _ => {
                return self.fail(
                    TransactionEvent::ReviewConstructionFailed,
                    ReviewReadyError::RetainedS0Mismatch,
                );
            }
        };
        self.advance(
            TransactionEvent::ReviewConstructed,
            TransactionState::ReviewReady,
        )?;
        self.ready = Some(ReviewReady {
            s0,
            review,
            review_hash,
        });
        Ok(())
    }

    fn build_once(&self, rebuilding: bool) -> Result<(ReviewV2, ReviewV2Hash), ReviewReadyError> {
        let s0 = self
            .s0
            .as_ref()
            .ok_or(ReviewReadyError::RetainedS0Mismatch)?;
        let view = s0.parse().map_err(|error| {
            if rebuilding {
                ReviewReadyError::Reparse(error)
            } else {
                ReviewReadyError::ConstructionParse(error)
            }
        })?;
        if view.buffer().as_ptr() != s0.bytes().as_ptr()
            || view.buffer().len() != s0.bytes().len()
            || view.source() != s0.source()
        {
            return Err(ReviewReadyError::RetainedS0Mismatch);
        }
        let review = build_review_v2(
            &view,
            &self.descriptor,
            ReviewContext {
                network: ReviewNetwork::BitcoinMainnet,
                input_source: s0.source(),
            },
        )
        .map_err(|error| {
            if rebuilding {
                ReviewReadyError::Rebuild(error)
            } else {
                ReviewReadyError::Build(error)
            }
        })?;
        if review.s0_sha256() != s0.sha256() {
            return Err(ReviewReadyError::RetainedS0Mismatch);
        }
        let hash = review.review_hash().map_err(|error| {
            if rebuilding {
                ReviewReadyError::Rehash(error)
            } else {
                ReviewReadyError::Hash(error)
            }
        })?;
        Ok((review, hash))
    }

    fn require_state(
        &mut self,
        expected: TransactionState,
        attempted_event: TransactionEvent,
    ) -> Result<(), ReviewReadyError> {
        if self.inner.is_finished() {
            return Err(ReviewReadyError::Finished);
        }
        if self.inner.state() == expected {
            return Ok(());
        }
        match self.inner.apply(WorkflowEvent::Plain(attempted_event)) {
            Ok(ApplyOutcome::RejectLocked(rejection)) => {
                self.clear();
                Err(ReviewReadyError::WorkflowRejected(rejection))
            }
            Ok(_) => {
                self.lock(TransactionEvent::ReviewConstructionFailed);
                Err(ReviewReadyError::WorkflowInvariant)
            }
            Err(_) => {
                self.clear();
                Err(ReviewReadyError::Finished)
            }
        }
    }

    fn advance(
        &mut self,
        event: TransactionEvent,
        expected: TransactionState,
    ) -> Result<(), ReviewReadyError> {
        match self.inner.apply(WorkflowEvent::Plain(event))? {
            ApplyOutcome::Continue(state) if state == expected => Ok(()),
            ApplyOutcome::RejectLocked(rejection) => {
                self.clear();
                Err(ReviewReadyError::WorkflowRejected(rejection))
            }
            ApplyOutcome::HaltLocked | ApplyOutcome::Continue(_) => {
                self.lock(TransactionEvent::ReviewConstructionFailed);
                Err(ReviewReadyError::WorkflowInvariant)
            }
        }
    }

    fn fail<T>(
        &mut self,
        event: TransactionEvent,
        error: ReviewReadyError,
    ) -> Result<T, ReviewReadyError> {
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

fn require_exact_rebuild(
    review: &ReviewV2,
    review_hash: ReviewV2Hash,
    rebuilt: &ReviewV2,
    rebuilt_hash: ReviewV2Hash,
) -> Result<(), ReviewReadyError> {
    if review != rebuilt {
        return Err(ReviewReadyError::ReviewMismatch);
    }
    if review_hash != rebuilt_hash {
        return Err(ReviewReadyError::ReviewHashMismatch);
    }
    Ok(())
}

#[cfg(test)]
#[allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects
)]
mod tests {
    use super::*;
    use qk_descriptor::parse_descriptor_pair;
    use qk_psbt::{RejectCategory, SemanticCategory};

    const REVIEW_FIXTURE: &str = include_str!("../../qk-psbt/tests/fixtures/review_v2.txt");
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
            .as_chunks::<2>()
            .0
            .iter()
            .map(|pair| {
                u8::from_str_radix(core::str::from_utf8(pair).expect("ASCII hex"), 16)
                    .expect("valid hex")
            })
            .collect()
    }

    fn descriptor() -> DescriptorPair {
        parse_descriptor_pair(
            field(DESCRIPTOR_FIXTURE, "receive: ").as_bytes(),
            field(DESCRIPTOR_FIXTURE, "change: ").as_bytes(),
        )
        .expect("valid descriptor fixture")
    }

    fn valid_s0() -> Vec<u8> {
        decode_hex(field(REVIEW_FIXTURE, "s0_hex: "))
    }

    fn minimal_psbt() -> Vec<u8> {
        let mut tx = vec![2, 0, 0, 0, 1];
        tx.extend_from_slice(&[0; 32]);
        tx.extend_from_slice(&[0; 4]);
        tx.push(0);
        tx.extend_from_slice(&[0xff; 4]);
        tx.push(1);
        tx.extend_from_slice(&[0; 8]);
        tx.extend_from_slice(&[1, 0x51]);
        tx.extend_from_slice(&[0; 4]);

        let mut psbt = b"psbt\xff\x01\x00".to_vec();
        psbt.push(u8::try_from(tx.len()).expect("small tx"));
        psbt.extend_from_slice(&tx);
        psbt.extend_from_slice(&[0, 0, 0]);
        psbt
    }

    fn reach_constructing(s0: &[u8], descriptor: DescriptorPair) -> ReviewReadyWorkflow {
        let mut workflow = ReviewReadyWorkflow::new(descriptor).expect("workflow");
        workflow.intake(s0, InputSource::MicroSd).expect("intake");
        workflow.wake().expect("wake");
        workflow.begin_validation().expect("begin validation");
        workflow.validate().expect("validate");
        workflow
    }

    #[test]
    fn exact_owned_s0_reaches_review_ready_through_every_state() {
        let mut caller = valid_s0();
        let expected = caller.clone();
        let mut workflow = ReviewReadyWorkflow::new(descriptor()).unwrap();
        workflow.intake(&caller, InputSource::MicroSd).unwrap();
        caller.fill(0xa5);

        assert_eq!(workflow.state(), TransactionState::Locked);
        workflow.wake().unwrap();
        assert_eq!(workflow.state(), TransactionState::Ready);
        workflow.begin_validation().unwrap();
        assert_eq!(workflow.state(), TransactionState::Validating);
        workflow.validate().unwrap();
        assert_eq!(workflow.state(), TransactionState::ConstructingReview);
        workflow.construct_review().unwrap();
        assert_eq!(workflow.state(), TransactionState::ReviewReady);
        assert!(!workflow.is_finished());

        let ready = workflow.review_ready().expect("typed ready fact");
        assert_eq!(ready.s0_len(), expected.len());
        assert_eq!(ready.s0_sha256(), ready.review().s0_sha256());
        assert_eq!(ready.input_source(), InputSource::MicroSd);
        assert_eq!(
            ready.review().canonical_bytes(),
            decode_hex(field(REVIEW_FIXTURE, "canonical_review_v2_hex: "))
        );
        assert_eq!(
            ready.review_hash(),
            decode_hex(field(REVIEW_FIXTURE, "review_hash: ")).as_slice()
        );
    }

    #[test]
    fn intake_parse_and_semantic_failures_are_named_and_locked() {
        let over = vec![0; (256 * 1024) + 1];
        let mut intake = ReviewReadyWorkflow::new(descriptor()).unwrap();
        assert!(matches!(
            intake.intake(&over, InputSource::Qr),
            Err(ReviewReadyError::Intake(IntakeError::TooLarge))
        ));
        assert_eq!(intake.state(), TransactionState::Locked);
        assert!(intake.is_finished());
        assert!(intake.s0.is_none());

        let mut malformed = ReviewReadyWorkflow::new(descriptor()).unwrap();
        malformed.intake(b"psbt\xff", InputSource::MicroSd).unwrap();
        malformed.wake().unwrap();
        malformed.begin_validation().unwrap();
        assert!(matches!(
            malformed.validate(),
            Err(ReviewReadyError::ValidationParse(ParseError {
                category: RejectCategory::Truncated,
                ..
            }))
        ));
        assert_eq!(malformed.state(), TransactionState::Locked);
        assert!(malformed.is_finished());
        assert!(malformed.s0.is_none());
        assert!(malformed.review_ready().is_none());

        let minimal = minimal_psbt();
        let mut semantic = reach_constructing(&minimal, descriptor());
        assert!(matches!(
            semantic.construct_review(),
            Err(ReviewReadyError::Build(ReviewV2Error::Semantic(error)))
                if error.category == SemanticCategory::MissingPrevTx
        ));
        assert_eq!(semantic.state(), TransactionState::Locked);
        assert!(semantic.is_finished());
        assert!(semantic.s0.is_none());
    }

    #[test]
    fn out_of_order_call_rejects_terminal_locked() {
        let s0 = valid_s0();
        let mut workflow = ReviewReadyWorkflow::new(descriptor()).unwrap();
        workflow.intake(&s0, InputSource::MicroSd).unwrap();
        assert!(matches!(
            workflow.begin_validation(),
            Err(ReviewReadyError::WorkflowRejected(
                WorkflowRejection::InvalidTransition(_)
            ))
        ));
        assert_eq!(workflow.state(), TransactionState::Locked);
        assert!(workflow.is_finished());
        assert!(workflow.s0.is_none());
        assert_eq!(workflow.wake(), Err(ReviewReadyError::Finished));
    }

    #[test]
    fn exact_review_and_hash_comparisons_are_distinct() {
        let s0 = valid_s0();
        let descriptor = descriptor();
        let micro = OwnedS0::new(&s0, InputSource::MicroSd).unwrap();
        let micro_view = micro.parse().unwrap();
        let first = build_review_v2(
            &micro_view,
            &descriptor,
            ReviewContext {
                network: ReviewNetwork::BitcoinMainnet,
                input_source: InputSource::MicroSd,
            },
        )
        .unwrap();
        let first_hash = first.review_hash().unwrap();
        assert_eq!(
            require_exact_rebuild(&first, first_hash, &first, first_hash),
            Ok(())
        );

        let mut altered_hash = first_hash;
        altered_hash[0] ^= 1;
        assert_eq!(
            require_exact_rebuild(&first, first_hash, &first, altered_hash),
            Err(ReviewReadyError::ReviewHashMismatch)
        );

        let qr = OwnedS0::new(&s0, InputSource::Qr).unwrap();
        let qr_view = qr.parse().unwrap();
        let other = build_review_v2(
            &qr_view,
            &descriptor,
            ReviewContext {
                network: ReviewNetwork::BitcoinMainnet,
                input_source: InputSource::Qr,
            },
        )
        .unwrap();
        assert_eq!(
            require_exact_rebuild(&first, first_hash, &other, other.review_hash().unwrap()),
            Err(ReviewReadyError::ReviewMismatch)
        );
    }

    #[test]
    fn public_slice_owns_d_and_exposes_no_post_review_transition() {
        let source = include_str!("review_ready.rs");
        let production = source.split("#[cfg(test)]").next().unwrap();
        assert!(production.contains("descriptor: DescriptorPair,"));
        assert!(!production.contains("descriptor: &DescriptorPair,"));
        for forbidden in [
            "pub fn approve(",
            "pub fn sign(",
            "pub fn insert_signature(",
            "pub fn finalize(",
            "pub fn extract(",
            "pub fn export(",
            "pub fn s0_bytes(",
        ] {
            assert!(!production.contains(forbidden), "{forbidden}");
        }
    }
}
