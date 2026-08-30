//! Final-only M15 signature insertion over the retained D-09 binding.

use super::{ApplyOutcome, ReviewBoundWorkflow, TransactionEvent, TransactionState, WorkflowEvent};
use crate::transaction_wipe_v2::{WipingArray, WipingValueVec, WipingVec};
use core::fmt;
use qk_psbt::{
    build_review, canonical_serialize, parse, InputSource, PsbtView, Review, ReviewContext,
    ReviewError, ReviewNetwork, SerializeError, Span, VerifiedAggregateStatus, VerifiedInputStatus,
};

#[cfg(test)]
std::thread_local! {
    static LAST_PARTIAL_OUTPUT_CAPACITY: core::cell::Cell<usize> = const { core::cell::Cell::new(0) };
}

const THRESHOLD: usize = 2;
const MAX_INSERTIONS: usize = 200;
const MIN_DER_BYTES: usize = 8;
const MAX_LOW_S_DER_BYTES: usize = 71;

/// Descriptor role in the fixed A/B/C order authenticated by D.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DescriptorRole {
    /// First descriptor authority.
    A,
    /// Second descriptor authority.
    B,
    /// Third descriptor authority.
    C,
}

impl DescriptorRole {
    const fn index(self) -> usize {
        match self {
            Self::A => 0,
            Self::B => 1,
            Self::C => 2,
        }
    }
}

/// One externally produced DER signature for a descriptor role.
///
/// The wrapper derives the compressed pubkey from D and appends the
/// fixed SIGHASH_ALL byte; callers cannot supply either value.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SubmittedSignature<'a> {
    /// Unsigned-transaction input index.
    pub input_index: u32,
    /// Authenticated descriptor role.
    pub role: DescriptorRole,
    /// Strict low-S DER bytes without a sighash byte.
    pub der_signature: &'a [u8],
}

/// Threshold-complete, M5-canonical PSBT bytes.
///
/// Construction is final-only: intermediate insertion buffers never
/// inhabit this type and cannot be returned by the production seam.
pub struct ThresholdCompletePsbt {
    pub(super) bytes: Vec<u8>,
    pub(super) source: InputSource,
}

impl ThresholdCompletePsbt {
    /// Borrow the complete canonical PSBT bytes.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes
    }

    /// Consume the artifact and return its complete canonical PSBT bytes.
    #[must_use]
    pub fn into_bytes(self) -> Vec<u8> {
        self.bytes
    }
}

/// Stable M15 insertion failure. No variant carries signature or hash bytes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SignatureInsertionError {
    /// The workflow is not at the post-revalidation signing gate.
    WrongState,
    /// No approved M14 review/hash is retained.
    MissingReviewHash,
    /// No approved current cycle token is retained.
    MissingApprovedToken,
    /// The retained token differs from the runner's current token.
    TokenMismatch,
    /// Immutable S0 no longer rebuilds the approved M14 hash.
    ReviewHashMismatch,
    /// Retained or intermediate bytes did not parse.
    ParseFailed,
    /// M5 canonical serialization failed.
    SerializeFailed(SerializeError),
    /// M6-M14 reconstruction or cryptographic verification failed.
    RevalidationFailed(ReviewError),
    /// A response names no input in the unsigned transaction.
    InputOutOfRange,
    /// The named input, or the complete candidate, already meets threshold.
    ThresholdAlreadyMet,
    /// Exact signature bytes repeat an existing or pending signature.
    DuplicateSignature,
    /// Two distinct pending signatures claim the same input and role.
    DuplicateRole,
    /// A different signature claims a role already present in the PSBT.
    SignatureConflict,
    /// DER length lies outside the strict low-S envelope.
    SignatureLength,
    /// More responses were supplied than the input needs for threshold.
    ThresholdWouldBeExceeded,
    /// At least one incomplete input would remain below threshold.
    ThresholdIncomplete,
    /// More than the bounded transaction-wide insertion count was supplied.
    TooManyInsertions,
    /// The emitted candidate would exceed the retained source byte cap.
    ArtifactTooLarge,
    /// A bounded vector reservation failed.
    AllocationFailed,
    /// Any preexisting record or approval fact changed unexpectedly.
    ForbiddenDelta,
    /// A reparsed candidate was not an M5 fixed point.
    NonCanonicalOutput,
    /// A parser-, descriptor-, or workflow-guaranteed invariant failed.
    InternalInvariant,
}

impl fmt::Display for SignatureInsertionError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::WrongState => f.write_str("signature insertion state invalid"),
            Self::MissingReviewHash => f.write_str("approved review hash missing"),
            Self::MissingApprovedToken => f.write_str("approved cycle token missing"),
            Self::TokenMismatch => f.write_str("approved cycle token mismatch"),
            Self::ReviewHashMismatch => f.write_str("approved review hash mismatch"),
            Self::ParseFailed => f.write_str("signature insertion parse failed"),
            Self::SerializeFailed(error) => {
                write!(f, "signature insertion serialize failed: {error:?}")
            }
            Self::RevalidationFailed(error) => {
                write!(f, "signature insertion revalidation failed: {error}")
            }
            Self::InputOutOfRange => f.write_str("signature input index out of range"),
            Self::ThresholdAlreadyMet => f.write_str("signature threshold already met"),
            Self::DuplicateSignature => f.write_str("duplicate signature"),
            Self::DuplicateRole => f.write_str("duplicate descriptor role"),
            Self::SignatureConflict => f.write_str("descriptor role signature conflict"),
            Self::SignatureLength => f.write_str("signature DER length invalid"),
            Self::ThresholdWouldBeExceeded => f.write_str("signature threshold would be exceeded"),
            Self::ThresholdIncomplete => f.write_str("signature threshold incomplete"),
            Self::TooManyInsertions => f.write_str("too many signature insertions"),
            Self::ArtifactTooLarge => f.write_str("emitted PSBT exceeds source byte cap"),
            Self::AllocationFailed => f.write_str("signature insertion allocation failed"),
            Self::ForbiddenDelta => f.write_str("signature insertion changed a frozen fact"),
            Self::NonCanonicalOutput => f.write_str("emitted PSBT is not canonical"),
            Self::InternalInvariant => f.write_str("signature insertion internal invariant failed"),
        }
    }
}

impl std::error::Error for SignatureInsertionError {}

struct InputSlots {
    public_keys: [WipingArray<33>; 3],
    existing: [Option<Span>; 3],
}

struct NormalizedSignature<'a> {
    input_index: usize,
    role_index: usize,
    der_signature: &'a [u8],
}

struct SignatureState {
    inputs: WipingValueVec<(u32, VerifiedInputStatus)>,
    aggregate: VerifiedAggregateStatus,
}

impl ReviewBoundWorkflow<'_> {
    /// Insert, reparse and revalidate one signature record at a time,
    /// returning bytes only after every input reaches threshold.
    ///
    /// # Errors
    ///
    /// Every error locks the workflow, clears its review/token binding,
    /// discards every intermediate buffer and returns no artifact.
    pub fn insert_and_emit_signatures(
        &mut self,
        submitted: &[SubmittedSignature<'_>],
    ) -> Result<ThresholdCompletePsbt, SignatureInsertionError> {
        let result = self.try_insert_and_emit_signatures(submitted);
        if result.is_err() {
            let _ = self.fail(TransactionEvent::SignatureInvalid);
        }
        result
    }

    fn try_insert_and_emit_signatures(
        &mut self,
        submitted: &[SubmittedSignature<'_>],
    ) -> Result<ThresholdCompletePsbt, SignatureInsertionError> {
        if self.inner.state() != TransactionState::SignPermitted {
            return Err(SignatureInsertionError::WrongState);
        }
        let approved_hash = self
            .approved_hash
            .ok_or(SignatureInsertionError::MissingReviewHash)?;
        if self.approved_review.is_none() {
            return Err(SignatureInsertionError::MissingReviewHash);
        }
        let token = self
            .approved_token
            .ok_or(SignatureInsertionError::MissingApprovedToken)?;
        if self.inner.minted_token() != Some(token) {
            return Err(SignatureInsertionError::TokenMismatch);
        }

        let retained_view = self
            .parse_retained()
            .map_err(|_| SignatureInsertionError::ParseFailed)?;
        let retained_review = build_review(
            &retained_view,
            self.descriptor,
            ReviewContext {
                network: ReviewNetwork::BitcoinMainnet,
                input_source: self.source,
            },
        )
        .map_err(SignatureInsertionError::RevalidationFailed)?;
        let rebuilt_hash = retained_review
            .review_hash()
            .map_err(SignatureInsertionError::RevalidationFailed)?;
        if rebuilt_hash != approved_hash {
            return Err(SignatureInsertionError::ReviewHashMismatch);
        }

        let mut current = WipingVec::take(
            canonical_serialize(&retained_view)
                .map_err(SignatureInsertionError::SerializeFailed)?,
        );
        let baseline_view = parse(current.as_slice(), self.source)
            .map_err(|_| SignatureInsertionError::ParseFailed)?;
        let baseline_review = build_review(
            &baseline_view,
            self.descriptor,
            ReviewContext {
                network: ReviewNetwork::BitcoinMainnet,
                input_source: self.source,
            },
        )
        .map_err(SignatureInsertionError::RevalidationFailed)?;
        let approved_review = self
            .approved_review
            .as_ref()
            .ok_or(SignatureInsertionError::MissingReviewHash)?;
        if !frozen_facts_equal(approved_review, &baseline_review)
            || !signature_state_equal(approved_review, &baseline_review)
        {
            return Err(SignatureInsertionError::ForbiddenDelta);
        }
        let mut signature_state = SignatureState::from_review(&baseline_review)?;

        let slots = collect_slots(&baseline_view, self.descriptor.origin_fingerprints())?;
        let normalized = normalize_submissions(submitted, &slots, current.as_slice())?;

        let produced = self
            .inner
            .apply(WorkflowEvent::SignatureProduced(token))
            .map_err(|_| SignatureInsertionError::InternalInvariant)?;
        if !matches!(
            produced,
            ApplyOutcome::Continue(TransactionState::VerifyingSignature)
        ) {
            return Err(SignatureInsertionError::InternalInvariant);
        }

        for signature in normalized.iter() {
            let public_key = slots
                .get(signature.input_index)
                .and_then(|input| input.public_keys.get(signature.role_index))
                .ok_or(SignatureInsertionError::InternalInvariant)?;
            let previous = core::mem::replace(&mut current, WipingVec::take(Vec::new()));
            let previous_view = parse(previous.as_slice(), self.source)
                .map_err(|_| SignatureInsertionError::ParseFailed)?;
            let (next, insertion_offset, inserted_len) = insert_partial_signature(
                &previous_view,
                previous.as_slice(),
                self.source,
                signature.input_index,
                public_key.as_slice(),
                signature.der_signature,
            )?;
            let next = WipingVec::take(next);
            if !exact_insert_delta(
                previous.as_slice(),
                next.as_slice(),
                insertion_offset,
                inserted_len,
            ) {
                return Err(SignatureInsertionError::ForbiddenDelta);
            }
            let next_view = parse(next.as_slice(), self.source)
                .map_err(|_| SignatureInsertionError::ParseFailed)?;
            let canonical = WipingVec::take(
                canonical_serialize(&next_view)
                    .map_err(SignatureInsertionError::SerializeFailed)?,
            );
            if canonical.as_slice() != next.as_slice() {
                return Err(SignatureInsertionError::NonCanonicalOutput);
            }
            let next_review = build_review(
                &next_view,
                self.descriptor,
                ReviewContext {
                    network: ReviewNetwork::BitcoinMainnet,
                    input_source: self.source,
                },
            )
            .map_err(SignatureInsertionError::RevalidationFailed)?;
            let approved = self
                .approved_review
                .as_ref()
                .ok_or(SignatureInsertionError::MissingReviewHash)?;
            if !allowed_review_step(
                approved,
                &mut signature_state,
                &next_review,
                signature.input_index,
            ) {
                return Err(SignatureInsertionError::ForbiddenDelta);
            }
            current = next;
        }

        let final_view = parse(current.as_slice(), self.source)
            .map_err(|_| SignatureInsertionError::ParseFailed)?;
        if signature_state.aggregate != VerifiedAggregateStatus::VerifyAndExportOnly {
            return Err(SignatureInsertionError::ThresholdIncomplete);
        }
        let final_canonical = WipingVec::take(
            canonical_serialize(&final_view).map_err(SignatureInsertionError::SerializeFailed)?,
        );
        if final_canonical.as_slice() != current.as_slice() {
            return Err(SignatureInsertionError::NonCanonicalOutput);
        }

        let verified = self
            .inner
            .apply(WorkflowEvent::Plain(TransactionEvent::SignatureVerified))
            .map_err(|_| SignatureInsertionError::InternalInvariant)?;
        if !matches!(
            verified,
            ApplyOutcome::Continue(TransactionState::ReparsingOutput)
        ) {
            return Err(SignatureInsertionError::InternalInvariant);
        }
        let reparsed = self
            .inner
            .apply(WorkflowEvent::Plain(TransactionEvent::OutputReparsed))
            .map_err(|_| SignatureInsertionError::InternalInvariant)?;
        if !matches!(reparsed, ApplyOutcome::Continue(TransactionState::Ready)) {
            return Err(SignatureInsertionError::InternalInvariant);
        }
        self.clean_after(&reparsed);
        Ok(ThresholdCompletePsbt {
            bytes: current.into_vec(),
            source: self.source,
        })
    }
}

fn collect_slots(
    view: &PsbtView<'_>,
    fingerprints: [[u8; 4]; 3],
) -> Result<WipingValueVec<InputSlots>, SignatureInsertionError> {
    let mut slots = WipingValueVec::new();
    slots
        .try_reserve_exact(view.input_map_count())
        .map_err(|_| SignatureInsertionError::AllocationFailed)?;
    for input_index in 0..view.input_map_count() {
        let records = view
            .input_records(input_index)
            .ok_or(SignatureInsertionError::InternalInvariant)?;
        let mut public_keys: [Option<WipingArray<33>>; 3] = [None, None, None];
        for record in records.clone() {
            if record.key_type != 0x06 {
                continue;
            }
            let fingerprint: [u8; 4] = record
                .value
                .get(..4)
                .ok_or(SignatureInsertionError::InternalInvariant)?
                .try_into()
                .map_err(|_| SignatureInsertionError::InternalInvariant)?;
            let role_index = fingerprints
                .iter()
                .position(|candidate| *candidate == fingerprint)
                .ok_or(SignatureInsertionError::InternalInvariant)?;
            let public_key = WipingArray::new(
                record
                    .key_data
                    .try_into()
                    .map_err(|_| SignatureInsertionError::InternalInvariant)?,
            );
            let slot = public_keys
                .get_mut(role_index)
                .ok_or(SignatureInsertionError::InternalInvariant)?;
            if slot.replace(public_key).is_some() {
                return Err(SignatureInsertionError::InternalInvariant);
            }
        }
        let [public_key_a, public_key_b, public_key_c] = public_keys;
        let public_keys = [
            public_key_a.ok_or(SignatureInsertionError::InternalInvariant)?,
            public_key_b.ok_or(SignatureInsertionError::InternalInvariant)?,
            public_key_c.ok_or(SignatureInsertionError::InternalInvariant)?,
        ];
        let mut existing: [Option<Span>; 3] = [None, None, None];
        for record in records {
            if record.key_type != 0x02 {
                continue;
            }
            let role_index = public_keys
                .iter()
                .position(|candidate| candidate.as_slice().as_slice() == record.key_data)
                .ok_or(SignatureInsertionError::InternalInvariant)?;
            let slot = existing
                .get_mut(role_index)
                .ok_or(SignatureInsertionError::InternalInvariant)?;
            if slot.replace(record.value_span).is_some() {
                return Err(SignatureInsertionError::InternalInvariant);
            }
        }
        slots.push(InputSlots {
            public_keys,
            existing,
        });
    }
    Ok(slots)
}

fn normalize_submissions<'a>(
    submitted: &'a [SubmittedSignature<'a>],
    slots: &[InputSlots],
    baseline: &[u8],
) -> Result<WipingValueVec<NormalizedSignature<'a>>, SignatureInsertionError> {
    if submitted.len() > MAX_INSERTIONS {
        return Err(SignatureInsertionError::TooManyInsertions);
    }
    let all_complete = slots
        .iter()
        .all(|slot| slot.existing.iter().flatten().count() >= THRESHOLD);
    if all_complete {
        return Err(SignatureInsertionError::ThresholdAlreadyMet);
    }
    let mut normalized: WipingValueVec<NormalizedSignature<'a>> = WipingValueVec::new();
    normalized
        .try_reserve_exact(submitted.len())
        .map_err(|_| SignatureInsertionError::AllocationFailed)?;
    let mut request_counts = WipingValueVec::new();
    request_counts
        .try_reserve_exact(slots.len())
        .map_err(|_| SignatureInsertionError::AllocationFailed)?;
    request_counts.resize_with(slots.len(), || 0usize);

    for response in submitted {
        let input_index = usize::try_from(response.input_index)
            .map_err(|_| SignatureInsertionError::InputOutOfRange)?;
        let input = slots
            .get(input_index)
            .ok_or(SignatureInsertionError::InputOutOfRange)?;
        let existing_count = input.existing.iter().flatten().count();
        if existing_count >= THRESHOLD {
            return Err(SignatureInsertionError::ThresholdAlreadyMet);
        }
        let role_index = response.role.index();
        for existing_input in slots {
            for span in existing_input.existing.iter().flatten() {
                let value = span
                    .slice(baseline)
                    .ok_or(SignatureInsertionError::InternalInvariant)?;
                if value.last() == Some(&0x01)
                    && value.get(..value.len().saturating_sub(1)) == Some(response.der_signature)
                {
                    return Err(SignatureInsertionError::DuplicateSignature);
                }
            }
        }
        if let Some(span) = input
            .existing
            .get(role_index)
            .ok_or(SignatureInsertionError::InternalInvariant)?
        {
            if span.slice(baseline).is_none() {
                return Err(SignatureInsertionError::InternalInvariant);
            }
            return Err(SignatureInsertionError::SignatureConflict);
        }
        for pending in normalized.iter() {
            if pending.der_signature == response.der_signature {
                return Err(SignatureInsertionError::DuplicateSignature);
            }
            if pending.input_index == input_index && pending.role_index == role_index {
                return Err(SignatureInsertionError::DuplicateRole);
            }
        }
        if !(MIN_DER_BYTES..=MAX_LOW_S_DER_BYTES).contains(&response.der_signature.len()) {
            return Err(SignatureInsertionError::SignatureLength);
        }
        let count = request_counts
            .get_mut(input_index)
            .ok_or(SignatureInsertionError::InternalInvariant)?;
        *count = count
            .checked_add(1)
            .ok_or(SignatureInsertionError::InternalInvariant)?;
        normalized.push(NormalizedSignature {
            input_index,
            role_index,
            der_signature: response.der_signature,
        });
    }

    for (input, requested) in slots.iter().zip(request_counts.iter()) {
        let existing = input.existing.iter().flatten().count();
        let projected = existing
            .checked_add(*requested)
            .ok_or(SignatureInsertionError::InternalInvariant)?;
        // M15 never inserts beyond threshold on a targeted input. An
        // untouched input may already carry all three verified descriptor
        // roles while another input is completed; M16 deliberately accepts
        // that preexisting shape and selects the first two script positions.
        if *requested != 0 && projected > THRESHOLD {
            return Err(SignatureInsertionError::ThresholdWouldBeExceeded);
        }
    }
    normalized.sort_unstable_by(|left, right| {
        let left_key = slots[left.input_index].public_keys[left.role_index].as_slice();
        let right_key = slots[right.input_index].public_keys[right.role_index].as_slice();
        left.input_index
            .cmp(&right.input_index)
            .then_with(|| left_key.cmp(right_key))
    });
    Ok(normalized)
}

pub(super) fn insert_partial_signature(
    view: &PsbtView<'_>,
    bytes: &[u8],
    source: InputSource,
    input_index: usize,
    public_key: &[u8; 33],
    der_signature: &[u8],
) -> Result<(Vec<u8>, usize, usize), SignatureInsertionError> {
    let span = view
        .input_map_span(input_index)
        .ok_or(SignatureInsertionError::InputOutOfRange)?;
    let records = view
        .input_records(input_index)
        .ok_or(SignatureInsertionError::InternalInvariant)?;
    let mut insertion_offset = span.start;
    for record in records {
        let ordered_after = record.key_type > 0x02
            || (record.key_type == 0x02 && record.key_data > public_key.as_slice());
        if ordered_after {
            break;
        }
        insertion_offset = record.value_span.end;
    }
    if insertion_offset >= span.end || bytes.get(insertion_offset).is_none() {
        return Err(SignatureInsertionError::InternalInvariant);
    }
    let value_len = der_signature
        .len()
        .checked_add(1)
        .ok_or(SignatureInsertionError::InternalInvariant)?;
    let record_len = 1usize
        .checked_add(34)
        .and_then(|value| value.checked_add(1))
        .and_then(|value| value.checked_add(value_len))
        .ok_or(SignatureInsertionError::InternalInvariant)?;
    let next_len = bytes
        .len()
        .checked_add(record_len)
        .ok_or(SignatureInsertionError::ArtifactTooLarge)?;
    if next_len > source.max_bytes() {
        return Err(SignatureInsertionError::ArtifactTooLarge);
    }
    let mut next = WipingVec::take(Vec::new());
    next.try_reserve_exact(next_len)
        .map_err(|_| SignatureInsertionError::AllocationFailed)?;
    #[cfg(test)]
    LAST_PARTIAL_OUTPUT_CAPACITY.with(|capacity| capacity.set(next.capacity()));
    next.extend_from_slice(
        bytes
            .get(..insertion_offset)
            .ok_or(SignatureInsertionError::InternalInvariant)?,
    );
    next.push(34);
    next.push(0x02);
    next.extend_from_slice(public_key);
    next.push(u8::try_from(value_len).map_err(|_| SignatureInsertionError::InternalInvariant)?);
    next.extend_from_slice(der_signature);
    next.push(0x01);
    next.extend_from_slice(
        bytes
            .get(insertion_offset..)
            .ok_or(SignatureInsertionError::InternalInvariant)?,
    );
    if next.len() != next_len {
        return Err(SignatureInsertionError::InternalInvariant);
    }
    Ok((next.into_vec(), insertion_offset, record_len))
}

pub(super) fn exact_insert_delta(
    previous: &[u8],
    next: &[u8],
    offset: usize,
    inserted: usize,
) -> bool {
    let suffix = match offset.checked_add(inserted) {
        Some(value) => value,
        None => return false,
    };
    next.get(..offset) == previous.get(..offset)
        && next.get(suffix..) == previous.get(offset..)
        && next.len() == previous.len().saturating_add(inserted)
}

fn frozen_facts_equal(left: &Review<'_>, right: &Review<'_>) -> bool {
    left.context() == right.context()
        && left.wallet_id() == right.wallet_id()
        && left.origin_fingerprints() == right.origin_fingerprints()
        && left.unsigned_tx_bytes() == right.unsigned_tx_bytes()
        && left.version() == right.version()
        && left.locktime() == right.locktime()
        && left.outputs() == right.outputs()
        && left.total_input_amount() == right.total_input_amount()
        && left.total_output_amount() == right.total_output_amount()
        && left.fee() == right.fee()
        && left.inputs().len() == right.inputs().len()
        && left.inputs().iter().zip(right.inputs()).all(|(a, b)| {
            a.index == b.index
                && a.outpoint_txid_wire == b.outpoint_txid_wire
                && a.outpoint_vout == b.outpoint_vout
                && a.prevout_amount == b.prevout_amount
                && a.prevout_script_pubkey == b.prevout_script_pubkey
                && a.sequence == b.sequence
                && a.effective_sighash == b.effective_sighash
                && a.branch == b.branch
                && a.child_index == b.child_index
        })
}

fn signature_state_equal(left: &Review<'_>, right: &Review<'_>) -> bool {
    left.aggregate_status() == right.aggregate_status()
        && left.inputs().iter().zip(right.inputs()).all(|(a, b)| {
            a.verified_signature_count == b.verified_signature_count
                && a.verified_status == b.verified_status
        })
}

impl SignatureState {
    fn from_review(review: &Review<'_>) -> Result<Self, SignatureInsertionError> {
        let mut inputs = WipingValueVec::new();
        inputs
            .try_reserve_exact(review.inputs().len())
            .map_err(|_| SignatureInsertionError::AllocationFailed)?;
        inputs.extend(
            review
                .inputs()
                .iter()
                .map(|input| (input.verified_signature_count, input.verified_status)),
        );
        Ok(Self {
            inputs,
            aggregate: review.aggregate_status(),
        })
    }
}

fn allowed_review_step(
    approved: &Review<'_>,
    previous: &mut SignatureState,
    next: &Review<'_>,
    changed_input: usize,
) -> bool {
    if !frozen_facts_equal(approved, next) || previous.inputs.len() != next.inputs().len() {
        return false;
    }
    for (index, ((before_count, before_status), after)) in
        previous.inputs.iter().zip(next.inputs()).enumerate()
    {
        if index == changed_input {
            if before_count.checked_add(1) != Some(after.verified_signature_count) {
                return false;
            }
        } else if *before_count != after.verified_signature_count
            || *before_status != after.verified_status
        {
            return false;
        }
        let expected = if after.verified_signature_count >= 2 {
            VerifiedInputStatus::CryptographicallyVerifiedThreshold
        } else {
            VerifiedInputStatus::BelowThreshold
        };
        if after.verified_status != expected {
            return false;
        }
    }
    let all_complete = next.inputs().iter().all(|input| {
        input.verified_status == VerifiedInputStatus::CryptographicallyVerifiedThreshold
    });
    let all_below = next
        .inputs()
        .iter()
        .all(|input| input.verified_status == VerifiedInputStatus::BelowThreshold);
    let expected_aggregate = if all_complete {
        VerifiedAggregateStatus::VerifyAndExportOnly
    } else if all_below {
        VerifiedAggregateStatus::AllInputsBelowThreshold
    } else {
        VerifiedAggregateStatus::MixedInputCompleteness
    };
    if next.aggregate_status() != expected_aggregate {
        return false;
    }
    for (state, after) in previous.inputs.iter_mut().zip(next.inputs()) {
        *state = (after.verified_signature_count, after.verified_status);
    }
    previous.aggregate = next.aggregate_status();
    true
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::transaction_wipe_v2::{reset_wiped_bytes, wiped_bytes};
    use crate::ReviewWorkflowEvent;
    use qk_descriptor::{parse_descriptor_pair, DescriptorPair};
    use std::panic::{catch_unwind, AssertUnwindSafe};

    const FIXTURE: &str = include_str!("../tests/fixtures/signature_insertion.txt");

    fn case_block(name: &str) -> &str {
        FIXTURE
            .split("\n\n")
            .find(|block| {
                block
                    .lines()
                    .next()
                    .and_then(|line| line.strip_prefix("case: "))
                    == Some(name)
            })
            .expect("fixture case")
    }

    fn field<'a>(block: &'a str, name: &str) -> &'a str {
        block
            .lines()
            .find_map(|line| line.strip_prefix(name))
            .expect("fixture field")
    }

    fn decode_hex(value: &str) -> Vec<u8> {
        value
            .as_bytes()
            .chunks_exact(2)
            .map(|pair| {
                u8::from_str_radix(core::str::from_utf8(pair).expect("ASCII hex"), 16)
                    .expect("valid hex")
            })
            .collect()
    }

    fn descriptor(block: &str) -> DescriptorPair {
        parse_descriptor_pair(
            field(block, "receive_descriptor: ").as_bytes(),
            field(block, "change_descriptor: ").as_bytes(),
        )
        .expect("fixture descriptor")
    }

    fn reach_sign_permitted<'a>(
        s0: &'a [u8],
        descriptor: &'a DescriptorPair,
    ) -> ReviewBoundWorkflow<'a> {
        let mut workflow = ReviewBoundWorkflow::new(s0, descriptor, InputSource::MicroSd);
        for event in [
            ReviewWorkflowEvent::Wake,
            ReviewWorkflowEvent::BeginValidation,
            ReviewWorkflowEvent::RequestApproval,
            ReviewWorkflowEvent::Approve,
            ReviewWorkflowEvent::BeginRevalidation,
        ] {
            workflow.apply(event).expect("workflow transition");
        }
        workflow.revalidate().expect("bound revalidation");
        assert_eq!(workflow.state(), TransactionState::SignPermitted);
        workflow
    }

    fn assert_locked(workflow: &ReviewBoundWorkflow<'_>) {
        assert_eq!(workflow.state(), TransactionState::Locked);
        assert!(workflow.is_finished());
        assert!(!workflow.has_review_binding());
        assert!(!workflow.has_approved_token());
    }

    #[test]
    fn insertion_gate_rejects_missing_stale_and_changed_bindings_before_mutation() {
        let missing_block = case_block("M15-MISSING-TOKEN");
        assert_eq!(field(missing_block, "expected: "), "MissingApprovedToken");
        let missing_s0 = decode_hex(field(missing_block, "initial_psbt_hex: "));
        let missing_descriptor = descriptor(missing_block);

        let mut missing = reach_sign_permitted(&missing_s0, &missing_descriptor);
        missing.approved_token = None;
        assert_eq!(
            missing.insert_and_emit_signatures(&[]).err(),
            Some(SignatureInsertionError::MissingApprovedToken)
        );
        assert_locked(&missing);

        let stale_block = case_block("M15-STALE-TOKEN");
        assert_eq!(field(stale_block, "expected: "), "TokenMismatch");
        let stale_s0 = decode_hex(field(stale_block, "initial_psbt_hex: "));
        let stale_descriptor = descriptor(stale_block);
        let foreign = reach_sign_permitted(&stale_s0, &stale_descriptor)
            .approved_token
            .expect("foreign token");
        let mut stale = reach_sign_permitted(&stale_s0, &stale_descriptor);
        stale.approved_token = Some(foreign);
        assert_eq!(
            stale.insert_and_emit_signatures(&[]).err(),
            Some(SignatureInsertionError::TokenMismatch)
        );
        assert_locked(&stale);

        let changed_block = case_block("M15-REVIEW-HASH-MISMATCH");
        assert_eq!(field(changed_block, "expected: "), "ReviewHashMismatch");
        let changed_s0 = decode_hex(field(changed_block, "initial_psbt_hex: "));
        let changed_descriptor = descriptor(changed_block);
        let mut changed = reach_sign_permitted(&changed_s0, &changed_descriptor);
        changed.approved_hash.as_mut().expect("review hash")[0] ^= 1;
        assert_eq!(
            changed.insert_and_emit_signatures(&[]).err(),
            Some(SignatureInsertionError::ReviewHashMismatch)
        );
        assert_locked(&changed);
    }

    #[test]
    fn insertion_count_above_two_per_maximum_input_count_locks_without_output() {
        let block = case_block("M15-GOLDEN-SHUFFLED");
        let s0 = decode_hex(field(block, "initial_psbt_hex: "));
        let descriptor = descriptor(block);
        let response = field(block, "response_0: ");
        let der = decode_hex(response.rsplit('|').next().expect("response DER"));
        let repeated = vec![
            SubmittedSignature {
                input_index: 0,
                role: DescriptorRole::A,
                der_signature: &der,
            };
            MAX_INSERTIONS + 1
        ];
        let mut workflow = reach_sign_permitted(&s0, &descriptor);
        assert_eq!(
            workflow.insert_and_emit_signatures(&repeated).err(),
            Some(SignatureInsertionError::TooManyInsertions)
        );
        assert_locked(&workflow);
    }

    #[test]
    fn existing_signature_bytes_replayed_for_another_input_reject_as_duplicate() {
        let block = case_block("M15-EXISTING-ONE");
        let s0 = decode_hex(field(block, "initial_psbt_hex: "));
        let descriptor = descriptor(block);
        let view = parse(&s0, InputSource::MicroSd).expect("fixture parse");
        let existing = view
            .input_records(0)
            .expect("input records")
            .find(|record| record.key_type == 0x02)
            .expect("existing signature")
            .value;
        assert_eq!(existing.last(), Some(&0x01));
        let der = existing
            .get(..existing.len().saturating_sub(1))
            .expect("DER bytes");
        let response = [SubmittedSignature {
            input_index: 1,
            role: DescriptorRole::A,
            der_signature: der,
        }];
        let mut workflow = reach_sign_permitted(&s0, &descriptor);
        assert_eq!(
            workflow.insert_and_emit_signatures(&response).err(),
            Some(SignatureInsertionError::DuplicateSignature)
        );
        assert_locked(&workflow);
    }

    #[test]
    fn complete_input_preservation_work_bounds_match_closed_combinatorics() {
        let mut max_per_record = (0usize, 0usize, 0usize, 0usize, 0usize);
        let mut max_whole_method = (0usize, 0usize, 0usize, 0usize, 0usize);
        for complete_inputs in 0usize..=100 {
            let incomplete_inputs = 100usize
                .checked_sub(complete_inputs)
                .expect("bounded subtraction");
            for singly_signed_inputs in 0usize..=incomplete_inputs {
                let insertions = incomplete_inputs
                    .checked_mul(2)
                    .and_then(|value| value.checked_sub(singly_signed_inputs))
                    .expect("bounded insertion count");
                let initial_signatures = complete_inputs
                    .checked_mul(3)
                    .and_then(|value| value.checked_add(singly_signed_inputs))
                    .expect("bounded initial count");
                let triangular = insertions
                    .checked_mul(insertions.checked_add(1).expect("bounded increment"))
                    .and_then(|value| value.checked_div(2))
                    .expect("bounded triangular count");
                let per_record = insertions
                    .checked_mul(initial_signatures)
                    .and_then(|value| value.checked_add(triangular))
                    .expect("bounded verification count");
                let whole_method = initial_signatures
                    .checked_mul(2)
                    .and_then(|value| value.checked_add(per_record))
                    .expect("bounded whole-method count");
                max_per_record = max_per_record.max((
                    per_record,
                    complete_inputs,
                    singly_signed_inputs,
                    insertions,
                    initial_signatures,
                ));
                max_whole_method = max_whole_method.max((
                    whole_method,
                    complete_inputs,
                    singly_signed_inputs,
                    insertions,
                    initial_signatures,
                ));
            }
        }
        assert_eq!(max_per_record, (22_575, 25, 0, 150, 75));
        assert_eq!(max_whole_method, (22_726, 26, 0, 148, 78));
        assert_eq!(MAX_INSERTIONS * 132 * 6, 158_400);
        assert_eq!((MAX_INSERTIONS + 2) * 132 * 6, 159_984);
    }

    #[test]
    fn partial_output_guard_clears_its_complete_capacity_on_rejection() {
        let block = case_block("M15-GOLDEN-SHUFFLED");
        let s0 = decode_hex(field(block, "initial_psbt_hex: "));
        let descriptor = descriptor(block);
        let view = parse(&s0, InputSource::MicroSd).expect("fixture parse");
        let slots = collect_slots(&view, descriptor.origin_fingerprints()).expect("fixture slots");
        let public_key = slots[0].public_keys[0].as_slice();
        let oversized_value = [0x31; 255];
        let record_len = 1 + 34 + 1 + oversized_value.len() + 1;
        let minimum_capacity = s0.len() + record_len;

        reset_wiped_bytes();
        assert_eq!(
            insert_partial_signature(
                &view,
                &s0,
                InputSource::MicroSd,
                0,
                public_key,
                &oversized_value,
            )
            .err(),
            Some(SignatureInsertionError::InternalInvariant)
        );
        let actual_capacity = LAST_PARTIAL_OUTPUT_CAPACITY.with(core::cell::Cell::get);
        assert!(actual_capacity >= minimum_capacity);
        assert_eq!(wiped_bytes(), actual_capacity);
    }

    #[test]
    fn slot_table_clears_key_bytes_and_spare_capacity_during_unwind() {
        let mut slots = WipingValueVec::new();
        slots.try_reserve_exact(2).unwrap();
        slots.push(InputSlots {
            public_keys: [
                WipingArray::new([0x11; 33]),
                WipingArray::new([0x22; 33]),
                WipingArray::new([0x33; 33]),
            ],
            existing: [None, Some(Span { start: 7, end: 11 }), None],
        });
        let table_capacity = slots.capacity() * core::mem::size_of::<InputSlots>();

        reset_wiped_bytes();
        let result = catch_unwind(AssertUnwindSafe(move || {
            let _slots = slots;
            panic!("bounded insertion unwind probe");
        }));
        assert!(result.is_err());
        assert_eq!(wiped_bytes(), (3 * 33) + table_capacity);
    }
}
