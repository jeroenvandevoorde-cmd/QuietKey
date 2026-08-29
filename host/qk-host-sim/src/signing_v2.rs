//! Non-authorizing v2 HOST signing continuation from schema-v3 ReviewReady.

use crate::finalization::FinalizedTransaction;
use crate::finalization_v2::{finalize_v2, FinalizationV2Error};
use crate::insertion::{exact_insert_delta, insert_partial_signature};
use crate::ReviewReadyV3Workflow;
use core::fmt;
use qk_descriptor::{derive_change_script_v2, derive_receive_script_v2, DescriptorPairV2};
use qk_psbt::bip143::{sighash_all_digest, Bip143InputFacts, Bip143PrecomputeBuilder, SIGHASH_ALL};
use qk_psbt::{
    analyze_descriptor_ownership_v2, build_review_v3, canonical_serialize, parse, InputSource,
    OwnedS0, PsbtView, ReviewContext, ReviewNetwork, ReviewV3, ReviewV3Error, SemanticError,
    SerializeError, Span, VerifiedAggregateStatus,
};
use qk_secp::{SecpError, SecretKey};

const THRESHOLD: usize = 2;
const ROLE_COUNT: usize = 2;
const MAX_INSERTIONS: usize = 200;
const DER_CONTAINER_BYTES: usize = 72;

/// One role-A child signing key for an unsigned-transaction input.
///
/// Secret ownership remains entirely inside qk-secp's opaque, zeroizing
/// [`SecretKey`]. This wrapper deliberately exposes only its public input
/// coordinate and implements no secret-revealing trait or accessor.
pub struct TerminalInputKeyV2 {
    input_index: u32,
    secret_key: SecretKey,
}

impl TerminalInputKeyV2 {
    /// Bind one opaque qk-secp secret owner to an input index.
    #[must_use]
    pub fn new(input_index: u32, secret_key: SecretKey) -> Self {
        Self {
            input_index,
            secret_key,
        }
    }

    /// Public input coordinate to which the opaque key is bound.
    #[must_use]
    pub const fn input_index(&self) -> u32 {
        self.input_index
    }
}

/// One DER-only mock response for the sole v2 card role B.
///
/// The continuation derives both the role-B public key and exact digest.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MockCardBSignature<'a> {
    /// Unsigned-transaction input index.
    pub input_index: u32,
    /// Strict low-S DER bytes without the fixed SIGHASH_ALL byte.
    pub der_signature: &'a [u8],
}

/// Stable slice-3 signing failure. No variant carries hostile or secret bytes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SigningV2Error {
    /// The consumed workflow was not successfully at schema-v3 ReviewReady.
    WrongState,
    /// Retained S0 no longer matches the bound schema-v3 identity.
    RetainedS0Mismatch,
    /// Retained or intermediate PSBT bytes failed structural parsing.
    ParseFailed,
    /// Schema-v3 reconstruction rejected.
    ReviewRebuild(ReviewV3Error),
    /// A rebuilt candidate changed an approval-relevant schema-v3 fact.
    ReviewFactsMismatch,
    /// The retained S0 rebuild changed the bound pre-signing review hash.
    ReviewHashMismatch,
    /// Existing partial-signature cryptography or descriptor proof rejected.
    ExistingSignatureVerification(SemanticError),
    /// BIP143 digest construction failed closed.
    DigestFailed,
    /// M5 canonical serialization failed.
    SerializeFailed(SerializeError),
    /// A supplied input index does not exist.
    InputOutOfRange,
    /// More than one terminal key names the same input.
    DuplicateTerminalKey,
    /// An incomplete input without role A lacks its terminal key.
    MissingTerminalKey,
    /// A terminal key was supplied where role A was already occupied.
    UnexpectedTerminalKey,
    /// The opaque terminal secret does not correspond to descriptor role A.
    TerminalKeyMismatch,
    /// Exact signature bytes repeat an existing or pending signature.
    DuplicateSignature,
    /// More than one mock response claims role B for one input.
    DuplicateRole,
    /// A mock response claims an already occupied role-B slot.
    SignatureConflict,
    /// A response or key targets an already complete input.
    ThresholdAlreadyMet,
    /// New records would place an input above the two-signature threshold.
    ThresholdWouldBeExceeded,
    /// At least one input cannot reach exactly A+B completion.
    ThresholdIncomplete,
    /// More than the transaction-wide insertion cap was requested.
    TooManyInsertions,
    /// Deterministic terminal signing failed at the pinned qk-secp boundary.
    TerminalSigning(SecpError),
    /// The serialized terminal signature failed its immediate self-check.
    TerminalPreInsertionVerificationFailed,
    /// A role-B mock failed syntax, low-S, key, or digest verification.
    InvalidMockSignature,
    /// An insertion changed bytes outside its one exact type-02 record.
    ForbiddenDelta,
    /// An intermediate PSBT was not an exact M5 fixed point.
    NonCanonicalOutput,
    /// An intermediate PSBT exceeded its retained source cap.
    ArtifactTooLarge,
    /// A bounded allocation failed.
    AllocationFailed,
    /// Native 2-of-2 finalization or final re-verification rejected.
    Finalization(FinalizationV2Error),
    /// A parser-, descriptor-, or workflow-established invariant failed.
    InternalInvariant,
}

impl fmt::Display for SigningV2Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::WrongState => f.write_str("v2 signing continuation state invalid"),
            Self::RetainedS0Mismatch => f.write_str("retained S0 identity mismatch"),
            Self::ParseFailed => f.write_str("v2 signing PSBT parse failed"),
            Self::ReviewRebuild(error) => write!(f, "schema-v3 review rebuild failed: {error}"),
            Self::ReviewFactsMismatch => f.write_str("schema-v3 review facts changed"),
            Self::ReviewHashMismatch => f.write_str("schema-v3 review hash changed"),
            Self::ExistingSignatureVerification(error) => {
                write!(f, "existing signature verification failed: {error}")
            }
            Self::DigestFailed => f.write_str("v2 BIP143 digest construction failed"),
            Self::SerializeFailed(error) => write!(f, "v2 serialization failed: {error:?}"),
            Self::InputOutOfRange => f.write_str("signature input index out of range"),
            Self::DuplicateTerminalKey => f.write_str("duplicate terminal input key"),
            Self::MissingTerminalKey => f.write_str("terminal role-A key missing"),
            Self::UnexpectedTerminalKey => f.write_str("terminal role-A key not required"),
            Self::TerminalKeyMismatch => f.write_str("terminal key does not match role A"),
            Self::DuplicateSignature => f.write_str("duplicate signature"),
            Self::DuplicateRole => f.write_str("duplicate role-B response"),
            Self::SignatureConflict => f.write_str("role-B signature conflict"),
            Self::ThresholdAlreadyMet => f.write_str("signature threshold already met"),
            Self::ThresholdWouldBeExceeded => f.write_str("signature threshold would be exceeded"),
            Self::ThresholdIncomplete => f.write_str("signature threshold incomplete"),
            Self::TooManyInsertions => f.write_str("too many signature insertions"),
            Self::TerminalSigning(error) => write!(f, "terminal signing failed: {error}"),
            Self::TerminalPreInsertionVerificationFailed => {
                f.write_str("terminal signature pre-insertion verification failed")
            }
            Self::InvalidMockSignature => f.write_str("invalid mock role-B signature"),
            Self::ForbiddenDelta => f.write_str("v2 insertion changed a frozen fact"),
            Self::NonCanonicalOutput => f.write_str("v2 PSBT is not canonical"),
            Self::ArtifactTooLarge => f.write_str("v2 PSBT exceeds source byte cap"),
            Self::AllocationFailed => f.write_str("v2 bounded allocation failed"),
            Self::Finalization(error) => write!(f, "v2 finalization failed: {error}"),
            Self::InternalInvariant => f.write_str("v2 signing invariant failed"),
        }
    }
}

impl std::error::Error for SigningV2Error {}

#[derive(Clone, Copy)]
struct InputSlots {
    role_keys: [[u8; 33]; ROLE_COUNT],
    existing: [Option<Span>; ROLE_COUNT],
    digest: [u8; 32],
}

struct PlannedSignature {
    input_index: usize,
    public_key: [u8; 33],
    der_signature: Vec<u8>,
}

#[derive(Clone, Copy)]
struct PendingAction {
    input_index: usize,
    role: usize,
    public_key: [u8; 33],
}

#[derive(Clone, Copy)]
struct RequestCounts {
    terminal: usize,
    mock_card_b: usize,
}

impl ReviewReadyV3Workflow {
    /// Consume one successful schema-v3 workflow, complete every incomplete
    /// input with descriptor roles A and B, finalize, extract, freshly reparse,
    /// and verify the resulting transaction.
    ///
    /// This HOST seam carries no approval, cycle token, physical card session,
    /// transport, export, or production authorization. Every failure consumes
    /// all inputs and releases no intermediate PSBT or signature.
    pub fn sign_and_finalize_v2(
        self,
        terminal_keys: Vec<TerminalInputKeyV2>,
        mock_signatures: &[MockCardBSignature<'_>],
    ) -> Result<FinalizedTransaction, SigningV2Error> {
        let (descriptor, ready) = self
            .into_signing_parts()
            .ok_or(SigningV2Error::WrongState)?;
        let (s0, bound_review, bound_hash) = ready.into_signing_parts();
        sign_and_finalize(
            s0,
            descriptor,
            bound_review,
            bound_hash,
            terminal_keys,
            mock_signatures,
        )
    }
}

fn sign_and_finalize(
    s0: OwnedS0,
    descriptor: DescriptorPairV2,
    bound_review: ReviewV3,
    bound_hash: [u8; 32],
    terminal_keys: Vec<TerminalInputKeyV2>,
    mock_signatures: &[MockCardBSignature<'_>],
) -> Result<FinalizedTransaction, SigningV2Error> {
    if s0.sha256() != bound_review.s0_sha256() {
        return Err(SigningV2Error::RetainedS0Mismatch);
    }
    let source = s0.source();
    let retained_view = s0.parse().map_err(|_| SigningV2Error::ParseFailed)?;
    if retained_view.buffer().as_ptr() != s0.bytes().as_ptr()
        || retained_view.buffer().len() != s0.bytes().len()
        || retained_view.source() != source
    {
        return Err(SigningV2Error::RetainedS0Mismatch);
    }
    let rebuilt = build_review(&retained_view, &descriptor, source)?;
    if rebuilt != bound_review {
        return Err(SigningV2Error::ReviewFactsMismatch);
    }
    let rebuilt_hash = rebuilt
        .review_hash()
        .map_err(SigningV2Error::ReviewRebuild)?;
    if rebuilt_hash != bound_hash {
        return Err(SigningV2Error::ReviewHashMismatch);
    }
    analyze_descriptor_ownership_v2(&retained_view, &descriptor)
        .map_err(SigningV2Error::ExistingSignatureVerification)?;

    let mut current =
        canonical_serialize(&retained_view).map_err(SigningV2Error::SerializeFailed)?;
    drop(retained_view);
    let baseline_view = parse(&current, source).map_err(|_| SigningV2Error::ParseFailed)?;
    let baseline_review = build_review(&baseline_view, &descriptor, source)?;
    if !transition_review_facts_equal(&bound_review, &baseline_review) {
        return Err(SigningV2Error::ReviewFactsMismatch);
    }
    let verified = analyze_descriptor_ownership_v2(&baseline_view, &descriptor)
        .map_err(SigningV2Error::ExistingSignatureVerification)?;
    let mut verified_counts = Vec::new();
    verified_counts
        .try_reserve_exact(verified.verified_inputs.len())
        .map_err(|_| SigningV2Error::AllocationFailed)?;
    verified_counts.extend(
        verified
            .verified_inputs
            .iter()
            .map(|input| input.verified_signature_count),
    );

    let slots = collect_slots(&baseline_view, &descriptor, &baseline_review)?;
    let planned =
        plan_and_verify_signatures(&baseline_view, &slots, &terminal_keys, mock_signatures)?;
    drop(baseline_view);

    for signature in planned {
        let previous = current;
        let previous_view = parse(&previous, source).map_err(|_| SigningV2Error::ParseFailed)?;
        let (next, offset, inserted) = insert_partial_signature(
            &previous_view,
            &previous,
            source,
            signature.input_index,
            &signature.public_key,
            &signature.der_signature,
        )
        .map_err(map_insertion_error)?;
        if !exact_insert_delta(&previous, &next, offset, inserted) {
            return Err(SigningV2Error::ForbiddenDelta);
        }
        let next_view = parse(&next, source).map_err(|_| SigningV2Error::ParseFailed)?;
        let canonical = canonical_serialize(&next_view).map_err(SigningV2Error::SerializeFailed)?;
        if canonical != next {
            return Err(SigningV2Error::NonCanonicalOutput);
        }
        let next_review = build_review(&next_view, &descriptor, source)?;
        if !transition_review_facts_equal(&bound_review, &next_review) {
            return Err(SigningV2Error::ForbiddenDelta);
        }
        let next_verified = analyze_descriptor_ownership_v2(&next_view, &descriptor)
            .map_err(SigningV2Error::ExistingSignatureVerification)?;
        advance_verified_counts(
            &mut verified_counts,
            &next_verified.verified_inputs,
            signature.input_index,
        )?;
        current = next;
    }

    let complete_view = parse(&current, source).map_err(|_| SigningV2Error::ParseFailed)?;
    let complete = analyze_descriptor_ownership_v2(&complete_view, &descriptor)
        .map_err(SigningV2Error::ExistingSignatureVerification)?;
    if complete.aggregate_status != VerifiedAggregateStatus::VerifyAndExportOnly
        || complete
            .verified_inputs
            .iter()
            .any(|input| input.verified_signature_count != THRESHOLD)
    {
        return Err(SigningV2Error::ThresholdIncomplete);
    }
    let canonical = canonical_serialize(&complete_view).map_err(SigningV2Error::SerializeFailed)?;
    if canonical != current {
        return Err(SigningV2Error::NonCanonicalOutput);
    }
    drop(complete_view);

    finalize_v2(current, source, &descriptor, &bound_review).map_err(SigningV2Error::Finalization)
}

fn build_review(
    view: &PsbtView<'_>,
    descriptor: &DescriptorPairV2,
    source: InputSource,
) -> Result<ReviewV3, SigningV2Error> {
    build_review_v3(
        view,
        descriptor,
        ReviewContext {
            network: ReviewNetwork::BitcoinMainnet,
            input_source: source,
        },
    )
    .map_err(SigningV2Error::ReviewRebuild)
}

fn transition_review_facts_equal(left: &ReviewV3, right: &ReviewV3) -> bool {
    left.context() == right.context()
        && left.wallet_id() == right.wallet_id()
        && left.origin_fingerprints() == right.origin_fingerprints()
        && left.fee_policy_identifier() == right.fee_policy_identifier()
        && left.unsigned_tx_bytes() == right.unsigned_tx_bytes()
        && left.version() == right.version()
        && left.locktime() == right.locktime()
        && left.inputs() == right.inputs()
        && left.outputs() == right.outputs()
        && left.total_input_amount() == right.total_input_amount()
        && left.total_output_amount() == right.total_output_amount()
        && left.fee() == right.fee()
        && left.fee_policy() == right.fee_policy()
}

fn collect_slots(
    view: &PsbtView<'_>,
    descriptor: &DescriptorPairV2,
    review: &ReviewV3,
) -> Result<Vec<InputSlots>, SigningV2Error> {
    if view.input_map_count() != review.inputs().len() {
        return Err(SigningV2Error::InternalInvariant);
    }
    let digests = compute_input_digests(review, descriptor)?;
    let fingerprints = descriptor.origin_fingerprints();
    let mut slots = Vec::new();
    slots
        .try_reserve_exact(view.input_map_count())
        .map_err(|_| SigningV2Error::AllocationFailed)?;
    for input_index in 0..view.input_map_count() {
        let records = view
            .input_records(input_index)
            .ok_or(SigningV2Error::InternalInvariant)?;
        let mut role_keys: [Option<[u8; 33]>; ROLE_COUNT] = [None, None];
        for record in records.clone() {
            if record.key_type != 0x06 {
                continue;
            }
            let fingerprint = record
                .value
                .get(..4)
                .ok_or(SigningV2Error::InternalInvariant)?;
            let role = fingerprints
                .iter()
                .position(|candidate| candidate.as_slice() == fingerprint)
                .ok_or(SigningV2Error::InternalInvariant)?;
            let key: [u8; 33] = record
                .key_data
                .try_into()
                .map_err(|_| SigningV2Error::InternalInvariant)?;
            let target = role_keys
                .get_mut(role)
                .ok_or(SigningV2Error::InternalInvariant)?;
            if target.replace(key).is_some() {
                return Err(SigningV2Error::InternalInvariant);
            }
        }
        let role_keys = [
            role_keys[0].ok_or(SigningV2Error::InternalInvariant)?,
            role_keys[1].ok_or(SigningV2Error::InternalInvariant)?,
        ];
        let mut existing: [Option<Span>; ROLE_COUNT] = [None, None];
        for record in records {
            if record.key_type != 0x02 {
                continue;
            }
            let role = role_keys
                .iter()
                .position(|candidate| candidate.as_slice() == record.key_data)
                .ok_or(SigningV2Error::InternalInvariant)?;
            let target = existing
                .get_mut(role)
                .ok_or(SigningV2Error::InternalInvariant)?;
            if target.replace(record.value_span).is_some() {
                return Err(SigningV2Error::InternalInvariant);
            }
        }
        slots.push(InputSlots {
            role_keys,
            existing,
            digest: *digests
                .get(input_index)
                .ok_or(SigningV2Error::InternalInvariant)?,
        });
    }
    Ok(slots)
}

fn derive_script(
    descriptor: &DescriptorPairV2,
    branch: u32,
    index: u32,
) -> Result<qk_descriptor::DerivedScriptV2, SigningV2Error> {
    match branch {
        0 => derive_receive_script_v2(descriptor, index),
        1 => derive_change_script_v2(descriptor, index),
        _ => return Err(SigningV2Error::InternalInvariant),
    }
    .map_err(|_| SigningV2Error::InternalInvariant)
}

fn compute_input_digests(
    review: &ReviewV3,
    descriptor: &DescriptorPairV2,
) -> Result<Vec<[u8; 32]>, SigningV2Error> {
    let mut builder = Bip143PrecomputeBuilder::new();
    for input in review.inputs() {
        let txid = input.outpoint_txid_wire();
        builder
            .add_input(&txid, input.outpoint_vout(), input.sequence())
            .map_err(|_| SigningV2Error::DigestFailed)?;
    }
    for output in review.outputs() {
        builder
            .add_output(output.amount(), output.script_pubkey())
            .map_err(|_| SigningV2Error::DigestFailed)?;
    }
    let precomputed = builder.finish().map_err(|_| SigningV2Error::DigestFailed)?;
    let mut digests = Vec::new();
    digests
        .try_reserve_exact(review.inputs().len())
        .map_err(|_| SigningV2Error::AllocationFailed)?;
    for input in review.inputs() {
        if input.effective_sighash() != u32::from(SIGHASH_ALL) {
            return Err(SigningV2Error::InternalInvariant);
        }
        let script = derive_script(descriptor, input.branch(), input.child_index())?;
        let txid = input.outpoint_txid_wire();
        let facts = Bip143InputFacts {
            outpoint_txid_wire: &txid,
            outpoint_vout: input.outpoint_vout(),
            script_code: &script.witness_script,
            amount_sats: input.prevout_amount(),
            sequence: input.sequence(),
        };
        digests.push(
            sighash_all_digest(review.version(), review.locktime(), &precomputed, &facts)
                .map_err(|_| SigningV2Error::DigestFailed)?,
        );
    }
    Ok(digests)
}

fn plan_and_verify_signatures(
    view: &PsbtView<'_>,
    slots: &[InputSlots],
    terminal_keys: &[TerminalInputKeyV2],
    mock_signatures: &[MockCardBSignature<'_>],
) -> Result<Vec<PlannedSignature>, SigningV2Error> {
    if terminal_keys.len().saturating_add(mock_signatures.len()) > MAX_INSERTIONS {
        return Err(SigningV2Error::TooManyInsertions);
    }
    let mut terminals_by_input: Vec<Vec<&TerminalInputKeyV2>> = Vec::new();
    terminals_by_input
        .try_reserve_exact(slots.len())
        .map_err(|_| SigningV2Error::AllocationFailed)?;
    for _ in slots {
        terminals_by_input.push(Vec::new());
    }
    for terminal in terminal_keys {
        let index =
            usize::try_from(terminal.input_index).map_err(|_| SigningV2Error::InputOutOfRange)?;
        let input = terminals_by_input
            .get_mut(index)
            .ok_or(SigningV2Error::InputOutOfRange)?;
        input
            .try_reserve(1)
            .map_err(|_| SigningV2Error::AllocationFailed)?;
        input.push(terminal);
    }

    let mut mocks_by_input: Vec<Vec<&MockCardBSignature<'_>>> = Vec::new();
    mocks_by_input
        .try_reserve_exact(slots.len())
        .map_err(|_| SigningV2Error::AllocationFailed)?;
    for _ in slots {
        mocks_by_input.push(Vec::new());
    }
    for mock_signature in mock_signatures {
        let index = usize::try_from(mock_signature.input_index)
            .map_err(|_| SigningV2Error::InputOutOfRange)?;
        let input = mocks_by_input
            .get_mut(index)
            .ok_or(SigningV2Error::InputOutOfRange)?;
        input
            .try_reserve(1)
            .map_err(|_| SigningV2Error::AllocationFailed)?;
        input.push(mock_signature);
    }

    let mut request_counts = Vec::new();
    request_counts
        .try_reserve_exact(slots.len())
        .map_err(|_| SigningV2Error::AllocationFailed)?;
    for (terminals, mocks) in terminals_by_input.iter().zip(&mocks_by_input) {
        request_counts.push(RequestCounts {
            terminal: terminals.len(),
            mock_card_b: mocks.len(),
        });
    }
    let pending = ordered_pending_actions(slots, &request_counts)?;

    let mut planned = Vec::new();
    planned
        .try_reserve_exact(terminal_keys.len().saturating_add(mock_signatures.len()))
        .map_err(|_| SigningV2Error::AllocationFailed)?;
    for action in pending {
        let input_index = action.input_index;
        let slot = slots
            .get(input_index)
            .ok_or(SigningV2Error::InternalInvariant)?;
        let existing_count = slot.existing.iter().flatten().count();
        let terminals = terminals_by_input
            .get(input_index)
            .ok_or(SigningV2Error::InternalInvariant)?;
        let mocks = mocks_by_input
            .get(input_index)
            .ok_or(SigningV2Error::InternalInvariant)?;
        match action.role {
            0 => {
                if terminals.len() > 1 {
                    return Err(SigningV2Error::DuplicateTerminalKey);
                }
                if existing_count >= THRESHOLD {
                    return Err(SigningV2Error::ThresholdAlreadyMet);
                }
                if slot.existing[0].is_some() {
                    if !terminals.is_empty() {
                        return Err(SigningV2Error::UnexpectedTerminalKey);
                    }
                    continue;
                }
                let terminal = terminals
                    .first()
                    .ok_or(SigningV2Error::MissingTerminalKey)?;
                let expected = qk_secp::pubkey_parse_compressed(&action.public_key)
                    .map_err(|_| SigningV2Error::InternalInvariant)?;
                let signature = match qk_secp::ecdsa_sign_rfc6979(
                    &terminal.secret_key,
                    &slot.digest,
                    &expected,
                ) {
                    Err(SecpError::SelfVerificationFailed) => {
                        return Err(SigningV2Error::TerminalKeyMismatch)
                    }
                    Err(error) => return Err(SigningV2Error::TerminalSigning(error)),
                    Ok(signature) => signature,
                };
                let der = serialize_and_verify_signature(
                    &signature,
                    &slot.digest,
                    &expected,
                    SigningV2Error::TerminalPreInsertionVerificationFailed,
                )?;
                if signature_matches_existing_or_planned(view, &planned, &der)? {
                    return Err(SigningV2Error::DuplicateSignature);
                }
                planned.push(PlannedSignature {
                    input_index,
                    public_key: action.public_key,
                    der_signature: der,
                });
            }
            1 => {
                if existing_count >= THRESHOLD {
                    return Err(SigningV2Error::ThresholdAlreadyMet);
                }
                if mock_group_repeats_existing_or_itself(view, mocks)? {
                    return Err(SigningV2Error::DuplicateSignature);
                }
                if mocks.len() > 1 {
                    return Err(SigningV2Error::DuplicateRole);
                }
                if slot.existing[1].is_some() {
                    if !mocks.is_empty() {
                        return Err(SigningV2Error::SignatureConflict);
                    }
                    continue;
                }
                let mock = mocks.first().ok_or(SigningV2Error::ThresholdIncomplete)?;
                if planned
                    .iter()
                    .any(|prior| prior.der_signature == mock.der_signature)
                {
                    return Err(SigningV2Error::DuplicateSignature);
                }
                verify_der_signature(mock.der_signature, &slot.digest, &action.public_key)
                    .map_err(|_| SigningV2Error::InvalidMockSignature)?;
                let mut der = Vec::new();
                der.try_reserve_exact(mock.der_signature.len())
                    .map_err(|_| SigningV2Error::AllocationFailed)?;
                der.extend_from_slice(mock.der_signature);
                planned.push(PlannedSignature {
                    input_index,
                    public_key: action.public_key,
                    der_signature: der,
                });
            }
            _ => return Err(SigningV2Error::InternalInvariant),
        }
    }

    for (input_index, slot) in slots.iter().enumerate() {
        let inserted = planned
            .iter()
            .filter(|candidate| candidate.input_index == input_index)
            .count();
        let projected = slot
            .existing
            .iter()
            .flatten()
            .count()
            .checked_add(inserted)
            .ok_or(SigningV2Error::InternalInvariant)?;
        if projected > THRESHOLD {
            return Err(SigningV2Error::ThresholdWouldBeExceeded);
        }
        if projected != THRESHOLD {
            return Err(SigningV2Error::ThresholdIncomplete);
        }
    }

    if planned.len() > MAX_INSERTIONS {
        return Err(SigningV2Error::TooManyInsertions);
    }
    if !planned.windows(2).all(|pair| {
        let Some(left) = pair.first() else {
            return false;
        };
        let Some(right) = pair.get(1) else {
            return false;
        };
        (left.input_index, left.public_key) < (right.input_index, right.public_key)
    }) {
        return Err(SigningV2Error::InternalInvariant);
    }
    Ok(planned)
}

fn ordered_pending_actions(
    slots: &[InputSlots],
    request_counts: &[RequestCounts],
) -> Result<Vec<PendingAction>, SigningV2Error> {
    if slots.len() != request_counts.len() {
        return Err(SigningV2Error::InternalInvariant);
    }
    let capacity = slots
        .len()
        .checked_mul(ROLE_COUNT)
        .ok_or(SigningV2Error::InternalInvariant)?;
    let mut pending = Vec::new();
    pending
        .try_reserve_exact(capacity)
        .map_err(|_| SigningV2Error::AllocationFailed)?;
    for (input_index, slot) in slots.iter().enumerate() {
        let complete = slot.existing.iter().flatten().count() >= THRESHOLD;
        let counts = request_counts
            .get(input_index)
            .ok_or(SigningV2Error::InternalInvariant)?;
        let [role_a_key, role_b_key] = slot.role_keys;
        if !complete || counts.terminal != 0 {
            pending.push(PendingAction {
                input_index,
                role: 0,
                public_key: role_a_key,
            });
        }
        if !complete || counts.mock_card_b != 0 {
            pending.push(PendingAction {
                input_index,
                role: 1,
                public_key: role_b_key,
            });
        }
    }
    pending.sort_unstable_by(|left, right| {
        left.input_index
            .cmp(&right.input_index)
            .then_with(|| left.public_key.cmp(&right.public_key))
    });
    Ok(pending)
}

fn mock_group_repeats_existing_or_itself(
    view: &PsbtView<'_>,
    mocks: &[&MockCardBSignature<'_>],
) -> Result<bool, SigningV2Error> {
    for (index, candidate) in mocks.iter().enumerate() {
        if existing_signature_matches(view, candidate.der_signature)?
            || mocks
                .get(..index)
                .ok_or(SigningV2Error::InternalInvariant)?
                .iter()
                .any(|prior| prior.der_signature == candidate.der_signature)
        {
            return Ok(true);
        }
    }
    Ok(false)
}

fn serialize_and_verify_signature(
    signature: &qk_secp::Signature,
    digest: &[u8; 32],
    expected: &qk_secp::PublicKey,
    failure: SigningV2Error,
) -> Result<Vec<u8>, SigningV2Error> {
    let mut bounded = [0u8; DER_CONTAINER_BYTES];
    let len = qk_secp::signature_serialize_der(signature, &mut bounded).map_err(|_| failure)?;
    let der = bounded
        .get(..len)
        .ok_or(SigningV2Error::InternalInvariant)?;
    let parsed = qk_secp::signature_parse_der(der).map_err(|_| failure)?;
    let mut canonical = [0u8; DER_CONTAINER_BYTES];
    let canonical_len =
        qk_secp::signature_serialize_der(&parsed, &mut canonical).map_err(|_| failure)?;
    if canonical.get(..canonical_len) != Some(der) {
        return Err(failure);
    }
    qk_secp::ecdsa_verify(&parsed, digest, expected).map_err(|_| failure)?;
    let mut owned = Vec::new();
    owned
        .try_reserve_exact(der.len())
        .map_err(|_| SigningV2Error::AllocationFailed)?;
    owned.extend_from_slice(der);
    Ok(owned)
}

pub(super) fn verify_der_signature(
    der: &[u8],
    digest: &[u8; 32],
    public_key: &[u8; 33],
) -> Result<(), ()> {
    let key = qk_secp::pubkey_parse_compressed(public_key).map_err(|_| ())?;
    let signature = qk_secp::signature_parse_der(der).map_err(|_| ())?;
    let mut canonical = [0u8; DER_CONTAINER_BYTES];
    let canonical_len =
        qk_secp::signature_serialize_der(&signature, &mut canonical).map_err(|_| ())?;
    if canonical.get(..canonical_len) != Some(der) {
        return Err(());
    }
    qk_secp::ecdsa_verify(&signature, digest, &key).map_err(|_| ())
}

fn signature_matches_existing_or_planned(
    view: &PsbtView<'_>,
    planned: &[PlannedSignature],
    candidate_der: &[u8],
) -> Result<bool, SigningV2Error> {
    Ok(existing_signature_matches(view, candidate_der)?
        || planned
            .iter()
            .any(|prior| prior.der_signature == candidate_der))
}

fn existing_signature_matches(
    view: &PsbtView<'_>,
    candidate_der: &[u8],
) -> Result<bool, SigningV2Error> {
    for input_index in 0..view.input_map_count() {
        let records = view
            .input_records(input_index)
            .ok_or(SigningV2Error::InternalInvariant)?;
        for record in records {
            if record.key_type == 0x02
                && record.value.last() == Some(&SIGHASH_ALL)
                && record.value.get(..record.value.len().saturating_sub(1)) == Some(candidate_der)
            {
                return Ok(true);
            }
        }
    }
    Ok(false)
}

fn advance_verified_counts(
    previous: &mut [usize],
    next: &[qk_psbt::VerifiedInputFacts],
    changed_input: usize,
) -> Result<(), SigningV2Error> {
    if previous.len() != next.len() {
        return Err(SigningV2Error::ForbiddenDelta);
    }
    for (index, (before, after)) in previous.iter_mut().zip(next).enumerate() {
        let expected = if index == changed_input {
            before
                .checked_add(1)
                .ok_or(SigningV2Error::InternalInvariant)?
        } else {
            *before
        };
        if after.verified_signature_count != expected {
            return Err(SigningV2Error::ForbiddenDelta);
        }
        *before = after.verified_signature_count;
    }
    Ok(())
}

fn map_insertion_error(error: crate::SignatureInsertionError) -> SigningV2Error {
    use crate::SignatureInsertionError as Error;
    match error {
        Error::InputOutOfRange => SigningV2Error::InputOutOfRange,
        Error::ArtifactTooLarge => SigningV2Error::ArtifactTooLarge,
        Error::AllocationFailed => SigningV2Error::AllocationFailed,
        Error::SerializeFailed(error) => SigningV2Error::SerializeFailed(error),
        Error::NonCanonicalOutput => SigningV2Error::NonCanonicalOutput,
        Error::ForbiddenDelta => SigningV2Error::ForbiddenDelta,
        _ => SigningV2Error::InternalInvariant,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const SIGNING_FIXTURE: &str =
        include_str!("../../qk-psbt/tests/fixtures/signing_finalization_v2.txt");

    fn fixture_field(name: &str) -> &'static str {
        let prefix = format!("{name}: ");
        SIGNING_FIXTURE
            .lines()
            .find_map(|line| line.strip_prefix(&prefix))
            .expect("registered v2 signing fixture field")
    }

    fn decode_hex(value: &str) -> Vec<u8> {
        let (pairs, remainder) = value.as_bytes().as_chunks::<2>();
        assert!(remainder.is_empty());
        pairs
            .iter()
            .map(|pair| {
                u8::from_str_radix(core::str::from_utf8(pair).expect("ASCII hex"), 16)
                    .expect("valid fixture hex")
            })
            .collect()
    }

    fn decode_hex_32(value: &str) -> [u8; 32] {
        decode_hex(value)
            .try_into()
            .expect("exact 32-byte fixture field")
    }

    fn decode_hex_33(value: &str) -> [u8; 33] {
        decode_hex(value)
            .try_into()
            .expect("exact compressed fixture key")
    }

    fn fixture_terminal(input_index: u32, field_name: &str) -> TerminalInputKeyV2 {
        let mut bytes = decode_hex_32(fixture_field(field_name));
        let secret_key = qk_secp::secret_key_import(&mut bytes).expect("public fixture scalar");
        assert_eq!(bytes, [0u8; 32]);
        TerminalInputKeyV2::new(input_index, secret_key)
    }

    fn fixture_view_bytes() -> Vec<u8> {
        decode_hex(fixture_field("s0_hex"))
    }

    #[test]
    fn pending_work_uses_public_key_order_when_role_b_sorts_first() {
        // This is the ordering shape of the registered receive-1 route:
        // role B begins 02 3e while role A begins 03 69.
        let role_a =
            decode_hex_33("0369116cac12973d76731c7df9d4d0e4122d93188f86161a030dbdd8eaf21e07c0");
        let role_b =
            decode_hex_33("023e69859ba56e40ca57cc1b6bb42a689707bba7d80e7edb87a4862cded8c2e6d3");
        let slots = [InputSlots {
            role_keys: [role_a, role_b],
            existing: [None, None],
            digest: decode_hex_32(fixture_field("bip143_digest_hex")),
        }];
        let pending = ordered_pending_actions(
            &slots,
            &[RequestCounts {
                terminal: 1,
                mock_card_b: 1,
            }],
        )
        .expect("bounded actions");
        assert_eq!(pending.len(), 2);
        let first = pending.first().expect("first action");
        let second = pending.get(1).expect("second action");
        assert_eq!((first.input_index, first.role), (0, 1));
        assert_eq!((second.input_index, second.role), (0, 0));
        assert!(first.public_key < second.public_key);

        let s0 = fixture_view_bytes();
        let view = parse(&s0, InputSource::MicroSd).expect("registered fixture PSBT");
        let terminal_keys = [fixture_terminal(0, "role_b_route_private_scalar_hex")];
        let invalid_mock = [0x30];
        let mocks = [MockCardBSignature {
            input_index: 0,
            der_signature: &invalid_mock,
        }];
        assert_eq!(
            plan_and_verify_signatures(&view, &slots, &terminal_keys, &mocks).err(),
            Some(SigningV2Error::InvalidMockSignature)
        );
    }

    #[test]
    fn pending_work_finishes_each_lower_input_before_later_keys() {
        let fixture_role_b = decode_hex_33(fixture_field("role_b_route_public_key_hex"));
        let later_role_b =
            decode_hex_33("023e69859ba56e40ca57cc1b6bb42a689707bba7d80e7edb87a4862cded8c2e6d3");
        let slots = [
            InputSlots {
                role_keys: [
                    fixture_role_b,
                    decode_hex_33(
                        "03a9e4b908b804bb0b65c5ececf641d0976ac8696ad903da2ef397c970db01eed5",
                    ),
                ],
                existing: [None, Some(Span { start: 0, end: 0 })],
                digest: decode_hex_32(fixture_field("bip143_digest_hex")),
            },
            InputSlots {
                role_keys: [
                    decode_hex_33(
                        "0369116cac12973d76731c7df9d4d0e4122d93188f86161a030dbdd8eaf21e07c0",
                    ),
                    later_role_b,
                ],
                existing: [None, None],
                digest: decode_hex_32(fixture_field("bip143_digest_hex")),
            },
        ];
        let counts = [
            RequestCounts {
                terminal: 1,
                mock_card_b: 1,
            },
            RequestCounts {
                terminal: 1,
                mock_card_b: 1,
            },
        ];
        let pending = ordered_pending_actions(&slots, &counts).expect("bounded actions");
        let tuples: Vec<_> = pending
            .iter()
            .map(|action| (action.input_index, action.public_key))
            .collect();
        assert_eq!(tuples.len(), 4);
        assert_eq!(tuples.first().expect("input 0 first").0, 0);
        assert_eq!(tuples.get(1).expect("input 0 second").0, 0);
        assert_eq!(tuples.get(2).expect("input 1 first").0, 1);
        assert_eq!(tuples.get(3).expect("input 1 second").0, 1);
        assert!(tuples.windows(2).all(|pair| {
            let Some(left) = pair.first() else {
                return false;
            };
            let Some(right) = pair.get(1) else {
                return false;
            };
            left < right
        }));
        assert!(later_role_b < fixture_role_b);

        let s0 = fixture_view_bytes();
        let view = parse(&s0, InputSource::MicroSd).expect("registered fixture PSBT");
        let terminal_keys = [fixture_terminal(0, "role_a_route_private_scalar_hex")];
        let invalid_mock = [0x30];
        let mocks = [MockCardBSignature {
            input_index: 1,
            der_signature: &invalid_mock,
        }];
        assert_eq!(
            plan_and_verify_signatures(&view, &slots, &terminal_keys, &mocks).err(),
            Some(SigningV2Error::TerminalKeyMismatch)
        );
    }
}
