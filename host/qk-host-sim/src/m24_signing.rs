//! Non-authorizing M24 HOST signing continuation from ReviewReady.

use crate::finalization::{fresh_final_witnesses, FinalizationError, FinalizedTransaction};
use crate::insertion::{exact_insert_delta, insert_partial_signature, ThresholdCompletePsbt};
use crate::ReviewReadyWorkflow;
use core::fmt;
use qk_descriptor::{derive_change_script, derive_receive_script, DescriptorPair};
use qk_psbt::bip143::{sighash_all_digest, Bip143InputFacts, Bip143PrecomputeBuilder, SIGHASH_ALL};
use qk_psbt::{
    analyze_descriptor_ownership, build_review_v2, canonical_serialize, parse, InputSource,
    OwnedS0, PsbtView, ReviewContext, ReviewNetwork, ReviewV2, ReviewV2Error, SemanticError,
    SerializeError, Span, VerifiedAggregateStatus,
};
use qk_secp::{SecpError, SecretKey};

const THRESHOLD: usize = 2;
const ROLE_COUNT: usize = 3;
const MAX_INSERTIONS: usize = 200;
const DER_CONTAINER_BYTES: usize = 72;

/// One role-A child signing key for an unsigned-transaction input.
///
/// The key is owned only by qk-secp's opaque, zeroizing [`SecretKey`]. This
/// wrapper intentionally implements neither `Debug`, `Clone`, `Copy`, nor
/// any accessor exposing the key.
pub struct TerminalInputKey {
    input_index: u32,
    secret_key: SecretKey,
}

impl TerminalInputKey {
    /// Bind one already-imported qk-secp secret owner to an input index.
    #[must_use]
    pub fn new(input_index: u32, secret_key: SecretKey) -> Self {
        Self {
            input_index,
            secret_key,
        }
    }

    /// The public input coordinate to which the opaque key is bound.
    #[must_use]
    pub const fn input_index(&self) -> u32 {
        self.input_index
    }
}

/// Mock-card role accepted by the M24 HOST slice. Role A cannot be named.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MockCardRole {
    /// Descriptor role B.
    B,
    /// Descriptor role C.
    C,
}

impl MockCardRole {
    const fn index(self) -> usize {
        match self {
            Self::B => 1,
            Self::C => 2,
        }
    }
}

/// One DER-only mock card response. The wrapper derives its key and digest.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MockCardSignature<'a> {
    /// Unsigned-transaction input index.
    pub input_index: u32,
    /// Descriptor card role B or C.
    pub role: MockCardRole,
    /// Strict low-S DER bytes without a sighash byte.
    pub der_signature: &'a [u8],
}

/// Stable M24 failure surface. No variant carries secret or hostile bytes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum M24SigningError {
    /// The consumed M23 workflow was not successfully at ReviewReady.
    WrongState,
    /// The privately retained S0 identity no longer matches its review.
    RetainedS0Mismatch,
    /// Retained or intermediate PSBT bytes failed structural parsing.
    ParseFailed,
    /// Schema-v2 review reconstruction rejected.
    ReviewRebuild(ReviewV2Error),
    /// Rebuilt schema-v2 facts differ from the bound pre-signing facts.
    ReviewFactsMismatch,
    /// The rebuilt schema-v2 hash differs from the bound review hash.
    ReviewHashMismatch,
    /// Existing partial-signature cryptography rejected.
    ExistingSignatureVerification(SemanticError),
    /// BIP143 digest construction failed closed.
    DigestFailed,
    /// M5 canonical serialization failed.
    SerializeFailed(SerializeError),
    /// A supplied input index does not exist.
    InputOutOfRange,
    /// More than one terminal key names the same input.
    DuplicateTerminalKey,
    /// An incomplete input with no role-A record lacks its terminal key.
    MissingTerminalKey,
    /// A terminal key was supplied where role A was already occupied or the input complete.
    UnexpectedTerminalKey,
    /// Exact signature bytes repeat an existing or pending signature.
    DuplicateSignature,
    /// Two mock responses claim the same input and role.
    DuplicateRole,
    /// A supplied signature claims an already occupied descriptor role.
    SignatureConflict,
    /// A supplied response targets an already complete input.
    ThresholdAlreadyMet,
    /// New records would place an input above the two-signature threshold.
    ThresholdWouldBeExceeded,
    /// At least one input cannot reach exactly the two-signature threshold.
    ThresholdIncomplete,
    /// More than the bounded transaction-wide insertion count was requested.
    TooManyInsertions,
    /// Terminal deterministic signing or its internal self-check failed.
    TerminalSigning(SecpError),
    /// The exact serialized terminal signature failed the pre-insertion check.
    TerminalPreInsertionVerificationFailed,
    /// A mock signature failed strict-DER, low-S, key, or digest verification.
    InvalidMockSignature,
    /// An insertion changed bytes outside its one exact new record.
    ForbiddenDelta,
    /// An intermediate PSBT was not an exact M5 fixed point.
    NonCanonicalOutput,
    /// An intermediate PSBT exceeded its retained intake cap.
    ArtifactTooLarge,
    /// A bounded allocation failed.
    AllocationFailed,
    /// M16 finalization or its first complete reparse rejected.
    Finalization(FinalizationError),
    /// The separate M24 final transaction reparse rejected.
    FinalTransactionReparse,
    /// The selected signatures are not in increasing witness-script key order.
    WitnessOrderMismatch,
    /// A freshly reparsed final witness signature failed cryptographic verification.
    FinalSignatureVerificationFailed,
    /// A previously established parser, descriptor, or workflow invariant failed.
    InternalInvariant,
}

impl fmt::Display for M24SigningError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::WrongState => f.write_str("M24 signing continuation state invalid"),
            Self::RetainedS0Mismatch => f.write_str("retained S0 identity mismatch"),
            Self::ParseFailed => f.write_str("M24 PSBT parse failed"),
            Self::ReviewRebuild(error) => write!(f, "M24 review rebuild failed: {error}"),
            Self::ReviewFactsMismatch => f.write_str("M24 review facts changed"),
            Self::ReviewHashMismatch => f.write_str("M24 review hash changed"),
            Self::ExistingSignatureVerification(error) => {
                write!(f, "existing signature verification failed: {error}")
            }
            Self::DigestFailed => f.write_str("M24 BIP143 digest construction failed"),
            Self::SerializeFailed(error) => write!(f, "M24 serialization failed: {error:?}"),
            Self::InputOutOfRange => f.write_str("signature input index out of range"),
            Self::DuplicateTerminalKey => f.write_str("duplicate terminal input key"),
            Self::MissingTerminalKey => f.write_str("terminal role-A key missing"),
            Self::UnexpectedTerminalKey => f.write_str("terminal role-A key not required"),
            Self::DuplicateSignature => f.write_str("duplicate signature"),
            Self::DuplicateRole => f.write_str("duplicate descriptor role"),
            Self::SignatureConflict => f.write_str("descriptor role signature conflict"),
            Self::ThresholdAlreadyMet => f.write_str("signature threshold already met"),
            Self::ThresholdWouldBeExceeded => f.write_str("signature threshold would be exceeded"),
            Self::ThresholdIncomplete => f.write_str("signature threshold incomplete"),
            Self::TooManyInsertions => f.write_str("too many signature insertions"),
            Self::TerminalSigning(error) => write!(f, "terminal signing failed: {error}"),
            Self::TerminalPreInsertionVerificationFailed => {
                f.write_str("terminal signature pre-insertion verification failed")
            }
            Self::InvalidMockSignature => f.write_str("invalid mock card signature"),
            Self::ForbiddenDelta => f.write_str("M24 insertion changed a frozen fact"),
            Self::NonCanonicalOutput => f.write_str("M24 PSBT is not canonical"),
            Self::ArtifactTooLarge => f.write_str("M24 PSBT exceeds source byte cap"),
            Self::AllocationFailed => f.write_str("M24 bounded allocation failed"),
            Self::Finalization(error) => write!(f, "M24 finalization failed: {error}"),
            Self::FinalTransactionReparse => f.write_str("M24 final transaction reparse failed"),
            Self::WitnessOrderMismatch => f.write_str("final witness signature order mismatch"),
            Self::FinalSignatureVerificationFailed => {
                f.write_str("final witness signature verification failed")
            }
            Self::InternalInvariant => f.write_str("M24 internal invariant failed"),
        }
    }
}

impl std::error::Error for M24SigningError {}

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

impl ReviewReadyWorkflow {
    /// Consume one successful M23 workflow, complete each incomplete input
    /// with terminal role A plus one verified mock role B/C as needed, then
    /// finalize and freshly verify the raw transaction.
    ///
    /// This HOST evidence seam deliberately carries no approval, token, card
    /// session, transport, or export authorization. Every failure consumes all
    /// inputs and releases no intermediate PSBT or signature.
    pub fn sign_and_finalize_m24(
        self,
        terminal_keys: Vec<TerminalInputKey>,
        mock_signatures: &[MockCardSignature<'_>],
    ) -> Result<FinalizedTransaction, M24SigningError> {
        let (descriptor, ready) = self.into_m24_parts().ok_or(M24SigningError::WrongState)?;
        let (s0, bound_review, bound_hash) = ready.into_m24_parts();
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
    descriptor: DescriptorPair,
    bound_review: ReviewV2,
    bound_hash: [u8; 32],
    terminal_keys: Vec<TerminalInputKey>,
    mock_signatures: &[MockCardSignature<'_>],
) -> Result<FinalizedTransaction, M24SigningError> {
    if s0.sha256() != bound_review.s0_sha256() {
        return Err(M24SigningError::RetainedS0Mismatch);
    }
    let source = s0.source();
    let retained_view = s0.parse().map_err(|_| M24SigningError::ParseFailed)?;
    if retained_view.buffer().as_ptr() != s0.bytes().as_ptr()
        || retained_view.buffer().len() != s0.bytes().len()
        || retained_view.source() != source
    {
        return Err(M24SigningError::RetainedS0Mismatch);
    }
    let rebuilt = build_review(&retained_view, &descriptor, source)?;
    if rebuilt != bound_review {
        return Err(M24SigningError::ReviewFactsMismatch);
    }
    let rebuilt_hash = rebuilt
        .review_hash()
        .map_err(M24SigningError::ReviewRebuild)?;
    if rebuilt_hash != bound_hash {
        return Err(M24SigningError::ReviewHashMismatch);
    }
    analyze_descriptor_ownership(&retained_view, &descriptor)
        .map_err(M24SigningError::ExistingSignatureVerification)?;

    let mut current =
        canonical_serialize(&retained_view).map_err(M24SigningError::SerializeFailed)?;
    drop(retained_view);
    let baseline_view = parse(&current, source).map_err(|_| M24SigningError::ParseFailed)?;
    let baseline_review = build_review(&baseline_view, &descriptor, source)?;
    if !frozen_review_facts_equal(&bound_review, &baseline_review) {
        return Err(M24SigningError::ReviewFactsMismatch);
    }
    let verified = analyze_descriptor_ownership(&baseline_view, &descriptor)
        .map_err(M24SigningError::ExistingSignatureVerification)?;
    let mut verified_counts: Vec<usize> = Vec::new();
    verified_counts
        .try_reserve_exact(verified.verified_inputs.len())
        .map_err(|_| M24SigningError::AllocationFailed)?;
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
        let previous_view = parse(&previous, source).map_err(|_| M24SigningError::ParseFailed)?;
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
            return Err(M24SigningError::ForbiddenDelta);
        }
        let next_view = parse(&next, source).map_err(|_| M24SigningError::ParseFailed)?;
        let canonical =
            canonical_serialize(&next_view).map_err(M24SigningError::SerializeFailed)?;
        if canonical != next {
            return Err(M24SigningError::NonCanonicalOutput);
        }
        let next_review = build_review(&next_view, &descriptor, source)?;
        if !frozen_review_facts_equal(&bound_review, &next_review) {
            return Err(M24SigningError::ForbiddenDelta);
        }
        let next_verified = analyze_descriptor_ownership(&next_view, &descriptor)
            .map_err(M24SigningError::ExistingSignatureVerification)?;
        advance_verified_counts(
            &mut verified_counts,
            &next_verified.verified_inputs,
            signature.input_index,
        )?;
        current = next;
    }

    let complete_view = parse(&current, source).map_err(|_| M24SigningError::ParseFailed)?;
    let complete = analyze_descriptor_ownership(&complete_view, &descriptor)
        .map_err(M24SigningError::ExistingSignatureVerification)?;
    if complete.aggregate_status != VerifiedAggregateStatus::VerifyAndExportOnly {
        return Err(M24SigningError::ThresholdIncomplete);
    }
    let selected_keys = selected_signature_keys(&complete_view)?;
    let final_canonical =
        canonical_serialize(&complete_view).map_err(M24SigningError::SerializeFailed)?;
    if final_canonical != current {
        return Err(M24SigningError::NonCanonicalOutput);
    }
    drop(complete_view);

    let capability = ThresholdCompletePsbt {
        bytes: current,
        source,
    };
    let finalized = capability
        .finalize_and_extract()
        .map_err(map_finalization)?;
    verify_fresh_final_transaction(
        &finalized,
        source,
        &bound_review,
        &descriptor,
        &selected_keys,
    )?;
    Ok(finalized)
}

fn build_review(
    view: &PsbtView<'_>,
    descriptor: &DescriptorPair,
    source: InputSource,
) -> Result<ReviewV2, M24SigningError> {
    build_review_v2(
        view,
        descriptor,
        ReviewContext {
            network: ReviewNetwork::BitcoinMainnet,
            input_source: source,
        },
    )
    .map_err(M24SigningError::ReviewRebuild)
}

fn frozen_review_facts_equal(left: &ReviewV2, right: &ReviewV2) -> bool {
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
    descriptor: &DescriptorPair,
    review: &ReviewV2,
) -> Result<Vec<InputSlots>, M24SigningError> {
    if view.input_map_count() != review.inputs().len() {
        return Err(M24SigningError::InternalInvariant);
    }
    let digests = compute_input_digests(review, descriptor)?;
    let fingerprints = descriptor.origin_fingerprints();
    let mut slots = Vec::new();
    slots
        .try_reserve_exact(view.input_map_count())
        .map_err(|_| M24SigningError::AllocationFailed)?;
    for input_index in 0..view.input_map_count() {
        let records = view
            .input_records(input_index)
            .ok_or(M24SigningError::InternalInvariant)?;
        let mut role_keys: [Option<[u8; 33]>; ROLE_COUNT] = [None, None, None];
        for record in records.clone() {
            if record.key_type != 0x06 {
                continue;
            }
            let fingerprint = record
                .value
                .get(..4)
                .ok_or(M24SigningError::InternalInvariant)?;
            let role = fingerprints
                .iter()
                .position(|candidate| candidate.as_slice() == fingerprint)
                .ok_or(M24SigningError::InternalInvariant)?;
            let key: [u8; 33] = record
                .key_data
                .try_into()
                .map_err(|_| M24SigningError::InternalInvariant)?;
            let target = role_keys
                .get_mut(role)
                .ok_or(M24SigningError::InternalInvariant)?;
            if target.replace(key).is_some() {
                return Err(M24SigningError::InternalInvariant);
            }
        }
        let role_keys = [
            role_keys[0].ok_or(M24SigningError::InternalInvariant)?,
            role_keys[1].ok_or(M24SigningError::InternalInvariant)?,
            role_keys[2].ok_or(M24SigningError::InternalInvariant)?,
        ];
        let mut existing: [Option<Span>; ROLE_COUNT] = [None, None, None];
        for record in records {
            if record.key_type != 0x02 {
                continue;
            }
            let role = role_keys
                .iter()
                .position(|candidate| candidate.as_slice() == record.key_data)
                .ok_or(M24SigningError::InternalInvariant)?;
            let target = existing
                .get_mut(role)
                .ok_or(M24SigningError::InternalInvariant)?;
            if target.replace(record.value_span).is_some() {
                return Err(M24SigningError::InternalInvariant);
            }
        }
        slots.push(InputSlots {
            role_keys,
            existing,
            digest: *digests
                .get(input_index)
                .ok_or(M24SigningError::InternalInvariant)?,
        });
    }
    Ok(slots)
}

fn derive_script(
    descriptor: &DescriptorPair,
    branch: u32,
    index: u32,
) -> Result<qk_descriptor::DerivedScript, M24SigningError> {
    match branch {
        0 => derive_receive_script(descriptor, index),
        1 => derive_change_script(descriptor, index),
        _ => return Err(M24SigningError::InternalInvariant),
    }
    .map_err(|_| M24SigningError::InternalInvariant)
}

fn compute_input_digests(
    review: &ReviewV2,
    descriptor: &DescriptorPair,
) -> Result<Vec<[u8; 32]>, M24SigningError> {
    let mut builder = Bip143PrecomputeBuilder::new();
    for input in review.inputs() {
        let txid = input.outpoint_txid_wire();
        builder
            .add_input(&txid, input.outpoint_vout(), input.sequence())
            .map_err(|_| M24SigningError::DigestFailed)?;
    }
    for output in review.outputs() {
        builder
            .add_output(output.amount(), output.script_pubkey())
            .map_err(|_| M24SigningError::DigestFailed)?;
    }
    let precomputed = builder
        .finish()
        .map_err(|_| M24SigningError::DigestFailed)?;
    let mut digests = Vec::new();
    digests
        .try_reserve_exact(review.inputs().len())
        .map_err(|_| M24SigningError::AllocationFailed)?;
    for input in review.inputs() {
        if input.effective_sighash() != u32::from(SIGHASH_ALL) {
            return Err(M24SigningError::InternalInvariant);
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
                .map_err(|_| M24SigningError::DigestFailed)?,
        );
    }
    Ok(digests)
}

fn plan_and_verify_signatures(
    view: &PsbtView<'_>,
    slots: &[InputSlots],
    terminal_keys: &[TerminalInputKey],
    mock_signatures: &[MockCardSignature<'_>],
) -> Result<Vec<PlannedSignature>, M24SigningError> {
    if terminal_keys.len().saturating_add(mock_signatures.len()) > MAX_INSERTIONS {
        return Err(M24SigningError::TooManyInsertions);
    }
    let mut terminal_seen = Vec::new();
    terminal_seen
        .try_reserve_exact(slots.len())
        .map_err(|_| M24SigningError::AllocationFailed)?;
    terminal_seen.resize(slots.len(), false);
    for terminal in terminal_keys {
        let index =
            usize::try_from(terminal.input_index).map_err(|_| M24SigningError::InputOutOfRange)?;
        let seen = terminal_seen
            .get_mut(index)
            .ok_or(M24SigningError::InputOutOfRange)?;
        if *seen {
            return Err(M24SigningError::DuplicateTerminalKey);
        }
        *seen = true;
    }

    let mut mocks_by_input: Vec<Vec<&MockCardSignature<'_>>> = Vec::new();
    mocks_by_input
        .try_reserve_exact(slots.len())
        .map_err(|_| M24SigningError::AllocationFailed)?;
    for _ in slots {
        mocks_by_input.push(Vec::new());
    }
    for mock_signature in mock_signatures {
        let index = usize::try_from(mock_signature.input_index)
            .map_err(|_| M24SigningError::InputOutOfRange)?;
        let input = mocks_by_input
            .get_mut(index)
            .ok_or(M24SigningError::InputOutOfRange)?;
        input
            .try_reserve(1)
            .map_err(|_| M24SigningError::AllocationFailed)?;
        input.push(mock_signature);
    }
    preflight_mock_duplicates(view, slots, mock_signatures)?;

    let mut planned = Vec::new();
    planned
        .try_reserve_exact(terminal_keys.len().saturating_add(mock_signatures.len()))
        .map_err(|_| M24SigningError::AllocationFailed)?;
    for (input_index, slot) in slots.iter().enumerate() {
        let existing_count = slot.existing.iter().flatten().count();
        let terminal = terminal_keys
            .iter()
            .find(|candidate| usize::try_from(candidate.input_index).ok() == Some(input_index));
        let mocks = mocks_by_input
            .get(input_index)
            .ok_or(M24SigningError::InternalInvariant)?;
        if existing_count >= THRESHOLD {
            if terminal.is_some() || !mocks.is_empty() {
                return Err(M24SigningError::ThresholdAlreadyMet);
            }
            continue;
        }

        let role_a_present = slot.existing[0].is_some();
        if role_a_present {
            if terminal.is_some() {
                return Err(M24SigningError::UnexpectedTerminalKey);
            }
        } else {
            let terminal = terminal.ok_or(M24SigningError::MissingTerminalKey)?;
            let public_key = slot.role_keys[0];
            let expected = qk_secp::pubkey_parse_compressed(&public_key)
                .map_err(|_| M24SigningError::InternalInvariant)?;
            let signature =
                qk_secp::ecdsa_sign_rfc6979(&terminal.secret_key, &slot.digest, &expected)
                    .map_err(M24SigningError::TerminalSigning)?;
            let der = serialize_and_verify_signature(
                &signature,
                &slot.digest,
                &expected,
                M24SigningError::TerminalPreInsertionVerificationFailed,
            )?;
            planned.push(PlannedSignature {
                input_index,
                public_key,
                der_signature: der,
            });
        }
    }

    // Exact bytes are the earliest signature-record distinction. Compare all
    // deterministic terminal results with existing and caller-supplied bytes
    // before role conflicts or mock cryptography can mask DuplicateSignature.
    reject_duplicate_signatures(view, &planned)?;
    for terminal in &planned {
        if mock_signatures
            .iter()
            .any(|mock_signature| mock_signature.der_signature == terminal.der_signature)
        {
            return Err(M24SigningError::DuplicateSignature);
        }
    }

    for (input_index, slot) in slots.iter().enumerate() {
        let existing_count = slot.existing.iter().flatten().count();
        if existing_count >= THRESHOLD {
            continue;
        }
        let role_a_present = slot.existing[0].is_some();
        let mut projected = existing_count
            .checked_add(usize::from(!role_a_present))
            .ok_or(M24SigningError::InternalInvariant)?;
        let mocks = mocks_by_input
            .get(input_index)
            .ok_or(M24SigningError::InternalInvariant)?;
        let mut mock_roles = [false; ROLE_COUNT];
        for mock_signature in mocks {
            let role_index = mock_signature.role.index();
            let role_seen = mock_roles
                .get_mut(role_index)
                .ok_or(M24SigningError::InternalInvariant)?;
            if *role_seen {
                return Err(M24SigningError::DuplicateRole);
            }
            *role_seen = true;
            if slot.existing[role_index].is_some() {
                return Err(M24SigningError::SignatureConflict);
            }
            projected = projected
                .checked_add(1)
                .ok_or(M24SigningError::InternalInvariant)?;
            if projected > THRESHOLD {
                return Err(M24SigningError::ThresholdWouldBeExceeded);
            }
            let public_key = slot.role_keys[role_index];
            verify_der_signature(mock_signature.der_signature, &slot.digest, &public_key)
                .map_err(|_| M24SigningError::InvalidMockSignature)?;
            let mut der = Vec::new();
            der.try_reserve_exact(mock_signature.der_signature.len())
                .map_err(|_| M24SigningError::AllocationFailed)?;
            der.extend_from_slice(mock_signature.der_signature);
            planned.push(PlannedSignature {
                input_index,
                public_key,
                der_signature: der,
            });
        }
        if projected != THRESHOLD {
            return Err(M24SigningError::ThresholdIncomplete);
        }
    }

    if planned.len() > MAX_INSERTIONS {
        return Err(M24SigningError::TooManyInsertions);
    }
    planned.sort_unstable_by(|left, right| {
        left.input_index
            .cmp(&right.input_index)
            .then_with(|| left.public_key.cmp(&right.public_key))
    });
    reject_duplicate_signatures(view, &planned)?;
    Ok(planned)
}

fn preflight_mock_duplicates(
    view: &PsbtView<'_>,
    slots: &[InputSlots],
    mock_signatures: &[MockCardSignature<'_>],
) -> Result<(), M24SigningError> {
    for (index, candidate) in mock_signatures.iter().enumerate() {
        let input_index =
            usize::try_from(candidate.input_index).map_err(|_| M24SigningError::InputOutOfRange)?;
        let slot = slots
            .get(input_index)
            .ok_or(M24SigningError::InputOutOfRange)?;
        if slot.existing.iter().flatten().count() >= THRESHOLD {
            return Err(M24SigningError::ThresholdAlreadyMet);
        }
        if existing_signature_matches(view, candidate.der_signature)?
            || mock_signatures
                .get(..index)
                .ok_or(M24SigningError::InternalInvariant)?
                .iter()
                .any(|prior| prior.der_signature == candidate.der_signature)
        {
            return Err(M24SigningError::DuplicateSignature);
        }
    }
    Ok(())
}

fn serialize_and_verify_signature(
    signature: &qk_secp::Signature,
    digest: &[u8; 32],
    expected: &qk_secp::PublicKey,
    failure: M24SigningError,
) -> Result<Vec<u8>, M24SigningError> {
    let mut bounded = [0u8; DER_CONTAINER_BYTES];
    let len = qk_secp::signature_serialize_der(signature, &mut bounded).map_err(|_| failure)?;
    let der = bounded
        .get(..len)
        .ok_or(M24SigningError::InternalInvariant)?;
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
        .map_err(|_| M24SigningError::AllocationFailed)?;
    owned.extend_from_slice(der);
    Ok(owned)
}

fn verify_der_signature(der: &[u8], digest: &[u8; 32], public_key: &[u8; 33]) -> Result<(), ()> {
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

fn reject_duplicate_signatures(
    view: &PsbtView<'_>,
    planned: &[PlannedSignature],
) -> Result<(), M24SigningError> {
    for (index, candidate) in planned.iter().enumerate() {
        if existing_signature_matches(view, &candidate.der_signature)?
            || planned
                .get(..index)
                .ok_or(M24SigningError::InternalInvariant)?
                .iter()
                .any(|prior| prior.der_signature == candidate.der_signature)
        {
            return Err(M24SigningError::DuplicateSignature);
        }
    }
    Ok(())
}

fn existing_signature_matches(
    view: &PsbtView<'_>,
    candidate_der: &[u8],
) -> Result<bool, M24SigningError> {
    for input_index in 0..view.input_map_count() {
        let records = view
            .input_records(input_index)
            .ok_or(M24SigningError::InternalInvariant)?;
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
) -> Result<(), M24SigningError> {
    if previous.len() != next.len() {
        return Err(M24SigningError::ForbiddenDelta);
    }
    for (index, (before, after)) in previous.iter_mut().zip(next).enumerate() {
        let expected = if index == changed_input {
            before
                .checked_add(1)
                .ok_or(M24SigningError::InternalInvariant)?
        } else {
            *before
        };
        if after.verified_signature_count != expected {
            return Err(M24SigningError::ForbiddenDelta);
        }
        *before = after.verified_signature_count;
    }
    Ok(())
}

fn selected_signature_keys(
    view: &PsbtView<'_>,
) -> Result<Vec<[[u8; 33]; THRESHOLD]>, M24SigningError> {
    let mut selected = Vec::new();
    selected
        .try_reserve_exact(view.input_map_count())
        .map_err(|_| M24SigningError::AllocationFailed)?;
    for input_index in 0..view.input_map_count() {
        let records = view
            .input_records(input_index)
            .ok_or(M24SigningError::InternalInvariant)?;
        let mut keys: [Option<[u8; 33]>; THRESHOLD] = [None, None];
        let mut seen = 0usize;
        for record in records {
            if record.key_type != 0x02 {
                continue;
            }
            if seen < THRESHOLD {
                let slot = keys
                    .get_mut(seen)
                    .ok_or(M24SigningError::InternalInvariant)?;
                *slot = Some(
                    record
                        .key_data
                        .try_into()
                        .map_err(|_| M24SigningError::InternalInvariant)?,
                );
            }
            seen = seen
                .checked_add(1)
                .ok_or(M24SigningError::InternalInvariant)?;
        }
        if seen < THRESHOLD {
            return Err(M24SigningError::ThresholdIncomplete);
        }
        selected.push([
            keys[0].ok_or(M24SigningError::InternalInvariant)?,
            keys[1].ok_or(M24SigningError::InternalInvariant)?,
        ]);
    }
    Ok(selected)
}

fn verify_fresh_final_transaction(
    finalized: &FinalizedTransaction,
    source: InputSource,
    review: &ReviewV2,
    descriptor: &DescriptorPair,
    selected_keys: &[[[u8; 33]; THRESHOLD]],
) -> Result<(), M24SigningError> {
    let witnesses = fresh_final_witnesses(finalized, source, review.unsigned_tx_bytes())
        .map_err(map_fresh_finalization)?;
    if witnesses.len() != review.inputs().len() || witnesses.len() != selected_keys.len() {
        return Err(M24SigningError::FinalTransactionReparse);
    }
    let digests = compute_input_digests(review, descriptor)?;
    for (input_index, witness) in witnesses.iter().enumerate() {
        let review_input = review
            .inputs()
            .get(input_index)
            .ok_or(M24SigningError::InternalInvariant)?;
        let derived = derive_script(
            descriptor,
            review_input.branch(),
            review_input.child_index(),
        )?;
        if witness.witness_script != derived.witness_script.as_slice() {
            return Err(M24SigningError::FinalTransactionReparse);
        }
        let digest = digests
            .get(input_index)
            .ok_or(M24SigningError::InternalInvariant)?;
        let keys = selected_keys
            .get(input_index)
            .ok_or(M24SigningError::InternalInvariant)?;
        verify_complete_witness_signature(witness.first_signature, digest, &keys[0])?;
        verify_complete_witness_signature(witness.second_signature, digest, &keys[1])?;
    }
    Ok(())
}

fn verify_complete_witness_signature(
    complete: &[u8],
    digest: &[u8; 32],
    key: &[u8; 33],
) -> Result<(), M24SigningError> {
    let (sighash, der) = complete
        .split_last()
        .ok_or(M24SigningError::FinalSignatureVerificationFailed)?;
    if *sighash != SIGHASH_ALL {
        return Err(M24SigningError::FinalSignatureVerificationFailed);
    }
    verify_der_signature(der, digest, key)
        .map_err(|_| M24SigningError::FinalSignatureVerificationFailed)
}

fn map_insertion_error(error: crate::SignatureInsertionError) -> M24SigningError {
    use crate::SignatureInsertionError as Error;
    match error {
        Error::InputOutOfRange => M24SigningError::InputOutOfRange,
        Error::ArtifactTooLarge => M24SigningError::ArtifactTooLarge,
        Error::AllocationFailed => M24SigningError::AllocationFailed,
        Error::SerializeFailed(error) => M24SigningError::SerializeFailed(error),
        Error::NonCanonicalOutput => M24SigningError::NonCanonicalOutput,
        Error::ForbiddenDelta => M24SigningError::ForbiddenDelta,
        _ => M24SigningError::InternalInvariant,
    }
}

fn map_finalization(error: FinalizationError) -> M24SigningError {
    if error == FinalizationError::WitnessOrderMismatch {
        M24SigningError::WitnessOrderMismatch
    } else {
        M24SigningError::Finalization(error)
    }
}

fn map_fresh_finalization(error: FinalizationError) -> M24SigningError {
    if error == FinalizationError::WitnessOrderMismatch {
        M24SigningError::WitnessOrderMismatch
    } else {
        M24SigningError::FinalTransactionReparse
    }
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

    const REVIEW_FIXTURE: &str = include_str!("../tests/fixtures/m16_finalization.txt");

    fn field(name: &str) -> &'static str {
        REVIEW_FIXTURE
            .lines()
            .find_map(|line| line.strip_prefix(name))
            .expect("fixture field")
    }

    #[test]
    fn continuation_consumes_only_review_ready() {
        let descriptor = parse_descriptor_pair(
            field("receive_descriptor: ").as_bytes(),
            field("change_descriptor: ").as_bytes(),
        )
        .unwrap();
        let workflow = ReviewReadyWorkflow::new(descriptor).unwrap();
        assert!(matches!(
            workflow.sign_and_finalize_m24(Vec::new(), &[]),
            Err(M24SigningError::WrongState)
        ));
    }

    #[test]
    fn public_types_do_not_expose_secret_or_authorization_state() {
        let source = include_str!("m24_signing.rs");
        let production_source = source.split_once("#[cfg(test)]").unwrap().0;
        let terminal_body = production_source
            .split_once("pub struct TerminalInputKey {")
            .unwrap()
            .1
            .split_once("}\n")
            .unwrap()
            .0;
        assert!(!terminal_body.contains("pub "));
        for forbidden in [
            "impl Debug for TerminalInputKey",
            "impl Clone for TerminalInputKey",
            "impl Copy for TerminalInputKey",
            "CycleToken",
            "RequestApproval",
            "Approve",
            "RevalidationPassed",
            "card_session",
            "export_transport",
        ] {
            assert!(!production_source.contains(forbidden), "{forbidden}");
        }
    }
}
