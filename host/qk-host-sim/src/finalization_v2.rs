//! Capability-private v2 native-P2WSH 2-of-2 finalization and extraction.

use crate::finalization::FinalizedTransaction;
use crate::signing_v2::verify_der_signature;
use crate::transaction_sha256::sha256d;
use core::fmt;
use qk_descriptor::{derive_change_script_v2, derive_receive_script_v2, DescriptorPairV2};
use qk_psbt::bip143::{sighash_all_digest, Bip143InputFacts, Bip143PrecomputeBuilder, SIGHASH_ALL};
use qk_psbt::{
    analyze_descriptor_ownership_v2, build_review_v3, canonical_serialize, parse, InputSource,
    PsbtView, Record, ReviewContext, ReviewNetwork, ReviewV3, SemanticError, SerializeError,
    VerifiedAggregateStatus,
};

const PSBT_MAGIC_BYTES: usize = 5;
const WITNESS_SCRIPT_BYTES: usize = 71;
const DER_PLUS_SIGHASH_MAX_BYTES: usize = 72;
const DERIVATION_RECORD_BYTES: usize = 64;
const PARTIAL_SIGNATURE_RECORD_MAX_BYTES: usize = 108;
const MAX_UNSIGNED_TRANSACTION_BYTES: usize = 5_535;
const MAX_WITNESS_BYTES_PER_INPUT: usize = 220;
const MAX_FINAL_WITNESS_RECORD_BYTES: usize = 223;
const MAX_RAW_TRANSACTION_BYTES: usize = 27_537;
const MIN_FINALIZED_PSBT_SHRINK_PER_INPUT: usize = 121;

const _: [(); MAX_WITNESS_BYTES_PER_INPUT] =
    [(); 1 + 1 + 2 * (1 + DER_PLUS_SIGHASH_MAX_BYTES) + (1 + WITNESS_SCRIPT_BYTES)];
const _: [(); MAX_FINAL_WITNESS_RECORD_BYTES] = [(); 1 + 1 + 1 + MAX_WITNESS_BYTES_PER_INPUT];
const _: [(); MAX_RAW_TRANSACTION_BYTES] =
    [(); MAX_UNSIGNED_TRANSACTION_BYTES + 2 + 100 * MAX_WITNESS_BYTES_PER_INPUT];
const _: [(); MIN_FINALIZED_PSBT_SHRINK_PER_INPUT] = [(); 2 * PARTIAL_SIGNATURE_RECORD_MAX_BYTES
    + 2 * DERIVATION_RECORD_BYTES
    - MAX_FINAL_WITNESS_RECORD_BYTES];

/// Stable v2 finalization failure. No variant carries artifact bytes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FinalizationV2Error {
    /// Threshold-complete bytes failed structural parsing.
    CapabilityParse,
    /// Threshold-complete bytes were not already an M5 fixed point.
    NonCanonicalInput,
    /// Schema-v3 facts no longer match the bound pre-insertion review.
    ReviewFactsMismatch,
    /// Existing signatures or descriptor ownership failed verification.
    CryptographicVerification(SemanticError),
    /// At least one input lacks exact verified A+B completion.
    ThresholdIncomplete,
    /// Derivation, witnessScript, signature, or final-field shape is wrong.
    WitnessShapeMismatch,
    /// Signature map order does not match sorted witness-script positions.
    WitnessOrderMismatch,
    /// Checked output-length arithmetic overflowed.
    LengthOverflow,
    /// A candidate exceeds the ratified HOST cap.
    ArtifactTooLarge,
    /// A bounded exact allocation failed.
    AllocationFailed,
    /// The finalized PSBT failed structural reparsing.
    FinalizedPsbtReparse,
    /// The finalized PSBT is not an M5 fixed point.
    FinalizedPsbtNonCanonical,
    /// A record outside the exact finalization delta changed.
    ForbiddenDelta,
    /// The extracted witness transaction failed parsing through EOF.
    RawTransactionReparse,
    /// Witness-stripped bytes differ from the bound base transaction.
    BaseTransactionMismatch,
    /// A raw witness differs from its exact type-08 PSBT value.
    WitnessMismatch,
    /// A freshly reparsed signature failed exact-digest verification.
    FinalSignatureVerificationFailed,
    /// Transaction-identifier hashing failed.
    HashFailed,
    /// A previously established invariant did not hold.
    InternalInvariant,
}

impl fmt::Display for FinalizationV2Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::CapabilityParse => f.write_str("v2 finalization capability parse failed"),
            Self::NonCanonicalInput => f.write_str("v2 finalization input is not canonical"),
            Self::ReviewFactsMismatch => f.write_str("v2 finalization review facts changed"),
            Self::CryptographicVerification(error) => {
                write!(f, "v2 finalization verification failed: {error}")
            }
            Self::ThresholdIncomplete => f.write_str("v2 signature threshold incomplete"),
            Self::WitnessShapeMismatch => f.write_str("v2 finalization witness shape mismatch"),
            Self::WitnessOrderMismatch => f.write_str("v2 finalization witness order mismatch"),
            Self::LengthOverflow => f.write_str("v2 finalization length overflow"),
            Self::ArtifactTooLarge => f.write_str("v2 finalization artifact exceeds cap"),
            Self::AllocationFailed => f.write_str("v2 finalization allocation failed"),
            Self::FinalizedPsbtReparse => f.write_str("v2 finalized PSBT reparse failed"),
            Self::FinalizedPsbtNonCanonical => f.write_str("v2 finalized PSBT is not canonical"),
            Self::ForbiddenDelta => f.write_str("v2 finalized PSBT delta forbidden"),
            Self::RawTransactionReparse => f.write_str("v2 raw transaction reparse failed"),
            Self::BaseTransactionMismatch => f.write_str("v2 base transaction mismatch"),
            Self::WitnessMismatch => f.write_str("v2 final witness mismatch"),
            Self::FinalSignatureVerificationFailed => {
                f.write_str("v2 final signature verification failed")
            }
            Self::HashFailed => f.write_str("v2 transaction identifier hash failed"),
            Self::InternalInvariant => f.write_str("v2 finalization invariant failed"),
        }
    }
}

impl std::error::Error for FinalizationV2Error {}

#[derive(Clone, Copy)]
struct InputShape {
    witness_script: [u8; WITNESS_SCRIPT_BYTES],
}

#[derive(Clone, Copy)]
struct WitnessParts<'a> {
    first_signature: &'a [u8],
    second_signature: &'a [u8],
    witness_script: [u8; WITNESS_SCRIPT_BYTES],
    encoded_len: usize,
}

pub(super) fn finalize_v2(
    capability: Vec<u8>,
    source: InputSource,
    descriptor: &DescriptorPairV2,
    bound_review: &ReviewV3,
) -> Result<FinalizedTransaction, FinalizationV2Error> {
    let view = parse(&capability, source).map_err(|_| FinalizationV2Error::CapabilityParse)?;
    let canonical = canonical_serialize(&view).map_err(map_serialize_error)?;
    if canonical != capability {
        return Err(FinalizationV2Error::NonCanonicalInput);
    }
    let candidate_review = build_review_v3(
        &view,
        descriptor,
        ReviewContext {
            network: ReviewNetwork::BitcoinMainnet,
            input_source: source,
        },
    )
    .map_err(|_| FinalizationV2Error::ReviewFactsMismatch)?;
    if !transition_review_facts_equal(bound_review, &candidate_review) {
        return Err(FinalizationV2Error::ReviewFactsMismatch);
    }
    let verified = analyze_descriptor_ownership_v2(&view, descriptor)
        .map_err(FinalizationV2Error::CryptographicVerification)?;
    if verified.aggregate_status != VerifiedAggregateStatus::VerifyAndExportOnly
        || verified
            .verified_inputs
            .iter()
            .any(|input| input.verified_signature_count != 2)
    {
        return Err(FinalizationV2Error::ThresholdIncomplete);
    }

    let shapes = collect_input_shapes(&view, descriptor, bound_review)?;
    let witnesses = select_witnesses(&view, &shapes)?;
    let finalized_psbt = transform_psbt(&view, &capability, &witnesses, source)?;
    let finalized_view =
        parse(&finalized_psbt, source).map_err(|_| FinalizationV2Error::FinalizedPsbtReparse)?;
    let final_canonical = canonical_serialize(&finalized_view).map_err(map_serialize_error)?;
    if final_canonical != finalized_psbt {
        return Err(FinalizationV2Error::FinalizedPsbtNonCanonical);
    }
    if finalized_view.unsigned_tx_bytes() != view.unsigned_tx_bytes()
        || !allowed_finalized_delta(&view, &finalized_view, &witnesses)?
    {
        return Err(FinalizationV2Error::ForbiddenDelta);
    }

    let raw_transaction = extract_raw_transaction(view.unsigned_tx_bytes(), &witnesses)?;
    let parsed_witnesses =
        parse_and_rebind_raw(&raw_transaction, view.unsigned_tx_bytes(), &finalized_view)?;
    verify_parsed_witnesses(&parsed_witnesses, &witnesses, bound_review, descriptor)?;
    rebind_final_witness_records(&parsed_witnesses, &finalized_view)?;

    let txid = sha256d(&[view.unsigned_tx_bytes()]).map_err(|_| FinalizationV2Error::HashFailed)?;
    let wtxid = sha256d(&[&raw_transaction]).map_err(|_| FinalizationV2Error::HashFailed)?;
    Ok(FinalizedTransaction::from_checked_parts(
        finalized_psbt,
        raw_transaction,
        txid,
        wtxid,
    ))
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

fn map_serialize_error(error: SerializeError) -> FinalizationV2Error {
    match error {
        SerializeError::AllocationFailed => FinalizationV2Error::AllocationFailed,
        SerializeError::InvariantViolation => FinalizationV2Error::InternalInvariant,
    }
}

fn derive_script(
    descriptor: &DescriptorPairV2,
    branch: u32,
    index: u32,
) -> Result<qk_descriptor::DerivedScriptV2, FinalizationV2Error> {
    match branch {
        0 => derive_receive_script_v2(descriptor, index),
        1 => derive_change_script_v2(descriptor, index),
        _ => return Err(FinalizationV2Error::InternalInvariant),
    }
    .map_err(|_| FinalizationV2Error::InternalInvariant)
}

fn collect_input_shapes(
    view: &PsbtView<'_>,
    descriptor: &DescriptorPairV2,
    review: &ReviewV3,
) -> Result<Vec<InputShape>, FinalizationV2Error> {
    if view.input_map_count() != review.inputs().len() {
        return Err(FinalizationV2Error::InternalInvariant);
    }
    let mut shapes = Vec::new();
    shapes
        .try_reserve_exact(view.input_map_count())
        .map_err(|_| FinalizationV2Error::AllocationFailed)?;
    for input_index in 0..view.input_map_count() {
        let review_input = review
            .inputs()
            .get(input_index)
            .ok_or(FinalizationV2Error::InternalInvariant)?;
        let derived = derive_script(
            descriptor,
            review_input.branch(),
            review_input.child_index(),
        )?;
        let records = view
            .input_records(input_index)
            .ok_or(FinalizationV2Error::InternalInvariant)?;
        let mut derivations = 0usize;
        let mut partials = 0usize;
        let mut witness_script = None;
        for record in records {
            match record.key_type {
                0x02 => {
                    partials = partials
                        .checked_add(1)
                        .ok_or(FinalizationV2Error::LengthOverflow)?;
                }
                0x05 => {
                    if !record.key_data.is_empty() || witness_script.replace(record.value).is_some()
                    {
                        return Err(FinalizationV2Error::WitnessShapeMismatch);
                    }
                }
                0x06 => {
                    derivations = derivations
                        .checked_add(1)
                        .ok_or(FinalizationV2Error::LengthOverflow)?;
                }
                0x07 | 0x08 => return Err(FinalizationV2Error::WitnessShapeMismatch),
                _ => {}
            }
        }
        if derivations != 2 || partials != 2 {
            return Err(FinalizationV2Error::WitnessShapeMismatch);
        }
        if witness_script.is_some_and(|value| value != derived.witness_script.as_slice()) {
            return Err(FinalizationV2Error::WitnessShapeMismatch);
        }
        shapes.push(InputShape {
            witness_script: derived.witness_script,
        });
    }
    Ok(shapes)
}

fn select_witnesses<'a>(
    view: &PsbtView<'a>,
    shapes: &[InputShape],
) -> Result<Vec<WitnessParts<'a>>, FinalizationV2Error> {
    if shapes.len() != view.input_map_count() {
        return Err(FinalizationV2Error::InternalInvariant);
    }
    let mut witnesses = Vec::new();
    witnesses
        .try_reserve_exact(view.input_map_count())
        .map_err(|_| FinalizationV2Error::AllocationFailed)?;
    for input_index in 0..view.input_map_count() {
        let shape = shapes
            .get(input_index)
            .ok_or(FinalizationV2Error::InternalInvariant)?;
        let script_keys = script_keys(&shape.witness_script)?;
        let records = view
            .input_records(input_index)
            .ok_or(FinalizationV2Error::InternalInvariant)?;
        let mut partials: [Option<Record<'a>>; 2] = [None, None];
        let mut partial_count = 0usize;
        for record in records {
            if record.key_type == 0x02 {
                let slot = partials
                    .get_mut(partial_count)
                    .ok_or(FinalizationV2Error::WitnessShapeMismatch)?;
                *slot = Some(record);
                partial_count = partial_count
                    .checked_add(1)
                    .ok_or(FinalizationV2Error::LengthOverflow)?;
            }
        }
        if partial_count != 2 {
            return Err(FinalizationV2Error::WitnessShapeMismatch);
        }
        let first = partials[0].ok_or(FinalizationV2Error::WitnessShapeMismatch)?;
        let second = partials[1].ok_or(FinalizationV2Error::WitnessShapeMismatch)?;
        if first.key_data != script_keys[0].as_slice()
            || second.key_data != script_keys[1].as_slice()
        {
            if first.key_data == script_keys[1].as_slice()
                && second.key_data == script_keys[0].as_slice()
            {
                return Err(FinalizationV2Error::WitnessOrderMismatch);
            }
            return Err(FinalizationV2Error::WitnessShapeMismatch);
        }
        let encoded_len = witness_encoded_len(first.value, second.value, &shape.witness_script)?;
        if encoded_len > MAX_WITNESS_BYTES_PER_INPUT {
            return Err(FinalizationV2Error::ArtifactTooLarge);
        }
        witnesses.push(WitnessParts {
            first_signature: first.value,
            second_signature: second.value,
            witness_script: shape.witness_script,
            encoded_len,
        });
    }
    Ok(witnesses)
}

fn script_keys(script: &[u8; WITNESS_SCRIPT_BYTES]) -> Result<[[u8; 33]; 2], FinalizationV2Error> {
    if script.first() != Some(&0x52)
        || script.get(1) != Some(&0x21)
        || script.get(35) != Some(&0x21)
        || script.get(69) != Some(&0x52)
        || script.get(70) != Some(&0xae)
    {
        return Err(FinalizationV2Error::WitnessShapeMismatch);
    }
    let first: [u8; 33] = script
        .get(2..35)
        .ok_or(FinalizationV2Error::WitnessShapeMismatch)?
        .try_into()
        .map_err(|_| FinalizationV2Error::WitnessShapeMismatch)?;
    let second: [u8; 33] = script
        .get(36..69)
        .ok_or(FinalizationV2Error::WitnessShapeMismatch)?
        .try_into()
        .map_err(|_| FinalizationV2Error::WitnessShapeMismatch)?;
    if !matches!(first.first().copied(), Some(0x02 | 0x03))
        || !matches!(second.first().copied(), Some(0x02 | 0x03))
        || first >= second
    {
        return Err(FinalizationV2Error::WitnessShapeMismatch);
    }
    Ok([first, second])
}

fn witness_encoded_len(
    first_signature: &[u8],
    second_signature: &[u8],
    script: &[u8],
) -> Result<usize, FinalizationV2Error> {
    1usize
        .checked_add(1)
        .and_then(|value| value.checked_add(compact_size_len(first_signature.len())))
        .and_then(|value| value.checked_add(first_signature.len()))
        .and_then(|value| value.checked_add(compact_size_len(second_signature.len())))
        .and_then(|value| value.checked_add(second_signature.len()))
        .and_then(|value| value.checked_add(compact_size_len(script.len())))
        .and_then(|value| value.checked_add(script.len()))
        .ok_or(FinalizationV2Error::LengthOverflow)
}

fn transform_psbt(
    view: &PsbtView<'_>,
    bytes: &[u8],
    witnesses: &[WitnessParts<'_>],
    source: InputSource,
) -> Result<Vec<u8>, FinalizationV2Error> {
    if witnesses.len() != view.input_map_count() {
        return Err(FinalizationV2Error::InternalInvariant);
    }
    let mut final_len = PSBT_MAGIC_BYTES
        .checked_add(view.global_map_span().len())
        .ok_or(FinalizationV2Error::LengthOverflow)?;
    for (input_index, witness) in witnesses.iter().enumerate() {
        let span = view
            .input_map_span(input_index)
            .ok_or(FinalizationV2Error::InternalInvariant)?;
        let mut removed = 0usize;
        let mut record_start = span.start;
        for record in view
            .input_records(input_index)
            .ok_or(FinalizationV2Error::InternalInvariant)?
        {
            let encoded_len = record
                .value_span
                .end
                .checked_sub(record_start)
                .ok_or(FinalizationV2Error::InternalInvariant)?;
            if (0x02..=0x06).contains(&record.key_type) {
                removed = removed
                    .checked_add(encoded_len)
                    .ok_or(FinalizationV2Error::LengthOverflow)?;
            }
            record_start = record.value_span.end;
        }
        if record_start.checked_add(1) != Some(span.end) {
            return Err(FinalizationV2Error::InternalInvariant);
        }
        let map_len = span
            .len()
            .checked_sub(removed)
            .and_then(|value| {
                value.checked_add(final_witness_record_len(witness.encoded_len).ok()?)
            })
            .ok_or(FinalizationV2Error::LengthOverflow)?;
        final_len = final_len
            .checked_add(map_len)
            .ok_or(FinalizationV2Error::LengthOverflow)?;
    }
    for output_index in 0..view.output_map_count() {
        final_len = final_len
            .checked_add(
                view.output_map_span(output_index)
                    .ok_or(FinalizationV2Error::InternalInvariant)?
                    .len(),
            )
            .ok_or(FinalizationV2Error::LengthOverflow)?;
    }
    let minimum_shrink = view
        .input_map_count()
        .checked_mul(MIN_FINALIZED_PSBT_SHRINK_PER_INPUT)
        .ok_or(FinalizationV2Error::LengthOverflow)?;
    let largest_allowed = bytes
        .len()
        .checked_sub(minimum_shrink)
        .ok_or(FinalizationV2Error::ForbiddenDelta)?;
    if final_len > largest_allowed {
        return Err(FinalizationV2Error::ForbiddenDelta);
    }
    if final_len > source.max_bytes() {
        return Err(FinalizationV2Error::ArtifactTooLarge);
    }

    let mut finalized = Vec::new();
    finalized
        .try_reserve_exact(final_len)
        .map_err(|_| FinalizationV2Error::AllocationFailed)?;
    append_slice(
        &mut finalized,
        bytes
            .get(..PSBT_MAGIC_BYTES)
            .ok_or(FinalizationV2Error::InternalInvariant)?,
    );
    append_span(&mut finalized, bytes, view.global_map_span())?;
    for (input_index, witness) in witnesses.iter().enumerate() {
        emit_finalized_input(&mut finalized, view, bytes, input_index, witness)?;
    }
    for output_index in 0..view.output_map_count() {
        append_span(
            &mut finalized,
            bytes,
            view.output_map_span(output_index)
                .ok_or(FinalizationV2Error::InternalInvariant)?,
        )?;
    }
    if finalized.len() != final_len {
        return Err(FinalizationV2Error::InternalInvariant);
    }
    Ok(finalized)
}

fn emit_finalized_input(
    output: &mut Vec<u8>,
    view: &PsbtView<'_>,
    bytes: &[u8],
    input_index: usize,
    witness: &WitnessParts<'_>,
) -> Result<(), FinalizationV2Error> {
    let span = view
        .input_map_span(input_index)
        .ok_or(FinalizationV2Error::InternalInvariant)?;
    let mut record_start = span.start;
    let mut emitted_final = false;
    for record in view
        .input_records(input_index)
        .ok_or(FinalizationV2Error::InternalInvariant)?
    {
        if !emitted_final && record.key_type > 0x08 {
            emit_final_witness_record(output, witness)?;
            emitted_final = true;
        }
        if !(0x02..=0x06).contains(&record.key_type) {
            append_slice(
                output,
                bytes
                    .get(record_start..record.value_span.end)
                    .ok_or(FinalizationV2Error::InternalInvariant)?,
            );
        }
        record_start = record.value_span.end;
    }
    if !emitted_final {
        emit_final_witness_record(output, witness)?;
    }
    if record_start.checked_add(1) != Some(span.end) || bytes.get(record_start) != Some(&0x00) {
        return Err(FinalizationV2Error::InternalInvariant);
    }
    output.push(0x00);
    Ok(())
}

fn final_witness_record_len(witness_len: usize) -> Result<usize, FinalizationV2Error> {
    2usize
        .checked_add(compact_size_len(witness_len))
        .and_then(|value| value.checked_add(witness_len))
        .ok_or(FinalizationV2Error::LengthOverflow)
}

fn emit_final_witness_record(
    output: &mut Vec<u8>,
    witness: &WitnessParts<'_>,
) -> Result<(), FinalizationV2Error> {
    output.extend_from_slice(&[0x01, 0x08]);
    write_compact_size(output, witness.encoded_len)?;
    emit_witness(output, witness)
}

fn emit_witness(
    output: &mut Vec<u8>,
    witness: &WitnessParts<'_>,
) -> Result<(), FinalizationV2Error> {
    let before = output.len();
    output.extend_from_slice(&[0x04, 0x00]);
    write_compact_size(output, witness.first_signature.len())?;
    append_slice(output, witness.first_signature);
    write_compact_size(output, witness.second_signature.len())?;
    append_slice(output, witness.second_signature);
    write_compact_size(output, witness.witness_script.len())?;
    append_slice(output, &witness.witness_script);
    if output.len().checked_sub(before) != Some(witness.encoded_len) {
        return Err(FinalizationV2Error::InternalInvariant);
    }
    Ok(())
}

fn allowed_finalized_delta(
    before: &PsbtView<'_>,
    after: &PsbtView<'_>,
    witnesses: &[WitnessParts<'_>],
) -> Result<bool, FinalizationV2Error> {
    if before.input_map_count() != after.input_map_count()
        || before.output_map_count() != after.output_map_count()
        || witnesses.len() != before.input_map_count()
        || before.global_map_span().slice(before.buffer())
            != after.global_map_span().slice(after.buffer())
    {
        return Ok(false);
    }
    for output_index in 0..before.output_map_count() {
        if before
            .output_map_span(output_index)
            .and_then(|span| span.slice(before.buffer()))
            != after
                .output_map_span(output_index)
                .and_then(|span| span.slice(after.buffer()))
        {
            return Ok(false);
        }
    }
    for (input_index, witness) in witnesses.iter().enumerate() {
        let mut preserved = match before.input_records(input_index) {
            Some(records) => records.filter(|record| {
                !(0x02..=0x06).contains(&record.key_type)
                    && record.key_type != 0x07
                    && record.key_type != 0x08
            }),
            None => return Ok(false),
        };
        let after_records = match after.input_records(input_index) {
            Some(records) => records,
            None => return Ok(false),
        };
        let mut final_seen = false;
        for record in after_records {
            if record.key_type == 0x08 {
                if final_seen || !record.key_data.is_empty() {
                    return Ok(false);
                }
                let mut expected = Vec::new();
                expected
                    .try_reserve_exact(witness.encoded_len)
                    .map_err(|_| FinalizationV2Error::AllocationFailed)?;
                emit_witness(&mut expected, witness)?;
                if record.value != expected.as_slice() {
                    return Ok(false);
                }
                final_seen = true;
            } else {
                if (0x02..=0x07).contains(&record.key_type) {
                    return Ok(false);
                }
                let expected = match preserved.next() {
                    Some(expected) => expected,
                    None => return Ok(false),
                };
                if record.full_key != expected.full_key || record.value != expected.value {
                    return Ok(false);
                }
            }
        }
        if !final_seen || preserved.next().is_some() {
            return Ok(false);
        }
    }
    Ok(true)
}

fn extract_raw_transaction(
    base: &[u8],
    witnesses: &[WitnessParts<'_>],
) -> Result<Vec<u8>, FinalizationV2Error> {
    if base.len() > MAX_UNSIGNED_TRANSACTION_BYTES || base.len() < 8 {
        return Err(FinalizationV2Error::ArtifactTooLarge);
    }
    let witness_total = witnesses.iter().try_fold(0usize, |total, witness| {
        total
            .checked_add(witness.encoded_len)
            .ok_or(FinalizationV2Error::LengthOverflow)
    })?;
    let raw_len = base
        .len()
        .checked_add(2)
        .and_then(|value| value.checked_add(witness_total))
        .ok_or(FinalizationV2Error::LengthOverflow)?;
    if raw_len > MAX_RAW_TRANSACTION_BYTES {
        return Err(FinalizationV2Error::ArtifactTooLarge);
    }
    let locktime_start = base
        .len()
        .checked_sub(4)
        .ok_or(FinalizationV2Error::InternalInvariant)?;
    let mut raw = Vec::new();
    raw.try_reserve_exact(raw_len)
        .map_err(|_| FinalizationV2Error::AllocationFailed)?;
    append_slice(
        &mut raw,
        base.get(..4)
            .ok_or(FinalizationV2Error::InternalInvariant)?,
    );
    raw.extend_from_slice(&[0x00, 0x01]);
    append_slice(
        &mut raw,
        base.get(4..locktime_start)
            .ok_or(FinalizationV2Error::InternalInvariant)?,
    );
    for witness in witnesses {
        emit_witness(&mut raw, witness)?;
    }
    append_slice(
        &mut raw,
        base.get(locktime_start..)
            .ok_or(FinalizationV2Error::InternalInvariant)?,
    );
    if raw.len() != raw_len {
        return Err(FinalizationV2Error::InternalInvariant);
    }
    Ok(raw)
}

#[derive(Clone, Copy)]
struct ParsedRawWitness<'a> {
    encoded: &'a [u8],
    item_count: u64,
    items: [Option<&'a [u8]>; 4],
}

fn parse_and_rebind_raw<'a>(
    raw: &'a [u8],
    base: &[u8],
    finalized_view: &PsbtView<'_>,
) -> Result<Vec<ParsedRawWitness<'a>>, FinalizationV2Error> {
    let mut cursor = RawCursor::new(raw);
    let mut stripped = Vec::new();
    stripped
        .try_reserve_exact(base.len())
        .map_err(|_| FinalizationV2Error::AllocationFailed)?;
    append_slice(&mut stripped, cursor.take(4)?);
    if cursor.take(2)? != [0x00, 0x01].as_slice() {
        return Err(FinalizationV2Error::RawTransactionReparse);
    }
    let (input_count, input_count_bytes) = cursor.compact_size()?;
    let input_count =
        usize::try_from(input_count).map_err(|_| FinalizationV2Error::RawTransactionReparse)?;
    if input_count == 0 || input_count != finalized_view.input_map_count() {
        return Err(FinalizationV2Error::RawTransactionReparse);
    }
    append_slice(&mut stripped, input_count_bytes);
    for _ in 0..input_count {
        append_slice(&mut stripped, cursor.take(36)?);
        let (script_len, script_len_bytes) = cursor.compact_size()?;
        if script_len != 0 {
            return Err(FinalizationV2Error::RawTransactionReparse);
        }
        append_slice(&mut stripped, script_len_bytes);
        append_slice(&mut stripped, cursor.take(4)?);
    }
    let (output_count, output_count_bytes) = cursor.compact_size()?;
    let output_count =
        usize::try_from(output_count).map_err(|_| FinalizationV2Error::RawTransactionReparse)?;
    if output_count == 0 || output_count != finalized_view.output_map_count() {
        return Err(FinalizationV2Error::RawTransactionReparse);
    }
    append_slice(&mut stripped, output_count_bytes);
    for _ in 0..output_count {
        append_slice(&mut stripped, cursor.take(8)?);
        let (script_len, script_len_bytes) = cursor.compact_size()?;
        let script_len =
            usize::try_from(script_len).map_err(|_| FinalizationV2Error::RawTransactionReparse)?;
        append_slice(&mut stripped, script_len_bytes);
        append_slice(&mut stripped, cursor.take(script_len)?);
    }

    let mut parsed_witnesses = Vec::new();
    parsed_witnesses
        .try_reserve_exact(input_count)
        .map_err(|_| FinalizationV2Error::AllocationFailed)?;
    for _ in 0..input_count {
        let witness_start = cursor.position();
        let (item_count, _) = cursor.compact_size()?;
        let mut items: [Option<&[u8]>; 4] = [None, None, None, None];
        let mut item_index = 0u64;
        while item_index < item_count {
            let (item_len, _) = cursor.compact_size()?;
            let item_len = usize::try_from(item_len)
                .map_err(|_| FinalizationV2Error::RawTransactionReparse)?;
            let item = cursor.take(item_len)?;
            if item_index < 4 {
                let index = usize::try_from(item_index)
                    .map_err(|_| FinalizationV2Error::RawTransactionReparse)?;
                let slot = items
                    .get_mut(index)
                    .ok_or(FinalizationV2Error::InternalInvariant)?;
                *slot = Some(item);
            }
            item_index = item_index
                .checked_add(1)
                .ok_or(FinalizationV2Error::RawTransactionReparse)?;
        }
        let encoded = raw
            .get(witness_start..cursor.position())
            .ok_or(FinalizationV2Error::RawTransactionReparse)?;
        parsed_witnesses.push(ParsedRawWitness {
            encoded,
            item_count,
            items,
        });
    }
    append_slice(&mut stripped, cursor.take(4)?);
    if !cursor.at_end() {
        return Err(FinalizationV2Error::RawTransactionReparse);
    }
    if stripped != base {
        return Err(FinalizationV2Error::BaseTransactionMismatch);
    }
    Ok(parsed_witnesses)
}

fn rebind_final_witness_records(
    parsed: &[ParsedRawWitness<'_>],
    finalized_view: &PsbtView<'_>,
) -> Result<(), FinalizationV2Error> {
    if parsed.len() != finalized_view.input_map_count() {
        return Err(FinalizationV2Error::InternalInvariant);
    }
    for (input_index, witness) in parsed.iter().enumerate() {
        let final_witness = finalized_view
            .input_records(input_index)
            .ok_or(FinalizationV2Error::InternalInvariant)?
            .find(|record| record.key_type == 0x08)
            .ok_or(FinalizationV2Error::WitnessMismatch)?;
        if witness.encoded != final_witness.value {
            return Err(FinalizationV2Error::WitnessMismatch);
        }
    }
    Ok(())
}

fn compute_input_digests(
    review: &ReviewV3,
    descriptor: &DescriptorPairV2,
) -> Result<Vec<[u8; 32]>, FinalizationV2Error> {
    let mut builder = Bip143PrecomputeBuilder::new();
    for input in review.inputs() {
        let txid = input.outpoint_txid_wire();
        builder
            .add_input(&txid, input.outpoint_vout(), input.sequence())
            .map_err(|_| FinalizationV2Error::FinalSignatureVerificationFailed)?;
    }
    for output in review.outputs() {
        builder
            .add_output(output.amount(), output.script_pubkey())
            .map_err(|_| FinalizationV2Error::FinalSignatureVerificationFailed)?;
    }
    let precomputed = builder
        .finish()
        .map_err(|_| FinalizationV2Error::FinalSignatureVerificationFailed)?;
    let mut digests = Vec::new();
    digests
        .try_reserve_exact(review.inputs().len())
        .map_err(|_| FinalizationV2Error::AllocationFailed)?;
    for input in review.inputs() {
        if input.effective_sighash() != u32::from(SIGHASH_ALL) {
            return Err(FinalizationV2Error::InternalInvariant);
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
                .map_err(|_| FinalizationV2Error::FinalSignatureVerificationFailed)?,
        );
    }
    Ok(digests)
}

fn verify_parsed_witnesses(
    parsed: &[ParsedRawWitness<'_>],
    expected: &[WitnessParts<'_>],
    review: &ReviewV3,
    descriptor: &DescriptorPairV2,
) -> Result<(), FinalizationV2Error> {
    if parsed.len() != expected.len() || parsed.len() != review.inputs().len() {
        return Err(FinalizationV2Error::InternalInvariant);
    }
    let digests = compute_input_digests(review, descriptor)?;
    for (input_index, (actual, expected_witness)) in parsed.iter().zip(expected).enumerate() {
        let empty_dummy = matches!(actual.items[0], Some(dummy) if dummy.is_empty());
        if actual.item_count != 4 || !empty_dummy {
            return Err(FinalizationV2Error::WitnessMismatch);
        }
        let first = actual.items[1].ok_or(FinalizationV2Error::WitnessMismatch)?;
        let second = actual.items[2].ok_or(FinalizationV2Error::WitnessMismatch)?;
        let script = actual.items[3].ok_or(FinalizationV2Error::WitnessMismatch)?;
        if first == expected_witness.second_signature && second == expected_witness.first_signature
        {
            return Err(FinalizationV2Error::WitnessOrderMismatch);
        }
        if first != expected_witness.first_signature
            || second != expected_witness.second_signature
            || script != expected_witness.witness_script.as_slice()
        {
            return Err(FinalizationV2Error::WitnessMismatch);
        }
        let keys = script_keys(&expected_witness.witness_script)?;
        let digest = digests
            .get(input_index)
            .ok_or(FinalizationV2Error::InternalInvariant)?;
        verify_complete_signature(first, digest, &keys[0])?;
        verify_complete_signature(second, digest, &keys[1])?;
    }
    Ok(())
}

fn verify_complete_signature(
    complete: &[u8],
    digest: &[u8; 32],
    key: &[u8; 33],
) -> Result<(), FinalizationV2Error> {
    let (sighash, der) = complete
        .split_last()
        .ok_or(FinalizationV2Error::FinalSignatureVerificationFailed)?;
    if *sighash != SIGHASH_ALL {
        return Err(FinalizationV2Error::FinalSignatureVerificationFailed);
    }
    verify_der_signature(der, digest, key)
        .map_err(|_| FinalizationV2Error::FinalSignatureVerificationFailed)
}

struct RawCursor<'a> {
    bytes: &'a [u8],
    position: usize,
}

impl<'a> RawCursor<'a> {
    const fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, position: 0 }
    }

    const fn position(&self) -> usize {
        self.position
    }

    fn take(&mut self, count: usize) -> Result<&'a [u8], FinalizationV2Error> {
        let end = self
            .position
            .checked_add(count)
            .ok_or(FinalizationV2Error::RawTransactionReparse)?;
        let value = self
            .bytes
            .get(self.position..end)
            .ok_or(FinalizationV2Error::RawTransactionReparse)?;
        self.position = end;
        Ok(value)
    }

    fn compact_size(&mut self) -> Result<(u64, &'a [u8]), FinalizationV2Error> {
        let start = self.position;
        let first = *self
            .take(1)?
            .first()
            .ok_or(FinalizationV2Error::RawTransactionReparse)?;
        let value = match first {
            0xfd => {
                let bytes: [u8; 2] = self
                    .take(2)?
                    .try_into()
                    .map_err(|_| FinalizationV2Error::RawTransactionReparse)?;
                let value = u64::from(u16::from_le_bytes(bytes));
                if value < 0xfd {
                    return Err(FinalizationV2Error::RawTransactionReparse);
                }
                value
            }
            0xfe => {
                let bytes: [u8; 4] = self
                    .take(4)?
                    .try_into()
                    .map_err(|_| FinalizationV2Error::RawTransactionReparse)?;
                let value = u64::from(u32::from_le_bytes(bytes));
                if value <= 0xffff {
                    return Err(FinalizationV2Error::RawTransactionReparse);
                }
                value
            }
            0xff => {
                let bytes: [u8; 8] = self
                    .take(8)?
                    .try_into()
                    .map_err(|_| FinalizationV2Error::RawTransactionReparse)?;
                let value = u64::from_le_bytes(bytes);
                if value <= 0xffff_ffff {
                    return Err(FinalizationV2Error::RawTransactionReparse);
                }
                value
            }
            value => u64::from(value),
        };
        let encoded = self
            .bytes
            .get(start..self.position)
            .ok_or(FinalizationV2Error::RawTransactionReparse)?;
        Ok((value, encoded))
    }

    fn at_end(&self) -> bool {
        self.position == self.bytes.len()
    }
}

fn compact_size_len(value: usize) -> usize {
    if value < 0xfd {
        1
    } else if value <= 0xffff {
        3
    } else if value <= 0xffff_ffff {
        5
    } else {
        9
    }
}

fn write_compact_size(output: &mut Vec<u8>, value: usize) -> Result<(), FinalizationV2Error> {
    let value = u64::try_from(value).map_err(|_| FinalizationV2Error::LengthOverflow)?;
    if value < 0xfd {
        output.push(u8::try_from(value).map_err(|_| FinalizationV2Error::InternalInvariant)?);
    } else if value <= 0xffff {
        output.push(0xfd);
        output.extend_from_slice(
            &u16::try_from(value)
                .map_err(|_| FinalizationV2Error::InternalInvariant)?
                .to_le_bytes(),
        );
    } else if value <= 0xffff_ffff {
        output.push(0xfe);
        output.extend_from_slice(
            &u32::try_from(value)
                .map_err(|_| FinalizationV2Error::InternalInvariant)?
                .to_le_bytes(),
        );
    } else {
        output.push(0xff);
        output.extend_from_slice(&value.to_le_bytes());
    }
    Ok(())
}

fn append_span(
    output: &mut Vec<u8>,
    source: &[u8],
    span: qk_psbt::Span,
) -> Result<(), FinalizationV2Error> {
    append_slice(
        output,
        span.slice(source)
            .ok_or(FinalizationV2Error::InternalInvariant)?,
    );
    Ok(())
}

fn append_slice(output: &mut Vec<u8>, value: &[u8]) {
    output.extend_from_slice(value);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn v2_cap_arithmetic_is_exact() {
        assert_eq!(MAX_WITNESS_BYTES_PER_INPUT, 220);
        assert_eq!(MAX_FINAL_WITNESS_RECORD_BYTES, 223);
        assert_eq!(MAX_RAW_TRANSACTION_BYTES, 27_537);
        assert_eq!(MIN_FINALIZED_PSBT_SHRINK_PER_INPUT, 121);
        assert_eq!(
            1 + 1 + 2 * (1 + DER_PLUS_SIGHASH_MAX_BYTES) + (1 + WITNESS_SCRIPT_BYTES),
            MAX_WITNESS_BYTES_PER_INPUT
        );
        assert_eq!(
            1 + 1 + 1 + MAX_WITNESS_BYTES_PER_INPUT,
            MAX_FINAL_WITNESS_RECORD_BYTES
        );
        assert_eq!(
            MAX_UNSIGNED_TRANSACTION_BYTES + 2 + 100 * MAX_WITNESS_BYTES_PER_INPUT,
            MAX_RAW_TRANSACTION_BYTES
        );
        assert_eq!(
            2 * PARTIAL_SIGNATURE_RECORD_MAX_BYTES + 2 * DERIVATION_RECORD_BYTES
                - MAX_FINAL_WITNESS_RECORD_BYTES,
            MIN_FINALIZED_PSBT_SHRINK_PER_INPUT
        );
    }
}
