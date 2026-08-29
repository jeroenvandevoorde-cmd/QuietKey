//! Capability-only M16 native-P2WSH finalization and extraction.

use crate::insertion::ThresholdCompletePsbt;
use crate::transaction_sha256::sha256d;
use core::fmt;
use qk_psbt::{
    analyze_and_verify_signatures, canonical_serialize, parse, InputSource, PsbtView, Record,
    SemanticError, SerializeError, VerifiedAggregateStatus,
};

const PSBT_MAGIC_BYTES: usize = 5;
const WITNESS_SCRIPT_BYTES: usize = 105;
const DER_PLUS_SIGHASH_MAX_BYTES: usize = 72;
const DERIVATION_RECORD_BYTES: usize = 64;
const PARTIAL_SIGNATURE_RECORD_FRAME_BYTES: usize = 36;
const FINAL_WITNESS_PAYLOAD_FRAME_BYTES: usize = 110;
const MAX_UNSIGNED_TRANSACTION_BYTES: usize = 5_535;
const MAX_WITNESS_BYTES_PER_INPUT: usize = 254;
const MAX_FINAL_WITNESS_RECORD_BYTES: usize = 259;
const MAX_RAW_TRANSACTION_BYTES: usize = 30_937;
const MIN_FINALIZED_PSBT_SHRINK_PER_INPUT: usize = 149;

const _: [(); MAX_WITNESS_BYTES_PER_INPUT] =
    [(); 1 + 1 + 2 * (1 + DER_PLUS_SIGHASH_MAX_BYTES) + 1 + WITNESS_SCRIPT_BYTES];
const _: [(); MAX_FINAL_WITNESS_RECORD_BYTES] = [(); 1 + 1 + 3 + MAX_WITNESS_BYTES_PER_INPUT];
const _: [(); MAX_RAW_TRANSACTION_BYTES] =
    [(); MAX_UNSIGNED_TRANSACTION_BYTES + 2 + 100 * MAX_WITNESS_BYTES_PER_INPUT];
const _: [(); MIN_FINALIZED_PSBT_SHRINK_PER_INPUT] = [(); 3 * DERIVATION_RECORD_BYTES
    + 2 * PARTIAL_SIGNATURE_RECORD_FRAME_BYTES
    - (2 + 3 + FINAL_WITNESS_PAYLOAD_FRAME_BYTES)];

/// One fully checked finalized PSBT and its exact extracted transaction.
///
/// Fields are private and the type has no public constructor. It can be obtained
/// only by consuming a checked [`ThresholdCompletePsbt`] capability through
/// the M15 external-signature path, the separate M24 HOST continuation, or
/// the parallel v2 slice-3 continuation.
pub struct FinalizedTransaction {
    finalized_psbt: Vec<u8>,
    raw_transaction: Vec<u8>,
    txid: [u8; 32],
    wtxid: [u8; 32],
}

impl FinalizedTransaction {
    pub(super) fn from_checked_parts(
        finalized_psbt: Vec<u8>,
        raw_transaction: Vec<u8>,
        txid: [u8; 32],
        wtxid: [u8; 32],
    ) -> Self {
        Self {
            finalized_psbt,
            raw_transaction,
            txid,
            wtxid,
        }
    }

    /// Borrow the exact M5-canonical finalized PSBT bytes.
    #[must_use]
    pub fn finalized_psbt(&self) -> &[u8] {
        &self.finalized_psbt
    }

    /// Borrow the exact BIP141 witness-transaction bytes.
    #[must_use]
    pub fn raw_transaction(&self) -> &[u8] {
        &self.raw_transaction
    }

    /// Raw SHA256d output bytes of the witness-stripped transaction.
    /// Conventional RPC hex displays these bytes in reverse order.
    #[must_use]
    pub const fn txid(&self) -> [u8; 32] {
        self.txid
    }

    /// Raw SHA256d output bytes of the exact witness transaction.
    /// Conventional RPC hex displays these bytes in reverse order.
    #[must_use]
    pub const fn wtxid(&self) -> [u8; 32] {
        self.wtxid
    }
}

/// Stable M16 failure. No variant carries PSBT, witness, or transaction bytes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FinalizationError {
    /// The consumed capability no longer parses under its retained source cap.
    CapabilityParse,
    /// The M15 bytes are not already an exact M5 fixed point.
    NonCanonicalInput,
    /// Existing signatures no longer pass the M8 verification pipeline.
    CryptographicVerification(SemanticError),
    /// At least one input is below its verified signature threshold.
    ThresholdIncomplete,
    /// WitnessScript, derivation, signature, or preexisting-final-field shape changed.
    WitnessShapeMismatch,
    /// Partial-signature map order does not match sorted script-key positions.
    WitnessOrderMismatch,
    /// Checked output-length arithmetic overflowed.
    LengthOverflow,
    /// A candidate exceeds its retained HOST cap.
    ArtifactTooLarge,
    /// A bounded exact allocation failed.
    AllocationFailed,
    /// The finalized PSBT failed structural reparsing.
    FinalizedPsbtReparse,
    /// The finalized PSBT is not an M5 fixed point.
    FinalizedPsbtNonCanonical,
    /// A record outside the ratified finalization delta changed.
    ForbiddenDelta,
    /// The extracted witness transaction failed bounded parsing through EOF.
    RawTransactionReparse,
    /// Reconstructed witness-stripped bytes differ from the approved base transaction.
    BaseTransactionMismatch,
    /// A raw input witness differs from its exact type-08 PSBT value.
    WitnessMismatch,
    /// SHA256d length accounting or finalization failed.
    HashFailed,
    /// An invariant established by M5 through M15 did not hold.
    InternalInvariant,
}

impl fmt::Display for FinalizationError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::CapabilityParse => f.write_str("finalization capability parse failed"),
            Self::NonCanonicalInput => f.write_str("finalization capability is not canonical"),
            Self::CryptographicVerification(error) => {
                write!(f, "finalization verification failed: {error}")
            }
            Self::ThresholdIncomplete => f.write_str("signature threshold incomplete"),
            Self::WitnessShapeMismatch => f.write_str("finalization witness shape mismatch"),
            Self::WitnessOrderMismatch => f.write_str("finalization witness order mismatch"),
            Self::LengthOverflow => f.write_str("finalization length overflow"),
            Self::ArtifactTooLarge => f.write_str("finalization artifact exceeds cap"),
            Self::AllocationFailed => f.write_str("finalization allocation failed"),
            Self::FinalizedPsbtReparse => f.write_str("finalized PSBT reparse failed"),
            Self::FinalizedPsbtNonCanonical => f.write_str("finalized PSBT is not canonical"),
            Self::ForbiddenDelta => f.write_str("finalized PSBT delta forbidden"),
            Self::RawTransactionReparse => f.write_str("raw transaction reparse failed"),
            Self::BaseTransactionMismatch => f.write_str("base transaction mismatch"),
            Self::WitnessMismatch => f.write_str("final witness mismatch"),
            Self::HashFailed => f.write_str("transaction identifier hash failed"),
            Self::InternalInvariant => f.write_str("finalization internal invariant failed"),
        }
    }
}

impl std::error::Error for FinalizationError {}

#[derive(Clone, Copy)]
struct InputShape {
    witness_script: [u8; WITNESS_SCRIPT_BYTES],
    recorded_witness_script: bool,
}

#[derive(Clone, Copy)]
struct WitnessParts<'a> {
    first_signature: &'a [u8],
    second_signature: &'a [u8],
    witness_script: [u8; WITNESS_SCRIPT_BYTES],
    encoded_len: usize,
}

impl ThresholdCompletePsbt {
    /// Consume this threshold-complete capability, finalize every exact
    /// native-P2WSH input, and extract one reparsed witness transaction.
    ///
    /// # Errors
    ///
    /// The capability is consumed on every path. A failure returns no PSBT,
    /// witness, transaction, or identifier bytes.
    pub fn finalize_and_extract(self) -> Result<FinalizedTransaction, FinalizationError> {
        finalize_capability(self.bytes, self.source)
    }
}

fn finalize_capability(
    capability: Vec<u8>,
    source: InputSource,
) -> Result<FinalizedTransaction, FinalizationError> {
    let view = parse(&capability, source).map_err(|_| FinalizationError::CapabilityParse)?;
    let canonical = canonical_serialize(&view).map_err(map_serialize_error)?;
    if canonical != capability {
        return Err(FinalizationError::NonCanonicalInput);
    }
    drop(canonical);

    let shapes = collect_input_shapes(&view)?;
    let verification_copy = if shapes.iter().any(|shape| !shape.recorded_witness_script) {
        Some(build_verification_copy(
            &view,
            &capability,
            &shapes,
            source,
        )?)
    } else {
        None
    };
    let aggregate = match verification_copy.as_ref() {
        Some(bytes) => {
            let verification_view =
                parse(bytes, source).map_err(|_| FinalizationError::InternalInvariant)?;
            analyze_and_verify_signatures(&verification_view)
                .map_err(FinalizationError::CryptographicVerification)?
                .aggregate_status
        }
        None => {
            analyze_and_verify_signatures(&view)
                .map_err(FinalizationError::CryptographicVerification)?
                .aggregate_status
        }
    };
    if aggregate != VerifiedAggregateStatus::VerifyAndExportOnly {
        return Err(FinalizationError::ThresholdIncomplete);
    }
    drop(verification_copy);
    let witnesses = select_witnesses(&view, &shapes)?;

    let finalized_psbt = transform_psbt(&view, &capability, &witnesses, source)?;
    let finalized_view =
        parse(&finalized_psbt, source).map_err(|_| FinalizationError::FinalizedPsbtReparse)?;
    let final_canonical = canonical_serialize(&finalized_view).map_err(map_serialize_error)?;
    if final_canonical != finalized_psbt {
        return Err(FinalizationError::FinalizedPsbtNonCanonical);
    }
    drop(final_canonical);
    if finalized_view.unsigned_tx_bytes() != view.unsigned_tx_bytes()
        || !allowed_finalized_delta(&view, &finalized_view, &witnesses)?
    {
        return Err(FinalizationError::ForbiddenDelta);
    }

    let raw_transaction = extract_raw_transaction(view.unsigned_tx_bytes(), &witnesses)?;
    reparse_and_rebind_raw(
        &raw_transaction,
        view.unsigned_tx_bytes(),
        &finalized_view,
        &witnesses,
    )?;

    let txid = sha256d(&[view.unsigned_tx_bytes()]).map_err(|_| FinalizationError::HashFailed)?;
    let wtxid = sha256d(&[&raw_transaction]).map_err(|_| FinalizationError::HashFailed)?;
    Ok(FinalizedTransaction {
        finalized_psbt,
        raw_transaction,
        txid,
        wtxid,
    })
}

fn map_serialize_error(error: SerializeError) -> FinalizationError {
    match error {
        SerializeError::AllocationFailed => FinalizationError::AllocationFailed,
        SerializeError::InvariantViolation => FinalizationError::InternalInvariant,
    }
}

fn collect_input_shapes(view: &PsbtView<'_>) -> Result<Vec<InputShape>, FinalizationError> {
    let mut shapes = Vec::new();
    shapes
        .try_reserve_exact(view.input_map_count())
        .map_err(|_| FinalizationError::AllocationFailed)?;
    for input_index in 0..view.input_map_count() {
        let records = view
            .input_records(input_index)
            .ok_or(FinalizationError::InternalInvariant)?;
        let mut recorded_script = None;
        let mut derivations: [Option<Record<'_>>; 3] = [None, None, None];
        let mut derivation_count = 0usize;
        for record in records {
            match record.key_type {
                0x05 => {
                    if recorded_script.replace(record.value).is_some() {
                        return Err(FinalizationError::WitnessShapeMismatch);
                    }
                }
                0x06 => {
                    let slot = derivations
                        .get_mut(derivation_count)
                        .ok_or(FinalizationError::WitnessShapeMismatch)?;
                    *slot = Some(record);
                    derivation_count = derivation_count
                        .checked_add(1)
                        .ok_or(FinalizationError::LengthOverflow)?;
                }
                0x07 | 0x08 => return Err(FinalizationError::WitnessShapeMismatch),
                _ => {}
            }
        }
        if derivation_count != 3 {
            return Err(FinalizationError::WitnessShapeMismatch);
        }
        let keys = exact_derivation_keys(&derivations)?;
        let witness_script = reconstruct_witness_script(&keys);
        if recorded_script.is_some_and(|script| script != witness_script.as_slice()) {
            return Err(FinalizationError::WitnessShapeMismatch);
        }
        shapes.push(InputShape {
            witness_script,
            recorded_witness_script: recorded_script.is_some(),
        });
    }
    Ok(shapes)
}

fn select_witnesses<'a>(
    view: &PsbtView<'a>,
    shapes: &[InputShape],
) -> Result<Vec<WitnessParts<'a>>, FinalizationError> {
    if shapes.len() != view.input_map_count() {
        return Err(FinalizationError::InternalInvariant);
    }
    let mut witnesses = Vec::new();
    witnesses
        .try_reserve_exact(view.input_map_count())
        .map_err(|_| FinalizationError::AllocationFailed)?;
    for input_index in 0..view.input_map_count() {
        let records = view
            .input_records(input_index)
            .ok_or(FinalizationError::InternalInvariant)?;
        let mut partials: [Option<Record<'a>>; 3] = [None, None, None];
        let mut partial_count = 0usize;
        for record in records {
            if record.key_type == 0x02 {
                let slot = partials
                    .get_mut(partial_count)
                    .ok_or(FinalizationError::WitnessShapeMismatch)?;
                *slot = Some(record);
                partial_count = partial_count
                    .checked_add(1)
                    .ok_or(FinalizationError::LengthOverflow)?;
            }
        }
        if !(2..=3).contains(&partial_count) {
            return Err(FinalizationError::WitnessShapeMismatch);
        }
        let shape = shapes
            .get(input_index)
            .ok_or(FinalizationError::InternalInvariant)?;
        let keys = script_keys(&shape.witness_script)?;

        let mut selected: [Option<&[u8]>; 2] = [None, None];
        let mut previous_position = None;
        for (seen, record) in partials.iter().flatten().enumerate() {
            let position = keys
                .iter()
                .position(|key| key.as_slice() == record.key_data)
                .ok_or(FinalizationError::WitnessShapeMismatch)?;
            if previous_position.is_some_and(|previous| position <= previous) {
                return Err(FinalizationError::WitnessOrderMismatch);
            }
            previous_position = Some(position);
            if let Some(slot) = selected.get_mut(seen) {
                *slot = Some(record.value);
            }
        }
        let first_signature = selected[0].ok_or(FinalizationError::WitnessShapeMismatch)?;
        let second_signature = selected[1].ok_or(FinalizationError::WitnessShapeMismatch)?;
        let encoded_len =
            witness_encoded_len(first_signature, second_signature, &shape.witness_script)?;
        if encoded_len > MAX_WITNESS_BYTES_PER_INPUT {
            return Err(FinalizationError::ArtifactTooLarge);
        }
        witnesses.push(WitnessParts {
            first_signature,
            second_signature,
            witness_script: shape.witness_script,
            encoded_len,
        });
    }
    Ok(witnesses)
}

fn script_keys(script: &[u8]) -> Result<[[u8; 33]; 3], FinalizationError> {
    if script.len() != WITNESS_SCRIPT_BYTES
        || script.first() != Some(&0x52)
        || script.get(1) != Some(&0x21)
        || script.get(35) != Some(&0x21)
        || script.get(69) != Some(&0x21)
        || script.get(103) != Some(&0x53)
        || script.get(104) != Some(&0xae)
    {
        return Err(FinalizationError::WitnessShapeMismatch);
    }
    let first: [u8; 33] = script
        .get(2..35)
        .ok_or(FinalizationError::WitnessShapeMismatch)?
        .try_into()
        .map_err(|_| FinalizationError::WitnessShapeMismatch)?;
    let second: [u8; 33] = script
        .get(36..69)
        .ok_or(FinalizationError::WitnessShapeMismatch)?
        .try_into()
        .map_err(|_| FinalizationError::WitnessShapeMismatch)?;
    let third: [u8; 33] = script
        .get(70..103)
        .ok_or(FinalizationError::WitnessShapeMismatch)?
        .try_into()
        .map_err(|_| FinalizationError::WitnessShapeMismatch)?;
    if !matches!(first.first().copied(), Some(0x02 | 0x03))
        || !matches!(second.first().copied(), Some(0x02 | 0x03))
        || !matches!(third.first().copied(), Some(0x02 | 0x03))
        || first >= second
        || second >= third
    {
        return Err(FinalizationError::WitnessShapeMismatch);
    }
    Ok([first, second, third])
}

fn exact_derivation_keys(
    derivations: &[Option<Record<'_>>; 3],
) -> Result<[[u8; 33]; 3], FinalizationError> {
    const PURPOSE: [u8; 4] = 0x8000_0030u32.to_le_bytes();
    const COIN: [u8; 4] = 0x8000_0000u32.to_le_bytes();
    const ACCOUNT: [u8; 4] = 0x8000_0000u32.to_le_bytes();
    const SCRIPT_TYPE: [u8; 4] = 0x8000_0002u32.to_le_bytes();
    let mut keys = [[0u8; 33]; 3];
    let mut fingerprints: [[u8; 4]; 3] = [[0; 4]; 3];
    let mut common_coordinates = None;
    for (index, record) in derivations.iter().flatten().enumerate() {
        if record.key_data.len() != 33 || record.value.len() != 28 {
            return Err(FinalizationError::WitnessShapeMismatch);
        }
        let key: [u8; 33] = record
            .key_data
            .try_into()
            .map_err(|_| FinalizationError::WitnessShapeMismatch)?;
        if !matches!(key.first().copied(), Some(0x02 | 0x03)) {
            return Err(FinalizationError::WitnessShapeMismatch);
        }
        let key_slot = keys
            .get_mut(index)
            .ok_or(FinalizationError::InternalInvariant)?;
        *key_slot = key;
        let fingerprint: [u8; 4] = record
            .value
            .get(..4)
            .ok_or(FinalizationError::WitnessShapeMismatch)?
            .try_into()
            .map_err(|_| FinalizationError::WitnessShapeMismatch)?;
        let fp_slot = fingerprints
            .get_mut(index)
            .ok_or(FinalizationError::InternalInvariant)?;
        *fp_slot = fingerprint;
        if record.value.get(4..8) != Some(PURPOSE.as_slice())
            || record.value.get(8..12) != Some(COIN.as_slice())
            || record.value.get(12..16) != Some(ACCOUNT.as_slice())
            || record.value.get(16..20) != Some(SCRIPT_TYPE.as_slice())
        {
            return Err(FinalizationError::WitnessShapeMismatch);
        }
        let branch = u32::from_le_bytes(
            record
                .value
                .get(20..24)
                .ok_or(FinalizationError::WitnessShapeMismatch)?
                .try_into()
                .map_err(|_| FinalizationError::WitnessShapeMismatch)?,
        );
        let child = u32::from_le_bytes(
            record
                .value
                .get(24..28)
                .ok_or(FinalizationError::WitnessShapeMismatch)?
                .try_into()
                .map_err(|_| FinalizationError::WitnessShapeMismatch)?,
        );
        if branch > 1 || child > qk_psbt::limits::MAX_CHILD_INDEX {
            return Err(FinalizationError::WitnessShapeMismatch);
        }
        match common_coordinates {
            None => common_coordinates = Some((branch, child)),
            Some(expected) if expected == (branch, child) => {}
            Some(_) => return Err(FinalizationError::WitnessShapeMismatch),
        }
    }
    if keys[0] >= keys[1]
        || keys[1] >= keys[2]
        || fingerprints[0] == fingerprints[1]
        || fingerprints[0] == fingerprints[2]
        || fingerprints[1] == fingerprints[2]
    {
        return Err(FinalizationError::WitnessShapeMismatch);
    }
    Ok(keys)
}

fn reconstruct_witness_script(keys: &[[u8; 33]; 3]) -> [u8; WITNESS_SCRIPT_BYTES] {
    let mut script = [0u8; WITNESS_SCRIPT_BYTES];
    script[0] = 0x52;
    script[1] = 0x21;
    script[2..35].copy_from_slice(&keys[0]);
    script[35] = 0x21;
    script[36..69].copy_from_slice(&keys[1]);
    script[69] = 0x21;
    script[70..103].copy_from_slice(&keys[2]);
    script[103] = 0x53;
    script[104] = 0xae;
    script
}

fn build_verification_copy(
    view: &PsbtView<'_>,
    bytes: &[u8],
    shapes: &[InputShape],
    source: InputSource,
) -> Result<Vec<u8>, FinalizationError> {
    if shapes.len() != view.input_map_count() {
        return Err(FinalizationError::InternalInvariant);
    }
    let mut copy_len = PSBT_MAGIC_BYTES
        .checked_add(view.global_map_span().len())
        .ok_or(FinalizationError::LengthOverflow)?;
    for (input_index, shape) in shapes.iter().enumerate() {
        let span = view
            .input_map_span(input_index)
            .ok_or(FinalizationError::InternalInvariant)?;
        let mut removed = 0usize;
        let mut record_start = span.start;
        for record in view
            .input_records(input_index)
            .ok_or(FinalizationError::InternalInvariant)?
        {
            let encoded_len = record
                .value_span
                .end
                .checked_sub(record_start)
                .ok_or(FinalizationError::InternalInvariant)?;
            if record.key_type == 0x06 {
                removed = removed
                    .checked_add(encoded_len)
                    .ok_or(FinalizationError::LengthOverflow)?;
            }
            record_start = record.value_span.end;
        }
        if record_start.checked_add(1) != Some(span.end) {
            return Err(FinalizationError::InternalInvariant);
        }
        let inserted = if shape.recorded_witness_script {
            0
        } else {
            1 + 1 + 1 + WITNESS_SCRIPT_BYTES
        };
        copy_len = copy_len
            .checked_add(
                span.len()
                    .checked_sub(removed)
                    .and_then(|value| value.checked_add(inserted))
                    .ok_or(FinalizationError::LengthOverflow)?,
            )
            .ok_or(FinalizationError::LengthOverflow)?;
    }
    for output_index in 0..view.output_map_count() {
        copy_len = copy_len
            .checked_add(
                view.output_map_span(output_index)
                    .ok_or(FinalizationError::InternalInvariant)?
                    .len(),
            )
            .ok_or(FinalizationError::LengthOverflow)?;
    }
    if copy_len > source.max_bytes() {
        return Err(FinalizationError::ArtifactTooLarge);
    }

    let mut copy = Vec::new();
    copy.try_reserve_exact(copy_len)
        .map_err(|_| FinalizationError::AllocationFailed)?;
    append_slice(
        &mut copy,
        bytes
            .get(..PSBT_MAGIC_BYTES)
            .ok_or(FinalizationError::InternalInvariant)?,
    );
    append_span(&mut copy, bytes, view.global_map_span())?;
    for (input_index, shape) in shapes.iter().enumerate() {
        emit_verification_input(&mut copy, view, bytes, input_index, shape)?;
    }
    for output_index in 0..view.output_map_count() {
        append_span(
            &mut copy,
            bytes,
            view.output_map_span(output_index)
                .ok_or(FinalizationError::InternalInvariant)?,
        )?;
    }
    if copy.len() != copy_len {
        return Err(FinalizationError::InternalInvariant);
    }
    let copy_view = parse(&copy, source).map_err(|_| FinalizationError::InternalInvariant)?;
    let canonical = canonical_serialize(&copy_view).map_err(map_serialize_error)?;
    if canonical != copy {
        return Err(FinalizationError::InternalInvariant);
    }
    Ok(copy)
}

fn emit_verification_input(
    output: &mut Vec<u8>,
    view: &PsbtView<'_>,
    bytes: &[u8],
    input_index: usize,
    shape: &InputShape,
) -> Result<(), FinalizationError> {
    let span = view
        .input_map_span(input_index)
        .ok_or(FinalizationError::InternalInvariant)?;
    let mut record_start = span.start;
    let mut inserted = shape.recorded_witness_script;
    for record in view
        .input_records(input_index)
        .ok_or(FinalizationError::InternalInvariant)?
    {
        if !inserted && record.key_type > 0x05 {
            emit_verification_witness_script(output, &shape.witness_script);
            inserted = true;
        }
        if record.key_type != 0x06 {
            append_slice(
                output,
                bytes
                    .get(record_start..record.value_span.end)
                    .ok_or(FinalizationError::InternalInvariant)?,
            );
        }
        record_start = record.value_span.end;
    }
    if !inserted {
        emit_verification_witness_script(output, &shape.witness_script);
    }
    if record_start.checked_add(1) != Some(span.end) || bytes.get(record_start) != Some(&0x00) {
        return Err(FinalizationError::InternalInvariant);
    }
    output.push(0x00);
    Ok(())
}

fn emit_verification_witness_script(output: &mut Vec<u8>, script: &[u8; WITNESS_SCRIPT_BYTES]) {
    output.extend_from_slice(&[0x01, 0x05, 0x69]);
    output.extend_from_slice(script);
}

fn witness_encoded_len(
    first_signature: &[u8],
    second_signature: &[u8],
    script: &[u8],
) -> Result<usize, FinalizationError> {
    1usize
        .checked_add(1)
        .and_then(|value| value.checked_add(compact_size_len(first_signature.len())))
        .and_then(|value| value.checked_add(first_signature.len()))
        .and_then(|value| value.checked_add(compact_size_len(second_signature.len())))
        .and_then(|value| value.checked_add(second_signature.len()))
        .and_then(|value| value.checked_add(compact_size_len(script.len())))
        .and_then(|value| value.checked_add(script.len()))
        .ok_or(FinalizationError::LengthOverflow)
}

fn transform_psbt(
    view: &PsbtView<'_>,
    bytes: &[u8],
    witnesses: &[WitnessParts<'_>],
    source: InputSource,
) -> Result<Vec<u8>, FinalizationError> {
    if witnesses.len() != view.input_map_count() {
        return Err(FinalizationError::InternalInvariant);
    }
    let mut final_len = PSBT_MAGIC_BYTES
        .checked_add(view.global_map_span().len())
        .ok_or(FinalizationError::LengthOverflow)?;
    for (input_index, witness) in witnesses.iter().enumerate() {
        let span = view
            .input_map_span(input_index)
            .ok_or(FinalizationError::InternalInvariant)?;
        let mut removed = 0usize;
        let mut record_start = span.start;
        for record in view
            .input_records(input_index)
            .ok_or(FinalizationError::InternalInvariant)?
        {
            let encoded_len = record
                .value_span
                .end
                .checked_sub(record_start)
                .ok_or(FinalizationError::InternalInvariant)?;
            if (0x02..=0x06).contains(&record.key_type) {
                removed = removed
                    .checked_add(encoded_len)
                    .ok_or(FinalizationError::LengthOverflow)?;
            }
            record_start = record.value_span.end;
        }
        if record_start.checked_add(1) != Some(span.end) {
            return Err(FinalizationError::InternalInvariant);
        }
        let final_record_len = final_witness_record_len(witness.encoded_len)?;
        let map_len = span
            .len()
            .checked_sub(removed)
            .and_then(|value| value.checked_add(final_record_len))
            .ok_or(FinalizationError::LengthOverflow)?;
        final_len = final_len
            .checked_add(map_len)
            .ok_or(FinalizationError::LengthOverflow)?;
    }
    for output_index in 0..view.output_map_count() {
        final_len = final_len
            .checked_add(
                view.output_map_span(output_index)
                    .ok_or(FinalizationError::InternalInvariant)?
                    .len(),
            )
            .ok_or(FinalizationError::LengthOverflow)?;
    }
    let minimum_shrink = view
        .input_map_count()
        .checked_mul(MIN_FINALIZED_PSBT_SHRINK_PER_INPUT)
        .ok_or(FinalizationError::LengthOverflow)?;
    let largest_allowed = bytes
        .len()
        .checked_sub(minimum_shrink)
        .ok_or(FinalizationError::ForbiddenDelta)?;
    if final_len > largest_allowed {
        return Err(FinalizationError::ForbiddenDelta);
    }
    if final_len > source.max_bytes() {
        return Err(FinalizationError::ArtifactTooLarge);
    }

    let mut finalized = Vec::new();
    finalized
        .try_reserve_exact(final_len)
        .map_err(|_| FinalizationError::AllocationFailed)?;
    append_slice(
        &mut finalized,
        bytes
            .get(..PSBT_MAGIC_BYTES)
            .ok_or(FinalizationError::InternalInvariant)?,
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
                .ok_or(FinalizationError::InternalInvariant)?,
        )?;
    }
    if finalized.len() != final_len {
        return Err(FinalizationError::InternalInvariant);
    }
    Ok(finalized)
}

fn emit_finalized_input(
    output: &mut Vec<u8>,
    view: &PsbtView<'_>,
    bytes: &[u8],
    input_index: usize,
    witness: &WitnessParts<'_>,
) -> Result<(), FinalizationError> {
    let span = view
        .input_map_span(input_index)
        .ok_or(FinalizationError::InternalInvariant)?;
    let mut record_start = span.start;
    let mut emitted_final = false;
    for record in view
        .input_records(input_index)
        .ok_or(FinalizationError::InternalInvariant)?
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
                    .ok_or(FinalizationError::InternalInvariant)?,
            );
        }
        record_start = record.value_span.end;
    }
    if !emitted_final {
        emit_final_witness_record(output, witness)?;
    }
    if record_start.checked_add(1) != Some(span.end) || bytes.get(record_start) != Some(&0x00) {
        return Err(FinalizationError::InternalInvariant);
    }
    output.push(0x00);
    Ok(())
}

fn final_witness_record_len(witness_len: usize) -> Result<usize, FinalizationError> {
    2usize
        .checked_add(compact_size_len(witness_len))
        .and_then(|value| value.checked_add(witness_len))
        .ok_or(FinalizationError::LengthOverflow)
}

fn emit_final_witness_record(
    output: &mut Vec<u8>,
    witness: &WitnessParts<'_>,
) -> Result<(), FinalizationError> {
    output.extend_from_slice(&[0x01, 0x08]);
    write_compact_size(output, witness.encoded_len)?;
    emit_witness(output, witness)?;
    Ok(())
}

fn emit_witness(output: &mut Vec<u8>, witness: &WitnessParts<'_>) -> Result<(), FinalizationError> {
    let before = output.len();
    output.extend_from_slice(&[0x04, 0x00]);
    write_compact_size(output, witness.first_signature.len())?;
    append_slice(output, witness.first_signature);
    write_compact_size(output, witness.second_signature.len())?;
    append_slice(output, witness.second_signature);
    write_compact_size(output, witness.witness_script.len())?;
    append_slice(output, &witness.witness_script);
    if output.len().checked_sub(before) != Some(witness.encoded_len) {
        return Err(FinalizationError::InternalInvariant);
    }
    Ok(())
}

fn allowed_finalized_delta(
    before: &PsbtView<'_>,
    after: &PsbtView<'_>,
    witnesses: &[WitnessParts<'_>],
) -> Result<bool, FinalizationError> {
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
        let before_records = match before.input_records(input_index) {
            Some(records) => records,
            None => return Ok(false),
        };
        let mut preserved = before_records.filter(|record| {
            !(0x02..=0x06).contains(&record.key_type)
                && record.key_type != 0x07
                && record.key_type != 0x08
        });
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
                    .map_err(|_| FinalizationError::AllocationFailed)?;
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
) -> Result<Vec<u8>, FinalizationError> {
    if base.len() > MAX_UNSIGNED_TRANSACTION_BYTES || base.len() < 8 {
        return Err(FinalizationError::ArtifactTooLarge);
    }
    let witness_total = witnesses.iter().try_fold(0usize, |total, witness| {
        total
            .checked_add(witness.encoded_len)
            .ok_or(FinalizationError::LengthOverflow)
    })?;
    let raw_len = base
        .len()
        .checked_add(2)
        .and_then(|value| value.checked_add(witness_total))
        .ok_or(FinalizationError::LengthOverflow)?;
    if raw_len > MAX_RAW_TRANSACTION_BYTES {
        return Err(FinalizationError::ArtifactTooLarge);
    }
    let locktime_start = base
        .len()
        .checked_sub(4)
        .ok_or(FinalizationError::InternalInvariant)?;
    let mut raw = Vec::new();
    raw.try_reserve_exact(raw_len)
        .map_err(|_| FinalizationError::AllocationFailed)?;
    append_slice(
        &mut raw,
        base.get(..4).ok_or(FinalizationError::InternalInvariant)?,
    );
    raw.extend_from_slice(&[0x00, 0x01]);
    append_slice(
        &mut raw,
        base.get(4..locktime_start)
            .ok_or(FinalizationError::InternalInvariant)?,
    );
    for witness in witnesses {
        emit_witness(&mut raw, witness)?;
    }
    append_slice(
        &mut raw,
        base.get(locktime_start..)
            .ok_or(FinalizationError::InternalInvariant)?,
    );
    if raw.len() != raw_len {
        return Err(FinalizationError::InternalInvariant);
    }
    Ok(raw)
}

#[derive(Clone, Copy)]
struct ParsedRawWitness<'a> {
    encoded: &'a [u8],
    item_count: u64,
    items: [Option<&'a [u8]>; 4],
}

/// Exact signature/script items obtained by an M24-only fresh parse of a
/// finalized raw transaction. The empty dummy and four-item shape have
/// already been checked, and every slice borrows the final raw bytes.
pub(super) struct FreshFinalWitness<'a> {
    pub(super) first_signature: &'a [u8],
    pub(super) second_signature: &'a [u8],
    pub(super) witness_script: &'a [u8],
}

fn parse_and_rebind_raw<'a>(
    raw: &'a [u8],
    base: &[u8],
    finalized_view: &PsbtView<'_>,
) -> Result<Vec<ParsedRawWitness<'a>>, FinalizationError> {
    let mut cursor = RawCursor::new(raw);
    let mut stripped = Vec::new();
    stripped
        .try_reserve_exact(base.len())
        .map_err(|_| FinalizationError::AllocationFailed)?;
    append_slice(&mut stripped, cursor.take(4)?);
    if cursor.take(2)? != [0x00, 0x01].as_slice() {
        return Err(FinalizationError::RawTransactionReparse);
    }
    let (input_count, input_count_bytes) = cursor.compact_size()?;
    let input_count =
        usize::try_from(input_count).map_err(|_| FinalizationError::RawTransactionReparse)?;
    if input_count == 0 || input_count != finalized_view.input_map_count() {
        return Err(FinalizationError::RawTransactionReparse);
    }
    append_slice(&mut stripped, input_count_bytes);
    for _ in 0..input_count {
        append_slice(&mut stripped, cursor.take(36)?);
        let (script_len, script_len_bytes) = cursor.compact_size()?;
        if script_len != 0 {
            return Err(FinalizationError::RawTransactionReparse);
        }
        append_slice(&mut stripped, script_len_bytes);
        append_slice(&mut stripped, cursor.take(4)?);
    }
    let (output_count, output_count_bytes) = cursor.compact_size()?;
    let output_count =
        usize::try_from(output_count).map_err(|_| FinalizationError::RawTransactionReparse)?;
    if output_count == 0 || output_count != finalized_view.output_map_count() {
        return Err(FinalizationError::RawTransactionReparse);
    }
    append_slice(&mut stripped, output_count_bytes);
    for _ in 0..output_count {
        append_slice(&mut stripped, cursor.take(8)?);
        let (script_len, script_len_bytes) = cursor.compact_size()?;
        let script_len =
            usize::try_from(script_len).map_err(|_| FinalizationError::RawTransactionReparse)?;
        append_slice(&mut stripped, script_len_bytes);
        append_slice(&mut stripped, cursor.take(script_len)?);
    }

    let mut parsed_witnesses = Vec::new();
    parsed_witnesses
        .try_reserve_exact(input_count)
        .map_err(|_| FinalizationError::AllocationFailed)?;
    for _ in 0..input_count {
        let witness_start = cursor.position();
        let (item_count, _) = cursor.compact_size()?;
        let mut parsed_items: [Option<&[u8]>; 4] = [None, None, None, None];
        let mut item_index = 0u64;
        while item_index < item_count {
            let (item_len, _) = cursor.compact_size()?;
            let item_len =
                usize::try_from(item_len).map_err(|_| FinalizationError::RawTransactionReparse)?;
            let item = cursor.take(item_len)?;
            if item_index < 4 {
                let index = usize::try_from(item_index)
                    .map_err(|_| FinalizationError::RawTransactionReparse)?;
                let slot = parsed_items
                    .get_mut(index)
                    .ok_or(FinalizationError::InternalInvariant)?;
                *slot = Some(item);
            }
            item_index = item_index
                .checked_add(1)
                .ok_or(FinalizationError::RawTransactionReparse)?;
        }
        let witness_end = cursor.position();
        let encoded = raw
            .get(witness_start..witness_end)
            .ok_or(FinalizationError::RawTransactionReparse)?;
        parsed_witnesses.push(ParsedRawWitness {
            encoded,
            item_count,
            items: parsed_items,
        });
    }
    append_slice(&mut stripped, cursor.take(4)?);
    if !cursor.at_end() {
        return Err(FinalizationError::RawTransactionReparse);
    }
    if stripped != base {
        return Err(FinalizationError::BaseTransactionMismatch);
    }

    Ok(parsed_witnesses)
}

fn rebind_final_witness_records(
    parsed_witnesses: &[ParsedRawWitness<'_>],
    finalized_view: &PsbtView<'_>,
) -> Result<(), FinalizationError> {
    if parsed_witnesses.len() != finalized_view.input_map_count() {
        return Err(FinalizationError::InternalInvariant);
    }
    for (input_index, parsed) in parsed_witnesses.iter().enumerate() {
        let final_witness = finalized_view
            .input_records(input_index)
            .ok_or(FinalizationError::InternalInvariant)?
            .find(|record| record.key_type == 0x08)
            .ok_or(FinalizationError::WitnessMismatch)?;
        if parsed.encoded != final_witness.value {
            return Err(FinalizationError::WitnessMismatch);
        }
    }
    Ok(())
}

fn reparse_and_rebind_raw(
    raw: &[u8],
    base: &[u8],
    finalized_view: &PsbtView<'_>,
    witnesses: &[WitnessParts<'_>],
) -> Result<(), FinalizationError> {
    if witnesses.len() != finalized_view.input_map_count() {
        return Err(FinalizationError::InternalInvariant);
    }
    let parsed_witnesses = parse_and_rebind_raw(raw, base, finalized_view)?;
    if parsed_witnesses.len() != witnesses.len() {
        return Err(FinalizationError::InternalInvariant);
    }
    for (parsed, expected) in parsed_witnesses.iter().zip(witnesses) {
        let empty_dummy = matches!(parsed.items[0], Some(dummy) if dummy.is_empty());
        if parsed.item_count != 4 || !empty_dummy {
            return Err(FinalizationError::WitnessMismatch);
        }
        let first = parsed.items[1].ok_or(FinalizationError::WitnessMismatch)?;
        let second = parsed.items[2].ok_or(FinalizationError::WitnessMismatch)?;
        let script = parsed.items[3].ok_or(FinalizationError::WitnessMismatch)?;
        if first == expected.second_signature && second == expected.first_signature {
            return Err(FinalizationError::WitnessOrderMismatch);
        }
        if first != expected.first_signature
            || second != expected.second_signature
            || script != expected.witness_script.as_slice()
        {
            return Err(FinalizationError::WitnessMismatch);
        }
    }
    rebind_final_witness_records(&parsed_witnesses, finalized_view)
}

/// Reparse a completed M24 result from byte zero through EOF and return only
/// its two selected signatures and exact witness script per input. This is a
/// second parse after M16 finalization, not a reuse of M16's parser result.
pub(super) fn fresh_final_witnesses<'a>(
    finalized: &'a FinalizedTransaction,
    source: InputSource,
    base: &[u8],
) -> Result<Vec<FreshFinalWitness<'a>>, FinalizationError> {
    let view = parse(finalized.finalized_psbt(), source)
        .map_err(|_| FinalizationError::FinalizedPsbtReparse)?;
    let parsed = parse_and_rebind_raw(finalized.raw_transaction(), base, &view)?;
    rebind_final_witness_records(&parsed, &view)?;
    let mut witnesses = Vec::new();
    witnesses
        .try_reserve_exact(parsed.len())
        .map_err(|_| FinalizationError::AllocationFailed)?;
    for witness in parsed {
        let empty_dummy = matches!(witness.items[0], Some(dummy) if dummy.is_empty());
        if witness.item_count != 4 || !empty_dummy {
            return Err(FinalizationError::WitnessMismatch);
        }
        witnesses.push(FreshFinalWitness {
            first_signature: witness.items[1].ok_or(FinalizationError::WitnessMismatch)?,
            second_signature: witness.items[2].ok_or(FinalizationError::WitnessMismatch)?,
            witness_script: witness.items[3].ok_or(FinalizationError::WitnessMismatch)?,
        });
    }
    Ok(witnesses)
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

    fn take(&mut self, count: usize) -> Result<&'a [u8], FinalizationError> {
        let end = self
            .position
            .checked_add(count)
            .ok_or(FinalizationError::RawTransactionReparse)?;
        let value = self
            .bytes
            .get(self.position..end)
            .ok_or(FinalizationError::RawTransactionReparse)?;
        self.position = end;
        Ok(value)
    }

    fn compact_size(&mut self) -> Result<(u64, &'a [u8]), FinalizationError> {
        let start = self.position;
        let first = *self
            .take(1)?
            .first()
            .ok_or(FinalizationError::RawTransactionReparse)?;
        let value = match first {
            0xfd => {
                let bytes: [u8; 2] = self
                    .take(2)?
                    .try_into()
                    .map_err(|_| FinalizationError::RawTransactionReparse)?;
                let value = u64::from(u16::from_le_bytes(bytes));
                if value < 0xfd {
                    return Err(FinalizationError::RawTransactionReparse);
                }
                value
            }
            0xfe => {
                let bytes: [u8; 4] = self
                    .take(4)?
                    .try_into()
                    .map_err(|_| FinalizationError::RawTransactionReparse)?;
                let value = u64::from(u32::from_le_bytes(bytes));
                if value <= 0xffff {
                    return Err(FinalizationError::RawTransactionReparse);
                }
                value
            }
            0xff => {
                let bytes: [u8; 8] = self
                    .take(8)?
                    .try_into()
                    .map_err(|_| FinalizationError::RawTransactionReparse)?;
                let value = u64::from_le_bytes(bytes);
                if value <= 0xffff_ffff {
                    return Err(FinalizationError::RawTransactionReparse);
                }
                value
            }
            value => u64::from(value),
        };
        let encoded = self
            .bytes
            .get(start..self.position)
            .ok_or(FinalizationError::RawTransactionReparse)?;
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

fn write_compact_size(output: &mut Vec<u8>, value: usize) -> Result<(), FinalizationError> {
    let value = u64::try_from(value).map_err(|_| FinalizationError::LengthOverflow)?;
    if value < 0xfd {
        output.push(u8::try_from(value).map_err(|_| FinalizationError::InternalInvariant)?);
    } else if value <= 0xffff {
        output.push(0xfd);
        output.extend_from_slice(
            &u16::try_from(value)
                .map_err(|_| FinalizationError::InternalInvariant)?
                .to_le_bytes(),
        );
    } else if value <= 0xffff_ffff {
        output.push(0xfe);
        output.extend_from_slice(
            &u32::try_from(value)
                .map_err(|_| FinalizationError::InternalInvariant)?
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
) -> Result<(), FinalizationError> {
    append_slice(
        output,
        span.slice(source)
            .ok_or(FinalizationError::InternalInvariant)?,
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
    fn m16_cap_arithmetic_is_exact() {
        assert_eq!(MAX_WITNESS_BYTES_PER_INPUT, 254);
        assert_eq!(MAX_FINAL_WITNESS_RECORD_BYTES, 259);
        assert_eq!(MAX_RAW_TRANSACTION_BYTES, 30_937);
        assert_eq!(MIN_FINALIZED_PSBT_SHRINK_PER_INPUT, 149);
        assert_eq!(
            1 + 1 + 2 * (1 + DER_PLUS_SIGHASH_MAX_BYTES) + 1 + WITNESS_SCRIPT_BYTES,
            MAX_WITNESS_BYTES_PER_INPUT
        );
        assert_eq!(
            MAX_UNSIGNED_TRANSACTION_BYTES + 2 + 100 * MAX_WITNESS_BYTES_PER_INPUT,
            MAX_RAW_TRANSACTION_BYTES
        );
        assert_eq!(
            1 + 1 + 3 + MAX_WITNESS_BYTES_PER_INPUT,
            MAX_FINAL_WITNESS_RECORD_BYTES
        );
        assert_eq!(
            3 * DERIVATION_RECORD_BYTES + 2 * PARTIAL_SIGNATURE_RECORD_FRAME_BYTES
                - (2 + 3 + FINAL_WITNESS_PAYLOAD_FRAME_BYTES),
            MIN_FINALIZED_PSBT_SHRINK_PER_INPUT
        );
    }

    #[test]
    fn compact_size_writer_and_parser_cover_all_widths_and_reject_nonminimal() {
        let max_u32 = usize::try_from(u32::MAX).expect("u32 fits usize on HOST");
        let first_u64 = usize::try_from(u64::from(u32::MAX) + 1).ok();
        for value in [
            Some(0usize),
            Some(252),
            Some(253),
            Some(65_535),
            Some(65_536),
            Some(max_u32),
            first_u64,
        ]
        .into_iter()
        .flatten()
        {
            let mut encoded = Vec::new();
            write_compact_size(&mut encoded, value).expect("encode");
            assert_eq!(encoded.len(), compact_size_len(value));
            let mut cursor = RawCursor::new(&encoded);
            let (decoded, original) = cursor.compact_size().expect("decode");
            assert_eq!(decoded, value as u64);
            assert_eq!(original, encoded.as_slice());
            assert!(cursor.at_end());
        }
        let first_u64_encoded = [0xff, 0, 0, 0, 0, 1, 0, 0, 0];
        let mut first_u64_cursor = RawCursor::new(&first_u64_encoded);
        assert_eq!(
            first_u64_cursor.compact_size(),
            Ok((u64::from(u32::MAX) + 1, first_u64_encoded.as_slice()))
        );
        assert!(first_u64_cursor.at_end());
        for nonminimal in [
            &[0xfd, 0xfc, 0x00][..],
            &[0xfe, 0xff, 0xff, 0x00, 0x00],
            &[0xff, 0xff, 0xff, 0xff, 0xff, 0, 0, 0, 0],
        ] {
            assert_eq!(
                RawCursor::new(nonminimal).compact_size().err(),
                Some(FinalizationError::RawTransactionReparse)
            );
        }
    }

    #[test]
    fn exact_sorted_script_shape_rejects_duplicates_and_unsorted_keys() {
        let mut script = Vec::new();
        script.push(0x52);
        for suffix in [1u8, 2, 3] {
            script.push(0x21);
            script.push(0x02);
            script.extend_from_slice(&[0; 31]);
            script.push(suffix);
        }
        script.extend_from_slice(&[0x53, 0xae]);
        assert!(script_keys(&script).is_ok());

        let mut duplicate = script.clone();
        let first = duplicate[2..35].to_vec();
        duplicate[36..69].copy_from_slice(&first);
        assert_eq!(
            script_keys(&duplicate).err(),
            Some(FinalizationError::WitnessShapeMismatch)
        );

        let mut unsorted = script;
        let first = unsorted[2..35].to_vec();
        let third = unsorted[70..103].to_vec();
        unsorted[2..35].copy_from_slice(&third);
        unsorted[70..103].copy_from_slice(&first);
        assert_eq!(
            script_keys(&unsorted).err(),
            Some(FinalizationError::WitnessShapeMismatch)
        );
    }

    #[test]
    fn raw_reparse_requires_exact_base_witness_order_and_eof() {
        let first_signature = [0x11];
        let second_signature = [0x22];
        let witness = WitnessParts {
            first_signature: &first_signature,
            second_signature: &second_signature,
            witness_script: [0x51; WITNESS_SCRIPT_BYTES],
            encoded_len: 112,
        };
        assert_eq!(
            witness_encoded_len(
                witness.first_signature,
                witness.second_signature,
                &witness.witness_script
            ),
            Ok(witness.encoded_len)
        );

        let mut base = Vec::new();
        base.extend_from_slice(&1u32.to_le_bytes());
        base.push(1);
        base.extend_from_slice(&[0; 32]);
        base.extend_from_slice(&0u32.to_le_bytes());
        base.push(0);
        base.extend_from_slice(&u32::MAX.to_le_bytes());
        base.push(1);
        base.extend_from_slice(&0u64.to_le_bytes());
        base.push(0);
        base.extend_from_slice(&0u32.to_le_bytes());
        assert_eq!(base.len(), 60);

        let mut psbt = b"psbt\xff".to_vec();
        psbt.extend_from_slice(&[1, 0]);
        write_compact_size(&mut psbt, base.len()).expect("base length");
        psbt.extend_from_slice(&base);
        psbt.push(0);
        psbt.extend_from_slice(&[1, 8]);
        write_compact_size(&mut psbt, witness.encoded_len).expect("witness length");
        emit_witness(&mut psbt, &witness).expect("witness");
        psbt.extend_from_slice(&[0, 0]);
        let finalized_view = parse(&psbt, InputSource::MicroSd).expect("finalized PSBT");
        let raw = extract_raw_transaction(&base, &[witness]).expect("raw transaction");
        assert_eq!(
            reparse_and_rebind_raw(&raw, &base, &finalized_view, &[witness]),
            Ok(())
        );

        let mut trailing = raw.clone();
        trailing.push(0);
        assert_eq!(
            reparse_and_rebind_raw(&trailing, &base, &finalized_view, &[witness]),
            Err(FinalizationError::RawTransactionReparse)
        );

        let mut swapped = raw.clone();
        let witness_start = 58;
        swapped[witness_start + 3] = second_signature[0];
        swapped[witness_start + 5] = first_signature[0];
        assert_eq!(
            reparse_and_rebind_raw(&swapped, &base, &finalized_view, &[witness]),
            Err(FinalizationError::WitnessOrderMismatch)
        );

        let mut mismatched_base_for_swapped = base.clone();
        *mismatched_base_for_swapped
            .last_mut()
            .expect("locktime byte") = 1;
        assert_eq!(
            reparse_and_rebind_raw(
                &swapped,
                &mismatched_base_for_swapped,
                &finalized_view,
                &[witness]
            ),
            Err(FinalizationError::BaseTransactionMismatch)
        );

        let mut swapped_with_trailing = swapped;
        swapped_with_trailing.push(0);
        assert_eq!(
            reparse_and_rebind_raw(&swapped_with_trailing, &base, &finalized_view, &[witness]),
            Err(FinalizationError::RawTransactionReparse)
        );

        let mut other_base = base;
        *other_base.last_mut().expect("locktime byte") = 1;
        assert_eq!(
            reparse_and_rebind_raw(&raw, &other_base, &finalized_view, &[witness]),
            Err(FinalizationError::BaseTransactionMismatch)
        );
    }
}
