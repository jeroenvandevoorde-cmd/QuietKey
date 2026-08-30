//! Canonical structural serializer for an already-parsed PSBT v0 view.
//!
//! HOST SCAFFOLD ONLY — NOT PRODUCT CODE — NOT A WALLET — NO TARGET CLAIM.
//!
//! Implements exactly the ratified M5 normalization (QK-DEC-036):
//! within each map, records are reordered by ascending decoded numeric
//! key type and then by raw key data lexicographically, and the outer
//! key-length and value-length prefixes are re-encoded as minimal
//! CompactSize. Every record's complete key bytes and value bytes are
//! copied verbatim (the key-type CompactSize inside the complete key
//! was already proven minimal by the parser), no record is added,
//! dropped, or rewritten, map order and map count are preserved, and
//! one 0x00 separator terminates each map. Unknown, proprietary, and
//! SIGHASH records pass through unchanged; S9 redundant-SIGHASH_ALL
//! stripping is deferred to the future semantic emit layer and does
//! not exist here. Because the parser already enforces minimal
//! CompactSize encodings, canonical output length always equals input
//! length; any other outcome is reported as an invariant violation.
//!
//! There is no raw-input serialization API: the only entry point
//! consumes a `PsbtView` produced by [`crate::parse`]. Allocation is a
//! single exact reservation of the input length; per-map sorting uses
//! one fixed stack scratch array of `MAX_RECORDS_PER_MAP` slots, and
//! every append is budget-checked so the output vector never grows
//! beyond the reservation.

use crate::limits::MAX_RECORDS_PER_MAP;
use crate::parse::PsbtView;
use crate::raw::{Record, Records};
use crate::wipe;
use core::cmp::Ordering;

/// Number of magic-prefix bytes (`psbt` + 0xff) copied verbatim.
const MAGIC_LEN: usize = 5;

/// Serialization failure. Carries no record bytes or offsets.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SerializeError {
    /// The single exact output reservation could not be satisfied.
    AllocationFailed,
    /// A structural invariant guaranteed by the parser did not hold
    /// during serialization (never expected for a genuine `PsbtView`).
    InvariantViolation,
}

/// Perform the single allocation: an empty vector with exactly the
/// output budget reserved. Reservation failure is reported as a clean
/// [`SerializeError::AllocationFailed`].
fn reserve_exact_output(budget: usize) -> Result<wipe::WipingByteVec, SerializeError> {
    let mut bytes = wipe::WipingByteVec::new();
    bytes
        .try_reserve_exact(budget)
        .map_err(|_| SerializeError::AllocationFailed)?;
    Ok(bytes)
}

/// Output vector wrapper that refuses any append past the input-length
/// budget, so the pre-reserved vector can never reallocate.
struct BudgetedOutput {
    bytes: wipe::WipingByteVec,
    budget: usize,
}

impl BudgetedOutput {
    fn append(&mut self, chunk: &[u8]) -> Result<(), SerializeError> {
        let new_len = self
            .bytes
            .len()
            .checked_add(chunk.len())
            .ok_or(SerializeError::InvariantViolation)?;
        if new_len > self.budget {
            return Err(SerializeError::InvariantViolation);
        }
        self.bytes.extend_from_slice(chunk);
        Ok(())
    }
}

/// Minimal CompactSize encoding into a fixed stack buffer; returns the
/// buffer and the number of significant bytes.
fn encode_compact_size(value: u64) -> (wipe::ByteArray<9>, usize) {
    let encoded = wipe::ByteArray::new(value.to_le_bytes());
    let [b0, b1, b2, b3, b4, b5, b6, b7] = *encoded.as_array();
    if value < 0xfd {
        (wipe::ByteArray::new([b0, 0, 0, 0, 0, 0, 0, 0, 0]), 1)
    } else if value <= 0xffff {
        (wipe::ByteArray::new([0xfd, b0, b1, 0, 0, 0, 0, 0, 0]), 3)
    } else if value <= 0xffff_ffff {
        (wipe::ByteArray::new([0xfe, b0, b1, b2, b3, 0, 0, 0, 0]), 5)
    } else {
        (
            wipe::ByteArray::new([0xff, b0, b1, b2, b3, b4, b5, b6, b7]),
            9,
        )
    }
}

/// Canonical record order: ascending decoded numeric key type, then
/// raw key data lexicographically (QK-DEC-036). Empty slots never
/// appear in the sorted range; ordering them first is inert.
fn record_order(a: &Option<Record<'_>>, b: &Option<Record<'_>>) -> Ordering {
    match (a, b) {
        (Some(x), Some(y)) => x
            .key_type
            .cmp(&y.key_type)
            .then_with(|| x.key_data.cmp(y.key_data)),
        (None, Some(_)) => Ordering::Less,
        (Some(_), None) => Ordering::Greater,
        (None, None) => Ordering::Equal,
    }
}

/// Emit one record: minimal CompactSize key length, complete key bytes
/// verbatim, minimal CompactSize value length, value bytes verbatim.
fn emit_record(record: &Record<'_>, out: &mut BudgetedOutput) -> Result<(), SerializeError> {
    let key_len =
        u64::try_from(record.full_key.len()).map_err(|_| SerializeError::InvariantViolation)?;
    let (key_cs, key_cs_len) = encode_compact_size(key_len);
    out.append(
        key_cs
            .as_array()
            .get(..key_cs_len)
            .ok_or(SerializeError::InvariantViolation)?,
    )?;
    out.append(record.full_key)?;
    let value_len =
        u64::try_from(record.value.len()).map_err(|_| SerializeError::InvariantViolation)?;
    let (value_cs, value_cs_len) = encode_compact_size(value_len);
    out.append(
        value_cs
            .as_array()
            .get(..value_cs_len)
            .ok_or(SerializeError::InvariantViolation)?,
    )?;
    out.append(record.value)
}

/// Serialize one map: collect its records into the shared stack
/// scratch, sort the initialized slice canonically, emit each record,
/// then the 0x00 separator.
fn serialize_map<'a>(
    records: Records<'a>,
    scratch: &mut [Option<Record<'a>>; MAX_RECORDS_PER_MAP],
    out: &mut BudgetedOutput,
) -> Result<(), SerializeError> {
    let mut count: usize = 0;
    for record in records {
        let slot = scratch
            .get_mut(count)
            .ok_or(SerializeError::InvariantViolation)?;
        *slot = Some(record);
        count = count
            .checked_add(1)
            .ok_or(SerializeError::InvariantViolation)?;
    }
    let filled = scratch
        .get_mut(..count)
        .ok_or(SerializeError::InvariantViolation)?;
    filled.sort_unstable_by(record_order);
    for slot in filled.iter() {
        let record = slot.as_ref().ok_or(SerializeError::InvariantViolation)?;
        emit_record(record, out)?;
    }
    out.append(&[0x00])
}

/// Serialize an already-parsed view into its canonical structural
/// form (QK-DEC-036). The output is always exactly as long as the
/// parsed input buffer; any deviation is an invariant violation.
pub fn canonical_serialize(view: &PsbtView<'_>) -> Result<Vec<u8>, SerializeError> {
    let input = view.buffer();
    let budget = input.len();
    let bytes = reserve_exact_output(budget)?;
    let mut out = BudgetedOutput { bytes, budget };
    let magic = input
        .get(..MAGIC_LEN)
        .ok_or(SerializeError::InvariantViolation)?;
    out.append(magic)?;
    let mut scratch = wipe::WipingValueArray::new([None; MAX_RECORDS_PER_MAP]);
    serialize_map(view.global_records(), scratch.as_mut_array(), &mut out)?;
    for index in 0..view.input_map_count() {
        let records = view
            .input_records(index)
            .ok_or(SerializeError::InvariantViolation)?;
        serialize_map(records, scratch.as_mut_array(), &mut out)?;
    }
    for index in 0..view.output_map_count() {
        let records = view
            .output_records(index)
            .ok_or(SerializeError::InvariantViolation)?;
        serialize_map(records, scratch.as_mut_array(), &mut out)?;
    }
    if out.bytes.len() != budget {
        return Err(SerializeError::InvariantViolation);
    }
    Ok(out.bytes.into_vec())
}

#[cfg(test)]
#[allow(clippy::panic, clippy::unwrap_used)]
mod tests {
    use super::{reserve_exact_output, BudgetedOutput, SerializeError};
    use crate::wipe::{reset_wiped_bytes, wiped_bytes};

    /// A `usize::MAX` reservation can never be satisfied; the helper
    /// must surface a clean `AllocationFailed` instead of aborting.
    #[test]
    fn impossible_reservation_reports_allocation_failed() {
        assert!(matches!(
            reserve_exact_output(usize::MAX),
            Err(SerializeError::AllocationFailed)
        ));
    }

    #[test]
    fn rejected_append_clears_the_complete_output_capacity() {
        let bytes = reserve_exact_output(64).unwrap();
        let mut out = BudgetedOutput { bytes, budget: 7 };
        out.append(&[0xa5; 7]).unwrap();
        let capacity = out.bytes.capacity();
        reset_wiped_bytes();
        assert!(matches!(
            out.append(&[0x5a]),
            Err(SerializeError::InvariantViolation)
        ));
        drop(out);
        assert_eq!(wiped_bytes(), capacity);
    }

    #[test]
    fn output_guard_clears_the_complete_capacity_on_unwind() {
        let bytes = reserve_exact_output(48).unwrap();
        let capacity = bytes.capacity();
        let mut out = BudgetedOutput { bytes, budget: 48 };
        out.append(&[0xa5; 11]).unwrap();
        reset_wiped_bytes();
        let caught = std::panic::catch_unwind(|| {
            let _out = out;
            std::panic::panic_any("cleanup probe");
        });
        assert!(caught.is_err());
        assert_eq!(wiped_bytes(), capacity);
    }
}
