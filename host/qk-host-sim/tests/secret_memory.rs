//! QK-DEC-137 host-simulator cleanup-owner and stable-surface pins.

const INSERTION: &str = include_str!("../src/insertion.rs");
const WIPE: &str = include_str!("../src/transaction_wipe_v2.rs");

#[test]
fn insertion_public_surface_and_released_artifact_stay_unchanged() {
    assert!(INSERTION.contains("pub struct SubmittedSignature<'a>"));
    assert!(INSERTION.contains("pub fn insert_and_emit_signatures("));
    assert!(INSERTION.contains(") -> Result<ThresholdCompletePsbt, SignatureInsertionError>"));
    assert!(INSERTION.contains("pub fn as_bytes(&self) -> &[u8]"));
    assert!(INSERTION.contains("pub fn into_bytes(self) -> Vec<u8>"));
    assert!(INSERTION.contains("pub(super) bytes: Vec<u8>"));
    assert!(INSERTION.contains(") -> Result<(Vec<u8>, usize, usize), SignatureInsertionError>"));
}

#[test]
fn every_insertion_scratch_class_uses_the_existing_owner_boundary() {
    assert!(INSERTION.contains("public_keys: [WipingArray<33>; 3]"));
    assert!(INSERTION.contains("inputs: WipingValueVec<(u32, VerifiedInputStatus)>"));
    assert!(INSERTION.contains("Result<WipingValueVec<InputSlots>, SignatureInsertionError>"));
    assert!(INSERTION
        .contains("Result<WipingValueVec<NormalizedSignature<'a>>, SignatureInsertionError>"));
    assert!(INSERTION.contains("let mut request_counts = WipingValueVec::new();"));
    assert!(INSERTION.contains("let mut current = WipingVec::take("));
    assert!(INSERTION.contains("core::mem::replace(&mut current, WipingVec::take(Vec::new()))"));
    assert!(INSERTION.contains("let next = WipingVec::take(next);"));
    assert_eq!(
        INSERTION
            .matches("let canonical = WipingVec::take(")
            .count(),
        1
    );
    assert_eq!(
        INSERTION
            .matches("let final_canonical = WipingVec::take(")
            .count(),
        1
    );
    assert!(INSERTION.contains("let mut next = WipingVec::take(Vec::new());"));
    assert!(INSERTION.contains("bytes: current.into_vec(),"));
}

#[test]
fn key_material_has_one_slot_owner_and_no_normalized_copy() {
    let normalized = INSERTION
        .split_once("struct NormalizedSignature<'a> {")
        .expect("normalized declaration")
        .1
        .split_once("}\n")
        .expect("normalized body")
        .0;
    assert!(!normalized.contains("public_key"));
    assert!(
        INSERTION.contains("let public_key = slots\n                .get(signature.input_index)")
    );
    assert!(INSERTION.contains("public_key.as_slice(),"));
}

#[test]
fn generic_value_owner_has_no_escape_and_reuses_the_existing_unsafe_module() {
    let owner = WIPE
        .split_once("pub(crate) struct WipingValueVec<T> {")
        .expect("value owner declaration")
        .1
        .split_once("#[cfg(test)]\nuse core::cell::Cell;")
        .expect("value owner implementation")
        .0;
    assert!(owner.contains("self.values.clear();"));
    assert!(!owner.contains(".pop()"));
    assert!(owner.contains("wipe_empty_value_allocation(&mut self.values);"));
    assert!(owner.contains("type Target = [T];"));
    assert!(!owner.contains("DerefMut for WipingValueVec"));
    assert!(!owner.contains("into_vec"));
    assert!(!owner.contains("Clone"));
    assert_eq!(WIPE.matches("unsafe {").count(), 3);
    assert!(WIPE.contains("impl Drop for crate::transaction_sha256::Sha256"));
    assert!(WIPE.contains("wipe_u32s(&mut self.state)"));
    assert!(WIPE.contains("wipe_bytes(&mut self.buffer)"));
    assert!(WIPE.contains("wipe_bytes(&mut self.padding)"));
    assert!(WIPE.contains("wipe_bytes(&mut self.length_bytes)"));
    assert!(WIPE.contains("wipe_u32s(&mut self.schedule)"));
    assert!(WIPE.contains("impl Drop for crate::transaction_sha256::DigestScratch"));
    assert!(WIPE.contains("value_owner_clears_fixed_values_and_complete_spare_capacity"));
    assert!(WIPE.contains("byte_and_value_owners_clear_during_caught_unwind"));
    assert!(INSERTION.contains("partial_output_guard_clears_its_complete_capacity_on_rejection"));
    assert!(INSERTION.contains("slot_table_clears_key_bytes_and_spare_capacity_during_unwind"));
}
