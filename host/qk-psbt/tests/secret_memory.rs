//! QK-DEC-137 public ownership and stable-surface pins.

use core::ops::{Deref, Index};
use qk_psbt::{
    bip143::{sighash_all_digest, Bip143InputFacts, Bip143PrecomputeBuilder, Bip143Precomputed},
    canonical_serialize, PsbtView, SerializeError, TransactionMaterialVec,
};

const LIB_SOURCE: &str = include_str!("../src/lib.rs");
const WIPE_SOURCE: &str = include_str!("../src/wipe.rs");
const SHA256_SOURCE: &str = include_str!("../src/sha256.rs");
const BIP143_SOURCE: &str = include_str!("../src/bip143.rs");
const SEMANTIC_SOURCE: &str = include_str!("../src/semantic.rs");
const SERIALIZE_SOURCE: &str = include_str!("../src/serialize.rs");

#[test]
fn transaction_material_owner_is_read_only_and_publicly_reachable() {
    fn require_read_surface<T: Copy>()
    where
        TransactionMaterialVec<T>: AsRef<[T]> + Deref<Target = [T]> + Index<usize, Output = T>,
        for<'a> &'a TransactionMaterialVec<T>: IntoIterator<Item = &'a T>,
    {
    }

    fn require_slice_comparison<T: Copy + PartialEq>()
    where
        TransactionMaterialVec<T>: PartialEq<[T; 1]>,
        for<'a> TransactionMaterialVec<T>: PartialEq<&'a [T]>,
    {
    }

    require_read_surface::<u8>();
    require_slice_comparison::<u8>();
    assert!(LIB_SOURCE.contains("pub use wipe::TransactionMaterialVec;"));
    assert!(WIPE_SOURCE.contains("pub struct TransactionMaterialVec<T: Copy>"));
    assert!(!WIPE_SOURCE.contains("impl<T> DerefMut for TransactionMaterialVec<T>"));
    assert!(!WIPE_SOURCE.contains("pub fn into_transaction_material"));
    assert!(!WIPE_SOURCE.contains("pub fn from_vec"));
}

#[test]
#[allow(clippy::type_complexity)]
fn bip143_and_serializer_public_signatures_remain_stable() {
    let _: fn(&PsbtView<'_>) -> Result<Vec<u8>, SerializeError> = canonical_serialize;
    let _: fn() -> Bip143PrecomputeBuilder = Bip143PrecomputeBuilder::new;
    let _: fn(
        u32,
        u32,
        &Bip143Precomputed,
        &Bip143InputFacts<'_>,
    ) -> Result<[u8; 32], qk_psbt::bip143::Bip143Error> = sighash_all_digest;

    assert!(BIP143_SOURCE.contains("pub fn finish(self) -> Result<Bip143Precomputed, Bip143Error>"));
    assert!(!BIP143_SOURCE.contains("impl Drop for Bip143Precomputed"));
    assert!(SERIALIZE_SOURCE.contains(
        "pub fn canonical_serialize(view: &PsbtView<'_>) -> Result<Vec<u8>, SerializeError>"
    ));
}

#[test]
fn hash_and_serialization_scratch_use_existing_wipe_boundaries() {
    assert!(!SHA256_SOURCE.contains("mod wipe;"));
    assert!(SHA256_SOURCE.contains("pub(crate) padding: [u8; 128]"));
    assert!(SHA256_SOURCE.contains("pub(crate) length_bytes: [u8; 8]"));
    assert!(SHA256_SOURCE.contains("pub(crate) schedule: [u32; 16]"));
    assert!(SHA256_SOURCE.contains("pub(crate) struct DigestScratch"));
    assert!(WIPE_SOURCE.contains("impl Drop for crate::sha256::Sha256"));
    assert!(WIPE_SOURCE.contains("u32s(&mut self.state)"));
    assert!(WIPE_SOURCE.contains("bytes(&mut self.buffer)"));
    assert!(WIPE_SOURCE.contains("bytes(&mut self.padding)"));
    assert!(WIPE_SOURCE.contains("bytes(&mut self.length_bytes)"));
    assert!(WIPE_SOURCE.contains("u32s(&mut self.schedule)"));
    assert!(WIPE_SOURCE.contains("impl Drop for crate::sha256::DigestScratch"));
    assert!(BIP143_SOURCE.contains("wipe::ByteArray::new(hasher.finalize()?)"));
    assert!(BIP143_SOURCE.contains("wipe::ByteArray::new(sink.0.finalize()?)"));
    assert!(SEMANTIC_SOURCE.contains("WipingValueArray::new([qk_secp::pubkey_parse_compressed"));
    assert!(SEMANTIC_SOURCE.contains("WipingValueArray::new([qk_secp::signature_parse_der"));
    assert!(SEMANTIC_SOURCE.contains("let [signature] = signature_owner.as_slice()"));
    assert!(SEMANTIC_SOURCE.contains("let [pubkey] = pubkey_owner.as_slice()"));
    assert!(SERIALIZE_SOURCE.contains("bytes: wipe::WipingByteVec"));
    assert!(SERIALIZE_SOURCE.contains("wipe::WipingValueArray::new"));
    assert!(SERIALIZE_SOURCE.contains("-> (wipe::ByteArray<9>, usize)"));
    assert!(SERIALIZE_SOURCE.contains("Ok(out.bytes.into_vec())"));

    for source in [SHA256_SOURCE, BIP143_SOURCE, SERIALIZE_SOURCE] {
        assert!(!source.contains("unsafe {"));
    }
}
