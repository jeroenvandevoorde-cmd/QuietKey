#![cfg(feature = "normal-v3")]

use qk_descriptor::{parse_descriptor_pair_v2, DescriptorPairV2};
use qk_psbt::{
    build_validated_normal_v3, finalize_validated_normal_v3, InputSource,
    NormalFinalizationErrorV3, NormalSubmittedSignatureV3, OwnedS0,
};

const FIXTURE: &str = include_str!("fixtures/signing_finalization_v2.txt");
const DESCRIPTORS: &str = include_str!("../../qk-descriptor/tests/fixtures/descriptor_pairs.txt");

fn field<'a>(text: &'a str, name: &str) -> &'a str {
    text.lines()
        .find_map(|line| line.strip_prefix(name)?.strip_prefix(": "))
        .expect("registered field")
}

fn hex(text: &str) -> Vec<u8> {
    assert!(text.len().is_multiple_of(2));
    text.as_bytes()
        .chunks_exact(2)
        .map(|pair| {
            u8::from_str_radix(core::str::from_utf8(pair).expect("ASCII"), 16).expect("fixture hex")
        })
        .collect()
}

fn hex32(text: &str) -> [u8; 32] {
    hex(text).try_into().expect("32-byte field")
}

fn descriptor() -> DescriptorPairV2 {
    let block = DESCRIPTORS
        .split("\n\n")
        .find(|block| block.lines().any(|line| line == "case: GOLDEN"))
        .expect("GOLDEN descriptor block");
    parse_descriptor_pair_v2(
        field(block, "receive").as_bytes(),
        field(block, "change").as_bytes(),
    )
    .expect("registered descriptors")
}

fn proof() -> qk_psbt::ValidatedNormalV3 {
    build_validated_normal_v3(
        OwnedS0::new(&hex(field(FIXTURE, "s0_hex")), InputSource::MicroSd).expect("registered S0"),
        descriptor(),
    )
    .expect("normal proof")
}

#[test]
fn exact_golden_revalidates_signs_finalizes_and_reparses() {
    let proof = proof();
    assert_eq!(
        proof.review_hash(),
        hex32(field(FIXTURE, "review_hash_hex"))
    );
    assert_eq!(proof.input_signing_plans().len(), 1);
    assert_eq!(
        *proof.input_signing_plans()[0].digest(),
        hex32(field(FIXTURE, "bip143_digest_hex"))
    );
    proof.revalidate().expect("same retained S0");
    let role_a = hex(field(FIXTURE, "role_a_der_hex"));
    let role_b = hex(field(FIXTURE, "role_b_der_hex"));
    let finalized = finalize_validated_normal_v3(
        proof.into_parts(),
        &[NormalSubmittedSignatureV3::new(0, &role_a)],
        &[NormalSubmittedSignatureV3::new(0, &role_b)],
    )
    .expect("fully checked artifact");
    assert_eq!(
        finalized.finalized_psbt(),
        hex(field(FIXTURE, "finalized_psbt_hex"))
    );
    assert_eq!(
        finalized.raw_transaction(),
        hex(field(FIXTURE, "raw_transaction_hex"))
    );
    assert_eq!(
        finalized.finalized_psbt_sha256(),
        hex32(field(FIXTURE, "finalized_psbt_sha256"))
    );
    assert_eq!(
        finalized.raw_transaction_sha256(),
        hex32(field(FIXTURE, "raw_transaction_sha256"))
    );
    assert_eq!(finalized.txid(), hex32(field(FIXTURE, "txid_raw_hex")));
    assert_eq!(finalized.wtxid(), hex32(field(FIXTURE, "wtxid_raw_hex")));
    assert_eq!(
        finalized.review_hash(),
        hex32(field(FIXTURE, "review_hash_hex"))
    );
}

#[test]
fn malformed_or_wrong_mock_b_never_enters_an_artifact() {
    let role_a = hex(field(FIXTURE, "role_a_der_hex"));
    let mut role_b = hex(field(FIXTURE, "role_b_der_hex"));
    let last = role_b.len().checked_sub(1).expect("nonempty DER");
    role_b[last] ^= 1;
    assert_eq!(
        finalize_validated_normal_v3(
            proof().into_parts(),
            &[NormalSubmittedSignatureV3::new(0, &role_a)],
            &[NormalSubmittedSignatureV3::new(0, &role_b)],
        )
        .err()
        .expect("wrong B must reject"),
        NormalFinalizationErrorV3::InvalidMockSignature
    );

    assert_eq!(
        finalize_validated_normal_v3(
            proof().into_parts(),
            &[NormalSubmittedSignatureV3::new(0, &role_a)],
            &[],
        )
        .err()
        .expect("missing B must reject"),
        NormalFinalizationErrorV3::ThresholdIncomplete
    );
}
