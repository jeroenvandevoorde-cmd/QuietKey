#![cfg(feature = "normal-v3")]

use qk_descriptor::parse_descriptor_pair_v2;
use qk_psbt::{
    build_validated_normal_v3, finalize_validated_normal_v3, InputSource,
    NormalSubmittedSignatureV3, OwnedS0,
};
use qk_wallet_v2::{
    sign_validated_normal_role_a_v3, validate_normal_role_a_binding_v3, WalletNormalV3Error,
};

const FIXTURE: &str = include_str!("../../qk-psbt/tests/fixtures/signing_finalization_v2.txt");
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
    hex(text).try_into().expect("32 bytes")
}

fn descriptor_bytes() -> [[u8; 306]; 2] {
    let block = DESCRIPTORS
        .split("\n\n")
        .find(|block| block.lines().any(|line| line == "case: GOLDEN"))
        .expect("GOLDEN descriptors");
    [
        field(block, "receive")
            .as_bytes()
            .try_into()
            .expect("receive bytes"),
        field(block, "change")
            .as_bytes()
            .try_into()
            .expect("change bytes"),
    ]
}

#[test]
fn purpose_bound_role_a_matches_golden_and_completes_with_verified_b() {
    let descriptors = descriptor_bytes();
    let pair = parse_descriptor_pair_v2(&descriptors[0], &descriptors[1])
        .expect("registered descriptor pair");
    let proof = build_validated_normal_v3(
        OwnedS0::new(&hex(field(FIXTURE, "s0_hex")), InputSource::MicroSd).expect("registered S0"),
        pair,
    )
    .expect("validated normal proof");
    validate_normal_role_a_binding_v3(
        &hex32(field(FIXTURE, "role_a_transcript_sha256")),
        &descriptors,
        &hex32(field(FIXTURE, "wallet_id_hex")),
        &proof,
    )
    .expect("pre-review role-A binding");
    let signed = sign_validated_normal_role_a_v3(
        &hex32(field(FIXTURE, "role_a_transcript_sha256")),
        &descriptors,
        &hex32(field(FIXTURE, "wallet_id_hex")),
        proof,
    )
    .expect("purpose-bound role A");
    let (parts, role_a) = signed.into_finalization_parts();
    let [input] = role_a.inputs() else {
        panic!("one input")
    };
    let role_a_der = input.role_a().expect("missing role A").der();
    assert_eq!(role_a_der, hex(field(FIXTURE, "role_a_der_hex")));
    let role_a_submitted = [NormalSubmittedSignatureV3::new(
        input.input_index(),
        role_a_der,
    )];
    let role_b = hex(field(FIXTURE, "role_b_der_hex"));
    let finalized = finalize_validated_normal_v3(
        parts,
        &role_a_submitted,
        &[NormalSubmittedSignatureV3::new(0, &role_b)],
    )
    .expect("complete artifact");
    assert_eq!(
        finalized.finalized_psbt(),
        hex(field(FIXTURE, "finalized_psbt_hex"))
    );
    assert_eq!(
        finalized.raw_transaction(),
        hex(field(FIXTURE, "raw_transaction_hex"))
    );
}

#[test]
fn non_signing_binding_rejects_the_wrong_seed_without_output() {
    let descriptors = descriptor_bytes();
    let pair = parse_descriptor_pair_v2(&descriptors[0], &descriptors[1])
        .expect("registered descriptor pair");
    let proof = build_validated_normal_v3(
        OwnedS0::new(&hex(field(FIXTURE, "s0_hex")), InputSource::MicroSd).expect("registered S0"),
        pair,
    )
    .expect("validated normal proof");
    assert_eq!(
        validate_normal_role_a_binding_v3(
            &[0x42; 32],
            &descriptors,
            &hex32(field(FIXTURE, "wallet_id_hex")),
            &proof,
        ),
        Err(WalletNormalV3Error::RecoveredWalletMismatch)
    );
}
