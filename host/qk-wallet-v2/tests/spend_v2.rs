//! Public capability, exact-proof integration, and fixed-error checks.

use qk_descriptor::parse_descriptor_pair_v2;
use qk_psbt::{
    build_validated_kit_sweep_v3, parse, InputSource, OwnedS0, ReplacementReceiveIndexV2,
    ValidatedKitSweepV3,
};
use qk_wallet_v2::{sign_validated_kit_sweep_v3, KitSweepSigningErrorV3};

const SPEND: &str = include_str!("../src/spend_v2.rs");
const BIP32: &str = include_str!("../src/bip32_private.rs");
const KIT_SPEND_FIXTURE: &str = include_str!("../../qk-host-sim/tests/fixtures/kit_spend_v2.txt");
const SIGNING_FIXTURE: &str =
    include_str!("../../qk-psbt/tests/fixtures/signing_finalization_v2.txt");

fn field<'a>(fixture: &'a str, name: &str) -> &'a str {
    fixture
        .lines()
        .find_map(|line| line.strip_prefix(name)?.strip_prefix(": "))
        .expect("registered field")
}

fn hex(text: &str) -> Vec<u8> {
    assert!(text.len().is_multiple_of(2));
    (0..text.len())
        .step_by(2)
        .map(|position| {
            u8::from_str_radix(&text[position..position + 2], 16).expect("registered lowercase hex")
        })
        .collect()
}

fn hex_array<const N: usize>(text: &str) -> [u8; N] {
    hex(text).try_into().expect("registered fixed-size hex")
}

fn old_descriptors() -> [[u8; 306]; 2] {
    [
        field(KIT_SPEND_FIXTURE, "old_receive_descriptor")
            .as_bytes()
            .try_into()
            .expect("old receive descriptor width"),
        field(KIT_SPEND_FIXTURE, "old_change_descriptor")
            .as_bytes()
            .try_into()
            .expect("old change descriptor width"),
    ]
}

fn validated_proof(existing_role_a: bool) -> ValidatedKitSweepV3 {
    let mut s0 = hex(field(KIT_SPEND_FIXTURE, "s0_hex"));
    if existing_role_a {
        let view = parse(&s0, InputSource::MicroSd).expect("registered S0");
        let insertion = view.input_map_span(0).expect("one input map").end - 1;
        let public_key =
            hex_array::<33>(field(KIT_SPEND_FIXTURE, "old_role_a_route_public_key_hex"));
        let mut value = hex(field(KIT_SPEND_FIXTURE, "role_a_der_hex"));
        value.push(1);
        let mut record = Vec::with_capacity(2 + public_key.len() + 1 + value.len());
        record.push(34);
        record.push(0x02);
        record.extend_from_slice(&public_key);
        record.push(u8::try_from(value.len()).expect("one-byte signature length"));
        record.extend_from_slice(&value);
        s0.splice(insertion..insertion, record);
    }

    let old = parse_descriptor_pair_v2(
        field(KIT_SPEND_FIXTURE, "old_receive_descriptor").as_bytes(),
        field(KIT_SPEND_FIXTURE, "old_change_descriptor").as_bytes(),
    )
    .expect("registered old descriptor");
    let replacement = parse_descriptor_pair_v2(
        field(KIT_SPEND_FIXTURE, "replacement_receive_descriptor").as_bytes(),
        field(KIT_SPEND_FIXTURE, "replacement_change_descriptor").as_bytes(),
    )
    .expect("registered replacement descriptor");
    build_validated_kit_sweep_v3(
        OwnedS0::new(&s0, InputSource::MicroSd).expect("bounded S0"),
        old,
        replacement,
        ReplacementReceiveIndexV2::from_untrusted(0),
    )
    .expect("registered exact sweep")
}

fn sign(proof: ValidatedKitSweepV3) -> qk_wallet_v2::WalletSignedKitSweepV3 {
    sign_validated_kit_sweep_v3(
        &hex_array(field(SIGNING_FIXTURE, "role_a_transcript_sha256")),
        &hex_array(field(SIGNING_FIXTURE, "role_b_transcript_sha256")),
        &old_descriptors(),
        &hex_array(field(KIT_SPEND_FIXTURE, "old_wallet_id_hex")),
        proof,
    )
    .expect("registered recovered authority")
}

#[test]
fn signing_errors_are_fixed_named_categories() {
    let cases = [
        (
            KitSweepSigningErrorV3::RecoveredWalletMismatch,
            "RecoveredWalletMismatch",
        ),
        (
            KitSweepSigningErrorV3::InvalidSigningPlan,
            "InvalidSigningPlan",
        ),
        (
            KitSweepSigningErrorV3::ChildDerivationFailed,
            "ChildDerivationFailed",
        ),
        (
            KitSweepSigningErrorV3::ExpectedPublicKeyMismatch,
            "ExpectedPublicKeyMismatch",
        ),
        (
            KitSweepSigningErrorV3::CryptographicSigningFailed,
            "CryptographicSigningFailed",
        ),
        (
            KitSweepSigningErrorV3::DuplicateSignature,
            "DuplicateSignature",
        ),
    ];
    for (error, expected) in cases {
        assert_eq!(error.name(), expected);
        assert_eq!(error.to_string(), expected);
    }
}

#[test]
fn no_reusable_or_arbitrary_signing_owner_exists() {
    assert!(SPEND.contains("proof: ValidatedKitSweepV3,"));
    assert!(!SPEND.contains("proof: &ValidatedKitSweepV3,"));
    assert!(SPEND.contains("pub struct WalletSignedKitSweepV3 {"));
    assert!(SPEND.contains("proof: ValidatedKitSweepV3Parts,"));
    assert!(SPEND.contains("signatures: WalletKitSweepSignaturesV3,"));
    assert!(SPEND.contains("let proof = proof.into_parts();"));
    assert!(SPEND.contains("pub struct WalletKitSweepSignaturesV3 {"));
    assert!(SPEND.contains("role_a: Option<KitSweepDerSignatureV3>,"));
    assert!(SPEND.contains("role_b: Option<KitSweepDerSignatureV3>,"));
    assert!(SPEND.contains("let occupied = plan.existing_role_signatures();"));
    assert!(SPEND.contains("inputs: [KitSweepInputSignaturesV3; MAX_INPUTS],"));
    assert!(!SPEND.contains("Vec<"));
    assert!(!SPEND.contains("Vec::"));
    assert!(!SPEND.contains("pub struct Signer"));
    assert!(!SPEND.contains("pub struct SigningKey"));
    assert!(!SPEND.contains("pub fn sign_digest"));
    assert!(!SPEND.contains("pub fn sign_request"));
    assert!(!SPEND.contains("pub fn scalar"));
    assert!(!SPEND.contains("pub fn secret"));
    assert!(!SPEND.contains("pub fn into_bytes"));
    assert!(!SPEND.contains("pub fn serialize"));
    assert!(!SPEND.contains("impl Clone for KitSweepDerSignatureV3"));
    assert!(!SPEND.contains("impl Clone for WalletKitSweepSignaturesV3"));
    assert!(!SPEND.contains("impl Clone for WalletSignedKitSweepV3"));
}

#[test]
fn child_derivation_is_exact_non_hardened_branch_then_index() {
    assert!(BIP32.contains("if branch > 1 || index > 65_535"));
    assert!(BIP32.contains("let branch_node = derive_non_hardened(account, branch)?;"));
    assert!(BIP32.contains("let child = derive_non_hardened(&branch_node, index)?;"));
    assert!(BIP32.contains("data[..33].copy_from_slice(&parent_pubkey);"));
    assert!(BIP32.contains("data[33..].copy_from_slice(&index.to_be_bytes());"));
}

#[test]
fn validated_sweep_produces_exact_registered_role_signatures() {
    let proof = validated_proof(false);
    assert_eq!(
        proof.input_signing_plans()[0].existing_role_signatures(),
        [false, false]
    );
    let signed = sign(proof);
    let (proof, signatures) = signed.into_execution_parts();
    assert_eq!(proof.input_count(), 1);
    assert_eq!(signatures.inputs().len(), 1);
    let input = &signatures.inputs()[0];
    assert_eq!(input.input_index(), 0);
    assert_eq!(
        input.role_a().expect("missing role A").der(),
        hex(field(KIT_SPEND_FIXTURE, "role_a_der_hex"))
    );
    assert_eq!(
        input.role_b().expect("missing role B").der(),
        hex(field(KIT_SPEND_FIXTURE, "role_b_der_hex"))
    );
}

#[test]
fn verified_existing_role_is_never_signed_twice() {
    let proof = validated_proof(true);
    assert_eq!(
        proof.input_signing_plans()[0].existing_role_signatures(),
        [true, false]
    );
    let signed = sign(proof);
    let (proof, signatures) = signed.into_execution_parts();
    assert_eq!(proof.input_count(), 1);
    let input = &signatures.inputs()[0];
    assert!(input.role_a().is_none());
    assert_eq!(
        input.role_b().expect("missing role B").der(),
        hex(field(KIT_SPEND_FIXTURE, "role_b_der_hex"))
    );
}
