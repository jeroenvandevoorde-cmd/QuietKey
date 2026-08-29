//! V2 two-role descriptor-backed existing-signature verification.
//!
//! The signing scalars below are reconstructed from the QK-DEC-121 GOLDEN
//! public transcript strings and exist only to exercise the read-only
//! verifier. PERMANENTLY NEVER-FUND PUBLIC PRIVATE MATERIAL.

use qk_descriptor::{derive_receive_script_v2, parse_descriptor_pair_v2, DescriptorPairV2};
use qk_psbt::bip143::{sighash_all_digest, Bip143InputFacts, Bip143PrecomputeBuilder, SIGHASH_ALL};
use qk_psbt::{
    analyze_descriptor_ownership_v2, build_review_v3, parse, InputSource, OutputOwnership,
    ReviewContext, ReviewNetwork, SemanticCategory, VerifiedAggregateStatus, VerifiedInputStatus,
    MAX_DESCRIPTOR_V2_VERIFICATION_CALLS,
};

const REVIEW_FIXTURE: &str = include_str!("fixtures/review_v3.txt");
const DESCRIPTOR_FIXTURE: &str =
    include_str!("../../qk-descriptor/tests/fixtures/descriptor_pairs.txt");

const ROLE_A_RECEIVE_0_SCALAR: &str =
    "f157e34f4db1854304bb10aeb045a653aa7c0dc50c9c578b0965ce4e48271134";
const ROLE_B_RECEIVE_0_SCALAR: &str =
    "4e0f3dd5fefc3acd35eddeb3b66c65fc4e732b8f3f5339e45f6c79f3cc0950b9";

fn field<'a>(text: &'a str, name: &str) -> &'a str {
    text.lines()
        .find_map(|line| line.strip_prefix(name))
        .unwrap()
}

fn hex(text: &str) -> Vec<u8> {
    assert!(text.len().is_multiple_of(2));
    text.as_bytes()
        .chunks_exact(2)
        .map(|pair| u8::from_str_radix(core::str::from_utf8(pair).unwrap(), 16).unwrap())
        .collect()
}

fn fixed_hex<const N: usize>(text: &str) -> [u8; N] {
    hex(text).try_into().unwrap()
}

fn golden_block() -> &'static str {
    DESCRIPTOR_FIXTURE
        .split("\n\n")
        .find(|block| block.lines().any(|line| line == "case: GOLDEN"))
        .unwrap()
}

fn descriptor() -> DescriptorPairV2 {
    let golden = golden_block();
    parse_descriptor_pair_v2(
        field(golden, "receive: ").as_bytes(),
        field(golden, "change: ").as_bytes(),
    )
    .unwrap()
}

fn base_s0() -> Vec<u8> {
    hex(field(REVIEW_FIXTURE, "s0_hex: "))
}

fn context() -> ReviewContext {
    ReviewContext {
        network: ReviewNetwork::BitcoinMainnet,
        input_source: InputSource::MicroSd,
    }
}

fn signing_digest(bytes: &[u8], descriptor: &DescriptorPairV2) -> [u8; 32] {
    let view = parse(bytes, InputSource::MicroSd).unwrap();
    let review = build_review_v3(&view, descriptor, context()).unwrap();
    assert_eq!(review.inputs().len(), 1);
    let input = &review.inputs()[0];
    let derived = derive_receive_script_v2(descriptor, input.child_index()).unwrap();

    let mut builder = Bip143PrecomputeBuilder::new();
    for input in review.inputs() {
        builder
            .add_input(
                &input.outpoint_txid_wire(),
                input.outpoint_vout(),
                input.sequence(),
            )
            .unwrap();
    }
    for output in review.outputs() {
        builder
            .add_output(output.amount(), output.script_pubkey())
            .unwrap();
    }
    let precomputed = builder.finish().unwrap();
    sighash_all_digest(
        review.version(),
        review.locktime(),
        &precomputed,
        &Bip143InputFacts {
            outpoint_txid_wire: &input.outpoint_txid_wire(),
            outpoint_vout: input.outpoint_vout(),
            script_code: &derived.witness_script,
            amount_sats: input.prevout_amount(),
            sequence: input.sequence(),
        },
    )
    .unwrap()
}

fn signature_value(scalar_hex: &str, expected_public_key: &[u8; 33], digest: &[u8; 32]) -> Vec<u8> {
    let mut scalar = fixed_hex::<32>(scalar_hex);
    assert_eq!(
        qk_secp::provisioning_pubkey_create(&scalar).unwrap(),
        *expected_public_key
    );
    let expected = qk_secp::pubkey_parse_compressed(expected_public_key).unwrap();
    let key = qk_secp::secret_key_import(&mut scalar).unwrap();
    assert_eq!(scalar, [0u8; 32]);
    let signature = qk_secp::ecdsa_sign_rfc6979(&key, digest, &expected).unwrap();
    let mut der = [0u8; 72];
    let der_len = qk_secp::signature_serialize_der(&signature, &mut der).unwrap();
    let mut value = Vec::with_capacity(der_len + 1);
    value.extend_from_slice(&der[..der_len]);
    value.push(SIGHASH_ALL);
    value
}

fn encoded_record(full_key: &[u8], value: &[u8]) -> Vec<u8> {
    assert!(!full_key.is_empty() && full_key.len() < 0xfd);
    assert!(value.len() < 0xfd);
    let mut record = Vec::with_capacity(full_key.len() + value.len() + 2);
    record.push(u8::try_from(full_key.len()).unwrap());
    record.extend_from_slice(full_key);
    record.push(u8::try_from(value.len()).unwrap());
    record.extend_from_slice(value);
    record
}

fn insert_input_record(bytes: &mut Vec<u8>, full_key: &[u8], value: &[u8]) {
    let view = parse(bytes, InputSource::MicroSd).unwrap();
    let map = view.input_map_span(0).unwrap();
    let insert_at = view
        .input_records(0)
        .unwrap()
        .find(|record| record.full_key > full_key)
        .map(|record| record.full_key_span.start.checked_sub(1).unwrap())
        .unwrap_or(map.end.checked_sub(1).unwrap());
    let record = encoded_record(full_key, value);
    bytes.splice(insert_at..insert_at, record);
}

fn remove_nth_input_record(bytes: &mut Vec<u8>, key_type: u64, nth: usize) {
    let view = parse(bytes, InputSource::MicroSd).unwrap();
    let record = view
        .input_records(0)
        .unwrap()
        .filter(|record| record.key_type == key_type)
        .nth(nth)
        .unwrap();
    let start = record.full_key_span.start.checked_sub(1).unwrap();
    let end = record.value_span.end;
    assert_eq!(usize::from(bytes[start]), record.full_key.len());
    assert_eq!(
        usize::from(bytes[record.full_key_span.end]),
        record.value.len()
    );
    bytes.drain(start..end);
}

fn partial_key(public_key: &[u8; 33]) -> [u8; 34] {
    let mut key = [0u8; 34];
    key[0] = 0x02;
    key[1..].copy_from_slice(public_key);
    key
}

fn role_keys() -> ([u8; 33], [u8; 33]) {
    let golden = golden_block();
    (
        fixed_hex(field(golden, "role_a: ")),
        fixed_hex(field(golden, "role_b: ")),
    )
}

#[test]
fn zero_one_and_two_valid_signatures_have_exact_two_role_status() {
    let descriptor = descriptor();
    let mut psbt = base_s0();
    let digest = signing_digest(&psbt, &descriptor);
    let (role_a, role_b) = role_keys();

    let view = parse(&psbt, InputSource::MicroSd).unwrap();
    let empty = analyze_descriptor_ownership_v2(&view, &descriptor).unwrap();
    assert_eq!(empty.verified_inputs.len(), 1);
    assert_eq!(empty.verified_inputs[0].verified_signature_count, 0);
    assert_eq!(
        empty.verified_inputs[0].status,
        VerifiedInputStatus::BelowThreshold
    );
    assert_eq!(
        empty.aggregate_status,
        VerifiedAggregateStatus::AllInputsBelowThreshold
    );
    assert_eq!(empty.wallet.inputs[0].branch, 0);
    assert_eq!(empty.wallet.inputs[0].index, 0);
    assert!(matches!(
        empty.wallet.outputs[0],
        OutputOwnership::ProvenChange(0)
    ));
    drop(view);

    let a_value = signature_value(ROLE_A_RECEIVE_0_SCALAR, &role_a, &digest);
    insert_input_record(&mut psbt, &partial_key(&role_a), &a_value);
    let view = parse(&psbt, InputSource::MicroSd).unwrap();
    let one = analyze_descriptor_ownership_v2(&view, &descriptor).unwrap();
    assert_eq!(one.verified_inputs[0].verified_signature_count, 1);
    assert_eq!(
        one.verified_inputs[0].status,
        VerifiedInputStatus::BelowThreshold
    );
    assert_eq!(
        one.aggregate_status,
        VerifiedAggregateStatus::AllInputsBelowThreshold
    );
    drop(view);

    let b_value = signature_value(ROLE_B_RECEIVE_0_SCALAR, &role_b, &digest);
    insert_input_record(&mut psbt, &partial_key(&role_b), &b_value);
    let view = parse(&psbt, InputSource::MicroSd).unwrap();
    let complete = analyze_descriptor_ownership_v2(&view, &descriptor).unwrap();
    assert_eq!(complete.verified_inputs[0].verified_signature_count, 2);
    assert_eq!(
        complete.verified_inputs[0].status,
        VerifiedInputStatus::CryptographicallyVerifiedThreshold
    );
    assert_eq!(
        complete.aggregate_status,
        VerifiedAggregateStatus::VerifyAndExportOnly
    );
}

#[test]
fn wrong_digest_and_foreign_third_key_reject_by_name() {
    let descriptor = descriptor();
    let base = base_s0();
    let digest = signing_digest(&base, &descriptor);
    let (role_a, _) = role_keys();

    let mut wrong_digest = digest;
    wrong_digest[0] ^= 0x01;
    let wrong_value = signature_value(ROLE_A_RECEIVE_0_SCALAR, &role_a, &wrong_digest);
    let mut wrong_psbt = base.clone();
    insert_input_record(&mut wrong_psbt, &partial_key(&role_a), &wrong_value);
    let view = parse(&wrong_psbt, InputSource::MicroSd).unwrap();
    assert_eq!(
        analyze_descriptor_ownership_v2(&view, &descriptor)
            .unwrap_err()
            .category,
        SemanticCategory::SignatureVerificationFailed
    );

    let foreign = {
        let receive_one = DESCRIPTOR_FIXTURE
            .split("derivation: receive-1\n")
            .nth(1)
            .unwrap();
        fixed_hex::<33>(field(receive_one, "role_a: "))
    };
    assert_ne!(foreign, role_a);
    let valid_value = signature_value(ROLE_A_RECEIVE_0_SCALAR, &role_a, &digest);
    let mut foreign_psbt = base;
    insert_input_record(&mut foreign_psbt, &partial_key(&foreign), &valid_value);
    let view = parse(&foreign_psbt, InputSource::MicroSd).unwrap();
    assert_eq!(
        analyze_descriptor_ownership_v2(&view, &descriptor)
            .unwrap_err()
            .category,
        SemanticCategory::PartialSignaturePubkeyNotInWitnessScript
    );
}

#[test]
fn sighash_precedence_exact_derivation_count_and_witness_match_are_locked() {
    let descriptor = descriptor();
    let base = base_s0();
    let digest = signing_digest(&base, &descriptor);
    let (role_a, _) = role_keys();

    let mut wrong_sighash_value = signature_value(ROLE_A_RECEIVE_0_SCALAR, &role_a, &digest);
    *wrong_sighash_value.last_mut().unwrap() = 0x02;
    let mut wrong_sighash = base.clone();
    insert_input_record(
        &mut wrong_sighash,
        &partial_key(&role_a),
        &wrong_sighash_value,
    );
    let view = parse(&wrong_sighash, InputSource::MicroSd).unwrap();
    assert_eq!(
        analyze_descriptor_ownership_v2(&view, &descriptor)
            .unwrap_err()
            .category,
        SemanticCategory::UnsupportedSighash
    );

    let mut one_derivation = base.clone();
    remove_nth_input_record(&mut one_derivation, 0x06, 1);
    let view = parse(&one_derivation, InputSource::MicroSd).unwrap();
    assert_eq!(
        analyze_descriptor_ownership_v2(&view, &descriptor)
            .unwrap_err()
            .category,
        SemanticCategory::DescriptorV2DerivationRecordCount
    );

    let mut mismatched_script = derive_receive_script_v2(&descriptor, 0)
        .unwrap()
        .witness_script;
    mismatched_script[2] ^= 0x01;
    let mut with_mismatch = base;
    insert_input_record(&mut with_mismatch, &[0x05], &mismatched_script);
    let view = parse(&with_mismatch, InputSource::MicroSd).unwrap();
    assert_eq!(
        analyze_descriptor_ownership_v2(&view, &descriptor)
            .unwrap_err()
            .category,
        SemanticCategory::DescriptorWitnessScriptMismatch
    );
}

#[test]
fn v2_verification_call_bound_is_exact_and_public() {
    assert_eq!(MAX_DESCRIPTOR_V2_VERIFICATION_CALLS, 200);
    assert_eq!(MAX_DESCRIPTOR_V2_VERIFICATION_CALLS, 100 * 2);
}
