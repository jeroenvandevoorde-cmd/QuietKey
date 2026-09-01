//! V2 slice-11 exact Kit-sweep proof and closed rejection matrix.

use qk_descriptor::{
    derive_change_script_v2, derive_receive_script_v2, parse_descriptor_pair_v2, DescriptorPairV2,
    DescriptorParseError,
};
use qk_psbt::{
    build_validated_kit_sweep_v3, parse, InputSource, KitSweepV3Error, OwnedS0, RecipientType,
    ReplacementReceiveIndexV2, ReviewV3OutputOwnership, ValidatedKitSweepV3,
};
#[cfg(feature = "normal-v3")]
use qk_psbt::{finalize_validated_kit_sweep_v3, NormalSubmittedSignatureV3};

const SIGNING_FIXTURE: &str = include_str!("fixtures/signing_finalization_v2.txt");
const KIT_SPEND_FIXTURE: &str = include_str!("../../qk-host-sim/tests/fixtures/kit_spend_v2.txt");

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
            u8::from_str_radix(core::str::from_utf8(pair).expect("ASCII hex"), 16)
                .expect("registered lowercase hex")
        })
        .collect()
}

fn hex_array<const N: usize>(text: &str) -> [u8; N] {
    hex(text).try_into().expect("registered fixed-size hex")
}

fn receive_index(value: u32) -> ReplacementReceiveIndexV2 {
    ReplacementReceiveIndexV2::from_untrusted(value)
}

fn old_descriptor() -> DescriptorPairV2 {
    parse_descriptor_pair_v2(
        field(KIT_SPEND_FIXTURE, "old_receive_descriptor").as_bytes(),
        field(KIT_SPEND_FIXTURE, "old_change_descriptor").as_bytes(),
    )
    .expect("registered old descriptor")
}

fn replacement_descriptor() -> DescriptorPairV2 {
    parse_descriptor_pair_v2(
        field(KIT_SPEND_FIXTURE, "replacement_receive_descriptor").as_bytes(),
        field(KIT_SPEND_FIXTURE, "replacement_change_descriptor").as_bytes(),
    )
    .expect("registered fresh NUMS replacement descriptor")
}

fn compact_size(output: &mut Vec<u8>, value: usize) {
    if value < 253 {
        output.push(u8::try_from(value).expect("one-byte fixture length"));
    } else {
        output.push(0xfd);
        output.extend_from_slice(
            &u16::try_from(value)
                .expect("two-byte fixture length")
                .to_le_bytes(),
        );
    }
}

fn one_output_psbt(base: &[u8], amount: u64, script: &[u8], output_map: Option<&[u8]>) -> Vec<u8> {
    let view = parse(base, InputSource::MicroSd).expect("registered base PSBT");
    assert_eq!(view.unsigned_tx().input_count, 1);
    let unsigned = view.unsigned_tx_bytes();
    assert_eq!(unsigned[4], 1);
    assert_eq!(unsigned[41], 0);

    let mut transaction = Vec::new();
    transaction.extend_from_slice(&unsigned[..46]);
    transaction.push(1);
    transaction.extend_from_slice(&amount.to_le_bytes());
    compact_size(&mut transaction, script.len());
    transaction.extend_from_slice(script);
    transaction.extend_from_slice(&unsigned[unsigned.len() - 4..]);

    let input_map = view.input_map_span(0).expect("one input map");
    let input_map = &base[input_map.start..input_map.end];
    let mut psbt = b"psbt\xff\x01\x00".to_vec();
    compact_size(&mut psbt, transaction.len());
    psbt.extend_from_slice(&transaction);
    psbt.push(0);
    psbt.extend_from_slice(input_map);
    psbt.extend_from_slice(output_map.unwrap_or(&[0]));
    parse(&psbt, InputSource::MicroSd).expect("constructed one-output PSBT");
    psbt
}

fn declared_output_count_psbt(base: &[u8], count: u8) -> Vec<u8> {
    let view = parse(base, InputSource::MicroSd).expect("registered base PSBT");
    assert_eq!(view.unsigned_tx().input_count, 1);
    let unsigned = view.unsigned_tx_bytes();
    assert_eq!(unsigned[4], 1);
    assert_eq!(unsigned[41], 0);

    let mut transaction = Vec::new();
    transaction.extend_from_slice(&unsigned[..46]);
    transaction.push(count);
    transaction.extend_from_slice(&unsigned[unsigned.len() - 4..]);

    let input_map = view.input_map_span(0).expect("one input map");
    let input_map = &base[input_map.start..input_map.end];
    let mut psbt = b"psbt\xff\x01\x00".to_vec();
    compact_size(&mut psbt, transaction.len());
    psbt.extend_from_slice(&transaction);
    psbt.push(0);
    psbt.extend_from_slice(input_map);
    psbt
}

fn zero_output_psbt(base: &[u8]) -> Vec<u8> {
    declared_output_count_psbt(base, 0)
}

fn two_output_psbt(base: &[u8], first: &[u8], second: &[u8]) -> Vec<u8> {
    let view = parse(base, InputSource::MicroSd).expect("registered base PSBT");
    assert_eq!(view.unsigned_tx().input_count, 1);
    let unsigned = view.unsigned_tx_bytes();

    let mut transaction = Vec::new();
    transaction.extend_from_slice(&unsigned[..46]);
    transaction.push(2);
    for script in [first, second] {
        transaction.extend_from_slice(&450_000u64.to_le_bytes());
        compact_size(&mut transaction, script.len());
        transaction.extend_from_slice(script);
    }
    transaction.extend_from_slice(&unsigned[unsigned.len() - 4..]);

    let input_map = view.input_map_span(0).expect("one input map");
    let input_map = &base[input_map.start..input_map.end];
    let mut psbt = b"psbt\xff\x01\x00".to_vec();
    compact_size(&mut psbt, transaction.len());
    psbt.extend_from_slice(&transaction);
    psbt.push(0);
    psbt.extend_from_slice(input_map);
    psbt.extend_from_slice(&[0, 0]);
    parse(&psbt, InputSource::MicroSd).expect("constructed two-output PSBT");
    psbt
}

fn unsigned_sweep() -> Vec<u8> {
    hex(field(KIT_SPEND_FIXTURE, "s0_hex"))
}

fn insert_partial_signature(psbt: &mut Vec<u8>, public_key: &[u8; 33], value: &[u8]) {
    let view = parse(psbt, InputSource::MicroSd).expect("unsigned sweep PSBT");
    let insertion = view.input_map_span(0).expect("one input map").end - 1;
    let mut record = Vec::new();
    record.push(34);
    record.push(0x02);
    record.extend_from_slice(public_key);
    compact_size(&mut record, value.len());
    record.extend_from_slice(value);
    psbt.splice(insertion..insertion, record);
}

fn role_a_signature(digest: &[u8; 32]) -> Vec<u8> {
    let public_key = hex_array(field(KIT_SPEND_FIXTURE, "old_role_a_route_public_key_hex"));
    let parsed_public = qk_secp::pubkey_parse_compressed(&public_key).expect("registered key");
    let mut scalar = hex_array(field(
        KIT_SPEND_FIXTURE,
        "old_role_a_route_private_scalar_hex",
    ));
    let secret = qk_secp::secret_key_import(&mut scalar).expect("public fixture scalar");
    let signature = qk_secp::ecdsa_sign_rfc6979(&secret, digest, &parsed_public)
        .expect("public fixture signature");
    let mut der = [0u8; 72];
    let length =
        qk_secp::signature_serialize_der(&signature, &mut der).expect("strict DER serialization");
    let mut value = der[..length].to_vec();
    value.push(1);
    value
}

fn rejected(result: Result<ValidatedKitSweepV3, KitSweepV3Error>) -> KitSweepV3Error {
    match result {
        Ok(proof) => {
            drop(proof);
            panic!("expected a named Kit-sweep rejection")
        }
        Err(error) => error,
    }
}

#[test]
fn exact_one_output_replacement_sweep_binds_review_and_input_plans() {
    let s0 = OwnedS0::new(&unsigned_sweep(), InputSource::MicroSd).expect("bounded S0");
    let old = old_descriptor();
    let old_wallet_id = old.wallet_id();
    let replacement = replacement_descriptor();
    let replacement_wallet_id = replacement.wallet_id();
    let proof = build_validated_kit_sweep_v3(s0, old, replacement, receive_index(0))
        .expect("exact replacement sweep");

    assert_eq!(proof.wallet_id(), old_wallet_id);
    assert_eq!(proof.replacement_wallet_id(), replacement_wallet_id);
    assert_eq!(
        proof.wallet_id(),
        hex_array(field(KIT_SPEND_FIXTURE, "old_wallet_id_hex"))
    );
    assert_eq!(
        proof.replacement_wallet_id(),
        hex_array(field(KIT_SPEND_FIXTURE, "replacement_wallet_id_hex"))
    );
    assert_eq!(
        proof.s0_sha256(),
        hex_array(field(KIT_SPEND_FIXTURE, "s0_sha256"))
    );
    assert_eq!(proof.destination_index(), 0);
    assert_eq!(proof.input_count(), 1);
    assert_eq!(proof.review().outputs().len(), 1);
    assert_eq!(
        proof.review().outputs()[0].amount(),
        field(KIT_SPEND_FIXTURE, "output_amount_sats")
            .parse::<u64>()
            .unwrap()
    );
    assert!(matches!(
        proof.review().outputs()[0].ownership(),
        ReviewV3OutputOwnership::NotOwned {
            recipient_type: RecipientType::P2wsh,
            ..
        }
    ));
    let plan = &proof.input_signing_plans()[0];
    assert_eq!(plan.input_index(), 0);
    assert_eq!(plan.branch(), 0);
    assert_eq!(plan.child_index(), 0);
    assert_eq!(plan.existing_role_signatures(), [false, false]);
    assert_eq!(
        plan.role_public_keys(),
        [
            hex_array(field(KIT_SPEND_FIXTURE, "old_role_a_route_public_key_hex",)),
            hex_array(field(KIT_SPEND_FIXTURE, "old_role_b_route_public_key_hex",)),
        ]
    );
    assert_eq!(
        plan.digest(),
        hex_array(field(KIT_SPEND_FIXTURE, "bip143_digest_hex"))
    );
    assert_eq!(
        proof.review().canonical_bytes(),
        hex(field(KIT_SPEND_FIXTURE, "review_v3_hex"))
    );
    assert_eq!(proof.review_hash(), proof.review().review_hash().unwrap());
    assert_eq!(
        proof.review_hash(),
        hex_array(field(KIT_SPEND_FIXTURE, "review_hash_hex"))
    );

    let parts = proof.into_parts();
    assert_eq!(parts.wallet_id(), old_wallet_id);
    assert_eq!(parts.replacement_wallet_id(), replacement_wallet_id);
    assert_eq!(parts.input_count(), 1);
    let (s0, descriptor, review, review_hash, plans) = parts.into_execution_parts();
    assert_eq!(s0.sha256(), review.s0_sha256());
    assert_eq!(descriptor.wallet_id(), old_wallet_id);
    assert_eq!(review_hash.value(), review.review_hash().unwrap());
    assert_eq!(plans.len(), 1);
}

#[cfg(feature = "normal-v3")]
#[test]
fn exact_sweep_adapter_delegates_to_the_normal_v3_finalizer() {
    let proof = build_validated_kit_sweep_v3(
        OwnedS0::new(&unsigned_sweep(), InputSource::MicroSd).expect("bounded S0"),
        old_descriptor(),
        replacement_descriptor(),
        receive_index(0),
    )
    .expect("exact replacement sweep");
    let role_a = hex(field(KIT_SPEND_FIXTURE, "role_a_der_hex"));
    let role_b = hex(field(KIT_SPEND_FIXTURE, "role_b_der_hex"));
    let finalized = finalize_validated_kit_sweep_v3(
        proof.into_parts(),
        &[NormalSubmittedSignatureV3::new(0, &role_a)],
        &[NormalSubmittedSignatureV3::new(0, &role_b)],
    )
    .expect("purpose-bound Kit sweep finalization");

    assert_eq!(
        finalized.finalized_psbt(),
        hex(field(KIT_SPEND_FIXTURE, "finalized_psbt_hex"))
    );
    assert_eq!(
        finalized.raw_transaction(),
        hex(field(KIT_SPEND_FIXTURE, "raw_transaction_hex"))
    );
    assert_eq!(
        finalized.finalized_psbt_sha256(),
        hex_array(field(KIT_SPEND_FIXTURE, "finalized_psbt_sha256"))
    );
    assert_eq!(
        finalized.raw_transaction_sha256(),
        hex_array(field(KIT_SPEND_FIXTURE, "raw_transaction_sha256"))
    );
    assert_eq!(
        finalized.review_hash(),
        hex_array(field(KIT_SPEND_FIXTURE, "review_hash_hex"))
    );
}

#[test]
fn existing_signature_occupancy_is_exposed_only_after_exact_verification() {
    let unsigned = unsigned_sweep();
    let proof = build_validated_kit_sweep_v3(
        OwnedS0::new(&unsigned, InputSource::MicroSd).unwrap(),
        old_descriptor(),
        replacement_descriptor(),
        receive_index(0),
    )
    .unwrap();
    let digest = proof.input_signing_plans()[0].digest();
    drop(proof);

    let public_key = hex_array(field(KIT_SPEND_FIXTURE, "old_role_a_route_public_key_hex"));
    let valid_der = role_a_signature(&digest);
    let mut signed = unsigned;
    insert_partial_signature(&mut signed, &public_key, &valid_der);
    let proof = build_validated_kit_sweep_v3(
        OwnedS0::new(&signed, InputSource::MicroSd).unwrap(),
        old_descriptor(),
        replacement_descriptor(),
        receive_index(0),
    )
    .expect("cryptographically valid existing role A");
    assert_eq!(
        proof.input_signing_plans()[0].existing_role_signatures(),
        [true, false]
    );
    let parts = proof.into_parts();
    let exact_der = &valid_der[..valid_der.len() - 1];
    assert!(parts.contains_existing_signature(exact_der));
    let mut distinct_der = exact_der.to_vec();
    distinct_der[0] ^= 1;
    assert!(!parts.contains_existing_signature(&distinct_der));
    drop(parts);

    let mut bad = role_a_signature(&digest);
    let final_der_byte = bad.len() - 2;
    bad[final_der_byte] ^= 1;
    let mut invalid = unsigned_sweep();
    insert_partial_signature(&mut invalid, &public_key, &bad);
    let error = rejected(build_validated_kit_sweep_v3(
        OwnedS0::new(&invalid, InputSource::MicroSd).unwrap(),
        old_descriptor(),
        replacement_descriptor(),
        receive_index(0),
    ));
    assert_eq!(error.name(), "ExistingSignatureVerificationFailed");

    let wrong_destination = derive_receive_script_v2(&replacement_descriptor(), 1).unwrap();
    let mut invalid_and_wrong_destination = one_output_psbt(
        &hex(field(SIGNING_FIXTURE, "s0_hex")),
        900_000,
        &wrong_destination.script_pubkey,
        None,
    );
    insert_partial_signature(&mut invalid_and_wrong_destination, &public_key, &bad);
    let precedence = rejected(build_validated_kit_sweep_v3(
        OwnedS0::new(&invalid_and_wrong_destination, InputSource::MicroSd).unwrap(),
        old_descriptor(),
        replacement_descriptor(),
        receive_index(0),
    ));
    assert_eq!(precedence.name(), "ExistingSignatureVerificationFailed");
}

#[test]
fn exact_sweep_rejections_are_named_and_state_closed() {
    let base = hex(field(SIGNING_FIXTURE, "s0_hex"));
    let old_receive = derive_receive_script_v2(&old_descriptor(), 0).unwrap();
    let old_change = derive_change_script_v2(&old_descriptor(), 0).unwrap();
    let replacement_receive_1 = derive_receive_script_v2(&replacement_descriptor(), 1).unwrap();
    let mut p2wpkh = vec![0x00, 0x14];
    p2wpkh.extend_from_slice(&[0x11; 20]);
    let mut p2pkh = vec![0x76, 0xa9, 0x14];
    p2pkh.extend_from_slice(&[0x22; 20]);
    p2pkh.extend_from_slice(&[0x88, 0xac]);
    let mut p2sh = vec![0xa9, 0x14];
    p2sh.extend_from_slice(&[0x33; 20]);
    p2sh.push(0x87);

    let cases = [
        (
            one_output_psbt(&base, 900_000, &old_receive.script_pubkey, None),
            0,
            "OldWalletDestination",
        ),
        (
            one_output_psbt(&base, 900_000, &old_change.script_pubkey, None),
            0,
            "ChangeOutputProhibited",
        ),
        (
            one_output_psbt(&base, 900_000, &replacement_receive_1.script_pubkey, None),
            0,
            "DestinationMismatch",
        ),
        (
            one_output_psbt(&base, 900_000, &p2wpkh, None),
            0,
            "DestinationTypeMismatch",
        ),
        (
            one_output_psbt(&base, 900_000, &p2pkh, None),
            0,
            "DestinationTypeMismatch",
        ),
        (
            one_output_psbt(&base, 900_000, &p2sh, None),
            0,
            "DestinationTypeMismatch",
        ),
    ];
    for (bytes, index, expected) in cases {
        let error = rejected(build_validated_kit_sweep_v3(
            OwnedS0::new(&bytes, InputSource::MicroSd).unwrap(),
            old_descriptor(),
            replacement_descriptor(),
            receive_index(index),
        ));
        assert_eq!(error.name(), expected);
    }

    let parsed = parse(&base, InputSource::MicroSd).unwrap();
    let output_map = parsed.output_map_span(0).unwrap();
    let change = one_output_psbt(
        &base,
        900_000,
        &old_change.script_pubkey,
        Some(&base[output_map.start..output_map.end]),
    );
    let change_error = rejected(build_validated_kit_sweep_v3(
        OwnedS0::new(&change, InputSource::MicroSd).unwrap(),
        old_descriptor(),
        replacement_descriptor(),
        receive_index(0),
    ));
    assert_eq!(change_error.name(), "ChangeOutputProhibited");

    let zero_count_error = rejected(build_validated_kit_sweep_v3(
        OwnedS0::new(&zero_output_psbt(&base), InputSource::MicroSd).unwrap(),
        old_descriptor(),
        replacement_descriptor(),
        receive_index(0),
    ));
    assert_eq!(zero_count_error.name(), "OutputCountNotOne");

    let over_cap_count_error = rejected(build_validated_kit_sweep_v3(
        OwnedS0::new(
            &declared_output_count_psbt(&base, 101),
            InputSource::MicroSd,
        )
        .unwrap(),
        old_descriptor(),
        replacement_descriptor(),
        receive_index(0),
    ));
    assert_eq!(over_cap_count_error.name(), "OutputCountNotOne");

    let replacement_receive = derive_receive_script_v2(&replacement_descriptor(), 0).unwrap();
    let mixed_count_error = rejected(build_validated_kit_sweep_v3(
        OwnedS0::new(
            &two_output_psbt(&base, &replacement_receive.script_pubkey, &[0x51]),
            InputSource::MicroSd,
        )
        .unwrap(),
        old_descriptor(),
        replacement_descriptor(),
        receive_index(0),
    ));
    assert_eq!(mixed_count_error.name(), "OutputCountNotOne");

    let count_error = rejected(build_validated_kit_sweep_v3(
        OwnedS0::new(&base, InputSource::MicroSd).unwrap(),
        old_descriptor(),
        replacement_descriptor(),
        receive_index(0),
    ));
    assert_eq!(count_error.name(), "OutputCountNotOne");

    let index_error = rejected(build_validated_kit_sweep_v3(
        OwnedS0::new(&unsigned_sweep(), InputSource::MicroSd).unwrap(),
        old_descriptor(),
        replacement_descriptor(),
        receive_index(65_536),
    ));
    assert_eq!(index_error, KitSweepV3Error::DestinationIndexOutOfRange);

    let maximum_destination = derive_receive_script_v2(&replacement_descriptor(), 65_535).unwrap();
    let maximum_index_proof = build_validated_kit_sweep_v3(
        OwnedS0::new(
            &one_output_psbt(&base, 900_000, &maximum_destination.script_pubkey, None),
            InputSource::MicroSd,
        )
        .unwrap(),
        old_descriptor(),
        replacement_descriptor(),
        receive_index(65_535),
    )
    .expect("inclusive maximum replacement receive index");
    assert_eq!(maximum_index_proof.destination_index(), 65_535);

    let same_error = rejected(build_validated_kit_sweep_v3(
        OwnedS0::new(&unsigned_sweep(), InputSource::MicroSd).unwrap(),
        old_descriptor(),
        old_descriptor(),
        receive_index(0),
    ));
    assert_eq!(same_error, KitSweepV3Error::ReplacementWalletUnchanged);

    let precedence_index = rejected(build_validated_kit_sweep_v3(
        OwnedS0::new(&zero_output_psbt(&base), InputSource::MicroSd).unwrap(),
        old_descriptor(),
        old_descriptor(),
        receive_index(65_536),
    ));
    assert_eq!(
        precedence_index,
        KitSweepV3Error::DestinationIndexOutOfRange
    );

    let precedence_wallet = rejected(build_validated_kit_sweep_v3(
        OwnedS0::new(&zero_output_psbt(&base), InputSource::MicroSd).unwrap(),
        old_descriptor(),
        old_descriptor(),
        receive_index(0),
    ));
    assert_eq!(
        precedence_wallet,
        KitSweepV3Error::ReplacementWalletUnchanged
    );
}

#[test]
fn both_registered_descriptor_members_are_required_before_sweep_rebinding() {
    let old_receive = field(KIT_SPEND_FIXTURE, "old_receive_descriptor").as_bytes();
    let old_change = field(KIT_SPEND_FIXTURE, "old_change_descriptor").as_bytes();
    let replacement_change = field(KIT_SPEND_FIXTURE, "replacement_change_descriptor").as_bytes();

    assert_eq!(
        parse_descriptor_pair_v2(old_receive, replacement_change).err(),
        Some(DescriptorParseError::DescriptorPairMismatch)
    );

    let mut mutated_change = old_change.to_vec();
    let checksum_byte = mutated_change.last_mut().expect("checksummed descriptor");
    *checksum_byte = if *checksum_byte == b'q' { b'p' } else { b'q' };
    assert_eq!(
        parse_descriptor_pair_v2(old_receive, &mutated_change).err(),
        Some(DescriptorParseError::ChecksumMismatch)
    );
}
