//! V2 slice-2's exact public D-09 review-v3 and no-crypto boundary.

use qk_descriptor::{
    derive_change_script_v2, derive_receive_script_v2, parse_descriptor_pair_v2, DescriptorPairV2,
};
use qk_psbt::{
    build_review_v3, parse, DirectRbf, FeeWarning, InputSource, RecipientType, ReviewContext,
    ReviewNetwork, ReviewV3Error, ReviewV3OutputOwnership, SemanticCategory,
    FEE_POLICY_V2_IDENTIFIER, MAX_CANONICAL_REVIEW_V3_BYTES, MAX_ESTIMATED_VSIZE_V2,
    MAX_FEE_WARNINGS_V2, MAX_REVIEW_V3_HASH_TRANSCRIPT_BYTES, REVIEW_V3_HASH_DOMAIN,
    REVIEW_V3_SCHEMA_VERSION,
};

const FIXTURE: &str = include_str!("fixtures/review_v3.txt");
const DESCRIPTOR_FIXTURE: &str =
    include_str!("../../qk-descriptor/tests/fixtures/descriptor_pairs.txt");

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

fn descriptor() -> DescriptorPairV2 {
    let golden = DESCRIPTOR_FIXTURE
        .split("\n\n")
        .find(|block| block.lines().any(|line| line == "case: GOLDEN"))
        .unwrap();
    parse_descriptor_pair_v2(
        field(golden, "receive: ").as_bytes(),
        field(golden, "change: ").as_bytes(),
    )
    .unwrap()
}

fn context(source: InputSource) -> ReviewContext {
    ReviewContext {
        network: ReviewNetwork::BitcoinMainnet,
        input_source: source,
    }
}

fn record_bounds(buffer: &[u8], record: qk_psbt::Record<'_>) -> (usize, usize) {
    let start = record.full_key_span.start.checked_sub(1).unwrap();
    assert_eq!(usize::from(buffer[start]), record.full_key.len());
    assert_eq!(
        usize::from(buffer[record.full_key_span.end]),
        record.value.len()
    );
    (start, record.value_span.end)
}

fn insert_record(buffer: &mut Vec<u8>, map_end: usize, key: &[u8], value: &[u8]) {
    assert!(!key.is_empty() && key.len() < 253);
    assert!(value.len() < 253);
    let mut encoded = Vec::with_capacity(key.len() + value.len() + 2);
    encoded.push(u8::try_from(key.len()).unwrap());
    encoded.extend_from_slice(key);
    encoded.push(u8::try_from(value.len()).unwrap());
    encoded.extend_from_slice(value);
    buffer.splice(map_end - 1..map_end - 1, encoded);
}

#[test]
fn exact_public_golden_binds_every_v3_fact() {
    let s0 = hex(field(FIXTURE, "s0_hex: "));
    let view = parse(&s0, InputSource::MicroSd).unwrap();
    let review = build_review_v3(&view, &descriptor(), context(InputSource::MicroSd)).unwrap();

    assert_eq!(review.schema_version(), 3);
    assert_eq!(review.context(), context(InputSource::MicroSd));
    assert_eq!(
        review.canonical_bytes(),
        hex(field(FIXTURE, "canonical_review_v3_hex: "))
    );
    assert_eq!(
        review.canonical_bytes().len(),
        field(FIXTURE, "canonical_review_v3_len: ").parse().unwrap()
    );
    assert_eq!(
        review.review_hash().unwrap().as_slice(),
        hex(field(FIXTURE, "review_hash: "))
    );
    assert_eq!(
        review.s0_sha256().as_slice(),
        hex(field(FIXTURE, "s0_sha256: "))
    );
    assert_eq!(
        review.wallet_id().as_slice(),
        hex(field(FIXTURE, "wallet_id: "))
    );
    assert_eq!(
        review.origin_fingerprints(),
        [[0x2f, 0xae, 0x97, 0x11], [0x72, 0xa1, 0x4a, 0xb8]]
    );
    assert_eq!(review.fee_policy_identifier(), b"QK-FEE-POLICY-V2");
    assert_eq!(
        review.unsigned_tx_bytes(),
        hex(field(FIXTURE, "unsigned_tx_hex: "))
    );
    assert_eq!(review.version(), 2);
    assert_eq!(review.locktime(), 500_000);

    assert_eq!(review.input_count(), 1);
    let input = &review.inputs()[0];
    assert_eq!(input.index(), 0);
    assert_eq!(
        input.outpoint_txid_wire().as_slice(),
        hex(field(FIXTURE, "outpoint_txid_wire: "))
    );
    assert_eq!(input.outpoint_vout(), 0);
    assert_eq!(input.prevout_amount(), 1_000_000);
    assert_eq!(
        input.prevout_script_pubkey(),
        hex("00204f202480a991034742ecc4ba29049134bcd5fb79c56bfc502289de3e7e0ba104")
    );
    assert_eq!(input.sequence(), 0xffff_fffd);
    assert_eq!(input.effective_sighash(), 1);
    assert_eq!(input.branch(), 0);
    assert_eq!(input.child_index(), 0);
    assert_eq!(input.direct_rbf(), DirectRbf::Signaled);
    assert_eq!(review.direct_rbf(), DirectRbf::Signaled);

    assert_eq!(review.outputs().len(), 4);
    assert_eq!(review.outputs()[0].index(), 0);
    assert_eq!(review.outputs()[0].amount(), 400_000);
    assert_eq!(
        review.outputs()[0].script_pubkey(),
        hex("0020af13c203a3389432b3a920c5f429dee4139c804ea692a3f77b1345f56e24b72f")
    );
    assert!(matches!(
        review.outputs()[0].ownership(),
        ReviewV3OutputOwnership::ProvenChange { child_index: 0 }
    ));

    assert_eq!(review.outputs()[1].index(), 1);
    assert_eq!(review.outputs()[1].amount(), 300_000);
    assert_eq!(
        review.outputs()[1].script_pubkey(),
        hex("00202fe9bb02255457981f0613c8f7b5cc2f354fade42a4b4b19f22b3566e1c6bae0")
    );
    match review.outputs()[1].ownership() {
        ReviewV3OutputOwnership::ProvenSelfTransfer {
            child_index,
            witness_program,
        } => {
            assert_eq!(*child_index, 1);
            assert_eq!(
                witness_program.as_slice(),
                &review.outputs()[1].script_pubkey()[2..]
            );
        }
        other => panic!("unexpected self-transfer fact: {other:?}"),
    }

    assert_eq!(review.outputs()[2].index(), 2);
    assert_eq!(review.outputs()[2].amount(), 200_000);
    assert_eq!(
        review.outputs()[2].script_pubkey(),
        hex("00141111111111111111111111111111111111111111")
    );
    assert!(matches!(
        review.outputs()[2].ownership(),
        ReviewV3OutputOwnership::NotOwned {
            recipient_type: RecipientType::P2wpkh,
            data,
        } if data.as_slice() == [0x11; 20]
    ));

    assert_eq!(review.outputs()[3].index(), 3);
    assert_eq!(review.outputs()[3].amount(), 0);
    assert_eq!(review.outputs()[3].script_pubkey(), hex("6a03aabbcc"));
    assert!(matches!(
        review.outputs()[3].ownership(),
        ReviewV3OutputOwnership::NotOwned {
            recipient_type: RecipientType::OpReturn,
            data,
        } if data.as_slice() == [0xaa, 0xbb, 0xcc]
    ));

    assert_eq!(review.total_input_amount(), 1_000_000);
    assert_eq!(review.total_output_amount(), 900_000);
    assert_eq!(review.fee(), 100_000);
    assert_eq!(review.estimated_vsize(), 238);
    assert_eq!(review.fee_rate_msat_per_vbyte(), 420_168);
    assert_eq!(review.fee_policy().warning_count(), 2);
    assert_eq!(
        review.fee_warnings().collect::<Vec<_>>(),
        [FeeWarning::RateHigh, FeeWarning::ShareHigh]
    );
}

#[test]
fn source_is_retained_and_conflicts_reject_before_semantics() {
    let s0 = hex(field(FIXTURE, "s0_hex: "));
    let descriptor = descriptor();
    let sd = parse(&s0, InputSource::MicroSd).unwrap();
    let qr = parse(&s0, InputSource::Qr).unwrap();

    assert_eq!(
        build_review_v3(&sd, &descriptor, context(InputSource::Qr)),
        Err(ReviewV3Error::SourceMismatch)
    );
    assert_eq!(
        build_review_v3(&qr, &descriptor, context(InputSource::MicroSd)),
        Err(ReviewV3Error::SourceMismatch)
    );
    let qr_review = build_review_v3(&qr, &descriptor, context(InputSource::Qr)).unwrap();
    assert_eq!(&qr_review.canonical_bytes()[..3], &[3, 1, 2]);
}

#[test]
fn witness_utxo_precedes_unsupported_sighash() {
    let original = hex(field(FIXTURE, "s0_hex: "));
    let descriptor = descriptor();

    let parsed = parse(&original, InputSource::MicroSd).unwrap();
    let witness_offset = parsed
        .input_records(0)
        .unwrap()
        .find(|record| record.key_type == 0x01)
        .unwrap()
        .value_span
        .start;
    let sighash_offset = parsed
        .input_records(0)
        .unwrap()
        .find(|record| record.key_type == 0x03)
        .unwrap()
        .value_span
        .start;
    drop(parsed);

    let mut witness_mismatch = original.clone();
    witness_mismatch[witness_offset] ^= 1;
    let view = parse(&witness_mismatch, InputSource::MicroSd).unwrap();
    assert!(matches!(
        build_review_v3(&view, &descriptor, context(InputSource::MicroSd)),
        Err(ReviewV3Error::Semantic(error))
            if error.category == SemanticCategory::WitnessUtxoMismatch
    ));

    let mut overlapping = witness_mismatch;
    overlapping[sighash_offset] = 2;
    let view = parse(&overlapping, InputSource::MicroSd).unwrap();
    assert!(matches!(
        build_review_v3(&view, &descriptor, context(InputSource::MicroSd)),
        Err(ReviewV3Error::Semantic(error))
            if error.category == SemanticCategory::WitnessUtxoMismatch
    ));

    let mut unsupported_sighash = original;
    unsupported_sighash[sighash_offset] = 2;
    let view = parse(&unsupported_sighash, InputSource::MicroSd).unwrap();
    assert!(matches!(
        build_review_v3(&view, &descriptor, context(InputSource::MicroSd)),
        Err(ReviewV3Error::Semantic(error))
            if error.category == SemanticCategory::UnsupportedSighash
    ));
}

#[test]
fn inputs_require_exactly_two_descriptor_derivations() {
    let original = hex(field(FIXTURE, "s0_hex: "));
    let descriptor = descriptor();
    let parsed = parse(&original, InputSource::MicroSd).unwrap();
    let derivation = parsed
        .input_records(0)
        .unwrap()
        .find(|record| record.key_type == 0x06)
        .unwrap();
    let (record_start, record_end) = record_bounds(&original, derivation);
    let mut third_key = derivation.full_key.to_vec();
    *third_key.last_mut().unwrap() ^= 1;
    let third_value = derivation.value.to_vec();
    let map_end = parsed.input_map_span(0).unwrap().end;
    drop(parsed);

    let mut one = original.clone();
    one.drain(record_start..record_end);
    let view = parse(&one, InputSource::MicroSd).unwrap();
    assert!(matches!(
        build_review_v3(&view, &descriptor, context(InputSource::MicroSd)),
        Err(ReviewV3Error::Semantic(error))
            if error.category == SemanticCategory::DescriptorV2DerivationRecordCount
    ));

    let mut three = original;
    insert_record(&mut three, map_end, &third_key, &third_value);
    let view = parse(&three, InputSource::MicroSd).unwrap();
    assert!(matches!(
        build_review_v3(&view, &descriptor, context(InputSource::MicroSd)),
        Err(ReviewV3Error::Semantic(error))
            if error.category == SemanticCategory::DescriptorV2DerivationRecordCount
    ));
}

#[test]
fn optional_witness_script_must_equal_the_reconstructed_script() {
    let s0 = hex(field(FIXTURE, "s0_hex: "));
    let descriptor = descriptor();
    let parsed = parse(&s0, InputSource::MicroSd).unwrap();
    let map_end = parsed.input_map_span(0).unwrap().end;
    drop(parsed);

    let receive_script = derive_receive_script_v2(&descriptor, 0).unwrap();
    let mut matching = s0.clone();
    insert_record(
        &mut matching,
        map_end,
        &[0x05],
        &receive_script.witness_script,
    );
    let view = parse(&matching, InputSource::MicroSd).unwrap();
    assert!(build_review_v3(&view, &descriptor, context(InputSource::MicroSd)).is_ok());

    let change_script = derive_change_script_v2(&descriptor, 0).unwrap();
    let mut mismatching = s0;
    insert_record(
        &mut mismatching,
        map_end,
        &[0x05],
        &change_script.witness_script,
    );
    let view = parse(&mismatching, InputSource::MicroSd).unwrap();
    assert!(matches!(
        build_review_v3(&view, &descriptor, context(InputSource::MicroSd)),
        Err(ReviewV3Error::Semantic(error))
            if error.category == SemanticCategory::DescriptorWitnessScriptMismatch
    ));
}

#[test]
fn exact_identity_rejects_v1_and_v2_before_canonical_comparison() {
    let s0 = hex(field(FIXTURE, "s0_hex: "));
    let view = parse(&s0, InputSource::MicroSd).unwrap();
    let review = build_review_v3(&view, &descriptor(), context(InputSource::MicroSd)).unwrap();
    let mut presented = review.canonical_bytes().to_vec();

    assert_eq!(review.verify_exact_identity(&presented), Ok(()));
    presented[20] ^= 1;
    assert_eq!(
        review.verify_exact_identity(&presented),
        Err(ReviewV3Error::CanonicalReviewMismatch)
    );
    for schema in [1, 2] {
        presented[0] = schema;
        assert_eq!(
            review.verify_exact_identity(&presented),
            Err(ReviewV3Error::UnsupportedReviewSchemaVersion)
        );
    }
    assert_eq!(
        review.verify_exact_identity(&[]),
        Err(ReviewV3Error::UnsupportedReviewSchemaVersion)
    );
}

#[test]
fn public_review_surface_has_no_verified_threshold_or_session_claim() {
    let source = include_str!("../src/review_v3.rs");
    let crate_root = include_str!("../src/lib.rs");
    let public_review = source
        .split("pub struct ReviewV3 {")
        .nth(1)
        .unwrap()
        .split("impl ReviewV3")
        .next()
        .unwrap();
    for forbidden in [
        "verified_signature",
        "threshold",
        "aggregate_status",
        "signable",
        "exportable",
        "CycleToken",
        "session",
    ] {
        assert!(!public_review.contains(forbidden), "{forbidden}");
    }
    for private_seam in [
        "analyze_review_v3_semantics",
        "ReviewV3SemanticAnalysis",
        "ReviewV3SemanticInput",
        "ReviewV3SemanticOutput",
        "ReviewV3InputFacts",
        "ReviewV3OutputFacts",
        "ReviewV3Facts",
        "build_review_v3_from_facts",
    ] {
        assert!(!crate_root.contains(private_seam), "{private_seam}");
    }
}

#[test]
fn schema_v3_policy_and_candidate_caps_are_exact_public_constants() {
    assert_eq!(REVIEW_V3_SCHEMA_VERSION, 3);
    assert_eq!(FEE_POLICY_V2_IDENTIFIER, b"QK-FEE-POLICY-V2");
    assert_eq!(REVIEW_V3_HASH_DOMAIN, b"QuietKey/D-09/review/v3");
    assert_eq!(MAX_CANONICAL_REVIEW_V3_BYTES, 18_930);
    assert_eq!(MAX_REVIEW_V3_HASH_TRANSCRIPT_BYTES, 18_954);
    assert_eq!(MAX_ESTIMATED_VSIZE_V2, 11_036);
    assert_eq!(MAX_FEE_WARNINGS_V2, 3);
    assert_eq!(qk_psbt::limits::MAX_CHILD_DERIVATIONS_V2, 528);

    assert_eq!(132 * 4, qk_psbt::limits::MAX_CHILD_DERIVATIONS_V2);
    assert_eq!(
        158 + 5_535 + (100 * 102) + (185 + 31 * 92),
        MAX_CANONICAL_REVIEW_V3_BYTES
    );
    assert_eq!(
        MAX_CANONICAL_REVIEW_V3_BYTES + REVIEW_V3_HASH_DOMAIN.len() + 1,
        MAX_REVIEW_V3_HASH_TRANSCRIPT_BYTES
    );
    assert_eq!(
        ((4usize * 5_535) + 2 + (100 * 220)).div_ceil(4),
        usize::try_from(MAX_ESTIMATED_VSIZE_V2).unwrap()
    );
}
