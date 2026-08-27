//! M23's exact public D-09 review-v2 and no-crypto semantic boundary.

use qk_descriptor::{parse_descriptor_pair, DescriptorPair};
use qk_psbt::{
    analyze_descriptor_ownership, build_review_v2, parse, DirectRbf, FeeWarning, InputSource,
    RecipientType, ReviewContext, ReviewNetwork, ReviewV2Error, ReviewV2OutputOwnership,
    SemanticCategory,
};

const FIXTURE: &str = include_str!("fixtures/review_v2.txt");
const DESCRIPTOR_FIXTURE: &str = include_str!("fixtures/descriptor_ownership.txt");

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

fn descriptor() -> DescriptorPair {
    parse_descriptor_pair(
        field(DESCRIPTOR_FIXTURE, "receive: ").as_bytes(),
        field(DESCRIPTOR_FIXTURE, "change: ").as_bytes(),
    )
    .unwrap()
}

fn context(source: InputSource) -> ReviewContext {
    ReviewContext {
        network: ReviewNetwork::BitcoinMainnet,
        input_source: source,
    }
}

#[test]
fn exact_public_golden_binds_all_v2_facts() {
    let s0 = hex(field(FIXTURE, "s0_hex: "));
    let view = parse(&s0, InputSource::MicroSd).unwrap();
    let review = build_review_v2(&view, &descriptor(), context(InputSource::MicroSd)).unwrap();

    assert_eq!(
        review.canonical_bytes(),
        hex(field(FIXTURE, "canonical_review_v2_hex: "))
    );
    assert_eq!(
        review.canonical_bytes().len(),
        field(FIXTURE, "canonical_review_v2_len: ").parse().unwrap()
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
        review.unsigned_tx_bytes(),
        hex(field(FIXTURE, "unsigned_tx_hex: "))
    );
    assert_eq!(review.version(), 2);
    assert_eq!(review.locktime(), 500_000);
    assert_eq!(review.total_input_amount(), 1_000_000);
    assert_eq!(review.total_output_amount(), 900_000);
    assert_eq!(review.fee(), 100_000);
    assert_eq!(review.fee_policy_identifier(), b"QK-FEE-POLICY-V1");
    assert_eq!(review.fee_policy().estimated_vsize(), 246);
    assert_eq!(review.fee_policy().fee_rate_msat_per_vbyte(), 406_504);
    assert_eq!(
        review.fee_policy().warnings().collect::<Vec<_>>(),
        [FeeWarning::RateHigh, FeeWarning::ShareHigh]
    );
    assert_eq!(review.direct_rbf(), DirectRbf::Signaled);
    assert_eq!(review.input_count(), 1);
    assert_eq!(review.inputs().len(), 1);
    assert_eq!(review.inputs()[0].direct_rbf(), DirectRbf::Signaled);
    assert_eq!(review.inputs()[0].effective_sighash(), 1);
    assert_eq!(review.inputs()[0].branch(), 0);
    assert_eq!(review.inputs()[0].child_index(), 0);

    assert_eq!(review.outputs().len(), 4);
    assert!(matches!(
        review.outputs()[0].ownership(),
        ReviewV2OutputOwnership::ProvenChange { child_index: 0 }
    ));
    match review.outputs()[1].ownership() {
        ReviewV2OutputOwnership::ProvenSelfTransfer {
            child_index,
            witness_program,
        } => {
            assert_eq!(*child_index, 65_535);
            assert_eq!(
                witness_program.as_slice(),
                &review.outputs()[1].script_pubkey()[2..]
            );
        }
        other => panic!("unexpected self-transfer fact: {other:?}"),
    }
    assert!(matches!(
        review.outputs()[2].ownership(),
        ReviewV2OutputOwnership::NotOwned {
            recipient_type: RecipientType::P2wpkh,
            data,
        } if data.as_slice() == [0x11; 20]
    ));
    assert!(matches!(
        review.outputs()[3].ownership(),
        ReviewV2OutputOwnership::NotOwned {
            recipient_type: RecipientType::OpReturn,
            data,
        } if data.as_slice() == [0xaa, 0xbb, 0xcc]
    ));
}

#[test]
fn source_is_retained_and_conflicts_reject_before_semantics() {
    let s0 = hex(field(FIXTURE, "s0_hex: "));
    let descriptor = descriptor();
    let sd = parse(&s0, InputSource::MicroSd).unwrap();
    let qr = parse(&s0, InputSource::Qr).unwrap();

    assert_eq!(
        build_review_v2(&sd, &descriptor, context(InputSource::Qr)),
        Err(ReviewV2Error::SourceMismatch)
    );
    assert_eq!(
        build_review_v2(&qr, &descriptor, context(InputSource::MicroSd)),
        Err(ReviewV2Error::SourceMismatch)
    );
    let qr_review = build_review_v2(&qr, &descriptor, context(InputSource::Qr)).unwrap();
    assert_eq!(&qr_review.canonical_bytes()[..3], &[2, 1, 2]);
}

#[test]
fn syntactically_valid_bad_signature_is_not_cryptographically_promoted() {
    let mut s0 = hex(field(FIXTURE, "s0_hex: "));
    let parsed = parse(&s0, InputSource::MicroSd).unwrap();
    let member_key = parsed
        .input_records(0)
        .unwrap()
        .find(|record| record.key_type == 0x06)
        .unwrap()
        .key_data
        .to_vec();
    let insertion = parsed.input_map_span(0).unwrap().end - 1;
    drop(parsed);

    let mut record = vec![34, 0x02];
    record.extend_from_slice(&member_key);
    record.extend_from_slice(&[9, 0x30, 0x06, 0x02, 0x01, 0x01, 0x02, 0x01, 0x01, 0x01]);
    s0.splice(insertion..insertion, record);

    let view = parse(&s0, InputSource::MicroSd).unwrap();
    let descriptor = descriptor();
    let review = build_review_v2(&view, &descriptor, context(InputSource::MicroSd)).unwrap();
    assert_ne!(
        review.s0_sha256().as_slice(),
        hex(field(FIXTURE, "s0_sha256: "))
    );
    assert!(matches!(
        analyze_descriptor_ownership(&view, &descriptor),
        Err(error) if error.category == SemanticCategory::SignatureVerificationFailed
    ));
}

#[test]
fn witness_utxo_and_sighash_fail_with_their_named_categories() {
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
        build_review_v2(&view, &descriptor, context(InputSource::MicroSd)),
        Err(ReviewV2Error::Semantic(error))
            if error.category == SemanticCategory::WitnessUtxoMismatch
    ));

    let mut overlapping = witness_mismatch;
    overlapping[sighash_offset] = 2;
    let view = parse(&overlapping, InputSource::MicroSd).unwrap();
    assert!(matches!(
        build_review_v2(&view, &descriptor, context(InputSource::MicroSd)),
        Err(ReviewV2Error::Semantic(error))
            if error.category == SemanticCategory::WitnessUtxoMismatch
    ));

    let mut unsupported_sighash = original;
    unsupported_sighash[sighash_offset] = 2;
    let view = parse(&unsupported_sighash, InputSource::MicroSd).unwrap();
    assert!(matches!(
        build_review_v2(&view, &descriptor, context(InputSource::MicroSd)),
        Err(ReviewV2Error::Semantic(error))
            if error.category == SemanticCategory::UnsupportedSighash
    ));
}

#[test]
fn returned_surface_has_no_verified_or_threshold_claim() {
    let source = include_str!("../src/review_v2.rs");
    let crate_root = include_str!("../src/lib.rs");
    let public_review = source
        .split("pub struct ReviewV2 {")
        .nth(1)
        .unwrap()
        .split("impl ReviewV2")
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
        "analyze_review_v2_semantics",
        "ReviewV2SemanticAnalysis",
        "ReviewV2SemanticInput",
        "ReviewV2SemanticOutput",
        "ReviewV2InputFacts",
        "ReviewV2OutputFacts",
        "ReviewV2Facts",
        "build_review_v2_from_facts",
    ] {
        assert!(!crate_root.contains(private_seam), "{private_seam}");
    }
}
