//! M14's exact public D-09 review-binding goldens.

use qk_descriptor::{parse_descriptor_pair, DescriptorPair};
use qk_psbt::{
    build_review, parse, InputSource, ReviewContext, ReviewError, ReviewNetwork,
    ReviewOutputOwnership, VerifiedAggregateStatus, VerifiedInputStatus,
};

const FIXTURE: &str = include_str!("fixtures/review_binding.txt");
const M11: &str = include_str!("fixtures/descriptor_ownership.txt");

fn field<'a>(block: &'a str, name: &str) -> &'a str {
    block
        .lines()
        .find_map(|line| line.strip_prefix(name))
        .unwrap()
}

fn case(name: &str) -> &'static str {
    FIXTURE
        .split("\n\n")
        .find(|block| block.lines().any(|line| line == format!("case: {name}")))
        .unwrap()
}

fn hex(text: &str) -> Vec<u8> {
    assert_eq!(text.len() % 2, 0);
    (0..text.len())
        .step_by(2)
        .map(|position| u8::from_str_radix(&text[position..position + 2], 16).unwrap())
        .collect()
}

fn descriptor() -> DescriptorPair {
    let receive = M11
        .lines()
        .find_map(|line| line.strip_prefix("receive: "))
        .unwrap();
    let change = M11
        .lines()
        .find_map(|line| line.strip_prefix("change: "))
        .unwrap();
    parse_descriptor_pair(receive.as_bytes(), change.as_bytes()).unwrap()
}

fn context(source: InputSource) -> ReviewContext {
    ReviewContext {
        network: ReviewNetwork::BitcoinMainnet,
        input_source: source,
    }
}

#[test]
fn exact_fixture_canonical_bytes_hash_and_stable_facts() {
    let block = case("M14-FULL");
    let s0 = hex(field(block, "s0_hex: "));
    let view = parse(&s0, InputSource::MicroSd).unwrap();
    let review = build_review(&view, &descriptor(), context(InputSource::MicroSd)).unwrap();

    let expected_canonical = hex(field(block, "canonical_review_hex: "));
    if review.canonical_bytes() != expected_canonical {
        let difference = review
            .canonical_bytes()
            .iter()
            .zip(&expected_canonical)
            .position(|(actual, expected)| actual != expected)
            .unwrap();
        panic!(
            "canonical difference at {difference}: {:02x} != {:02x}",
            review.canonical_bytes()[difference],
            expected_canonical[difference]
        );
    }
    assert_eq!(
        review.canonical_bytes().len(),
        field(block, "canonical_review_len: ")
            .parse::<usize>()
            .unwrap()
    );
    assert_eq!(
        review.review_hash().unwrap().as_slice(),
        hex(field(block, "review_hash: "))
    );
    assert_eq!(
        review.s0_sha256().as_slice(),
        hex(field(block, "s0_sha256: "))
    );
    assert_eq!(
        review.wallet_id().as_slice(),
        hex(field(block, "wallet_id: "))
    );
    assert_eq!(
        review.unsigned_tx_bytes(),
        hex(field(block, "unsigned_tx_hex: "))
    );
    assert_eq!(review.version(), 2);
    assert_eq!(review.locktime(), 500_000);
    assert_eq!(review.inputs().len(), 1);
    assert_eq!(review.outputs().len(), 4);
    assert_eq!(review.total_input_amount(), 1_000_000);
    assert_eq!(review.total_output_amount(), 900_000);
    assert_eq!(review.fee(), 100_000);
    assert_eq!(
        review.aggregate_status(),
        VerifiedAggregateStatus::AllInputsBelowThreshold
    );
    let input = review.inputs()[0];
    assert_eq!(input.index, 0);
    assert_eq!(input.effective_sighash, 1);
    assert_eq!(input.branch, 0);
    assert_eq!(input.child_index, 0);
    assert_eq!(input.verified_signature_count, 0);
    assert_eq!(input.verified_status, VerifiedInputStatus::BelowThreshold);
    assert!(matches!(
        review.outputs()[0].ownership,
        ReviewOutputOwnership::Change(0)
    ));
    assert!(matches!(
        review.outputs()[1].ownership,
        ReviewOutputOwnership::SelfTransfer(65_535)
    ));
    assert!(matches!(
        review.outputs()[2].ownership,
        ReviewOutputOwnership::NotOwned(_)
    ));
    assert!(matches!(
        review.outputs()[3].ownership,
        ReviewOutputOwnership::NotOwned(_)
    ));
}

#[test]
fn raw_s0_mutation_preserves_unsigned_semantics_but_changes_binding() {
    let full = case("M14-FULL");
    let mutated = case("M14-RAW-MUTATION");
    let full_s0 = hex(field(full, "s0_hex: "));
    let mutated_s0 = hex(field(mutated, "s0_hex: "));
    let full_view = parse(&full_s0, InputSource::MicroSd).unwrap();
    let mutated_view = parse(&mutated_s0, InputSource::MicroSd).unwrap();
    let descriptor = descriptor();
    let first = build_review(&full_view, &descriptor, context(InputSource::MicroSd)).unwrap();
    let second = build_review(&mutated_view, &descriptor, context(InputSource::MicroSd)).unwrap();

    assert_eq!(first.unsigned_tx_bytes(), second.unsigned_tx_bytes());
    assert_eq!(first.inputs(), second.inputs());
    assert_eq!(first.outputs(), second.outputs());
    assert_ne!(first.s0_sha256(), second.s0_sha256());
    assert_ne!(first.review_hash().unwrap(), second.review_hash().unwrap());
    assert_eq!(
        second.canonical_bytes(),
        hex(field(mutated, "canonical_review_hex: "))
    );
    assert_eq!(
        second.review_hash().unwrap().as_slice(),
        hex(field(mutated, "review_hash: "))
    );
}

#[test]
fn retained_parse_source_is_the_only_review_provenance() {
    let s0 = hex(field(case("M14-FULL"), "s0_hex: "));
    let descriptor = descriptor();
    let micro_view = parse(&s0, InputSource::MicroSd).unwrap();
    let qr_view = parse(&s0, InputSource::Qr).unwrap();
    assert_eq!(micro_view.source(), InputSource::MicroSd);
    assert_eq!(qr_view.source(), InputSource::Qr);
    let first = build_review(&micro_view, &descriptor, context(InputSource::MicroSd)).unwrap();
    let fixed = build_review(&micro_view, &descriptor, context(InputSource::MicroSd)).unwrap();
    let qr = build_review(&qr_view, &descriptor, context(InputSource::Qr)).unwrap();

    assert_eq!(first.canonical_bytes(), fixed.canonical_bytes());
    assert_eq!(first.review_hash().unwrap(), fixed.review_hash().unwrap());
    assert_eq!(&first.canonical_bytes()[..3], &[1, 1, 1]);
    assert_eq!(&qr.canonical_bytes()[..3], &[1, 1, 2]);
    assert_eq!(&first.canonical_bytes()[3..], &qr.canonical_bytes()[3..]);
    assert_ne!(first.review_hash().unwrap(), qr.review_hash().unwrap());
}

#[test]
fn context_source_must_match_the_immutable_parse_source_before_analysis() {
    let s0 = hex(field(case("M14-FULL"), "s0_hex: "));
    let descriptor = descriptor();
    let sd_view = parse(&s0, InputSource::MicroSd).unwrap();
    let qr_view = parse(&s0, InputSource::Qr).unwrap();

    assert!(matches!(
        build_review(&sd_view, &descriptor, context(InputSource::Qr)),
        Err(ReviewError::SourceMismatch)
    ));
    assert!(matches!(
        build_review(&qr_view, &descriptor, context(InputSource::MicroSd)),
        Err(ReviewError::SourceMismatch)
    ));
}

#[test]
fn canonical_schema_inventory_consumes_exactly_all_bytes() {
    let s0 = hex(field(case("M14-FULL"), "s0_hex: "));
    let view = parse(&s0, InputSource::MicroSd).unwrap();
    let descriptor = descriptor();
    let review = build_review(&view, &descriptor, context(InputSource::MicroSd)).unwrap();
    let bytes = review.canonical_bytes();
    let mut cursor = 0usize;
    let take = |cursor: &mut usize, count: usize| {
        let start = *cursor;
        *cursor += count;
        &bytes[start..*cursor]
    };
    let u32le = |cursor: &mut usize| u32::from_le_bytes(take(cursor, 4).try_into().unwrap());

    assert_eq!(take(&mut cursor, 3), [1, 1, 1]);
    take(&mut cursor, 32 + 32 + 12);
    let unsigned_len = u32le(&mut cursor) as usize;
    assert_eq!(take(&mut cursor, unsigned_len), review.unsigned_tx_bytes());
    assert_eq!(u32le(&mut cursor), 2);
    assert_eq!(u32le(&mut cursor), 500_000);
    let inputs = u32le(&mut cursor);
    assert_eq!(inputs, 1);
    for _ in 0..inputs {
        take(&mut cursor, 4 + 32 + 4 + 8);
        let script_len = u32le(&mut cursor) as usize;
        take(&mut cursor, script_len);
        take(&mut cursor, 4 + 4 + 4 + 4 + 4 + 1);
    }
    let outputs = u32le(&mut cursor);
    assert_eq!(outputs, 4);
    for _ in 0..outputs {
        take(&mut cursor, 4 + 8);
        let script_len = u32le(&mut cursor) as usize;
        take(&mut cursor, script_len);
        match take(&mut cursor, 1)[0] {
            1 => {
                take(&mut cursor, 1);
                let data_len = u32le(&mut cursor) as usize;
                take(&mut cursor, data_len);
            }
            2 | 3 => {
                take(&mut cursor, 4);
            }
            code => panic!("unexpected ownership code {code}"),
        }
    }
    take(&mut cursor, 8 + 8 + 8 + 1);
    assert_eq!(cursor, bytes.len());
}

#[test]
fn exact_candidate_cap_arithmetic_is_frozen() {
    assert_eq!(qk_psbt::limits::MAX_CANONICAL_REVIEW_BYTES, 19_272);
    assert_eq!(124 + 5_535 + 100 * 107 + (185 + 31 * 88), 19_272);
    assert_eq!(19_272 + 23 + 1, 19_296);
}

#[test]
fn production_review_source_has_no_session_or_opaque_binding_inputs() {
    let source = include_str!("../src/review.rs");
    for forbidden in [
        "CycleToken",
        "SessionId",
        "session_id",
        "preflight_blob",
        "caller_hash",
        "caller-supplied hash",
    ] {
        assert!(!source.contains(forbidden), "{forbidden}");
    }
}
