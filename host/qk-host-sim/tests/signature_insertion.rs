//! M15 final-only insertion against the complete public NEVER-FUND fixture.

use qk_descriptor::{parse_descriptor_pair, DescriptorPair};
use qk_host_model::transaction_policy::TransactionState;
use qk_host_sim::{
    ApplyOutcome, DescriptorRole, ReviewBoundWorkflow, ReviewWorkflowEvent,
    SignatureInsertionError, SubmittedSignature,
};
use qk_psbt::{
    build_review, canonical_serialize, parse, InputSource, ReviewContext, ReviewError,
    ReviewNetwork, SemanticCategory, VerifiedAggregateStatus,
};
use std::collections::{BTreeMap, BTreeSet};

#[path = "../../qk-psbt/src/sha256.rs"]
mod fixture_sha256;

const FIXTURE: &str = include_str!("fixtures/signature_insertion.txt");

type Case = BTreeMap<String, String>;

fn cases() -> Vec<Case> {
    FIXTURE
        .split("\n\n")
        .filter(|block| block.lines().any(|line| line.starts_with("case: ")))
        .map(|block| {
            let mut fields = Case::new();
            for line in block.lines() {
                let (name, value) = line.split_once(": ").expect("fixture field separator");
                assert!(fields.insert(name.to_owned(), value.to_owned()).is_none());
            }
            fields
        })
        .collect()
}

fn field<'a>(case: &'a Case, name: &str) -> &'a str {
    case.get(name).map(String::as_str).expect("fixture field")
}

fn decode_hex(value: &str) -> Vec<u8> {
    assert_eq!(value.len() % 2, 0);
    value
        .as_bytes()
        .chunks_exact(2)
        .map(|pair| {
            u8::from_str_radix(core::str::from_utf8(pair).expect("ASCII hex"), 16)
                .expect("valid hex")
        })
        .collect()
}

fn descriptor(case: &Case) -> DescriptorPair {
    parse_descriptor_pair(
        field(case, "receive_descriptor").as_bytes(),
        field(case, "change_descriptor").as_bytes(),
    )
    .expect("fixture descriptor pair")
}

fn decoded_responses(case: &Case) -> Vec<(u32, DescriptorRole, Vec<u8>)> {
    let count: usize = field(case, "response_count")
        .parse()
        .expect("response count");
    (0..count)
        .map(|index| {
            let value = field(case, &format!("response_{index}"));
            let mut parts = value.split('|');
            let input_index = parts.next().expect("input").parse().expect("input u32");
            let role = match parts.next().expect("role") {
                "A" => DescriptorRole::A,
                "B" => DescriptorRole::B,
                "C" => DescriptorRole::C,
                _ => panic!("closed role"),
            };
            let der = decode_hex(parts.next().expect("DER"));
            assert!(parts.next().is_none());
            (input_index, role, der)
        })
        .collect()
}

fn submitted(decoded: &[(u32, DescriptorRole, Vec<u8>)]) -> Vec<SubmittedSignature<'_>> {
    decoded
        .iter()
        .map(|(input_index, role, der)| SubmittedSignature {
            input_index: *input_index,
            role: *role,
            der_signature: der,
        })
        .collect()
}

fn reach_sign_permitted<'a>(
    s0: &'a [u8],
    descriptor: &'a DescriptorPair,
) -> ReviewBoundWorkflow<'a> {
    let mut workflow = ReviewBoundWorkflow::new(s0, descriptor, InputSource::MicroSd);
    assert_eq!(
        workflow.apply(ReviewWorkflowEvent::Wake),
        Ok(ApplyOutcome::Continue(TransactionState::Ready))
    );
    assert_eq!(
        workflow.apply(ReviewWorkflowEvent::BeginValidation),
        Ok(ApplyOutcome::Continue(TransactionState::ReviewReady))
    );
    assert_eq!(
        workflow.apply(ReviewWorkflowEvent::RequestApproval),
        Ok(ApplyOutcome::Continue(TransactionState::Confirming))
    );
    assert_eq!(
        workflow.apply(ReviewWorkflowEvent::Approve),
        Ok(ApplyOutcome::Continue(TransactionState::Approved))
    );
    assert_eq!(
        workflow.apply(ReviewWorkflowEvent::BeginRevalidation),
        Ok(ApplyOutcome::Continue(TransactionState::Revalidating))
    );
    assert_eq!(
        workflow.revalidate(),
        Ok(ApplyOutcome::Continue(TransactionState::SignPermitted))
    );
    workflow
}

fn case_named<'a>(all: &'a [Case], name: &str) -> &'a Case {
    all.iter()
        .find(|case| field(case, "case") == name)
        .expect("named fixture case")
}

#[test]
fn fixture_identity_inventory_and_every_literal_payload_are_closed() {
    assert_eq!(FIXTURE.len(), 240_876);
    assert_eq!(FIXTURE.bytes().filter(|byte| *byte == b'\n').count(), 779);
    assert_eq!(FIXTURE.bytes().filter(|byte| *byte == b'\r').count(), 0);
    assert!(FIXTURE.ends_with('\n'));
    let mut hasher = fixture_sha256::Sha256::new();
    hasher
        .update(FIXTURE.as_bytes())
        .expect("fixture hash input");
    let expected_hash: [u8; 32] =
        decode_hex("897673082a8560d095ffa4372f57536dd03b39054aa8b3a14a64b57ef90291f0")
            .try_into()
            .expect("32-byte fixture hash");
    assert_eq!(hasher.finalize().expect("fixture hash"), expected_hash);
    let all = cases();
    assert_eq!(all.len(), 22);
    let expected_names = [
        "M15-GOLDEN-SHUFFLED",
        "M15-GOLDEN-CANONICAL",
        "M15-EXISTING-ONE",
        "M15-MIXED-RESUME",
        "M15-DUPLICATE-SIGNATURE-EXISTING",
        "M15-DUPLICATE-SIGNATURE-BATCH",
        "M15-DUPLICATE-ROLE",
        "M15-SIGNATURE-CONFLICT",
        "M15-THRESHOLD-ALREADY-MET",
        "M15-ALL-INPUTS-COMPLETE",
        "M15-STRICT-DER",
        "M15-HIGH-S",
        "M15-CALLER-SIGHASH-BYTE",
        "M15-CRYPTO-INVALID",
        "M15-WRONG-ROLE",
        "M15-INCOMPLETE-THRESHOLD",
        "M15-THRESHOLD-WOULD-BE-EXCEEDED",
        "M15-INPUT-OUT-OF-RANGE",
        "M15-WRONG-DIGEST",
        "M15-MISSING-TOKEN",
        "M15-STALE-TOKEN",
        "M15-REVIEW-HASH-MISMATCH",
    ];
    assert_eq!(
        all.iter()
            .map(|case| field(case, "case"))
            .collect::<Vec<_>>(),
        expected_names
    );
    let mut names = BTreeSet::new();
    let mut classes = BTreeMap::<&str, usize>::new();
    let mut responses = 0usize;
    let mut stages = 0usize;
    for case in &all {
        assert!(names.insert(field(case, "case")));
        *classes.entry(field(case, "class")).or_default() += 1;
        let response_count: usize = field(case, "response_count").parse().expect("count");
        let stage_count: usize = field(case, "stage_count").parse().expect("count");
        responses += response_count;
        stages += stage_count;
        let expected_fields = 23 + (2 * response_count) + (11 * stage_count);
        assert_eq!(case.len(), expected_fields, "{}", field(case, "case"));
        assert_eq!(
            decode_hex(field(case, "initial_psbt_hex"))
                .len()
                .to_string(),
            field(case, "initial_psbt_len")
        );
        assert_eq!(
            field(case, "initial_psbt_hex"),
            field(case, "baseline_psbt_hex")
        );
        assert_eq!(
            field(case, "initial_psbt_len"),
            field(case, "baseline_psbt_len")
        );
        assert_eq!(
            field(case, "initial_psbt_sha256"),
            field(case, "baseline_psbt_sha256")
        );
        assert_eq!(
            decode_hex(field(case, "approved_review_canonical_hex"))
                .len()
                .to_string(),
            field(case, "approved_review_len")
        );
        for index in 0..response_count {
            let oracle = decode_hex(field(case, &format!("response_{index}_expected_pubkey")));
            assert_eq!(oracle.len(), 33);
        }
        for index in 1..=stage_count {
            assert_eq!(
                decode_hex(field(case, &format!("stage_{index}_psbt_hex")))
                    .len()
                    .to_string(),
                field(case, &format!("stage_{index}_psbt_len"))
            );
            assert_eq!(
                decode_hex(field(case, &format!("stage_{index}_actual_review_hex")))
                    .len()
                    .to_string(),
                field(case, &format!("stage_{index}_actual_review_len"))
            );
            assert_eq!(
                decode_hex(field(case, &format!("stage_{index}_frozen_review_hex")))
                    .len()
                    .to_string(),
                field(case, &format!("stage_{index}_frozen_review_len"))
            );
        }
    }
    assert_eq!(classes.get("emission"), Some(&4));
    assert_eq!(classes.get("named-rejection"), Some(&15));
    assert_eq!(classes.get("binding-rejection"), Some(&3));
    assert_eq!(responses, 47);
    assert_eq!(stages, 13);
}

#[test]
fn four_complete_emissions_match_every_embedded_final_byte() {
    for case in cases()
        .iter()
        .filter(|case| field(case, "class") == "emission")
    {
        let original = decode_hex(field(case, "initial_psbt_hex"));
        let preserved = original.clone();
        let descriptor = descriptor(case);
        let decoded = decoded_responses(case);
        let submitted = submitted(&decoded);
        let mut workflow = reach_sign_permitted(&original, &descriptor);
        let artifact = workflow
            .insert_and_emit_signatures(&submitted)
            .expect("emission case succeeds");
        let expected = decode_hex(field(case, "final_psbt_hex"));
        assert_eq!(artifact.as_bytes(), expected);
        assert_eq!(
            artifact.as_bytes().len().to_string(),
            field(case, "final_psbt_len")
        );
        assert_eq!(workflow.state(), TransactionState::Ready);
        assert!(!workflow.is_finished());
        assert!(!workflow.has_review_binding());
        assert!(!workflow.has_approved_token());
        assert_eq!(original, preserved);

        let view = parse(artifact.as_bytes(), InputSource::MicroSd).expect("final parse");
        assert_eq!(
            canonical_serialize(&view).expect("final serialize"),
            artifact.as_bytes()
        );
        let review = build_review(
            &view,
            &descriptor,
            ReviewContext {
                network: ReviewNetwork::BitcoinMainnet,
                input_source: InputSource::MicroSd,
            },
        )
        .expect("final review");
        assert_eq!(
            review.aggregate_status(),
            VerifiedAggregateStatus::VerifyAndExportOnly
        );
        assert!(review
            .inputs()
            .iter()
            .all(|input| input.verified_signature_count == 2));
    }
}

#[test]
fn arrival_permutations_and_resume_states_emit_one_identical_fixed_point() {
    let all = cases();
    let golden = decode_hex(field(
        case_named(&all, "M15-GOLDEN-SHUFFLED"),
        "final_psbt_hex",
    ));
    for name in [
        "M15-GOLDEN-CANONICAL",
        "M15-EXISTING-ONE",
        "M15-MIXED-RESUME",
    ] {
        assert_eq!(
            decode_hex(field(case_named(&all, name), "final_psbt_hex")),
            golden
        );
    }
    let view = parse(&golden, InputSource::MicroSd).expect("golden parse");
    for input_index in 0..view.input_map_count() {
        let keys = view
            .input_records(input_index)
            .expect("input records")
            .filter(|record| record.key_type == 0x02)
            .map(|record| record.key_data.to_vec())
            .collect::<Vec<_>>();
        assert_eq!(keys.len(), 2);
        assert!(keys[0] < keys[1]);
    }
    assert_eq!(canonical_serialize(&view).expect("fixed point"), golden);
}

fn assert_semantic_category(error: SignatureInsertionError, category: SemanticCategory) {
    match error {
        SignatureInsertionError::RevalidationFailed(ReviewError::Semantic(actual)) => {
            assert_eq!(actual.category, category)
        }
        other => panic!("unexpected error: {other:?}"),
    }
}

#[test]
fn named_duplicate_threshold_and_input_rejections_are_distinct_and_lock() {
    let all = cases();
    let table = [
        (
            "M15-DUPLICATE-SIGNATURE-EXISTING",
            SignatureInsertionError::DuplicateSignature,
        ),
        (
            "M15-DUPLICATE-SIGNATURE-BATCH",
            SignatureInsertionError::DuplicateSignature,
        ),
        ("M15-DUPLICATE-ROLE", SignatureInsertionError::DuplicateRole),
        (
            "M15-SIGNATURE-CONFLICT",
            SignatureInsertionError::SignatureConflict,
        ),
        (
            "M15-THRESHOLD-ALREADY-MET",
            SignatureInsertionError::ThresholdAlreadyMet,
        ),
        (
            "M15-ALL-INPUTS-COMPLETE",
            SignatureInsertionError::ThresholdAlreadyMet,
        ),
        (
            "M15-INCOMPLETE-THRESHOLD",
            SignatureInsertionError::ThresholdIncomplete,
        ),
        (
            "M15-THRESHOLD-WOULD-BE-EXCEEDED",
            SignatureInsertionError::ThresholdWouldBeExceeded,
        ),
        (
            "M15-INPUT-OUT-OF-RANGE",
            SignatureInsertionError::InputOutOfRange,
        ),
    ];
    for (name, expected) in table {
        let case = case_named(&all, name);
        let original = decode_hex(field(case, "initial_psbt_hex"));
        let descriptor = descriptor(case);
        let decoded = decoded_responses(case);
        let submitted = submitted(&decoded);
        let mut workflow = reach_sign_permitted(&original, &descriptor);
        let error = workflow
            .insert_and_emit_signatures(&submitted)
            .err()
            .expect(name);
        assert_eq!(error, expected, "{name}");
        assert_eq!(workflow.state(), TransactionState::Locked);
        assert!(workflow.is_finished());
        assert!(!workflow.has_review_binding());
        assert!(!workflow.has_approved_token());
    }
}

#[test]
fn malformed_high_s_wrong_role_and_wrong_digest_fail_through_existing_engine() {
    let all = cases();
    let table = [
        ("M15-STRICT-DER", SemanticCategory::StrictDer),
        ("M15-HIGH-S", SemanticCategory::HighS),
        ("M15-CALLER-SIGHASH-BYTE", SemanticCategory::StrictDer),
        (
            "M15-CRYPTO-INVALID",
            SemanticCategory::SignatureVerificationFailed,
        ),
        (
            "M15-WRONG-ROLE",
            SemanticCategory::SignatureVerificationFailed,
        ),
        (
            "M15-WRONG-DIGEST",
            SemanticCategory::SignatureVerificationFailed,
        ),
    ];
    for (name, category) in table {
        let case = case_named(&all, name);
        let original = decode_hex(field(case, "initial_psbt_hex"));
        let descriptor = descriptor(case);
        let decoded = decoded_responses(case);
        let submitted = submitted(&decoded);
        let mut workflow = reach_sign_permitted(&original, &descriptor);
        let error = workflow
            .insert_and_emit_signatures(&submitted)
            .err()
            .expect(name);
        assert_semantic_category(error, category);
        assert_eq!(workflow.state(), TransactionState::Locked);
        assert!(workflow.is_finished());
    }
}

#[test]
fn public_surface_exposes_no_signer_finalizer_or_intermediate_artifact() {
    let source = include_str!("../src/insertion.rs");
    for forbidden in [
        "fn sign(",
        "ecdsa_sign",
        "signature_create",
        "private_key",
        "secret_key",
        "nonce",
        "finalize",
        "extract_transaction",
        "intermediate_bytes",
    ] {
        assert!(!source.contains(forbidden), "{forbidden}");
    }
    assert!(source.contains("canonical_serialize"));
    assert!(source.contains("WorkflowEvent::SignatureProduced(token)"));
    assert_eq!(source.matches("build_review(").count(), 3);
    assert!(!source.contains("previous_review"));
    assert!(!source.contains("final_review"));
    assert!(!source.contains("qk_secp"));
}
