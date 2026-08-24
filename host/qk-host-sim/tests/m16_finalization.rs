//! M16 capability finalization through the complete public M15 workflow.

use qk_descriptor::{parse_descriptor_pair, DescriptorPair};
use qk_host_model::transaction_policy::TransactionState;
use qk_host_sim::{
    ApplyOutcome, DescriptorRole, ReviewBoundWorkflow, ReviewWorkflowEvent, SubmittedSignature,
    ThresholdCompletePsbt,
};
use qk_psbt::{parse, InputSource, PsbtView};
use std::collections::{BTreeMap, BTreeSet};

#[path = "../../qk-psbt/src/sha256.rs"]
mod fixture_sha256;

const FIXTURE: &str = include_str!("fixtures/m16_finalization.txt");

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

fn header_field(name: &str) -> &str {
    FIXTURE
        .lines()
        .take_while(|line| !line.starts_with("case: "))
        .find_map(|line| line.strip_prefix(name))
        .expect("header field")
}

fn field<'a>(case: &'a Case, name: &str) -> &'a str {
    case.get(name).map(String::as_str).expect("fixture field")
}

fn case_named<'a>(all: &'a [Case], name: &str) -> &'a Case {
    all.iter()
        .find(|case| field(case, "case") == name)
        .expect("named case")
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

fn encode_hex(value: &[u8]) -> String {
    value.iter().map(|byte| format!("{byte:02x}")).collect()
}

fn sha256(value: &[u8]) -> [u8; 32] {
    let mut hasher = fixture_sha256::Sha256::new();
    hasher.update(value).expect("fixture hash update");
    hasher.finalize().expect("fixture hash finalization")
}

fn descriptor(case: &Case) -> DescriptorPair {
    parse_descriptor_pair(
        field(case, "receive_descriptor").as_bytes(),
        field(case, "change_descriptor").as_bytes(),
    )
    .expect("fixture descriptor")
}

fn decoded_responses(case: &Case) -> Vec<(u32, DescriptorRole, Vec<u8>)> {
    let count: usize = field(case, "response_count")
        .parse()
        .expect("response count");
    (0..count)
        .map(|index| {
            let mut parts = field(case, &format!("response_{index}")).split('|');
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

fn produce_m15(case: &Case) -> ThresholdCompletePsbt {
    let initial = decode_hex(field(case, "initial_psbt_hex"));
    let descriptor = descriptor(case);
    let decoded = decoded_responses(case);
    let submitted = submitted(&decoded);
    let mut workflow = reach_sign_permitted(&initial, &descriptor);
    let complete = workflow
        .insert_and_emit_signatures(&submitted)
        .expect("public M15 workflow produces threshold capability");
    assert_eq!(complete.as_bytes(), decode_hex(field(case, "m15_psbt_hex")));
    assert_eq!(workflow.state(), TransactionState::Ready);
    assert!(!workflow.is_finished());
    assert!(!workflow.has_review_binding());
    assert!(!workflow.has_approved_token());
    complete
}

fn csv_counts(case: &Case, name: &str) -> Vec<usize> {
    field(case, name)
        .split(',')
        .map(|value| value.parse().expect("count"))
        .collect()
}

fn partial_counts(bytes: &[u8]) -> Vec<usize> {
    let view = parse(bytes, InputSource::MicroSd).expect("PSBT parse");
    (0..view.input_map_count())
        .map(|input_index| {
            view.input_records(input_index)
                .expect("input records")
                .filter(|record| record.key_type == 0x02)
                .count()
        })
        .collect()
}

fn type05_counts(bytes: &[u8]) -> Vec<usize> {
    let view = parse(bytes, InputSource::MicroSd).expect("PSBT parse");
    (0..view.input_map_count())
        .map(|input_index| {
            view.input_records(input_index)
                .expect("input records")
                .filter(|record| record.key_type == 0x05)
                .count()
        })
        .collect()
}

fn assert_payload(case: &Case, prefix: &str) {
    let bytes = decode_hex(field(case, &format!("{prefix}_hex")));
    assert_eq!(
        bytes.len(),
        field(case, &format!("{prefix}_len"))
            .parse()
            .expect("payload length")
    );
    assert_eq!(
        encode_hex(&sha256(&bytes)),
        field(case, &format!("{prefix}_sha256"))
    );
}

fn assert_final_oracles(case: &Case) {
    let complete = produce_m15(case);
    let finalized = complete
        .finalize_and_extract()
        .expect("M16 finalization succeeds");
    assert_eq!(
        finalized.finalized_psbt(),
        decode_hex(field(case, "finalized_psbt_hex"))
    );
    assert_eq!(
        finalized.raw_transaction(),
        decode_hex(field(case, "raw_tx_hex"))
    );
    let txid: [u8; 32] = decode_hex(field(case, "txid_raw"))
        .try_into()
        .expect("txid width");
    let wtxid: [u8; 32] = decode_hex(field(case, "wtxid_raw"))
        .try_into()
        .expect("wtxid width");
    assert_eq!(finalized.txid(), txid);
    assert_eq!(finalized.wtxid(), wtxid);
    let mut txid_display = txid;
    txid_display.reverse();
    let mut wtxid_display = wtxid;
    wtxid_display.reverse();
    assert_eq!(encode_hex(&txid_display), field(case, "txid_display"));
    assert_eq!(encode_hex(&wtxid_display), field(case, "wtxid_display"));
}

#[test]
fn fixture_identity_inventory_and_literal_payloads_are_closed() {
    assert_eq!(FIXTURE.len(), 46_154);
    assert_eq!(FIXTURE.bytes().filter(|byte| *byte == b'\n').count(), 186);
    assert_eq!(FIXTURE.bytes().filter(|byte| *byte == b'\r').count(), 0);
    assert!(FIXTURE.ends_with('\n'));
    assert_eq!(
        encode_hex(&sha256(FIXTURE.as_bytes())),
        "d597de0b1ba578366e34dd39d34a438eb19c7fcd8b16b3631d286e8958eaac8b"
    );
    assert_eq!(header_field("fixture_profile: "), "QuietKey/M16/Rust/v1");
    assert_eq!(header_field("case_count: "), "5");
    let all = cases();
    assert_eq!(all.len(), 5);
    assert_eq!(
        all.iter()
            .map(|case| field(case, "case"))
            .collect::<Vec<_>>(),
        [
            "M16-PRESENT-TYPE05-TWO-SIGNATURES",
            "M16-ABSENT-TYPE05-TWO-SIGNATURES",
            "M16-UNKNOWN-PRESERVATION-TWO-SIGNATURES",
            "M16-MULTI-INPUT-THREE-SUBMISSIONS",
            "M16-MULTI-INPUT-EXISTING-THREE-ROLE-INPUT",
        ]
    );
    let mut names = BTreeSet::new();
    for case in &all {
        assert!(names.insert(field(case, "case")));
        for prefix in ["initial_psbt", "m15_psbt", "finalized_psbt", "raw_tx"] {
            assert_payload(case, prefix);
        }
        let input_count: usize = field(case, "input_count").parse().expect("input count");
        assert_eq!(csv_counts(case, "initial_type05_counts").len(), input_count);
        assert_eq!(csv_counts(case, "m15_type05_counts").len(), input_count);
        assert_eq!(
            csv_counts(case, "initial_partial_signature_counts").len(),
            input_count
        );
        assert_eq!(
            csv_counts(case, "m15_partial_signature_counts").len(),
            input_count
        );
        let initial = decode_hex(field(case, "initial_psbt_hex"));
        let m15 = decode_hex(field(case, "m15_psbt_hex"));
        assert_eq!(
            type05_counts(&initial),
            csv_counts(case, "initial_type05_counts")
        );
        assert_eq!(type05_counts(&m15), csv_counts(case, "m15_type05_counts"));
        assert_eq!(
            partial_counts(&initial),
            csv_counts(case, "initial_partial_signature_counts")
        );
        assert_eq!(
            partial_counts(&m15),
            csv_counts(case, "m15_partial_signature_counts")
        );
    }
}

#[test]
fn every_case_uses_public_m15_then_matches_final_psbt_raw_and_ids() {
    for case in cases() {
        assert_final_oracles(&case);
    }
}

#[test]
fn present_and_absent_type05_paths_have_identical_final_transaction_oracles() {
    let all = cases();
    let present = case_named(&all, "M16-PRESENT-TYPE05-TWO-SIGNATURES");
    let absent = case_named(&all, "M16-ABSENT-TYPE05-TWO-SIGNATURES");
    assert_eq!(csv_counts(present, "m15_type05_counts"), [1]);
    assert_eq!(csv_counts(absent, "m15_type05_counts"), [0]);
    assert_eq!(csv_counts(present, "m15_partial_signature_counts"), [2]);
    assert_eq!(csv_counts(absent, "m15_partial_signature_counts"), [2]);
    for field_name in ["finalized_psbt_hex", "raw_tx_hex", "txid_raw", "wtxid_raw"] {
        assert_eq!(field(present, field_name), field(absent, field_name));
    }
    assert_final_oracles(present);
    assert_final_oracles(absent);
}

#[test]
fn multi_input_three_submission_and_three_role_existing_paths_are_reachable() {
    let all = cases();
    let submissions = case_named(&all, "M16-MULTI-INPUT-THREE-SUBMISSIONS");
    assert_eq!(field(submissions, "input_count"), "2");
    assert_eq!(field(submissions, "response_count"), "3");
    assert_eq!(
        csv_counts(submissions, "initial_partial_signature_counts"),
        [1, 0]
    );
    assert_eq!(
        csv_counts(submissions, "m15_partial_signature_counts"),
        [2, 2]
    );
    assert_final_oracles(submissions);

    let existing = case_named(&all, "M16-MULTI-INPUT-EXISTING-THREE-ROLE-INPUT");
    assert_eq!(field(existing, "input_count"), "2");
    assert_eq!(field(existing, "response_count"), "2");
    assert_eq!(
        csv_counts(existing, "initial_partial_signature_counts"),
        [3, 0]
    );
    assert_eq!(csv_counts(existing, "m15_partial_signature_counts"), [3, 2]);
    assert_final_oracles(existing);
}

fn matching_record_count(
    view: &PsbtView<'_>,
    scope: &str,
    expected_type: u64,
    full_key: &[u8],
    value: &[u8],
) -> usize {
    let matches = |record: &qk_psbt::Record<'_>| {
        record.key_type == expected_type && record.full_key == full_key && record.value == value
    };
    match scope {
        "global" => view.global_records().filter(matches).count(),
        "input" => view
            .input_records(0)
            .expect("input records")
            .filter(matches)
            .count(),
        "output" => view
            .output_records(0)
            .expect("output records")
            .filter(matches)
            .count(),
        _ => panic!("closed scope"),
    }
}

#[test]
fn unknown_and_proprietary_records_are_preserved_exactly_in_every_scope() {
    let all = cases();
    let case = case_named(&all, "M16-UNKNOWN-PRESERVATION-TWO-SIGNATURES");
    let complete = produce_m15(case);
    let complete_bytes = complete.as_bytes().to_vec();
    let finalized = complete
        .finalize_and_extract()
        .expect("unknown-bearing finalization");
    assert_eq!(
        finalized.finalized_psbt(),
        decode_hex(field(case, "finalized_psbt_hex"))
    );
    let before = parse(&complete_bytes, InputSource::MicroSd).expect("M15 parse");
    let after = parse(finalized.finalized_psbt(), InputSource::MicroSd).expect("final parse");
    for scope in ["global", "input", "output"] {
        for key_type in [255u64, 256] {
            let full_key = decode_hex(field(case, &format!("unknown_{scope}_{key_type}_full_key")));
            let value = decode_hex(field(case, &format!("unknown_{scope}_{key_type}_value")));
            assert_eq!(
                matching_record_count(&before, scope, key_type, &full_key, &value),
                1
            );
            assert_eq!(
                matching_record_count(&after, scope, key_type, &full_key, &value),
                1
            );
        }
        let full_key = decode_hex(field(case, &format!("proprietary_{scope}_full_key")));
        let value = decode_hex(field(case, &format!("proprietary_{scope}_value")));
        assert_eq!(
            matching_record_count(&before, scope, 252, &full_key, &value),
            1
        );
        assert_eq!(
            matching_record_count(&after, scope, 252, &full_key, &value),
            1
        );
    }
}
