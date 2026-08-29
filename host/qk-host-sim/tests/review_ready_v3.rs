//! Parallel schema-v3 ReviewReady workflow over the registered v2 GOLDEN facts.

use qk_descriptor::{parse_descriptor_pair_v2, DescriptorPairV2};
use qk_host_model::transaction_policy::TransactionState;
use qk_host_sim::{ReviewReadyV3Error, ReviewReadyV3Workflow};
use qk_psbt::InputSource;

const REVIEW_FIXTURE: &str = include_str!("../../qk-psbt/tests/fixtures/review_v3.txt");
const DESCRIPTOR_FIXTURE: &str =
    include_str!("../../qk-descriptor/tests/fixtures/descriptor_pairs.txt");

fn field(name: &str) -> &'static str {
    REVIEW_FIXTURE
        .lines()
        .find_map(|line| line.strip_prefix(&format!("{name}: ")))
        .expect("review-v3 fixture field")
}

fn descriptor_field(name: &str) -> &'static str {
    let golden = DESCRIPTOR_FIXTURE
        .split("\n\n")
        .find(|block| block.lines().any(|line| line == "case: GOLDEN"))
        .expect("GOLDEN descriptor block");
    golden
        .lines()
        .find_map(|line| line.strip_prefix(&format!("{name}: ")))
        .expect("GOLDEN descriptor field")
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

fn decode_hex_32(value: &str) -> [u8; 32] {
    decode_hex(value).try_into().expect("exact 32-byte field")
}

fn descriptor() -> DescriptorPairV2 {
    parse_descriptor_pair_v2(
        descriptor_field("receive").as_bytes(),
        descriptor_field("change").as_bytes(),
    )
    .expect("GOLDEN descriptor pair")
}

fn ready_workflow() -> ReviewReadyV3Workflow {
    let s0 = decode_hex(field("s0_hex"));
    let mut workflow = ReviewReadyV3Workflow::new(descriptor()).expect("workflow");
    workflow
        .intake(&s0, InputSource::MicroSd)
        .expect("immutable S0 intake");
    workflow.wake().expect("wake");
    workflow.begin_validation().expect("begin validation");
    workflow.validate().expect("validate");
    workflow.construct_review().expect("construct and rebind");
    workflow
}

#[test]
fn registered_s0_reaches_exact_schema_v3_review_ready() {
    let s0 = decode_hex(field("s0_hex"));
    let workflow = ready_workflow();
    assert_eq!(workflow.state(), TransactionState::ReviewReady);
    assert!(!workflow.is_finished());
    let ready = workflow.review_ready().expect("ReviewReadyV3");
    assert_eq!(ready.s0_len(), s0.len());
    assert_eq!(ready.s0_sha256(), decode_hex_32(field("s0_sha256")));
    assert_eq!(ready.input_source(), InputSource::MicroSd);
    assert_eq!(ready.review().schema_version(), 3);
    assert_eq!(
        ready.review().canonical_bytes(),
        decode_hex(field("canonical_review_v3_hex"))
    );
    assert_eq!(ready.review_hash(), decode_hex_32(field("review_hash")));
}

#[test]
fn wrong_order_rejects_and_terminates_without_a_review() {
    let s0 = decode_hex(field("s0_hex"));
    let mut workflow = ReviewReadyV3Workflow::new(descriptor()).expect("workflow");
    workflow
        .intake(&s0, InputSource::MicroSd)
        .expect("immutable S0 intake");
    assert!(matches!(
        workflow.begin_validation(),
        Err(ReviewReadyV3Error::WorkflowRejected(_))
    ));
    assert!(workflow.is_finished());
    assert_eq!(workflow.state(), TransactionState::Locked);
    assert!(workflow.review_ready().is_none());
}
