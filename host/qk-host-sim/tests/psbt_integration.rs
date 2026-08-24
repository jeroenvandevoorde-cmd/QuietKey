//! Production review-binding integration over the exact public M14 fixture.

use qk_descriptor::parse_descriptor_pair;
use qk_host_model::transaction_policy::TransactionState;
use qk_host_sim::{ApplyOutcome, ReviewBoundWorkflow, ReviewWorkflowEvent};
use qk_psbt::InputSource;

const REVIEW_FIXTURE: &str = include_str!("../../qk-psbt/tests/fixtures/review_binding.txt");
const DESCRIPTOR_FIXTURE: &str =
    include_str!("../../qk-psbt/tests/fixtures/descriptor_ownership.txt");

fn field<'a>(text: &'a str, name: &str) -> &'a str {
    text.lines()
        .find_map(|line| line.strip_prefix(name))
        .expect("fixture field must exist")
}

fn decode_hex(value: &str) -> Vec<u8> {
    assert_eq!(value.len() % 2, 0);
    value
        .as_bytes()
        .chunks_exact(2)
        .map(|pair| {
            let text = core::str::from_utf8(pair).expect("fixture hex is ASCII");
            u8::from_str_radix(text, 16).expect("fixture hex is valid")
        })
        .collect()
}

#[test]
fn exact_m14_fixture_reaches_sign_permitted_for_both_sources() {
    let s0 = decode_hex(field(REVIEW_FIXTURE, "s0_hex: "));
    let receive = field(DESCRIPTOR_FIXTURE, "receive: ").as_bytes();
    let change = field(DESCRIPTOR_FIXTURE, "change: ").as_bytes();
    let descriptor = parse_descriptor_pair(receive, change).expect("descriptor fixture is valid");

    for source in [InputSource::MicroSd, InputSource::Qr] {
        let mut workflow = ReviewBoundWorkflow::new(&s0, &descriptor, source);
        assert_eq!(
            workflow.apply(ReviewWorkflowEvent::Wake),
            Ok(ApplyOutcome::Continue(TransactionState::Ready))
        );
        assert_eq!(
            workflow.apply(ReviewWorkflowEvent::BeginValidation),
            Ok(ApplyOutcome::Continue(TransactionState::ReviewReady))
        );
        assert!(workflow.has_review_binding());
        assert_eq!(
            workflow.apply(ReviewWorkflowEvent::RequestApproval),
            Ok(ApplyOutcome::Continue(TransactionState::Confirming))
        );
        assert_eq!(
            workflow.apply(ReviewWorkflowEvent::Approve),
            Ok(ApplyOutcome::Continue(TransactionState::Approved))
        );
        assert!(workflow.has_approved_token());
        assert_eq!(
            workflow.apply(ReviewWorkflowEvent::BeginRevalidation),
            Ok(ApplyOutcome::Continue(TransactionState::Revalidating))
        );
        assert_eq!(
            workflow.revalidate(),
            Ok(ApplyOutcome::Continue(TransactionState::SignPermitted))
        );
        assert!(!workflow.is_finished());
    }
}

#[test]
fn public_wrapper_source_has_no_critical_escape_or_s0_copy_path() {
    let source = include_str!("../src/lib.rs");
    let wrapper = source
        .split("pub struct ReviewBoundWorkflow")
        .nth(1)
        .expect("wrapper declaration exists");
    let wrapper = wrapper
        .split("impl<'a> ReviewBoundWorkflow")
        .next()
        .expect("wrapper declaration terminates");
    assert!(wrapper.contains("s0: &'a [u8]"));
    assert!(!wrapper.contains("Vec<u8>"));
    assert!(!wrapper.contains("Box<[u8]>"));
    assert!(!source.contains("to_vec"));
    assert!(!source.contains("copy_from_slice"));
    assert!(!source.contains("clone_from_slice"));
    assert!(!source.contains("Clone for ReviewBoundWorkflow"));

    let ordinary = source
        .split("pub enum ReviewWorkflowEvent")
        .nth(1)
        .expect("ordinary event enum exists")
        .split('}')
        .next()
        .expect("ordinary event enum terminates");
    for forbidden in [
        "ValidationPassed",
        "ReviewConstructed",
        "RevalidationPassed",
        "SignatureProduced",
    ] {
        assert!(!ordinary.contains(forbidden));
    }
}
