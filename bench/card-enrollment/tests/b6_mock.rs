use std::io::Write;
use std::process::{Command, Stdio};

use qk_card_enrollment::{
    b6_exchange, fixed_sitting_plan, run_b6, B6Error, B6Exchange, B6Observer, B6Outcome,
    B6SignatureFacts, SittingMode, B6_DIGEST, B6_EXCHANGES_PER_SESSION, B6_EXPANDED_REQUEST_BYTES,
    B6_PLAN_SHA256, B6_REVIEW_HASH, B6_SESSION_COUNT, B6_SESSION_IDS, B6_TOTAL_EXCHANGES,
    B6_WALLET_ID,
};
use qk_card_model::{CardModel, RESPONSE_BYTES};
use qk_card_protocol::{parse_command, CommandRef, Media, Mode};

#[derive(Default)]
struct Observer {
    facts: Vec<B6SignatureFacts>,
    comparisons: Vec<B6Outcome>,
    sessions: usize,
}
impl B6Observer for Observer {
    fn session_start(&mut self, _: usize, _: &str) -> Result<(), B6Error> {
        Ok(())
    }
    fn session_end(&mut self, _: usize, _: &str, _: B6Outcome) -> Result<(), B6Error> {
        self.sessions += 1;
        Ok(())
    }
    fn record_request(&mut self, _: &B6Exchange) -> Result<(), B6Error> {
        Ok(())
    }
    fn record_response(&mut self, _: &B6Exchange, _: &[u8]) -> Result<(), B6Error> {
        Ok(())
    }
    fn record_comparison(&mut self, _: &B6Exchange, outcome: B6Outcome) -> Result<(), B6Error> {
        self.comparisons.push(outcome);
        Ok(())
    }
    fn record_signature(&mut self, _: &B6Exchange, facts: B6SignatureFacts) -> Result<(), B6Error> {
        self.facts.push(facts);
        Ok(())
    }
}

#[test]
fn expanded_plan_has_exact_bounds_order_fields_and_sha256() {
    let mut bytes = Vec::new();
    let mut count = 0;
    for (session, session_id) in B6_SESSION_IDS.iter().enumerate() {
        for position in 0..B6_EXCHANGES_PER_SESSION {
            let exchange = b6_exchange(session, position).unwrap();
            assert_eq!(exchange.index(), count);
            assert_eq!(exchange.session_index(), session);
            assert_eq!(exchange.position(), position);
            match parse_command(Media::ContactT1, exchange.request()).unwrap() {
                CommandRef::Select => assert_eq!(position, 0),
                CommandRef::OpenSession {
                    mode,
                    session_id: actual,
                } => {
                    assert_eq!(position, 1);
                    assert_eq!(mode, Mode::Normal);
                    assert_eq!(actual, session_id);
                }
                CommandRef::SignDigest {
                    envelope,
                    wallet_id,
                    review_hash,
                    input_index,
                    branch,
                    child_index,
                    digest,
                } => {
                    assert_eq!(envelope.session_id(), session_id);
                    assert_eq!(envelope.sequence(), (position - 1) as u32);
                    assert_eq!(wallet_id, &B6_WALLET_ID);
                    assert_eq!(review_hash, &B6_REVIEW_HASH);
                    assert_eq!(input_index, (position - 2) as u32);
                    assert_eq!(branch, 0);
                    assert_eq!(child_index, 0);
                    assert_eq!(digest, &B6_DIGEST);
                }
                _ => panic!("unexpected operation"),
            }
            bytes.extend_from_slice(exchange.request());
            count += 1;
        }
    }
    assert_eq!(count, B6_TOTAL_EXCHANGES);
    assert_eq!(bytes.len(), B6_EXPANDED_REQUEST_BYTES);
    let mut child = Command::new("shasum")
        .args(["-a", "256"])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .spawn()
        .unwrap();
    child.stdin.take().unwrap().write_all(&bytes).unwrap();
    let output = child.wait_with_output().unwrap();
    assert!(output.status.success());
    assert_eq!(
        String::from_utf8(output.stdout)
            .unwrap()
            .split_whitespace()
            .next(),
        Some(B6_PLAN_SHA256)
    );
    assert_eq!(
        B6_PLAN_SHA256,
        "44ca636942407f6523d5641cf1bf4396bb07b980ec534395514dee0abd31b348"
    );
    assert_eq!(
        b6_exchange(B6_SESSION_COUNT, 0),
        Err(B6Error::B6SequenceViolation)
    );
    assert_eq!(
        b6_exchange(0, B6_EXCHANGES_PER_SESSION),
        Err(B6Error::B6SequenceViolation)
    );
}

#[test]
fn deterministic_model_second_signature_is_rejected_for_repeated_r() {
    let mut model = CardModel::new();
    let plan = fixed_sitting_plan(SittingMode::ProvisionGolden).unwrap();
    for exchange in plan.exchanges() {
        let mut output = [0; RESPONSE_BYTES];
        let length = model
            .process_apdu(Media::ContactT1, exchange.request(), &mut output)
            .unwrap();
        assert_eq!(&output[..length], exchange.expected_response());
    }
    let mut observer = Observer::default();
    let mut calls = 0;
    let summary = run_b6(
        &mut observer,
        |request, output| {
            calls += 1;
            let mut response = [0; RESPONSE_BYTES];
            let length = model
                .process_apdu(Media::ContactT1, request, &mut response)
                .unwrap();
            output[..length].copy_from_slice(&response[..length]);
            Ok(length)
        },
        || Ok("2026-09-07T12:00:00Z".into()),
    );
    assert_eq!(summary.outcome, B6Outcome::Reject(B6Error::B6RepeatedR));
    assert_eq!(calls, 4);
    assert_eq!(summary.transmit_calls, 4);
    assert_eq!(summary.received_responses, 4);
    assert_eq!(summary.verified_signatures, 1);
    assert_eq!(summary.completed_sessions, 0);
    assert_eq!(observer.sessions, 1);
    assert_eq!(observer.facts.len(), 2);
    assert_eq!(observer.facts[0].r, observer.facts[1].r);
    assert!(observer.facts.iter().all(|facts| facts.verified));
    assert_eq!(
        observer.comparisons.last(),
        Some(&B6Outcome::Reject(B6Error::B6RepeatedR))
    );
}

#[test]
fn transport_failure_is_first_and_no_later_request_is_sent() {
    let mut observer = Observer::default();
    let summary = run_b6(
        &mut observer,
        |_, _| Err(qk_card_enrollment::SittingTransportFailure::Failed),
        || Ok("2026-09-07T12:00:00Z".into()),
    );
    assert_eq!(
        summary.outcome,
        B6Outcome::Reject(B6Error::B6TransmitFailed)
    );
    assert_eq!(summary.transmit_calls, 1);
    assert_eq!(summary.received_responses, 0);
    assert_eq!(observer.sessions, 1);
}
