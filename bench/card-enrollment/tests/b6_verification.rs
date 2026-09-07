use qk_card_enrollment::{
    run_b6, B6Error, B6Exchange, B6Observer, B6Outcome, B6RunSummary, B6SignatureFacts,
    SittingTransportFailure, B6_DIGEST, B6_PUBLIC_KEY,
};

const GOLDEN: &str =
    include_str!("../../../host/qk-card-protocol/tests/fixtures/card_protocol_v1.txt");

#[derive(Default)]
struct Observer {
    facts: Vec<B6SignatureFacts>,
    outcomes: Vec<B6Outcome>,
    responses: Vec<Vec<u8>>,
    ends: usize,
}
impl B6Observer for Observer {
    fn session_start(&mut self, _: usize, _: &str) -> Result<(), B6Error> {
        Ok(())
    }
    fn session_end(&mut self, _: usize, _: &str, _: B6Outcome) -> Result<(), B6Error> {
        self.ends += 1;
        Ok(())
    }
    fn record_request(&mut self, _: &B6Exchange) -> Result<(), B6Error> {
        Ok(())
    }
    fn record_response(&mut self, _: &B6Exchange, bytes: &[u8]) -> Result<(), B6Error> {
        self.responses.push(bytes.to_vec());
        Ok(())
    }
    fn record_comparison(&mut self, _: &B6Exchange, outcome: B6Outcome) -> Result<(), B6Error> {
        self.outcomes.push(outcome);
        Ok(())
    }
    fn record_signature(&mut self, _: &B6Exchange, facts: B6SignatureFacts) -> Result<(), B6Error> {
        self.facts.push(facts);
        Ok(())
    }
}

fn decode(value: &str) -> Vec<u8> {
    assert!(value.len().is_multiple_of(2));
    value
        .as_bytes()
        .chunks_exact(2)
        .map(|pair| u8::from_str_radix(std::str::from_utf8(pair).unwrap(), 16).unwrap())
        .collect()
}
fn golden_response() -> Vec<u8> {
    decode(
        GOLDEN
            .lines()
            .find_map(|line| line.strip_prefix("normal_sign_0_response_hex: "))
            .unwrap(),
    )
}
fn response_for(request: &[u8]) -> Vec<u8> {
    match request[1] {
        0xa4 => vec![0x90, 0],
        0x10 => {
            let mut response = vec![1];
            response.extend_from_slice(&request[7..23]);
            response.extend_from_slice(&[0, 0, 0, 0, 0x90, 0]);
            response
        }
        0x15 => {
            let mut response = golden_response();
            response[..21].copy_from_slice(&request[5..26]);
            response[53..57].copy_from_slice(&request[90..94]);
            response
        }
        _ => panic!("unexpected plan command"),
    }
}
fn altered_sign(mut mutate: impl FnMut(&mut Vec<u8>)) -> (B6RunSummary, Observer) {
    let mut observer = Observer::default();
    let mut signatures = 0;
    let result = run_b6(
        &mut observer,
        |request, output| {
            let mut response = response_for(request);
            if request[1] == 0x15 {
                signatures += 1;
                if signatures > 1 {
                    return Err(SittingTransportFailure::Failed);
                }
                mutate(&mut response);
            }
            output[..response.len()].copy_from_slice(&response);
            Ok(response.len())
        },
        || Ok("2026-09-07T12:00:00Z".into()),
    );
    (result, observer)
}

#[test]
fn every_sign_binding_has_a_named_rejection_before_curve_verification() {
    for (offset, error) in [
        (0, B6Error::B6ResponseVersionMismatch),
        (1, B6Error::B6ResponseSessionMismatch),
        (20, B6Error::B6ResponseCounterMismatch),
        (21, B6Error::B6ResponseReviewHashMismatch),
        (56, B6Error::B6ResponseInputIndexMismatch),
        (57, B6Error::B6ResponseKeyMismatch),
        (90, B6Error::B6ResponseDerLengthMismatch),
    ] {
        let (summary, observer) = altered_sign(|response| response[offset] ^= 1);
        assert_eq!(summary.outcome, B6Outcome::Reject(error));
        assert_eq!(summary.transmit_calls, 3);
        assert_eq!(summary.received_responses, 3);
        assert_eq!(summary.verified_signatures, 0);
        assert!(
            observer.facts.is_empty(),
            "{error} must precede signature facts"
        );
        assert_eq!(observer.ends, 1);
    }
}

#[test]
fn status_is_checked_first_and_full_hostile_response_is_recorded() {
    let (summary, observer) = altered_sign(|response| {
        let last = response.len() - 1;
        response[last] = 1;
        response[0] = 99;
        response[57] = 99;
    });
    assert_eq!(
        summary.outcome,
        B6Outcome::Reject(B6Error::B6StatusRejected)
    );
    assert_eq!(observer.responses.last().unwrap()[0], 99);
    assert_eq!(observer.responses.last().unwrap().last(), Some(&1));
    assert!(observer.facts.is_empty());
}

#[test]
fn high_s_is_normalized_before_verification_and_flagged_without_changing_r() {
    let raw = golden_response();
    let low_der = &raw[91..raw.len() - 2];
    let mut high = vec![0x30, 0x46, 2, 0x21];
    high.extend_from_slice(&low_der[4..37]);
    high.extend_from_slice(&[2, 0x21, 0]);
    high.extend_from_slice(&decode(
        "bf61fc4abd1a78f9fa367c00a6442598aebf994ca058bf34e8a747b94a49ad0a",
    ));
    let parsed_high = qk_secp::signature_parse_der(&high).unwrap();
    let key = qk_secp::pubkey_parse_compressed(&B6_PUBLIC_KEY).unwrap();
    assert!(qk_secp::ecdsa_verify(&parsed_high, &B6_DIGEST, &key).is_err());

    let (low_summary, low_observer) = altered_sign(|_| {});
    let (high_summary, high_observer) = altered_sign(|response| {
        response.truncate(91);
        response[90] = high.len() as u8;
        response.extend_from_slice(&high);
        response.extend_from_slice(&[0x90, 0]);
    });
    for summary in [low_summary, high_summary] {
        assert_eq!(summary.verified_signatures, 1);
        assert_eq!(
            summary.outcome,
            B6Outcome::Reject(B6Error::B6TransmitFailed)
        );
    }
    assert!(!low_observer.facts[0].normalized);
    assert!(high_observer.facts[0].normalized);
    assert!(high_observer.facts[0].verified);
    assert_eq!(high_observer.facts[0].r, low_observer.facts[0].r);
    assert_eq!(high_summary.normalized_signatures, 1);
    assert_eq!(low_summary.normalized_signatures, 0);
}

#[test]
fn malformed_der_and_invalid_curve_signature_are_distinct() {
    let (summary, observer) = altered_sign(|response| response[91] = 0x31);
    assert_eq!(summary.outcome, B6Outcome::Reject(B6Error::B6DerRejected));
    assert!(observer.facts.is_empty());
    let (summary, observer) = altered_sign(|response| {
        let last_s = response.len() - 3;
        response[last_s] ^= 1;
    });
    assert_eq!(
        summary.outcome,
        B6Outcome::Reject(B6Error::B6SignatureVerificationFailed)
    );
    assert_eq!(observer.facts.len(), 1);
    assert!(!observer.facts[0].verified);
    assert_eq!(summary.transmit_calls, 3);
}

#[test]
fn truncated_excess_and_inconsistent_der_tail_stop_before_a_next_command() {
    for (kind, error) in [
        (0, B6Error::B6ResponseLengthMismatch),
        (1, B6Error::B6ResponseLimitExceeded),
        (2, B6Error::B6ResponseDerLengthMismatch),
    ] {
        let (summary, _) = altered_sign(|response| match kind {
            0 => *response = vec![0x90, 0],
            1 => {
                response.resize(219, 0);
                response[217..].copy_from_slice(&[0x90, 0]);
            }
            _ => {
                response.insert(response.len() - 2, 0);
            }
        });
        assert_eq!(summary.outcome, B6Outcome::Reject(error));
        assert_eq!(summary.transmit_calls, 3);
    }
}

#[test]
fn select_and_open_are_exact_before_any_sign_can_be_sent() {
    for (instruction, mutation, error) in [
        (0xa4, 0, B6Error::B6ResponseLengthMismatch),
        (0x10, 0, B6Error::B6ResponseVersionMismatch),
        (0x10, 1, B6Error::B6ResponseSessionMismatch),
        (0x10, 20, B6Error::B6ResponseCounterMismatch),
    ] {
        let mut observer = Observer::default();
        let summary = run_b6(
            &mut observer,
            |request, output| {
                let mut response = response_for(request);
                if request[1] == instruction {
                    if instruction == 0xa4 {
                        response.insert(0, 0);
                    } else {
                        response[mutation] ^= 1;
                    }
                }
                output[..response.len()].copy_from_slice(&response);
                Ok(response.len())
            },
            || Ok("2026-09-07T12:00:00Z".into()),
        );
        assert_eq!(summary.outcome, B6Outcome::Reject(error));
        assert_eq!(
            summary.transmit_calls,
            if instruction == 0xa4 { 1 } else { 2 }
        );
    }
}
