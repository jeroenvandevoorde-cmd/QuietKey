use std::collections::VecDeque;
use std::io::{self, Write};
use std::path::PathBuf;

use qk_card_enrollment::{
    run_management_observation, EnrollmentMetadata, EnrollmentMode, InitializationFields,
    ManagementObservationBackend, ManagementObservationMetadata, ManagementObservationTranscript,
    NegotiatedProtocol, ObservationError, ObservationOutcome, ObservationPhase, ObservationStatus,
    SittingError, SittingTransportFailure, INITIALIZE_UPDATE_COMMAND,
    KEY_INFORMATION_TEMPLATE_COMMAND, MANAGEMENT_CARD_RECOGNITION_COMMAND,
    MAX_OBSERVATION_RESPONSE_BYTES, MAX_READERS, MAX_READER_NAME_BYTES, REGISTERED_J3R180_ATR,
    SELECT_ISD_COMMAND, SITTING_READER_NAME,
};

const SOURCE_COMMIT: &str = "0123456789abcdef0123456789abcdef01234567";
const TIMESTAMP: &str = "2026-09-07T12:34:56Z";

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum FailAt {
    Establish,
    Enumerate,
    Connect,
    ConnectAfterRetainingCard,
    Reset,
    Status,
    Exchange(usize),
    ExchangeCaptureExceeded(usize),
    ExchangePanics(usize),
    Disconnect,
    IsConnectedPanics,
}

#[derive(Clone, Debug)]
struct ExchangeReply {
    bytes: Vec<u8>,
    reported_len: usize,
}

impl ExchangeReply {
    fn exact(bytes: Vec<u8>) -> Self {
        let reported_len = bytes.len();
        Self {
            bytes,
            reported_len,
        }
    }
}

#[derive(Debug)]
struct MockBackend {
    readers: Vec<Vec<u8>>,
    status: ObservationStatus,
    replies: VecDeque<ExchangeReply>,
    requests: Vec<Vec<u8>>,
    fail_at: Option<FailAt>,
    connected: bool,
    establish_calls: usize,
    connect_calls: usize,
    disconnect_calls: usize,
}

impl MockBackend {
    fn passing() -> Self {
        Self {
            readers: vec![SITTING_READER_NAME.to_vec()],
            status: ObservationStatus {
                atr: REGISTERED_J3R180_ATR.to_vec(),
                protocol: Some(NegotiatedProtocol::T1),
            },
            replies: passing_responses(0x02, None)
                .into_iter()
                .map(ExchangeReply::exact)
                .collect(),
            requests: Vec::new(),
            fail_at: None,
            connected: false,
            establish_calls: 0,
            connect_calls: 0,
            disconnect_calls: 0,
        }
    }

    fn with_responses(responses: Vec<Vec<u8>>) -> Self {
        let mut backend = Self::passing();
        backend.replies = responses.into_iter().map(ExchangeReply::exact).collect();
        backend
    }
}

impl ManagementObservationBackend for MockBackend {
    fn establish_context(&mut self) -> Result<(), SittingError> {
        self.establish_calls += 1;
        if self.fail_at == Some(FailAt::Establish) {
            return Err(SittingError::SittingContextUnavailable);
        }
        Ok(())
    }

    fn enumerate_readers(&mut self) -> Result<Vec<Vec<u8>>, SittingError> {
        if self.fail_at == Some(FailAt::Enumerate) {
            return Err(SittingError::SittingReaderEnumerationFailed);
        }
        Ok(self.readers.clone())
    }

    fn connect_exclusive(&mut self, reader_name: &[u8]) -> Result<(), SittingError> {
        assert_eq!(reader_name, SITTING_READER_NAME);
        self.connect_calls += 1;
        match self.fail_at {
            Some(FailAt::Connect) => Err(SittingError::SittingConnectFailed),
            Some(FailAt::ConnectAfterRetainingCard) => {
                self.connected = true;
                panic!("mock connect boundary panic after retaining card")
            }
            _ => {
                self.connected = true;
                Ok(())
            }
        }
    }

    fn is_connected(&self) -> bool {
        if self.fail_at == Some(FailAt::IsConnectedPanics) {
            panic!("mock connected-state boundary panic")
        }
        self.connected
    }

    fn reset(&mut self) -> Result<(), SittingError> {
        if self.fail_at == Some(FailAt::Reset) {
            return Err(SittingError::SittingResetFailed);
        }
        Ok(())
    }

    fn capture_status(&mut self) -> Result<ObservationStatus, SittingError> {
        if self.fail_at == Some(FailAt::Status) {
            return Err(SittingError::SittingStatusFailed);
        }
        Ok(self.status.clone())
    }

    fn exchange(
        &mut self,
        request: &[u8],
        response: &mut [u8; MAX_OBSERVATION_RESPONSE_BYTES],
    ) -> Result<usize, SittingTransportFailure> {
        let index = self.requests.len();
        self.requests.push(request.to_vec());
        if self.fail_at == Some(FailAt::Exchange(index)) {
            return Err(SittingTransportFailure::Failed);
        }
        if self.fail_at == Some(FailAt::ExchangeCaptureExceeded(index)) {
            return Err(SittingTransportFailure::CaptureExceeded);
        }
        if self.fail_at == Some(FailAt::ExchangePanics(index)) {
            panic!("mock exchange boundary panic")
        }
        let reply = self.replies.pop_front().expect("registered mock response");
        assert!(reply.bytes.len() <= response.len());
        response[..reply.bytes.len()].copy_from_slice(&reply.bytes);
        Ok(reply.reported_len)
    }

    fn disconnect_leave_card(&mut self) -> Result<(), SittingError> {
        self.disconnect_calls += 1;
        self.connected = false;
        if self.fail_at == Some(FailAt::Disconnect) {
            return Err(SittingError::SittingDisconnectFailed);
        }
        Ok(())
    }
}

#[test]
fn pass_runs_only_the_four_fixed_requests_and_retains_initialization_fields() {
    let mut backend = MockBackend::passing();
    let (summary, transcript) = run(&mut backend);

    assert_eq!(summary.outcome, ObservationOutcome::Pass);
    assert_eq!(summary.transmit_calls, 4);
    assert_eq!(summary.received_responses, 4);
    assert_eq!(summary.disconnect, Some(ObservationOutcome::Pass));
    assert_eq!(summary.first_failure, None);
    assert_eq!(
        summary.initialization,
        Some(InitializationFields {
            body_len: 28,
            key_version: 0x21,
            scp_version: 0x02,
            scp_i: None,
        })
    );
    assert_eq!(backend.connect_calls, 1);
    assert_eq!(backend.disconnect_calls, 1);
    assert!(!backend.connected);
    assert_eq!(
        backend.requests,
        [
            SELECT_ISD_COMMAND.to_vec(),
            MANAGEMENT_CARD_RECOGNITION_COMMAND.to_vec(),
            INITIALIZE_UPDATE_COMMAND.to_vec(),
            KEY_INFORMATION_TEMPLATE_COMMAND.to_vec(),
        ]
    );
    assert!(transcript.contains("transmit_call_count=4\n"));
    assert!(transcript.contains("received_response_count=4\n"));
    assert!(transcript.contains("event.0=WriteHeader:PASS\n"));
    assert!(transcript.contains("initialize.body_bytes=28\n"));
    assert!(transcript.contains("initialize.key_version_hex=21\n"));
    assert!(transcript.contains("initialize.scp_version_hex=02\n"));
    assert!(transcript.contains("initialize.scp_i_hex=NONE\n"));
    assert!(transcript.contains("first_failure=NONE\n"));
    assert!(transcript.ends_with("result=PASS\n"));
}

#[test]
fn e0_status_failure_retains_the_scp_fact_and_all_four_exchange_counts() {
    let mut responses = passing_responses(0x02, None);
    responses[3] = vec![0x6a, 0x82];
    let mut backend = MockBackend::with_responses(responses);
    let (summary, transcript) = run(&mut backend);

    assert_eq!(summary.transmit_calls, 4);
    assert_eq!(summary.received_responses, 4);
    assert_eq!(
        summary.initialization,
        Some(InitializationFields {
            body_len: 28,
            key_version: 0x21,
            scp_version: 0x02,
            scp_i: None,
        })
    );
    assert_eq!(
        summary.first_failure,
        Some(qk_card_enrollment::ObservationFailure {
            phase: ObservationPhase::KeyInformation,
            error: ObservationError::ObservationStatusRejected,
        })
    );
    assert_eq!(
        summary.outcome,
        ObservationOutcome::Reject(ObservationError::ObservationStatusRejected)
    );
    let parsed = transcript
        .find("initialize.scp_version_hex=02\n")
        .expect("parsed SCP field retained");
    let failed_response = transcript
        .find("exchange.3.rx_hex=6a82\n")
        .expect("failed E0 response retained");
    assert!(parsed < failed_response);
    assert!(transcript.contains("first_failure=KeyInformation:ObservationStatusRejected\n"));
}

#[test]
fn e0_contents_are_opaque_after_the_complete_outer_tlv_gate() {
    for e0 in [
        vec![0xe0, 0x00, 0x90, 0x00],
        vec![0xe0, 0x03, 0xff, 0x80, 0x00, 0x90, 0x00],
    ] {
        let mut responses = passing_responses(0x02, None);
        responses[3] = e0;
        let mut backend = MockBackend::with_responses(responses);
        let (summary, _) = run(&mut backend);
        assert_eq!(summary.outcome, ObservationOutcome::Pass);
    }
}

#[test]
fn all_outer_tlv_gates_accept_short_127_long_128_and_maximum_253_values() {
    for (phase, tag) in [
        (ObservationPhase::SelectIsd, 0x6f),
        (ObservationPhase::CardRecognition, 0x66),
        (ObservationPhase::KeyInformation, 0xe0),
    ] {
        for value_len in [127usize, 128, 253] {
            let mut value = vec![0xa5; value_len];
            if phase == ObservationPhase::CardRecognition {
                value[0] = 0x73;
            }
            let mut responses = passing_responses(0x02, None);
            responses[phase_index(phase)] = complete_tlv_response(tag, &value);
            let mut backend = MockBackend::with_responses(responses);
            let (summary, _) = run(&mut backend);
            assert_eq!(
                summary.outcome,
                ObservationOutcome::Pass,
                "{} value length {value_len}",
                phase.name()
            );
        }
    }
}

#[test]
fn all_outer_tlv_gates_reject_nonminimal_indefinite_82_truncated_and_trailing_forms() {
    for (phase, tag) in [
        (ObservationPhase::SelectIsd, 0x6f),
        (ObservationPhase::CardRecognition, 0x66),
        (ObservationPhase::KeyInformation, 0xe0),
    ] {
        let malformed = [
            {
                let mut response = vec![tag, 0x81, 0x7f];
                response.extend(std::iter::repeat_n(0x73, 127));
                response.extend_from_slice(&[0x90, 0x00]);
                response
            },
            vec![tag, 0x80, 0x90, 0x00],
            vec![tag, 0x82, 0x00, 0x01, 0x73, 0x90, 0x00],
            vec![tag, 0x02, 0x73, 0x90, 0x00],
            vec![tag, 0x00, 0x73, 0x90, 0x00],
        ];
        for response in malformed {
            let mut responses = passing_responses(0x02, None);
            responses[phase_index(phase)] = response;
            let mut backend = MockBackend::with_responses(responses);
            let (summary, _) = run(&mut backend);
            assert_eq!(
                summary.outcome,
                ObservationOutcome::Reject(ObservationError::ObservationTlvRejected),
                "{}",
                phase.name()
            );
        }
    }
}

#[test]
fn validation_precedence_is_availability_then_status_then_shape() {
    let cases = [
        (
            ObservationPhase::SelectIsd,
            Vec::new(),
            ObservationError::ObservationResponseLengthRejected,
        ),
        (
            ObservationPhase::SelectIsd,
            vec![0x90],
            ObservationError::ObservationResponseLengthRejected,
        ),
        (
            ObservationPhase::SelectIsd,
            vec![0x00, 0x00, 0x6a, 0x82],
            ObservationError::ObservationStatusRejected,
        ),
        (
            ObservationPhase::SelectIsd,
            vec![0x00, 0x00, 0x90, 0x00],
            ObservationError::ObservationTlvRejected,
        ),
        (
            ObservationPhase::InitializeUpdate,
            vec![0x6a, 0x82],
            ObservationError::ObservationStatusRejected,
        ),
        (
            ObservationPhase::InitializeUpdate,
            vec![0x90, 0x00],
            ObservationError::ObservationInitializeLengthRejected,
        ),
    ];

    for (phase, replacement, expected) in cases {
        let index = phase_index(phase);
        let mut responses = passing_responses(0x02, None);
        responses[index] = replacement;
        let mut backend = MockBackend::with_responses(responses);
        let (summary, _) = run(&mut backend);
        assert_eq!(
            summary.first_failure.map(|failure| failure.error),
            Some(expected),
            "phase {}",
            phase.name()
        );
    }
}

#[test]
fn every_scp03_i_byte_uses_only_bits_zero_and_four_for_the_length_formula() {
    for scp_i in 0u8..=u8::MAX {
        let mut backend = MockBackend::with_responses(passing_responses(0x03, Some(scp_i)));
        let (summary, _) = run(&mut backend);
        let expected_len = 29usize
            + if scp_i & 0x01 != 0 { 16 } else { 0 }
            + if scp_i & 0x10 != 0 { 3 } else { 0 };
        assert_eq!(summary.outcome, ObservationOutcome::Pass, "i={scp_i:02x}");
        assert_eq!(
            summary.initialization,
            Some(InitializationFields {
                body_len: expected_len,
                key_version: 0x21,
                scp_version: 0x03,
                scp_i: Some(scp_i),
            })
        );
    }
}

#[test]
fn scp01_and_scp02_have_no_i_and_require_exactly_twenty_eight_body_bytes() {
    for scp_version in [0x01, 0x02] {
        let mut backend = MockBackend::with_responses(passing_responses(scp_version, None));
        let (summary, _) = run(&mut backend);
        assert_eq!(summary.outcome, ObservationOutcome::Pass);
        assert_eq!(summary.initialization.expect("fields").scp_i, None);

        for length_delta in [-1isize, 1] {
            let mut responses = passing_responses(scp_version, None);
            let status_offset = responses[2].len() - 2;
            if length_delta < 0 {
                responses[2].remove(status_offset - 1);
            } else {
                responses[2].insert(status_offset, 0x00);
            }
            let mut backend = MockBackend::with_responses(responses);
            let (summary, _) = run(&mut backend);
            assert_eq!(
                summary.outcome,
                ObservationOutcome::Reject(ObservationError::ObservationInitializeLengthRejected)
            );
        }
    }
}

#[test]
fn every_initialize_form_rejects_exactly_one_byte_short_or_long_before_e0() {
    let forms = [
        (0x01, None, 28usize),
        (0x02, None, 28),
        (0x03, Some(0x00), 29),
        (0x03, Some(0x10), 32),
        (0x03, Some(0x01), 45),
        (0x03, Some(0x11), 48),
    ];
    for (scp_version, scp_i, expected_len) in forms {
        for delta in [-1isize, 1] {
            let mut responses = passing_responses(scp_version, scp_i);
            assert_eq!(responses[2].len() - 2, expected_len);
            let status_offset = responses[2].len() - 2;
            if delta < 0 {
                responses[2].remove(status_offset - 1);
            } else {
                responses[2].insert(status_offset, 0x00);
            }
            let mut backend = MockBackend::with_responses(responses);
            let (summary, _) = run(&mut backend);
            assert_eq!(
                summary.outcome,
                ObservationOutcome::Reject(ObservationError::ObservationInitializeLengthRejected),
                "SCP {scp_version:02x} i={scp_i:02x?} delta={delta}"
            );
            assert_eq!(summary.transmit_calls, 3);
            assert_eq!(summary.received_responses, 3);
            assert_eq!(backend.requests.len(), 3);
            assert_eq!(backend.requests[2], INITIALIZE_UPDATE_COMMAND);
            assert!(!backend
                .requests
                .iter()
                .any(|request| request.as_slice() == KEY_INFORMATION_TEMPLATE_COMMAND));
            assert_eq!(backend.disconnect_calls, 1);
            assert!(!backend.connected);
        }
    }
}

#[test]
fn unsupported_scp_is_named_separately_from_an_initialize_length_failure() {
    let mut responses = passing_responses(0x02, None);
    responses[2][11] = 0x04;
    let mut backend = MockBackend::with_responses(responses);
    let (summary, _) = run(&mut backend);
    assert_eq!(
        summary.outcome,
        ObservationOutcome::Reject(ObservationError::ObservationScpRejected)
    );

    let mut responses = passing_responses(0x03, Some(0x00));
    let status_offset = responses[2].len() - 2;
    responses[2].insert(status_offset, 0x00);
    let mut backend = MockBackend::with_responses(responses);
    let (summary, _) = run(&mut backend);
    assert_eq!(
        summary.outcome,
        ObservationOutcome::Reject(ObservationError::ObservationInitializeLengthRejected)
    );
}

#[test]
fn first_shape_failure_stops_all_remaining_commands_and_disconnects_once() {
    let mut responses = passing_responses(0x02, None);
    responses[1] = vec![0x66, 0x00, 0x90, 0x00];
    let mut backend = MockBackend::with_responses(responses);
    let (summary, _) = run(&mut backend);

    assert_eq!(summary.transmit_calls, 2);
    assert_eq!(summary.received_responses, 2);
    assert_eq!(backend.requests.len(), 2);
    assert_eq!(backend.disconnect_calls, 1);
    assert_eq!(
        summary.first_failure.map(|failure| failure.phase),
        Some(ObservationPhase::CardRecognition)
    );
    assert_eq!(
        summary.outcome,
        ObservationOutcome::Reject(ObservationError::ObservationTlvRejected)
    );
}

#[test]
fn pre_apdu_failures_keep_both_counts_zero_and_cleanup_a_connected_card() {
    for fail_at in [FailAt::Reset, FailAt::Status] {
        let mut backend = MockBackend::passing();
        backend.fail_at = Some(fail_at);
        let (summary, _) = run(&mut backend);
        assert_eq!(summary.transmit_calls, 0);
        assert_eq!(summary.received_responses, 0);
        assert_eq!(backend.disconnect_calls, 1);
        assert!(!backend.connected);
        assert!(matches!(summary.outcome, ObservationOutcome::Reject(_)));
    }
}

#[test]
fn a_connect_unwind_after_retaining_the_card_still_runs_leave_card_cleanup() {
    let mut backend = MockBackend::passing();
    backend.fail_at = Some(FailAt::ConnectAfterRetainingCard);
    let (summary, _) = run(&mut backend);

    assert_eq!(summary.transmit_calls, 0);
    assert_eq!(summary.received_responses, 0);
    assert_eq!(backend.disconnect_calls, 1);
    assert!(!backend.connected);
    assert_eq!(
        summary.first_failure,
        Some(qk_card_enrollment::ObservationFailure {
            phase: ObservationPhase::ExclusiveConnect,
            error: ObservationError::Sitting(SittingError::SittingBoundaryPanicked),
        })
    );
}

#[test]
fn a_connected_state_unwind_attempts_cleanup_and_retains_the_first_failure() {
    let mut backend = MockBackend::passing();
    backend.fail_at = Some(FailAt::IsConnectedPanics);
    let (summary, _) = run(&mut backend);

    assert_eq!(backend.disconnect_calls, 1);
    assert!(!backend.connected);
    assert_eq!(
        summary.first_failure,
        Some(qk_card_enrollment::ObservationFailure {
            phase: ObservationPhase::Disconnect,
            error: ObservationError::Sitting(SittingError::SittingBoundaryPanicked),
        })
    );
}

#[test]
fn disconnect_failure_never_replaces_an_earlier_response_failure() {
    let mut responses = passing_responses(0x02, None);
    responses[3] = vec![0x69, 0x85];
    let mut backend = MockBackend::with_responses(responses);
    backend.fail_at = Some(FailAt::Disconnect);
    let (summary, _) = run(&mut backend);

    assert_eq!(
        summary.first_failure,
        Some(qk_card_enrollment::ObservationFailure {
            phase: ObservationPhase::KeyInformation,
            error: ObservationError::ObservationStatusRejected,
        })
    );
    assert_eq!(
        summary.disconnect,
        Some(ObservationOutcome::Reject(ObservationError::Sitting(
            SittingError::SittingDisconnectFailed
        )))
    );
    assert_eq!(
        summary.outcome,
        ObservationOutcome::Reject(ObservationError::ObservationStatusRejected)
    );
}

#[test]
fn disconnect_failure_is_the_outcome_when_every_prior_phase_passed() {
    let mut backend = MockBackend::passing();
    backend.fail_at = Some(FailAt::Disconnect);
    let (summary, _) = run(&mut backend);
    assert_eq!(
        summary.first_failure.map(|failure| failure.phase),
        Some(ObservationPhase::Disconnect)
    );
    assert_eq!(
        summary.outcome,
        ObservationOutcome::Reject(ObservationError::Sitting(
            SittingError::SittingDisconnectFailed
        ))
    );
}

#[test]
fn exchange_failures_and_panics_are_named_and_never_count_an_uncaptured_response() {
    for index in 0..4 {
        for (fail_at, expected) in [
            (
                FailAt::Exchange(index),
                ObservationError::Sitting(SittingError::SittingTransmitFailed),
            ),
            (
                FailAt::ExchangePanics(index),
                ObservationError::Sitting(SittingError::SittingBoundaryPanicked),
            ),
        ] {
            let mut backend = MockBackend::passing();
            backend.fail_at = Some(fail_at);
            let (summary, _) = run(&mut backend);
            assert_eq!(summary.transmit_calls, index + 1);
            assert_eq!(summary.received_responses, index);
            assert_eq!(
                summary.first_failure.map(|failure| failure.error),
                Some(expected)
            );
            assert_eq!(backend.requests.len(), index + 1);
            assert_eq!(backend.disconnect_calls, 1);
        }
    }
}

#[test]
fn every_exchange_status_and_shape_failure_stops_at_that_exchange_with_exact_counts() {
    let phases = [
        ObservationPhase::SelectIsd,
        ObservationPhase::CardRecognition,
        ObservationPhase::InitializeUpdate,
        ObservationPhase::KeyInformation,
    ];
    let malformed_shapes = [
        vec![0x00, 0x00, 0x90, 0x00],
        vec![0x66, 0x00, 0x90, 0x00],
        vec![0x90, 0x00],
        vec![0x00, 0x00, 0x90, 0x00],
    ];
    let shape_errors = [
        ObservationError::ObservationTlvRejected,
        ObservationError::ObservationTlvRejected,
        ObservationError::ObservationInitializeLengthRejected,
        ObservationError::ObservationTlvRejected,
    ];

    for index in 0..4 {
        let mut status_responses = passing_responses(0x02, None);
        status_responses[index] = vec![0x6a, 0x82];
        let mut backend = MockBackend::with_responses(status_responses);
        let (summary, _) = run(&mut backend);
        assert_eq!(summary.transmit_calls, index + 1);
        assert_eq!(summary.received_responses, index + 1);
        assert_eq!(
            summary.first_failure,
            Some(qk_card_enrollment::ObservationFailure {
                phase: phases[index],
                error: ObservationError::ObservationStatusRejected,
            })
        );
        assert_eq!(backend.requests.len(), index + 1);

        let mut shape_responses = passing_responses(0x02, None);
        shape_responses[index] = malformed_shapes[index].clone();
        let mut backend = MockBackend::with_responses(shape_responses);
        let (summary, _) = run(&mut backend);
        assert_eq!(summary.transmit_calls, index + 1);
        assert_eq!(summary.received_responses, index + 1);
        assert_eq!(
            summary.first_failure,
            Some(qk_card_enrollment::ObservationFailure {
                phase: phases[index],
                error: shape_errors[index],
            })
        );
        assert_eq!(backend.requests.len(), index + 1);
    }
}

#[test]
fn response_capture_overflow_is_a_named_length_rejection() {
    let mut backend = MockBackend::passing();
    backend.replies[0].reported_len = MAX_OBSERVATION_RESPONSE_BYTES + 1;
    let (summary, _) = run(&mut backend);
    assert_eq!(summary.transmit_calls, 1);
    assert_eq!(summary.received_responses, 0);
    assert_eq!(
        summary.outcome,
        ObservationOutcome::Reject(ObservationError::ObservationResponseLengthRejected)
    );
}

#[test]
fn backend_capture_exceeded_is_the_same_named_length_rejection() {
    let mut backend = MockBackend::passing();
    backend.fail_at = Some(FailAt::ExchangeCaptureExceeded(0));
    let (summary, _) = run(&mut backend);
    assert_eq!(summary.transmit_calls, 1);
    assert_eq!(summary.received_responses, 0);
    assert_eq!(
        summary.outcome,
        ObservationOutcome::Reject(ObservationError::ObservationResponseLengthRejected)
    );
    assert_eq!(backend.disconnect_calls, 1);
}

#[test]
fn reader_identity_atr_and_protocol_are_all_checked_before_any_apdu() {
    let cases = [
        (Vec::<Vec<u8>>::new(), None, None),
        (
            vec![SITTING_READER_NAME.to_vec(), SITTING_READER_NAME.to_vec()],
            None,
            None,
        ),
        (vec![vec![0]], None, None),
        (vec![SITTING_READER_NAME.to_vec()], Some(vec![0x3b]), None),
        (
            vec![SITTING_READER_NAME.to_vec()],
            None,
            Some(NegotiatedProtocol::T0),
        ),
    ];
    for (readers, atr, protocol) in cases {
        let mut backend = MockBackend::passing();
        backend.readers = readers;
        if let Some(atr) = atr {
            backend.status.atr = atr;
        }
        if let Some(protocol) = protocol {
            backend.status.protocol = Some(protocol);
        }
        let (summary, _) = run(&mut backend);
        assert!(matches!(summary.outcome, ObservationOutcome::Reject(_)));
        assert_eq!(summary.transmit_calls, 0);
        assert_eq!(summary.received_responses, 0);
        assert!(backend.requests.is_empty());
    }
}

#[test]
fn reader_count_name_and_total_byte_bounds_keep_the_sitting_pre_apdu() {
    let cases = [
        (
            vec![b"r".to_vec(); MAX_READERS + 1],
            SittingError::SittingReaderCountExceeded,
        ),
        (
            vec![vec![b'r'; MAX_READER_NAME_BYTES + 1]],
            SittingError::SittingReaderNameRejected,
        ),
        (
            vec![vec![b'r'; MAX_READER_NAME_BYTES]; 17],
            SittingError::SittingReaderListTooLarge,
        ),
    ];
    for (readers, expected) in cases {
        let mut backend = MockBackend::passing();
        backend.readers = readers;
        let (summary, _) = run(&mut backend);
        assert_eq!(summary.transmit_calls, 0);
        assert_eq!(summary.received_responses, 0);
        assert_eq!(
            summary.outcome,
            ObservationOutcome::Reject(ObservationError::Sitting(expected))
        );
        assert_eq!(backend.connect_calls, 0);
    }
}

#[test]
fn observation_metadata_accepts_a_new_tool_commit_but_not_a_wrong_binding_or_name() {
    let valid = metadata_result(
        SOURCE_COMMIT,
        &format!("/tmp/qk-card-sitting-v1__management-observe__J3R180-02__{TIMESTAMP}.txt"),
        "J3R180-02",
    );
    assert!(valid.is_ok());

    let wrong_specimen = metadata_result(
        SOURCE_COMMIT,
        &format!("/tmp/qk-card-sitting-v1__management-observe__J3R180-02__{TIMESTAMP}.txt"),
        "J3R180-03",
    );
    assert_eq!(
        wrong_specimen.expect_err("wrong specimen"),
        ObservationError::Sitting(SittingError::SittingBindingMismatch)
    );

    let wrong_name = metadata_result(SOURCE_COMMIT, "/tmp/management-observe.txt", "J3R180-02");
    assert_eq!(
        wrong_name.expect_err("wrong basename"),
        ObservationError::Sitting(SittingError::SittingOutputNameMismatch)
    );
}

#[test]
fn infrastructure_backend_failures_are_normalized_without_a_card_or_apdu() {
    for (fail_at, expected_phase) in [
        (FailAt::Establish, ObservationPhase::EstablishContext),
        (FailAt::Enumerate, ObservationPhase::EnumerateReaders),
        (FailAt::Connect, ObservationPhase::ExclusiveConnect),
    ] {
        let mut backend = MockBackend::passing();
        backend.fail_at = Some(fail_at);
        let (summary, _) = run(&mut backend);
        assert_eq!(summary.transmit_calls, 0);
        assert_eq!(summary.received_responses, 0);
        assert_eq!(
            summary.first_failure.map(|failure| failure.phase),
            Some(expected_phase)
        );
        assert_eq!(backend.disconnect_calls, 0);
    }
}

#[test]
fn header_output_failure_prevents_context_establishment_and_card_contact() {
    let mut backend = MockBackend::passing();
    let writer = NeedleWriter::new(WriterFailure::Write(b"QK-CARD-MANAGEMENT-OBSERVATION-V1"));
    let mut transcript = ManagementObservationTranscript::new(writer);
    let summary = run_management_observation(&metadata(), &mut backend, &mut transcript);

    assert_eq!(backend.establish_calls, 0);
    assert_eq!(backend.connect_calls, 0);
    assert_eq!(backend.disconnect_calls, 0);
    assert!(backend.requests.is_empty());
    assert_eq!(summary.transmit_calls, 0);
    assert_eq!(summary.received_responses, 0);
    assert_eq!(
        summary.first_failure,
        Some(qk_card_enrollment::ObservationFailure {
            phase: ObservationPhase::WriteHeader,
            error: ObservationError::Sitting(SittingError::SittingOutputWriteFailed),
        })
    );
}

#[test]
fn request_and_response_write_or_flush_failures_preserve_counts_and_cleanup() {
    let cases = [
        (
            WriterFailure::Write(b"exchange.0.tx_hex="),
            SittingError::SittingOutputWriteFailed,
            0,
            0,
        ),
        (
            WriterFailure::FlushAfter(b"exchange.0.tx_hex="),
            SittingError::SittingOutputFlushFailed,
            0,
            0,
        ),
        (
            WriterFailure::Write(b"exchange.0.rx_hex="),
            SittingError::SittingOutputWriteFailed,
            1,
            1,
        ),
        (
            WriterFailure::FlushAfter(b"exchange.0.rx_hex="),
            SittingError::SittingOutputFlushFailed,
            1,
            1,
        ),
    ];
    for (failure, expected, transmit_calls, received_responses) in cases {
        let mut backend = MockBackend::passing();
        let mut transcript = ManagementObservationTranscript::new(NeedleWriter::new(failure));
        let summary = run_management_observation(&metadata(), &mut backend, &mut transcript);
        assert_eq!(summary.transmit_calls, transmit_calls);
        assert_eq!(summary.received_responses, received_responses);
        assert_eq!(
            summary.first_failure,
            Some(qk_card_enrollment::ObservationFailure {
                phase: ObservationPhase::SelectIsd,
                error: ObservationError::Sitting(expected),
            })
        );
        assert_eq!(backend.disconnect_calls, 1);
        assert!(!backend.connected);
    }
}

fn run(backend: &mut MockBackend) -> (qk_card_enrollment::ObservationSummary, String) {
    let metadata = metadata();
    let mut transcript = ManagementObservationTranscript::new(Vec::new());
    let summary = run_management_observation(&metadata, backend, &mut transcript);
    let transcript = String::from_utf8(transcript.into_inner()).expect("ASCII transcript");
    (summary, transcript)
}

fn metadata() -> ManagementObservationMetadata {
    metadata_result(
        SOURCE_COMMIT,
        &format!("/tmp/qk-card-sitting-v1__management-observe__J3R180-02__{TIMESTAMP}.txt"),
        "J3R180-02",
    )
    .expect("valid observation metadata")
}

fn metadata_result(
    source_commit: &str,
    path: &str,
    specimen: &str,
) -> Result<ManagementObservationMetadata, ObservationError> {
    let enrollment = EnrollmentMetadata {
        mode: EnrollmentMode::Enroll,
        source_commit: source_commit.to_owned(),
        timestamp_utc: TIMESTAMP.to_owned(),
        host_alias: "iMac".to_owned(),
        reader_alias: "SCR3310-01".to_owned(),
        specimen_alias: Some(specimen.to_owned()),
        selected_reader_name: Some(SITTING_READER_NAME.to_vec()),
    }
    .validate()
    .expect("valid enrollment metadata shape");
    ManagementObservationMetadata::new(enrollment, PathBuf::from(path))
}

fn passing_responses(scp_version: u8, scp_i: Option<u8>) -> Vec<Vec<u8>> {
    vec![
        vec![0x6f, 0x00, 0x90, 0x00],
        vec![0x66, 0x01, 0x73, 0x90, 0x00],
        initialize_response(scp_version, scp_i),
        vec![0xe0, 0x00, 0x90, 0x00],
    ]
}

fn initialize_response(scp_version: u8, scp_i: Option<u8>) -> Vec<u8> {
    let body_len = match scp_version {
        0x01 | 0x02 => 28,
        0x03 => {
            let scp_i = scp_i.expect("SCP03 i");
            29 + if scp_i & 0x01 != 0 { 16 } else { 0 } + if scp_i & 0x10 != 0 { 3 } else { 0 }
        }
        _ => 28,
    };
    let mut response = vec![0xa5; body_len];
    response[10] = 0x21;
    response[11] = scp_version;
    if scp_version == 0x03 {
        response[12] = scp_i.expect("SCP03 i");
    }
    response.extend_from_slice(&[0x90, 0x00]);
    response
}

fn complete_tlv_response(tag: u8, value: &[u8]) -> Vec<u8> {
    let mut response = Vec::with_capacity(value.len() + 5);
    response.push(tag);
    if value.len() <= 127 {
        response.push(u8::try_from(value.len()).expect("short TLV length"));
    } else {
        response.extend_from_slice(&[
            0x81,
            u8::try_from(value.len()).expect("bounded long TLV length"),
        ]);
    }
    response.extend_from_slice(value);
    response.extend_from_slice(&[0x90, 0x00]);
    response
}

fn phase_index(phase: ObservationPhase) -> usize {
    match phase {
        ObservationPhase::SelectIsd => 0,
        ObservationPhase::CardRecognition => 1,
        ObservationPhase::InitializeUpdate => 2,
        ObservationPhase::KeyInformation => 3,
        _ => panic!("not an exchange phase"),
    }
}

#[derive(Clone, Copy)]
enum WriterFailure {
    Write(&'static [u8]),
    FlushAfter(&'static [u8]),
}

struct NeedleWriter {
    bytes: Vec<u8>,
    failure: WriterFailure,
    flush_armed: bool,
}

impl NeedleWriter {
    fn new(failure: WriterFailure) -> Self {
        Self {
            bytes: Vec::new(),
            failure,
            flush_armed: false,
        }
    }
}

impl Write for NeedleWriter {
    fn write(&mut self, buffer: &[u8]) -> io::Result<usize> {
        match self.failure {
            WriterFailure::Write(needle) if contains_bytes(buffer, needle) => {
                return Err(io::Error::other("injected transcript write failure"));
            }
            WriterFailure::FlushAfter(needle) if contains_bytes(buffer, needle) => {
                self.flush_armed = true;
            }
            _ => {}
        }
        self.bytes.extend_from_slice(buffer);
        Ok(buffer.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        if self.flush_armed {
            return Err(io::Error::other("injected transcript flush failure"));
        }
        Ok(())
    }
}

fn contains_bytes(haystack: &[u8], needle: &[u8]) -> bool {
    !needle.is_empty()
        && haystack
            .windows(needle.len())
            .any(|window| window == needle)
}
