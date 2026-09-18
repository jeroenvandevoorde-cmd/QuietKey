//! One existing Normal owner over the compile-time SEC1210 application seam.

use crate::card_apdu_session_v2::{CardApduExchangeV2, CardApduSessionErrorV2, CardApduSessionV2};
use crate::{
    CardProcessErrorV1, CardTransportErrorV2, CoreOutbound, NormalErrorV2,
    NormalProcessControllerV2, NormalProcessErrorV2, NormalProcessEventV2, NormalProcessStageV2,
    NormalProfileV2, NormalScreenV2, NormalStageV2, Sec1210DescriptorV2, Sec1210MonotonicClockV2,
    Sec1210TransportV2,
};
use core::fmt;
use qk_card_protocol::{EncodeError, ProtocolError, ResponseError, MAX_RESPONSE_BYTES};

/// Closed leaf names only; neither transport evidence nor caller data crosses here.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum NormalSec1210ErrorV2 {
    Transport(CardTransportErrorV2),
    CardEncode(EncodeError),
    CardProtocol(ProtocolError),
    CardResponse(ResponseError),
    CardBinding(CardProcessErrorV1),
    CardSessionIdentityUnavailable,
    CardSessionIdentityExhausted,
    Normal(NormalProcessErrorV2),
    UnexpectedEvent,
}

impl NormalSec1210ErrorV2 {
    pub const fn name(self) -> &'static str {
        match self {
            Self::Transport(error) => error.name(),
            Self::CardEncode(error) => error.name(),
            Self::CardProtocol(error) => error.name(),
            Self::CardResponse(error) => error.name(),
            Self::CardBinding(error) => error.name(),
            Self::CardSessionIdentityUnavailable => "CardSessionIdentityUnavailable",
            Self::CardSessionIdentityExhausted => "CardSessionIdentityExhausted",
            Self::Normal(error) => error.name(),
            Self::UnexpectedEvent => "UnexpectedEvent",
        }
    }
}

impl fmt::Display for NormalSec1210ErrorV2 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.name())
    }
}
impl std::error::Error for NormalSec1210ErrorV2 {}

/// Immutable facts delivered only outside a pending card exchange.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum NormalSec1210DisplayV2 {
    Stage(NormalStageV2),
    CardOutcomeUnknown,
}

impl NormalSec1210DisplayV2 {
    pub const fn message(self) -> Option<&'static str> {
        match self {
            Self::Stage(_) => None,
            Self::CardOutcomeUnknown => Some("Signing was not completed by this terminal. The card may have produced a signature before the failure."),
        }
    }
}

/// Owns, but never replaces, the existing review/approval/signing controller.
/// The descriptor grant is a platform assertion, not verified exclusivity.
pub struct NormalSec1210V2<D, C> {
    controller: NormalProcessControllerV2,
    application_session: CardApduSessionV2,
    transport: Option<Sec1210TransportV2<D, C>>,
    first_failure: Option<NormalSec1210ErrorV2>,
    sign_write_attempted: bool,
    unknown_display_delivered: bool,
}

struct Sec1210ApduAdapter<'a, D, C> {
    transport: &'a mut Sec1210TransportV2<D, C>,
    sign_write_attempted: &'a mut bool,
}

impl<D: Sec1210DescriptorV2, C: Sec1210MonotonicClockV2> CardApduExchangeV2
    for Sec1210ApduAdapter<'_, D, C>
{
    type Error = CardTransportErrorV2;

    fn exchange(
        &mut self,
        request: &[u8],
        response: &mut [u8; MAX_RESPONSE_BYTES],
    ) -> Result<usize, Self::Error> {
        // This is deliberately conservative: once the SIGN dispatch begins,
        // a failure is not evidence that no card-side signature exists.
        if request.get(1) == Some(&0x15) {
            *self.sign_write_attempted = true;
        }
        let reply = self.transport.transmit_apdu(request)?;
        let bytes = reply.bytes();
        let destination = response
            .get_mut(..bytes.len())
            .ok_or(CardTransportErrorV2::Sec1210ApplicationResponseLengthRejected)?;
        destination.copy_from_slice(bytes);
        Ok(bytes.len())
    }
}

impl<D: Sec1210DescriptorV2, C: Sec1210MonotonicClockV2> NormalSec1210V2<D, C> {
    pub fn start(
        profile_ascii: &[u8],
        descriptor: D,
        clock: C,
    ) -> Result<(Self, CoreOutbound), NormalSec1210ErrorV2> {
        let controller = NormalProcessControllerV2::start(profile_ascii)
            .map_err(NormalSec1210ErrorV2::Normal)?;
        Self::from_controller(controller, CardApduSessionV2::new(), descriptor, clock)
    }

    /// Public-fixture identity minting without an OS entropy source. This
    /// constructor is absent from the production configuration.
    #[cfg(any(test, feature = "fuzzing"))]
    #[doc(hidden)]
    pub fn fuzz_start(
        profile_ascii: &[u8],
        descriptor: D,
        clock: C,
        namespace: [u8; 12],
        last_counter: u32,
    ) -> Result<(Self, CoreOutbound), NormalSec1210ErrorV2> {
        let controller =
            NormalProcessControllerV2::fuzz_start(profile_ascii, namespace, last_counter)
                .map_err(NormalSec1210ErrorV2::Normal)?;
        // A separate deterministic namespace for the card application session.
        let card_namespace = namespace.map(|byte| byte ^ 0x80);
        Self::from_controller(
            controller,
            CardApduSessionV2::deterministic(card_namespace, last_counter),
            descriptor,
            clock,
        )
    }

    fn from_controller(
        mut controller: NormalProcessControllerV2,
        application_session: CardApduSessionV2,
        descriptor: D,
        clock: C,
    ) -> Result<(Self, CoreOutbound), NormalSec1210ErrorV2> {
        let profile = match controller.selected_profile() {
            NormalProfileV2::SimpleRecovery => 1,
            NormalProfileV2::Inheritance => 2,
            NormalProfileV2::QuantumShelter => 3,
        };
        controller
            .accept_profile(profile)
            .map_err(NormalSec1210ErrorV2::Normal)?;
        let mut transport = Sec1210TransportV2::new(descriptor, clock);
        transport
            .initialize()
            .map_err(NormalSec1210ErrorV2::Transport)?;
        let mut owner = Self {
            controller,
            application_session,
            transport: Some(transport),
            first_failure: None,
            sign_write_attempted: false,
            unknown_display_delivered: false,
        };
        let bound = owner.bind()?;
        let opening = match owner.controller.accept_bound_card(bound) {
            Ok(opening) => opening,
            Err(error) => return Err(owner.fail(NormalSec1210ErrorV2::Normal(error))),
        };
        Ok((owner, opening))
    }

    fn bind(&mut self) -> Result<crate::NormalCardBDataV2, NormalSec1210ErrorV2> {
        let transport = self
            .transport
            .as_mut()
            .ok_or(NormalSec1210ErrorV2::UnexpectedEvent)?;
        let result = self.application_session.bind_normal_card(
            &mut Sec1210ApduAdapter {
                transport,
                sign_write_attempted: &mut self.sign_write_attempted,
            },
            self.controller.selected_profile(),
        );
        result.map_err(|error| self.fail(map_application_error(error)))
    }

    pub fn stage(&self) -> NormalProcessStageV2 {
        self.controller.stage()
    }
    pub fn screen(&self) -> Option<NormalScreenV2<'_>> {
        self.controller.screen()
    }
    pub const fn terminal_error(&self) -> Option<NormalSec1210ErrorV2> {
        self.first_failure
    }
    pub fn sign_attempts(&self) -> usize {
        self.application_session.sign_attempts()
    }

    pub fn take_display_fact(&mut self) -> Option<NormalSec1210DisplayV2> {
        if let Some(stage) = self.controller.take_display_stage() {
            return Some(NormalSec1210DisplayV2::Stage(stage));
        }
        if self.first_failure.is_some()
            && self.sign_write_attempted
            && !self.unknown_display_delivered
        {
            self.unknown_display_delivered = true;
            return Some(NormalSec1210DisplayV2::CardOutcomeUnknown);
        }
        None
    }

    pub fn receive_qkip(
        &mut self,
        bytes: &mut [u8],
        ancillary_present: bool,
    ) -> Result<Option<CoreOutbound>, NormalSec1210ErrorV2> {
        let result = match self.ensure_live() {
            Ok(()) => self.controller.receive_qkip(bytes, ancillary_present),
            Err(error) => {
                crate::wipe::bytes(bytes);
                return Err(error);
            }
        };
        crate::wipe::bytes(bytes);
        self.complete_action(result)
    }

    pub fn advance_automatic(&mut self) -> Result<Option<CoreOutbound>, NormalSec1210ErrorV2> {
        self.ensure_live()?;
        let result = self.controller.advance_automatic();
        self.complete_action(result)
    }

    pub fn handle_event(
        &mut self,
        event: NormalProcessEventV2,
    ) -> Result<Option<CoreOutbound>, NormalSec1210ErrorV2> {
        self.ensure_live()?;
        let result = self.controller.handle_event(event);
        self.complete_action(result)
    }

    /// Unsolicited or late card bytes are never a resumable reply interface.
    pub fn reject_card_reply(&mut self, bytes: &mut [u8]) -> NormalSec1210ErrorV2 {
        crate::wipe::bytes(bytes);
        self.fail(NormalSec1210ErrorV2::UnexpectedEvent)
    }

    fn complete_action(
        &mut self,
        result: Result<Option<CoreOutbound>, NormalProcessErrorV2>,
    ) -> Result<Option<CoreOutbound>, NormalSec1210ErrorV2> {
        let mut outbound = match result {
            Ok(outbound) => outbound,
            Err(error) => return Err(self.fail(NormalSec1210ErrorV2::Normal(error))),
        };
        while let Some(request) = self.controller.card_b_signing_request() {
            if outbound.is_some() {
                return Err(self.fail(NormalSec1210ErrorV2::UnexpectedEvent));
            }
            let transport = match self.transport.as_mut() {
                Some(transport) => transport,
                None => return Err(self.fail(NormalSec1210ErrorV2::UnexpectedEvent)),
            };
            let response = self.application_session.sign_card_b(
                &mut Sec1210ApduAdapter {
                    transport,
                    sign_write_attempted: &mut self.sign_write_attempted,
                },
                &request,
            );
            drop(request);
            let mut response = match response {
                Ok(response) => response,
                Err(error) => return Err(self.fail(map_application_error(error))),
            };
            let review = response.review_hash;
            let index = response.input_index;
            let key = response.public_key;
            let Some(signature) = response.signature_mut() else {
                return Err(self.fail(NormalSec1210ErrorV2::UnexpectedEvent));
            };
            outbound = match self
                .controller
                .accept_card_b_signature(review, index, key, signature)
            {
                Ok(outbound) => outbound,
                Err(error) => return Err(self.fail(NormalSec1210ErrorV2::Normal(error))),
            };
        }
        Ok(outbound)
    }

    fn ensure_live(&self) -> Result<(), NormalSec1210ErrorV2> {
        match self.first_failure {
            Some(error) => Err(error),
            None => Ok(()),
        }
    }

    fn fail(&mut self, error: NormalSec1210ErrorV2) -> NormalSec1210ErrorV2 {
        let first = *self.first_failure.get_or_insert(error);
        let reason = match first {
            NormalSec1210ErrorV2::Normal(NormalProcessErrorV2::Normal(error)) => error,
            _ => NormalErrorV2::SigningRejected,
        };
        self.controller.terminate_operation(reason);
        self.application_session.terminate();
        drop(self.transport.take());
        first
    }
}

impl<D, C> Drop for NormalSec1210V2<D, C> {
    fn drop(&mut self) {
        self.controller
            .terminate_operation(NormalErrorV2::SigningRejected);
        self.application_session.terminate();
        drop(self.transport.take());
    }
}

fn map_application_error(
    error: CardApduSessionErrorV2<CardTransportErrorV2>,
) -> NormalSec1210ErrorV2 {
    match error {
        CardApduSessionErrorV2::Transport(error) => NormalSec1210ErrorV2::Transport(error),
        CardApduSessionErrorV2::CardEncode(error) => NormalSec1210ErrorV2::CardEncode(error),
        CardApduSessionErrorV2::CardProtocol(error) => NormalSec1210ErrorV2::CardProtocol(error),
        CardApduSessionErrorV2::CardResponse(error) => NormalSec1210ErrorV2::CardResponse(error),
        CardApduSessionErrorV2::CardBinding(error) => NormalSec1210ErrorV2::CardBinding(error),
        CardApduSessionErrorV2::CardSessionIdentityUnavailable => {
            NormalSec1210ErrorV2::CardSessionIdentityUnavailable
        }
        CardApduSessionErrorV2::CardSessionIdentityExhausted => {
            NormalSec1210ErrorV2::CardSessionIdentityExhausted
        }
        CardApduSessionErrorV2::SigningRejected => NormalSec1210ErrorV2::Normal(
            NormalProcessErrorV2::Normal(NormalErrorV2::SigningRejected),
        ),
        CardApduSessionErrorV2::UnexpectedEvent => NormalSec1210ErrorV2::UnexpectedEvent,
    }
}

#[cfg(test)]
#[allow(clippy::expect_used)]
mod tests {
    #[allow(
        clippy::unwrap_used,
        clippy::expect_used,
        clippy::panic,
        clippy::indexing_slicing,
        clippy::arithmetic_side_effects
    )]
    mod fixture {
        use crate as qk_core;
        // SUP-003 requires this cross-tree include, not a copied fixture body.
        include!("../tests/support/normal_signing_fixture.rs");

        use super::super::{CardApduSessionV2, Sec1210ApduAdapter};
        use crate::{
            CardTransportErrorV2, Interruption, NormalErrorV2, NormalProcessControllerV2,
            NormalProcessErrorV2, NormalSec1210ErrorV2, Sec1210TransportV2,
            QK_LIM_APDU_021_MAX_SIGN_EXCHANGES,
        };

        fn assert_no_request(owner: &Owner) {
            assert!(
                owner.controller.card_b_signing_request().is_none(),
                "a public return exposed a pending SIGN request"
            );
        }

        fn observe_returns(owner: &mut Owner) {
            assert_no_request(owner);
            let _ = owner.stage();
            assert_no_request(owner);
            let _ = owner.screen();
            assert_no_request(owner);
            let _ = owner.terminal_error();
            assert_no_request(owner);
            let _ = owner.sign_attempts();
            assert_no_request(owner);
            loop {
                let fact = owner.take_display_fact();
                assert_no_request(owner);
                if fact.is_none() {
                    break;
                }
            }
        }

        fn receive_checked(
            owner: &mut Owner,
            bytes: &mut [u8],
        ) -> Result<Option<CoreOutbound>, NormalSec1210ErrorV2> {
            let result = owner.receive_qkip(bytes, false);
            assert_no_request(owner);
            assert!(bytes.iter().all(|byte| *byte == 0));
            observe_returns(owner);
            result
        }

        fn advance_checked(
            owner: &mut Owner,
        ) -> Result<Option<CoreOutbound>, NormalSec1210ErrorV2> {
            let result = owner.advance_automatic();
            assert_no_request(owner);
            observe_returns(owner);
            result
        }

        fn event_checked(
            owner: &mut Owner,
            event: NormalProcessEventV2,
        ) -> Result<Option<CoreOutbound>, NormalSec1210ErrorV2> {
            let result = owner.handle_event(event);
            assert_no_request(owner);
            observe_returns(owner);
            result
        }

        fn reject_checked(owner: &mut Owner, bytes: &mut [u8]) -> NormalSec1210ErrorV2 {
            let result = owner.reject_card_reply(bytes);
            assert_no_request(owner);
            assert!(bytes.iter().all(|byte| *byte == 0));
            observe_returns(owner);
            result
        }

        fn deliver_checked(owner: &mut Owner, reply: &BrokerReply) -> Option<CoreOutbound> {
            receive_checked(owner, &mut reply.frame_bytes().to_vec())
                .expect("accepted public broker reply")
        }

        fn ingress_checked(
            owner: &mut Owner,
            broker: &mut BrokerSession,
            opening: CoreOutbound,
            source: IoSource,
            payload: &[u8],
        ) {
            let mut input = MockInput::try_new(source, payload).expect("public input");
            let response = reply(broker, &opening, Some(&mut input), None);
            let mut next = deliver_checked(owner, &response);
            while let Some(outbound) = next {
                next = deliver_checked(owner, &reply(broker, &outbound, None, None));
            }
        }

        fn review_with_return_checks(
            mut owner: Owner,
            opening: CoreOutbound,
            psbt: &[u8],
        ) -> Owner {
            observe_returns(&mut owner);
            let mut broker = BrokerSession::new();
            assert!(
                deliver_checked(&mut owner, &reply(&mut broker, &opening, None, None)).is_none()
            );
            event_checked(
                &mut owner,
                NormalProcessEventV2::LogicalKey(KeypadKey::EqualsConfirmEnter),
            )
            .expect("confirm bound profile");
            let begin = event_checked(
                &mut owner,
                NormalProcessEventV2::SelectPsbtSource(Source::MediaPsbt),
            )
            .expect("select public input")
            .expect("input opening");
            ingress_checked(
                &mut owner,
                &mut broker,
                begin,
                IoSource::MediaPsbt,
                &media_record(psbt),
            );
            let begin = advance_checked(&mut owner)
                .expect("bound B factor")
                .expect("A1 opening");
            ingress_checked(
                &mut owner,
                &mut broker,
                begin,
                IoSource::CameraA1Candidate,
                &a1(),
            );
            assert!(advance_checked(&mut owner).expect("A1 validated").is_none());
            for _ in 0..400 {
                if owner.stage() == NormalProcessStageV2::Normal(NormalStageV2::FinalApproval) {
                    assert_no_request(&owner);
                    break;
                }
                assert_no_request(&owner);
                event_checked(
                    &mut owner,
                    NormalProcessEventV2::LogicalKey(KeypadKey::EqualsConfirmEnter),
                )
                .expect("review next");
            }
            assert_eq!(
                owner.stage(),
                NormalProcessStageV2::Normal(NormalStageV2::FinalApproval)
            );
            assert_no_request(&owner);
            owner
        }

        fn approved_owner(profile: u8, psbt: &[u8]) -> (Owner, Trace) {
            let (descriptor, clock, trace) = rig(profile);
            let ascii = [b'0', b'0' + profile];
            let (owner, opening) = Owner::start(&ascii, descriptor, clock).expect("bound card");
            assert_no_request(&owner);
            let owner = review_with_return_checks(owner, opening, psbt);
            assert_eq!(trace.sign_count(), 0, "no SIGN before approval");
            (owner, trace)
        }

        fn assert_latched_returns(owner: &mut Owner, trace: &Trace, first: NormalSec1210ErrorV2) {
            assert_no_request(owner);
            assert_eq!(owner.terminal_error(), Some(first));
            assert_no_request(owner);
            assert_eq!(owner.stage(), NormalProcessStageV2::Terminated);
            assert_no_request(owner);
            assert!(owner.screen().is_none());
            assert_no_request(owner);
            assert!(trace.descriptor_dropped());
            assert!(owner.application_session.is_terminated());
            let writes = trace.writes();
            for _ in 0..2 {
                let mut input = [0x55; 20];
                assert_eq!(receive_checked(owner, &mut input).err(), Some(first));
                assert_eq!(trace.writes(), writes);
                assert_eq!(advance_checked(owner).err(), Some(first));
                assert_eq!(trace.writes(), writes);
                for event in [
                    NormalProcessEventV2::HoldCompleted,
                    NormalProcessEventV2::SelectSd {
                        caller_nonce: [1; 16],
                    },
                    NormalProcessEventV2::SelectBbqr {
                        non_final_part_len: 256,
                    },
                ] {
                    assert_eq!(event_checked(owner, event).err(), Some(first));
                    assert_eq!(trace.writes(), writes, "no retry or partial export");
                }
                let mut late = trace
                    .last_valid_sign_reply()
                    .unwrap_or_else(|| hex(field(CARD, "normal_sign_0_response_hex")));
                assert!(matches!(
                    qk_card_protocol::parse_response(Instruction::SignDigest, &late),
                    Ok(qk_card_protocol::ResponseRef::SignDigest { .. })
                ));
                assert_eq!(reject_checked(owner, &mut late), first);
                assert_eq!(trace.writes(), writes, "late reply cannot resume dispatch");
            }
        }

        #[test]
        fn public_entrypoint_returns_leave_no_pending_sign_request() {
            for profile in 1..=3 {
                for (input, missing) in [
                    (psbt_with_existing_b(1, &[0]), 0),
                    (psbt(), 1),
                    (psbt_with_existing_b(3, &[0, 2]), 1),
                    (psbt_with_inputs(3), 3),
                ] {
                    let (mut owner, trace) = approved_owner(profile, &input);
                    trace.set_fragment_bytes(1);
                    assert!(
                        event_checked(&mut owner, NormalProcessEventV2::HoldCompleted)
                            .expect("complete bound signing outcome")
                            .is_none()
                    );
                    assert_eq!(trace.sign_count(), missing);
                    assert_eq!(
                        owner.stage(),
                        NormalProcessStageV2::Normal(NormalStageV2::AwaitingExportAction)
                    );
                    assert_no_request(&owner);
                }
            }
            let (mut owner, trace) = approved_owner(1, &psbt());
            trace.set_fault(Fault::Sign {
                ordinal: 1,
                kind: SignFault::HighS,
            });
            assert!(
                event_checked(&mut owner, NormalProcessEventV2::HoldCompleted)
                    .expect("existing verifier normalizes high S")
                    .is_none()
            );
            assert_eq!(trace.sign_count(), 1);
        }

        #[test]
        fn start_failures_return_no_owner_or_sign_write() {
            let (descriptor, clock, trace) = rig(1);
            assert_eq!(
                Owner::start(b"04", descriptor, clock)
                    .err()
                    .expect("invalid profile")
                    .name(),
                "ProfileUnknown"
            );
            assert_eq!(trace.sign_count(), 0);
            assert!(trace.writes().is_empty());
            assert!(trace.descriptor_dropped());
            let (descriptor, clock, trace) = rig(1);
            trace.set_clock_script([Err(Sec1210ClockErrorV2)]);
            assert_eq!(
                Owner::start(b"01", descriptor, clock)
                    .err()
                    .expect("initialization rejected")
                    .name(),
                "Sec1210ClockFailed"
            );
            assert_eq!(trace.sign_count(), 0);
            assert!(trace.descriptor_dropped());
            for (fault, name, exchanges) in binding_cases() {
                let (descriptor, clock, trace) = rig(1);
                trace.set_fault(fault);
                assert_eq!(
                    Owner::start(b"01", descriptor, clock)
                        .err()
                        .expect("binding rejected")
                        .name(),
                    name
                );
                assert_eq!(trace.apdus().len(), exchanges);
                assert_eq!(trace.sign_count(), 0);
                assert!(trace.descriptor_dropped());
            }
        }

        #[test]
        fn pending_service_rejections_and_latched_returns_leave_no_request() {
            for entry in 0..6 {
                let (mut owner, trace) = approved_owner(1, &psbt_with_inputs(3));
                assert!(owner
                    .controller
                    .handle_event(NormalProcessEventV2::HoldCompleted)
                    .expect("real approval creates pending request")
                    .is_none());
                assert!(owner.controller.card_b_signing_request().is_some());
                let normal =
                    |error| NormalSec1210ErrorV2::Normal(NormalProcessErrorV2::Normal(error));
                let (actual, expected) = match entry {
                    0 => (
                        receive_checked(&mut owner, &mut [])
                            .err()
                            .expect("intake rejected"),
                        normal(NormalErrorV2::PostApprovalYield),
                    ),
                    1 => (
                        advance_checked(&mut owner).err().expect("advance rejected"),
                        normal(NormalErrorV2::InvalidTransition),
                    ),
                    2 => (
                        event_checked(&mut owner, NormalProcessEventV2::HoldCompleted)
                            .err()
                            .expect("second hold rejected"),
                        normal(NormalErrorV2::InvalidTransition),
                    ),
                    3 => (
                        event_checked(&mut owner, NormalProcessEventV2::CardRemoved)
                            .err()
                            .expect("removed"),
                        normal(NormalErrorV2::Interrupted(Interruption::CardRemoved)),
                    ),
                    4 => (
                        event_checked(&mut owner, NormalProcessEventV2::SessionTimeout)
                            .err()
                            .expect("timed out"),
                        normal(NormalErrorV2::Interrupted(Interruption::SessionTimeout)),
                    ),
                    _ => (
                        reject_checked(&mut owner, &mut [0x55; 72]),
                        NormalSec1210ErrorV2::UnexpectedEvent,
                    ),
                };
                assert_eq!(actual, expected);
                assert_eq!(trace.sign_count(), 0);
                assert_latched_returns(&mut owner, &trace, actual);
            }
        }

        #[test]
        fn signing_failures_leave_no_request_after_first_or_partial_signatures() {
            let extra = [
                (SignFault::ReadFailure, "Sec1210DescriptorReadFailed", 1),
                (SignFault::ShortWrite, "Sec1210PartialWrite", 1),
                (SignFault::WriteFailure, "Sec1210DescriptorWriteFailed", 1),
                (SignFault::TimedOut, "Sec1210DeadlineExceeded", 1),
                (SignFault::BadChecksum, "Sec1210ChecksumRejected", 1),
            ];
            for (kind, name, ordinal) in signing_cases().into_iter().chain(extra) {
                let (mut owner, trace) = approved_owner(1, &psbt_with_inputs(3));
                trace.set_fault(Fault::Sign { ordinal, kind });
                let error = event_checked(&mut owner, NormalProcessEventV2::HoldCompleted)
                    .err()
                    .expect("fault terminates operation");
                assert_eq!(error.name(), name);
                assert_latched_returns(&mut owner, &trace, error);
            }
            let (mut owner, trace) = approved_owner(1, &psbt());
            trace.set_clock_script([Err(Sec1210ClockErrorV2)]);
            let error = event_checked(&mut owner, NormalProcessEventV2::HoldCompleted)
                .err()
                .expect("clock failure while signing");
            assert_eq!(error.name(), "Sec1210ClockFailed");
            assert_latched_returns(&mut owner, &trace, error);
        }

        // Hand-assembled facade; only the exhausted application-session state
        // is simulated. Controller/transport come from actual setup and binding.
        fn assembled_exhausted_owner() -> (Owner, CoreOutbound, Trace) {
            let (descriptor, clock, trace) = rig(1);
            let mut controller = NormalProcessControllerV2::start(b"01").expect("public profile");
            controller.accept_profile(1).expect("matching profile");
            let mut transport = Sec1210TransportV2::new(descriptor, clock);
            transport.initialize().expect("real modeled initialization");
            let mut binding_session = CardApduSessionV2::new();
            let mut sign_write_attempted = false;
            let card = binding_session
                .bind_normal_card(
                    &mut Sec1210ApduAdapter {
                        transport: &mut transport,
                        sign_write_attempted: &mut sign_write_attempted,
                    },
                    controller.selected_profile(),
                )
                .expect("actual binding exchanges");
            let opening = controller
                .accept_bound_card(card)
                .expect("actual bound controller");
            assert_eq!(trace.apdus().len(), 8);
            assert_eq!(trace.sign_count(), 0);
            assert!(!sign_write_attempted);
            assert!(controller.card_b_signing_request().is_none());
            assert_eq!(controller.terminal_error(), None);
            assert_eq!(transport.failure(), None);
            drop(binding_session);
            let owner = Owner {
                controller,
                application_session: CardApduSessionV2::simulated_exhausted_sign_budget_for_test()
                    .expect("simulated counter, not 100 executed SIGNs"),
                transport: Some(transport),
                first_failure: None,
                sign_write_attempted,
                unknown_display_delivered: false,
            };
            assert_no_request(&owner);
            (owner, opening, trace)
        }

        #[test]
        fn exhausted_sign_budget_terminates_the_pending_request() {
            for stage_pending_first in [false, true] {
                let (owner, opening, trace) = assembled_exhausted_owner();
                let mut owner = review_with_return_checks(owner, opening, &psbt());
                let writes = trace.writes();
                let error = if stage_pending_first {
                    let result = owner
                        .controller
                        .handle_event(NormalProcessEventV2::HoldCompleted);
                    assert!(result.as_ref().expect("actual approval").is_none());
                    assert!(
                        owner.controller.card_b_signing_request().is_some(),
                        "complete_action must enter with a real pending request"
                    );
                    let result = owner.complete_action(result);
                    assert_no_request(&owner);
                    result
                        .err()
                        .expect("pending request rejected at application limit")
                } else {
                    event_checked(&mut owner, NormalProcessEventV2::HoldCompleted)
                        .err()
                        .expect("public entrypoint rejects exhausted budget")
                };
                assert_eq!(
                    error,
                    NormalSec1210ErrorV2::Normal(NormalProcessErrorV2::Normal(
                        NormalErrorV2::SigningRejected
                    ))
                );
                assert_ne!(
                    error,
                    NormalSec1210ErrorV2::Transport(
                        CardTransportErrorV2::Sec1210ApplicationApduLimitExceeded
                    )
                );
                assert_eq!(owner.sign_attempts(), QK_LIM_APDU_021_MAX_SIGN_EXCHANGES);
                assert_no_request(&owner);
                assert_eq!(trace.sign_count(), 0);
                assert_eq!(trace.writes(), writes, "limit rejects before SIGN dispatch");
                assert_latched_returns(&mut owner, &trace, error);
            }
        }

        #[test]
        fn test_available_fuzz_start_obeys_the_same_return_contract() {
            let (descriptor, clock, trace) = rig(1);
            let (owner, opening) = Owner::fuzz_start(b"01", descriptor, clock, [0x72; 12], 0)
                .expect("test-only deterministic constructor");
            assert_no_request(&owner);
            let mut owner = review_with_return_checks(owner, opening, &psbt_with_inputs(3));
            assert!(
                event_checked(&mut owner, NormalProcessEventV2::HoldCompleted)
                    .expect("deterministic completed outcome")
                    .is_none()
            );
            assert_eq!(trace.sign_count(), 3);
            let (descriptor, clock, trace) = rig(1);
            assert_eq!(
                Owner::fuzz_start(b"01", descriptor, clock, [0x72; 12], u32::MAX)
                    .err()
                    .expect("no owner at identity exhaustion")
                    .name(),
                "CardSessionIdentityExhausted"
            );
            assert_eq!(trace.sign_count(), 0);
            assert!(trace.descriptor_dropped());
        }
    }
}
