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
