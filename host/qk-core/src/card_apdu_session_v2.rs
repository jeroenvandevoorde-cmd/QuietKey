//! Shared Normal card application session; transport framing remains in its adapter.

use crate::card_process_v1::{validate_normal_descriptors_v1, validate_normal_info_v1};
use crate::session_id::{mint_session_id, SessionId, SessionIdError};
use crate::wipe::{self, WipingArray};
use crate::{
    bind_normal_card_v1, CardInfoV1, CardProcessErrorV1, NormalCardBDataV2,
    NormalCardBSigningRequestV2, NormalProfileV2,
};
use qk_card_protocol::{
    encode_export_a2, encode_get_info, encode_open_session, encode_read_d_chunk, encode_select,
    encode_sign_digest, parse_command, parse_response, A2Purpose, DescriptorSelector, EncodeError,
    EnvelopeRef, Instruction, Media, Mode, ProtocolError, ResponseError, ResponseRef,
    SessionTracker, SignRequest, DESCRIPTOR_BYTES, MAX_REQUEST_BYTES, MAX_RESPONSE_BYTES,
};

/// QK-LIM-APDU-021: attempted per-input SIGN exchanges per Normal operation.
pub const QK_LIM_APDU_021_MAX_SIGN_EXCHANGES: usize = 100;
const _: () = assert!(QK_LIM_APDU_021_MAX_SIGN_EXCHANGES == 100);
/// SELECT, OPEN, INFO, four descriptor reads and EXPORT_A2.
pub(crate) const BINDING_APDUS: usize = 1 + 1 + 1 + 4 + 1;
const _: () = assert!(BINDING_APDUS == 8);
#[cfg(all(feature = "sec1210-production", feature = "normal-process"))]
const _: () = assert!(
    BINDING_APDUS + QK_LIM_APDU_021_MAX_SIGN_EXCHANGES
        <= crate::sec1210_transport_v2::MAX_APPLICATION_APDUS
);

pub(crate) trait CardApduExchangeV2 {
    type Error;
    fn exchange(
        &mut self,
        request: &[u8],
        response: &mut [u8; MAX_RESPONSE_BYTES],
    ) -> Result<usize, Self::Error>;
}

/// Closed application names and the adapter's closed error; never response data.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum CardApduSessionErrorV2<E> {
    Transport(E),
    CardEncode(EncodeError),
    CardProtocol(ProtocolError),
    CardResponse(ResponseError),
    CardBinding(CardProcessErrorV1),
    CardSessionIdentityUnavailable,
    CardSessionIdentityExhausted,
    SigningRejected,
    UnexpectedEvent,
}

pub(crate) struct CardApduSessionV2 {
    card_session: Option<CardProtocolSession>,
    opened: bool,
    terminated: bool,
    sign_attempts: usize,
    #[cfg(all(any(test, feature = "fuzzing"), feature = "sec1210-production"))]
    deterministic_mint: Option<crate::session_id::DeterministicSessionIdMint>,
}

struct CardApduResponseV2 {
    bytes: WipingArray<MAX_RESPONSE_BYTES>,
    length: usize,
}

impl CardApduResponseV2 {
    fn bytes<E>(&self) -> Result<&[u8], CardApduSessionErrorV2<E>> {
        self.bytes
            .as_array()
            .get(..self.length)
            .ok_or(CardApduSessionErrorV2::UnexpectedEvent)
    }
}

struct CardProtocolSession {
    session_id: SessionId,
    tracker: SessionTracker,
}

pub(crate) struct CardSignatureReply {
    pub(crate) review_hash: [u8; 32],
    pub(crate) input_index: u32,
    pub(crate) public_key: [u8; 33],
    signature: WipingArray<72>,
    signature_len: usize,
}

impl CardSignatureReply {
    fn try_from_response<E>(response: ResponseRef<'_>) -> Result<Self, CardApduSessionErrorV2<E>> {
        let ResponseRef::SignDigest {
            review_hash,
            input_index,
            public_key,
            signature_der,
            ..
        } = response
        else {
            return Err(CardApduSessionErrorV2::UnexpectedEvent);
        };
        let mut signature = WipingArray::<72>::zeroed();
        signature
            .as_mut_array()
            .get_mut(..signature_der.len())
            .ok_or(CardApduSessionErrorV2::UnexpectedEvent)?
            .copy_from_slice(signature_der);
        Ok(Self {
            review_hash: *review_hash,
            input_index,
            public_key: *public_key,
            signature,
            signature_len: signature_der.len(),
        })
    }

    pub(crate) fn signature_mut(&mut self) -> Option<&mut [u8]> {
        self.signature.as_mut_array().get_mut(..self.signature_len)
    }
}

impl Drop for CardSignatureReply {
    fn drop(&mut self) {
        wipe::bytes(&mut self.review_hash);
        wipe::words32(core::slice::from_mut(&mut self.input_index));
        wipe::bytes(&mut self.public_key);
        self.signature_len = 0;
    }
}

impl CardApduSessionV2 {
    pub(crate) const fn new() -> Self {
        Self {
            card_session: None,
            opened: false,
            terminated: false,
            sign_attempts: 0,
            #[cfg(all(any(test, feature = "fuzzing"), feature = "sec1210-production"))]
            deterministic_mint: None,
        }
    }

    #[cfg(all(any(test, feature = "fuzzing"), feature = "sec1210-production"))]
    pub(crate) fn deterministic(namespace: [u8; 12], last_counter: u32) -> Self {
        let mut session = Self::new();
        session.deterministic_mint = Some(crate::session_id::DeterministicSessionIdMint::new(
            namespace,
            last_counter,
        ));
        session
    }

    pub(crate) fn bind_normal_card<T: CardApduExchangeV2>(
        &mut self,
        transport: &mut T,
        selected_profile: NormalProfileV2,
    ) -> Result<NormalCardBDataV2, CardApduSessionErrorV2<T::Error>> {
        if self.opened || self.is_terminated() {
            self.terminate();
            return Err(CardApduSessionErrorV2::UnexpectedEvent);
        }
        self.opened = true;
        let result = self.bind_normal_card_inner(transport, selected_profile);
        if result.is_err() {
            self.terminate();
        }
        result
    }

    pub(crate) fn sign_card_b<T: CardApduExchangeV2>(
        &mut self,
        transport: &mut T,
        request: &NormalCardBSigningRequestV2,
    ) -> Result<CardSignatureReply, CardApduSessionErrorV2<T::Error>> {
        if self.is_terminated() || self.card_session.is_none() {
            self.terminate();
            return Err(CardApduSessionErrorV2::UnexpectedEvent);
        }
        if self.sign_attempts() >= QK_LIM_APDU_021_MAX_SIGN_EXCHANGES {
            self.terminate();
            return Err(CardApduSessionErrorV2::SigningRejected);
        }
        self.sign_attempts = self.sign_attempts.saturating_add(1);
        let result = self.sign_card_b_inner(transport, request);
        if result.is_err() {
            self.terminate();
        }
        result
    }

    pub(crate) const fn sign_attempts(&self) -> usize {
        self.sign_attempts
    }

    /// Counter-only simulated post-binding state; this does not execute the
    /// binding trace or the preceding 100 SIGN exchanges.
    #[cfg(all(test, feature = "sec1210-production"))]
    pub(crate) fn simulated_exhausted_sign_budget_for_test(
    ) -> Result<Self, CardApduSessionErrorV2<()>> {
        let mut mint = crate::session_id::DeterministicSessionIdMint::new([0x72; 12], 0);
        let session_id = mint.mint().map_err(map_card_session_identity_error)?;
        let tracker = SessionTracker::new(Mode::Normal, session_id.as_bytes(), 24, 23)
            .map_err(CardApduSessionErrorV2::CardProtocol)?;
        Ok(Self {
            card_session: Some(CardProtocolSession {
                session_id,
                tracker,
            }),
            opened: true,
            terminated: false,
            sign_attempts: QK_LIM_APDU_021_MAX_SIGN_EXCHANGES,
            deterministic_mint: None,
        })
    }

    pub(crate) const fn is_terminated(&self) -> bool {
        self.terminated
    }

    pub(crate) fn terminate(&mut self) {
        drop(self.card_session.take());
        #[cfg(all(any(test, feature = "fuzzing"), feature = "sec1210-production"))]
        drop(self.deterministic_mint.take());
        self.terminated = true;
    }

    fn raw_card_exchange<T: CardApduExchangeV2>(
        &mut self,
        transport: &mut T,
        command: &[u8],
    ) -> Result<CardApduResponseV2, CardApduSessionErrorV2<T::Error>> {
        let mut response = CardApduResponseV2 {
            bytes: WipingArray::zeroed(),
            length: 0,
        };
        let length = transport
            .exchange(command, response.bytes.as_mut_array())
            .map_err(CardApduSessionErrorV2::Transport)?;
        if length > MAX_RESPONSE_BYTES {
            return Err(CardApduSessionErrorV2::UnexpectedEvent);
        }
        response.length = length;
        Ok(response)
    }

    fn bind_normal_card_inner<T: CardApduExchangeV2>(
        &mut self,
        transport: &mut T,
        selected_profile: NormalProfileV2,
    ) -> Result<NormalCardBDataV2, CardApduSessionErrorV2<T::Error>> {
        self.open_card_session(transport)?;
        let info = self.card_info(transport)?;
        if let Err(error) = validate_normal_info_v1(selected_profile, &info) {
            self.terminate();
            return Err(CardApduSessionErrorV2::CardBinding(error));
        }
        let mut receive = WipingArray::<DESCRIPTOR_BYTES>::zeroed();
        self.read_descriptor(transport, DescriptorSelector::Receive, &mut receive)?;
        let mut change = WipingArray::<DESCRIPTOR_BYTES>::zeroed();
        self.read_descriptor(transport, DescriptorSelector::Change, &mut change)?;
        let descriptors = [*receive.as_array(), *change.as_array()];
        drop(receive);
        drop(change);
        if let Err(error) = validate_normal_descriptors_v1(&info, &descriptors) {
            self.terminate();
            return Err(CardApduSessionErrorV2::CardBinding(error));
        }
        let mut a2 = self.export_normal_a2(transport)?;
        let card = match bind_normal_card_v1(selected_profile, info, descriptors, a2.as_mut_array())
        {
            Ok(card) => card,
            Err(error) => {
                self.terminate();
                return Err(CardApduSessionErrorV2::CardBinding(error));
            }
        };
        drop(a2);
        Ok(card)
    }

    fn open_card_session<T: CardApduExchangeV2>(
        &mut self,
        transport: &mut T,
    ) -> Result<(), CardApduSessionErrorV2<T::Error>> {
        let mut select = WipingArray::<MAX_REQUEST_BYTES>::zeroed();
        let select_len =
            encode_select(select.as_mut_array()).map_err(CardApduSessionErrorV2::CardEncode)?;
        let response = self.raw_card_exchange(
            transport,
            select
                .as_array()
                .get(..select_len)
                .ok_or(CardApduSessionErrorV2::UnexpectedEvent)?,
        )?;
        drop(select);
        let response_bytes = response.bytes()?;
        let parsed = parse_response(Instruction::Select, response_bytes)
            .map_err(CardApduSessionErrorV2::CardResponse)?;
        match parsed {
            ResponseRef::Select => {}
            ResponseRef::Rejected(error) => {
                return Err(CardApduSessionErrorV2::CardProtocol(error));
            }
            _ => return Err(CardApduSessionErrorV2::UnexpectedEvent),
        }
        drop(response);

        #[cfg(all(any(test, feature = "fuzzing"), feature = "sec1210-production"))]
        let minted = match self.deterministic_mint.as_mut() {
            Some(mint) => mint.mint(),
            None => mint_session_id(),
        };
        #[cfg(not(all(any(test, feature = "fuzzing"), feature = "sec1210-production")))]
        let minted = mint_session_id();
        let session_id = minted.map_err(map_card_session_identity_error)?;
        let mut open = WipingArray::<MAX_REQUEST_BYTES>::zeroed();
        let open_len =
            encode_open_session(Mode::Normal, session_id.as_bytes(), open.as_mut_array())
                .map_err(CardApduSessionErrorV2::CardEncode)?;
        let response = self.raw_card_exchange(
            transport,
            open.as_array()
                .get(..open_len)
                .ok_or(CardApduSessionErrorV2::UnexpectedEvent)?,
        )?;
        drop(open);
        let response_bytes = response.bytes()?;
        let parsed = parse_response(Instruction::OpenSession, response_bytes)
            .map_err(CardApduSessionErrorV2::CardResponse)?;
        match parsed {
            ResponseRef::OpenSession { envelope }
                if envelope.session_id() == session_id.as_bytes() && envelope.sequence() == 0 => {}
            ResponseRef::OpenSession { .. } => {
                return Err(CardApduSessionErrorV2::CardProtocol(
                    ProtocolError::SessionIdMismatch,
                ));
            }
            ResponseRef::Rejected(error) => {
                return Err(CardApduSessionErrorV2::CardProtocol(error));
            }
            _ => return Err(CardApduSessionErrorV2::UnexpectedEvent),
        }
        let tracker = SessionTracker::new(
            Mode::Normal,
            session_id.as_bytes(),
            open_len,
            response_bytes.len(),
        )
        .map_err(CardApduSessionErrorV2::CardProtocol)?;
        drop(response);
        self.card_session = Some(CardProtocolSession {
            session_id,
            tracker,
        });
        Ok(())
    }

    fn card_info<T: CardApduExchangeV2>(
        &mut self,
        transport: &mut T,
    ) -> Result<CardInfoV1, CardApduSessionErrorV2<T::Error>> {
        self.session_exchange(
            transport,
            Instruction::GetInfo,
            encode_get_info,
            |response| {
                CardInfoV1::try_from_response(response).map_err(CardApduSessionErrorV2::CardBinding)
            },
        )
    }

    fn read_descriptor<T: CardApduExchangeV2>(
        &mut self,
        transport: &mut T,
        selector: DescriptorSelector,
        output: &mut WipingArray<DESCRIPTOR_BYTES>,
    ) -> Result<(), CardApduSessionErrorV2<T::Error>> {
        for offset in [0u16, 192u16] {
            self.session_exchange(
                transport,
                Instruction::ReadDChunk,
                |envelope, command| encode_read_d_chunk(envelope, selector, offset, command),
                |response| {
                    let ResponseRef::ReadDChunk {
                        selector: actual_selector,
                        offset: actual_offset,
                        bytes,
                        ..
                    } = response
                    else {
                        return Err(CardApduSessionErrorV2::UnexpectedEvent);
                    };
                    if actual_selector != selector || actual_offset != offset {
                        return Err(CardApduSessionErrorV2::CardProtocol(
                            ProtocolError::ModeOrOperationRejected,
                        ));
                    }
                    let start = usize::from(offset);
                    let end = start
                        .checked_add(bytes.len())
                        .ok_or(CardApduSessionErrorV2::UnexpectedEvent)?;
                    output
                        .as_mut_array()
                        .get_mut(start..end)
                        .ok_or(CardApduSessionErrorV2::UnexpectedEvent)?
                        .copy_from_slice(bytes);
                    Ok(())
                },
            )?;
        }
        Ok(())
    }

    fn export_normal_a2<T: CardApduExchangeV2>(
        &mut self,
        transport: &mut T,
    ) -> Result<WipingArray<32>, CardApduSessionErrorV2<T::Error>> {
        self.session_exchange(
            transport,
            Instruction::ExportA2,
            |envelope, command| encode_export_a2(envelope, A2Purpose::Normal, command),
            |response| {
                let ResponseRef::ExportA2 {
                    purpose: A2Purpose::Normal,
                    a2,
                    ..
                } = response
                else {
                    return Err(CardApduSessionErrorV2::UnexpectedEvent);
                };
                let mut owned = WipingArray::<32>::zeroed();
                owned.as_mut_array().copy_from_slice(a2);
                Ok(owned)
            },
        )
    }

    fn sign_card_b_inner<T: CardApduExchangeV2>(
        &mut self,
        transport: &mut T,
        request: &NormalCardBSigningRequestV2,
    ) -> Result<CardSignatureReply, CardApduSessionErrorV2<T::Error>> {
        let branch = u8::try_from(request.branch()).map_err(|_| {
            CardApduSessionErrorV2::CardProtocol(ProtocolError::DerivationPathRejected)
        })?;
        self.session_exchange(
            transport,
            Instruction::SignDigest,
            |envelope, command| {
                encode_sign_digest(
                    envelope,
                    SignRequest {
                        wallet_id: request.wallet_id(),
                        review_hash: request.review_hash(),
                        input_index: request.input_index(),
                        branch,
                        child_index: request.child_index(),
                        digest: request.digest(),
                    },
                    command,
                )
            },
            CardSignatureReply::try_from_response,
        )
    }

    fn session_exchange<T: CardApduExchangeV2, R>(
        &mut self,
        transport: &mut T,
        instruction: Instruction,
        encode: impl FnOnce(EnvelopeRef<'_>, &mut [u8]) -> Result<usize, EncodeError>,
        consume: impl FnOnce(ResponseRef<'_>) -> Result<R, CardApduSessionErrorV2<T::Error>>,
    ) -> Result<R, CardApduSessionErrorV2<T::Error>> {
        let mut session_id = WipingArray::<16>::zeroed();
        let sequence = match self.card_session.as_ref() {
            Some(session) => {
                session_id
                    .as_mut_array()
                    .copy_from_slice(session.session_id.as_bytes());
                session.tracker.next_sequence()
            }
            None => return Err(CardApduSessionErrorV2::UnexpectedEvent),
        };
        let mut command = WipingArray::<MAX_REQUEST_BYTES>::zeroed();
        let command_len = match encode(
            EnvelopeRef::new(session_id.as_array(), sequence),
            command.as_mut_array(),
        ) {
            Ok(length) => length,
            Err(error) => {
                self.terminate();
                return Err(CardApduSessionErrorV2::CardEncode(error));
            }
        };
        drop(session_id);
        let command_bytes = command
            .as_array()
            .get(..command_len)
            .ok_or(CardApduSessionErrorV2::UnexpectedEvent)?;
        let parsed_command = match parse_command(Media::ContactT1, command_bytes) {
            Ok(parsed) if parsed.instruction() == instruction => parsed,
            Ok(_) => {
                self.terminate();
                return Err(CardApduSessionErrorV2::UnexpectedEvent);
            }
            Err(error) => {
                self.terminate();
                return Err(CardApduSessionErrorV2::CardProtocol(error));
            }
        };
        if let Err(error) = self
            .card_session
            .as_mut()
            .ok_or(CardApduSessionErrorV2::UnexpectedEvent)?
            .tracker
            .begin_exchange(parsed_command, command_len)
        {
            self.terminate();
            return Err(CardApduSessionErrorV2::CardProtocol(error));
        }
        let response = match self.raw_card_exchange(transport, command_bytes) {
            Ok(response) => response,
            Err(error) => {
                self.terminate();
                return Err(error);
            }
        };
        drop(command);
        let response_bytes = match response.bytes() {
            Ok(bytes) => bytes,
            Err(error) => {
                self.terminate();
                return Err(error);
            }
        };
        let parsed_response = match parse_response(instruction, response_bytes) {
            Ok(parsed) => parsed,
            Err(error) => {
                self.terminate();
                return Err(CardApduSessionErrorV2::CardResponse(error));
            }
        };
        if let ResponseRef::Rejected(error) = parsed_response {
            let accounting = self
                .card_session
                .as_mut()
                .ok_or(CardApduSessionErrorV2::UnexpectedEvent)?
                .tracker
                .finish_rejection(response_bytes.len());
            let result = match accounting {
                Ok(()) => Err(CardApduSessionErrorV2::CardProtocol(error)),
                Err(accounting_error) => {
                    Err(CardApduSessionErrorV2::CardProtocol(accounting_error))
                }
            };
            self.terminate();
            return result;
        }
        if let Err(error) = self
            .card_session
            .as_mut()
            .ok_or(CardApduSessionErrorV2::UnexpectedEvent)?
            .tracker
            .finish_success(parsed_response, response_bytes.len())
        {
            self.terminate();
            return Err(CardApduSessionErrorV2::CardProtocol(error));
        }
        match consume(parsed_response) {
            Ok(value) => Ok(value),
            Err(error) => {
                self.terminate();
                Err(error)
            }
        }
    }
}

impl Drop for CardApduSessionV2 {
    fn drop(&mut self) {
        self.terminate();
    }
}

const fn map_card_session_identity_error<E>(error: SessionIdError) -> CardApduSessionErrorV2<E> {
    match error {
        SessionIdError::Unavailable => CardApduSessionErrorV2::CardSessionIdentityUnavailable,
        SessionIdError::Exhausted => CardApduSessionErrorV2::CardSessionIdentityExhausted,
    }
}

#[cfg(test)]
#[allow(clippy::expect_used)]
mod tests {
    use super::{
        CardApduExchangeV2, CardApduSessionErrorV2, CardApduSessionV2, CardProtocolSession,
    };
    use crate::session_id::DeterministicSessionIdMint;
    use crate::wipe::{reset_wiped_bytes, wiped_bytes};
    use crate::NormalProfileV2;
    use qk_card_protocol::{Mode, SessionTracker, MAX_RESPONSE_BYTES};

    struct FailedTransport {
        calls: usize,
    }

    impl CardApduExchangeV2 for FailedTransport {
        type Error = ();

        fn exchange(&mut self, _: &[u8], _: &mut [u8; MAX_RESPONSE_BYTES]) -> Result<usize, ()> {
            self.calls = self.calls.saturating_add(1);
            Err(())
        }
    }

    #[test]
    fn failed_binding_cannot_reopen_or_send_a_second_select() {
        let mut transport = FailedTransport { calls: 0 };
        let mut session = CardApduSessionV2::new();
        assert!(matches!(
            session.bind_normal_card(&mut transport, NormalProfileV2::SimpleRecovery),
            Err(CardApduSessionErrorV2::Transport(()))
        ));
        assert!(session.is_terminated());
        assert!(matches!(
            session.bind_normal_card(&mut transport, NormalProfileV2::SimpleRecovery),
            Err(CardApduSessionErrorV2::UnexpectedEvent)
        ));
        assert_eq!(transport.calls, 1);
    }

    #[cfg(feature = "sec1210-production")]
    #[test]
    fn attempted_sign_101_rejects_before_the_transport_and_terminates_the_owner() {
        use crate::normal_v2::tests::process_allocations::{
            assert_signing_rejected_and_wiped, final_approval,
        };
        use crate::{CardTransportErrorV2, NormalErrorV2, NormalExportActionV2};

        struct LimitTransport {
            calls: usize,
        }
        impl CardApduExchangeV2 for LimitTransport {
            type Error = CardTransportErrorV2;

            fn exchange(
                &mut self,
                _: &[u8],
                _: &mut [u8; MAX_RESPONSE_BYTES],
            ) -> Result<usize, Self::Error> {
                self.calls = self.calls.saturating_add(1);
                Err(CardTransportErrorV2::Sec1210ApplicationApduLimitExceeded)
            }
        }

        let mut owner = final_approval();
        let token = owner
            .begin_approval_hold()
            .expect("approved public fixture");
        owner
            .complete_process_approval_hold(token)
            .expect("revalidated owner with a pending request");
        let request = owner
            .process_card_b_signing_request()
            .expect("valid pending SIGN request");
        let mut session = CardApduSessionV2::simulated_exhausted_sign_budget_for_test()
            .expect("test-only counter state");
        let mut transport = LimitTransport { calls: 0 };
        reset_wiped_bytes();
        let result = session.sign_card_b(&mut transport, &request);
        assert!(matches!(
            result,
            Err(CardApduSessionErrorV2::SigningRejected)
        ));
        assert!(!matches!(
            result,
            Err(CardApduSessionErrorV2::Transport(
                CardTransportErrorV2::Sec1210ApplicationApduLimitExceeded
            ))
        ));
        assert_eq!(transport.calls, 0);
        assert_eq!(session.sign_attempts(), 100);
        assert!(session.is_terminated());
        assert_eq!(
            owner.terminate_process(NormalErrorV2::SigningRejected),
            NormalErrorV2::SigningRejected
        );
        assert_signing_rejected_and_wiped(&owner);
        assert!(wiped_bytes() > 0);
        assert!(matches!(
            owner.choose_export(NormalExportActionV2::Sd {
                caller_nonce: [0; 16]
            }),
            Err(NormalErrorV2::Finished)
        ));
        let mut late = [0x55; 72];
        assert!(matches!(
            owner.accept_process_card_b_signature(
                *request.review_hash(),
                request.input_index(),
                *request.role_b_pubkey(),
                &mut late,
            ),
            Err(NormalErrorV2::Finished)
        ));
        assert!(late.iter().all(|byte| *byte == 0));
        assert_signing_rejected_and_wiped(&owner);
        assert!(matches!(
            session.sign_card_b(&mut transport, &request),
            Err(CardApduSessionErrorV2::UnexpectedEvent)
        ));
        assert_eq!(transport.calls, 0);
    }

    #[test]
    fn terminating_card_session_drops_the_duplicate_core_identity_owner() {
        let mut mint = DeterministicSessionIdMint::new([0x51; 12], 0);
        let session_id = mint.mint().expect("deterministic session identity");
        let tracker = SessionTracker::new(Mode::Normal, session_id.as_bytes(), 24, 23)
            .expect("card protocol tracker");
        let mut session = CardApduSessionV2::new();
        session.card_session = Some(CardProtocolSession {
            session_id,
            tracker,
        });

        reset_wiped_bytes();
        session.terminate();
        assert!(session.card_session.is_none());
        assert!(session.is_terminated());
        assert_eq!(wiped_bytes(), 16);
    }
}
