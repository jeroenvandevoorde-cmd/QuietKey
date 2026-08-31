//! QKIP-bound non-signing product shell.

use crate::capability::{CardPresence, CoreDeviceGrants, CoreScreen, KeypadKey};
use crate::error::{CoreError, Interruption};
use crate::io_wire::{
    encode_ingress_begin, encode_ingress_read, parse_response, ExpectedResponse, Response, Source,
};
#[cfg(any(test, feature = "fuzzing"))]
use crate::session_id::DeterministicSessionIdMint;
use crate::session_id::{mint_session_id, SessionId, SessionIdError};
use crate::wipe::{self, WipingVec};
use qk_ipc::{CoreEvent, CoreProtocol, IpcError, OutboundFrame, StreamDecoder};

/// Product-flow family selected by the supervisor for this HOST shell.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CoreMode {
    Setup,
    A1B,
    Kit,
}

/// Exact public shell state vocabulary.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CoreState {
    Opening,
    Ready,
    IngressBeginPending,
    IngressReadReady,
    IngressReadPending,
    IngressComplete,
    Closing,
    Closed,
    Terminated,
}

/// Non-byte result of consuming one stream prefix.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CoreReceiveEvent {
    NeedMore,
    SessionReady,
    IngressBegan {
        source: Source,
        total_len: u32,
    },
    IngressChunk {
        offset: u32,
        chunk_len: u32,
        final_chunk: bool,
    },
    SessionClosed,
}

/// Exact stream-consumption fact and the at-most-one resulting shell event.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CoreReceiveOutcome {
    consumed: usize,
    event: CoreReceiveEvent,
}

impl CoreReceiveOutcome {
    pub const fn consumed(&self) -> usize {
        self.consumed
    }

    pub const fn event(&self) -> CoreReceiveEvent {
        self.event
    }
}

/// One already-formed QKIP frame owned under the qk-core wipe boundary.
pub struct CoreOutbound {
    frame: WipingVec,
}

impl CoreOutbound {
    /// Exact complete frame bytes, valid only while this owner lives.
    pub fn frame_bytes(&self) -> &[u8] {
        self.frame.as_slice()
    }

    pub fn len(&self) -> usize {
        self.frame.len()
    }

    pub fn is_empty(&self) -> bool {
        self.frame.len() == 0
    }
}

/// Completed hostile transport bytes.
///
/// The owner is deliberately non-Clone, non-Copy, non-Debug and non-Display.
/// This slice exposes only its source and length; it exposes no byte accessor
/// and creates no semantic or authentication fact.
pub struct HostileIngress {
    source: Source,
    bytes: WipingVec,
}

impl HostileIngress {
    pub const fn source(&self) -> Source {
        self.source
    }

    pub fn len(&self) -> usize {
        self.bytes.len()
    }

    pub fn is_empty(&self) -> bool {
        self.bytes.len() == 0
    }

    #[cfg(feature = "fuzzing")]
    #[doc(hidden)]
    pub fn fuzz_bytes(&self) -> &[u8] {
        self.bytes.as_slice()
    }
}

struct IngressTransfer {
    source: Source,
    total_len: u32,
    offset: u32,
    bytes: WipingVec,
}

impl IngressTransfer {
    fn try_new(source: Source, total_len: u32) -> Result<Self, CoreError> {
        let length = usize::try_from(total_len).map_err(|_| CoreError::AllocationFailed)?;
        let bytes = WipingVec::try_zeroed(length).map_err(|_| CoreError::AllocationFailed)?;
        Ok(Self {
            source,
            total_len,
            offset: 0,
            bytes,
        })
    }

    fn append(&mut self, offset: u32, chunk: &[u8]) -> Result<bool, CoreError> {
        if offset != self.offset {
            return Err(CoreError::ResponseOffsetMismatch);
        }
        let chunk_len =
            u32::try_from(chunk.len()).map_err(|_| CoreError::ResponseChunkLengthExceeded)?;
        let end = offset
            .checked_add(chunk_len)
            .ok_or(CoreError::ResponseTransferLengthExceeded)?;
        if end > self.total_len {
            return Err(CoreError::ResponseTransferLengthExceeded);
        }
        let start = usize::try_from(offset).map_err(|_| CoreError::ResponseOffsetMismatch)?;
        let end_usize =
            usize::try_from(end).map_err(|_| CoreError::ResponseTransferLengthExceeded)?;
        let destination = self
            .bytes
            .as_mut_slice()
            .get_mut(start..end_usize)
            .ok_or(CoreError::ResponseTransferLengthExceeded)?;
        destination.copy_from_slice(chunk);
        self.offset = end;
        Ok(end == self.total_len)
    }

    fn complete(self) -> Result<HostileIngress, CoreError> {
        if self.offset != self.total_len {
            return Err(CoreError::InvalidTransition);
        }
        Ok(HostileIngress {
            source: self.source,
            bytes: self.bytes,
        })
    }
}

/// One qk-core HOST session and all of its transport-owned state.
pub struct CoreSession {
    mode: CoreMode,
    state: CoreState,
    terminal_reason: Option<Interruption>,
    ipc: Option<CoreProtocol>,
    decoder: Option<StreamDecoder>,
    expected: Option<ExpectedResponse>,
    transfer: Option<IngressTransfer>,
    completed: Option<HostileIngress>,
    grants: CoreDeviceGrants,
}

impl CoreSession {
    /// Mint a process-owned identity and emit exchange-one SessionOpen.
    pub fn start(
        mode: CoreMode,
        mut grants: CoreDeviceGrants,
    ) -> Result<(Self, CoreOutbound), CoreError> {
        grants.display_mut().show(CoreScreen::Opening)?;
        let session_id = mint_session_id().map_err(map_session_id_error)?;
        Self::start_with_id(mode, grants, session_id)
    }

    fn start_with_id(
        mode: CoreMode,
        grants: CoreDeviceGrants,
        session_id: SessionId,
    ) -> Result<(Self, CoreOutbound), CoreError> {
        let mut ipc = CoreProtocol::new(*session_id.as_bytes());
        let outbound = ipc.begin().map_err(CoreError::Ipc)?;
        let frame = encode_outer(outbound, &[])?;
        let session = Self {
            mode,
            state: CoreState::Opening,
            terminal_reason: None,
            ipc: Some(ipc),
            decoder: Some(StreamDecoder::new()),
            expected: None,
            transfer: None,
            completed: None,
            grants,
        };
        Ok((session, frame))
    }

    pub const fn mode(&self) -> CoreMode {
        self.mode
    }

    pub const fn state(&self) -> CoreState {
        self.state
    }

    pub const fn terminal_reason(&self) -> Option<Interruption> {
        self.terminal_reason
    }

    pub fn current_screen(&self) -> Option<CoreScreen> {
        self.grants.display().current()
    }

    pub fn completed_ingress(&self) -> Option<&HostileIngress> {
        self.completed.as_ref()
    }

    /// Emit the sole typed ingress-begin operation.
    pub fn begin_ingress(&mut self, source: Source) -> Result<CoreOutbound, CoreError> {
        self.require_live()?;
        if self.state != CoreState::Ready
            || self.transfer.is_some()
            || self.completed.is_some()
            || self.expected.is_some()
        {
            return Err(self.fail(CoreError::InvalidTransition));
        }
        self.show_or_terminate(CoreScreen::IngressBeginPending)?;
        let mut payload = encode_ingress_begin(source);
        let result = self.begin_operation(
            &payload,
            ExpectedResponse::IngressBegin { source },
            CoreState::IngressBeginPending,
        );
        wipe::bytes(&mut payload);
        result
    }

    /// Emit the next exact-offset ingress-read operation.
    pub fn request_next_chunk(&mut self) -> Result<CoreOutbound, CoreError> {
        self.require_live()?;
        if self.state != CoreState::IngressReadReady || self.expected.is_some() {
            return Err(self.fail(CoreError::InvalidTransition));
        }
        let (offset, total_len) = match self.transfer.as_ref() {
            Some(transfer) => (transfer.offset, transfer.total_len),
            None => return Err(self.fail(CoreError::InvalidTransition)),
        };
        self.show_or_terminate(CoreScreen::IngressReadPending)?;
        let mut payload = encode_ingress_read(offset);
        let result = self.begin_operation(
            &payload,
            ExpectedResponse::IngressRead {
                expected_offset: offset,
                total_len,
            },
            CoreState::IngressReadPending,
        );
        wipe::bytes(&mut payload);
        result
    }

    /// Begin graceful QKIP close when no transfer is active.
    pub fn begin_close(&mut self) -> Result<CoreOutbound, CoreError> {
        self.require_live()?;
        if !matches!(self.state, CoreState::Ready | CoreState::IngressComplete)
            || self.transfer.is_some()
            || self.expected.is_some()
        {
            return Err(self.fail(CoreError::InvalidTransition));
        }
        self.show_or_terminate(CoreScreen::Closing)?;
        let outbound = match self.ipc.as_mut() {
            Some(ipc) => ipc.close().map_err(CoreError::Ipc),
            None => Err(CoreError::CoreTerminated),
        };
        let outbound = match outbound {
            Ok(value) => value,
            Err(error) => return Err(self.fail(error)),
        };
        match encode_outer(outbound, &[]) {
            Ok(frame) => {
                self.state = CoreState::Closing;
                Ok(frame)
            }
            Err(error) => Err(self.fail(error)),
        }
    }

    /// Consume at most one complete hostile stream frame.
    pub fn receive(
        &mut self,
        input: &[u8],
        ancillary_present: bool,
    ) -> Result<CoreReceiveOutcome, CoreError> {
        self.require_live()?;
        let outcome = match self.decoder.as_mut() {
            Some(decoder) => decoder.ingest(input, ancillary_present),
            None => return Err(CoreError::CoreTerminated),
        };
        let outcome = match outcome {
            Ok(value) => value,
            Err(error) => return Err(self.fail_ipc(error)),
        };
        if !outcome.frame_ready() {
            return Ok(CoreReceiveOutcome {
                consumed: outcome.consumed(),
                event: CoreReceiveEvent::NeedMore,
            });
        }
        let frame = match self.decoder.as_mut() {
            Some(decoder) => decoder.take_frame(),
            None => return Err(CoreError::CoreTerminated),
        };
        let frame = match frame {
            Ok(value) => value,
            Err(error) => return Err(self.fail_ipc(error)),
        };
        let event = match self.ipc.as_mut() {
            Some(ipc) => ipc.accept(&frame),
            None => return Err(CoreError::CoreTerminated),
        };
        let event = match event {
            Ok(value) => value,
            Err(error) => return Err(self.fail_ipc(error)),
        };
        let shell_event = match event {
            CoreEvent::SessionReady => self.accept_ready(frame.payload()),
            CoreEvent::OperationResponse => self.accept_operation(frame.payload()),
            CoreEvent::SessionClosed => self.accept_closed(frame.payload()),
        };
        match shell_event {
            Ok(event) => Ok(CoreReceiveOutcome {
                consumed: outcome.consumed(),
                event,
            }),
            Err(error) => Err(self.fail(error)),
        }
    }

    /// Record clean or partial connection EOF through the QKIP receive-failure
    /// family, then enter the universal peer-loss terminal path.
    pub fn connection_closed(&mut self) -> Result<Interruption, CoreError> {
        self.require_live()?;
        let decoder_error = match self.decoder.as_mut() {
            Some(decoder) => decoder.finish(),
            None => IpcError::PeerLost,
        };
        let protocol_error = match self.ipc.as_mut() {
            Some(ipc) => ipc.receive_failed(decoder_error),
            None => IpcError::SessionTerminated,
        };
        self.terminate(Interruption::PeerLost);
        if protocol_error == IpcError::PeerLost {
            Ok(Interruption::PeerLost)
        } else {
            Err(CoreError::Ipc(protocol_error))
        }
    }

    /// Apply one universal closed interruption.
    pub fn interrupt(&mut self, reason: Interruption) -> Result<Interruption, CoreError> {
        self.require_live()?;
        if reason == Interruption::PeerLost {
            return self.connection_closed();
        }
        self.terminate(reason);
        Ok(reason)
    }

    /// Apply one typed P0.1 key in the deliberately empty business shell.
    pub fn handle_key(&mut self, key: KeypadKey) -> Result<Interruption, CoreError> {
        self.require_live()?;
        let key = match self.grants.keypad_mut().read(key) {
            Ok(value) => value,
            Err(error) => {
                self.terminate(Interruption::CapabilityFailed);
                return Err(error);
            }
        };
        if key == KeypadKey::CancelBack {
            self.terminate(Interruption::Cancelled);
            Ok(Interruption::Cancelled)
        } else {
            Err(CoreError::NoActiveFlow)
        }
    }

    /// Observe only card presence; removal is a universal interruption.
    pub fn observe_card(&mut self, presence: CardPresence) -> Result<CardPresence, CoreError> {
        self.require_live()?;
        let observed = match self.grants.card_slot_mut().observe(presence) {
            Ok(value) => value,
            Err(error) => {
                self.terminate(Interruption::CapabilityFailed);
                return Err(error);
            }
        };
        if observed == CardPresence::Absent {
            self.terminate(Interruption::CardRemoved);
        }
        Ok(observed)
    }

    fn begin_operation(
        &mut self,
        payload: &[u8],
        expected: ExpectedResponse,
        pending_state: CoreState,
    ) -> Result<CoreOutbound, CoreError> {
        let outbound = match self.ipc.as_mut() {
            Some(ipc) => ipc.request().map_err(CoreError::Ipc),
            None => Err(CoreError::CoreTerminated),
        };
        let outbound = match outbound {
            Ok(value) => value,
            Err(error) => return Err(self.fail(error)),
        };
        let frame = match encode_outer(outbound, payload) {
            Ok(value) => value,
            Err(error) => return Err(self.fail(error)),
        };
        self.expected = Some(expected);
        self.state = pending_state;
        Ok(frame)
    }

    fn accept_ready(&mut self, payload: &[u8]) -> Result<CoreReceiveEvent, CoreError> {
        if self.state != CoreState::Opening || !payload.is_empty() {
            return Err(CoreError::InvalidTransition);
        }
        self.state = CoreState::Ready;
        self.show_or_terminate(CoreScreen::Ready)?;
        Ok(CoreReceiveEvent::SessionReady)
    }

    fn accept_operation(&mut self, payload: &[u8]) -> Result<CoreReceiveEvent, CoreError> {
        let expected = self.expected.take().ok_or(CoreError::InvalidTransition)?;
        let parsed = parse_response(payload, expected)?;
        match parsed {
            Response::IngressBegin { source, total_len } => {
                if self.state != CoreState::IngressBeginPending || self.transfer.is_some() {
                    return Err(CoreError::InvalidTransition);
                }
                self.transfer = Some(IngressTransfer::try_new(source, total_len)?);
                self.state = CoreState::IngressReadReady;
                self.show_or_terminate(CoreScreen::IngressReadReady)?;
                Ok(CoreReceiveEvent::IngressBegan { source, total_len })
            }
            Response::IngressRead {
                offset,
                final_chunk,
                chunk,
            } => {
                if self.state != CoreState::IngressReadPending {
                    return Err(CoreError::InvalidTransition);
                }
                let complete = match self.transfer.as_mut() {
                    Some(transfer) => transfer.append(offset, chunk)?,
                    None => return Err(CoreError::InvalidTransition),
                };
                if complete != final_chunk {
                    return Err(CoreError::ResponseFinalMismatch);
                }
                let chunk_len = u32::try_from(chunk.len())
                    .map_err(|_| CoreError::ResponseChunkLengthExceeded)?;
                if complete {
                    let transfer = self.transfer.take().ok_or(CoreError::InvalidTransition)?;
                    self.completed = Some(transfer.complete()?);
                    self.state = CoreState::IngressComplete;
                    self.show_or_terminate(CoreScreen::IngressComplete)?;
                } else {
                    self.state = CoreState::IngressReadReady;
                    self.show_or_terminate(CoreScreen::IngressReadReady)?;
                }
                Ok(CoreReceiveEvent::IngressChunk {
                    offset,
                    chunk_len,
                    final_chunk,
                })
            }
        }
    }

    fn accept_closed(&mut self, payload: &[u8]) -> Result<CoreReceiveEvent, CoreError> {
        if self.state != CoreState::Closing || !payload.is_empty() {
            return Err(CoreError::InvalidTransition);
        }
        self.state = CoreState::Closed;
        self.decoder = None;
        self.ipc = None;
        self.expected = None;
        self.transfer = None;
        self.completed = None;
        self.show_or_terminate(CoreScreen::Closed)?;
        Ok(CoreReceiveEvent::SessionClosed)
    }

    fn show_or_terminate(&mut self, screen: CoreScreen) -> Result<(), CoreError> {
        match self.grants.display_mut().show(screen) {
            Ok(()) => Ok(()),
            Err(error) => {
                self.terminate(Interruption::CapabilityFailed);
                Err(error)
            }
        }
    }

    fn fail_ipc(&mut self, error: IpcError) -> CoreError {
        if let Some(ipc) = self.ipc.as_mut() {
            let _ = ipc.receive_failed(error);
        }
        self.terminate(Interruption::OperationFailed);
        CoreError::Ipc(error)
    }

    fn fail(&mut self, error: CoreError) -> CoreError {
        self.terminate(Interruption::OperationFailed);
        error
    }

    fn terminate(&mut self, reason: Interruption) {
        if self.state == CoreState::Terminated {
            return;
        }
        self.state = CoreState::Terminated;
        self.terminal_reason = Some(reason);
        self.expected = None;
        self.transfer = None;
        self.completed = None;
        self.decoder = None;
        self.ipc = None;
        let _ = self.grants.display_mut().show(CoreScreen::Terminated);
    }

    fn require_live(&self) -> Result<(), CoreError> {
        if self.state == CoreState::Terminated || self.state == CoreState::Closed {
            Err(CoreError::CoreTerminated)
        } else {
            Ok(())
        }
    }
}

impl Drop for CoreSession {
    fn drop(&mut self) {
        if !matches!(self.state, CoreState::Closed | CoreState::Terminated) {
            self.terminate(Interruption::OperationFailed);
        }
    }
}

fn encode_outer(outbound: OutboundFrame, payload: &[u8]) -> Result<CoreOutbound, CoreError> {
    let length = qk_ipc::HEADER_BYTES
        .checked_add(payload.len())
        .ok_or(CoreError::AllocationFailed)?;
    let mut frame = WipingVec::try_zeroed(length).map_err(|_| CoreError::AllocationFailed)?;
    let written = outbound
        .encode(payload, frame.as_mut_slice())
        .map_err(CoreError::Ipc)?;
    if written != length {
        return Err(CoreError::InvalidTransition);
    }
    Ok(CoreOutbound { frame })
}

const fn map_session_id_error(error: SessionIdError) -> CoreError {
    match error {
        SessionIdError::Unavailable => CoreError::SessionIdUnavailable,
        SessionIdError::Exhausted => CoreError::SessionIdExhausted,
    }
}

/// Deterministic public-data constructor used only by unit tests and the
/// ring-fenced session target.
#[cfg(any(test, feature = "fuzzing"))]
pub fn fuzz_start_session(
    namespace: [u8; 12],
    last_counter: u32,
    mode: CoreMode,
    mut grants: CoreDeviceGrants,
) -> Result<(CoreSession, CoreOutbound), CoreError> {
    grants.display_mut().show(CoreScreen::Opening)?;
    let mut mint = DeterministicSessionIdMint::new(namespace, last_counter);
    let session_id = mint.mint().map_err(map_session_id_error)?;
    CoreSession::start_with_id(mode, grants, session_id)
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    use crate::capability::{MockCardSlot, MockDisplay, MockKeypad};
    use qk_ipc::{encode_frame, Direction, MessageKind, HEADER_BYTES};

    fn grants() -> CoreDeviceGrants {
        CoreDeviceGrants::validate(
            Some(MockDisplay::new()),
            Some(MockKeypad::new()),
            Some(MockCardSlot::new(CardPresence::Present)),
            false,
        )
        .unwrap()
    }

    fn response(
        session_id: [u8; 16],
        exchange_id: u32,
        kind: MessageKind,
        payload: &[u8],
    ) -> Vec<u8> {
        let mut output = vec![0; HEADER_BYTES + payload.len()];
        let length = encode_frame(
            Direction::IoToCore,
            kind,
            session_id,
            exchange_id,
            payload,
            &mut output,
        )
        .unwrap();
        assert_eq!(length, output.len());
        output
    }

    fn session_id(outbound: &CoreOutbound) -> [u8; 16] {
        let mut id = [0u8; 16];
        id.copy_from_slice(&outbound.frame_bytes()[8..24]);
        id
    }

    #[test]
    fn deterministic_open_and_close_are_exact_and_absorbing() {
        let (mut session, open) =
            fuzz_start_session([0x2a; 12], 0, CoreMode::Setup, grants()).unwrap();
        let id = session_id(&open);
        assert_eq!(&id[..12], &[0x2a; 12]);
        assert_eq!(&id[12..], &[1, 0, 0, 0]);
        let ready = response(id, 1, MessageKind::SessionReady, &[]);
        assert_eq!(
            session.receive(&ready, false).unwrap().event(),
            CoreReceiveEvent::SessionReady
        );
        let close = session.begin_close().unwrap();
        assert!(!close.is_empty());
        let closed = response(id, 2, MessageKind::SessionClosed, &[]);
        assert_eq!(
            session.receive(&closed, false).unwrap().event(),
            CoreReceiveEvent::SessionClosed
        );
        assert_eq!(session.state(), CoreState::Closed);
        assert_eq!(session.receive(&[], false), Err(CoreError::CoreTerminated));
    }

    #[test]
    fn key_and_card_routes_are_closed() {
        let (mut session, _) = fuzz_start_session([0x31; 12], 0, CoreMode::A1B, grants()).unwrap();
        assert_eq!(
            session.handle_key(KeypadKey::One),
            Err(CoreError::NoActiveFlow)
        );
        assert_eq!(session.state(), CoreState::Opening);
        assert_eq!(
            session.observe_card(CardPresence::Absent),
            Ok(CardPresence::Absent)
        );
        assert_eq!(session.state(), CoreState::Terminated);
        assert_eq!(session.terminal_reason(), Some(Interruption::CardRemoved));
    }
}
