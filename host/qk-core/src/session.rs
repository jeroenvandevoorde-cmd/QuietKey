//! QKIP-bound HOST product shell for provisioning and purpose-bound normal sessions.

use crate::capability::{
    CardBPublicBindingV2, CardMockErrorV2, CardPresence, CoreDeviceGrants, CoreScreen, KeypadKey,
    NormalCardBDataV2, NormalCardMockErrorV2,
};
use crate::error::{CoreError, Interruption};
use crate::io_wire::{
    encode_a1_print_begin, encode_a1_print_finish, encode_a1_print_write, encode_ingress_begin,
    encode_ingress_read, encode_kit_print_begin, encode_kit_print_finish, encode_kit_print_write,
    parse_print_response, parse_response, ExpectedPrintResponse, ExpectedResponse, PrintArtifact,
    PrintResponse, Response, Source, A1_PRINT_BYTES, KIT_PRINT_BYTES,
};
#[cfg(any(test, feature = "fuzzing"))]
use crate::session_id::DeterministicSessionIdMint;
use crate::session_id::{mint_session_id, SessionId, SessionIdError};
use crate::wipe::{self, WipingArray, WipingVec};
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
    EgressBeginPending,
    EgressWriteReady,
    EgressWritePending,
    EgressFinishReady,
    EgressFinishPending,
    EgressComplete,
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
    A1PrintBegan,
    KitPrintBegan,
    A1PrintWritten {
        accepted_total: u32,
    },
    KitPrintWritten {
        accepted_total: u32,
    },
    A1PrintFinished {
        total_len: u32,
    },
    KitPrintFinished {
        total_len: u32,
    },
    SessionClosed,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum OutstandingResponse {
    Ingress(ExpectedResponse),
    Print(ExpectedPrintResponse),
    NormalEgress,
}

/// Exact stream-consumption fact and the at-most-one resulting shell event.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CoreReceiveOutcome {
    consumed: usize,
    event: CoreReceiveEvent,
}

/// Crate-private stream fact for the purpose-bound normal egress path.
pub(crate) struct NormalCoreReceiveOutcome {
    pub(crate) consumed: usize,
    pub(crate) response_ready: bool,
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

    pub(crate) fn into_normal_parts(self) -> (Source, WipingVec) {
        (self.source, self.bytes)
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
    session_identity: Option<WipingArray<16>>,
    ipc: Option<CoreProtocol>,
    decoder: Option<StreamDecoder>,
    expected: Option<OutstandingResponse>,
    transfer: Option<IngressTransfer>,
    completed: Option<HostileIngress>,
    normal_response: Option<WipingVec>,
    print_artifact: Option<PrintArtifact>,
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
        let mut identity = *session_id.as_bytes();
        let mut ipc = CoreProtocol::new(identity);
        let outbound = ipc.begin().map_err(CoreError::Ipc)?;
        let frame = encode_outer(outbound, &[])?;
        let session = Self {
            mode,
            state: CoreState::Opening,
            terminal_reason: None,
            session_identity: Some(WipingArray::take(&mut identity)),
            ipc: Some(ipc),
            decoder: Some(StreamDecoder::new()),
            expected: None,
            transfer: None,
            completed: None,
            normal_response: None,
            print_artifact: None,
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

    /// Borrow the exact QKIP identity solely for purpose-bound approval-token
    /// provenance. No public shell surface exposes this retained copy.
    pub(crate) fn normal_session_identity(&mut self) -> Result<&[u8; 16], CoreError> {
        self.require_normal_live()?;
        if self.session_identity.is_none() {
            return Err(self.fail(CoreError::InvalidTransition));
        }
        match self.session_identity.as_ref() {
            Some(identity) => Ok(identity.as_array()),
            None => Err(CoreError::InvalidTransition),
        }
    }

    /// Emit the sole typed ingress-begin operation.
    pub fn begin_ingress(&mut self, source: Source) -> Result<CoreOutbound, CoreError> {
        self.require_live()?;
        if self.state != CoreState::Ready
            || self.transfer.is_some()
            || self.completed.is_some()
            || self.normal_response.is_some()
            || self.expected.is_some()
            || self.print_artifact.is_some()
        {
            return Err(self.fail(CoreError::InvalidTransition));
        }
        self.show_or_terminate(CoreScreen::IngressBeginPending)?;
        let mut payload = encode_ingress_begin(source);
        let result = self.begin_operation(
            &payload,
            OutstandingResponse::Ingress(ExpectedResponse::IngressBegin { source }),
            CoreState::IngressBeginPending,
        );
        wipe::bytes(&mut payload);
        result
    }

    /// Emit the next exact-offset ingress-read operation.
    pub fn request_next_chunk(&mut self) -> Result<CoreOutbound, CoreError> {
        self.request_chunk(true)
    }

    /// Emit the next exact-offset A1 scan-back read without replacing the
    /// purpose screen with the generic ingress lifecycle screen.
    pub(crate) fn request_a1_scanback_chunk(&mut self) -> Result<CoreOutbound, CoreError> {
        if self.mode != CoreMode::Setup || self.print_artifact != Some(PrintArtifact::A1) {
            return Err(self.fail(CoreError::InvalidTransition));
        }
        self.request_chunk(false)
    }

    fn request_chunk(&mut self, show_lifecycle: bool) -> Result<CoreOutbound, CoreError> {
        self.require_live()?;
        if self.state != CoreState::IngressReadReady || self.expected.is_some() {
            return Err(self.fail(CoreError::InvalidTransition));
        }
        let (offset, total_len) = match self.transfer.as_ref() {
            Some(transfer) => (transfer.offset, transfer.total_len),
            None => return Err(self.fail(CoreError::InvalidTransition)),
        };
        if show_lifecycle {
            self.show_or_terminate(CoreScreen::IngressReadPending)?;
        }
        let mut payload = encode_ingress_read(offset);
        let result = self.begin_operation(
            &payload,
            OutstandingResponse::Ingress(ExpectedResponse::IngressRead {
                expected_offset: offset,
                total_len,
            }),
            CoreState::IngressReadPending,
        );
        wipe::bytes(&mut payload);
        result
    }

    /// Begin the exact purpose-bound 67-byte A1 print transfer.
    pub(crate) fn begin_a1_print(&mut self) -> Result<CoreOutbound, CoreError> {
        let mut payload = encode_a1_print_begin();
        let result = self.begin_print(
            PrintArtifact::A1,
            &payload,
            ExpectedPrintResponse::Begin {
                artifact: PrintArtifact::A1,
            },
            CoreState::EgressBeginPending,
        );
        wipe::bytes(&mut payload);
        result
    }

    /// Write the sole complete A1 artifact at offset zero.
    pub(crate) fn write_a1_print(
        &mut self,
        artifact: &[u8; A1_PRINT_BYTES],
    ) -> Result<CoreOutbound, CoreError> {
        self.require_print_phase(PrintArtifact::A1, CoreState::EgressWriteReady)?;
        let mut payload = encode_a1_print_write(artifact);
        let result = self.begin_operation(
            &payload,
            OutstandingResponse::Print(ExpectedPrintResponse::Write {
                artifact: PrintArtifact::A1,
            }),
            CoreState::EgressWritePending,
        );
        wipe::bytes(&mut payload);
        result
    }

    /// Finish the exact A1 print transfer.
    pub(crate) fn finish_a1_print(&mut self) -> Result<CoreOutbound, CoreError> {
        self.require_print_phase(PrintArtifact::A1, CoreState::EgressFinishReady)?;
        let mut payload = encode_a1_print_finish();
        let result = self.begin_operation(
            &payload,
            OutstandingResponse::Print(ExpectedPrintResponse::Finish {
                artifact: PrintArtifact::A1,
            }),
            CoreState::EgressFinishPending,
        );
        wipe::bytes(&mut payload);
        result
    }

    /// Begin the exact purpose-bound 829-byte Kit-page print transfer.
    pub(crate) fn begin_kit_print(&mut self) -> Result<CoreOutbound, CoreError> {
        let mut payload = encode_kit_print_begin();
        let result = self.begin_print(
            PrintArtifact::Kit,
            &payload,
            ExpectedPrintResponse::Begin {
                artifact: PrintArtifact::Kit,
            },
            CoreState::EgressBeginPending,
        );
        wipe::bytes(&mut payload);
        result
    }

    /// Write the sole complete Kit-page artifact at offset zero.
    pub(crate) fn write_kit_print(
        &mut self,
        artifact: &[u8; KIT_PRINT_BYTES],
    ) -> Result<CoreOutbound, CoreError> {
        self.require_print_phase(PrintArtifact::Kit, CoreState::EgressWriteReady)?;
        let mut payload = encode_kit_print_write(artifact);
        let result = self.begin_operation(
            &payload,
            OutstandingResponse::Print(ExpectedPrintResponse::Write {
                artifact: PrintArtifact::Kit,
            }),
            CoreState::EgressWritePending,
        );
        wipe::bytes(&mut payload);
        result
    }

    /// Finish the exact Kit-page print transfer.
    pub(crate) fn finish_kit_print(&mut self) -> Result<CoreOutbound, CoreError> {
        self.require_print_phase(PrintArtifact::Kit, CoreState::EgressFinishReady)?;
        let mut payload = encode_kit_print_finish();
        let result = self.begin_operation(
            &payload,
            OutstandingResponse::Print(ExpectedPrintResponse::Finish {
                artifact: PrintArtifact::Kit,
            }),
            CoreState::EgressFinishPending,
        );
        wipe::bytes(&mut payload);
        result
    }

    /// Begin the sole allowed scan-back after an accepted A1 print receipt.
    pub(crate) fn begin_a1_scanback(&mut self) -> Result<CoreOutbound, CoreError> {
        self.require_live()?;
        if self.mode != CoreMode::Setup
            || self.state != CoreState::EgressComplete
            || self.print_artifact != Some(PrintArtifact::A1)
            || self.transfer.is_some()
            || self.completed.is_some()
            || self.expected.is_some()
        {
            return Err(self.fail(CoreError::InvalidTransition));
        }
        let mut payload = encode_ingress_begin(Source::CameraA1Candidate);
        let result = self.begin_operation(
            &payload,
            OutstandingResponse::Ingress(ExpectedResponse::IngressBegin {
                source: Source::CameraA1Candidate,
            }),
            CoreState::IngressBeginPending,
        );
        wipe::bytes(&mut payload);
        result
    }

    /// Consume the sealed A1 scan-back and compare it without exposing bytes.
    pub(crate) fn consume_a1_scanback(
        &mut self,
        expected: &[u8; A1_PRINT_BYTES],
    ) -> Result<bool, CoreError> {
        self.require_live()?;
        if self.mode != CoreMode::Setup
            || self.state != CoreState::IngressComplete
            || self.print_artifact != Some(PrintArtifact::A1)
            || self.transfer.is_some()
            || self.expected.is_some()
        {
            return Err(self.fail(CoreError::InvalidTransition));
        }
        let candidate = self
            .completed
            .take()
            .ok_or_else(|| self.fail(CoreError::InvalidTransition))?;
        if candidate.source != Source::CameraA1Candidate {
            drop(candidate);
            return Err(self.fail(CoreError::InvalidTransition));
        }
        let matches = candidate.bytes.as_slice() == expected.as_slice();
        drop(candidate);
        self.print_artifact = None;
        if matches {
            self.state = CoreState::Ready;
            Ok(true)
        } else {
            self.terminate(Interruption::OperationFailed);
            Ok(false)
        }
    }

    /// Select one setup screen without exposing the capability owner.
    pub(crate) fn setup_show(&mut self, screen: CoreScreen) -> Result<(), CoreError> {
        self.require_setup_live()?;
        self.show_or_terminate(screen)
    }

    /// Read one normalized setup key without applying shell navigation.
    pub(crate) fn setup_read_key(&mut self, key: KeypadKey) -> Result<KeypadKey, CoreError> {
        self.require_setup_live()?;
        match self.grants.keypad_mut().read(key) {
            Ok(value) => Ok(value),
            Err(error) => {
                self.terminate(Interruption::CapabilityFailed);
                Err(error)
            }
        }
    }

    /// Apply one public-only role-B setup binding to the card mock.
    pub(crate) fn setup_provision_b(
        &mut self,
        binding: CardBPublicBindingV2,
    ) -> Result<(), CardMockErrorV2> {
        self.grants.card_slot_mut().provision_b(binding)
    }

    /// Check one public-only role-B setup binding against the card mock.
    pub(crate) fn setup_verify_b(
        &mut self,
        binding: CardBPublicBindingV2,
    ) -> Result<(), CardMockErrorV2> {
        self.grants.card_slot_mut().verify_b(binding)
    }

    /// Consume one complete normal-flow ingress without exposing it through
    /// the public shell surface. The purpose owner performs the only semantic
    /// or authentication operation over the returned wiping allocation.
    pub(crate) fn take_normal_ingress(&mut self) -> Result<HostileIngress, CoreError> {
        self.require_normal_live()?;
        if self.state != CoreState::IngressComplete
            || self.transfer.is_some()
            || self.expected.is_some()
            || self.normal_response.is_some()
        {
            return Err(self.fail(CoreError::InvalidTransition));
        }
        let ingress = self
            .completed
            .take()
            .ok_or_else(|| self.fail(CoreError::InvalidTransition))?;
        self.state = CoreState::Ready;
        Ok(ingress)
    }

    /// Select one normal-flow typed screen without exposing the capability.
    pub(crate) fn normal_show(&mut self, screen: CoreScreen) -> Result<(), CoreError> {
        self.require_normal_live()?;
        self.show_or_terminate(screen)
    }

    /// Read one normalized normal-flow key.
    pub(crate) fn normal_read_key(&mut self, key: KeypadKey) -> Result<KeypadKey, CoreError> {
        self.require_normal_live()?;
        match self.grants.keypad_mut().read(key) {
            Ok(value) => Ok(value),
            Err(error) => {
                self.terminate(Interruption::CapabilityFailed);
                Err(error)
            }
        }
    }

    /// Consume the sole preloaded authenticated mock card-B factor.
    pub(crate) fn take_normal_card_data(
        &mut self,
    ) -> Result<NormalCardBDataV2, NormalCardMockErrorV2> {
        self.grants.card_slot_mut().take_normal_data()
    }

    /// Wrap one exact purpose-bound normal egress request in QKIP.
    pub(crate) fn begin_normal_egress(
        &mut self,
        payload: &[u8],
    ) -> Result<CoreOutbound, CoreError> {
        self.require_normal_live()?;
        if self.state != CoreState::Ready
            || self.transfer.is_some()
            || self.completed.is_some()
            || self.normal_response.is_some()
            || self.expected.is_some()
            || self.print_artifact.is_some()
        {
            return Err(self.fail(CoreError::InvalidTransition));
        }
        self.begin_operation(
            payload,
            OutstandingResponse::NormalEgress,
            CoreState::EgressWritePending,
        )
    }

    /// Consume the complete hostile inner response retained by QKIP.
    pub(crate) fn take_normal_egress_response(&mut self) -> Result<WipingVec, CoreError> {
        self.require_normal_live()?;
        if self.state != CoreState::Ready || self.expected.is_some() {
            return Err(self.fail(CoreError::InvalidTransition));
        }
        self.normal_response
            .take()
            .ok_or_else(|| self.fail(CoreError::InvalidTransition))
    }

    /// Consume at most one QKIP frame while an exact normal egress response is
    /// outstanding. This separate path avoids widening the legacy public
    /// shell-event vocabulary consumed by the byte-frozen setup owner.
    pub(crate) fn receive_normal_egress(
        &mut self,
        input: &[u8],
        ancillary_present: bool,
    ) -> Result<NormalCoreReceiveOutcome, CoreError> {
        self.require_normal_live()?;
        if self.expected != Some(OutstandingResponse::NormalEgress)
            || self.state != CoreState::EgressWritePending
        {
            return Err(self.fail(CoreError::InvalidTransition));
        }
        let outcome = match self.decoder.as_mut() {
            Some(decoder) => decoder.ingest(input, ancillary_present),
            None => return Err(CoreError::CoreTerminated),
        };
        let outcome = match outcome {
            Ok(value) => value,
            Err(error) => return Err(self.fail_ipc(error)),
        };
        if !outcome.frame_ready() {
            return Ok(NormalCoreReceiveOutcome {
                consumed: outcome.consumed(),
                response_ready: false,
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
        if event != CoreEvent::OperationResponse {
            return Err(self.fail(CoreError::InvalidTransition));
        }
        self.accept_normal_egress(frame.payload())?;
        Ok(NormalCoreReceiveOutcome {
            consumed: outcome.consumed(),
            response_ready: true,
        })
    }

    /// Route one normal-flow interruption through the universal terminal path.
    pub(crate) fn terminate_normal(&mut self, reason: Interruption) {
        self.terminate(reason);
    }

    /// Force a local setup failure through the universal wiping terminal path.
    pub(crate) fn setup_fail(&mut self) {
        self.terminate(Interruption::OperationFailed);
    }

    /// Route one setup interruption through the universal terminal path.
    pub(crate) fn terminate_setup(&mut self, reason: Interruption) {
        self.terminate(reason);
    }

    /// Begin graceful QKIP close when no transfer is active.
    pub fn begin_close(&mut self) -> Result<CoreOutbound, CoreError> {
        self.require_live()?;
        if !matches!(self.state, CoreState::Ready | CoreState::IngressComplete)
            || self.transfer.is_some()
            || self.expected.is_some()
            || self.print_artifact.is_some()
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
        expected: OutstandingResponse,
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
        match expected {
            OutstandingResponse::Ingress(expected) => self.accept_ingress(payload, expected),
            OutstandingResponse::Print(expected) => self.accept_print(payload, expected),
            OutstandingResponse::NormalEgress => Err(CoreError::InvalidTransition),
        }
    }

    fn accept_normal_egress(&mut self, payload: &[u8]) -> Result<(), CoreError> {
        if self.expected.take() != Some(OutstandingResponse::NormalEgress)
            || self.mode != CoreMode::A1B
            || self.state != CoreState::EgressWritePending
            || self.normal_response.is_some()
        {
            return Err(CoreError::InvalidTransition);
        }
        self.normal_response =
            Some(WipingVec::try_copy(payload).map_err(|_| CoreError::AllocationFailed)?);
        self.state = CoreState::Ready;
        Ok(())
    }

    fn accept_ingress(
        &mut self,
        payload: &[u8],
        expected: ExpectedResponse,
    ) -> Result<CoreReceiveEvent, CoreError> {
        let parsed = parse_response(payload, expected)?;
        match parsed {
            Response::IngressBegin { source, total_len } => {
                if self.state != CoreState::IngressBeginPending || self.transfer.is_some() {
                    return Err(CoreError::InvalidTransition);
                }
                self.transfer = Some(IngressTransfer::try_new(source, total_len)?);
                self.state = CoreState::IngressReadReady;
                if self.print_artifact != Some(PrintArtifact::A1) {
                    self.show_or_terminate(CoreScreen::IngressReadReady)?;
                }
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
                    if self.print_artifact != Some(PrintArtifact::A1) {
                        self.show_or_terminate(CoreScreen::IngressComplete)?;
                    }
                } else {
                    self.state = CoreState::IngressReadReady;
                    if self.print_artifact != Some(PrintArtifact::A1) {
                        self.show_or_terminate(CoreScreen::IngressReadReady)?;
                    }
                }
                Ok(CoreReceiveEvent::IngressChunk {
                    offset,
                    chunk_len,
                    final_chunk,
                })
            }
        }
    }

    fn accept_print(
        &mut self,
        payload: &[u8],
        expected: ExpectedPrintResponse,
    ) -> Result<CoreReceiveEvent, CoreError> {
        let parsed = parse_print_response(payload, expected)?;
        match parsed {
            PrintResponse::Begin { artifact } => {
                self.require_print_phase(artifact, CoreState::EgressBeginPending)?;
                self.state = CoreState::EgressWriteReady;
                Ok(match artifact {
                    PrintArtifact::A1 => CoreReceiveEvent::A1PrintBegan,
                    PrintArtifact::Kit => CoreReceiveEvent::KitPrintBegan,
                })
            }
            PrintResponse::Write {
                artifact,
                accepted_total,
            } => {
                self.require_print_phase(artifact, CoreState::EgressWritePending)?;
                self.state = CoreState::EgressFinishReady;
                Ok(match artifact {
                    PrintArtifact::A1 => CoreReceiveEvent::A1PrintWritten { accepted_total },
                    PrintArtifact::Kit => CoreReceiveEvent::KitPrintWritten { accepted_total },
                })
            }
            PrintResponse::Finish {
                artifact,
                total_len,
            } => {
                self.require_print_phase(artifact, CoreState::EgressFinishPending)?;
                match artifact {
                    PrintArtifact::A1 => {
                        self.state = CoreState::EgressComplete;
                        Ok(CoreReceiveEvent::A1PrintFinished { total_len })
                    }
                    PrintArtifact::Kit => {
                        self.print_artifact = None;
                        self.state = CoreState::Ready;
                        Ok(CoreReceiveEvent::KitPrintFinished { total_len })
                    }
                }
            }
        }
    }

    fn begin_print(
        &mut self,
        artifact: PrintArtifact,
        payload: &[u8],
        expected: ExpectedPrintResponse,
        pending_state: CoreState,
    ) -> Result<CoreOutbound, CoreError> {
        self.require_live()?;
        if self.mode != CoreMode::Setup
            || self.state != CoreState::Ready
            || self.transfer.is_some()
            || self.completed.is_some()
            || self.expected.is_some()
            || self.print_artifact.is_some()
        {
            return Err(self.fail(CoreError::InvalidTransition));
        }
        self.print_artifact = Some(artifact);
        self.begin_operation(payload, OutstandingResponse::Print(expected), pending_state)
    }

    fn require_print_phase(
        &mut self,
        artifact: PrintArtifact,
        state: CoreState,
    ) -> Result<(), CoreError> {
        self.require_live()?;
        if self.mode != CoreMode::Setup
            || self.state != state
            || self.print_artifact != Some(artifact)
            || self.transfer.is_some()
            || self.completed.is_some()
        {
            Err(self.fail(CoreError::InvalidTransition))
        } else {
            Ok(())
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
        self.normal_response = None;
        self.print_artifact = None;
        drop(self.session_identity.take());
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
        self.normal_response = None;
        self.print_artifact = None;
        self.decoder = None;
        self.ipc = None;
        drop(self.session_identity.take());
        let _ = self.grants.display_mut().show(CoreScreen::Terminated);
    }

    fn require_live(&self) -> Result<(), CoreError> {
        if self.state == CoreState::Terminated || self.state == CoreState::Closed {
            Err(CoreError::CoreTerminated)
        } else {
            Ok(())
        }
    }

    fn require_setup_live(&mut self) -> Result<(), CoreError> {
        self.require_live()?;
        if self.mode == CoreMode::Setup {
            Ok(())
        } else {
            Err(self.fail(CoreError::InvalidTransition))
        }
    }

    fn require_normal_live(&mut self) -> Result<(), CoreError> {
        self.require_live()?;
        if self.mode == CoreMode::A1B {
            Ok(())
        } else {
            Err(self.fail(CoreError::InvalidTransition))
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
    use crate::wipe::{reset_wiped_bytes, wiped_bytes};
    use crate::INNER_VERSION;
    use qk_ipc::{encode_frame, parse_frame, Direction, MessageKind, HEADER_BYTES};

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
        let output_len = HEADER_BYTES.checked_add(payload.len()).unwrap();
        let mut output = vec![0; output_len];
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
        id.copy_from_slice(outbound.frame_bytes().get(8..24).unwrap());
        id
    }

    fn inner_success(opcode: u8, body: &[u8]) -> Vec<u8> {
        let mut payload = vec![INNER_VERSION, opcode, 0, 0];
        payload.extend_from_slice(&(body.len() as u32).to_le_bytes());
        payload.extend_from_slice(body);
        payload
    }

    fn ready_setup(namespace: [u8; 12]) -> (CoreSession, [u8; 16]) {
        let (mut session, open) =
            fuzz_start_session(namespace, 0, CoreMode::Setup, grants()).unwrap();
        let id = session_id(&open);
        let ready = response(id, 1, MessageKind::SessionReady, &[]);
        assert_eq!(
            session.receive(&ready, false).unwrap().event(),
            CoreReceiveEvent::SessionReady
        );
        (session, id)
    }

    fn accept_operation(
        session: &mut CoreSession,
        id: [u8; 16],
        exchange: u32,
        opcode: u8,
        body: &[u8],
    ) -> CoreReceiveEvent {
        let payload = inner_success(opcode, body);
        let frame = response(id, exchange, MessageKind::OperationResponse, &payload);
        session.receive(&frame, false).unwrap().event()
    }

    fn finish_a1_scanback(
        session: &mut CoreSession,
        id: [u8; 16],
        expected: &[u8; A1_PRINT_BYTES],
        candidate: &[u8; A1_PRINT_BYTES],
    ) -> bool {
        let begin = session.begin_a1_scanback().unwrap();
        assert_eq!(
            parse_frame(begin.frame_bytes()).unwrap().payload(),
            [1, 1, 0, 0, 3, 0, 0, 0, 1, 0, 0]
        );
        assert_eq!(
            accept_operation(session, id, 5, 1, &[1, 67, 0, 0, 0]),
            CoreReceiveEvent::IngressBegan {
                source: Source::CameraA1Candidate,
                total_len: 67,
            }
        );
        let read = session.request_next_chunk().unwrap();
        assert_eq!(
            parse_frame(read.frame_bytes()).unwrap().payload(),
            [1, 2, 0, 0, 4, 0, 0, 0, 0, 0, 0, 0]
        );
        let mut body = vec![0, 0, 0, 0, 67, 0, 0, 0, 1];
        body.extend_from_slice(candidate);
        assert_eq!(
            accept_operation(session, id, 6, 2, &body),
            CoreReceiveEvent::IngressChunk {
                offset: 0,
                chunk_len: 67,
                final_chunk: true,
            }
        );
        session.consume_a1_scanback(expected).unwrap()
    }

    fn finish_a1_print(session: &mut CoreSession, id: [u8; 16], artifact: &[u8; A1_PRINT_BYTES]) {
        let begin = session.begin_a1_print().unwrap();
        assert_eq!(
            parse_frame(begin.frame_bytes()).unwrap().payload(),
            [1, 3, 0, 0, 8, 0, 0, 0, 3, 4, 67, 0, 0, 0, 0, 0]
        );
        assert_eq!(
            accept_operation(session, id, 2, 3, &[]),
            CoreReceiveEvent::A1PrintBegan
        );
        let write = session.write_a1_print(artifact).unwrap();
        let write = parse_frame(write.frame_bytes()).unwrap();
        assert_eq!(write.payload().len(), 83);
        assert_eq!(write.payload().get(16..), Some(artifact.as_slice()));
        assert_eq!(
            accept_operation(session, id, 3, 4, &[67, 0, 0, 0]),
            CoreReceiveEvent::A1PrintWritten { accepted_total: 67 }
        );
        let finish = session.finish_a1_print().unwrap();
        assert_eq!(
            parse_frame(finish.frame_bytes()).unwrap().payload(),
            [1, 5, 0, 0, 0, 0, 0, 0]
        );
        assert_eq!(
            accept_operation(session, id, 4, 5, &[3, 4, 67, 0, 0, 0]),
            CoreReceiveEvent::A1PrintFinished { total_len: 67 }
        );
        assert_eq!(session.state(), CoreState::EgressComplete);
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

    #[test]
    fn a1_print_receipt_is_the_only_path_to_exact_consuming_scanback() {
        let artifact = [0xa1; A1_PRINT_BYTES];
        let (mut matched, matched_id) = ready_setup([0x41; 12]);
        matched.setup_show(CoreScreen::ScanBackA1).unwrap();
        finish_a1_print(&mut matched, matched_id, &artifact);
        assert!(finish_a1_scanback(
            &mut matched,
            matched_id,
            &artifact,
            &artifact
        ));
        assert_eq!(matched.state(), CoreState::Ready);
        assert!(matched.completed_ingress().is_none());

        let (mut mismatch, mismatch_id) = ready_setup([0x42; 12]);
        finish_a1_print(&mut mismatch, mismatch_id, &artifact);
        assert!(!finish_a1_scanback(
            &mut mismatch,
            mismatch_id,
            &artifact,
            &[0xa2; A1_PRINT_BYTES]
        ));
        assert_eq!(mismatch.state(), CoreState::Terminated);
        assert_eq!(
            mismatch.terminal_reason(),
            Some(Interruption::OperationFailed)
        );
        assert!(mismatch.completed_ingress().is_none());
    }

    #[test]
    fn kit_print_is_exactly_one_begin_write_finish_and_returns_ready() {
        let artifact = [0x4b; KIT_PRINT_BYTES];
        let (mut session, id) = ready_setup([0x43; 12]);
        let begin = session.begin_kit_print().unwrap();
        assert_eq!(
            parse_frame(begin.frame_bytes()).unwrap().payload(),
            [1, 3, 0, 0, 8, 0, 0, 0, 3, 5, 0x3d, 0x03, 0, 0, 0, 0]
        );
        assert_eq!(
            accept_operation(&mut session, id, 2, 3, &[]),
            CoreReceiveEvent::KitPrintBegan
        );
        let write = session.write_kit_print(&artifact).unwrap();
        let write = parse_frame(write.frame_bytes()).unwrap();
        assert_eq!(write.payload().len(), 845);
        assert_eq!(write.payload().get(16..), Some(artifact.as_slice()));
        assert_eq!(
            accept_operation(&mut session, id, 3, 4, &[0x3d, 0x03, 0, 0]),
            CoreReceiveEvent::KitPrintWritten {
                accepted_total: 829
            }
        );
        let finish = session.finish_kit_print().unwrap();
        assert_eq!(
            parse_frame(finish.frame_bytes()).unwrap().payload(),
            [1, 5, 0, 0, 0, 0, 0, 0]
        );
        assert_eq!(
            accept_operation(&mut session, id, 4, 5, &[3, 5, 0x3d, 0x03, 0, 0]),
            CoreReceiveEvent::KitPrintFinished { total_len: 829 }
        );
        assert_eq!(session.state(), CoreState::Ready);
    }

    #[test]
    fn print_artifact_and_phase_mismatch_are_absorbing() {
        let (mut session, id) = ready_setup([0x44; 12]);
        let _begin = session.begin_a1_print().unwrap();
        assert_eq!(
            accept_operation(&mut session, id, 2, 3, &[]),
            CoreReceiveEvent::A1PrintBegan
        );
        assert_eq!(
            session.write_kit_print(&[0x4b; KIT_PRINT_BYTES]).err(),
            Some(CoreError::InvalidTransition)
        );
        assert_eq!(session.state(), CoreState::Terminated);
        assert_eq!(
            session.begin_a1_scanback().err(),
            Some(CoreError::CoreTerminated)
        );
    }

    #[test]
    fn setup_capability_helpers_are_mode_locked_and_typed() {
        let (mut setup, _) = ready_setup([0x45; 12]);
        assert_eq!(
            setup.setup_read_key(KeypadKey::SixRight).unwrap(),
            KeypadKey::SixRight
        );
        setup.setup_show(CoreScreen::ProvisionB).unwrap();
        assert_eq!(setup.current_screen(), Some(CoreScreen::ProvisionB));
        let binding = CardBPublicBindingV2::new(
            crate::capability::CardInstanceV2::Required,
            [0x11; 32],
            [0x22; 111],
        );
        assert_eq!(setup.setup_provision_b(binding), Ok(()));
        assert_eq!(setup.setup_verify_b(binding), Ok(()));

        let (mut wrong_mode, _) =
            fuzz_start_session([0x46; 12], 0, CoreMode::A1B, grants()).unwrap();
        assert_eq!(
            wrong_mode.setup_show(CoreScreen::SetupStart),
            Err(CoreError::InvalidTransition)
        );
        assert_eq!(wrong_mode.state(), CoreState::Terminated);

        let (mut failed, _) = ready_setup([0x47; 12]);
        failed.setup_fail();
        assert_eq!(failed.state(), CoreState::Terminated);
        assert_eq!(
            failed.terminal_reason(),
            Some(Interruption::OperationFailed)
        );

        let (mut interrupted, _) = ready_setup([0x48; 12]);
        interrupted.terminate_setup(Interruption::SessionTimeout);
        assert_eq!(interrupted.state(), CoreState::Terminated);
        assert_eq!(
            interrupted.terminal_reason(),
            Some(Interruption::SessionTimeout)
        );
    }

    #[test]
    fn normal_response_and_retained_session_identity_wipe_on_interruption() {
        let (mut session, open) =
            fuzz_start_session([0x49; 12], 0, CoreMode::A1B, grants()).unwrap();
        let id = session_id(&open);
        let ready = response(id, 1, MessageKind::SessionReady, &[]);
        assert_eq!(
            session.receive(&ready, false).unwrap().event(),
            CoreReceiveEvent::SessionReady
        );
        let request = session.begin_normal_egress(&[0xa5; 9]).unwrap();
        drop(request);
        let reply = response(id, 2, MessageKind::OperationResponse, &[0x5a; 37]);
        let outcome = session.receive_normal_egress(&reply, false).unwrap();
        assert_eq!(outcome.consumed, reply.len());
        assert!(outcome.response_ready);

        reset_wiped_bytes();
        session.terminate_normal(Interruption::SessionTimeout);
        assert_eq!(wiped_bytes(), 37 + 16);
        assert_eq!(session.state(), CoreState::Terminated);
        assert_eq!(
            session.terminal_reason(),
            Some(Interruption::SessionTimeout)
        );
    }
}
