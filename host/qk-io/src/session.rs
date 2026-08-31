//! QKIP-bound no-secret broker session.

use crate::egress::EgressTransfer;
use crate::ingress::IngressTransfer;
use crate::inner::parse_request;
use crate::mock::{MockInput, MockOutputWriter};
use crate::wipe::WipingVec;
use crate::{InnerError, Operation, Request, INNER_HEADER_BYTES, INNER_VERSION};
use core::fmt;
use qk_ipc::{IoEvent, IoProtocol, IpcError, OutboundFrame, ReceivedFrame};

/// Public, non-byte session state fact.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum BrokerState {
    Idle,
    IngressReady,
    EgressReceiving,
    ErrorReplyPending,
    Closed,
    Terminated,
}

/// Public reply category without transported bytes.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ReplyStatus {
    Control,
    Success(Operation),
    Rejected { opcode: u8, error: InnerError },
}

/// Local failures for which no valid inner reply exists.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum BrokerError {
    BrokerTerminated,
    CloseWithActiveTransfer,
    Inner(InnerError),
    Ipc(IpcError),
}

impl fmt::Display for BrokerError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::BrokerTerminated => formatter.write_str("BrokerTerminated"),
            Self::CloseWithActiveTransfer => formatter.write_str("CloseWithActiveTransfer"),
            Self::Inner(error) => error.fmt(formatter),
            Self::Ipc(error) => error.fmt(formatter),
        }
    }
}

impl std::error::Error for BrokerError {}

/// One already-formed QKIP reply in a wipe-owned frame.
pub struct BrokerReply {
    frame: WipingVec,
    status: ReplyStatus,
}

impl BrokerReply {
    /// Non-byte reply category.
    pub const fn status(&self) -> ReplyStatus {
        self.status
    }

    /// Exact already-formed QKIP frame bytes, valid while this owner lives.
    pub fn frame_bytes(&self) -> &[u8] {
        self.frame.as_slice()
    }

    /// Exact complete QKIP frame length.
    pub fn len(&self) -> usize {
        self.frame.len()
    }

    /// A valid reply is always one nonempty complete QKIP frame.
    pub fn is_empty(&self) -> bool {
        self.frame.len() == 0
    }
}

enum State {
    Idle,
    Ingress(IngressTransfer),
    Egress(EgressTransfer),
    ErrorReplyPending,
    Closed,
    Terminated,
}

/// One no-secret qk-io endpoint and transfer owner.
pub struct BrokerSession {
    ipc: IoProtocol,
    state: State,
}

impl BrokerSession {
    /// Construct one endpoint awaiting QKIP SessionOpen.
    pub const fn new() -> Self {
        Self {
            ipc: IoProtocol::new(),
            state: State::Idle,
        }
    }

    /// Current non-byte broker state.
    pub const fn state(&self) -> BrokerState {
        match self.state {
            State::Idle => BrokerState::Idle,
            State::Ingress(_) => BrokerState::IngressReady,
            State::Egress(_) => BrokerState::EgressReceiving,
            State::ErrorReplyPending => BrokerState::ErrorReplyPending,
            State::Closed => BrokerState::Closed,
            State::Terminated => BrokerState::Terminated,
        }
    }

    /// Accept one already-decoded QKIP frame and at most one injected boundary.
    pub fn accept(
        &mut self,
        frame: &ReceivedFrame,
        mut input: Option<&mut MockInput>,
        mut writer: Option<&mut MockOutputWriter>,
    ) -> Result<BrokerReply, BrokerError> {
        if matches!(
            self.state,
            State::ErrorReplyPending | State::Closed | State::Terminated
        ) {
            discard_boundaries(&mut input, &mut writer);
            return Err(BrokerError::BrokerTerminated);
        }
        let event = match self.ipc.accept(frame) {
            Ok(event) => event,
            Err(error) => {
                self.terminate();
                discard_boundaries(&mut input, &mut writer);
                return Err(BrokerError::Ipc(error));
            }
        };
        match event {
            IoEvent::SessionOpen => {
                if input.is_some() || writer.is_some() {
                    discard_boundaries(&mut input, &mut writer);
                    self.terminate();
                    return Err(BrokerError::Inner(InnerError::UnexpectedBoundary));
                }
                self.control_reply()
            }
            IoEvent::SessionClose => {
                if input.is_some() || writer.is_some() {
                    discard_boundaries(&mut input, &mut writer);
                    self.terminate();
                    return Err(BrokerError::Inner(InnerError::UnexpectedBoundary));
                }
                if !matches!(self.state, State::Idle) {
                    self.terminate();
                    return Err(BrokerError::CloseWithActiveTransfer);
                }
                let reply = self.control_reply()?;
                self.state = State::Closed;
                Ok(reply)
            }
            IoEvent::OperationRequest => {
                let raw_opcode = frame.payload().get(1).copied().unwrap_or(0);
                let parsed = parse_request(frame.payload());
                let request = match parsed {
                    Ok(request) => request,
                    Err(error) => {
                        discard_boundaries(&mut input, &mut writer);
                        return self.rejection_reply(raw_opcode, error);
                    }
                };
                let operation = request.operation();
                let result = self.dispatch(request, &mut input, &mut writer);
                match result {
                    Ok(body) => self.success_reply(operation, body),
                    Err(error) => {
                        discard_boundaries(&mut input, &mut writer);
                        self.rejection_reply(operation.wire_value(), error)
                    }
                }
            }
        }
    }

    /// Convert peer loss into terminal cleanup.
    pub fn peer_lost(&mut self) -> BrokerError {
        if matches!(
            self.state,
            State::ErrorReplyPending | State::Closed | State::Terminated
        ) {
            return BrokerError::BrokerTerminated;
        }
        let error = self.ipc.peer_lost();
        self.terminate();
        BrokerError::Ipc(error)
    }

    fn dispatch(
        &mut self,
        request: Request<'_>,
        input: &mut Option<&mut MockInput>,
        writer: &mut Option<&mut MockOutputWriter>,
    ) -> Result<WipingVec, InnerError> {
        match request {
            Request::IngressBegin { source, aux } => {
                if !matches!(self.state, State::Idle) {
                    return Err(InnerError::ActiveTransfer);
                }
                if writer.is_some() {
                    return Err(InnerError::UnexpectedBoundary);
                }
                let input = input.as_deref_mut().ok_or(InnerError::BoundaryMissing)?;
                let transfer = IngressTransfer::begin(source, aux, input)?;
                let mut body =
                    WipingVec::try_zeroed(5).map_err(|_| InnerError::AllocationFailed)?;
                body.as_mut_slice()[0] = transfer.source().wire_value();
                body.as_mut_slice()[1..5]
                    .copy_from_slice(&(transfer.total_len() as u32).to_le_bytes());
                self.state = State::Ingress(transfer);
                Ok(body)
            }
            Request::IngressRead { expected_offset } => {
                if input.is_some() || writer.is_some() {
                    return Err(InnerError::UnexpectedBoundary);
                }
                let State::Ingress(transfer) = &mut self.state else {
                    return Err(if matches!(self.state, State::Egress(_)) {
                        InnerError::WrongTransferDirection
                    } else {
                        InnerError::NoActiveTransfer
                    });
                };
                let (body, final_chunk) = transfer.read(expected_offset as usize)?;
                if final_chunk {
                    self.state = State::Idle;
                }
                Ok(body)
            }
            Request::EgressBegin {
                sink,
                artifact,
                total_len,
                aux,
            } => {
                if !matches!(self.state, State::Idle) {
                    return Err(InnerError::ActiveTransfer);
                }
                if input.is_some() || writer.is_some() {
                    return Err(InnerError::UnexpectedBoundary);
                }
                self.state = State::Egress(EgressTransfer::begin(
                    sink,
                    artifact,
                    total_len as usize,
                    aux,
                )?);
                WipingVec::try_zeroed(0).map_err(|_| InnerError::AllocationFailed)
            }
            Request::EgressWrite { offset, chunk } => {
                if input.is_some() || writer.is_some() {
                    return Err(InnerError::UnexpectedBoundary);
                }
                let State::Egress(transfer) = &mut self.state else {
                    return Err(if matches!(self.state, State::Ingress(_)) {
                        InnerError::WrongTransferDirection
                    } else {
                        InnerError::NoActiveTransfer
                    });
                };
                let accepted = transfer.write(offset as usize, chunk)?;
                let mut body =
                    WipingVec::try_zeroed(4).map_err(|_| InnerError::AllocationFailed)?;
                body.as_mut_slice()
                    .copy_from_slice(&(accepted as u32).to_le_bytes());
                Ok(body)
            }
            Request::EgressFinish => {
                if input.is_some() {
                    return Err(InnerError::UnexpectedBoundary);
                }
                let state = core::mem::replace(&mut self.state, State::Idle);
                let State::Egress(transfer) = state else {
                    self.state = state;
                    return Err(if matches!(self.state, State::Ingress(_)) {
                        InnerError::WrongTransferDirection
                    } else {
                        InnerError::NoActiveTransfer
                    });
                };
                transfer.finish(writer.as_deref_mut())
            }
        }
    }

    fn control_reply(&mut self) -> Result<BrokerReply, BrokerError> {
        let outbound = match self.ipc.reply() {
            Ok(value) => value,
            Err(error) => {
                self.terminate();
                return Err(BrokerError::Ipc(error));
            }
        };
        match encode_reply(outbound, &[], ReplyStatus::Control) {
            Ok(reply) => Ok(reply),
            Err(error) => {
                self.terminate();
                Err(error)
            }
        }
    }

    fn success_reply(
        &mut self,
        operation: Operation,
        body: WipingVec,
    ) -> Result<BrokerReply, BrokerError> {
        let payload = match wrap_response(operation.wire_value(), 0, body.as_slice()) {
            Ok(value) => value,
            Err(error) => {
                self.terminate();
                return Err(BrokerError::Inner(error));
            }
        };
        let outbound = match self.ipc.reply() {
            Ok(value) => value,
            Err(error) => {
                self.terminate();
                return Err(BrokerError::Ipc(error));
            }
        };
        match encode_reply(
            outbound,
            payload.as_slice(),
            ReplyStatus::Success(operation),
        ) {
            Ok(reply) => Ok(reply),
            Err(error) => {
                self.terminate();
                Err(error)
            }
        }
    }

    fn rejection_reply(
        &mut self,
        opcode: u8,
        error: InnerError,
    ) -> Result<BrokerReply, BrokerError> {
        let payload = match wrap_response(opcode, error.status_code(), &[]) {
            Ok(value) => value,
            Err(inner_error) => {
                self.terminate();
                return Err(BrokerError::Inner(inner_error));
            }
        };
        let outbound = match self.ipc.reply() {
            Ok(value) => value,
            Err(ipc_error) => {
                self.terminate();
                return Err(BrokerError::Ipc(ipc_error));
            }
        };
        self.state = State::ErrorReplyPending;
        match encode_reply(
            outbound,
            payload.as_slice(),
            ReplyStatus::Rejected { opcode, error },
        ) {
            Ok(reply) => Ok(reply),
            Err(reply_error) => {
                self.terminate();
                Err(reply_error)
            }
        }
    }

    fn terminate(&mut self) {
        self.state = State::Terminated;
    }
}

impl Default for BrokerSession {
    fn default() -> Self {
        Self::new()
    }
}

impl Drop for BrokerSession {
    fn drop(&mut self) {
        self.state = State::Terminated;
    }
}

fn wrap_response(opcode: u8, status: u16, body: &[u8]) -> Result<WipingVec, InnerError> {
    let length = INNER_HEADER_BYTES
        .checked_add(body.len())
        .filter(|length| *length <= qk_ipc::MAX_PAYLOAD_BYTES)
        .ok_or(InnerError::BodyLengthExceeded)?;
    let mut payload = WipingVec::try_zeroed(length).map_err(|_| InnerError::AllocationFailed)?;
    payload.as_mut_slice()[0] = INNER_VERSION;
    payload.as_mut_slice()[1] = opcode;
    payload.as_mut_slice()[2..4].copy_from_slice(&status.to_le_bytes());
    payload.as_mut_slice()[4..8].copy_from_slice(&(body.len() as u32).to_le_bytes());
    payload.as_mut_slice()[8..].copy_from_slice(body);
    Ok(payload)
}

fn encode_reply(
    outbound: OutboundFrame,
    payload: &[u8],
    status: ReplyStatus,
) -> Result<BrokerReply, BrokerError> {
    let frame_len = qk_ipc::HEADER_BYTES
        .checked_add(payload.len())
        .filter(|length| *length <= qk_ipc::MAX_FRAME_BYTES)
        .ok_or(BrokerError::Inner(InnerError::BodyLengthExceeded))?;
    let mut frame = WipingVec::try_zeroed(frame_len)
        .map_err(|_| BrokerError::Inner(InnerError::AllocationFailed))?;
    let written = outbound
        .encode(payload, frame.as_mut_slice())
        .map_err(BrokerError::Ipc)?;
    debug_assert_eq!(written, frame_len);
    Ok(BrokerReply { frame, status })
}

fn discard_boundaries(
    input: &mut Option<&mut MockInput>,
    writer: &mut Option<&mut MockOutputWriter>,
) {
    if let Some(input) = input.as_deref_mut() {
        let _ = input.discard();
    }
    if let Some(writer) = writer.as_deref_mut() {
        let _ = writer.discard();
    }
}
