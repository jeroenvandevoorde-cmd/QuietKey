//! Pure one-outstanding-exchange endpoint protocols.

use crate::wipe;
use crate::{encode_frame, Direction, IpcError, MessageKind, ReceivedFrame};

/// Immutable outbound header facts produced only by a valid transition.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct OutboundFrame {
    direction: Direction,
    kind: MessageKind,
    session_id: [u8; 16],
    exchange_id: u32,
}

impl OutboundFrame {
    /// Canonical direction.
    pub const fn direction(&self) -> Direction {
        self.direction
    }

    /// Canonical role-bound kind.
    pub const fn kind(&self) -> MessageKind {
        self.kind
    }

    /// Exact session identity.
    pub const fn session_id(&self) -> &[u8; 16] {
        &self.session_id
    }

    /// Exact exchange identity.
    pub const fn exchange_id(&self) -> u32 {
        self.exchange_id
    }

    /// Encode this transition with the caller-supplied opaque payload.
    pub fn encode(&self, payload: &[u8], output: &mut [u8]) -> Result<usize, IpcError> {
        encode_frame(
            self.direction,
            self.kind,
            self.session_id,
            self.exchange_id,
            payload,
            output,
        )
    }
}

/// Accepted event at the core endpoint.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CoreEvent {
    SessionReady,
    OperationResponse,
    SessionClosed,
}

/// Accepted event at the I/O endpoint.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum IoEvent {
    SessionOpen,
    OperationRequest,
    SessionClose,
}

#[derive(Clone, Copy, Eq, PartialEq)]
enum CoreState {
    New,
    Opening,
    Ready,
    Requesting,
    Closing,
    Closed,
    Terminated,
}

#[derive(Clone, Copy, Eq, PartialEq)]
enum ExpectedReply {
    SessionReady,
    OperationResponse,
    SessionClosed,
}

impl ExpectedReply {
    const fn kind(self) -> MessageKind {
        match self {
            Self::SessionReady => MessageKind::SessionReady,
            Self::OperationResponse => MessageKind::OperationResponse,
            Self::SessionClosed => MessageKind::SessionClosed,
        }
    }

    const fn event(self) -> CoreEvent {
        match self {
            Self::SessionReady => CoreEvent::SessionReady,
            Self::OperationResponse => CoreEvent::OperationResponse,
            Self::SessionClosed => CoreEvent::SessionClosed,
        }
    }
}

/// Core-side protocol owner.
///
/// The caller supplies the session identity; generating it is outside slice 1.
pub struct CoreProtocol {
    session_id: [u8; 16],
    state: CoreState,
    last_completed: u32,
    outstanding: Option<(u32, ExpectedReply)>,
}

impl CoreProtocol {
    /// Construct a new core endpoint with the caller-supplied 16 bytes.
    pub const fn new(session_id: [u8; 16]) -> Self {
        Self {
            session_id,
            state: CoreState::New,
            last_completed: 0,
            outstanding: None,
        }
    }

    /// Exercise the otherwise impractical exchange-exhaustion boundary.
    ///
    /// This seam exists only in ring-fenced fuzz builds, constructs its own
    /// endpoint, and cannot alter a caller-owned live session.
    #[cfg(feature = "fuzzing")]
    #[doc(hidden)]
    pub fn fuzz_exchange_exhaustion_probe(session_id: [u8; 16]) -> IpcError {
        let mut endpoint = Self::new(session_id);
        endpoint.state = CoreState::Ready;
        endpoint.last_completed = u32::MAX;
        match endpoint.request() {
            Err(error) => error,
            Ok(_) => endpoint.terminate(IpcError::InvalidTransition),
        }
    }

    /// Start the exact exchange-one opening handshake.
    pub fn begin(&mut self) -> Result<OutboundFrame, IpcError> {
        self.require_not_terminal()?;
        if self.outstanding.is_some() {
            return Err(IpcError::OutstandingExchange);
        }
        if self.state != CoreState::New {
            return Err(IpcError::InvalidTransition);
        }
        self.state = CoreState::Opening;
        self.outstanding = Some((1, ExpectedReply::SessionReady));
        Ok(self.outbound(Direction::CoreToIo, MessageKind::SessionOpen, 1))
    }

    /// Start the next exact operation exchange.
    pub fn request(&mut self) -> Result<OutboundFrame, IpcError> {
        self.require_not_terminal()?;
        if self.outstanding.is_some() {
            return Err(IpcError::OutstandingExchange);
        }
        if self.state != CoreState::Ready {
            return Err(IpcError::SessionNotReady);
        }
        let exchange_id = self.next_exchange()?;
        self.state = CoreState::Requesting;
        self.outstanding = Some((exchange_id, ExpectedReply::OperationResponse));
        Ok(self.outbound(
            Direction::CoreToIo,
            MessageKind::OperationRequest,
            exchange_id,
        ))
    }

    /// Start the final close exchange.
    pub fn close(&mut self) -> Result<OutboundFrame, IpcError> {
        self.require_not_terminal()?;
        if self.outstanding.is_some() {
            return Err(IpcError::OutstandingExchange);
        }
        if self.state != CoreState::Ready {
            return Err(IpcError::SessionNotReady);
        }
        let exchange_id = self.next_exchange()?;
        self.state = CoreState::Closing;
        self.outstanding = Some((exchange_id, ExpectedReply::SessionClosed));
        Ok(self.outbound(Direction::CoreToIo, MessageKind::SessionClose, exchange_id))
    }

    /// Accept exactly the outstanding I/O reply.
    ///
    /// Every inbound rejection latches terminal.
    pub fn accept(&mut self, frame: &ReceivedFrame) -> Result<CoreEvent, IpcError> {
        self.require_not_terminal()?;
        let header = frame.header();
        if header.direction() != Direction::IoToCore {
            return Err(self.terminate(IpcError::UnexpectedDirection));
        }
        if header.session_id() != &self.session_id {
            return Err(self.terminate(IpcError::SessionIdMismatch));
        }
        let (exchange_id, expected) = match self.outstanding {
            Some(pending) => pending,
            None => return Err(self.terminate(IpcError::NoOutstandingExchange)),
        };
        if header.kind() != expected.kind() {
            return Err(self.terminate(IpcError::UnexpectedMessageKind));
        }
        if header.exchange_id() != exchange_id {
            return Err(self.terminate(IpcError::ResponseIdMismatch));
        }

        self.outstanding = None;
        self.last_completed = exchange_id;
        self.state = match expected {
            ExpectedReply::SessionReady | ExpectedReply::OperationResponse => CoreState::Ready,
            ExpectedReply::SessionClosed => CoreState::Closed,
        };
        Ok(expected.event())
    }

    /// Convert connection loss to the closed terminating event.
    pub fn peer_lost(&mut self) -> IpcError {
        if self.state == CoreState::Terminated {
            IpcError::SessionTerminated
        } else if self.state == CoreState::Closed {
            IpcError::SessionClosed
        } else {
            self.terminate(IpcError::PeerLost)
        }
    }

    /// Latch a decoder or receive-boundary rejection into this session.
    ///
    /// The receive owner must call this transition whenever the paired stream
    /// decoder rejects, before any replacement decoder can be constructed.
    pub fn receive_failed(&mut self, error: IpcError) -> IpcError {
        match self.state {
            CoreState::Terminated => IpcError::SessionTerminated,
            CoreState::Closed => IpcError::SessionClosed,
            _ => self.terminate(error),
        }
    }

    /// Whether this endpoint completed SessionClosed.
    pub const fn is_closed(&self) -> bool {
        matches!(self.state, CoreState::Closed)
    }

    /// Whether a rejection or peer loss latched terminal.
    pub const fn is_terminated(&self) -> bool {
        matches!(self.state, CoreState::Terminated)
    }

    fn next_exchange(&mut self) -> Result<u32, IpcError> {
        match self.last_completed.checked_add(1) {
            Some(next) => Ok(next),
            None => Err(self.terminate(IpcError::ExchangeIdExhausted)),
        }
    }

    const fn outbound(
        &self,
        direction: Direction,
        kind: MessageKind,
        exchange_id: u32,
    ) -> OutboundFrame {
        OutboundFrame {
            direction,
            kind,
            session_id: self.session_id,
            exchange_id,
        }
    }

    fn require_not_terminal(&self) -> Result<(), IpcError> {
        match self.state {
            CoreState::Terminated => Err(IpcError::SessionTerminated),
            CoreState::Closed => Err(IpcError::SessionClosed),
            _ => Ok(()),
        }
    }

    fn terminate(&mut self, error: IpcError) -> IpcError {
        self.outstanding = None;
        self.state = CoreState::Terminated;
        error
    }
}

impl Drop for CoreProtocol {
    fn drop(&mut self) {
        wipe::bytes(&mut self.session_id);
    }
}

#[derive(Clone, Copy, Eq, PartialEq)]
enum IoState {
    AwaitOpen,
    Ready,
    ReplyPending,
    Closed,
    Terminated,
}

#[derive(Clone, Copy, Eq, PartialEq)]
enum PendingReply {
    SessionReady,
    OperationResponse,
    SessionClosed,
}

impl PendingReply {
    const fn kind(self) -> MessageKind {
        match self {
            Self::SessionReady => MessageKind::SessionReady,
            Self::OperationResponse => MessageKind::OperationResponse,
            Self::SessionClosed => MessageKind::SessionClosed,
        }
    }
}

/// I/O-side protocol owner that learns the session identity only from open.
pub struct IoProtocol {
    session_id: Option<[u8; 16]>,
    state: IoState,
    last_completed: u32,
    pending: Option<(u32, PendingReply)>,
}

impl IoProtocol {
    /// Construct an endpoint awaiting exchange-one SessionOpen.
    pub const fn new() -> Self {
        Self {
            session_id: None,
            state: IoState::AwaitOpen,
            last_completed: 0,
            pending: None,
        }
    }

    /// Accept the next exact core initiation.
    ///
    /// Every inbound rejection latches terminal.
    pub fn accept(&mut self, frame: &ReceivedFrame) -> Result<IoEvent, IpcError> {
        self.require_not_terminal()?;
        let header = frame.header();
        if header.direction() != Direction::CoreToIo {
            return Err(self.terminate(IpcError::UnexpectedDirection));
        }

        if self.state == IoState::AwaitOpen {
            if header.kind() != MessageKind::SessionOpen {
                return Err(self.terminate(IpcError::UnexpectedMessageKind));
            }
            if header.exchange_id() != 1 {
                return Err(self.terminate(IpcError::ExchangeIdSkipped));
            }
            self.session_id = Some(*header.session_id());
            self.pending = Some((1, PendingReply::SessionReady));
            self.state = IoState::ReplyPending;
            return Ok(IoEvent::SessionOpen);
        }

        let session_id = match self.session_id {
            Some(session_id) => session_id,
            None => return Err(self.terminate(IpcError::InvalidTransition)),
        };
        if header.session_id() != &session_id {
            return Err(self.terminate(IpcError::SessionIdMismatch));
        }
        if self.pending.is_some() || self.state == IoState::ReplyPending {
            return Err(self.terminate(IpcError::OutstandingExchange));
        }
        if self.state != IoState::Ready {
            return Err(self.terminate(IpcError::InvalidTransition));
        }

        let pending_reply = match header.kind() {
            MessageKind::OperationRequest => PendingReply::OperationResponse,
            MessageKind::SessionClose => PendingReply::SessionClosed,
            _ => return Err(self.terminate(IpcError::UnexpectedMessageKind)),
        };
        self.validate_initiating_exchange(header.exchange_id())?;
        self.pending = Some((header.exchange_id(), pending_reply));
        self.state = IoState::ReplyPending;
        Ok(match header.kind() {
            MessageKind::OperationRequest => IoEvent::OperationRequest,
            MessageKind::SessionClose => IoEvent::SessionClose,
            _ => return Err(self.terminate(IpcError::InvalidTransition)),
        })
    }

    /// Produce the exact reply for the sole outstanding exchange.
    pub fn reply(&mut self) -> Result<OutboundFrame, IpcError> {
        self.require_not_terminal()?;
        let (exchange_id, pending) = match self.pending.take() {
            Some(pending) => pending,
            None => return Err(IpcError::NoOutstandingExchange),
        };
        let session_id = match self.session_id {
            Some(session_id) => session_id,
            None => {
                self.pending = Some((exchange_id, pending));
                return Err(self.terminate(IpcError::InvalidTransition));
            }
        };
        self.last_completed = exchange_id;
        self.state = match pending {
            PendingReply::SessionReady | PendingReply::OperationResponse => IoState::Ready,
            PendingReply::SessionClosed => IoState::Closed,
        };
        Ok(OutboundFrame {
            direction: Direction::IoToCore,
            kind: pending.kind(),
            session_id,
            exchange_id,
        })
    }

    /// Convert connection loss to the closed terminating event.
    pub fn peer_lost(&mut self) -> IpcError {
        if self.state == IoState::Terminated {
            IpcError::SessionTerminated
        } else if self.state == IoState::Closed {
            IpcError::SessionClosed
        } else {
            self.terminate(IpcError::PeerLost)
        }
    }

    /// Latch a decoder or receive-boundary rejection into this session.
    ///
    /// The receive owner must call this transition whenever the paired stream
    /// decoder rejects, before any replacement decoder can be constructed.
    pub fn receive_failed(&mut self, error: IpcError) -> IpcError {
        match self.state {
            IoState::Terminated => IpcError::SessionTerminated,
            IoState::Closed => IpcError::SessionClosed,
            _ => self.terminate(error),
        }
    }

    /// Whether this endpoint produced SessionClosed.
    pub const fn is_closed(&self) -> bool {
        matches!(self.state, IoState::Closed)
    }

    /// Whether a rejection or peer loss latched terminal.
    pub const fn is_terminated(&self) -> bool {
        matches!(self.state, IoState::Terminated)
    }

    fn validate_initiating_exchange(&mut self, received: u32) -> Result<(), IpcError> {
        if received == self.last_completed {
            return Err(self.terminate(IpcError::ExchangeIdReuse));
        }
        if received < self.last_completed {
            return Err(self.terminate(IpcError::ExchangeIdRegression));
        }
        let expected = match self.last_completed.checked_add(1) {
            Some(expected) => expected,
            None => return Err(self.terminate(IpcError::ExchangeIdExhausted)),
        };
        if received > expected {
            return Err(self.terminate(IpcError::ExchangeIdSkipped));
        }
        Ok(())
    }

    fn require_not_terminal(&self) -> Result<(), IpcError> {
        match self.state {
            IoState::Terminated => Err(IpcError::SessionTerminated),
            IoState::Closed => Err(IpcError::SessionClosed),
            _ => Ok(()),
        }
    }

    fn terminate(&mut self, error: IpcError) -> IpcError {
        self.pending = None;
        self.state = IoState::Terminated;
        error
    }
}

impl Default for IoProtocol {
    fn default() -> Self {
        Self::new()
    }
}

impl Drop for IoProtocol {
    fn drop(&mut self) {
        if let Some(session_id) = self.session_id.as_mut() {
            wipe::bytes(session_id);
        }
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::{CoreProtocol, CoreState, IoProtocol, IoState};
    use crate::wipe::{reset_wiped_bytes, wiped_bytes};
    use crate::IpcError;

    #[test]
    fn exchange_exhaustion_terminates_without_wrapping() {
        let mut core = CoreProtocol::new([0x11; 16]);
        core.state = CoreState::Ready;
        core.last_completed = u32::MAX;
        assert_eq!(core.request(), Err(IpcError::ExchangeIdExhausted));
        assert!(core.is_terminated());

        let mut reused = IoProtocol::new();
        reused.state = IoState::Ready;
        reused.last_completed = u32::MAX;
        assert_eq!(
            reused.validate_initiating_exchange(u32::MAX),
            Err(IpcError::ExchangeIdReuse)
        );
        assert!(reused.is_terminated());

        let mut regressed = IoProtocol::new();
        regressed.state = IoState::Ready;
        regressed.last_completed = u32::MAX;
        assert_eq!(
            regressed.validate_initiating_exchange(u32::MAX - 1),
            Err(IpcError::ExchangeIdRegression)
        );
        assert!(regressed.is_terminated());
    }

    #[test]
    fn core_owner_drop_clears_the_complete_session_identity() {
        let core = CoreProtocol::new([0xa5; 16]);
        reset_wiped_bytes();
        drop(core);
        assert_eq!(wiped_bytes(), 16);
    }

    #[test]
    fn io_owner_without_an_open_session_has_no_session_bytes_to_clear() {
        let io = IoProtocol::new();
        reset_wiped_bytes();
        drop(io);
        assert_eq!(wiped_bytes(), 0);
    }
}
