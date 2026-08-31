#![no_main]

use libfuzzer_sys::fuzz_target;
use qk_ipc::{
    encode_frame, CoreEvent, CoreProtocol, Direction, IoEvent, IoProtocol, IpcError, MessageKind,
    OutboundFrame, ReceivedFrame, StreamDecoder, HEADER_BYTES,
};

const MAX_PRESENTED_BYTES: usize = 4_096;

fn error_name(error: IpcError) -> &'static str {
    match error {
        IpcError::DecoderTerminated => "DecoderTerminated",
        IpcError::SessionTerminated => "SessionTerminated",
        IpcError::AncillaryData => "AncillaryData",
        IpcError::HeaderTruncated => "HeaderTruncated",
        IpcError::MagicMismatch => "MagicMismatch",
        IpcError::VersionMismatch => "VersionMismatch",
        IpcError::DirectionOutOfRange => "DirectionOutOfRange",
        IpcError::KindOutOfRange => "KindOutOfRange",
        IpcError::DirectionKindMismatch => "DirectionKindMismatch",
        IpcError::ExchangeIdZero => "ExchangeIdZero",
        IpcError::PayloadLengthExceeded => "PayloadLengthExceeded",
        IpcError::PayloadTruncated => "PayloadTruncated",
        IpcError::TrailingByte => "TrailingByte",
        IpcError::ControlPayloadNotEmpty => "ControlPayloadNotEmpty",
        IpcError::OperationPayloadEmpty => "OperationPayloadEmpty",
        IpcError::OutputBufferTooSmall => "OutputBufferTooSmall",
        IpcError::PayloadAllocationFailed => "PayloadAllocationFailed",
        IpcError::UnexpectedDirection => "UnexpectedDirection",
        IpcError::SessionIdMismatch => "SessionIdMismatch",
        IpcError::UnexpectedMessageKind => "UnexpectedMessageKind",
        IpcError::ExchangeIdReuse => "ExchangeIdReuse",
        IpcError::ExchangeIdRegression => "ExchangeIdRegression",
        IpcError::ExchangeIdSkipped => "ExchangeIdSkipped",
        IpcError::ExchangeIdExhausted => "ExchangeIdExhausted",
        IpcError::ResponseIdMismatch => "ResponseIdMismatch",
        IpcError::OutstandingExchange => "OutstandingExchange",
        IpcError::NoOutstandingExchange => "NoOutstandingExchange",
        IpcError::SessionNotReady => "SessionNotReady",
        IpcError::SessionClosed => "SessionClosed",
        IpcError::InvalidTransition => "InvalidTransition",
        IpcError::PeerLost => "PeerLost",
        IpcError::ConnectionClosedMidFrame => "ConnectionClosedMidFrame",
    }
}

fn assert_named(error: IpcError) -> IpcError {
    assert_eq!(error.to_string(), error_name(error));
    error
}

fn payload_for(kind: MessageKind, byte: u8) -> Vec<u8> {
    if kind.requires_payload() {
        vec![byte]
    } else {
        Vec::new()
    }
}

fn receive(outbound: OutboundFrame, payload_byte: u8) -> ReceivedFrame {
    let payload = payload_for(outbound.kind(), payload_byte);
    let mut encoded = vec![0u8; HEADER_BYTES + payload.len()];
    let written = outbound
        .encode(&payload, &mut encoded)
        .expect("protocol outbound must encode");
    let mut decoder = StreamDecoder::new();
    let outcome = decoder
        .ingest(&encoded[..written], false)
        .expect("protocol outbound must decode");
    assert_eq!(outcome.consumed(), written);
    assert!(outcome.frame_ready());
    decoder.take_frame().expect("complete protocol frame")
}

fn injected(
    direction: Direction,
    kind: MessageKind,
    session_id: [u8; 16],
    exchange_id: u32,
    payload_byte: u8,
) -> Result<ReceivedFrame, IpcError> {
    let payload = payload_for(kind, payload_byte);
    let mut encoded = vec![0u8; HEADER_BYTES + payload.len()];
    let written = encode_frame(
        direction,
        kind,
        session_id,
        exchange_id,
        &payload,
        &mut encoded,
    )?;
    let mut decoder = StreamDecoder::new();
    let outcome = decoder.ingest(&encoded[..written], false)?;
    assert!(outcome.frame_ready());
    decoder.take_frame()
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct FrameFacts {
    direction: Direction,
    kind: MessageKind,
    session_id: [u8; 16],
    exchange_id: u32,
}

impl From<OutboundFrame> for FrameFacts {
    fn from(frame: OutboundFrame) -> Self {
        Self {
            direction: frame.direction(),
            kind: frame.kind(),
            session_id: *frame.session_id(),
            exchange_id: frame.exchange_id(),
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Outcome {
    Outbound(FrameFacts),
    CoreEvent(CoreEvent),
    IoEvent(IoEvent),
    Error(IpcError),
    ConstructionError(IpcError),
    MissingCoreOutbound,
    MissingIoOutbound,
    Status(u8),
}

fn actual_outbound(
    result: Result<OutboundFrame, IpcError>,
    slot: &mut Option<OutboundFrame>,
) -> Outcome {
    match result {
        Ok(frame) => {
            *slot = Some(frame);
            Outcome::Outbound(frame.into())
        }
        Err(error) => Outcome::Error(assert_named(error)),
    }
}

fn actual_core_event(result: Result<CoreEvent, IpcError>) -> Outcome {
    match result {
        Ok(event) => Outcome::CoreEvent(event),
        Err(error) => Outcome::Error(assert_named(error)),
    }
}

fn actual_io_event(result: Result<IoEvent, IpcError>) -> Outcome {
    match result {
        Ok(event) => Outcome::IoEvent(event),
        Err(error) => Outcome::Error(assert_named(error)),
    }
}

struct ActualMachine {
    core: CoreProtocol,
    io: IoProtocol,
    core_outbound: Option<OutboundFrame>,
    io_outbound: Option<OutboundFrame>,
    session_id: [u8; 16],
}

impl ActualMachine {
    fn new(session_id: [u8; 16]) -> Self {
        Self {
            core: CoreProtocol::new(session_id),
            io: IoProtocol::new(),
            core_outbound: None,
            io_outbound: None,
            session_id,
        }
    }

    fn step(&mut self, command: &[u8]) -> Outcome {
        let action = command[0] % 15;
        let selector = command.get(1).copied().unwrap_or(0);
        let value = command.get(2).copied().unwrap_or(0);
        let id_delta = command.get(3).copied().unwrap_or(0);
        match action {
            0 => actual_outbound(self.core.begin(), &mut self.core_outbound),
            1 => actual_outbound(self.core.request(), &mut self.core_outbound),
            2 => actual_outbound(self.core.close(), &mut self.core_outbound),
            3 => match self.core_outbound {
                Some(frame) => actual_io_event(self.io.accept(&receive(frame, value))),
                None => Outcome::MissingCoreOutbound,
            },
            4 => actual_outbound(self.io.reply(), &mut self.io_outbound),
            5 => match self.io_outbound {
                Some(frame) => actual_core_event(self.core.accept(&receive(frame, value))),
                None => Outcome::MissingIoOutbound,
            },
            6 => Outcome::Error(assert_named(self.core.peer_lost())),
            7 => Outcome::Error(assert_named(self.io.peer_lost())),
            8 => {
                let (direction, kind) = io_injection(selector);
                let session_id = selected_session(selector, value, self.session_id);
                match injected(direction, kind, session_id, u32::from(id_delta) + 1, value) {
                    Ok(frame) => actual_io_event(self.io.accept(&frame)),
                    Err(error) => Outcome::ConstructionError(assert_named(error)),
                }
            }
            9 => {
                let (direction, kind) = core_injection(selector);
                let session_id = selected_session(selector, value, self.session_id);
                match injected(direction, kind, session_id, u32::from(id_delta) + 1, value) {
                    Ok(frame) => actual_core_event(self.core.accept(&frame)),
                    Err(error) => Outcome::ConstructionError(assert_named(error)),
                }
            }
            10 => Outcome::Error(assert_named(
                self.core.receive_failed(receive_error(selector)),
            )),
            11 => Outcome::Error(assert_named(
                self.io.receive_failed(receive_error(selector)),
            )),
            12 => Outcome::Status(endpoint_status(
                self.core.is_closed(),
                self.core.is_terminated(),
            )),
            13 => Outcome::Status(endpoint_status(
                self.io.is_closed(),
                self.io.is_terminated(),
            )),
            _ => Outcome::Error(assert_named(CoreProtocol::fuzz_exchange_exhaustion_probe(
                self.session_id,
            ))),
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum ModelCoreState {
    New,
    Opening,
    Ready,
    Requesting,
    Closing,
    Closed,
    Terminated,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum ModelExpectedReply {
    SessionReady,
    OperationResponse,
    SessionClosed,
}

impl ModelExpectedReply {
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

struct ModelCore {
    session_id: [u8; 16],
    state: ModelCoreState,
    last_completed: u32,
    outstanding: Option<(u32, ModelExpectedReply)>,
}

impl ModelCore {
    const fn new(session_id: [u8; 16]) -> Self {
        Self {
            session_id,
            state: ModelCoreState::New,
            last_completed: 0,
            outstanding: None,
        }
    }

    fn begin(&mut self) -> Result<FrameFacts, IpcError> {
        self.require_not_terminal()?;
        if self.outstanding.is_some() {
            return Err(IpcError::OutstandingExchange);
        }
        if self.state != ModelCoreState::New {
            return Err(IpcError::InvalidTransition);
        }
        self.state = ModelCoreState::Opening;
        self.outstanding = Some((1, ModelExpectedReply::SessionReady));
        Ok(self.outbound(Direction::CoreToIo, MessageKind::SessionOpen, 1))
    }

    fn request(&mut self) -> Result<FrameFacts, IpcError> {
        self.require_not_terminal()?;
        if self.outstanding.is_some() {
            return Err(IpcError::OutstandingExchange);
        }
        if self.state != ModelCoreState::Ready {
            return Err(IpcError::SessionNotReady);
        }
        let exchange_id = self.next_exchange()?;
        self.state = ModelCoreState::Requesting;
        self.outstanding = Some((exchange_id, ModelExpectedReply::OperationResponse));
        Ok(self.outbound(
            Direction::CoreToIo,
            MessageKind::OperationRequest,
            exchange_id,
        ))
    }

    fn close(&mut self) -> Result<FrameFacts, IpcError> {
        self.require_not_terminal()?;
        if self.outstanding.is_some() {
            return Err(IpcError::OutstandingExchange);
        }
        if self.state != ModelCoreState::Ready {
            return Err(IpcError::SessionNotReady);
        }
        let exchange_id = self.next_exchange()?;
        self.state = ModelCoreState::Closing;
        self.outstanding = Some((exchange_id, ModelExpectedReply::SessionClosed));
        Ok(self.outbound(Direction::CoreToIo, MessageKind::SessionClose, exchange_id))
    }

    fn accept(&mut self, frame: FrameFacts) -> Result<CoreEvent, IpcError> {
        self.require_not_terminal()?;
        if frame.direction != Direction::IoToCore {
            return Err(self.terminate(IpcError::UnexpectedDirection));
        }
        if frame.session_id != self.session_id {
            return Err(self.terminate(IpcError::SessionIdMismatch));
        }
        let (exchange_id, expected) = match self.outstanding {
            Some(pending) => pending,
            None => return Err(self.terminate(IpcError::NoOutstandingExchange)),
        };
        if frame.kind != expected.kind() {
            return Err(self.terminate(IpcError::UnexpectedMessageKind));
        }
        if frame.exchange_id != exchange_id {
            return Err(self.terminate(IpcError::ResponseIdMismatch));
        }
        self.outstanding = None;
        self.last_completed = exchange_id;
        self.state = match expected {
            ModelExpectedReply::SessionReady | ModelExpectedReply::OperationResponse => {
                ModelCoreState::Ready
            }
            ModelExpectedReply::SessionClosed => ModelCoreState::Closed,
        };
        Ok(expected.event())
    }

    fn peer_lost(&mut self) -> IpcError {
        match self.state {
            ModelCoreState::Terminated => IpcError::SessionTerminated,
            ModelCoreState::Closed => IpcError::SessionClosed,
            _ => self.terminate(IpcError::PeerLost),
        }
    }

    fn receive_failed(&mut self, error: IpcError) -> IpcError {
        match self.state {
            ModelCoreState::Terminated => IpcError::SessionTerminated,
            ModelCoreState::Closed => IpcError::SessionClosed,
            _ => self.terminate(error),
        }
    }

    const fn status(&self) -> u8 {
        endpoint_status(
            matches!(self.state, ModelCoreState::Closed),
            matches!(self.state, ModelCoreState::Terminated),
        )
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
    ) -> FrameFacts {
        FrameFacts {
            direction,
            kind,
            session_id: self.session_id,
            exchange_id,
        }
    }

    fn require_not_terminal(&self) -> Result<(), IpcError> {
        match self.state {
            ModelCoreState::Terminated => Err(IpcError::SessionTerminated),
            ModelCoreState::Closed => Err(IpcError::SessionClosed),
            _ => Ok(()),
        }
    }

    fn terminate(&mut self, error: IpcError) -> IpcError {
        self.outstanding = None;
        self.state = ModelCoreState::Terminated;
        error
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum ModelIoState {
    AwaitOpen,
    Ready,
    ReplyPending,
    Closed,
    Terminated,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum ModelPendingReply {
    SessionReady,
    OperationResponse,
    SessionClosed,
}

impl ModelPendingReply {
    const fn kind(self) -> MessageKind {
        match self {
            Self::SessionReady => MessageKind::SessionReady,
            Self::OperationResponse => MessageKind::OperationResponse,
            Self::SessionClosed => MessageKind::SessionClosed,
        }
    }
}

struct ModelIo {
    session_id: Option<[u8; 16]>,
    state: ModelIoState,
    last_completed: u32,
    pending: Option<(u32, ModelPendingReply)>,
}

impl ModelIo {
    const fn new() -> Self {
        Self {
            session_id: None,
            state: ModelIoState::AwaitOpen,
            last_completed: 0,
            pending: None,
        }
    }

    fn accept(&mut self, frame: FrameFacts) -> Result<IoEvent, IpcError> {
        self.require_not_terminal()?;
        if frame.direction != Direction::CoreToIo {
            return Err(self.terminate(IpcError::UnexpectedDirection));
        }
        if self.state == ModelIoState::AwaitOpen {
            if frame.kind != MessageKind::SessionOpen {
                return Err(self.terminate(IpcError::UnexpectedMessageKind));
            }
            if frame.exchange_id != 1 {
                return Err(self.terminate(IpcError::ExchangeIdSkipped));
            }
            self.session_id = Some(frame.session_id);
            self.pending = Some((1, ModelPendingReply::SessionReady));
            self.state = ModelIoState::ReplyPending;
            return Ok(IoEvent::SessionOpen);
        }
        let session_id = match self.session_id {
            Some(session_id) => session_id,
            None => return Err(self.terminate(IpcError::InvalidTransition)),
        };
        if frame.session_id != session_id {
            return Err(self.terminate(IpcError::SessionIdMismatch));
        }
        if self.pending.is_some() || self.state == ModelIoState::ReplyPending {
            return Err(self.terminate(IpcError::OutstandingExchange));
        }
        if self.state != ModelIoState::Ready {
            return Err(self.terminate(IpcError::InvalidTransition));
        }
        let pending_reply = match frame.kind {
            MessageKind::OperationRequest => ModelPendingReply::OperationResponse,
            MessageKind::SessionClose => ModelPendingReply::SessionClosed,
            _ => return Err(self.terminate(IpcError::UnexpectedMessageKind)),
        };
        self.validate_initiating_exchange(frame.exchange_id)?;
        self.pending = Some((frame.exchange_id, pending_reply));
        self.state = ModelIoState::ReplyPending;
        Ok(match frame.kind {
            MessageKind::OperationRequest => IoEvent::OperationRequest,
            MessageKind::SessionClose => IoEvent::SessionClose,
            _ => return Err(self.terminate(IpcError::InvalidTransition)),
        })
    }

    fn reply(&mut self) -> Result<FrameFacts, IpcError> {
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
            ModelPendingReply::SessionReady | ModelPendingReply::OperationResponse => {
                ModelIoState::Ready
            }
            ModelPendingReply::SessionClosed => ModelIoState::Closed,
        };
        Ok(FrameFacts {
            direction: Direction::IoToCore,
            kind: pending.kind(),
            session_id,
            exchange_id,
        })
    }

    fn peer_lost(&mut self) -> IpcError {
        match self.state {
            ModelIoState::Terminated => IpcError::SessionTerminated,
            ModelIoState::Closed => IpcError::SessionClosed,
            _ => self.terminate(IpcError::PeerLost),
        }
    }

    fn receive_failed(&mut self, error: IpcError) -> IpcError {
        match self.state {
            ModelIoState::Terminated => IpcError::SessionTerminated,
            ModelIoState::Closed => IpcError::SessionClosed,
            _ => self.terminate(error),
        }
    }

    const fn status(&self) -> u8 {
        endpoint_status(
            matches!(self.state, ModelIoState::Closed),
            matches!(self.state, ModelIoState::Terminated),
        )
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
            ModelIoState::Terminated => Err(IpcError::SessionTerminated),
            ModelIoState::Closed => Err(IpcError::SessionClosed),
            _ => Ok(()),
        }
    }

    fn terminate(&mut self, error: IpcError) -> IpcError {
        self.pending = None;
        self.state = ModelIoState::Terminated;
        error
    }
}

struct ModelMachine {
    core: ModelCore,
    io: ModelIo,
    core_outbound: Option<FrameFacts>,
    io_outbound: Option<FrameFacts>,
    session_id: [u8; 16],
}

impl ModelMachine {
    const fn new(session_id: [u8; 16]) -> Self {
        Self {
            core: ModelCore::new(session_id),
            io: ModelIo::new(),
            core_outbound: None,
            io_outbound: None,
            session_id,
        }
    }

    fn step(&mut self, command: &[u8]) -> Outcome {
        let action = command[0] % 15;
        let selector = command.get(1).copied().unwrap_or(0);
        let value = command.get(2).copied().unwrap_or(0);
        let id_delta = command.get(3).copied().unwrap_or(0);
        match action {
            0 => model_outbound(self.core.begin(), &mut self.core_outbound),
            1 => model_outbound(self.core.request(), &mut self.core_outbound),
            2 => model_outbound(self.core.close(), &mut self.core_outbound),
            3 => match self.core_outbound {
                Some(frame) => model_io_event(self.io.accept(frame)),
                None => Outcome::MissingCoreOutbound,
            },
            4 => model_outbound(self.io.reply(), &mut self.io_outbound),
            5 => match self.io_outbound {
                Some(frame) => model_core_event(self.core.accept(frame)),
                None => Outcome::MissingIoOutbound,
            },
            6 => Outcome::Error(self.core.peer_lost()),
            7 => Outcome::Error(self.io.peer_lost()),
            8 => {
                let (direction, kind) = io_injection(selector);
                model_io_event(self.io.accept(FrameFacts {
                    direction,
                    kind,
                    session_id: selected_session(selector, value, self.session_id),
                    exchange_id: u32::from(id_delta) + 1,
                }))
            }
            9 => {
                let (direction, kind) = core_injection(selector);
                model_core_event(self.core.accept(FrameFacts {
                    direction,
                    kind,
                    session_id: selected_session(selector, value, self.session_id),
                    exchange_id: u32::from(id_delta) + 1,
                }))
            }
            10 => Outcome::Error(self.core.receive_failed(receive_error(selector))),
            11 => Outcome::Error(self.io.receive_failed(receive_error(selector))),
            12 => Outcome::Status(self.core.status()),
            13 => Outcome::Status(self.io.status()),
            _ => Outcome::Error(IpcError::ExchangeIdExhausted),
        }
    }
}

fn model_outbound(result: Result<FrameFacts, IpcError>, slot: &mut Option<FrameFacts>) -> Outcome {
    match result {
        Ok(frame) => {
            *slot = Some(frame);
            Outcome::Outbound(frame)
        }
        Err(error) => Outcome::Error(error),
    }
}

fn model_core_event(result: Result<CoreEvent, IpcError>) -> Outcome {
    match result {
        Ok(event) => Outcome::CoreEvent(event),
        Err(error) => Outcome::Error(error),
    }
}

fn model_io_event(result: Result<IoEvent, IpcError>) -> Outcome {
    match result {
        Ok(event) => Outcome::IoEvent(event),
        Err(error) => Outcome::Error(error),
    }
}

const fn core_kind(selector: u8) -> MessageKind {
    match selector % 3 {
        0 => MessageKind::SessionOpen,
        1 => MessageKind::OperationRequest,
        _ => MessageKind::SessionClose,
    }
}

const fn io_kind(selector: u8) -> MessageKind {
    match selector % 3 {
        0 => MessageKind::SessionReady,
        1 => MessageKind::OperationResponse,
        _ => MessageKind::SessionClosed,
    }
}

const fn io_injection(selector: u8) -> (Direction, MessageKind) {
    if selector & 0x40 == 0 {
        (Direction::CoreToIo, core_kind(selector))
    } else {
        (Direction::IoToCore, io_kind(selector))
    }
}

const fn core_injection(selector: u8) -> (Direction, MessageKind) {
    if selector & 0x40 == 0 {
        (Direction::IoToCore, io_kind(selector))
    } else {
        (Direction::CoreToIo, core_kind(selector))
    }
}

const fn selected_session(selector: u8, value: u8, expected_session: [u8; 16]) -> [u8; 16] {
    if selector & 0x80 == 0 {
        expected_session
    } else {
        [value; 16]
    }
}

const fn receive_error(selector: u8) -> IpcError {
    if selector & 1 == 0 {
        IpcError::MagicMismatch
    } else {
        IpcError::AncillaryData
    }
}

const fn endpoint_status(closed: bool, terminated: bool) -> u8 {
    (closed as u8) | ((terminated as u8) << 1)
}

fn assert_complete_happy_path(session_id: [u8; 16]) {
    const COMMANDS: [[u8; 4]; 12] = [
        [0, 0, 0, 0],
        [3, 0, 0, 0],
        [4, 0, 0, 0],
        [5, 0, 0, 0],
        [1, 0, 0, 0],
        [3, 0, 0x51, 0],
        [4, 0, 0, 0],
        [5, 0, 0x52, 0],
        [2, 0, 0, 0],
        [3, 0, 0, 0],
        [4, 0, 0, 0],
        [5, 0, 0, 0],
    ];
    let mut actual = ActualMachine::new(session_id);
    let mut model = ModelMachine::new(session_id);
    for (step, command) in COMMANDS.iter().enumerate() {
        assert_eq!(
            actual.step(command),
            model.step(command),
            "happy-path endpoint/model divergence at step {step}"
        );
    }
    assert!(actual.core.is_closed());
    assert!(actual.io.is_closed());
    assert_eq!(model.core.status(), 1);
    assert_eq!(model.io.status(), 1);
}

fuzz_target!(|data: &[u8]| {
    if data.len() > MAX_PRESENTED_BYTES {
        return;
    }
    let mut session_id = [0u8; 16];
    for (destination, source) in session_id.iter_mut().zip(data.iter().copied()) {
        *destination = source;
    }
    assert_complete_happy_path(session_id);
    let mut actual = ActualMachine::new(session_id);
    let mut repeated = ActualMachine::new(session_id);
    let mut model = ModelMachine::new(session_id);
    for (step, command) in data.chunks(4).take(1_024).enumerate() {
        let actual_outcome = actual.step(command);
        let repeated_outcome = repeated.step(command);
        let expected_outcome = model.step(command);
        assert_eq!(
            actual_outcome,
            repeated_outcome,
            "nondeterministic endpoint outcome at step {step} action {}",
            command[0] % 15
        );
        assert_eq!(
            actual_outcome,
            expected_outcome,
            "endpoint/model divergence at step {step} action {}",
            command[0] % 15
        );
    }
    assert_eq!(
        endpoint_status(actual.core.is_closed(), actual.core.is_terminated()),
        model.core.status()
    );
    assert_eq!(
        endpoint_status(actual.core.is_closed(), actual.core.is_terminated()),
        endpoint_status(repeated.core.is_closed(), repeated.core.is_terminated())
    );
    assert_eq!(
        endpoint_status(actual.io.is_closed(), actual.io.is_terminated()),
        model.io.status()
    );
    assert_eq!(
        endpoint_status(actual.io.is_closed(), actual.io.is_terminated()),
        endpoint_status(repeated.io.is_closed(), repeated.io.is_terminated())
    );
});
