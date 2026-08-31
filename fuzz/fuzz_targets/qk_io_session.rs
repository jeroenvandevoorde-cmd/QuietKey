#![no_main]

use libfuzzer_sys::fuzz_target;
use qk_io::{
    reset_wiped_bytes, wiped_bytes, Artifact, BrokerError, BrokerReply, BrokerSession, BrokerState,
    InnerError, MockInput, MockOutputWriter, Operation, OutputFault, ReplyStatus, Sink, Source,
    A1_CANDIDATE_BYTES, INNER_HEADER_BYTES, INNER_VERSION, KIT_CANDIDATE_BYTES, MAX_FILENAME_BYTES,
    MAX_INNER_BODY_BYTES,
};
use qk_ipc::{IpcError, MessageKind, ReceivedFrame, StreamDecoder, HEADER_BYTES};

const MAX_PRESENTED_BYTES: usize = 4_096;
const COMMAND_BYTES: usize = 16;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum InputMode {
    Missing,
    Valid,
    WrongKind,
    Failing,
    WrongLength,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum WriterMode {
    Missing,
    Valid,
    WrongKind,
    Fault(OutputFault),
}

#[derive(Clone, Debug, Eq, PartialEq)]
enum Action {
    IngressBegin {
        source: Source,
        input: InputMode,
        pattern: u8,
    },
    IngressRead {
        offset: u32,
        boundaries: u8,
    },
    EgressBegin {
        artifact: Artifact,
        total_len: u32,
        boundaries: u8,
    },
    EgressWrite {
        offset: u32,
        chunk: Vec<u8>,
        boundaries: u8,
    },
    EgressFinish {
        writer: WriterMode,
        unexpected_input: bool,
    },
    Malformed {
        case: u8,
        pattern: u8,
        with_input: bool,
    },
    Close {
        boundaries: u8,
    },
    PeerLost,
    ReceiveFailed(IpcError),
    TerminalProbe,
}

#[derive(Clone, Debug, Eq, PartialEq)]
enum ModelState {
    Idle,
    Ingress {
        data: Vec<u8>,
        next_offset: usize,
    },
    Egress {
        artifact: Artifact,
        total_len: usize,
        next_offset: usize,
        data: Vec<u8>,
    },
    ErrorReplyPending,
    Closed,
    Terminated,
}

impl ModelState {
    const fn public(&self) -> BrokerState {
        match self {
            Self::Idle => BrokerState::Idle,
            Self::Ingress { .. } => BrokerState::IngressReady,
            Self::Egress { .. } => BrokerState::EgressReceiving,
            Self::ErrorReplyPending => BrokerState::ErrorReplyPending,
            Self::Closed => BrokerState::Closed,
            Self::Terminated => BrokerState::Terminated,
        }
    }

    const fn absorbs_frames(&self) -> bool {
        matches!(
            self,
            Self::ErrorReplyPending | Self::Closed | Self::Terminated
        )
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
enum Outcome {
    Reply { status: ReplyStatus, frame: Vec<u8> },
    Error(BrokerError),
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct ExpectedStep {
    outcome: Outcome,
    final_output: Option<Vec<u8>>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct BoundaryFacts {
    input_used: Option<bool>,
    writer_used: Option<bool>,
    temporary: Option<Vec<u8>>,
    final_output: Option<Vec<u8>>,
    final_name: Option<Vec<u8>>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct StepFact {
    outcome: Outcome,
    state: BrokerState,
    boundaries: BoundaryFacts,
    wiped: usize,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct RunTrace {
    initial_wiped: usize,
    steps: Vec<StepFact>,
    final_state: BrokerState,
    final_wiped: usize,
}

struct Model {
    state: ModelState,
    session_id: [u8; 16],
}

impl Model {
    const fn new(session_id: [u8; 16]) -> Self {
        Self {
            state: ModelState::Idle,
            session_id,
        }
    }

    fn step(&mut self, action: &Action, exchange_id: u32) -> ExpectedStep {
        if self.state.absorbs_frames()
            && !matches!(action, Action::PeerLost | Action::ReceiveFailed(_))
        {
            return ExpectedStep {
                outcome: Outcome::Error(BrokerError::BrokerTerminated),
                final_output: None,
            };
        }
        match action {
            Action::IngressBegin {
                source,
                input,
                pattern,
            } => self.ingress_begin(*source, *input, *pattern, exchange_id),
            Action::IngressRead { offset, boundaries } => {
                self.ingress_read(*offset, *boundaries, exchange_id)
            }
            Action::EgressBegin {
                artifact,
                total_len,
                boundaries,
            } => self.egress_begin(*artifact, *total_len, *boundaries, exchange_id),
            Action::EgressWrite {
                offset,
                chunk,
                boundaries,
            } => self.egress_write(*offset, chunk, *boundaries, exchange_id),
            Action::EgressFinish {
                writer,
                unexpected_input,
            } => self.egress_finish(*writer, *unexpected_input, exchange_id),
            Action::Malformed { case, pattern, .. } => {
                let (opcode, error) = malformed_error(*case, *pattern);
                self.reject(opcode, error, exchange_id)
            }
            Action::Close { boundaries } => self.close(*boundaries, exchange_id),
            Action::PeerLost => self.peer_lost(),
            Action::ReceiveFailed(error) => self.receive_failed(*error),
            Action::TerminalProbe => self.ingress_read(0, 0, exchange_id),
        }
    }

    fn ingress_begin(
        &mut self,
        source: Source,
        input: InputMode,
        pattern: u8,
        exchange_id: u32,
    ) -> ExpectedStep {
        if !matches!(self.state, ModelState::Idle) {
            return self.reject(
                Operation::IngressBegin.wire_value(),
                InnerError::ActiveTransfer,
                exchange_id,
            );
        }
        let error = match input {
            InputMode::Missing => Some(InnerError::BoundaryMissing),
            InputMode::WrongKind => Some(InnerError::SourceKindMismatch),
            InputMode::Failing => Some(InnerError::SourceReadFailed),
            InputMode::WrongLength => Some(InnerError::SourceLengthMismatch),
            InputMode::Valid => None,
        };
        if let Some(error) = error {
            return self.reject(Operation::IngressBegin.wire_value(), error, exchange_id);
        }
        let data = candidate(source, pattern, false);
        let mut body = Vec::with_capacity(5);
        body.push(source.wire_value());
        body.extend_from_slice(&(data.len() as u32).to_le_bytes());
        self.state = ModelState::Ingress {
            data,
            next_offset: 0,
        };
        self.success(Operation::IngressBegin, &body, exchange_id, None)
    }

    fn ingress_read(&mut self, offset: u32, boundaries: u8, exchange_id: u32) -> ExpectedStep {
        if boundaries & 3 != 0 {
            return self.reject(
                Operation::IngressRead.wire_value(),
                InnerError::UnexpectedBoundary,
                exchange_id,
            );
        }
        let (data, next_offset) = match &self.state {
            ModelState::Ingress { data, next_offset } => (data.clone(), *next_offset),
            ModelState::Egress { .. } => {
                return self.reject(
                    Operation::IngressRead.wire_value(),
                    InnerError::WrongTransferDirection,
                    exchange_id,
                );
            }
            _ => {
                return self.reject(
                    Operation::IngressRead.wire_value(),
                    InnerError::NoActiveTransfer,
                    exchange_id,
                );
            }
        };
        if offset as usize != next_offset {
            return self.reject(
                Operation::IngressRead.wire_value(),
                InnerError::OffsetMismatch,
                exchange_id,
            );
        }
        let chunk_len = data.len() - next_offset;
        let mut body = Vec::with_capacity(9 + chunk_len);
        body.extend_from_slice(&offset.to_le_bytes());
        body.extend_from_slice(&(chunk_len as u32).to_le_bytes());
        body.push(1);
        body.extend_from_slice(&data[next_offset..]);
        self.state = ModelState::Idle;
        self.success(Operation::IngressRead, &body, exchange_id, None)
    }

    fn egress_begin(
        &mut self,
        artifact: Artifact,
        total_len: u32,
        boundaries: u8,
        exchange_id: u32,
    ) -> ExpectedStep {
        if !matches!(self.state, ModelState::Idle) {
            return self.reject(
                Operation::EgressBegin.wire_value(),
                InnerError::ActiveTransfer,
                exchange_id,
            );
        }
        if boundaries & 3 != 0 {
            return self.reject(
                Operation::EgressBegin.wire_value(),
                InnerError::UnexpectedBoundary,
                exchange_id,
            );
        }
        if !matches!(
            artifact,
            Artifact::A1PrintArtifact | Artifact::KitPrintArtifact
        ) {
            return self.reject(
                Operation::EgressBegin.wire_value(),
                InnerError::SinkArtifactMismatch,
                exchange_id,
            );
        }
        if total_len == 0 {
            return self.reject(
                Operation::EgressBegin.wire_value(),
                InnerError::DeclaredLengthZero,
                exchange_id,
            );
        }
        self.state = ModelState::Egress {
            artifact,
            total_len: total_len as usize,
            next_offset: 0,
            data: vec![0; total_len as usize],
        };
        self.success(Operation::EgressBegin, &[], exchange_id, None)
    }

    fn egress_write(
        &mut self,
        offset: u32,
        chunk: &[u8],
        boundaries: u8,
        exchange_id: u32,
    ) -> ExpectedStep {
        if boundaries & 3 != 0 {
            return self.reject(
                Operation::EgressWrite.wire_value(),
                InnerError::UnexpectedBoundary,
                exchange_id,
            );
        }
        let (total_len, next_offset) = match &self.state {
            ModelState::Egress {
                total_len,
                next_offset,
                ..
            } => (*total_len, *next_offset),
            ModelState::Ingress { .. } => {
                return self.reject(
                    Operation::EgressWrite.wire_value(),
                    InnerError::WrongTransferDirection,
                    exchange_id,
                );
            }
            _ => {
                return self.reject(
                    Operation::EgressWrite.wire_value(),
                    InnerError::NoActiveTransfer,
                    exchange_id,
                );
            }
        };
        if chunk.is_empty() {
            return self.reject(
                Operation::EgressWrite.wire_value(),
                InnerError::ChunkLengthZero,
                exchange_id,
            );
        }
        if offset as usize != next_offset {
            return self.reject(
                Operation::EgressWrite.wire_value(),
                InnerError::OffsetMismatch,
                exchange_id,
            );
        }
        let Some(end) = next_offset.checked_add(chunk.len()) else {
            return self.reject(
                Operation::EgressWrite.wire_value(),
                InnerError::TransferLengthExceeded,
                exchange_id,
            );
        };
        if end > total_len {
            return self.reject(
                Operation::EgressWrite.wire_value(),
                InnerError::TransferLengthExceeded,
                exchange_id,
            );
        }
        let ModelState::Egress {
            data, next_offset, ..
        } = &mut self.state
        else {
            unreachable!("the model state was matched above");
        };
        data[offset as usize..end].copy_from_slice(chunk);
        *next_offset = end;
        self.success(
            Operation::EgressWrite,
            &(end as u32).to_le_bytes(),
            exchange_id,
            None,
        )
    }

    fn egress_finish(
        &mut self,
        writer: WriterMode,
        unexpected_input: bool,
        exchange_id: u32,
    ) -> ExpectedStep {
        if unexpected_input {
            return self.reject(
                Operation::EgressFinish.wire_value(),
                InnerError::UnexpectedBoundary,
                exchange_id,
            );
        }
        let (artifact, total_len, next_offset, data) = match &self.state {
            ModelState::Egress {
                artifact,
                total_len,
                next_offset,
                data,
            } => (*artifact, *total_len, *next_offset, data.clone()),
            ModelState::Ingress { .. } => {
                return self.reject(
                    Operation::EgressFinish.wire_value(),
                    InnerError::WrongTransferDirection,
                    exchange_id,
                );
            }
            _ => {
                return self.reject(
                    Operation::EgressFinish.wire_value(),
                    InnerError::NoActiveTransfer,
                    exchange_id,
                );
            }
        };
        if next_offset != total_len {
            return self.reject(
                Operation::EgressFinish.wire_value(),
                InnerError::TransferIncomplete,
                exchange_id,
            );
        }
        let writer_error = match writer {
            WriterMode::Missing => Some(InnerError::BoundaryMissing),
            WriterMode::WrongKind => Some(InnerError::WriterKindMismatch),
            WriterMode::Fault(OutputFault::None) | WriterMode::Valid => None,
            WriterMode::Fault(_) => Some(InnerError::PrintFailed),
        };
        if let Some(error) = writer_error {
            return self.reject(Operation::EgressFinish.wire_value(), error, exchange_id);
        }
        let mut body = Vec::with_capacity(6);
        body.push(Sink::Print.wire_value());
        body.push(artifact.wire_value());
        body.extend_from_slice(&(total_len as u32).to_le_bytes());
        self.state = ModelState::Idle;
        self.success(Operation::EgressFinish, &body, exchange_id, Some(data))
    }

    fn close(&mut self, boundaries: u8, exchange_id: u32) -> ExpectedStep {
        if boundaries & 3 != 0 {
            self.state = ModelState::Terminated;
            return ExpectedStep {
                outcome: Outcome::Error(BrokerError::Inner(InnerError::UnexpectedBoundary)),
                final_output: None,
            };
        }
        if matches!(self.state, ModelState::Idle) {
            self.state = ModelState::Closed;
            ExpectedStep {
                outcome: Outcome::Reply {
                    status: ReplyStatus::Control,
                    frame: qkip_frame(0x02, 0x0103, self.session_id, exchange_id, &[]),
                },
                final_output: None,
            }
        } else {
            self.state = ModelState::Terminated;
            ExpectedStep {
                outcome: Outcome::Error(BrokerError::CloseWithActiveTransfer),
                final_output: None,
            }
        }
    }

    fn peer_lost(&mut self) -> ExpectedStep {
        let error = if self.state.absorbs_frames() {
            BrokerError::BrokerTerminated
        } else {
            self.state = ModelState::Terminated;
            BrokerError::Ipc(IpcError::PeerLost)
        };
        ExpectedStep {
            outcome: Outcome::Error(error),
            final_output: None,
        }
    }

    fn receive_failed(&mut self, receive_error: IpcError) -> ExpectedStep {
        let error = if self.state.absorbs_frames() {
            BrokerError::BrokerTerminated
        } else {
            self.state = ModelState::Terminated;
            BrokerError::Ipc(receive_error)
        };
        ExpectedStep {
            outcome: Outcome::Error(error),
            final_output: None,
        }
    }

    fn success(
        &self,
        operation: Operation,
        body: &[u8],
        exchange_id: u32,
        final_output: Option<Vec<u8>>,
    ) -> ExpectedStep {
        let payload = inner_response(operation.wire_value(), 0, body);
        ExpectedStep {
            outcome: Outcome::Reply {
                status: ReplyStatus::Success(operation),
                frame: qkip_frame(0x02, 0x0102, self.session_id, exchange_id, &payload),
            },
            final_output,
        }
    }

    fn reject(&mut self, opcode: u8, error: InnerError, exchange_id: u32) -> ExpectedStep {
        self.state = ModelState::ErrorReplyPending;
        let payload = inner_response(opcode, error.status_code(), &[]);
        ExpectedStep {
            outcome: Outcome::Reply {
                status: ReplyStatus::Rejected { opcode, error },
                frame: qkip_frame(0x02, 0x0102, self.session_id, exchange_id, &payload),
            },
            final_output: None,
        }
    }
}

fn candidate(source: Source, pattern: u8, wrong_length: bool) -> Vec<u8> {
    let exact = match source {
        Source::CameraA1Candidate => A1_CANDIDATE_BYTES,
        Source::CameraKitCandidate => KIT_CANDIDATE_BYTES,
        Source::CameraBbqrPsbt | Source::MediaPsbt => {
            unreachable!("the session target constructs only fixed candidates")
        }
    };
    vec![pattern; exact - usize::from(wrong_length)]
}

fn wrong_source(source: Source) -> Source {
    match source {
        Source::CameraA1Candidate => Source::CameraKitCandidate,
        Source::CameraKitCandidate => Source::CameraA1Candidate,
        Source::CameraBbqrPsbt | Source::MediaPsbt => Source::CameraA1Candidate,
    }
}

fn make_input(action: &Action) -> Option<MockInput> {
    match action {
        Action::IngressBegin {
            source,
            input,
            pattern,
        } => match input {
            InputMode::Missing => None,
            InputMode::Valid => Some(
                MockInput::try_new(*source, &candidate(*source, *pattern, false))
                    .expect("bounded candidate"),
            ),
            InputMode::WrongKind => {
                let wrong = wrong_source(*source);
                Some(
                    MockInput::try_new(wrong, &candidate(wrong, *pattern, false))
                        .expect("bounded wrong-kind candidate"),
                )
            }
            InputMode::Failing => Some(MockInput::failing(*source)),
            InputMode::WrongLength => Some(
                MockInput::try_new(*source, &candidate(*source, *pattern, true))
                    .expect("bounded short candidate"),
            ),
        },
        Action::IngressRead { boundaries, .. }
        | Action::EgressBegin { boundaries, .. }
        | Action::EgressWrite { boundaries, .. }
        | Action::Close { boundaries }
            if boundaries & 1 != 0 =>
        {
            Some(
                MockInput::try_new(
                    Source::CameraA1Candidate,
                    &candidate(Source::CameraA1Candidate, 0x41, false),
                )
                .expect("bounded unexpected input"),
            )
        }
        Action::EgressFinish {
            unexpected_input: true,
            ..
        }
        | Action::Malformed {
            with_input: true, ..
        } => Some(
            MockInput::try_new(
                Source::CameraA1Candidate,
                &candidate(Source::CameraA1Candidate, 0x4d, false),
            )
            .expect("bounded discarded input"),
        ),
        _ => None,
    }
}

fn make_writer(action: &Action) -> Option<MockOutputWriter> {
    match action {
        Action::IngressRead { boundaries, .. }
        | Action::EgressBegin { boundaries, .. }
        | Action::EgressWrite { boundaries, .. }
        | Action::Close { boundaries }
            if boundaries & 2 != 0 =>
        {
            Some(MockOutputWriter::new(Sink::Print))
        }
        Action::EgressFinish { writer, .. } => match writer {
            WriterMode::Missing => None,
            WriterMode::Valid => Some(MockOutputWriter::new(Sink::Print)),
            WriterMode::WrongKind => Some(MockOutputWriter::new(Sink::Sd)),
            WriterMode::Fault(fault) => Some(MockOutputWriter::with_fault(Sink::Print, *fault)),
        },
        _ => None,
    }
}

fn request_payload(action: &Action) -> Option<Vec<u8>> {
    match action {
        Action::IngressBegin { source, .. } => Some(inner_request(
            Operation::IngressBegin,
            &[source.wire_value(), 0, 0],
        )),
        Action::IngressRead { offset, .. } => {
            Some(inner_request(Operation::IngressRead, &offset.to_le_bytes()))
        }
        Action::EgressBegin {
            artifact,
            total_len,
            ..
        } => {
            let mut body = vec![Sink::Print.wire_value(), artifact.wire_value()];
            body.extend_from_slice(&total_len.to_le_bytes());
            body.extend_from_slice(&0u16.to_le_bytes());
            Some(inner_request(Operation::EgressBegin, &body))
        }
        Action::EgressWrite { offset, chunk, .. } => {
            let mut body = Vec::with_capacity(8 + chunk.len());
            body.extend_from_slice(&offset.to_le_bytes());
            body.extend_from_slice(&(chunk.len() as u32).to_le_bytes());
            body.extend_from_slice(chunk);
            Some(inner_request(Operation::EgressWrite, &body))
        }
        Action::EgressFinish { .. } => Some(inner_request(Operation::EgressFinish, &[])),
        Action::Malformed { case, pattern, .. } => Some(malformed_payload(*case, *pattern)),
        Action::TerminalProbe => Some(inner_request(Operation::IngressRead, &0u32.to_le_bytes())),
        Action::Close { .. } | Action::PeerLost | Action::ReceiveFailed(_) => None,
    }
}

fn actual_step(
    broker: &mut BrokerSession,
    action: &Action,
    session_id: [u8; 16],
    exchange_id: u32,
) -> (Outcome, BoundaryFacts) {
    if matches!(action, Action::PeerLost) {
        let error = broker.peer_lost();
        assert_broker_named(error);
        return (
            Outcome::Error(error),
            BoundaryFacts {
                input_used: None,
                writer_used: None,
                temporary: None,
                final_output: None,
                final_name: None,
            },
        );
    }
    if let Action::ReceiveFailed(receive_error) = action {
        let error = broker.receive_failed(*receive_error);
        assert_broker_named(error);
        return (
            Outcome::Error(error),
            BoundaryFacts {
                input_used: None,
                writer_used: None,
                temporary: None,
                final_output: None,
                final_name: None,
            },
        );
    }

    let kind = if matches!(action, Action::Close { .. }) {
        MessageKind::SessionClose
    } else {
        MessageKind::OperationRequest
    };
    let payload = request_payload(action).unwrap_or_default();
    let request = receive(&qkip_frame(
        0x01,
        kind.wire_value(),
        session_id,
        exchange_id,
        &payload,
    ));
    let mut input = make_input(action);
    let mut writer = make_writer(action);
    let result = broker.accept(&request, input.as_mut(), writer.as_mut());
    let outcome = match result {
        Ok(reply) => {
            assert!(!reply.is_empty());
            assert_eq!(reply.len(), reply.frame_bytes().len());
            assert_reply_named(reply.status());
            Outcome::Reply {
                status: reply.status(),
                frame: reply.frame_bytes().to_vec(),
            }
        }
        Err(error) => {
            assert_broker_named(error);
            Outcome::Error(error)
        }
    };
    let facts = BoundaryFacts {
        input_used: input.as_ref().map(MockInput::is_used),
        writer_used: writer.as_ref().map(MockOutputWriter::is_used),
        temporary: writer
            .as_ref()
            .and_then(MockOutputWriter::temporary_bytes)
            .map(<[u8]>::to_vec),
        final_output: writer
            .as_ref()
            .and_then(MockOutputWriter::final_bytes)
            .map(<[u8]>::to_vec),
        final_name: writer
            .as_ref()
            .and_then(MockOutputWriter::final_name)
            .map(<[u8]>::to_vec),
    };
    if facts.input_used.is_some() {
        assert_eq!(facts.input_used, Some(true));
    }
    if facts.writer_used.is_some() {
        assert_eq!(facts.writer_used, Some(true));
    }
    (outcome, facts)
}

fn drive(actions: &[Action], session_id: [u8; 16]) -> RunTrace {
    reset_wiped_bytes();
    let mut broker = BrokerSession::new();
    let opening = receive(&qkip_frame(0x01, 0x0001, session_id, 1, &[]));
    let ready = broker
        .accept(&opening, None, None)
        .expect("canonical session opening");
    assert_eq!(ready.status(), ReplyStatus::Control);
    assert_eq!(
        ready.frame_bytes(),
        qkip_frame(0x02, 0x0101, session_id, 1, &[])
    );
    drop(ready);
    let initial_wiped = wiped_bytes();
    assert!(initial_wiped >= HEADER_BYTES);

    let mut model = Model::new(session_id);
    let mut steps = Vec::with_capacity(actions.len());
    let mut exchange_id = 2u32;
    let mut previous_wiped = initial_wiped;
    for (index, action) in actions.iter().enumerate() {
        let expected = model.step(action, exchange_id);
        let (actual, boundaries) = actual_step(&mut broker, action, session_id, exchange_id);
        assert_eq!(
            actual, expected.outcome,
            "session/model divergence at step {index}"
        );
        assert_eq!(
            boundaries.final_output, expected.final_output,
            "partial or mismatched output at step {index}"
        );
        if expected.final_output.is_none() {
            assert!(boundaries.final_name.is_none());
        }
        assert_eq!(broker.state(), model.state.public());
        let wiped = wiped_bytes();
        assert!(wiped >= previous_wiped);
        previous_wiped = wiped;
        steps.push(StepFact {
            outcome: actual,
            state: broker.state(),
            boundaries,
            wiped,
        });
        if !matches!(action, Action::PeerLost | Action::ReceiveFailed(_)) {
            exchange_id = exchange_id.checked_add(1).expect("bounded command count");
        }
    }
    let final_state = broker.state();
    let active_drop_minimum = match &model.state {
        ModelState::Ingress { data, .. } => data.len(),
        ModelState::Egress { total_len, .. } => total_len.saturating_add(MAX_FILENAME_BYTES),
        ModelState::Idle
        | ModelState::ErrorReplyPending
        | ModelState::Closed
        | ModelState::Terminated => 0,
    };
    drop(broker);
    let final_wiped = wiped_bytes();
    assert!(final_wiped >= previous_wiped.saturating_add(active_drop_minimum));
    RunTrace {
        initial_wiped,
        steps,
        final_state,
        final_wiped,
    }
}

fn inner_request(operation: Operation, body: &[u8]) -> Vec<u8> {
    let mut bytes = Vec::with_capacity(INNER_HEADER_BYTES + body.len());
    bytes.extend_from_slice(&[INNER_VERSION, operation.wire_value(), 0, 0]);
    bytes.extend_from_slice(&(body.len() as u32).to_le_bytes());
    bytes.extend_from_slice(body);
    bytes
}

fn inner_response(opcode: u8, status: u16, body: &[u8]) -> Vec<u8> {
    let mut bytes = Vec::with_capacity(INNER_HEADER_BYTES + body.len());
    bytes.extend_from_slice(&[INNER_VERSION, opcode]);
    bytes.extend_from_slice(&status.to_le_bytes());
    bytes.extend_from_slice(&(body.len() as u32).to_le_bytes());
    bytes.extend_from_slice(body);
    bytes
}

fn qkip_frame(
    direction: u8,
    kind: u16,
    session_id: [u8; 16],
    exchange_id: u32,
    payload: &[u8],
) -> Vec<u8> {
    let mut bytes = Vec::with_capacity(HEADER_BYTES + payload.len());
    bytes.extend_from_slice(b"QKIP");
    bytes.push(1);
    bytes.push(direction);
    bytes.extend_from_slice(&kind.to_le_bytes());
    bytes.extend_from_slice(&session_id);
    bytes.extend_from_slice(&exchange_id.to_le_bytes());
    bytes.extend_from_slice(&(payload.len() as u32).to_le_bytes());
    bytes.extend_from_slice(payload);
    bytes
}

fn receive(bytes: &[u8]) -> ReceivedFrame {
    let mut decoder = StreamDecoder::new();
    let outcome = decoder
        .ingest(bytes, false)
        .expect("model-built QKIP frame decodes");
    assert_eq!(outcome.consumed(), bytes.len());
    assert!(outcome.frame_ready());
    decoder.take_frame().expect("model-built complete frame")
}

fn malformed_payload(case: u8, pattern: u8) -> Vec<u8> {
    match case % 7 {
        0 => vec![pattern; usize::from(pattern % 7) + 1],
        1 => {
            let mut bytes = inner_request(Operation::EgressFinish, &[]);
            bytes[0] = 2;
            bytes
        }
        2 => {
            let mut bytes = inner_request(Operation::EgressFinish, &[]);
            bytes[2] = 1;
            bytes
        }
        3 => {
            let mut bytes = inner_request(Operation::EgressFinish, &[]);
            bytes[1] = 0xff;
            bytes
        }
        4 => {
            let mut bytes = inner_request(Operation::EgressFinish, &[]);
            bytes[4..8].copy_from_slice(&((MAX_INNER_BODY_BYTES as u32) + 1).to_le_bytes());
            bytes
        }
        5 => {
            let mut bytes = inner_request(Operation::IngressRead, &[]);
            bytes[4..8].copy_from_slice(&4u32.to_le_bytes());
            bytes
        }
        6 => {
            let mut bytes = inner_request(Operation::EgressFinish, &[]);
            bytes.push(pattern);
            bytes
        }
        _ => unreachable!("modulo seven is exhaustive"),
    }
}

fn malformed_error(case: u8, pattern: u8) -> (u8, InnerError) {
    match case % 7 {
        0 => (
            if pattern.is_multiple_of(7) {
                0
            } else {
                pattern
            },
            InnerError::InnerHeaderTruncated,
        ),
        1 => (
            Operation::EgressFinish.wire_value(),
            InnerError::InnerVersionMismatch,
        ),
        2 => (
            Operation::EgressFinish.wire_value(),
            InnerError::RequestReservedNonZero,
        ),
        3 => (0xff, InnerError::OperationOutOfRange),
        4 => (
            Operation::EgressFinish.wire_value(),
            InnerError::BodyLengthExceeded,
        ),
        5 => (
            Operation::IngressRead.wire_value(),
            InnerError::BodyTruncated,
        ),
        6 => (
            Operation::EgressFinish.wire_value(),
            InnerError::TrailingByte,
        ),
        _ => unreachable!("modulo seven is exhaustive"),
    }
}

fn control(command: &[u8], index: usize) -> u8 {
    match command.get(index).copied().unwrap_or(0) {
        byte @ b'0'..=b'9' => byte - b'0',
        byte @ b'a'..=b'f' => byte - b'a' + 10,
        byte @ b'A'..=b'F' => byte - b'A' + 10,
        byte => byte,
    }
}

fn u32_control(command: &[u8], index: usize) -> u32 {
    u32::from_le_bytes([
        control(command, index),
        control(command, index + 1),
        control(command, index + 2),
        control(command, index + 3),
    ])
}

fn action(command: &[u8]) -> Action {
    match control(command, 0) % 10 {
        0 => Action::IngressBegin {
            source: if control(command, 1) & 1 == 0 {
                Source::CameraA1Candidate
            } else {
                Source::CameraKitCandidate
            },
            input: match control(command, 2) % 5 {
                0 => InputMode::Missing,
                1 => InputMode::Valid,
                2 => InputMode::WrongKind,
                3 => InputMode::Failing,
                _ => InputMode::WrongLength,
            },
            pattern: control(command, 3),
        },
        1 => Action::IngressRead {
            offset: if control(command, 1) & 1 == 0 {
                0
            } else {
                u32_control(command, 2)
            },
            boundaries: control(command, 6) & 3,
        },
        2 => Action::EgressBegin {
            artifact: match control(command, 1) % 3 {
                0 => Artifact::A1PrintArtifact,
                1 => Artifact::KitPrintArtifact,
                _ => Artifact::RawTransaction,
            },
            total_len: u32::from(control(command, 2) % 9),
            boundaries: control(command, 3) & 3,
        },
        3 => {
            let length = usize::from(control(command, 2) % 9);
            Action::EgressWrite {
                offset: if control(command, 1) & 1 == 0 {
                    0
                } else {
                    u32_control(command, 3)
                },
                chunk: vec![control(command, 7); length],
                boundaries: control(command, 8) & 3,
            }
        }
        4 => Action::EgressFinish {
            writer: match control(command, 1) % 4 {
                0 => WriterMode::Missing,
                1 => WriterMode::Valid,
                2 => WriterMode::WrongKind,
                _ => WriterMode::Fault(output_fault(control(command, 2))),
            },
            unexpected_input: control(command, 3) & 1 != 0,
        },
        5 => Action::Malformed {
            case: control(command, 1),
            pattern: control(command, 2),
            with_input: control(command, 3) & 1 != 0,
        },
        6 => Action::Close {
            boundaries: control(command, 1) & 3,
        },
        7 => Action::PeerLost,
        8 => Action::TerminalProbe,
        9 => Action::ReceiveFailed(receive_error(control(command, 1))),
        _ => unreachable!("modulo ten is exhaustive"),
    }
}

fn receive_error(selector: u8) -> IpcError {
    match selector % 32 {
        0 => IpcError::DecoderTerminated,
        1 => IpcError::SessionTerminated,
        2 => IpcError::AncillaryData,
        3 => IpcError::HeaderTruncated,
        4 => IpcError::MagicMismatch,
        5 => IpcError::VersionMismatch,
        6 => IpcError::DirectionOutOfRange,
        7 => IpcError::KindOutOfRange,
        8 => IpcError::DirectionKindMismatch,
        9 => IpcError::ExchangeIdZero,
        10 => IpcError::PayloadLengthExceeded,
        11 => IpcError::PayloadTruncated,
        12 => IpcError::TrailingByte,
        13 => IpcError::ControlPayloadNotEmpty,
        14 => IpcError::OperationPayloadEmpty,
        15 => IpcError::OutputBufferTooSmall,
        16 => IpcError::PayloadAllocationFailed,
        17 => IpcError::UnexpectedDirection,
        18 => IpcError::SessionIdMismatch,
        19 => IpcError::UnexpectedMessageKind,
        20 => IpcError::ExchangeIdReuse,
        21 => IpcError::ExchangeIdRegression,
        22 => IpcError::ExchangeIdSkipped,
        23 => IpcError::ExchangeIdExhausted,
        24 => IpcError::ResponseIdMismatch,
        25 => IpcError::OutstandingExchange,
        26 => IpcError::NoOutstandingExchange,
        27 => IpcError::SessionNotReady,
        28 => IpcError::SessionClosed,
        29 => IpcError::InvalidTransition,
        30 => IpcError::PeerLost,
        31 => IpcError::ConnectionClosedMidFrame,
        _ => unreachable!("modulo 32 is exhaustive"),
    }
}

fn output_fault(selector: u8) -> OutputFault {
    match selector % 10 {
        0 => OutputFault::None,
        1 => OutputFault::Collision,
        2 => OutputFault::Create,
        3 => OutputFault::Write,
        4 => OutputFault::Sync,
        5 => OutputFault::Close,
        6 => OutputFault::Reopen,
        7 => OutputFault::ReadbackMismatch,
        8 => OutputFault::Rename,
        9 => OutputFault::Print,
        _ => unreachable!("modulo ten is exhaustive"),
    }
}

fn assert_reply_named(status: ReplyStatus) {
    if let ReplyStatus::Rejected { error, .. } = status {
        assert_inner_named(error);
    }
}

fn assert_broker_named(error: BrokerError) {
    let expected = match error {
        BrokerError::BrokerTerminated => "BrokerTerminated",
        BrokerError::CloseWithActiveTransfer => "CloseWithActiveTransfer",
        BrokerError::Inner(inner) => {
            assert_inner_named(inner);
            return;
        }
        BrokerError::Ipc(ipc) => ipc_name(ipc),
    };
    assert_eq!(error.to_string(), expected);
}

fn assert_inner_named(error: InnerError) {
    let expected = inner_name(error);
    if !matches!(error, InnerError::Bbqr(_)) {
        assert_eq!(error.to_string(), expected);
    } else {
        assert!(!error.to_string().is_empty());
        assert!((0x0101..=0x011e).contains(&error.status_code()));
    }
}

fn inner_name(error: InnerError) -> &'static str {
    match error {
        InnerError::InnerHeaderTruncated => "InnerHeaderTruncated",
        InnerError::InnerVersionMismatch => "InnerVersionMismatch",
        InnerError::RequestReservedNonZero => "RequestReservedNonZero",
        InnerError::OperationOutOfRange => "OperationOutOfRange",
        InnerError::BodyLengthExceeded => "BodyLengthExceeded",
        InnerError::BodyTruncated => "BodyTruncated",
        InnerError::TrailingByte => "TrailingByte",
        InnerError::UnexpectedBoundary => "UnexpectedBoundary",
        InnerError::BoundaryMissing => "BoundaryMissing",
        InnerError::SourceKindMismatch => "SourceKindMismatch",
        InnerError::SourceAlreadyUsed => "SourceAlreadyUsed",
        InnerError::WriterKindMismatch => "WriterKindMismatch",
        InnerError::WriterAlreadyUsed => "WriterAlreadyUsed",
        InnerError::ActiveTransfer => "ActiveTransfer",
        InnerError::NoActiveTransfer => "NoActiveTransfer",
        InnerError::WrongTransferDirection => "WrongTransferDirection",
        InnerError::SourceLengthMismatch => "SourceLengthMismatch",
        InnerError::DeclaredLengthZero => "DeclaredLengthZero",
        InnerError::DeclaredLengthExceeded => "DeclaredLengthExceeded",
        InnerError::OffsetMismatch => "OffsetMismatch",
        InnerError::ChunkLengthZero => "ChunkLengthZero",
        InnerError::ChunkLengthExceeded => "ChunkLengthExceeded",
        InnerError::TransferLengthExceeded => "TransferLengthExceeded",
        InnerError::TransferIncomplete => "TransferIncomplete",
        InnerError::SourceOutOfRange => "SourceOutOfRange",
        InnerError::SinkOutOfRange => "SinkOutOfRange",
        InnerError::ArtifactOutOfRange => "ArtifactOutOfRange",
        InnerError::SinkArtifactMismatch => "SinkArtifactMismatch",
        InnerError::InvalidFilename => "InvalidFilename",
        InnerError::InvalidBbqrPartLength => "InvalidBbqrPartLength",
        InnerError::AllocationFailed => "AllocationFailed",
        InnerError::SourceReadFailed => "SourceReadFailed",
        InnerError::OutputCollision => "OutputCollision",
        InnerError::OutputCreateFailed => "OutputCreateFailed",
        InnerError::OutputWriteFailed => "OutputWriteFailed",
        InnerError::OutputSyncFailed => "OutputSyncFailed",
        InnerError::OutputCloseFailed => "OutputCloseFailed",
        InnerError::OutputReopenFailed => "OutputReopenFailed",
        InnerError::OutputReadbackMismatch => "OutputReadbackMismatch",
        InnerError::OutputRenameFailed => "OutputRenameFailed",
        InnerError::PrintFailed => "PrintFailed",
        InnerError::Bbqr(_) => "Bbqr",
    }
}

fn ipc_name(error: IpcError) -> &'static str {
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

fn fixed_paths() {
    let ingress = [
        Action::IngressBegin {
            source: Source::CameraKitCandidate,
            input: InputMode::Valid,
            pattern: 0x4b,
        },
        Action::IngressRead {
            offset: 0,
            boundaries: 0,
        },
        Action::Close { boundaries: 0 },
    ];
    let ingress_trace = drive(&ingress, [0x31; 16]);
    assert_eq!(ingress_trace.final_state, BrokerState::Closed);

    let egress = [
        Action::EgressBegin {
            artifact: Artifact::A1PrintArtifact,
            total_len: 3,
            boundaries: 0,
        },
        Action::EgressWrite {
            offset: 0,
            chunk: b"abc".to_vec(),
            boundaries: 0,
        },
        Action::EgressFinish {
            writer: WriterMode::Valid,
            unexpected_input: false,
        },
        Action::Close { boundaries: 0 },
    ];
    let egress_trace = drive(&egress, [0x32; 16]);
    assert_eq!(egress_trace.final_state, BrokerState::Closed);
    assert_eq!(
        egress_trace.steps[2].boundaries.final_output,
        Some(b"abc".to_vec())
    );

    let active_loss = [
        Action::IngressBegin {
            source: Source::CameraA1Candidate,
            input: InputMode::Valid,
            pattern: 0x41,
        },
        Action::PeerLost,
    ];
    let loss_trace = drive(&active_loss, [0x33; 16]);
    assert_eq!(loss_trace.final_state, BrokerState::Terminated);
    assert!(
        loss_trace.steps[1].wiped >= loss_trace.steps[0].wiped.saturating_add(A1_CANDIDATE_BYTES)
    );

    let active_close = [
        Action::EgressBegin {
            artifact: Artifact::KitPrintArtifact,
            total_len: 8,
            boundaries: 0,
        },
        Action::Close { boundaries: 0 },
    ];
    let close_trace = drive(&active_close, [0x34; 16]);
    assert_eq!(close_trace.final_state, BrokerState::Terminated);
    assert!(matches!(
        close_trace.steps[1].outcome,
        Outcome::Error(BrokerError::CloseWithActiveTransfer)
    ));

    let rejected = [
        Action::Malformed {
            case: 1,
            pattern: 0x52,
            with_input: true,
        },
        Action::TerminalProbe,
    ];
    let rejected_trace = drive(&rejected, [0x35; 16]);
    assert_eq!(rejected_trace.final_state, BrokerState::ErrorReplyPending);
    assert!(matches!(
        rejected_trace.steps[1].outcome,
        Outcome::Error(BrokerError::BrokerTerminated)
    ));

    let fault = [
        Action::EgressBegin {
            artifact: Artifact::A1PrintArtifact,
            total_len: 1,
            boundaries: 0,
        },
        Action::EgressWrite {
            offset: 0,
            chunk: vec![0x58],
            boundaries: 0,
        },
        Action::EgressFinish {
            writer: WriterMode::Fault(OutputFault::Print),
            unexpected_input: false,
        },
    ];
    let fault_trace = drive(&fault, [0x36; 16]);
    assert_eq!(fault_trace.final_state, BrokerState::ErrorReplyPending);
    assert!(fault_trace.steps[2].boundaries.final_output.is_none());

    for selector in 0u8..32 {
        let receive_error = receive_error(selector);
        let category_actions = [
            Action::ReceiveFailed(receive_error),
            Action::ReceiveFailed(IpcError::ConnectionClosedMidFrame),
        ];
        let category_trace = drive(&category_actions, [selector; 16]);
        assert_eq!(
            category_trace.steps[0].outcome,
            Outcome::Error(BrokerError::Ipc(receive_error))
        );
        assert_eq!(category_trace.steps[0].state, BrokerState::Terminated);
        assert_eq!(
            category_trace.steps[1].outcome,
            Outcome::Error(BrokerError::BrokerTerminated)
        );
    }

    let receive_failed_ingress = [
        Action::IngressBegin {
            source: Source::CameraA1Candidate,
            input: InputMode::Valid,
            pattern: 0x61,
        },
        Action::ReceiveFailed(IpcError::AncillaryData),
        Action::ReceiveFailed(IpcError::PayloadTruncated),
    ];
    let ingress_failure_trace = drive(&receive_failed_ingress, [0x37; 16]);
    assert_eq!(
        ingress_failure_trace.steps[1].outcome,
        Outcome::Error(BrokerError::Ipc(IpcError::AncillaryData))
    );
    assert_eq!(
        ingress_failure_trace.steps[1].state,
        BrokerState::Terminated
    );
    assert!(
        ingress_failure_trace.steps[1].wiped
            >= ingress_failure_trace.steps[0]
                .wiped
                .saturating_add(A1_CANDIDATE_BYTES)
    );
    assert_eq!(
        ingress_failure_trace.steps[2].outcome,
        Outcome::Error(BrokerError::BrokerTerminated)
    );

    const RECEIVE_FAILED_EGRESS_BYTES: u32 = 7;
    let receive_failed_egress = [
        Action::EgressBegin {
            artifact: Artifact::KitPrintArtifact,
            total_len: RECEIVE_FAILED_EGRESS_BYTES,
            boundaries: 0,
        },
        Action::ReceiveFailed(IpcError::ConnectionClosedMidFrame),
        Action::TerminalProbe,
    ];
    let egress_failure_trace = drive(&receive_failed_egress, [0x38; 16]);
    assert_eq!(
        egress_failure_trace.steps[1].outcome,
        Outcome::Error(BrokerError::Ipc(IpcError::ConnectionClosedMidFrame))
    );
    assert_eq!(egress_failure_trace.steps[1].state, BrokerState::Terminated);
    assert!(
        egress_failure_trace.steps[1].wiped
            >= egress_failure_trace.steps[0]
                .wiped
                .saturating_add(RECEIVE_FAILED_EGRESS_BYTES as usize)
                .saturating_add(MAX_FILENAME_BYTES)
    );
    assert_eq!(
        egress_failure_trace.steps[2].outcome,
        Outcome::Error(BrokerError::BrokerTerminated)
    );

    fixed_cleanup_paths();
}

fn open_direct(session_id: [u8; 16]) -> BrokerSession {
    let mut broker = BrokerSession::new();
    let opening = receive(&qkip_frame(0x01, 0x0001, session_id, 1, &[]));
    let ready = broker
        .accept(&opening, None, None)
        .expect("direct cleanup opening");
    assert_eq!(ready.status(), ReplyStatus::Control);
    drop(ready);
    broker
}

fn direct_request(
    broker: &mut BrokerSession,
    session_id: [u8; 16],
    exchange_id: u32,
    payload: &[u8],
    input: Option<&mut MockInput>,
    writer: Option<&mut MockOutputWriter>,
) -> BrokerReply {
    let request = receive(&qkip_frame(
        0x01,
        MessageKind::OperationRequest.wire_value(),
        session_id,
        exchange_id,
        payload,
    ));
    broker
        .accept(&request, input, writer)
        .expect("direct cleanup request")
}

fn fixed_cleanup_paths() {
    const INGRESS_SESSION: [u8; 16] = [0x41; 16];
    let mut ingress_broker = open_direct(INGRESS_SESSION);
    let candidate = [0x51; KIT_CANDIDATE_BYTES];
    let mut input =
        MockInput::try_new(Source::CameraKitCandidate, &candidate).expect("bounded direct input");
    drop(direct_request(
        &mut ingress_broker,
        INGRESS_SESSION,
        2,
        &inner_request(
            Operation::IngressBegin,
            &[Source::CameraKitCandidate.wire_value(), 0, 0],
        ),
        Some(&mut input),
        None,
    ));
    drop(input);
    let read_request = receive(&qkip_frame(
        0x01,
        MessageKind::OperationRequest.wire_value(),
        INGRESS_SESSION,
        3,
        &inner_request(Operation::IngressRead, &0u32.to_le_bytes()),
    ));
    reset_wiped_bytes();
    let read_reply = ingress_broker
        .accept(&read_request, None, None)
        .expect("direct final ingress read");
    assert_eq!(
        read_reply.status(),
        ReplyStatus::Success(Operation::IngressRead)
    );
    assert_eq!(ingress_broker.state(), BrokerState::Idle);
    let read_body_bytes = 9usize + KIT_CANDIDATE_BYTES;
    let read_payload_bytes = INNER_HEADER_BYTES + read_body_bytes;
    assert!(
        wiped_bytes()
            >= KIT_CANDIDATE_BYTES
                .saturating_add(read_body_bytes)
                .saturating_add(read_payload_bytes)
    );
    drop(read_reply);
    drop(read_request);
    drop(ingress_broker);

    const EGRESS_SESSION: [u8; 16] = [0x42; 16];
    const EGRESS_BYTES: usize = 11;
    let mut egress_broker = open_direct(EGRESS_SESSION);
    drop(direct_request(
        &mut egress_broker,
        EGRESS_SESSION,
        2,
        &{
            let mut body = vec![
                Sink::Print.wire_value(),
                Artifact::A1PrintArtifact.wire_value(),
            ];
            body.extend_from_slice(&(EGRESS_BYTES as u32).to_le_bytes());
            body.extend_from_slice(&0u16.to_le_bytes());
            inner_request(Operation::EgressBegin, &body)
        },
        None,
        None,
    ));
    drop(direct_request(
        &mut egress_broker,
        EGRESS_SESSION,
        3,
        &{
            let mut body = Vec::with_capacity(8 + EGRESS_BYTES);
            body.extend_from_slice(&0u32.to_le_bytes());
            body.extend_from_slice(&(EGRESS_BYTES as u32).to_le_bytes());
            body.extend_from_slice(&[0x62; EGRESS_BYTES]);
            inner_request(Operation::EgressWrite, &body)
        },
        None,
        None,
    ));
    let finish_request = receive(&qkip_frame(
        0x01,
        MessageKind::OperationRequest.wire_value(),
        EGRESS_SESSION,
        4,
        &inner_request(Operation::EgressFinish, &[]),
    ));
    let mut writer = MockOutputWriter::new(Sink::Print);
    reset_wiped_bytes();
    let finish_reply = egress_broker
        .accept(&finish_request, None, Some(&mut writer))
        .expect("direct egress handoff");
    assert_eq!(
        finish_reply.status(),
        ReplyStatus::Success(Operation::EgressFinish)
    );
    assert_eq!(egress_broker.state(), BrokerState::Idle);
    let receipt_bytes = 6usize;
    let receipt_payload_bytes = INNER_HEADER_BYTES + receipt_bytes;
    assert!(
        wiped_bytes()
            >= EGRESS_BYTES
                .saturating_add(MAX_FILENAME_BYTES)
                .saturating_add(receipt_bytes)
                .saturating_add(receipt_payload_bytes)
    );
    assert_eq!(writer.final_bytes(), Some(&[0x62; EGRESS_BYTES][..]));
    drop(finish_reply);
    drop(finish_request);
    drop(writer);
    drop(egress_broker);

    const CLOSE_SESSION: [u8; 16] = [0x43; 16];
    const CLOSE_BYTES: usize = 13;
    let mut close_broker = open_direct(CLOSE_SESSION);
    drop(direct_request(
        &mut close_broker,
        CLOSE_SESSION,
        2,
        &{
            let mut body = vec![
                Sink::Print.wire_value(),
                Artifact::KitPrintArtifact.wire_value(),
            ];
            body.extend_from_slice(&(CLOSE_BYTES as u32).to_le_bytes());
            body.extend_from_slice(&0u16.to_le_bytes());
            inner_request(Operation::EgressBegin, &body)
        },
        None,
        None,
    ));
    let close_request = receive(&qkip_frame(
        0x01,
        MessageKind::SessionClose.wire_value(),
        CLOSE_SESSION,
        3,
        &[],
    ));
    reset_wiped_bytes();
    assert!(matches!(
        close_broker.accept(&close_request, None, None),
        Err(BrokerError::CloseWithActiveTransfer)
    ));
    assert_eq!(close_broker.state(), BrokerState::Terminated);
    assert!(wiped_bytes() >= CLOSE_BYTES.saturating_add(MAX_FILENAME_BYTES));
    drop(close_request);
    drop(close_broker);
}

fuzz_target!(|data: &[u8]| {
    if data.len() > MAX_PRESENTED_BYTES {
        return;
    }
    fixed_paths();
    let mut session_id = [0u8; 16];
    for (destination, source) in session_id.iter_mut().zip(data.iter().copied()) {
        *destination = source;
    }
    let actions: Vec<Action> = data.chunks(COMMAND_BYTES).map(action).collect();
    let first = drive(&actions, session_id);
    let repeated = drive(&actions, session_id);
    assert_eq!(first, repeated, "nondeterministic broker session outcome");
});
