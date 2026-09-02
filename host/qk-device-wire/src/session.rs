//! Pure sequence, request/response, and transfer state owners.

use crate::{
    encode_frame,
    wire::{parse_output, validate_input_begin, validate_output_body},
    Artifact, BodyRef, Capability, CardResponseBody, DeviceError, InputBody, MessageKind,
    OutputBody, OutputReplyBody, ReceivedFrame, Source,
};

/// Immutable outbound header facts produced only by a valid transition.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct OutboundFrame {
    capability: Capability,
    kind: MessageKind,
    sequence: u32,
    output: Option<OutputExpectation>,
}

impl OutboundFrame {
    pub const fn capability(self) -> Capability {
        self.capability
    }

    pub const fn kind(self) -> MessageKind {
        self.kind
    }

    pub const fn sequence(self) -> u32 {
        self.sequence
    }

    pub fn encode(self, body: &[u8], output: &mut [u8]) -> Result<usize, DeviceError> {
        if let Some(expected) = self.output {
            let actual = parse_output(self.capability, self.kind, body)?;
            output_request_matches(expected, actual)?;
        }
        encode_frame(self.capability, self.kind, self.sequence, body, output)
    }
}

/// One exact sequence owner for an unpaired descriptor.
pub struct OneWayProtocol {
    capability: Capability,
    next_outbound: Option<u32>,
    last_inbound: u32,
    terminated: bool,
}

impl OneWayProtocol {
    pub const fn new(capability: Capability) -> Self {
        Self {
            capability,
            next_outbound: Some(1),
            last_inbound: 0,
            terminated: false,
        }
    }

    pub fn next(&mut self, kind: MessageKind) -> Result<OutboundFrame, DeviceError> {
        self.require_live()?;
        if kind.capability() != self.capability {
            return Err(self.terminate(DeviceError::CapabilityKindMismatch));
        }
        let sequence = match self.next_outbound {
            Some(sequence) => sequence,
            None => return Err(self.terminate(DeviceError::SequenceExhausted)),
        };
        self.next_outbound = sequence.checked_add(1);
        Ok(OutboundFrame {
            capability: self.capability,
            kind,
            sequence,
            output: None,
        })
    }

    /// Accept a frame when a caller does not use StreamDecoder's sequence
    /// owner. Using both is harmless and locks the same monotonic facts.
    pub fn accept(&mut self, frame: &ReceivedFrame) -> Result<(), DeviceError> {
        self.require_live()?;
        let header = frame.header();
        if header.capability() != self.capability {
            return Err(self.terminate(DeviceError::CapabilityMismatch));
        }
        if let Err(error) = sequence_check(self.last_inbound, header.sequence()) {
            return Err(self.terminate(error));
        }
        frame.parsed_body().map_err(|error| self.terminate(error))?;
        self.last_inbound = header.sequence();
        Ok(())
    }

    pub fn peer_lost(&mut self) -> DeviceError {
        if self.terminated {
            DeviceError::DecoderTerminated
        } else {
            self.terminate(DeviceError::PeerLost)
        }
    }

    pub const fn is_terminated(&self) -> bool {
        self.terminated
    }

    #[cfg(feature = "fuzzing")]
    #[doc(hidden)]
    pub fn fuzz_sequence_exhaustion_probe(capability: Capability) -> DeviceError {
        let mut protocol = Self::new(capability);
        protocol.next_outbound = None;
        protocol.next(MessageKind::DisplayStage).unwrap_err()
    }

    fn require_live(&self) -> Result<(), DeviceError> {
        if self.terminated {
            Err(DeviceError::DecoderTerminated)
        } else {
            Ok(())
        }
    }

    fn terminate(&mut self, error: DeviceError) -> DeviceError {
        self.terminated = true;
        error
    }
}

/// One outstanding request/response owner across paired one-way descriptors.
pub struct ExchangeProtocol {
    request_capability: Capability,
    response_capability: Capability,
    next_sequence: Option<u32>,
    outstanding: Option<OutstandingExchange>,
    terminated: bool,
}

#[derive(Clone, Copy)]
struct OutstandingExchange {
    sequence: u32,
    request_kind: MessageKind,
    output: Option<OutputExpectation>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum OutputExpectation {
    Begin {
        artifact: Artifact,
        total_len: u32,
    },
    Chunk {
        offset: u32,
        chunk_len: u32,
        next_offset: u32,
    },
    Finish {
        artifact: Artifact,
        total_len: u32,
    },
}

impl ExchangeProtocol {
    pub fn new(
        request_capability: Capability,
        response_capability: Capability,
    ) -> Result<Self, DeviceError> {
        let valid = matches!(
            (request_capability, response_capability),
            (Capability::CardRequest, Capability::CardResponse)
                | (Capability::PrintOutput, Capability::MediaInput)
                | (Capability::MediaOutput, Capability::MediaInput)
        );
        if !valid {
            return Err(DeviceError::CapabilityMismatch);
        }
        Ok(Self {
            request_capability,
            response_capability,
            next_sequence: Some(1),
            outstanding: None,
            terminated: false,
        })
    }

    pub fn begin(&mut self, kind: MessageKind) -> Result<OutboundFrame, DeviceError> {
        self.require_live()?;
        if self.outstanding.is_some() {
            return Err(self.terminate(DeviceError::OutstandingExchange));
        }
        if kind.capability() != self.request_capability {
            return Err(self.terminate(DeviceError::CapabilityKindMismatch));
        }
        if matches!(
            self.request_capability,
            Capability::PrintOutput | Capability::MediaOutput
        ) {
            return Err(self.terminate(DeviceError::UnexpectedFrame));
        }
        let sequence = match self.next_sequence {
            Some(sequence) => sequence,
            None => return Err(self.terminate(DeviceError::SequenceExhausted)),
        };
        self.outstanding = Some(OutstandingExchange {
            sequence,
            request_kind: kind,
            output: None,
        });
        Ok(OutboundFrame {
            capability: self.request_capability,
            kind,
            sequence,
            output: None,
        })
    }

    /// Begin one output request while binding every fact echoed by its reply.
    pub fn begin_output(&mut self, body: OutputBody<'_>) -> Result<OutboundFrame, DeviceError> {
        self.require_live()?;
        if self.outstanding.is_some() {
            return Err(self.terminate(DeviceError::OutstandingExchange));
        }
        if !matches!(
            self.request_capability,
            Capability::PrintOutput | Capability::MediaOutput
        ) {
            return Err(self.terminate(DeviceError::CapabilityMismatch));
        }
        if let Err(error) = validate_output_body(self.request_capability, body) {
            return Err(self.terminate(error));
        }
        let (kind, output) = match body {
            OutputBody::WriteBegin {
                artifact,
                total_len,
                ..
            } => (
                output_kind(
                    self.request_capability,
                    MessageKind::PrintWriteBegin,
                    MessageKind::MediaWriteBegin,
                )?,
                OutputExpectation::Begin {
                    artifact,
                    total_len,
                },
            ),
            OutputBody::WriteChunk { offset, chunk } => {
                let chunk_len = u32::try_from(chunk.len())
                    .map_err(|_| self.terminate(DeviceError::TransferLengthExceeded))?;
                let next_offset = offset
                    .checked_add(chunk_len)
                    .ok_or_else(|| self.terminate(DeviceError::TransferLengthExceeded))?;
                (
                    output_kind(
                        self.request_capability,
                        MessageKind::PrintWriteChunk,
                        MessageKind::MediaWriteChunk,
                    )?,
                    OutputExpectation::Chunk {
                        offset,
                        chunk_len,
                        next_offset,
                    },
                )
            }
            OutputBody::WriteFinish {
                artifact,
                total_len,
            } => (
                output_kind(
                    self.request_capability,
                    MessageKind::PrintWriteFinish,
                    MessageKind::MediaWriteFinish,
                )?,
                OutputExpectation::Finish {
                    artifact,
                    total_len,
                },
            ),
        };
        let sequence = match self.next_sequence {
            Some(sequence) => sequence,
            None => return Err(self.terminate(DeviceError::SequenceExhausted)),
        };
        self.outstanding = Some(OutstandingExchange {
            sequence,
            request_kind: kind,
            output: Some(output),
        });
        Ok(OutboundFrame {
            capability: self.request_capability,
            kind,
            sequence,
            output: Some(output),
        })
    }

    /// Accept the sole expected response. Every rejection latches terminal.
    pub fn accept_response(&mut self, frame: &ReceivedFrame) -> Result<(), DeviceError> {
        self.require_live()?;
        let header = frame.header();
        if header.capability() != self.response_capability {
            return Err(self.terminate(DeviceError::CapabilityMismatch));
        }
        let outstanding = match self.outstanding {
            Some(value) => value,
            None => return Err(self.terminate(DeviceError::NoOutstandingExchange)),
        };
        let sequence = outstanding.sequence;
        let request_kind = outstanding.request_kind;
        if header.sequence() != sequence {
            return Err(self.terminate(DeviceError::ResponseSequenceMismatch));
        }
        if !response_kind_matches(request_kind, header.kind()) {
            return Err(self.terminate(DeviceError::ResponseKindMismatch));
        }
        let body = match frame.parsed_body() {
            Ok(body) => body,
            Err(error) => return Err(self.terminate(error)),
        };
        if !rejection_matches_request(request_kind, body) {
            return Err(self.terminate(DeviceError::ResponseKindMismatch));
        }
        if matches!(
            body,
            BodyRef::CardResponse(CardResponseBody::Rejected { .. })
                | BodyRef::OutputReply(OutputReplyBody::Rejected { .. })
        ) {
            return Err(self.terminate(DeviceError::DeviceRejected));
        }
        if let Some(expected) = outstanding.output {
            if let Err(error) = output_reply_matches(expected, body) {
                return Err(self.terminate(error));
            }
        }
        self.outstanding = None;
        self.next_sequence = sequence.checked_add(1);
        Ok(())
    }

    pub fn receive_failed(&mut self, error: DeviceError) -> DeviceError {
        if self.terminated {
            DeviceError::DecoderTerminated
        } else {
            self.terminate(error)
        }
    }

    pub fn peer_lost(&mut self) -> DeviceError {
        self.receive_failed(DeviceError::PeerLost)
    }

    pub const fn is_terminated(&self) -> bool {
        self.terminated
    }

    pub const fn has_outstanding(&self) -> bool {
        self.outstanding.is_some()
    }

    fn require_live(&self) -> Result<(), DeviceError> {
        if self.terminated {
            Err(DeviceError::DecoderTerminated)
        } else {
            Ok(())
        }
    }

    fn terminate(&mut self, error: DeviceError) -> DeviceError {
        self.outstanding = None;
        self.terminated = true;
        error
    }
}

fn output_kind(
    capability: Capability,
    print_kind: MessageKind,
    media_kind: MessageKind,
) -> Result<MessageKind, DeviceError> {
    match capability {
        Capability::PrintOutput => Ok(print_kind),
        Capability::MediaOutput => Ok(media_kind),
        _ => Err(DeviceError::CapabilityMismatch),
    }
}

fn output_reply_matches(expected: OutputExpectation, body: BodyRef<'_>) -> Result<(), DeviceError> {
    match (expected, body) {
        (
            OutputExpectation::Begin {
                artifact: expected_artifact,
                total_len: expected_total,
            },
            BodyRef::OutputReply(OutputReplyBody::BeginAccepted {
                artifact,
                total_len,
            }),
        )
        | (
            OutputExpectation::Finish {
                artifact: expected_artifact,
                total_len: expected_total,
            },
            BodyRef::OutputReply(OutputReplyBody::Finished {
                artifact,
                total_len,
            }),
        ) => {
            if artifact == expected_artifact && total_len == expected_total {
                Ok(())
            } else {
                Err(DeviceError::ArtifactMismatch)
            }
        }
        (
            OutputExpectation::Chunk {
                next_offset: expected,
                ..
            },
            BodyRef::OutputReply(OutputReplyBody::ChunkAccepted { next_offset }),
        ) => {
            if next_offset == expected {
                Ok(())
            } else {
                Err(DeviceError::OffsetMismatch)
            }
        }
        _ => Err(DeviceError::ResponseKindMismatch),
    }
}

fn output_request_matches(
    expected: OutputExpectation,
    actual: OutputBody<'_>,
) -> Result<(), DeviceError> {
    match (expected, actual) {
        (
            OutputExpectation::Begin {
                artifact: expected_artifact,
                total_len: expected_total,
            },
            OutputBody::WriteBegin {
                artifact,
                total_len,
                ..
            },
        )
        | (
            OutputExpectation::Finish {
                artifact: expected_artifact,
                total_len: expected_total,
            },
            OutputBody::WriteFinish {
                artifact,
                total_len,
            },
        ) => {
            if artifact == expected_artifact && total_len == expected_total {
                Ok(())
            } else {
                Err(DeviceError::ArtifactMismatch)
            }
        }
        (
            OutputExpectation::Chunk {
                offset: expected_offset,
                chunk_len: expected_len,
                ..
            },
            OutputBody::WriteChunk { offset, chunk },
        ) => {
            if offset == expected_offset && usize::try_from(expected_len) == Ok(chunk.len()) {
                Ok(())
            } else {
                Err(DeviceError::OffsetMismatch)
            }
        }
        _ => Err(DeviceError::UnexpectedFrame),
    }
}

fn response_kind_matches(request: MessageKind, response: MessageKind) -> bool {
    match request {
        MessageKind::CardReadProfile => {
            matches!(
                response,
                MessageKind::CardProfile | MessageKind::CardRejected
            )
        }
        MessageKind::CardReadNormalFactor => matches!(
            response,
            MessageKind::CardNormalFactor | MessageKind::CardRejected
        ),
        MessageKind::PrintWriteBegin | MessageKind::MediaWriteBegin => matches!(
            response,
            MessageKind::MediaBeginAccepted | MessageKind::MediaRejected
        ),
        MessageKind::PrintWriteChunk | MessageKind::MediaWriteChunk => matches!(
            response,
            MessageKind::MediaChunkAccepted | MessageKind::MediaRejected
        ),
        MessageKind::PrintWriteFinish | MessageKind::MediaWriteFinish => matches!(
            response,
            MessageKind::MediaFinished | MessageKind::MediaRejected
        ),
        _ => false,
    }
}

fn rejection_matches_request(request: MessageKind, body: BodyRef<'_>) -> bool {
    match body {
        BodyRef::CardResponse(CardResponseBody::Rejected { request_kind, .. }) => {
            request_kind == request
        }
        BodyRef::OutputReply(OutputReplyBody::Rejected { request_kind, .. }) => {
            request_kind == request.wire_value()
        }
        _ => true,
    }
}

fn sequence_check(last: u32, current: u32) -> Result<(), DeviceError> {
    if last == u32::MAX {
        return Err(DeviceError::SequenceExhausted);
    }
    if last == 0 {
        return if current == 1 {
            Ok(())
        } else {
            Err(DeviceError::SequenceSkipped)
        };
    }
    if current == last {
        return Err(DeviceError::SequenceReplay);
    }
    if current < last {
        return Err(DeviceError::SequenceRegression);
    }
    if current != last + 1 {
        return Err(DeviceError::SequenceSkipped);
    }
    Ok(())
}

/// One bounded input-transfer state owner.
pub struct InputTransfer {
    capability: Capability,
    source: Source,
    total_len: u32,
    next_offset: u32,
    complete: bool,
    finished: bool,
    terminated: bool,
}

impl InputTransfer {
    pub fn begin(capability: Capability, body: InputBody<'_>) -> Result<Self, DeviceError> {
        validate_input_begin(capability, body)?;
        let (source, total_len) = match body {
            InputBody::Begin {
                source, total_len, ..
            } => (source, total_len),
            InputBody::Chunk { .. } => return Err(DeviceError::UnexpectedFrame),
        };
        Ok(Self {
            capability,
            source,
            total_len,
            next_offset: 0,
            complete: false,
            finished: false,
            terminated: false,
        })
    }

    pub fn accept(&mut self, body: InputBody<'_>) -> Result<(), DeviceError> {
        self.require_live()?;
        if self.complete {
            return Err(self.terminate(DeviceError::UnexpectedFrame));
        }
        let (offset, final_chunk, chunk) = match body {
            InputBody::Chunk {
                offset,
                final_chunk,
                chunk,
            } => (offset, final_chunk, chunk),
            InputBody::Begin { .. } => return Err(self.terminate(DeviceError::UnexpectedFrame)),
        };
        if chunk.is_empty() {
            return Err(self.terminate(DeviceError::ChunkLengthZero));
        }
        if chunk.len() > crate::MAX_CHUNK_BYTES {
            return Err(self.terminate(DeviceError::ChunkLengthExceeded));
        }
        if offset != self.next_offset {
            return Err(self.terminate(DeviceError::OffsetMismatch));
        }
        let chunk_len = u32::try_from(chunk.len())
            .map_err(|_| self.terminate(DeviceError::TransferLengthExceeded))?;
        let end = offset
            .checked_add(chunk_len)
            .filter(|end| *end <= self.total_len)
            .ok_or_else(|| self.terminate(DeviceError::TransferLengthExceeded))?;
        let expected_final = end == self.total_len;
        if final_chunk != expected_final {
            return Err(self.terminate(DeviceError::FinalFlagMismatch));
        }
        self.next_offset = end;
        self.complete = expected_final;
        Ok(())
    }

    pub fn finish(&mut self) -> Result<(), DeviceError> {
        self.require_live()?;
        if self.finished {
            return Err(self.terminate(DeviceError::UnexpectedFrame));
        }
        if !self.complete || self.next_offset != self.total_len {
            return Err(self.terminate(DeviceError::TransferIncomplete));
        }
        self.finished = true;
        Ok(())
    }

    pub const fn capability(&self) -> Capability {
        self.capability
    }

    pub const fn source(&self) -> Source {
        self.source
    }

    pub const fn next_offset(&self) -> u32 {
        self.next_offset
    }

    fn require_live(&self) -> Result<(), DeviceError> {
        if self.terminated {
            Err(DeviceError::DecoderTerminated)
        } else {
            Ok(())
        }
    }

    fn terminate(&mut self, error: DeviceError) -> DeviceError {
        self.terminated = true;
        error
    }
}

/// One bounded output-transfer state owner.
pub struct OutputTransfer {
    capability: Capability,
    artifact: Artifact,
    total_len: u32,
    next_offset: u32,
    complete: bool,
    terminated: bool,
}

impl OutputTransfer {
    pub fn begin(capability: Capability, body: OutputBody<'_>) -> Result<Self, DeviceError> {
        validate_output_body(capability, body)?;
        let (artifact, total_len) = match body {
            OutputBody::WriteBegin {
                artifact,
                total_len,
                ..
            } => (artifact, total_len),
            _ => return Err(DeviceError::UnexpectedFrame),
        };
        if !matches!(
            capability,
            Capability::PrintOutput | Capability::MediaOutput
        ) {
            return Err(DeviceError::CapabilityMismatch);
        }
        Ok(Self {
            capability,
            artifact,
            total_len,
            next_offset: 0,
            complete: false,
            terminated: false,
        })
    }

    pub fn accept(&mut self, body: OutputBody<'_>) -> Result<(), DeviceError> {
        self.require_live()?;
        if self.complete {
            return Err(self.terminate(DeviceError::UnexpectedFrame));
        }
        if let Err(error) = validate_output_body(self.capability, body) {
            return Err(self.terminate(error));
        }
        let (offset, chunk) = match body {
            OutputBody::WriteChunk { offset, chunk } => (offset, chunk),
            _ => return Err(self.terminate(DeviceError::UnexpectedFrame)),
        };
        if offset != self.next_offset {
            return Err(self.terminate(DeviceError::OffsetMismatch));
        }
        let chunk_len = u32::try_from(chunk.len())
            .map_err(|_| self.terminate(DeviceError::TransferLengthExceeded))?;
        let end = offset
            .checked_add(chunk_len)
            .filter(|end| *end <= self.total_len)
            .ok_or_else(|| self.terminate(DeviceError::TransferLengthExceeded))?;
        self.next_offset = end;
        Ok(())
    }

    pub fn finish(&mut self, body: OutputBody<'_>) -> Result<(), DeviceError> {
        self.require_live()?;
        if self.complete {
            return Err(self.terminate(DeviceError::UnexpectedFrame));
        }
        if let Err(error) = validate_output_body(self.capability, body) {
            return Err(self.terminate(error));
        }
        let (artifact, total_len) = match body {
            OutputBody::WriteFinish {
                artifact,
                total_len,
            } => (artifact, total_len),
            _ => return Err(self.terminate(DeviceError::UnexpectedFrame)),
        };
        if artifact != self.artifact || total_len != self.total_len {
            return Err(self.terminate(DeviceError::ArtifactMismatch));
        }
        if self.next_offset != self.total_len {
            return Err(self.terminate(DeviceError::TransferIncomplete));
        }
        self.complete = true;
        Ok(())
    }

    pub const fn capability(&self) -> Capability {
        self.capability
    }

    pub const fn artifact(&self) -> Artifact {
        self.artifact
    }

    pub const fn next_offset(&self) -> u32 {
        self.next_offset
    }

    fn require_live(&self) -> Result<(), DeviceError> {
        if self.terminated {
            Err(DeviceError::DecoderTerminated)
        } else {
            Ok(())
        }
    }

    fn terminate(&mut self, error: DeviceError) -> DeviceError {
        self.terminated = true;
        error
    }
}
