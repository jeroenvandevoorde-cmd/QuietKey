//! Pure sequence, request/response, and transfer state owners.

use crate::{
    encode_frame, Artifact, BodyRef, Capability, CardResponseBody, DeviceError, InputBody,
    MessageKind, OutputBody, OutputReplyBody, ReceivedFrame, Source,
};

/// Immutable outbound header facts produced only by a valid transition.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct OutboundFrame {
    capability: Capability,
    kind: MessageKind,
    sequence: u32,
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
    outstanding: Option<(u32, MessageKind)>,
    terminated: bool,
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
        let sequence = match self.next_sequence {
            Some(sequence) => sequence,
            None => return Err(self.terminate(DeviceError::SequenceExhausted)),
        };
        self.outstanding = Some((sequence, kind));
        Ok(OutboundFrame {
            capability: self.request_capability,
            kind,
            sequence,
        })
    }

    /// Accept the sole expected response. Every rejection latches terminal.
    pub fn accept_response(&mut self, frame: &ReceivedFrame) -> Result<(), DeviceError> {
        self.require_live()?;
        let header = frame.header();
        if header.capability() != self.response_capability {
            return Err(self.terminate(DeviceError::CapabilityMismatch));
        }
        let (sequence, request_kind) = match self.outstanding {
            Some(value) => value,
            None => return Err(self.terminate(DeviceError::NoOutstandingExchange)),
        };
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
    terminated: bool,
}

impl InputTransfer {
    pub fn begin(capability: Capability, body: InputBody<'_>) -> Result<Self, DeviceError> {
        let (source, total_len) = match body {
            InputBody::Begin {
                source, total_len, ..
            } => (source, total_len),
            InputBody::Chunk { .. } => return Err(DeviceError::UnexpectedFrame),
        };
        let valid = match capability {
            Capability::CameraInput => {
                matches!(source, Source::CameraA1Candidate | Source::CameraBbqrPsbt)
            }
            Capability::MediaInput => source == Source::MediaPsbt,
            _ => false,
        };
        if !valid {
            return Err(DeviceError::SourceMismatch);
        }
        Ok(Self {
            capability,
            source,
            total_len,
            next_offset: 0,
            complete: false,
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
        if !self.complete || self.next_offset != self.total_len {
            return Err(self.terminate(DeviceError::TransferIncomplete));
        }
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
