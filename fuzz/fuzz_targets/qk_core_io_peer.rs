#![no_main]

use libfuzzer_sys::fuzz_target;
use qk_core::fuzz::{fuzz_start_session, parse_response, ExpectedResponse, Response};
use qk_core::{
    CardPresence, CoreDeviceGrants, CoreError, CoreMode, CoreReceiveEvent, CoreSession, CoreState,
    IoRejection, MockCardSlot, MockDisplay, MockKeypad, Source,
};
use qk_ipc::{encode_frame, Direction, IpcError, MessageKind, HEADER_BYTES};

const MAX_PRESENTED_BYTES: usize = 16_384;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum ParsedFact {
    Begin {
        source: Source,
        total_len: u32,
    },
    Read {
        offset: u32,
        chunk_len: usize,
        final_chunk: bool,
    },
    Rejected(&'static str),
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct RunFact {
    parsed: ParsedFact,
    transfer_source: Source,
    transfer_len: usize,
    outer_result: Result<CoreReceiveEvent, &'static str>,
    outer_state: CoreState,
}

fn ipc_name(error: IpcError) -> &'static str {
    let name = match error {
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
    };
    assert_eq!(error.to_string(), name);
    name
}

fn io_name(error: IoRejection) -> &'static str {
    let name = match error {
        IoRejection::InnerHeaderTruncated => "InnerHeaderTruncated",
        IoRejection::InnerVersionMismatch => "InnerVersionMismatch",
        IoRejection::RequestReservedNonZero => "RequestReservedNonZero",
        IoRejection::OperationOutOfRange => "OperationOutOfRange",
        IoRejection::BodyLengthExceeded => "BodyLengthExceeded",
        IoRejection::BodyTruncated => "BodyTruncated",
        IoRejection::TrailingByte => "TrailingByte",
        IoRejection::UnexpectedBoundary => "UnexpectedBoundary",
        IoRejection::BoundaryMissing => "BoundaryMissing",
        IoRejection::SourceKindMismatch => "SourceKindMismatch",
        IoRejection::SourceAlreadyUsed => "SourceAlreadyUsed",
        IoRejection::WriterKindMismatch => "WriterKindMismatch",
        IoRejection::WriterAlreadyUsed => "WriterAlreadyUsed",
        IoRejection::ActiveTransfer => "ActiveTransfer",
        IoRejection::NoActiveTransfer => "NoActiveTransfer",
        IoRejection::WrongTransferDirection => "WrongTransferDirection",
        IoRejection::SourceLengthMismatch => "SourceLengthMismatch",
        IoRejection::DeclaredLengthZero => "DeclaredLengthZero",
        IoRejection::DeclaredLengthExceeded => "DeclaredLengthExceeded",
        IoRejection::OffsetMismatch => "OffsetMismatch",
        IoRejection::ChunkLengthZero => "ChunkLengthZero",
        IoRejection::ChunkLengthExceeded => "ChunkLengthExceeded",
        IoRejection::TransferLengthExceeded => "TransferLengthExceeded",
        IoRejection::TransferIncomplete => "TransferIncomplete",
        IoRejection::SourceOutOfRange => "SourceOutOfRange",
        IoRejection::SinkOutOfRange => "SinkOutOfRange",
        IoRejection::ArtifactOutOfRange => "ArtifactOutOfRange",
        IoRejection::SinkArtifactMismatch => "SinkArtifactMismatch",
        IoRejection::InvalidFilename => "InvalidFilename",
        IoRejection::InvalidBbqrPartLength => "InvalidBbqrPartLength",
        IoRejection::AllocationFailed => "AllocationFailed",
        IoRejection::SourceReadFailed => "SourceReadFailed",
        IoRejection::OutputCollision => "OutputCollision",
        IoRejection::OutputCreateFailed => "OutputCreateFailed",
        IoRejection::OutputWriteFailed => "OutputWriteFailed",
        IoRejection::OutputSyncFailed => "OutputSyncFailed",
        IoRejection::OutputCloseFailed => "OutputCloseFailed",
        IoRejection::OutputReopenFailed => "OutputReopenFailed",
        IoRejection::OutputReadbackMismatch => "OutputReadbackMismatch",
        IoRejection::OutputRenameFailed => "OutputRenameFailed",
        IoRejection::PrintFailed => "PrintFailed",
        IoRejection::EmptyPayload => "EmptyPayload",
        IoRejection::PayloadTooLarge => "PayloadTooLarge",
        IoRejection::InvalidNonFinalPartLength => "InvalidNonFinalPartLength",
        IoRejection::TooManyParts => "TooManyParts",
        IoRejection::PartIndexOutOfRange => "PartIndexOutOfRange",
        IoRejection::FrameTooShort => "FrameTooShort",
        IoRejection::FrameTooLarge => "FrameTooLarge",
        IoRejection::InvalidMagic => "InvalidMagic",
        IoRejection::UnsupportedEncoding => "UnsupportedEncoding",
        IoRejection::UnsupportedFileType => "UnsupportedFileType",
        IoRejection::InvalidDeclaredPartCount => "InvalidDeclaredPartCount",
        IoRejection::DeclaredPartCountExceeded => "DeclaredPartCountExceeded",
        IoRejection::InvalidPartIndex => "InvalidPartIndex",
        IoRejection::EmptyPart => "EmptyPart",
        IoRejection::Base32PaddingForbidden => "Base32PaddingForbidden",
        IoRejection::MalformedBase32Symbol => "MalformedBase32Symbol",
        IoRejection::NonCanonicalBase32Length => "NonCanonicalBase32Length",
        IoRejection::NonCanonicalBase32Padding => "NonCanonicalBase32Padding",
        IoRejection::NonFinalPartLengthNotMultipleOfFive => "NonFinalPartLengthNotMultipleOfFive",
        IoRejection::StreamEncodingMismatch => "StreamEncodingMismatch",
        IoRejection::StreamFileTypeMismatch => "StreamFileTypeMismatch",
        IoRejection::StreamPartCountMismatch => "StreamPartCountMismatch",
        IoRejection::NonUniformPartLength => "NonUniformPartLength",
        IoRejection::FinalPartTooLarge => "FinalPartTooLarge",
        IoRejection::TotalDecodedSizeExceeded => "TotalDecodedSizeExceeded",
        IoRejection::ConflictingDuplicate => "ConflictingDuplicate",
        IoRejection::DuplicateWorkExceeded => "DuplicateWorkExceeded",
        IoRejection::SubmissionWorkExceeded => "SubmissionWorkExceeded",
        IoRejection::Incomplete => "Incomplete",
        IoRejection::AlreadyComplete => "AlreadyComplete",
    };
    assert_eq!(error.to_string(), name);
    assert_ne!(error.status_code(), 0);
    name
}

fn core_name(error: CoreError) -> &'static str {
    let name = match error {
        CoreError::CoreTerminated => "CoreTerminated",
        CoreError::InvalidTransition => "InvalidTransition",
        CoreError::SessionIdUnavailable => "SessionIdUnavailable",
        CoreError::SessionIdExhausted => "SessionIdExhausted",
        CoreError::CapabilitiesMissing => "CapabilitiesMissing",
        CoreError::CapabilitiesUnexpected => "CapabilitiesUnexpected",
        CoreError::NoActiveFlow => "NoActiveFlow",
        CoreError::ResponseHeaderTruncated => "ResponseHeaderTruncated",
        CoreError::ResponseVersionMismatch => "ResponseVersionMismatch",
        CoreError::ResponseOpcodeMismatch => "ResponseOpcodeMismatch",
        CoreError::ResponseBodyLengthExceeded => "ResponseBodyLengthExceeded",
        CoreError::ResponseBodyTruncated => "ResponseBodyTruncated",
        CoreError::ResponseTrailingByte => "ResponseTrailingByte",
        CoreError::ResponseStatusOutOfRange => "ResponseStatusOutOfRange",
        CoreError::ResponseErrorBodyNonEmpty => "ResponseErrorBodyNonEmpty",
        CoreError::ResponseSourceOutOfRange => "ResponseSourceOutOfRange",
        CoreError::ResponseSourceMismatch => "ResponseSourceMismatch",
        CoreError::ResponseTotalLengthMismatch => "ResponseTotalLengthMismatch",
        CoreError::ResponseOffsetMismatch => "ResponseOffsetMismatch",
        CoreError::ResponseChunkLengthZero => "ResponseChunkLengthZero",
        CoreError::ResponseChunkLengthExceeded => "ResponseChunkLengthExceeded",
        CoreError::ResponseTransferLengthExceeded => "ResponseTransferLengthExceeded",
        CoreError::ResponseFinalOutOfRange => "ResponseFinalOutOfRange",
        CoreError::ResponseFinalMismatch => "ResponseFinalMismatch",
        CoreError::AllocationFailed => "AllocationFailed",
        CoreError::DisplayFailed => "DisplayFailed",
        CoreError::KeypadFailed => "KeypadFailed",
        CoreError::CardFailed => "CardFailed",
        CoreError::Ipc(inner) => ipc_name(inner),
        CoreError::IoRejected(inner) => io_name(inner),
    };
    assert_eq!(error.to_string(), name);
    name
}

fn grants() -> CoreDeviceGrants {
    CoreDeviceGrants::validate(
        Some(MockDisplay::new()),
        Some(MockKeypad::new()),
        Some(MockCardSlot::new(CardPresence::Present)),
        false,
    )
    .expect("complete fixed capability set")
}

fn source(byte: u8) -> Source {
    match byte % 4 {
        0 => Source::CameraA1Candidate,
        1 => Source::CameraKitCandidate,
        2 => Source::CameraBbqrPsbt,
        3 => Source::MediaPsbt,
        _ => unreachable!("modulo four is exhaustive"),
    }
}

fn source_len(source: Source, selector: u8) -> usize {
    match source {
        Source::CameraA1Candidate => 67,
        Source::CameraKitCandidate => 142,
        Source::CameraBbqrPsbt | Source::MediaPsbt => usize::from(selector % 191) + 1,
    }
}

fn mode(byte: u8) -> CoreMode {
    match byte % 3 {
        0 => CoreMode::Setup,
        1 => CoreMode::A1B,
        2 => CoreMode::Kit,
        _ => unreachable!("modulo three is exhaustive"),
    }
}

fn session_id(open: &[u8]) -> [u8; 16] {
    let mut id = [0u8; 16];
    id.copy_from_slice(open.get(8..24).expect("canonical QKIP header"));
    id
}

fn outer(id: [u8; 16], exchange: u32, kind: MessageKind, payload: &[u8]) -> Vec<u8> {
    let mut output = vec![0u8; HEADER_BYTES + payload.len()];
    let written = encode_frame(
        Direction::IoToCore,
        kind,
        id,
        exchange,
        payload,
        &mut output,
    )
    .expect("generated peer frame is canonical");
    assert_eq!(written, output.len());
    output
}

fn inner_success(opcode: u8, body: &[u8]) -> Vec<u8> {
    let mut payload = Vec::with_capacity(8 + body.len());
    payload.extend_from_slice(&[1, opcode, 0, 0]);
    payload.extend_from_slice(&(body.len() as u32).to_le_bytes());
    payload.extend_from_slice(body);
    payload
}

fn receive_fragmented(
    session: &mut CoreSession,
    frame: &[u8],
    selector: u8,
) -> Result<CoreReceiveEvent, CoreError> {
    let split = if frame.len() <= 1 {
        frame.len()
    } else {
        usize::from(selector) % frame.len()
    };
    if split != 0 && split < frame.len() {
        let first = session.receive(&frame[..split], false)?;
        assert_eq!(first.consumed(), split);
        assert_eq!(first.event(), CoreReceiveEvent::NeedMore);
    }
    let remaining = frame.get(split..).expect("split is in bounds");
    let second = session.receive(remaining, false)?;
    assert_eq!(second.consumed(), remaining.len());
    Ok(second.event())
}

fn direct_fact(data: &[u8]) -> ParsedFact {
    let selector = data.first().copied().unwrap_or(0);
    let expected = if selector & 1 == 0 {
        ExpectedResponse::IngressBegin {
            source: source(selector >> 1),
        }
    } else {
        ExpectedResponse::IngressRead {
            expected_offset: u32::from(data.get(1).copied().unwrap_or(0)),
            total_len: u32::from(data.get(2).copied().unwrap_or(1)).max(1),
        }
    };
    match parse_response(data, expected) {
        Ok(Response::IngressBegin { source, total_len }) => ParsedFact::Begin { source, total_len },
        Ok(Response::IngressRead {
            offset,
            final_chunk,
            chunk,
        }) => ParsedFact::Read {
            offset,
            chunk_len: chunk.len(),
            final_chunk,
        },
        Err(error) => ParsedFact::Rejected(core_name(error)),
    }
}

fn complete_valid_transfer(data: &[u8]) -> (Source, usize) {
    let selector = data.first().copied().unwrap_or(0);
    let chosen = source(selector);
    let total_len = source_len(chosen, data.get(1).copied().unwrap_or(0));
    let namespace = [data.get(2).copied().unwrap_or(0x44); 12];
    let (mut session, open) = fuzz_start_session(namespace, 0, mode(selector), grants())
        .expect("deterministic session starts");
    let id = session_id(open.frame_bytes());

    assert_eq!(
        receive_fragmented(
            &mut session,
            &outer(id, 1, MessageKind::SessionReady, &[]),
            data.get(3).copied().unwrap_or(0)
        )
        .expect("generated ready response"),
        CoreReceiveEvent::SessionReady
    );
    let begin = session
        .begin_ingress(chosen)
        .expect("ready state accepts ingress begin");
    assert!(!begin.is_empty());
    let mut begin_body = vec![chosen.wire_value()];
    begin_body.extend_from_slice(&(total_len as u32).to_le_bytes());
    let begin_response = outer(
        id,
        2,
        MessageKind::OperationResponse,
        &inner_success(1, &begin_body),
    );
    assert_eq!(
        receive_fragmented(
            &mut session,
            &begin_response,
            data.get(4).copied().unwrap_or(0)
        )
        .expect("generated begin response"),
        CoreReceiveEvent::IngressBegan {
            source: chosen,
            total_len: total_len as u32,
        }
    );

    let read = session
        .request_next_chunk()
        .expect("active transfer accepts exact-offset read");
    assert!(!read.is_empty());
    let mut chunk = Vec::with_capacity(total_len);
    for index in 0..total_len {
        let pattern = data
            .get(5 + (index % data.len().max(1)))
            .copied()
            .unwrap_or(index as u8);
        chunk.push(pattern);
    }
    let mut read_body = Vec::with_capacity(9 + chunk.len());
    read_body.extend_from_slice(&0u32.to_le_bytes());
    read_body.extend_from_slice(&(chunk.len() as u32).to_le_bytes());
    read_body.push(1);
    read_body.extend_from_slice(&chunk);
    let read_response = outer(
        id,
        3,
        MessageKind::OperationResponse,
        &inner_success(2, &read_body),
    );
    let event = receive_fragmented(
        &mut session,
        &read_response,
        data.get(5).copied().unwrap_or(0),
    )
    .expect("generated read response");
    assert_eq!(
        event,
        CoreReceiveEvent::IngressChunk {
            offset: 0,
            chunk_len: total_len as u32,
            final_chunk: true,
        }
    );
    let complete = session.completed_ingress().expect("sealed hostile bytes");
    assert_eq!(complete.source(), chosen);
    assert_eq!(complete.fuzz_bytes(), chunk);

    let close = session.begin_close().expect("completed ingress can close");
    assert!(!close.is_empty());
    assert_eq!(
        receive_fragmented(
            &mut session,
            &outer(id, 4, MessageKind::SessionClosed, &[]),
            data.get(6).copied().unwrap_or(0)
        )
        .expect("generated close response"),
        CoreReceiveEvent::SessionClosed
    );
    assert_eq!(session.state(), CoreState::Closed);
    (chosen, total_len)
}

fn hostile_outer(data: &[u8]) -> (Result<CoreReceiveEvent, &'static str>, CoreState) {
    let selector = data.first().copied().unwrap_or(0);
    let namespace = [data.get(1).copied().unwrap_or(0x81); 12];
    let (mut session, open) =
        fuzz_start_session(namespace, 7, mode(selector), grants()).expect("session starts");
    let id = session_id(open.frame_bytes());
    let ready = outer(id, 1, MessageKind::SessionReady, &[]);
    let result = match selector % 6 {
        0 => session.receive(data, false),
        1 => session.receive(&ready, true),
        2 => {
            let mut wrong = id;
            wrong[0] ^= 1;
            session.receive(&outer(wrong, 1, MessageKind::SessionReady, &[]), false)
        }
        3 => session.receive(&outer(id, 2, MessageKind::SessionReady, &[]), false),
        4 => {
            let mut coalesced = ready.clone();
            coalesced.extend_from_slice(&ready);
            let first = session
                .receive(&coalesced, false)
                .expect("first coalesced frame is ready");
            assert_eq!(first.consumed(), ready.len());
            assert_eq!(first.event(), CoreReceiveEvent::SessionReady);
            session.receive(
                coalesced.get(first.consumed()..).expect("remainder exists"),
                false,
            )
        }
        5 => {
            let split = usize::from(data.get(2).copied().unwrap_or(1)) % ready.len();
            if split == 0 {
                session.receive(&ready, false)
            } else {
                let first = session.receive(&ready[..split], false);
                assert_eq!(
                    first.as_ref().map(CoreReceiveOutcomeExt::event_copy),
                    Ok(CoreReceiveEvent::NeedMore)
                );
                session.receive(&ready[split..], false)
            }
        }
        _ => unreachable!("modulo six is exhaustive"),
    };
    let fact = match result {
        Ok(outcome) => Ok(outcome.event()),
        Err(error) => Err(core_name(error)),
    };
    (fact, session.state())
}

trait CoreReceiveOutcomeExt {
    fn event_copy(&self) -> CoreReceiveEvent;
}

impl CoreReceiveOutcomeExt for qk_core::CoreReceiveOutcome {
    fn event_copy(&self) -> CoreReceiveEvent {
        self.event()
    }
}

fn run(data: &[u8]) -> RunFact {
    let parsed = direct_fact(data);
    let (transfer_source, transfer_len) = complete_valid_transfer(data);
    let (outer_result, outer_state) = hostile_outer(data);
    RunFact {
        parsed,
        transfer_source,
        transfer_len,
        outer_result,
        outer_state,
    }
}

fuzz_target!(|data: &[u8]| {
    let bounded = &data[..data.len().min(MAX_PRESENTED_BYTES)];
    assert_eq!(run(bounded), run(bounded));
});
