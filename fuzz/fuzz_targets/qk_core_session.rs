#![no_main]

use libfuzzer_sys::fuzz_target;
use qk_core::fuzz::{fuzz_start_session, reset_wiped_bytes, wiped_bytes};
use qk_core::{
    CardPresence, CoreDeviceGrants, CoreError, CoreMode, CoreReceiveEvent, CoreSession, CoreState,
    Interruption, IoRejection, KeypadKey, MockCardSlot, MockDisplay, MockKeypad, Source,
};
use qk_ipc::{encode_frame, Direction, IpcError, MessageKind, HEADER_BYTES};

const MAX_PRESENTED_BYTES: usize = 4_096;
const ALL_KEYS: [KeypadKey; 19] = [
    KeypadKey::Seven,
    KeypadKey::EightUp,
    KeypadKey::Nine,
    KeypadKey::CeDelete,
    KeypadKey::CancelBack,
    KeypadKey::FourLeft,
    KeypadKey::Five,
    KeypadKey::SixRight,
    KeypadKey::Multiply,
    KeypadKey::Divide,
    KeypadKey::One,
    KeypadKey::TwoDown,
    KeypadKey::Three,
    KeypadKey::Minus,
    KeypadKey::Percent,
    KeypadKey::Zero,
    KeypadKey::Decimal,
    KeypadKey::Plus,
    KeypadKey::EqualsConfirmEnter,
];
const ALL_INTERRUPTS: [Interruption; 10] = [
    Interruption::Cancelled,
    Interruption::OperationFailed,
    Interruption::MediaRemoved,
    Interruption::CardRemoved,
    Interruption::SessionTimeout,
    Interruption::Shutdown,
    Interruption::Restart,
    Interruption::PowerLoss,
    Interruption::PeerLost,
    Interruption::CapabilityFailed,
];

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum OutcomeFact {
    Outbound(usize),
    Received(CoreReceiveEvent),
    Interrupted(Interruption),
    Card(CardPresence),
    Rejected(&'static str),
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct StepFact {
    outcome: OutcomeFact,
    state: CoreState,
    terminal_reason: Option<Interruption>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct RunFact {
    session_id: [u8; 16],
    next_session_id: [u8; 16],
    steps: Vec<StepFact>,
    wiped: usize,
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

fn interruption_name(reason: Interruption) -> &'static str {
    let name = match reason {
        Interruption::Cancelled => "Cancelled",
        Interruption::OperationFailed => "OperationFailed",
        Interruption::MediaRemoved => "MediaRemoved",
        Interruption::CardRemoved => "CardRemoved",
        Interruption::SessionTimeout => "SessionTimeout",
        Interruption::Shutdown => "Shutdown",
        Interruption::Restart => "Restart",
        Interruption::PowerLoss => "PowerLoss",
        Interruption::PeerLost => "PeerLost",
        Interruption::CapabilityFailed => "CapabilityFailed",
    };
    assert_eq!(reason.name(), name);
    assert_eq!(reason.to_string(), name);
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

fn grants_with_fault(selector: u8) -> CoreDeviceGrants {
    let mut display = MockDisplay::new();
    let mut keypad = MockKeypad::new();
    let mut card = MockCardSlot::new(CardPresence::Present);
    match selector % 3 {
        0 => display.inject_failure(),
        1 => keypad.inject_failure(),
        2 => card.inject_failure(),
        _ => unreachable!("modulo three is exhaustive"),
    }
    CoreDeviceGrants::validate(Some(display), Some(keypad), Some(card), false)
        .expect("complete fixed capability set")
}

fn mode(byte: u8) -> CoreMode {
    match byte % 3 {
        0 => CoreMode::Setup,
        1 => CoreMode::A1B,
        2 => CoreMode::Kit,
        _ => unreachable!("modulo three is exhaustive"),
    }
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

fn source_len(source: Source, byte: u8) -> u32 {
    match source {
        Source::CameraA1Candidate => 67,
        Source::CameraKitCandidate => 142,
        Source::CameraBbqrPsbt | Source::MediaPsbt => u32::from(byte % 63) + 1,
    }
}

fn key(byte: u8) -> KeypadKey {
    ALL_KEYS[usize::from(byte) % ALL_KEYS.len()]
}

fn interruption(byte: u8) -> Interruption {
    ALL_INTERRUPTS[usize::from(byte) % ALL_INTERRUPTS.len()]
}

fn id_from_frame(frame: &[u8]) -> [u8; 16] {
    let mut id = [0u8; 16];
    id.copy_from_slice(frame.get(8..24).expect("canonical QKIP header"));
    id
}

fn exchange_from_frame(frame: &[u8]) -> u32 {
    u32::from_le_bytes(
        frame
            .get(24..28)
            .expect("canonical QKIP exchange field")
            .try_into()
            .expect("four-byte exchange field"),
    )
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

fn record<T>(
    session: &CoreSession,
    result: Result<T, CoreError>,
    accepted: impl FnOnce(T) -> OutcomeFact,
) -> StepFact {
    let outcome = match result {
        Ok(value) => accepted(value),
        Err(error) => OutcomeFact::Rejected(core_name(error)),
    };
    StepFact {
        outcome,
        state: session.state(),
        terminal_reason: session.terminal_reason(),
    }
}

fn assert_terminal_absorption(session: &mut CoreSession) {
    assert!(matches!(
        session.state(),
        CoreState::Closed | CoreState::Terminated
    ));
    for error in [
        session.begin_ingress(Source::CameraA1Candidate).err(),
        session.request_next_chunk().err(),
        session.begin_close().err(),
        session.receive(&[], false).err(),
        session.connection_closed().err(),
        session.interrupt(Interruption::Shutdown).err(),
        session.handle_key(KeypadKey::One).err(),
        session.observe_card(CardPresence::Present).err(),
    ] {
        assert_eq!(error.map(core_name), Some("CoreTerminated"));
    }
}

fn assert_capability_boundaries(namespace: [u8; 12], selector: u8) {
    let missing = CoreDeviceGrants::validate(
        None,
        Some(MockKeypad::new()),
        Some(MockCardSlot::new(CardPresence::Present)),
        true,
    )
    .err()
    .expect("missing grant rejects");
    assert_eq!(core_name(missing), "CapabilitiesMissing");
    let unexpected = CoreDeviceGrants::validate(
        Some(MockDisplay::new()),
        Some(MockKeypad::new()),
        Some(MockCardSlot::new(CardPresence::Present)),
        true,
    )
    .err()
    .expect("unexpected grant rejects");
    assert_eq!(core_name(unexpected), "CapabilitiesUnexpected");

    match selector % 3 {
        0 => {
            let error = fuzz_start_session(namespace, 0, CoreMode::Setup, grants_with_fault(0))
                .err()
                .expect("opening display fault rejects");
            assert_eq!(core_name(error), "DisplayFailed");
        }
        1 => {
            let (mut session, open) =
                fuzz_start_session(namespace, 0, CoreMode::Setup, grants_with_fault(1))
                    .expect("keypad fault is deferred");
            let id = id_from_frame(open.frame_bytes());
            session
                .receive(&outer(id, 1, MessageKind::SessionReady, &[]), false)
                .expect("ready response");
            let error = session
                .handle_key(KeypadKey::One)
                .expect_err("injected keypad fault");
            assert_eq!(core_name(error), "KeypadFailed");
            assert_eq!(
                session.terminal_reason(),
                Some(Interruption::CapabilityFailed)
            );
            assert_terminal_absorption(&mut session);
        }
        2 => {
            let (mut session, open) =
                fuzz_start_session(namespace, 0, CoreMode::Setup, grants_with_fault(2))
                    .expect("card fault is deferred");
            let id = id_from_frame(open.frame_bytes());
            session
                .receive(&outer(id, 1, MessageKind::SessionReady, &[]), false)
                .expect("ready response");
            let error = session
                .observe_card(CardPresence::Present)
                .expect_err("injected card fault");
            assert_eq!(core_name(error), "CardFailed");
            assert_eq!(
                session.terminal_reason(),
                Some(Interruption::CapabilityFailed)
            );
            assert_terminal_absorption(&mut session);
        }
        _ => unreachable!("modulo three is exhaustive"),
    }

    let exhausted = fuzz_start_session(namespace, u32::MAX, CoreMode::Setup, grants())
        .err()
        .expect("maximum prior counter rejects");
    assert_eq!(core_name(exhausted), "SessionIdExhausted");
}

struct Harness {
    session: CoreSession,
    id: [u8; 16],
    pending_exchange: Option<u32>,
    pending_source: Option<Source>,
    total_len: u32,
    offset: u32,
}

impl Harness {
    fn new(namespace: [u8; 12], counter: u32, mode: CoreMode) -> (Self, [u8; 16]) {
        let (session, open) =
            fuzz_start_session(namespace, counter, mode, grants()).expect("session starts");
        let id = id_from_frame(open.frame_bytes());
        assert_eq!(id.get(..12), Some(namespace.as_slice()));
        assert_eq!(
            id.get(12..),
            Some(counter.wrapping_add(1).to_le_bytes().as_slice())
        );

        let (next_session, next_open) = fuzz_start_session(
            namespace,
            counter.checked_add(1).expect("bounded counter"),
            mode,
            grants(),
        )
        .expect("next deterministic session starts");
        let next_id = id_from_frame(next_open.frame_bytes());
        assert_ne!(id, next_id);
        drop(next_session);
        drop(next_open);
        drop(open);
        (
            Self {
                session,
                id,
                pending_exchange: Some(1),
                pending_source: None,
                total_len: 0,
                offset: 0,
            },
            next_id,
        )
    }

    fn begin(&mut self, chosen: Source) -> StepFact {
        let result = self.session.begin_ingress(chosen);
        if let Ok(outbound) = &result {
            self.pending_exchange = Some(exchange_from_frame(outbound.frame_bytes()));
            self.pending_source = Some(chosen);
        }
        record(&self.session, result, |outbound| {
            OutcomeFact::Outbound(outbound.len())
        })
    }

    fn read(&mut self) -> StepFact {
        let result = self.session.request_next_chunk();
        if let Ok(outbound) = &result {
            self.pending_exchange = Some(exchange_from_frame(outbound.frame_bytes()));
        }
        record(&self.session, result, |outbound| {
            OutcomeFact::Outbound(outbound.len())
        })
    }

    fn close(&mut self) -> StepFact {
        let result = self.session.begin_close();
        if let Ok(outbound) = &result {
            self.pending_exchange = Some(exchange_from_frame(outbound.frame_bytes()));
        }
        record(&self.session, result, |outbound| {
            OutcomeFact::Outbound(outbound.len())
        })
    }

    fn valid_response(&mut self, selector: u8) -> StepFact {
        let exchange = self.pending_exchange.unwrap_or(1);
        let frame = match self.session.state() {
            CoreState::Opening => outer(self.id, exchange, MessageKind::SessionReady, &[]),
            CoreState::IngressBeginPending => {
                let chosen = self.pending_source.unwrap_or(Source::CameraA1Candidate);
                self.total_len = source_len(chosen, selector);
                self.offset = 0;
                let mut body = vec![chosen.wire_value()];
                body.extend_from_slice(&self.total_len.to_le_bytes());
                outer(
                    self.id,
                    exchange,
                    MessageKind::OperationResponse,
                    &inner_success(1, &body),
                )
            }
            CoreState::IngressReadPending => {
                let remaining = self.total_len.saturating_sub(self.offset);
                let chunk_len = remaining.min(u32::from(selector % 31) + 1);
                let final_chunk = chunk_len == remaining;
                let mut body = Vec::with_capacity(9 + chunk_len as usize);
                body.extend_from_slice(&self.offset.to_le_bytes());
                body.extend_from_slice(&chunk_len.to_le_bytes());
                body.push(u8::from(final_chunk));
                body.resize(9 + chunk_len as usize, selector);
                let frame = outer(
                    self.id,
                    exchange,
                    MessageKind::OperationResponse,
                    &inner_success(2, &body),
                );
                self.offset = self.offset.saturating_add(chunk_len);
                frame
            }
            CoreState::Closing => outer(self.id, exchange, MessageKind::SessionClosed, &[]),
            _ => outer(self.id, exchange, MessageKind::SessionReady, &[]),
        };
        let result = self.session.receive(&frame, false);
        if result.is_ok() {
            self.pending_exchange = None;
        }
        record(&self.session, result, |outcome| {
            OutcomeFact::Received(outcome.event())
        })
    }

    fn hostile_response(&mut self, bytes: &[u8], ancillary: bool) -> StepFact {
        let result = self.session.receive(bytes, ancillary);
        record(&self.session, result, |outcome| {
            OutcomeFact::Received(outcome.event())
        })
    }

    fn interrupt(&mut self, reason: Interruption) -> StepFact {
        interruption_name(reason);
        let result = self.session.interrupt(reason);
        record(&self.session, result, OutcomeFact::Interrupted)
    }

    fn key(&mut self, key: KeypadKey) -> StepFact {
        let result = self.session.handle_key(key);
        record(&self.session, result, OutcomeFact::Interrupted)
    }

    fn card(&mut self, presence: CardPresence) -> StepFact {
        let result = self.session.observe_card(presence);
        record(&self.session, result, OutcomeFact::Card)
    }

    fn connection_closed(&mut self) -> StepFact {
        let result = self.session.connection_closed();
        record(&self.session, result, OutcomeFact::Interrupted)
    }
}

fn run(data: &[u8]) -> RunFact {
    reset_wiped_bytes();
    let namespace = [data.first().copied().unwrap_or(0x5a); 12];
    let counter = u32::from(data.get(1).copied().unwrap_or(0));
    assert_capability_boundaries(namespace, data.get(2).copied().unwrap_or(0));

    let (session_id, next_session_id, steps) = {
        let (mut harness, next_id) =
            Harness::new(namespace, counter, mode(data.get(2).copied().unwrap_or(0)));
        let mut steps = Vec::with_capacity(data.len().div_ceil(4) + 2);
        for command in data.chunks(4) {
            let action = command.first().copied().unwrap_or(0) % 11;
            let selector = command.get(1).copied().unwrap_or(0);
            let step = match action {
                0 => harness.begin(source(selector)),
                1 => harness.read(),
                2 => harness.valid_response(selector),
                3 => harness.close(),
                4 => harness.hostile_response(command, selector & 1 != 0),
                5 => harness.interrupt(interruption(selector)),
                6 => harness.key(key(selector)),
                7 => harness.card(if selector & 1 == 0 {
                    CardPresence::Present
                } else {
                    CardPresence::Absent
                }),
                8 => harness.connection_closed(),
                9 => {
                    let wrong_exchange = harness
                        .pending_exchange
                        .unwrap_or(1)
                        .wrapping_add(u32::from(selector) + 1);
                    let wrong = outer(harness.id, wrong_exchange, MessageKind::SessionReady, &[]);
                    harness.hostile_response(&wrong, false)
                }
                10 => harness.key(KeypadKey::One),
                _ => unreachable!("modulo eleven is exhaustive"),
            };
            if let Some(reason) = step.terminal_reason {
                interruption_name(reason);
            }
            steps.push(step);
            if matches!(
                harness.session.state(),
                CoreState::Closed | CoreState::Terminated
            ) {
                assert_terminal_absorption(&mut harness.session);
                break;
            }
        }
        if !matches!(
            harness.session.state(),
            CoreState::Closed | CoreState::Terminated
        ) {
            steps.push(harness.interrupt(Interruption::Shutdown));
        }
        assert_terminal_absorption(&mut harness.session);
        (harness.id, next_id, steps)
    };
    let wiped = wiped_bytes();
    assert!(wiped > 0);
    RunFact {
        session_id,
        next_session_id,
        steps,
        wiped,
    }
}

fuzz_target!(|data: &[u8]| {
    for reason in ALL_INTERRUPTS {
        interruption_name(reason);
    }
    let bounded = &data[..data.len().min(MAX_PRESENTED_BYTES)];
    assert_eq!(run(bounded), run(bounded));
});
