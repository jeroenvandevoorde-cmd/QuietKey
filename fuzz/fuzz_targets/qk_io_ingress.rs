#![no_main]

use libfuzzer_sys::fuzz_target;
use qk_bbqr::{BbqrFileType, Reassembler, MAX_TOTAL_DECODED_BYTES};
use qk_io::{
    reset_wiped_bytes, wiped_bytes, BrokerError, BrokerSession, BrokerState, InnerError, MockInput,
    Operation, ReplyStatus, Source, A1_CANDIDATE_BYTES, INNER_HEADER_BYTES, INNER_VERSION,
    KIT_CANDIDATE_BYTES, MAX_CHUNK_BYTES, MAX_INNER_BODY_BYTES, MAX_TRANSFER_BYTES,
};
use qk_ipc::{CoreEvent, CoreProtocol, OutboundFrame, ReceivedFrame, StreamDecoder, HEADER_BYTES};

const MAX_PRESENTED_BYTES: usize = 16_384;
const SESSION_ID: [u8; 16] = *b"qk-io-fuzz-ingrs";
const BBQR_MAX_FRAME_BYTES: usize = 4_296;
const BBQR_MAX_SUBMISSIONS: usize = 512;
const BASE32: &[u8; 32] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
const BBQR_NAMES: [&str; 30] = [
    "EmptyPayload",
    "PayloadTooLarge",
    "InvalidNonFinalPartLength",
    "TooManyParts",
    "PartIndexOutOfRange",
    "FrameTooShort",
    "FrameTooLarge",
    "InvalidMagic",
    "UnsupportedEncoding",
    "UnsupportedFileType",
    "InvalidDeclaredPartCount",
    "DeclaredPartCountExceeded",
    "InvalidPartIndex",
    "EmptyPart",
    "Base32PaddingForbidden",
    "MalformedBase32Symbol",
    "NonCanonicalBase32Length",
    "NonCanonicalBase32Padding",
    "NonFinalPartLengthNotMultipleOfFive",
    "StreamEncodingMismatch",
    "StreamFileTypeMismatch",
    "StreamPartCountMismatch",
    "NonUniformPartLength",
    "FinalPartTooLarge",
    "TotalDecodedSizeExceeded",
    "ConflictingDuplicate",
    "DuplicateWorkExceeded",
    "SubmissionWorkExceeded",
    "Incomplete",
    "AlreadyComplete",
];

#[derive(Clone, Debug, Eq, PartialEq)]
struct Step {
    opcode: u8,
    status: u16,
    error: Option<&'static str>,
    body: Vec<u8>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct CaseSummary {
    replies: Vec<Vec<u8>>,
    steps: Vec<Step>,
    output: Vec<u8>,
    final_state: BrokerState,
    post_terminal: &'static str,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct ExpectedError {
    status: u16,
    name: &'static str,
}

#[derive(Clone, Debug, Eq, PartialEq)]
enum Expected {
    Accepted(Vec<u8>),
    Rejected(ExpectedError),
}

struct Harness {
    core: CoreProtocol,
    broker: BrokerSession,
    next_exchange: u32,
    replies: Vec<Vec<u8>>,
}

impl Harness {
    fn open() -> Self {
        let mut core = CoreProtocol::new(SESSION_ID);
        let mut broker = BrokerSession::new();
        let request = receive(core.begin().expect("opening transition"), &[]);
        let reply = broker.accept(&request, None, None).expect("opening reply");
        assert_eq!(reply.status(), ReplyStatus::Control);
        let wire = reply.frame_bytes().to_vec();
        assert_reply_wire(&wire, 0x0101, 1, &[]);
        let received = decode(&wire);
        assert_eq!(core.accept(&received), Ok(CoreEvent::SessionReady));
        assert_eq!(broker.state(), BrokerState::Idle);
        Self {
            core,
            broker,
            next_exchange: 2,
            replies: vec![wire],
        }
    }

    fn exchange(&mut self, request_payload: &[u8], input: Option<&mut MockInput>) -> Step {
        let request = receive(
            self.core.request().expect("operation transition"),
            request_payload,
        );
        let reply = self
            .broker
            .accept(&request, input, None)
            .expect("inner request always has one reply");
        let reply_status = reply.status();
        let wire = reply.frame_bytes().to_vec();
        let received = decode(&wire);
        let payload = received.payload().to_vec();
        assert_reply_wire(&wire, 0x0102, self.next_exchange, &payload);
        self.next_exchange += 1;
        assert_eq!(
            self.core.accept(&received),
            Ok(CoreEvent::OperationResponse)
        );
        self.replies.push(wire);
        parse_step(reply_status, &payload)
    }

    fn request_frame(&mut self, payload: &[u8]) -> ReceivedFrame {
        receive(
            self.core.request().expect("post-rejection transition"),
            payload,
        )
    }
}

fn receive(outbound: OutboundFrame, payload: &[u8]) -> ReceivedFrame {
    let mut bytes = vec![0xa5; HEADER_BYTES + payload.len()];
    let length = outbound
        .encode(payload, &mut bytes)
        .expect("valid QKIP outbound");
    assert_eq!(length, bytes.len());
    decode(&bytes)
}

fn decode(bytes: &[u8]) -> ReceivedFrame {
    let mut decoder = StreamDecoder::new();
    let outcome = decoder
        .ingest(bytes, false)
        .expect("valid QKIP stream frame");
    assert_eq!(outcome.consumed(), bytes.len());
    assert!(outcome.frame_ready());
    decoder.take_frame().expect("complete QKIP frame")
}

fn assert_reply_wire(bytes: &[u8], kind: u16, exchange: u32, payload: &[u8]) {
    assert_eq!(bytes.len(), HEADER_BYTES + payload.len());
    assert_eq!(&bytes[..4], b"QKIP");
    assert_eq!(bytes[4], 1);
    assert_eq!(bytes[5], 2);
    assert_eq!(u16::from_le_bytes([bytes[6], bytes[7]]), kind);
    assert_eq!(&bytes[8..24], &SESSION_ID);
    assert_eq!(
        u32::from_le_bytes(bytes[24..28].try_into().expect("exchange id")),
        exchange
    );
    assert_eq!(
        u32::from_le_bytes(bytes[28..32].try_into().expect("payload length")) as usize,
        payload.len()
    );
    assert_eq!(&bytes[HEADER_BYTES..], payload);
}

fn parse_step(reply_status: ReplyStatus, payload: &[u8]) -> Step {
    assert!(payload.len() >= INNER_HEADER_BYTES);
    assert_eq!(payload[0], INNER_VERSION);
    let opcode = payload[1];
    let status = u16::from_le_bytes([payload[2], payload[3]]);
    let body_len =
        u32::from_le_bytes(payload[4..8].try_into().expect("inner body length")) as usize;
    assert_eq!(payload.len(), INNER_HEADER_BYTES + body_len);
    let body = payload[INNER_HEADER_BYTES..].to_vec();
    let error = match reply_status {
        ReplyStatus::Success(operation) => {
            assert_eq!(opcode, operation.wire_value());
            assert_eq!(status, 0);
            None
        }
        ReplyStatus::Rejected {
            opcode: rejected_opcode,
            error,
        } => {
            assert_eq!(opcode, rejected_opcode);
            assert_eq!(status, error.status_code());
            assert!(body.is_empty());
            Some(assert_named_inner(error))
        }
        ReplyStatus::Control => panic!("operation cannot return a control reply"),
    };
    Step {
        opcode,
        status,
        error,
        body,
    }
}

fn assert_named_inner(error: InnerError) -> &'static str {
    let name = match error {
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
        InnerError::Bbqr(_) => {
            let index = error
                .status_code()
                .checked_sub(0x0101)
                .map(usize::from)
                .expect("BBQr status base");
            *BBQR_NAMES.get(index).expect("registered BBQr status")
        }
    };
    assert_eq!(error.to_string(), name);
    name
}

fn assert_named_broker(error: BrokerError) -> &'static str {
    let name = match error {
        BrokerError::BrokerTerminated => "BrokerTerminated",
        BrokerError::CloseWithActiveTransfer => "CloseWithActiveTransfer",
        BrokerError::Inner(inner) => assert_named_inner(inner),
        BrokerError::Ipc(ipc) => {
            let name = ipc.to_string();
            assert!(!name.is_empty());
            return "Ipc";
        }
    };
    assert_eq!(error.to_string(), name);
    name
}

fn request(operation: Operation, body: &[u8]) -> Vec<u8> {
    let mut bytes = Vec::with_capacity(INNER_HEADER_BYTES + body.len());
    bytes.extend_from_slice(&[INNER_VERSION, operation.wire_value(), 0, 0]);
    bytes.extend_from_slice(&(body.len() as u32).to_le_bytes());
    bytes.extend_from_slice(body);
    bytes
}

fn ingress_begin(source: Source) -> Vec<u8> {
    request(Operation::IngressBegin, &[source.wire_value(), 0, 0])
}

fn ingress_read(offset: usize) -> Vec<u8> {
    request(Operation::IngressRead, &(offset as u32).to_le_bytes())
}

fn expected_error(error: InnerError) -> ExpectedError {
    ExpectedError {
        status: error.status_code(),
        name: assert_named_inner(error),
    }
}

fn source_from_byte(byte: u8) -> Source {
    match byte % 4 {
        0 => Source::CameraA1Candidate,
        1 => Source::CameraKitCandidate,
        2 => Source::CameraBbqrPsbt,
        3 => Source::MediaPsbt,
        _ => unreachable!("modulo four is exhaustive"),
    }
}

fn source_from_tag(tag: u8) -> Result<Source, InnerError> {
    match tag {
        1 => Ok(Source::CameraA1Candidate),
        2 => Ok(Source::CameraKitCandidate),
        3 => Ok(Source::CameraBbqrPsbt),
        4 => Ok(Source::MediaPsbt),
        _ => Err(InnerError::SourceOutOfRange),
    }
}

fn reference_request(bytes: &[u8], boundary_source: Source, raw: &[u8]) -> Expected {
    if bytes.len() < INNER_HEADER_BYTES {
        return Expected::Rejected(expected_error(InnerError::InnerHeaderTruncated));
    }
    if bytes[0] != INNER_VERSION {
        return Expected::Rejected(expected_error(InnerError::InnerVersionMismatch));
    }
    if bytes[2] != 0 || bytes[3] != 0 {
        return Expected::Rejected(expected_error(InnerError::RequestReservedNonZero));
    }
    if bytes[1] != Operation::IngressBegin.wire_value() {
        return Expected::Rejected(expected_error(InnerError::OperationOutOfRange));
    }
    let body_len =
        u32::from_le_bytes(bytes[4..8].try_into().expect("request body length")) as usize;
    if body_len > MAX_INNER_BODY_BYTES {
        return Expected::Rejected(expected_error(InnerError::BodyLengthExceeded));
    }
    let complete = INNER_HEADER_BYTES + body_len;
    if bytes.len() < complete {
        return Expected::Rejected(expected_error(InnerError::BodyTruncated));
    }
    if bytes.len() > complete {
        return Expected::Rejected(expected_error(InnerError::TrailingByte));
    }
    let body = &bytes[INNER_HEADER_BYTES..];
    if body.len() < 3 {
        return Expected::Rejected(expected_error(InnerError::BodyTruncated));
    }
    let source = match source_from_tag(body[0]) {
        Ok(source) => source,
        Err(error) => return Expected::Rejected(expected_error(error)),
    };
    let aux_len = usize::from(u16::from_le_bytes([body[1], body[2]]));
    let expected_body = 3usize.saturating_add(aux_len);
    if body.len() < expected_body {
        return Expected::Rejected(expected_error(InnerError::BodyTruncated));
    }
    if body.len() > expected_body || aux_len != 0 {
        return Expected::Rejected(expected_error(InnerError::TrailingByte));
    }
    if source != boundary_source {
        return Expected::Rejected(expected_error(InnerError::SourceKindMismatch));
    }
    reference_source(source, raw)
}

fn reference_source(source: Source, raw: &[u8]) -> Expected {
    match source {
        Source::CameraA1Candidate => {
            if raw.len() == A1_CANDIDATE_BYTES {
                Expected::Accepted(raw.to_vec())
            } else {
                Expected::Rejected(expected_error(InnerError::SourceLengthMismatch))
            }
        }
        Source::CameraKitCandidate => {
            if raw.len() == KIT_CANDIDATE_BYTES {
                Expected::Accepted(raw.to_vec())
            } else {
                Expected::Rejected(expected_error(InnerError::SourceLengthMismatch))
            }
        }
        Source::MediaPsbt => reference_media(raw),
        Source::CameraBbqrPsbt => reference_bbqr(raw),
    }
}

fn reference_media(raw: &[u8]) -> Expected {
    let Some(&name_len) = raw.first() else {
        return Expected::Rejected(expected_error(InnerError::SourceLengthMismatch));
    };
    let name_len = usize::from(name_len);
    if !(1..=64).contains(&name_len) {
        return Expected::Rejected(expected_error(InnerError::InvalidFilename));
    }
    let data_length_offset = 1 + name_len;
    let data_offset = data_length_offset + 4;
    if raw.len() < data_offset {
        return Expected::Rejected(expected_error(InnerError::SourceLengthMismatch));
    }
    let name = &raw[1..data_length_offset];
    let valid_name = name.ends_with(b".psbt")
        && name.iter().all(|byte| {
            byte.is_ascii_lowercase() || byte.is_ascii_digit() || matches!(byte, b'.' | b'_' | b'-')
        });
    if !valid_name {
        return Expected::Rejected(expected_error(InnerError::InvalidFilename));
    }
    let data_len = u32::from_le_bytes(
        raw[data_length_offset..data_offset]
            .try_into()
            .expect("media length"),
    ) as usize;
    if data_len == 0 {
        return Expected::Rejected(expected_error(InnerError::DeclaredLengthZero));
    }
    if data_len > MAX_TRANSFER_BYTES {
        return Expected::Rejected(expected_error(InnerError::DeclaredLengthExceeded));
    }
    let end = data_offset + data_len;
    if raw.len() != end {
        return Expected::Rejected(expected_error(InnerError::SourceLengthMismatch));
    }
    Expected::Accepted(raw[data_offset..].to_vec())
}

fn reference_bbqr(raw: &[u8]) -> Expected {
    if raw.len() < 2 {
        return Expected::Rejected(expected_error(InnerError::SourceLengthMismatch));
    }
    let count = usize::from(u16::from_le_bytes([raw[0], raw[1]]));
    if !(1..=BBQR_MAX_SUBMISSIONS).contains(&count) {
        return Expected::Rejected(expected_error(InnerError::SourceLengthMismatch));
    }

    let mut output: Box<[u8; MAX_TOTAL_DECODED_BYTES]> = vec![0; MAX_TOTAL_DECODED_BYTES]
        .into_boxed_slice()
        .try_into()
        .expect("fixed reference reassembly backing");
    let mut reassembler = Reassembler::new_typed(BbqrFileType::Psbt, &mut output);
    let mut cursor = 2usize;
    for _ in 0..count {
        if raw.len() < cursor + 2 {
            return Expected::Rejected(expected_error(InnerError::SourceLengthMismatch));
        }
        let length = usize::from(u16::from_le_bytes([raw[cursor], raw[cursor + 1]]));
        cursor += 2;
        if !(8..=BBQR_MAX_FRAME_BYTES).contains(&length) || raw.len() < cursor + length {
            return Expected::Rejected(expected_error(InnerError::SourceLengthMismatch));
        }
        if let Err(error) = reassembler.submit(&raw[cursor..cursor + length]) {
            return Expected::Rejected(expected_error(InnerError::Bbqr(error)));
        }
        cursor += length;
    }
    if cursor != raw.len() {
        return Expected::Rejected(expected_error(InnerError::SourceLengthMismatch));
    }
    match reassembler.payload() {
        Ok(payload) => Expected::Accepted(payload.to_vec()),
        Err(error) => Expected::Rejected(expected_error(InnerError::Bbqr(error))),
    }
}

fn run_case(
    request_bytes: &[u8],
    boundary_source: Source,
    raw: &[u8],
    expected: Expected,
) -> CaseSummary {
    reset_wiped_bytes();
    let summary = {
        let mut harness = Harness::open();
        let mut input = MockInput::try_new(boundary_source, raw).expect("bounded mock input");
        let begin = harness.exchange(request_bytes, Some(&mut input));
        assert!(input.is_used());
        let mut steps = vec![begin.clone()];
        let mut output = Vec::new();

        if begin.status == 0 {
            assert_eq!(begin.opcode, Operation::IngressBegin.wire_value());
            assert_eq!(begin.error, None);
            assert_eq!(begin.body.len(), 5);
            assert_eq!(begin.body[0], boundary_source.wire_value());
            let total =
                u32::from_le_bytes(begin.body[1..5].try_into().expect("ingress total")) as usize;
            match &expected {
                Expected::Accepted(expected_output) => assert_eq!(total, expected_output.len()),
                Expected::Rejected(error) => panic!("expected rejection {error:?}"),
            }
            assert_eq!(harness.broker.state(), BrokerState::IngressReady);
            let mut offset = 0usize;
            while offset < total {
                let read = harness.exchange(&ingress_read(offset), None);
                assert_eq!(read.opcode, Operation::IngressRead.wire_value());
                assert_eq!(read.status, 0);
                assert_eq!(read.error, None);
                assert!(read.body.len() >= 9);
                let actual_offset =
                    u32::from_le_bytes(read.body[..4].try_into().expect("returned chunk offset"))
                        as usize;
                let chunk_len =
                    u32::from_le_bytes(read.body[4..8].try_into().expect("returned chunk length"))
                        as usize;
                let expected_chunk = (total - offset).min(MAX_CHUNK_BYTES);
                assert_eq!(actual_offset, offset);
                assert_eq!(chunk_len, expected_chunk);
                assert_eq!(read.body.len(), 9 + chunk_len);
                assert_eq!(read.body[8], u8::from(offset + chunk_len == total));
                output.extend_from_slice(&read.body[9..]);
                offset += chunk_len;
                steps.push(read);
            }
            assert_eq!(output.len(), total);
            if let Expected::Accepted(expected_output) = &expected {
                assert_eq!(&output, expected_output);
            }
            assert_eq!(harness.broker.state(), BrokerState::Idle);

            let reused = harness.exchange(&ingress_begin(boundary_source), Some(&mut input));
            assert_step_rejection(&reused, expected_error(InnerError::SourceAlreadyUsed));
            steps.push(reused);
        } else {
            match expected {
                Expected::Rejected(error) => assert_step_rejection(&begin, error),
                Expected::Accepted(_) => panic!("reference accepted a rejected ingress"),
            }
        }
        assert_eq!(harness.broker.state(), BrokerState::ErrorReplyPending);

        let mut discarded =
            MockInput::try_new(Source::CameraA1Candidate, &[0x51; A1_CANDIDATE_BYTES])
                .expect("post-terminal boundary");
        let request = harness.request_frame(&ingress_begin(Source::CameraA1Candidate));
        let terminal = match harness.broker.accept(&request, Some(&mut discarded), None) {
            Err(error) => error,
            Ok(_) => panic!("terminal broker cannot reply"),
        };
        let post_terminal = assert_named_broker(terminal);
        assert!(discarded.is_used());
        assert_eq!(harness.broker.state(), BrokerState::ErrorReplyPending);
        CaseSummary {
            replies: harness.replies.clone(),
            steps,
            output,
            final_state: harness.broker.state(),
            post_terminal,
        }
    };
    assert!(wiped_bytes() >= raw.len());
    assert!(wiped_bytes() > 0);
    summary
}

fn assert_step_rejection(step: &Step, expected: ExpectedError) {
    assert_eq!(step.status, expected.status);
    assert_eq!(step.error, Some(expected.name));
    assert!(step.body.is_empty());
}

fn patterned(data: &[u8], length: usize, domain: u8) -> Vec<u8> {
    (0..length)
        .map(|index| {
            data.get(index % data.len().max(1))
                .copied()
                .unwrap_or(index as u8)
                .wrapping_add(domain)
                .wrapping_add((index as u8).wrapping_mul(29))
        })
        .collect()
}

fn media_record(name: &[u8], payload: &[u8], declared_len: usize) -> Vec<u8> {
    let mut raw = Vec::with_capacity(1 + name.len() + 4 + payload.len());
    raw.push(name.len() as u8);
    raw.extend_from_slice(name);
    raw.extend_from_slice(&(declared_len as u32).to_le_bytes());
    raw.extend_from_slice(payload);
    raw
}

fn base36(value: u16) -> [u8; 2] {
    fn symbol(value: u8) -> u8 {
        match value {
            0..=9 => b'0' + value,
            10..=35 => b'A' + value - 10,
            _ => unreachable!("base36 digit"),
        }
    }
    [symbol((value / 36) as u8), symbol((value % 36) as u8)]
}

fn base32(input: &[u8]) -> Vec<u8> {
    let mut output = Vec::with_capacity((input.len() * 8).div_ceil(5));
    let mut accumulator = 0u16;
    let mut bits = 0usize;
    for byte in input {
        accumulator = (accumulator << 8) | u16::from(*byte);
        bits += 8;
        while bits >= 5 {
            bits -= 5;
            output.push(BASE32[usize::from((accumulator >> bits) & 0x1f)]);
            accumulator &= (1u16 << bits).wrapping_sub(1);
        }
    }
    if bits != 0 {
        output.push(BASE32[usize::from((accumulator << (5 - bits)) & 0x1f)]);
    }
    output
}

fn bbqr_record(payload: &[u8], part_len: usize, file_type: u8, reverse: bool) -> Vec<u8> {
    let part_count = payload.len().div_ceil(part_len) as u16;
    assert!((1..=256).contains(&part_count));
    let mut frames = Vec::with_capacity(usize::from(part_count));
    for index in 0..part_count {
        let start = usize::from(index) * part_len;
        let end = payload.len().min(start + part_len);
        let mut frame = Vec::new();
        frame.extend_from_slice(b"B$2");
        frame.push(file_type);
        frame.extend_from_slice(&base36(part_count));
        frame.extend_from_slice(&base36(index));
        frame.extend_from_slice(&base32(&payload[start..end]));
        frames.push(frame);
    }
    if reverse {
        frames.reverse();
    }
    let mut raw = Vec::new();
    raw.extend_from_slice(&part_count.to_le_bytes());
    for frame in frames {
        raw.extend_from_slice(&(frame.len() as u16).to_le_bytes());
        raw.extend_from_slice(&frame);
    }
    raw
}

fn exact_candidate_cases(data: &[u8], source: Source, exact: usize) -> Vec<CaseSummary> {
    [exact - 1, exact, exact + 1]
        .into_iter()
        .map(|length| {
            let raw = patterned(data, length, source.wire_value());
            let expected = reference_source(source, &raw);
            run_case(&ingress_begin(source), source, &raw, expected)
        })
        .collect()
}

fn media_cases(data: &[u8]) -> Vec<CaseSummary> {
    let payload_len = data.len().clamp(1, 4_096);
    let payload = patterned(data, payload_len, 0x31);
    let valid = media_record(b"fuzz_input.psbt", &payload, payload.len());
    let selected = match data.get(1).copied().unwrap_or(0) % 6 {
        0 => Vec::new(),
        1 => media_record(b"fuzz_input.txt", &payload, payload.len()),
        2 => media_record(b"fuzz_input.psbt", &[], 0),
        3 => media_record(
            b"fuzz_input.psbt",
            &[],
            MAX_TRANSFER_BYTES.saturating_add(1),
        ),
        4 => media_record(b"fuzz_input.psbt", &payload, payload.len() + 1),
        5 => {
            let mut trailing = media_record(b"fuzz_input.psbt", &payload, payload.len());
            trailing.push(0);
            trailing
        }
        _ => unreachable!("modulo six is exhaustive"),
    };
    [&valid, &selected]
        .into_iter()
        .map(|raw| {
            run_case(
                &ingress_begin(Source::MediaPsbt),
                Source::MediaPsbt,
                raw,
                reference_source(Source::MediaPsbt, raw),
            )
        })
        .collect()
}

fn bbqr_cases(data: &[u8]) -> Vec<CaseSummary> {
    let payload_len = data.len().clamp(1, 4_096);
    let payload = patterned(data, payload_len, 0x62);
    let minimum = payload_len.div_ceil(256).div_ceil(5) * 5;
    let choices = [5usize, 10, 20, 40, 80, 160, 320, 640, 1_025, 2_680];
    let selected = choices[usize::from(data.get(1).copied().unwrap_or(0)) % choices.len()];
    let part_len = selected.max(minimum.max(5));
    let p = bbqr_record(&payload, part_len, b'P', true);
    let t = bbqr_record(&payload, part_len, b'T', false);
    vec![
        run_case(
            &ingress_begin(Source::CameraBbqrPsbt),
            Source::CameraBbqrPsbt,
            &p,
            Expected::Accepted(payload),
        ),
        run_case(
            &ingress_begin(Source::CameraBbqrPsbt),
            Source::CameraBbqrPsbt,
            &t,
            Expected::Rejected(ExpectedError {
                status: 0x010a,
                name: "UnsupportedFileType",
            }),
        ),
    ]
}

fn raw_request_case(data: &[u8]) -> Vec<CaseSummary> {
    let boundary_source = source_from_byte(data.get(2).copied().unwrap_or(0));
    let raw = data.get(8..).unwrap_or_default().to_vec();
    let source_tag = data.get(1).copied().unwrap_or(0);
    let declared_aux = u16::from_le_bytes([
        data.get(2).copied().unwrap_or(0),
        data.get(3).copied().unwrap_or(0),
    ]);
    let aux = data.get(8..data.len().min(40)).unwrap_or_default();
    let mut body = vec![source_tag];
    body.extend_from_slice(&declared_aux.to_le_bytes());
    body.extend_from_slice(aux);
    let mut candidate = request(Operation::IngressBegin, &body);
    match data.get(4).copied().unwrap_or(0) % 8 {
        0 => {}
        1 => candidate[0] = 2,
        2 => candidate[2] = 1,
        3 => candidate[1] = 0xff,
        4 => candidate[4..8].copy_from_slice(&u32::MAX.to_le_bytes()),
        5 => candidate.truncate(usize::from(data.get(5).copied().unwrap_or(0)) % 7 + 1),
        6 => {
            let declared = body.len().saturating_add(1) as u32;
            candidate[4..8].copy_from_slice(&declared.to_le_bytes());
        }
        7 => candidate = request(Operation::IngressBegin, &[source_tag, 0, 0]),
        _ => unreachable!("modulo eight is exhaustive"),
    }
    let expected = reference_request(&candidate, boundary_source, &raw);
    vec![run_case(&candidate, boundary_source, &raw, expected)]
}

fn exact_chunk_case(data: &[u8]) -> Vec<CaseSummary> {
    let payload = patterned(data, MAX_CHUNK_BYTES + 17, 0x94);
    let raw = media_record(b"chunk_boundary.psbt", &payload, payload.len());
    vec![run_case(
        &ingress_begin(Source::MediaPsbt),
        Source::MediaPsbt,
        &raw,
        Expected::Accepted(payload),
    )]
}

fn offset_rejection_case(data: &[u8]) -> Vec<CaseSummary> {
    let raw = patterned(data, A1_CANDIDATE_BYTES, 0xa7);
    reset_wiped_bytes();
    let summary = {
        let mut harness = Harness::open();
        let mut input = MockInput::try_new(Source::CameraA1Candidate, &raw).expect("offset input");
        let begin = harness.exchange(&ingress_begin(Source::CameraA1Candidate), Some(&mut input));
        assert_eq!(begin.status, 0);
        let wrong_offset = usize::from(data.get(1).copied().unwrap_or(0)) + 1;
        let read = harness.exchange(&ingress_read(wrong_offset), None);
        assert_step_rejection(&read, expected_error(InnerError::OffsetMismatch));
        assert_eq!(harness.broker.state(), BrokerState::ErrorReplyPending);
        let post_terminal = assert_named_broker(harness.broker.peer_lost());
        CaseSummary {
            replies: harness.replies.clone(),
            steps: vec![begin, read],
            output: Vec::new(),
            final_state: harness.broker.state(),
            post_terminal,
        }
    };
    assert!(wiped_bytes() >= raw.len());
    vec![summary]
}

fn established_rejections(data: &[u8]) -> Vec<CaseSummary> {
    let mut results = Vec::new();

    let raw = patterned(data, A1_CANDIDATE_BYTES, 0xc1);
    let request_bytes = ingress_begin(Source::CameraA1Candidate);
    results.push(run_case(
        &request_bytes,
        Source::CameraKitCandidate,
        &raw,
        reference_request(&request_bytes, Source::CameraKitCandidate, &raw),
    ));

    let request_bytes = request(
        Operation::IngressBegin,
        &[Source::CameraA1Candidate.wire_value(), 1, 0, 0x51],
    );
    results.push(run_case(
        &request_bytes,
        Source::CameraA1Candidate,
        &raw,
        reference_request(&request_bytes, Source::CameraA1Candidate, &raw),
    ));

    let empty = Vec::new();
    let request_bytes = ingress_begin(Source::CameraBbqrPsbt);
    results.push(run_case(
        &request_bytes,
        Source::CameraBbqrPsbt,
        &empty,
        reference_request(&request_bytes, Source::CameraBbqrPsbt, &empty),
    ));
    results
}

fn drive(data: &[u8]) -> Vec<CaseSummary> {
    match data.first().copied().unwrap_or(0) % 8 {
        0 => exact_candidate_cases(data, Source::CameraA1Candidate, A1_CANDIDATE_BYTES),
        1 => exact_candidate_cases(data, Source::CameraKitCandidate, KIT_CANDIDATE_BYTES),
        2 => media_cases(data),
        3 => bbqr_cases(data),
        4 => raw_request_case(data),
        5 => exact_chunk_case(data),
        6 => offset_rejection_case(data),
        7 => established_rejections(data),
        _ => unreachable!("modulo eight is exhaustive"),
    }
}

fn assert_isolated_active_ingress_cleanup() {
    let candidate = [0x5e; A1_CANDIDATE_BYTES];
    let mut harness = Harness::open();
    let mut input =
        MockInput::try_new(Source::CameraA1Candidate, &candidate).expect("cleanup input");
    let begin = harness.exchange(&ingress_begin(Source::CameraA1Candidate), Some(&mut input));
    assert_eq!(begin.status, 0);
    assert_eq!(harness.broker.state(), BrokerState::IngressReady);
    assert!(input.is_used());

    reset_wiped_bytes();
    drop(input);
    assert_eq!(wiped_bytes(), 0);
    drop(harness);
    assert_eq!(wiped_bytes(), A1_CANDIDATE_BYTES);
}

fuzz_target!(|data: &[u8]| {
    if data.len() > MAX_PRESENTED_BYTES {
        return;
    }
    let first = drive(data);
    let repeated = drive(data);
    assert_eq!(first, repeated);
    assert_isolated_active_ingress_cleanup();
});
