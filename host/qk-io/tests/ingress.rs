use qk_bbqr::{encode_typed_frame, encoded_part_count, BbqrFileType, MAX_FRAME_TEXT_BYTES};
use qk_io::{
    BrokerError, BrokerSession, BrokerState, InnerError, MockInput, Operation, ReplyStatus, Source,
    A1_CANDIDATE_BYTES, INNER_HEADER_BYTES, INNER_VERSION, KIT_CANDIDATE_BYTES, MAX_CHUNK_BYTES,
    MAX_TRANSFER_BYTES,
};
use qk_ipc::{CoreEvent, CoreProtocol, OutboundFrame, ReceivedFrame, StreamDecoder, HEADER_BYTES};

const SESSION_ID: [u8; 16] = *b"qk-io-ingress-v1";

struct Exchange {
    status: ReplyStatus,
    payload: Vec<u8>,
}

struct Response<'a> {
    opcode: u8,
    status: u16,
    body: &'a [u8],
}

struct Harness {
    core: CoreProtocol,
    broker: BrokerSession,
}

impl Harness {
    fn open() -> Self {
        let mut core = CoreProtocol::new(SESSION_ID);
        let mut broker = BrokerSession::new();
        let outbound = core.begin().expect("open transition");
        let request = decode_one(&encode_outbound(&outbound, &[]));
        let reply = broker.accept(&request, None, None).expect("open accepted");
        assert_eq!(reply.status(), ReplyStatus::Control);
        assert!(!reply.is_empty());
        assert_eq!(reply.len(), reply.frame_bytes().len());
        let response = decode_one(reply.frame_bytes());
        assert!(response.payload().is_empty());
        assert_eq!(core.accept(&response), Ok(CoreEvent::SessionReady));
        assert_eq!(broker.state(), BrokerState::Idle);
        Self { core, broker }
    }

    fn exchange(&mut self, payload: &[u8], input: Option<&mut MockInput>) -> Exchange {
        let request = self.request_frame(payload);
        let reply = self
            .broker
            .accept(&request, input, None)
            .expect("broker operation reply");
        let status = reply.status();
        assert!(!reply.is_empty());
        assert_eq!(reply.len(), reply.frame_bytes().len());
        let response = decode_one(reply.frame_bytes());
        let payload = response.payload().to_vec();
        assert_eq!(
            self.core.accept(&response),
            Ok(CoreEvent::OperationResponse)
        );
        Exchange { status, payload }
    }

    fn request_frame(&mut self, payload: &[u8]) -> ReceivedFrame {
        let outbound = self.core.request().expect("operation transition");
        decode_one(&encode_outbound(&outbound, payload))
    }
}

fn encode_outbound(outbound: &OutboundFrame, payload: &[u8]) -> Vec<u8> {
    let mut bytes = vec![0xa5; HEADER_BYTES + payload.len()];
    let length = outbound
        .encode(payload, &mut bytes)
        .expect("encode QKIP frame");
    assert_eq!(length, bytes.len());
    bytes
}

fn decode_one(bytes: &[u8]) -> ReceivedFrame {
    let mut decoder = StreamDecoder::new();
    let outcome = decoder.ingest(bytes, false).expect("decode QKIP frame");
    assert_eq!(outcome.consumed(), bytes.len());
    assert!(outcome.frame_ready());
    decoder.take_frame().expect("take QKIP frame")
}

fn operation_request(operation: Operation, body: &[u8]) -> Vec<u8> {
    let mut request = Vec::with_capacity(INNER_HEADER_BYTES + body.len());
    request.extend_from_slice(&[INNER_VERSION, operation.wire_value(), 0, 0]);
    request.extend_from_slice(&(body.len() as u32).to_le_bytes());
    request.extend_from_slice(body);
    request
}

fn ingress_begin(source: Source) -> Vec<u8> {
    operation_request(Operation::IngressBegin, &[source.wire_value(), 0, 0])
}

fn ingress_read(expected_offset: usize) -> Vec<u8> {
    operation_request(
        Operation::IngressRead,
        &(expected_offset as u32).to_le_bytes(),
    )
}

fn response(payload: &[u8]) -> Response<'_> {
    assert!(payload.len() >= INNER_HEADER_BYTES);
    assert_eq!(payload[0], INNER_VERSION);
    let body_len = u32::from_le_bytes(payload[4..8].try_into().expect("body length")) as usize;
    assert_eq!(payload.len(), INNER_HEADER_BYTES + body_len);
    Response {
        opcode: payload[1],
        status: u16::from_le_bytes(payload[2..4].try_into().expect("response status")),
        body: &payload[INNER_HEADER_BYTES..],
    }
}

fn begin_ingress(
    harness: &mut Harness,
    source: Source,
    input: &mut MockInput,
    expected_len: usize,
) {
    let exchange = harness.exchange(&ingress_begin(source), Some(input));
    assert_eq!(
        exchange.status,
        ReplyStatus::Success(Operation::IngressBegin)
    );
    let parsed = response(&exchange.payload);
    assert_eq!(parsed.opcode, Operation::IngressBegin.wire_value());
    assert_eq!(parsed.status, 0);
    assert_eq!(parsed.body.len(), 5);
    assert_eq!(parsed.body[0], source.wire_value());
    assert_eq!(
        u32::from_le_bytes(parsed.body[1..5].try_into().expect("ingress length")) as usize,
        expected_len
    );
    assert!(input.is_used());
    assert_eq!(harness.broker.state(), BrokerState::IngressReady);
}

fn read_chunk(harness: &mut Harness, expected_offset: usize, expected: &[u8], final_chunk: bool) {
    let exchange = harness.exchange(&ingress_read(expected_offset), None);
    assert_eq!(
        exchange.status,
        ReplyStatus::Success(Operation::IngressRead)
    );
    let parsed = response(&exchange.payload);
    assert_eq!(parsed.opcode, Operation::IngressRead.wire_value());
    assert_eq!(parsed.status, 0);
    assert_eq!(parsed.body.len(), 9 + expected.len());
    assert_eq!(
        u32::from_le_bytes(parsed.body[..4].try_into().expect("chunk offset")) as usize,
        expected_offset
    );
    assert_eq!(
        u32::from_le_bytes(parsed.body[4..8].try_into().expect("chunk length")) as usize,
        expected.len()
    );
    assert_eq!(parsed.body[8], u8::from(final_chunk));
    assert_eq!(&parsed.body[9..], expected);
    assert_eq!(
        harness.broker.state(),
        if final_chunk {
            BrokerState::Idle
        } else {
            BrokerState::IngressReady
        }
    );
}

fn patterned(length: usize, seed: u8) -> Vec<u8> {
    (0..length)
        .map(|index| seed.wrapping_add((index as u8).wrapping_mul(29)))
        .collect()
}

fn media_record(name: &[u8], payload: &[u8]) -> Vec<u8> {
    let mut record = Vec::with_capacity(1 + name.len() + 4 + payload.len());
    record.push(name.len() as u8);
    record.extend_from_slice(name);
    record.extend_from_slice(&(payload.len() as u32).to_le_bytes());
    record.extend_from_slice(payload);
    record
}

fn bbqr_record(file_type: BbqrFileType, payload: &[u8], part_len: usize) -> Vec<u8> {
    let part_count = encoded_part_count(payload.len(), part_len).expect("BBQr part count");
    let mut frames = Vec::with_capacity(usize::from(part_count));
    for index in 0..part_count {
        let mut frame = [0xa5; MAX_FRAME_TEXT_BYTES];
        let length = encode_typed_frame(file_type, payload, part_len, index, &mut frame)
            .expect("BBQr frame");
        frames.push(frame[..length].to_vec());
    }
    let mut record = Vec::new();
    record.extend_from_slice(&part_count.to_le_bytes());
    for frame in frames.iter().rev() {
        record.extend_from_slice(&(frame.len() as u16).to_le_bytes());
        record.extend_from_slice(frame);
    }
    record
}

fn assert_rejection(exchange: &Exchange, operation: Operation, error: InnerError) {
    assert_eq!(
        exchange.status,
        ReplyStatus::Rejected {
            opcode: operation.wire_value(),
            error,
        }
    );
    let parsed = response(&exchange.payload);
    assert_eq!(parsed.opcode, operation.wire_value());
    assert_eq!(parsed.status, error.status_code());
    assert!(parsed.body.is_empty());
}

#[test]
fn qkip_open_and_exact_a1_and_kit_candidates_round_trip() {
    let mut harness = Harness::open();

    let a1 = patterned(A1_CANDIDATE_BYTES, 0x11);
    let mut a1_input = MockInput::try_new(Source::CameraA1Candidate, &a1).expect("A1 input");
    begin_ingress(
        &mut harness,
        Source::CameraA1Candidate,
        &mut a1_input,
        a1.len(),
    );
    read_chunk(&mut harness, 0, &a1, true);

    let kit = patterned(KIT_CANDIDATE_BYTES, 0x42);
    let mut kit_input = MockInput::try_new(Source::CameraKitCandidate, &kit).expect("Kit input");
    begin_ingress(
        &mut harness,
        Source::CameraKitCandidate,
        &mut kit_input,
        kit.len(),
    );
    read_chunk(&mut harness, 0, &kit, true);
}

#[test]
fn candidate_lengths_are_exact_and_each_mismatch_is_terminal() {
    let cases = [
        (Source::CameraA1Candidate, A1_CANDIDATE_BYTES),
        (Source::CameraKitCandidate, KIT_CANDIDATE_BYTES),
    ];
    for (source, exact_len) in cases {
        for rejected_len in [exact_len - 1, exact_len + 1] {
            let candidate = patterned(rejected_len, 0xd2);
            let mut input = MockInput::try_new(source, &candidate).expect("candidate input");
            let mut harness = Harness::open();
            let exchange = harness.exchange(&ingress_begin(source), Some(&mut input));
            assert_rejection(
                &exchange,
                Operation::IngressBegin,
                InnerError::SourceLengthMismatch,
            );
            assert!(input.is_used());
            assert_eq!(harness.broker.state(), BrokerState::ErrorReplyPending);
        }
    }
}

#[test]
fn media_psbt_record_is_unwrapped_and_returned_byte_exactly() {
    let payload = patterned(4_103, 0x73);
    let record = media_record(b"unsigned_01.psbt", &payload);
    let mut input = MockInput::try_new(Source::MediaPsbt, &record).expect("media input");
    let mut harness = Harness::open();

    begin_ingress(&mut harness, Source::MediaPsbt, &mut input, payload.len());
    read_chunk(&mut harness, 0, &payload, true);
}

#[test]
fn maximum_media_payload_uses_eight_deterministic_262144_byte_chunks() {
    let payload = patterned(MAX_TRANSFER_BYTES, 0x29);
    let record = media_record(b"maximum.psbt", &payload);
    let mut input = MockInput::try_new(Source::MediaPsbt, &record).expect("maximum media input");
    let mut harness = Harness::open();

    begin_ingress(&mut harness, Source::MediaPsbt, &mut input, payload.len());
    for chunk_index in 0..8 {
        let offset = chunk_index * MAX_CHUNK_BYTES;
        let end = offset + MAX_CHUNK_BYTES;
        read_chunk(
            &mut harness,
            offset,
            &payload[offset..end],
            chunk_index == 7,
        );
    }
}

#[test]
fn out_of_order_bbqr_p_frames_reassemble_to_the_exact_psbt() {
    let payload = patterned(7_001, 0x5c);
    let record = bbqr_record(BbqrFileType::Psbt, &payload, 1_000);
    let mut input = MockInput::try_new(Source::CameraBbqrPsbt, &record).expect("BBQr camera input");
    let mut harness = Harness::open();

    begin_ingress(
        &mut harness,
        Source::CameraBbqrPsbt,
        &mut input,
        payload.len(),
    );
    read_chunk(&mut harness, 0, &payload, true);
}

#[test]
fn bbqr_transaction_type_is_a_named_terminal_rejection() {
    let payload = patterned(31, 0x81);
    let record = bbqr_record(BbqrFileType::Transaction, &payload, 10);
    let mut input = MockInput::try_new(Source::CameraBbqrPsbt, &record).expect("typed BBQr input");
    let mut harness = Harness::open();

    let exchange = harness.exchange(&ingress_begin(Source::CameraBbqrPsbt), Some(&mut input));
    assert_rejection(
        &exchange,
        Operation::IngressBegin,
        InnerError::Bbqr(qk_bbqr::BbqrError::UnsupportedFileType),
    );
    assert!(input.is_used());
    assert_eq!(harness.broker.state(), BrokerState::ErrorReplyPending);
}

#[test]
fn a_consumed_source_cannot_be_reused_and_the_rejection_latches_terminal() {
    let candidate = patterned(A1_CANDIDATE_BYTES, 0xb4);
    let mut input =
        MockInput::try_new(Source::CameraA1Candidate, &candidate).expect("one-use input");
    let mut harness = Harness::open();

    begin_ingress(
        &mut harness,
        Source::CameraA1Candidate,
        &mut input,
        candidate.len(),
    );
    read_chunk(&mut harness, 0, &candidate, true);
    let exchange = harness.exchange(&ingress_begin(Source::CameraA1Candidate), Some(&mut input));
    assert_rejection(
        &exchange,
        Operation::IngressBegin,
        InnerError::SourceAlreadyUsed,
    );
    assert_eq!(harness.broker.state(), BrokerState::ErrorReplyPending);

    let mut discarded =
        MockInput::try_new(Source::CameraA1Candidate, &candidate).expect("post-rejection input");
    let request = harness.request_frame(&ingress_begin(Source::CameraA1Candidate));
    assert!(matches!(
        harness.broker.accept(&request, Some(&mut discarded), None),
        Err(BrokerError::BrokerTerminated)
    ));
    assert!(discarded.is_used());
    assert_eq!(harness.broker.state(), BrokerState::ErrorReplyPending);
}

#[test]
fn malformed_media_record_consumes_its_source_and_rejection_is_terminal() {
    let record = media_record(b"unsigned.txt", b"public malformed media payload");
    let mut input = MockInput::try_new(Source::MediaPsbt, &record).expect("bad media input");
    let mut harness = Harness::open();

    let exchange = harness.exchange(&ingress_begin(Source::MediaPsbt), Some(&mut input));
    assert_rejection(
        &exchange,
        Operation::IngressBegin,
        InnerError::InvalidFilename,
    );
    assert!(input.is_used());
    assert_eq!(harness.broker.state(), BrokerState::ErrorReplyPending);

    let mut later = MockInput::try_new(Source::CameraKitCandidate, &[0x33; KIT_CANDIDATE_BYTES])
        .expect("later boundary");
    let request = harness.request_frame(&ingress_begin(Source::CameraKitCandidate));
    assert!(matches!(
        harness.broker.accept(&request, Some(&mut later), None),
        Err(BrokerError::BrokerTerminated)
    ));
    assert!(later.is_used());
}
