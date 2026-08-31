use qk_bbqr::{
    encode_typed_frame, encoded_part_count, BbqrFileType, Reassembler, MAX_FRAME_TEXT_BYTES,
    MAX_TOTAL_DECODED_BYTES,
};
use qk_io::{
    Artifact, BrokerReply, BrokerSession, BrokerState, InnerError, MockOutputWriter, Operation,
    OutputFault, ReplyStatus, Sink, INNER_HEADER_BYTES, INNER_VERSION, MAX_CHUNK_BYTES,
    MAX_TRANSFER_BYTES,
};
use qk_ipc::{
    CoreEvent, CoreProtocol, OutboundFrame, ReceivedFrame, StreamDecoder, MAX_FRAME_BYTES,
};

const SESSION_ID: [u8; 16] = [0x73; 16];

struct InnerResponse {
    opcode: u8,
    status: u16,
    body: Vec<u8>,
}

struct Harness {
    core: CoreProtocol,
    broker: BrokerSession,
}

impl Harness {
    fn open() -> Self {
        let mut core = CoreProtocol::new(SESSION_ID);
        let mut broker = BrokerSession::new();
        let outbound = core.begin().expect("opening transition");
        let request = received(outbound, &[]);
        let reply = broker.accept(&request, None, None).expect("opening reply");
        assert_eq!(reply.status(), ReplyStatus::Control);
        let response = reply_frame(reply);
        assert_eq!(
            core.accept(&response).expect("core accepts ready"),
            CoreEvent::SessionReady
        );
        assert_eq!(broker.state(), BrokerState::Idle);
        Self { core, broker }
    }

    fn operation(
        &mut self,
        payload: &[u8],
        writer: Option<&mut MockOutputWriter>,
    ) -> (ReplyStatus, InnerResponse) {
        let outbound = self.core.request().expect("operation transition");
        let request = received(outbound, payload);
        let reply = self
            .broker
            .accept(&request, None, writer)
            .expect("operation reply");
        let status = reply.status();
        let response = reply_frame(reply);
        assert_eq!(
            self.core.accept(&response).expect("core accepts response"),
            CoreEvent::OperationResponse
        );
        (status, parse_response(response.payload()))
    }

    fn begin(&mut self, sink: Sink, artifact: Artifact, total_len: usize, aux: &[u8]) {
        let (status, response) =
            self.operation(&egress_begin(sink, artifact, total_len, aux), None);
        assert_eq!(status, ReplyStatus::Success(Operation::EgressBegin));
        assert_success(&response, Operation::EgressBegin, &[]);
        assert_eq!(self.broker.state(), BrokerState::EgressReceiving);
    }

    fn write(&mut self, offset: usize, chunk: &[u8]) {
        let (status, response) = self.operation(&egress_write(offset, chunk), None);
        assert_eq!(status, ReplyStatus::Success(Operation::EgressWrite));
        assert_success(
            &response,
            Operation::EgressWrite,
            &((offset + chunk.len()) as u32).to_le_bytes(),
        );
    }

    fn finish(&mut self, writer: Option<&mut MockOutputWriter>) -> (ReplyStatus, InnerResponse) {
        self.operation(&request(Operation::EgressFinish, &[]), writer)
    }
}

fn received(outbound: OutboundFrame, payload: &[u8]) -> ReceivedFrame {
    let mut bytes = vec![0u8; MAX_FRAME_BYTES];
    let length = outbound
        .encode(payload, &mut bytes)
        .expect("encode outbound QKIP frame");
    bytes.truncate(length);
    decode_frame(&bytes)
}

fn reply_frame(reply: BrokerReply) -> ReceivedFrame {
    assert!(!reply.is_empty());
    assert_eq!(reply.len(), reply.frame_bytes().len());
    decode_frame(reply.frame_bytes())
}

fn decode_frame(bytes: &[u8]) -> ReceivedFrame {
    let mut decoder = StreamDecoder::new();
    let outcome = decoder.ingest(bytes, false).expect("decode QKIP frame");
    assert_eq!(outcome.consumed(), bytes.len());
    assert!(outcome.frame_ready());
    decoder.take_frame().expect("complete QKIP frame")
}

fn parse_response(payload: &[u8]) -> InnerResponse {
    assert!(payload.len() >= INNER_HEADER_BYTES);
    assert_eq!(payload[0], INNER_VERSION);
    let opcode = payload[1];
    let status = u16::from_le_bytes([payload[2], payload[3]]);
    let body_len = u32::from_le_bytes([payload[4], payload[5], payload[6], payload[7]]) as usize;
    assert_eq!(payload.len(), INNER_HEADER_BYTES + body_len);
    if status != 0 {
        assert_eq!(body_len, 0);
    }
    InnerResponse {
        opcode,
        status,
        body: payload[INNER_HEADER_BYTES..].to_vec(),
    }
}

fn request(operation: Operation, body: &[u8]) -> Vec<u8> {
    let mut bytes = Vec::with_capacity(INNER_HEADER_BYTES + body.len());
    bytes.extend_from_slice(&[INNER_VERSION, operation.wire_value(), 0, 0]);
    bytes.extend_from_slice(&(body.len() as u32).to_le_bytes());
    bytes.extend_from_slice(body);
    bytes
}

fn egress_begin(sink: Sink, artifact: Artifact, total_len: usize, aux: &[u8]) -> Vec<u8> {
    let mut body = vec![sink.wire_value(), artifact.wire_value()];
    body.extend_from_slice(&(total_len as u32).to_le_bytes());
    body.extend_from_slice(&(aux.len() as u16).to_le_bytes());
    body.extend_from_slice(aux);
    request(Operation::EgressBegin, &body)
}

fn egress_write(offset: usize, chunk: &[u8]) -> Vec<u8> {
    let mut body = Vec::with_capacity(8 + chunk.len());
    body.extend_from_slice(&(offset as u32).to_le_bytes());
    body.extend_from_slice(&(chunk.len() as u32).to_le_bytes());
    body.extend_from_slice(chunk);
    request(Operation::EgressWrite, &body)
}

fn sd_aux(name: &[u8]) -> Vec<u8> {
    let mut aux = Vec::with_capacity(1 + name.len());
    aux.push(name.len() as u8);
    aux.extend_from_slice(name);
    aux
}

fn bbqr_aux(non_final_part_len: u16) -> [u8; 2] {
    non_final_part_len.to_le_bytes()
}

fn assert_success(response: &InnerResponse, operation: Operation, body: &[u8]) {
    assert_eq!(response.opcode, operation.wire_value());
    assert_eq!(response.status, 0);
    assert_eq!(response.body, body);
}

fn assert_rejection(
    status: ReplyStatus,
    response: &InnerResponse,
    operation: Operation,
    error: InnerError,
) {
    assert_eq!(
        status,
        ReplyStatus::Rejected {
            opcode: operation.wire_value(),
            error,
        }
    );
    assert_eq!(response.opcode, operation.wire_value());
    assert_eq!(response.status, error.status_code());
    assert!(response.body.is_empty());
}

fn receipt(sink: Sink, artifact: Artifact, length: usize) -> [u8; 6] {
    let mut bytes = [0u8; 6];
    bytes[0] = sink.wire_value();
    bytes[1] = artifact.wire_value();
    bytes[2..6].copy_from_slice(&(length as u32).to_le_bytes());
    bytes
}

#[test]
fn all_three_sd_artifacts_use_exact_names_and_one_use_atomic_output() {
    let cases: [(Artifact, &[u8], &[u8]); 3] = [
        (
            Artifact::FinalizedPsbt,
            b"qk-0123456789abcdef0123456789abcdef-final.psbt",
            b"finalized-psbt-bytes",
        ),
        (
            Artifact::RawTransaction,
            b"qk-fedcba9876543210fedcba9876543210-final.tx",
            b"raw-transaction-bytes",
        ),
        (
            Artifact::WatchOnlyBsms,
            b"qk-00112233445566778899aabbccddeeff-watch.bsms",
            b"BSMS 1.0\nfixed test record\n",
        ),
    ];

    for (artifact, name, payload) in cases {
        let mut harness = Harness::open();
        let aux = sd_aux(name);
        harness.begin(Sink::Sd, artifact, payload.len(), &aux);
        let split = payload.len() / 2;
        harness.write(0, &payload[..split]);
        harness.write(split, &payload[split..]);

        let mut writer = MockOutputWriter::new(Sink::Sd);
        let (status, response) = harness.finish(Some(&mut writer));
        assert_eq!(status, ReplyStatus::Success(Operation::EgressFinish));
        assert_success(
            &response,
            Operation::EgressFinish,
            &receipt(Sink::Sd, artifact, payload.len()),
        );
        assert_eq!(harness.broker.state(), BrokerState::Idle);
        assert!(writer.is_used());
        assert_eq!(writer.final_name(), Some(name));
        assert_eq!(writer.final_bytes(), Some(payload));
        assert!(writer.temporary_bytes().is_none());
    }
}

#[test]
fn successful_sd_writer_cannot_be_reused_for_a_second_artifact() {
    let name = b"qk-0123456789abcdef0123456789abcdef-final.tx";
    let aux = sd_aux(name);
    let payload = b"first";
    let mut harness = Harness::open();
    let mut writer = MockOutputWriter::new(Sink::Sd);

    harness.begin(Sink::Sd, Artifact::RawTransaction, payload.len(), &aux);
    harness.write(0, payload);
    let (status, response) = harness.finish(Some(&mut writer));
    assert_eq!(status, ReplyStatus::Success(Operation::EgressFinish));
    assert_success(
        &response,
        Operation::EgressFinish,
        &receipt(Sink::Sd, Artifact::RawTransaction, payload.len()),
    );

    harness.begin(Sink::Sd, Artifact::RawTransaction, payload.len(), &aux);
    harness.write(0, payload);
    let (status, response) = harness.finish(Some(&mut writer));
    assert_rejection(
        status,
        &response,
        Operation::EgressFinish,
        InnerError::WriterAlreadyUsed,
    );
    assert_eq!(harness.broker.state(), BrokerState::ErrorReplyPending);
    assert_eq!(writer.final_name(), Some(name.as_slice()));
    assert_eq!(writer.final_bytes(), Some(payload.as_slice()));
}

#[test]
fn every_sd_writer_failure_has_its_exact_error_and_residue_posture() {
    let cases = [
        (OutputFault::Collision, InnerError::OutputCollision, false),
        (OutputFault::Create, InnerError::OutputCreateFailed, false),
        (OutputFault::Write, InnerError::OutputWriteFailed, true),
        (OutputFault::Sync, InnerError::OutputSyncFailed, true),
        (OutputFault::Close, InnerError::OutputCloseFailed, true),
        (OutputFault::Reopen, InnerError::OutputReopenFailed, true),
        (
            OutputFault::ReadbackMismatch,
            InnerError::OutputReadbackMismatch,
            true,
        ),
        (OutputFault::Rename, InnerError::OutputRenameFailed, true),
    ];
    let name = b"qk-0123456789abcdef0123456789abcdef-final.tx";
    let aux = sd_aux(name);
    let payload = b"writer-failure-payload";

    for (fault, expected, temporary_expected) in cases {
        let mut harness = Harness::open();
        harness.begin(Sink::Sd, Artifact::RawTransaction, payload.len(), &aux);
        harness.write(0, payload);
        let mut writer = MockOutputWriter::with_fault(Sink::Sd, fault);
        let (status, response) = harness.finish(Some(&mut writer));
        assert_rejection(status, &response, Operation::EgressFinish, expected);
        assert_eq!(harness.broker.state(), BrokerState::ErrorReplyPending);
        assert!(writer.is_used());
        assert!(writer.final_name().is_none());
        assert!(writer.final_bytes().is_none());
        assert_eq!(writer.temporary_bytes().is_some(), temporary_expected);
        if temporary_expected && fault != OutputFault::ReadbackMismatch {
            assert_eq!(writer.temporary_bytes(), Some(payload.as_slice()));
        }
        if fault == OutputFault::ReadbackMismatch {
            let residue = writer.temporary_bytes().expect("mutated temporary residue");
            assert_eq!(residue.len(), payload.len());
            assert_ne!(residue, payload);
        }
    }
}

#[test]
fn print_artifacts_are_one_use_opaque_writes_with_named_failure() {
    let cases: [(Artifact, &[u8]); 2] = [
        (Artifact::A1PrintArtifact, &[0x41; 67]),
        (Artifact::KitPrintArtifact, &[0x4b; 899]),
    ];
    for (artifact, payload) in cases {
        let mut harness = Harness::open();
        harness.begin(Sink::Print, artifact, payload.len(), &[]);
        harness.write(0, payload);
        let mut writer = MockOutputWriter::new(Sink::Print);
        let (status, response) = harness.finish(Some(&mut writer));
        assert_eq!(status, ReplyStatus::Success(Operation::EgressFinish));
        assert_success(
            &response,
            Operation::EgressFinish,
            &receipt(Sink::Print, artifact, payload.len()),
        );
        assert!(writer.is_used());
        assert_eq!(writer.final_bytes(), Some(payload));
        assert!(writer.final_name().is_none());
        assert!(writer.temporary_bytes().is_none());
    }

    let payload = b"opaque-print";
    let mut harness = Harness::open();
    harness.begin(Sink::Print, Artifact::A1PrintArtifact, payload.len(), &[]);
    harness.write(0, payload);
    let mut writer = MockOutputWriter::with_fault(Sink::Print, OutputFault::Print);
    let (status, response) = harness.finish(Some(&mut writer));
    assert_rejection(
        status,
        &response,
        Operation::EgressFinish,
        InnerError::PrintFailed,
    );
    assert!(writer.is_used());
    assert!(writer.final_bytes().is_none());
}

#[test]
fn missing_wrong_and_early_writers_are_consuming_named_rejections() {
    let name = b"qk-0123456789abcdef0123456789abcdef-final.tx";
    let aux = sd_aux(name);
    let payload = b"writer-boundary";

    let mut missing = Harness::open();
    missing.begin(Sink::Sd, Artifact::RawTransaction, payload.len(), &aux);
    missing.write(0, payload);
    let (status, response) = missing.finish(None);
    assert_rejection(
        status,
        &response,
        Operation::EgressFinish,
        InnerError::BoundaryMissing,
    );

    let mut wrong = Harness::open();
    wrong.begin(Sink::Sd, Artifact::RawTransaction, payload.len(), &aux);
    wrong.write(0, payload);
    let mut print_writer = MockOutputWriter::new(Sink::Print);
    let (status, response) = wrong.finish(Some(&mut print_writer));
    assert_rejection(
        status,
        &response,
        Operation::EgressFinish,
        InnerError::WriterKindMismatch,
    );
    assert!(print_writer.is_used());

    let mut early = Harness::open();
    let mut writer = MockOutputWriter::new(Sink::Sd);
    let (status, response) = early.operation(
        &egress_begin(Sink::Sd, Artifact::RawTransaction, payload.len(), &aux),
        Some(&mut writer),
    );
    assert_rejection(
        status,
        &response,
        Operation::EgressBegin,
        InnerError::UnexpectedBoundary,
    );
    assert!(writer.is_used());
}

#[test]
fn filename_grammar_is_exact_and_artifact_bound() {
    let invalid: [(Artifact, &[u8]); 8] = [
        (
            Artifact::FinalizedPsbt,
            b"qk-0123456789abcdef0123456789abcde-final.psbt",
        ),
        (
            Artifact::FinalizedPsbt,
            b"qk-0123456789abcdef0123456789abcdefg-final.psbt",
        ),
        (
            Artifact::FinalizedPsbt,
            b"qk-0123456789ABCDEF0123456789ABCDEF-final.psbt",
        ),
        (
            Artifact::FinalizedPsbt,
            b"xk-0123456789abcdef0123456789abcdef-final.psbt",
        ),
        (
            Artifact::FinalizedPsbt,
            b"qk-0123456789abcdef0123456789abcdef-final.tx",
        ),
        (
            Artifact::RawTransaction,
            b"qk-0123456789abcdef0123456789abcdef-final.psbt",
        ),
        (
            Artifact::WatchOnlyBsms,
            b"qk-0123456789abcdef0123456789abcdef-watch.BSMS",
        ),
        (
            Artifact::WatchOnlyBsms,
            b"qk-0123456789abcdef0123456789abcdef/watch.bsms",
        ),
    ];
    for (artifact, name) in invalid {
        let mut harness = Harness::open();
        let (status, response) =
            harness.operation(&egress_begin(Sink::Sd, artifact, 1, &sd_aux(name)), None);
        assert_rejection(
            status,
            &response,
            Operation::EgressBegin,
            InnerError::InvalidFilename,
        );
    }

    for aux in [&[][..], &[0][..], &[2, b'x'][..], &[1, b'x', b'y'][..]] {
        let mut harness = Harness::open();
        let (status, response) = harness.operation(
            &egress_begin(Sink::Sd, Artifact::RawTransaction, 1, aux),
            None,
        );
        assert_rejection(
            status,
            &response,
            Operation::EgressBegin,
            InnerError::InvalidFilename,
        );
    }
}

#[test]
fn every_sink_artifact_cross_product_outside_the_allowlist_rejects() {
    let sinks = [Sink::Sd, Sink::Bbqr, Sink::Print];
    let artifacts = [
        Artifact::FinalizedPsbt,
        Artifact::RawTransaction,
        Artifact::WatchOnlyBsms,
        Artifact::A1PrintArtifact,
        Artifact::KitPrintArtifact,
    ];
    for sink in sinks {
        for artifact in artifacts {
            let allowed = matches!(
                (sink, artifact),
                (
                    Sink::Sd,
                    Artifact::FinalizedPsbt | Artifact::RawTransaction | Artifact::WatchOnlyBsms
                ) | (
                    Sink::Bbqr,
                    Artifact::FinalizedPsbt | Artifact::RawTransaction
                ) | (
                    Sink::Print,
                    Artifact::A1PrintArtifact | Artifact::KitPrintArtifact
                )
            );
            if allowed {
                continue;
            }
            let mut harness = Harness::open();
            let (status, response) = harness.operation(&egress_begin(sink, artifact, 1, &[]), None);
            assert_rejection(
                status,
                &response,
                Operation::EgressBegin,
                InnerError::SinkArtifactMismatch,
            );
        }
    }
}

#[test]
fn declared_length_and_bbqr_part_geometry_boundaries_are_named() {
    let name = b"qk-0123456789abcdef0123456789abcdef-final.tx";
    let aux = sd_aux(name);
    for (length, expected) in [
        (0usize, InnerError::DeclaredLengthZero),
        (MAX_TRANSFER_BYTES + 1, InnerError::DeclaredLengthExceeded),
    ] {
        let mut harness = Harness::open();
        let (status, response) = harness.operation(
            &egress_begin(Sink::Sd, Artifact::RawTransaction, length, &aux),
            None,
        );
        assert_rejection(status, &response, Operation::EgressBegin, expected);
    }

    for part_len in [0u16, 4, 6, 2_681] {
        let mut harness = Harness::open();
        let (status, response) = harness.operation(
            &egress_begin(Sink::Bbqr, Artifact::FinalizedPsbt, 10, &bbqr_aux(part_len)),
            None,
        );
        assert_rejection(
            status,
            &response,
            Operation::EgressBegin,
            InnerError::InvalidBbqrPartLength,
        );
    }

    let mut too_many_parts = Harness::open();
    let (status, response) = too_many_parts.operation(
        &egress_begin(Sink::Bbqr, Artifact::FinalizedPsbt, 1_281, &bbqr_aux(5)),
        None,
    );
    assert_rejection(
        status,
        &response,
        Operation::EgressBegin,
        InnerError::Bbqr(qk_bbqr::BbqrError::TooManyParts),
    );

    let mut over_bbqr = Harness::open();
    let (status, response) = over_bbqr.operation(
        &egress_begin(
            Sink::Bbqr,
            Artifact::FinalizedPsbt,
            MAX_TOTAL_DECODED_BYTES + 1,
            &bbqr_aux(1_025),
        ),
        None,
    );
    assert_rejection(
        status,
        &response,
        Operation::EgressBegin,
        InnerError::DeclaredLengthExceeded,
    );
}

#[test]
fn chunk_zero_cap_offset_overrun_and_incomplete_finish_are_closed() {
    let payload = [0x5au8; 17];

    let mut zero = Harness::open();
    zero.begin(Sink::Print, Artifact::A1PrintArtifact, payload.len(), &[]);
    let (status, response) = zero.operation(&egress_write(0, &[]), None);
    assert_rejection(
        status,
        &response,
        Operation::EgressWrite,
        InnerError::ChunkLengthZero,
    );

    let mut over_cap = Harness::open();
    over_cap.begin(
        Sink::Print,
        Artifact::A1PrintArtifact,
        MAX_CHUNK_BYTES + 1,
        &[],
    );
    let oversized = vec![0x6b; MAX_CHUNK_BYTES + 1];
    let (status, response) = over_cap.operation(&egress_write(0, &oversized), None);
    assert_rejection(
        status,
        &response,
        Operation::EgressWrite,
        InnerError::ChunkLengthExceeded,
    );

    let mut offset = Harness::open();
    offset.begin(Sink::Print, Artifact::A1PrintArtifact, payload.len(), &[]);
    let (status, response) = offset.operation(&egress_write(1, &payload[..1]), None);
    assert_rejection(
        status,
        &response,
        Operation::EgressWrite,
        InnerError::OffsetMismatch,
    );

    let mut overrun = Harness::open();
    overrun.begin(
        Sink::Print,
        Artifact::A1PrintArtifact,
        payload.len() - 1,
        &[],
    );
    let (status, response) = overrun.operation(&egress_write(0, &payload), None);
    assert_rejection(
        status,
        &response,
        Operation::EgressWrite,
        InnerError::TransferLengthExceeded,
    );

    let mut incomplete = Harness::open();
    incomplete.begin(Sink::Print, Artifact::A1PrintArtifact, payload.len(), &[]);
    incomplete.write(0, &payload[..4]);
    let mut writer = MockOutputWriter::new(Sink::Print);
    let (status, response) = incomplete.finish(Some(&mut writer));
    assert_rejection(
        status,
        &response,
        Operation::EgressFinish,
        InnerError::TransferIncomplete,
    );
    assert!(writer.is_used(), "rejected boundary is consumed");
    assert!(writer.final_bytes().is_none());
}

#[test]
fn maximum_sd_transfer_is_exactly_eight_deterministic_chunks() {
    let name = b"qk-0123456789abcdef0123456789abcdef-final.psbt";
    let aux = sd_aux(name);
    let payload: Vec<u8> = (0..MAX_TRANSFER_BYTES)
        .map(|index| (index as u8).wrapping_mul(29).wrapping_add(7))
        .collect();
    let mut harness = Harness::open();
    harness.begin(Sink::Sd, Artifact::FinalizedPsbt, payload.len(), &aux);
    for (index, chunk) in payload.chunks(MAX_CHUNK_BYTES).enumerate() {
        assert_eq!(chunk.len(), MAX_CHUNK_BYTES);
        harness.write(index * MAX_CHUNK_BYTES, chunk);
    }
    let mut writer = MockOutputWriter::new(Sink::Sd);
    let (status, response) = harness.finish(Some(&mut writer));
    assert_eq!(status, ReplyStatus::Success(Operation::EgressFinish));
    assert_success(
        &response,
        Operation::EgressFinish,
        &receipt(Sink::Sd, Artifact::FinalizedPsbt, payload.len()),
    );
    assert_eq!(writer.final_name(), Some(name.as_slice()));
    assert_eq!(writer.final_bytes(), Some(payload.as_slice()));
}

#[test]
fn bbqr_p_and_t_batches_tie_to_direct_encoding_and_reassembly() {
    let cases = [
        (
            Artifact::FinalizedPsbt,
            BbqrFileType::Psbt,
            b'P',
            4_013usize,
        ),
        (
            Artifact::RawTransaction,
            BbqrFileType::Transaction,
            b'T',
            6_019usize,
        ),
    ];
    let part_len = 1_000u16;

    for (artifact, file_type, file_type_byte, payload_len) in cases {
        let payload: Vec<u8> = (0..payload_len)
            .map(|index| (index as u8).wrapping_mul(17).wrapping_add(0x23))
            .collect();
        let mut harness = Harness::open();
        harness.begin(Sink::Bbqr, artifact, payload.len(), &bbqr_aux(part_len));
        let split = payload.len().min(MAX_CHUNK_BYTES) / 2;
        harness.write(0, &payload[..split]);
        harness.write(split, &payload[split..]);
        let (status, response) = harness.finish(None);
        assert_eq!(status, ReplyStatus::Success(Operation::EgressFinish));
        assert_eq!(response.opcode, Operation::EgressFinish.wire_value());
        assert_eq!(response.status, 0);

        let body = &response.body;
        assert!(body.len() >= 8);
        assert_eq!(body[0], Sink::Bbqr.wire_value());
        assert_eq!(body[1], artifact.wire_value());
        assert_eq!(
            u32::from_le_bytes([body[2], body[3], body[4], body[5]]) as usize,
            payload.len()
        );
        let frame_count = u16::from_le_bytes([body[6], body[7]]);
        assert_eq!(
            frame_count,
            encoded_part_count(payload.len(), usize::from(part_len)).expect("part count")
        );

        let mut assembled = [0u8; MAX_TOTAL_DECODED_BYTES];
        let mut reassembler = Reassembler::new_typed(file_type, &mut assembled);
        let mut cursor = 8usize;
        for index in 0..frame_count {
            assert!(cursor + 2 <= body.len());
            let frame_len = u16::from_le_bytes([body[cursor], body[cursor + 1]]) as usize;
            cursor += 2;
            assert!((9..=MAX_FRAME_TEXT_BYTES).contains(&frame_len));
            assert!(cursor + frame_len <= body.len());
            let frame = &body[cursor..cursor + frame_len];
            cursor += frame_len;
            assert_eq!(&frame[..3], b"B$2");
            assert_eq!(frame[3], file_type_byte);

            let mut direct = [0u8; MAX_FRAME_TEXT_BYTES];
            let direct_len = encode_typed_frame(
                file_type,
                &payload,
                usize::from(part_len),
                index,
                &mut direct,
            )
            .expect("direct frame");
            assert_eq!(frame, &direct[..direct_len]);

            let progress = reassembler.submit(frame).expect("reassemble emitted frame");
            assert_eq!(progress.received_parts, index + 1);
            assert_eq!(progress.complete, index + 1 == frame_count);
        }
        assert_eq!(cursor, body.len(), "no byte outside the registered batch");
        assert_eq!(reassembler.payload().expect("complete payload"), payload);
        assert_eq!(harness.broker.state(), BrokerState::Idle);
    }
}

#[test]
fn bbqr_finish_rejects_an_injected_writer_and_consumes_it() {
    let payload = b"bbqr-writer-confusion";
    let mut harness = Harness::open();
    harness.begin(
        Sink::Bbqr,
        Artifact::RawTransaction,
        payload.len(),
        &bbqr_aux(20),
    );
    harness.write(0, payload);
    let mut writer = MockOutputWriter::new(Sink::Sd);
    let (status, response) = harness.finish(Some(&mut writer));
    assert_rejection(
        status,
        &response,
        Operation::EgressFinish,
        InnerError::UnexpectedBoundary,
    );
    assert!(writer.is_used());
    assert!(writer.final_bytes().is_none());
}
