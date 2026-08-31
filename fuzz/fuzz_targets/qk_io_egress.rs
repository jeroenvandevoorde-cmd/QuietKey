#![no_main]

use libfuzzer_sys::fuzz_target;
use qk_bbqr::{
    BbqrError, BbqrFileType, Reassembler, MAX_PART_DECODED_BYTES, MAX_TOTAL_DECODED_BYTES,
};
use qk_io::{
    reset_wiped_bytes, wiped_bytes, BrokerError, BrokerSession, BrokerState, InnerError,
    MockOutputWriter, Operation, OutputFault, ReplyStatus, Sink, INNER_HEADER_BYTES, INNER_VERSION,
    MAX_CHUNK_BYTES, MAX_FILENAME_BYTES, MAX_INNER_BODY_BYTES, MAX_TRANSFER_BYTES,
};
use qk_ipc::{
    encode_frame, parse_frame, Direction, IpcError, MessageKind, ReceivedFrame, StreamDecoder,
    HEADER_BYTES,
};

const MAX_PRESENTED_BYTES: usize = 16_384;
const SESSION_ID: [u8; 16] = *b"qk-io-egress-v1!";

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum RefSink {
    Sd,
    Bbqr,
    Print,
}

impl RefSink {
    fn parse(value: u8) -> Result<Self, InnerError> {
        match value {
            1 => Ok(Self::Sd),
            2 => Ok(Self::Bbqr),
            3 => Ok(Self::Print),
            _ => Err(InnerError::SinkOutOfRange),
        }
    }

    const fn wire(self) -> u8 {
        match self {
            Self::Sd => 1,
            Self::Bbqr => 2,
            Self::Print => 3,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum RefArtifact {
    Psbt,
    Transaction,
    WatchOnly,
    A1Print,
    KitPrint,
}

impl RefArtifact {
    fn parse(value: u8) -> Result<Self, InnerError> {
        match value {
            1 => Ok(Self::Psbt),
            2 => Ok(Self::Transaction),
            3 => Ok(Self::WatchOnly),
            4 => Ok(Self::A1Print),
            5 => Ok(Self::KitPrint),
            _ => Err(InnerError::ArtifactOutOfRange),
        }
    }

    const fn wire(self) -> u8 {
        match self {
            Self::Psbt => 1,
            Self::Transaction => 2,
            Self::WatchOnly => 3,
            Self::A1Print => 4,
            Self::KitPrint => 5,
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct RefTransfer {
    sink: RefSink,
    artifact: RefArtifact,
    total_len: usize,
    offset: usize,
    filename: Vec<u8>,
    part_len: usize,
    bytes: Vec<u8>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum RefState {
    Idle,
    Egress,
    Error,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct RefWriter {
    sink: RefSink,
    fault: u8,
    used: bool,
    temporary: Option<Vec<u8>>,
    final_bytes: Option<Vec<u8>>,
    final_name: Option<Vec<u8>>,
}

impl RefWriter {
    fn new(sink: RefSink, fault: u8) -> Self {
        Self {
            sink,
            fault: fault % 10,
            used: false,
            temporary: None,
            final_bytes: None,
            final_name: None,
        }
    }

    fn discard(&mut self) {
        self.used = true;
    }

    fn write_sd(&mut self, name: &[u8], bytes: &[u8]) -> Result<(), InnerError> {
        if self.used {
            return Err(InnerError::WriterAlreadyUsed);
        }
        self.used = true;
        if self.sink != RefSink::Sd {
            return Err(InnerError::WriterKindMismatch);
        }
        match self.fault {
            1 => return Err(InnerError::OutputCollision),
            2 => return Err(InnerError::OutputCreateFailed),
            _ => {}
        }
        self.temporary = Some(bytes.to_vec());
        match self.fault {
            3 => return Err(InnerError::OutputWriteFailed),
            4 => return Err(InnerError::OutputSyncFailed),
            5 => return Err(InnerError::OutputCloseFailed),
            6 => return Err(InnerError::OutputReopenFailed),
            7 => {
                if let Some(first) = self.temporary.as_mut().and_then(|value| value.first_mut()) {
                    *first ^= 1;
                }
                return Err(InnerError::OutputReadbackMismatch);
            }
            8 => return Err(InnerError::OutputRenameFailed),
            _ => {}
        }
        self.final_name = Some(name.to_vec());
        self.final_bytes = self.temporary.take();
        Ok(())
    }

    fn write_print(&mut self, bytes: &[u8]) -> Result<(), InnerError> {
        if self.used {
            return Err(InnerError::WriterAlreadyUsed);
        }
        self.used = true;
        if self.sink != RefSink::Print {
            return Err(InnerError::WriterKindMismatch);
        }
        if self.fault != 0 {
            return Err(InnerError::PrintFailed);
        }
        self.final_bytes = Some(bytes.to_vec());
        Ok(())
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
enum RefRequest<'a> {
    IngressBegin,
    IngressRead,
    EgressBegin {
        sink: RefSink,
        artifact: RefArtifact,
        total_len: usize,
        aux: &'a [u8],
    },
    EgressWrite {
        offset: usize,
        chunk: &'a [u8],
    },
    EgressFinish,
}

impl RefRequest<'_> {
    const fn opcode(&self) -> u8 {
        match self {
            Self::IngressBegin => 1,
            Self::IngressRead => 2,
            Self::EgressBegin { .. } => 3,
            Self::EgressWrite { .. } => 4,
            Self::EgressFinish => 5,
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct Reference {
    state: RefState,
    transfer: Option<RefTransfer>,
    maximum_owned: usize,
}

impl Reference {
    fn new() -> Self {
        Self {
            state: RefState::Idle,
            transfer: None,
            maximum_owned: 0,
        }
    }

    fn apply(
        &mut self,
        bytes: &[u8],
        writer: Option<&mut RefWriter>,
    ) -> Result<Vec<u8>, BrokerError> {
        if self.state == RefState::Error {
            if let Some(writer) = writer {
                writer.discard();
            }
            return Err(BrokerError::BrokerTerminated);
        }
        let raw_opcode = bytes.get(1).copied().unwrap_or(0);
        let request = match reference_parse(bytes) {
            Ok(request) => request,
            Err(error) => return Ok(self.reject(raw_opcode, error, writer)),
        };
        let opcode = request.opcode();
        match self.dispatch(request, writer) {
            Ok(body) => Ok(response(opcode, 0, &body)),
            Err((error, writer)) => Ok(self.reject(opcode, error, writer)),
        }
    }

    fn dispatch<'a>(
        &mut self,
        request: RefRequest<'_>,
        writer: Option<&'a mut RefWriter>,
    ) -> Result<Vec<u8>, (InnerError, Option<&'a mut RefWriter>)> {
        match request {
            RefRequest::IngressBegin => {
                if self.state != RefState::Idle {
                    Err((InnerError::ActiveTransfer, writer))
                } else if writer.is_some() {
                    Err((InnerError::UnexpectedBoundary, writer))
                } else {
                    Err((InnerError::BoundaryMissing, writer))
                }
            }
            RefRequest::IngressRead => {
                if writer.is_some() {
                    Err((InnerError::UnexpectedBoundary, writer))
                } else if self.state == RefState::Egress {
                    Err((InnerError::WrongTransferDirection, writer))
                } else {
                    Err((InnerError::NoActiveTransfer, writer))
                }
            }
            RefRequest::EgressBegin {
                sink,
                artifact,
                total_len,
                aux,
            } => {
                if self.state != RefState::Idle {
                    return Err((InnerError::ActiveTransfer, writer));
                }
                if writer.is_some() {
                    return Err((InnerError::UnexpectedBoundary, writer));
                }
                let transfer = reference_begin(sink, artifact, total_len, aux)
                    .map_err(|error| (error, writer))?;
                self.maximum_owned = self.maximum_owned.max(total_len);
                self.state = RefState::Egress;
                self.transfer = Some(transfer);
                Ok(Vec::new())
            }
            RefRequest::EgressWrite { offset, chunk } => {
                if writer.is_some() {
                    return Err((InnerError::UnexpectedBoundary, writer));
                }
                let Some(transfer) = self.transfer.as_mut() else {
                    return Err((InnerError::NoActiveTransfer, writer));
                };
                if chunk.is_empty() {
                    return Err((InnerError::ChunkLengthZero, writer));
                }
                if chunk.len() > MAX_CHUNK_BYTES {
                    return Err((InnerError::ChunkLengthExceeded, writer));
                }
                if offset != transfer.offset {
                    return Err((InnerError::OffsetMismatch, writer));
                }
                let Some(end) = offset.checked_add(chunk.len()) else {
                    return Err((InnerError::TransferLengthExceeded, writer));
                };
                if end > transfer.total_len {
                    return Err((InnerError::TransferLengthExceeded, writer));
                }
                transfer.bytes[offset..end].copy_from_slice(chunk);
                transfer.offset = end;
                Ok((end as u32).to_le_bytes().to_vec())
            }
            RefRequest::EgressFinish => {
                let Some(transfer) = self.transfer.take() else {
                    return Err((InnerError::NoActiveTransfer, writer));
                };
                self.state = RefState::Idle;
                if transfer.offset != transfer.total_len {
                    return Err((InnerError::TransferIncomplete, writer));
                }
                match transfer.sink {
                    RefSink::Sd => {
                        let Some(writer) = writer else {
                            return Err((InnerError::BoundaryMissing, None));
                        };
                        writer
                            .write_sd(&transfer.filename, &transfer.bytes)
                            .map_err(|error| (error, Some(writer)))?;
                        Ok(receipt(&transfer))
                    }
                    RefSink::Print => {
                        let Some(writer) = writer else {
                            return Err((InnerError::BoundaryMissing, None));
                        };
                        writer
                            .write_print(&transfer.bytes)
                            .map_err(|error| (error, Some(writer)))?;
                        Ok(receipt(&transfer))
                    }
                    RefSink::Bbqr => {
                        if writer.is_some() {
                            return Err((InnerError::UnexpectedBoundary, writer));
                        }
                        reference_bbqr(&transfer).map_err(|error| (error, None))
                    }
                }
            }
        }
    }

    fn reject(&mut self, opcode: u8, error: InnerError, writer: Option<&mut RefWriter>) -> Vec<u8> {
        if let Some(writer) = writer {
            writer.discard();
        }
        assert_named(error);
        self.state = RefState::Error;
        self.transfer = None;
        response(opcode, error.status_code(), &[])
    }
}

fn reference_parse(bytes: &[u8]) -> Result<RefRequest<'_>, InnerError> {
    if bytes.len() < INNER_HEADER_BYTES {
        return Err(InnerError::InnerHeaderTruncated);
    }
    if bytes[0] != INNER_VERSION {
        return Err(InnerError::InnerVersionMismatch);
    }
    if bytes[2] != 0 || bytes[3] != 0 {
        return Err(InnerError::RequestReservedNonZero);
    }
    let opcode = bytes[1];
    if !(1..=5).contains(&opcode) {
        return Err(InnerError::OperationOutOfRange);
    }
    let body_len = le_u32(&bytes[4..8]) as usize;
    if body_len > MAX_INNER_BODY_BYTES {
        return Err(InnerError::BodyLengthExceeded);
    }
    let Some(end) = INNER_HEADER_BYTES.checked_add(body_len) else {
        return Err(InnerError::BodyLengthExceeded);
    };
    if bytes.len() < end {
        return Err(InnerError::BodyTruncated);
    }
    if bytes.len() > end {
        return Err(InnerError::TrailingByte);
    }
    let body = &bytes[INNER_HEADER_BYTES..];
    match opcode {
        1 => {
            if body.len() < 3 {
                return Err(InnerError::BodyTruncated);
            }
            if !(1..=4).contains(&body[0]) {
                return Err(InnerError::SourceOutOfRange);
            }
            exact_tail(body, 3, usize::from(u16::from_le_bytes([body[1], body[2]])))?;
            Ok(RefRequest::IngressBegin)
        }
        2 => {
            exact_length(body, 4)?;
            Ok(RefRequest::IngressRead)
        }
        3 => {
            if body.len() < 8 {
                return Err(InnerError::BodyTruncated);
            }
            let sink = RefSink::parse(body[0])?;
            let artifact = RefArtifact::parse(body[1])?;
            let total_len = le_u32(&body[2..6]) as usize;
            let aux = exact_tail(body, 8, usize::from(u16::from_le_bytes([body[6], body[7]])))?;
            Ok(RefRequest::EgressBegin {
                sink,
                artifact,
                total_len,
                aux,
            })
        }
        4 => {
            if body.len() < 8 {
                return Err(InnerError::BodyTruncated);
            }
            let offset = le_u32(&body[..4]) as usize;
            let chunk = exact_tail(body, 8, le_u32(&body[4..8]) as usize)?;
            Ok(RefRequest::EgressWrite { offset, chunk })
        }
        5 => {
            exact_length(body, 0)?;
            Ok(RefRequest::EgressFinish)
        }
        _ => unreachable!(),
    }
}

fn exact_tail(bytes: &[u8], start: usize, length: usize) -> Result<&[u8], InnerError> {
    let Some(end) = start.checked_add(length) else {
        return Err(InnerError::BodyLengthExceeded);
    };
    if bytes.len() < end {
        Err(InnerError::BodyTruncated)
    } else if bytes.len() > end {
        Err(InnerError::TrailingByte)
    } else {
        Ok(&bytes[start..end])
    }
}

fn exact_length(bytes: &[u8], length: usize) -> Result<(), InnerError> {
    if bytes.len() < length {
        Err(InnerError::BodyTruncated)
    } else if bytes.len() > length {
        Err(InnerError::TrailingByte)
    } else {
        Ok(())
    }
}

fn reference_begin(
    sink: RefSink,
    artifact: RefArtifact,
    total_len: usize,
    aux: &[u8],
) -> Result<RefTransfer, InnerError> {
    let valid = matches!(
        (sink, artifact),
        (
            RefSink::Sd,
            RefArtifact::Psbt | RefArtifact::Transaction | RefArtifact::WatchOnly
        ) | (RefSink::Bbqr, RefArtifact::Psbt | RefArtifact::Transaction)
            | (RefSink::Print, RefArtifact::A1Print | RefArtifact::KitPrint)
    );
    if !valid {
        return Err(InnerError::SinkArtifactMismatch);
    }
    if total_len == 0 {
        return Err(InnerError::DeclaredLengthZero);
    }
    let cap = if sink == RefSink::Bbqr {
        MAX_TOTAL_DECODED_BYTES
    } else {
        MAX_TRANSFER_BYTES
    };
    if total_len > cap {
        return Err(InnerError::DeclaredLengthExceeded);
    }
    let (filename, part_len) = match sink {
        RefSink::Sd => {
            let length = aux.first().copied().map(usize::from).unwrap_or(0);
            if length == 0 || length > MAX_FILENAME_BYTES || aux.len() != length + 1 {
                return Err(InnerError::InvalidFilename);
            }
            let name = &aux[1..];
            if !valid_filename(artifact, name) {
                return Err(InnerError::InvalidFilename);
            }
            (name.to_vec(), 0)
        }
        RefSink::Bbqr => {
            if aux.len() < 2 {
                return Err(InnerError::BodyTruncated);
            }
            if aux.len() > 2 {
                return Err(InnerError::TrailingByte);
            }
            let part_len = usize::from(u16::from_le_bytes([aux[0], aux[1]]));
            if !(5..=MAX_PART_DECODED_BYTES).contains(&part_len) || part_len % 5 != 0 {
                return Err(InnerError::InvalidBbqrPartLength);
            }
            if total_len.div_ceil(part_len) > 256 {
                return Err(InnerError::Bbqr(BbqrError::TooManyParts));
            }
            (Vec::new(), part_len)
        }
        RefSink::Print => {
            if !aux.is_empty() {
                return Err(InnerError::TrailingByte);
            }
            (Vec::new(), 0)
        }
    };
    Ok(RefTransfer {
        sink,
        artifact,
        total_len,
        offset: 0,
        filename,
        part_len,
        bytes: vec![0; total_len],
    })
}

fn valid_filename(artifact: RefArtifact, name: &[u8]) -> bool {
    let suffix: &[u8] = match artifact {
        RefArtifact::Psbt => b"-final.psbt",
        RefArtifact::Transaction => b"-final.tx",
        RefArtifact::WatchOnly => b"-watch.bsms",
        RefArtifact::A1Print | RefArtifact::KitPrint => return false,
    };
    name.len() == 35 + suffix.len()
        && name.starts_with(b"qk-")
        && name[3..35]
            .iter()
            .all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f'))
        && name[35..] == *suffix
}

fn receipt(transfer: &RefTransfer) -> Vec<u8> {
    let mut body = vec![transfer.sink.wire(), transfer.artifact.wire()];
    body.extend_from_slice(&(transfer.total_len as u32).to_le_bytes());
    body
}

fn reference_bbqr(transfer: &RefTransfer) -> Result<Vec<u8>, InnerError> {
    let count = transfer.total_len.div_ceil(transfer.part_len);
    if count > 256 {
        return Err(InnerError::Bbqr(BbqrError::TooManyParts));
    }
    let mut body = receipt(transfer);
    body.extend_from_slice(&(count as u16).to_le_bytes());
    for index in 0..count {
        let start = index * transfer.part_len;
        let end = transfer.total_len.min(start + transfer.part_len);
        let mut frame = Vec::new();
        frame.extend_from_slice(b"B$2");
        frame.push(match transfer.artifact {
            RefArtifact::Psbt => b'P',
            RefArtifact::Transaction => b'T',
            _ => return Err(InnerError::SinkArtifactMismatch),
        });
        base36_pair(count as u16, &mut frame);
        base36_pair(index as u16, &mut frame);
        reference_base32(&transfer.bytes[start..end], &mut frame);
        body.extend_from_slice(&(frame.len() as u16).to_le_bytes());
        body.extend_from_slice(&frame);
    }
    Ok(body)
}

fn base36_pair(value: u16, output: &mut Vec<u8>) {
    fn digit(value: u16) -> u8 {
        match value {
            0..=9 => b'0' + value as u8,
            _ => b'A' + (value - 10) as u8,
        }
    }
    output.push(digit(value / 36));
    output.push(digit(value % 36));
}

fn reference_base32(bytes: &[u8], output: &mut Vec<u8>) {
    const ALPHABET: &[u8; 32] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
    let mut accumulator = 0u16;
    let mut bits = 0usize;
    for byte in bytes {
        accumulator = (accumulator << 8) | u16::from(*byte);
        bits += 8;
        while bits >= 5 {
            bits -= 5;
            output.push(ALPHABET[usize::from((accumulator >> bits) & 31)]);
            accumulator &= (1u16 << bits).wrapping_sub(1);
        }
    }
    if bits != 0 {
        output.push(ALPHABET[usize::from((accumulator << (5 - bits)) & 31)]);
    }
}

fn response(opcode: u8, status: u16, body: &[u8]) -> Vec<u8> {
    let mut output = vec![INNER_VERSION, opcode];
    output.extend_from_slice(&status.to_le_bytes());
    output.extend_from_slice(&(body.len() as u32).to_le_bytes());
    output.extend_from_slice(body);
    output
}

fn le_u32(bytes: &[u8]) -> u32 {
    u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]])
}

struct Actual {
    broker: BrokerSession,
    exchange: u32,
    transcript: u64,
}

impl Actual {
    fn open() -> Self {
        let mut broker = BrokerSession::new();
        let request = received(MessageKind::SessionOpen, 1, &[]);
        let reply = broker.accept(&request, None, None).expect("valid opening");
        assert_eq!(reply.status(), ReplyStatus::Control);
        let frame = parse_frame(reply.frame_bytes()).expect("valid opening reply");
        assert_eq!(frame.header().direction(), Direction::IoToCore);
        assert_eq!(frame.header().kind(), MessageKind::SessionReady);
        assert_eq!(frame.header().session_id(), &SESSION_ID);
        assert_eq!(frame.header().exchange_id(), 1);
        assert!(frame.payload().is_empty());
        Self {
            broker,
            exchange: 2,
            transcript: fold(0, reply.frame_bytes()),
        }
    }

    fn apply(
        &mut self,
        payload: &[u8],
        writer: Option<&mut MockOutputWriter>,
    ) -> Result<(Vec<u8>, ReplyStatus), BrokerError> {
        let request = received(MessageKind::OperationRequest, self.exchange, payload);
        let result = self.broker.accept(&request, None, writer);
        self.exchange = self.exchange.saturating_add(1);
        match result {
            Ok(reply) => {
                let outer = parse_frame(reply.frame_bytes()).expect("broker emitted valid QKIP");
                assert_eq!(outer.header().direction(), Direction::IoToCore);
                assert_eq!(outer.header().kind(), MessageKind::OperationResponse);
                assert_eq!(outer.header().session_id(), &SESSION_ID);
                assert_eq!(outer.header().exchange_id(), self.exchange - 1);
                self.transcript = fold(self.transcript, reply.frame_bytes());
                Ok((outer.payload().to_vec(), reply.status()))
            }
            Err(error) => Err(error),
        }
    }
}

fn received(kind: MessageKind, exchange: u32, payload: &[u8]) -> ReceivedFrame {
    let mut bytes = vec![0u8; HEADER_BYTES + payload.len()];
    let length = encode_frame(
        Direction::CoreToIo,
        kind,
        SESSION_ID,
        exchange,
        payload,
        &mut bytes,
    )
    .expect("bounded QKIP request");
    let mut decoder = StreamDecoder::new();
    let outcome = decoder
        .ingest(&bytes[..length], false)
        .expect("encoded frame decodes");
    assert_eq!(outcome.consumed(), length);
    assert!(outcome.frame_ready());
    decoder.take_frame().expect("complete frame")
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct Outcome {
    transcript: u64,
    state: RefState,
    writer_used: bool,
    temporary: Option<Vec<u8>>,
    final_bytes: Option<Vec<u8>>,
    final_name: Option<Vec<u8>>,
    wiped: usize,
}

fn execute(data: &[u8]) -> Outcome {
    reset_wiped_bytes();
    let mut reference = Reference::new();
    let mut actual = Actual::open();

    let sink_byte = control(data, 0);
    let artifact_byte = control(data, 1);
    let total = selected_total(data, sink_byte);
    let payload = patterned_bytes(data, total.min(MAX_PRESENTED_BYTES));
    let mut begin = begin_request(data, sink_byte, artifact_byte, total);

    let writer_sink = match control(data, 7) % 3 {
        0 => RefSink::Sd,
        1 => RefSink::Bbqr,
        _ => RefSink::Print,
    };
    let fault = control(data, 5) % 10;
    let mut ref_writer = RefWriter::new(writer_sink, fault);
    let mut writer =
        MockOutputWriter::with_fault(production_sink(writer_sink), production_fault(fault));

    let begin_boundary = control(data, 10) % 7 == 6;
    if !step(
        &mut reference,
        &mut actual,
        &begin,
        begin_boundary.then_some(&mut ref_writer),
        begin_boundary.then_some(&mut writer),
        None,
    ) {
        return finish_outcome(reference, actual, ref_writer, writer);
    }

    let write_mode = control(data, 4) % 9;
    let chunks = make_writes(write_mode, &payload, total, data);
    for (index, request) in chunks.iter().enumerate() {
        let pass_writer = write_mode == 6 && index == 0;
        if !step(
            &mut reference,
            &mut actual,
            request,
            pass_writer.then_some(&mut ref_writer),
            pass_writer.then_some(&mut writer),
            None,
        ) {
            return finish_outcome(reference, actual, ref_writer, writer);
        }
    }

    let finish_mode = control(data, 7) % 4;
    let expected_sink = RefSink::parse(sink_byte).ok();
    let pass_writer = match (expected_sink, finish_mode) {
        (Some(RefSink::Bbqr), 0 | 3) => false,
        (Some(RefSink::Bbqr), _) => true,
        (Some(RefSink::Sd | RefSink::Print), 1) => false,
        (Some(RefSink::Sd | RefSink::Print), _) => true,
        (None, _) => false,
    };
    if !step(
        &mut reference,
        &mut actual,
        &plain_request(5, &[]),
        pass_writer.then_some(&mut ref_writer),
        pass_writer.then_some(&mut writer),
        Some(&payload),
    ) {
        return finish_outcome(reference, actual, ref_writer, writer);
    }

    if control(data, 8) & 1 != 0 && writer.is_used() {
        begin = canonical_begin(sink_byte, artifact_byte, 1, data, true);
        if step(&mut reference, &mut actual, &begin, None, None, None) {
            let one = write_request(0, &[0x5a]);
            if step(&mut reference, &mut actual, &one, None, None, None) {
                let _ = step(
                    &mut reference,
                    &mut actual,
                    &plain_request(5, &[]),
                    Some(&mut ref_writer),
                    Some(&mut writer),
                    None,
                );
            }
        }
    }
    finish_outcome(reference, actual, ref_writer, writer)
}

fn step(
    reference: &mut Reference,
    actual: &mut Actual,
    request: &[u8],
    ref_writer: Option<&mut RefWriter>,
    writer: Option<&mut MockOutputWriter>,
    expected_payload: Option<&[u8]>,
) -> bool {
    let expected = reference.apply(request, ref_writer);
    let observed = actual.apply(request, writer);
    match (expected, observed) {
        (Ok(expected_payload_bytes), Ok((observed_payload, status))) => {
            assert_eq!(observed_payload, expected_payload_bytes);
            let status_code = u16::from_le_bytes([observed_payload[2], observed_payload[3]]);
            if status_code == 0 {
                let operation = match observed_payload[1] {
                    1 => Operation::IngressBegin,
                    2 => Operation::IngressRead,
                    3 => Operation::EgressBegin,
                    4 => Operation::EgressWrite,
                    5 => Operation::EgressFinish,
                    _ => unreachable!(),
                };
                assert_eq!(status, ReplyStatus::Success(operation));
                if operation == Operation::EgressFinish
                    && observed_payload.get(INNER_HEADER_BYTES) == Some(&2)
                {
                    verify_bbqr(
                        &observed_payload[INNER_HEADER_BYTES..],
                        expected_payload.unwrap_or(&[]),
                    );
                }
                true
            } else {
                match status {
                    ReplyStatus::Rejected { opcode, error } => {
                        assert_eq!(opcode, observed_payload[1]);
                        assert_eq!(error.status_code(), status_code);
                        assert_named(error);
                    }
                    _ => panic!("rejection status mismatch"),
                }
                assert_eq!(actual.broker.state(), BrokerState::ErrorReplyPending);
                let terminal = actual.apply(&plain_request(5, &[]), None);
                assert_eq!(terminal, Err(BrokerError::BrokerTerminated));
                false
            }
        }
        (Err(expected_error), Err(observed_error)) => {
            assert_eq!(observed_error, expected_error);
            false
        }
        (left, right) => panic!("reference/implementation mismatch: {left:?} {right:?}"),
    }
}

fn finish_outcome(
    reference: Reference,
    actual: Actual,
    ref_writer: RefWriter,
    writer: MockOutputWriter,
) -> Outcome {
    let expected_broker_state = match reference.state {
        RefState::Idle => BrokerState::Idle,
        RefState::Egress => BrokerState::EgressReceiving,
        RefState::Error => BrokerState::ErrorReplyPending,
    };
    assert_eq!(actual.broker.state(), expected_broker_state);
    assert_eq!(writer.is_used(), ref_writer.used);
    assert_eq!(writer.temporary_bytes(), ref_writer.temporary.as_deref());
    assert_eq!(writer.final_bytes(), ref_writer.final_bytes.as_deref());
    assert_eq!(writer.final_name(), ref_writer.final_name.as_deref());
    let transcript = actual.transcript;
    let state = reference.state;
    let writer_used = writer.is_used();
    let temporary = writer.temporary_bytes().map(ToOwned::to_owned);
    let final_bytes = writer.final_bytes().map(ToOwned::to_owned);
    let final_name = writer.final_name().map(ToOwned::to_owned);
    let minimum_wipe = reference.maximum_owned;
    drop(actual);
    drop(writer);
    let wiped = wiped_bytes();
    assert!(wiped > 0);
    assert!(wiped >= minimum_wipe);
    Outcome {
        transcript,
        state,
        writer_used,
        temporary,
        final_bytes,
        final_name,
        wiped,
    }
}

fn begin_request(data: &[u8], sink: u8, artifact: u8, total: usize) -> Vec<u8> {
    let shape = control(data, 3) % 8;
    let mut request = canonical_begin(sink, artifact, total, data, shape == 0);
    match shape {
        0 => {}
        1 => {
            let raw = &data.get(12..).unwrap_or(&[])[..data.len().saturating_sub(12).min(64)];
            request = begin_with_aux(sink, artifact, total, raw);
        }
        2 => request.extend_from_slice(b"x"),
        3 => {
            let declared = if control(data, 9) & 1 == 0 {
                le_u32(&request[4..8]).saturating_add(1)
            } else {
                (MAX_INNER_BODY_BYTES as u32).saturating_add(1)
            };
            request[4..8].copy_from_slice(&declared.to_le_bytes());
        }
        4 => request[0] = control(data, 9),
        5 => request[2] = control(data, 9) | 1,
        6 => request[1] = control(data, 9),
        _ => request.truncate(1 + control(data, 9) as usize % request.len()),
    }
    request
}

fn canonical_begin(
    sink: u8,
    artifact: u8,
    total: usize,
    data: &[u8],
    canonical_aux: bool,
) -> Vec<u8> {
    let aux = if canonical_aux {
        match sink {
            1 => filename_aux(artifact, data),
            2 => {
                let parts = [5u16, 10, 20, 60, 2_680];
                parts[usize::from(control(data, 6)) % parts.len()]
                    .to_le_bytes()
                    .to_vec()
            }
            3 => Vec::new(),
            _ => data.get(12..20).unwrap_or(&[]).to_vec(),
        }
    } else {
        data.get(12..20).unwrap_or(&[]).to_vec()
    };
    begin_with_aux(sink, artifact, total, &aux)
}

fn begin_with_aux(sink: u8, artifact: u8, total: usize, aux: &[u8]) -> Vec<u8> {
    let mut body = vec![sink, artifact];
    body.extend_from_slice(&(total as u32).to_le_bytes());
    body.extend_from_slice(&(aux.len() as u16).to_le_bytes());
    body.extend_from_slice(aux);
    plain_request(3, &body)
}

fn filename_aux(artifact: u8, data: &[u8]) -> Vec<u8> {
    let suffix: &[u8] = match artifact {
        1 => b"-final.psbt",
        2 => b"-final.tx",
        3 => b"-watch.bsms",
        _ => b"-invalid",
    };
    let mut name = b"qk-".to_vec();
    const HEX: &[u8; 16] = b"0123456789abcdef";
    for index in 0..32 {
        name.push(HEX[usize::from(input_byte(data, 12 + index) & 15)]);
    }
    name.extend_from_slice(suffix);
    let mut aux = vec![name.len() as u8];
    aux.extend_from_slice(&name);
    aux
}

fn make_writes(mode: u8, payload: &[u8], total: usize, data: &[u8]) -> Vec<Vec<u8>> {
    match mode {
        0 => vec![write_request(0, payload)],
        1 => {
            let split = payload.len() / 2;
            let mut result = Vec::new();
            if split != 0 {
                result.push(write_request(0, &payload[..split]));
            }
            if split < payload.len() {
                result.push(write_request(split, &payload[split..]));
            }
            result
        }
        2 => vec![write_request(0, &[])],
        3 => vec![write_request(1, payload)],
        4 => {
            let mut overrun = payload.to_vec();
            overrun.push(control(data, 11));
            vec![write_request(0, &overrun)]
        }
        5 => {
            let mut request = write_request(0, payload);
            let declared = (request.len() as u32).saturating_add(1);
            request[4..8].copy_from_slice(&declared.to_le_bytes());
            vec![request]
        }
        6 => vec![write_request(0, payload)],
        7 => {
            let take = total
                .min(payload.len())
                .min(1 + usize::from(control(data, 11)));
            vec![write_request(0, &payload[..take])]
        }
        _ => vec![write_request(
            0,
            &vec![control(data, 11); MAX_CHUNK_BYTES + 1],
        )],
    }
}

fn write_request(offset: usize, bytes: &[u8]) -> Vec<u8> {
    let mut body = Vec::with_capacity(8 + bytes.len());
    body.extend_from_slice(&(offset as u32).to_le_bytes());
    body.extend_from_slice(&(bytes.len() as u32).to_le_bytes());
    body.extend_from_slice(bytes);
    plain_request(4, &body)
}

fn plain_request(opcode: u8, body: &[u8]) -> Vec<u8> {
    let mut request = vec![INNER_VERSION, opcode, 0, 0];
    request.extend_from_slice(&(body.len() as u32).to_le_bytes());
    request.extend_from_slice(body);
    request
}

fn selected_total(data: &[u8], sink: u8) -> usize {
    match control(data, 2) % 6 {
        0 => {
            1 + usize::from(u16::from_le_bytes([
                input_byte(data, 10),
                input_byte(data, 11),
            ])) % 4096
        }
        1 => 0,
        2 => {
            if sink == 2 {
                MAX_TOTAL_DECODED_BYTES + 1
            } else {
                MAX_TRANSFER_BYTES + 1
            }
        }
        3 => data.len().saturating_sub(12).max(1),
        4 => 5,
        _ => 2_680,
    }
}

fn patterned_bytes(data: &[u8], length: usize) -> Vec<u8> {
    (0..length)
        .map(|index| input_byte(data, 12 + index).wrapping_add(index as u8))
        .collect()
}

fn control(data: &[u8], index: usize) -> u8 {
    let value = input_byte(data, index);
    if value.is_ascii_digit() {
        value - b'0'
    } else {
        value
    }
}

fn input_byte(data: &[u8], index: usize) -> u8 {
    if data.is_empty() {
        0
    } else {
        data[index % data.len()]
    }
}

fn production_sink(sink: RefSink) -> Sink {
    match sink {
        RefSink::Sd => Sink::Sd,
        RefSink::Bbqr => Sink::Bbqr,
        RefSink::Print => Sink::Print,
    }
}

fn production_fault(value: u8) -> OutputFault {
    match value % 10 {
        0 => OutputFault::None,
        1 => OutputFault::Collision,
        2 => OutputFault::Create,
        3 => OutputFault::Write,
        4 => OutputFault::Sync,
        5 => OutputFault::Close,
        6 => OutputFault::Reopen,
        7 => OutputFault::ReadbackMismatch,
        8 => OutputFault::Rename,
        _ => OutputFault::Print,
    }
}

fn verify_bbqr(body: &[u8], payload: &[u8]) {
    assert!(body.len() >= 8);
    let artifact = body[1];
    let file_type = match artifact {
        1 => BbqrFileType::Psbt,
        2 => BbqrFileType::Transaction,
        _ => panic!("invalid BBQr artifact"),
    };
    let total = le_u32(&body[2..6]) as usize;
    assert_eq!(total, payload.len());
    let count = usize::from(u16::from_le_bytes([body[6], body[7]]));
    let mut cursor = 8usize;
    let mut frames = Vec::with_capacity(count);
    for _ in 0..count {
        assert!(cursor + 2 <= body.len());
        let length = usize::from(u16::from_le_bytes([body[cursor], body[cursor + 1]]));
        cursor += 2;
        assert!(cursor + length <= body.len());
        let frame = &body[cursor..cursor + length];
        let mut direct = [0u8; MAX_PART_DECODED_BYTES];
        qk_bbqr::decode_typed_frame(file_type, frame, &mut direct).expect("direct decode tie");
        frames.push(frame);
        cursor += length;
    }
    assert_eq!(cursor, body.len());
    let mut output = [0u8; MAX_TOTAL_DECODED_BYTES];
    let mut reassembler = Reassembler::new_typed(file_type, &mut output);
    for frame in frames {
        reassembler.submit(frame).expect("reassembly tie");
    }
    assert_eq!(reassembler.payload().expect("complete BBQr"), payload);
}

fn assert_named(error: InnerError) {
    let expected = match error {
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
        InnerError::Bbqr(error) => {
            assert!(!error.to_string().is_empty());
            return;
        }
    };
    assert_eq!(error.to_string(), expected);
}

fn fold(mut state: u64, bytes: &[u8]) -> u64 {
    if state == 0 {
        state = 0xcbf2_9ce4_8422_2325;
    }
    for byte in bytes {
        state ^= u64::from(*byte);
        state = state.wrapping_mul(0x0000_0100_0000_01b3);
    }
    state
}

fn fixed_active_transfer_cleanup() {
    const ACTIVE_BYTES: usize = 257;
    let mut actual = Actual::open();
    let begin = begin_with_aux(
        RefSink::Print.wire(),
        RefArtifact::A1Print.wire(),
        ACTIVE_BYTES,
        &[],
    );
    let (_, begin_status) = actual.apply(&begin, None).expect("fixed egress begin");
    assert_eq!(begin_status, ReplyStatus::Success(Operation::EgressBegin));
    let write = write_request(0, &[0x63; ACTIVE_BYTES]);
    let (_, write_status) = actual.apply(&write, None).expect("fixed egress write");
    assert_eq!(write_status, ReplyStatus::Success(Operation::EgressWrite));
    assert_eq!(actual.broker.state(), BrokerState::EgressReceiving);

    let writer = MockOutputWriter::new(Sink::Print);
    reset_wiped_bytes();
    assert_eq!(
        actual.broker.receive_failed(IpcError::AncillaryData),
        BrokerError::Ipc(IpcError::AncillaryData)
    );
    assert_eq!(actual.broker.state(), BrokerState::Terminated);
    assert_eq!(wiped_bytes(), ACTIVE_BYTES + MAX_FILENAME_BYTES);
    assert!(!writer.is_used());
    assert!(writer.temporary_bytes().is_none());
    assert!(writer.final_bytes().is_none());
    assert!(writer.final_name().is_none());
}

fuzz_target!(|data: &[u8]| {
    fixed_active_transfer_cleanup();
    let bounded = &data[..data.len().min(MAX_PRESENTED_BYTES)];
    let first = execute(bounded);
    let second = execute(bounded);
    assert_eq!(first, second);
});
