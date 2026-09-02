//! QKDV bridge for the four inherited no-secret qk-io device descriptors.
//!
//! Input and output descriptors are opened lazily, so a control-only child
//! touches no device boundary and an unchosen source or route stays closed.
//! Output descriptors are strictly one-way: successful OS delivery is the
//! device-side result and no reverse QKDV channel is invented here.

use crate::wipe::WipingVec;
use crate::{
    parse_request, Artifact, BrokerError, BrokerReply, BrokerSession, BrokerState, InnerError,
    MockInput, MockOutputWriter, Operation, ReplyStatus, Request, Sink, Source, MAX_CHUNK_BYTES,
    MAX_FILENAME_BYTES, MAX_MOCK_INPUT_BYTES,
};
use core::fmt;
use qk_device_wire::{
    BodyRef, Capability, DeviceError, InputBody, InputTransfer, MessageKind, OneWayProtocol,
    OutputBody, OutputTransfer, StreamDecoder, HEADER_BYTES,
};
use qk_ipc::ReceivedFrame;
use std::fs::{File, OpenOptions};
use std::io::{Read, Write};

const CAMERA_INPUT_PATH: &str = "/dev/fd/3";
const MEDIA_INPUT_PATH: &str = "/dev/fd/4";
const PRINT_OUTPUT_PATH: &str = "/dev/fd/5";
const MEDIA_OUTPUT_PATH: &str = "/dev/fd/6";
const DEVICE_READ_BYTES: usize = 1;

/// Closed bridge failure surface. No variant carries transported bytes.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum DeviceProcessError {
    Broker(BrokerError),
    Device(DeviceError),
    Inner(InnerError),
}

impl fmt::Display for DeviceProcessError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Broker(error) => error.fmt(formatter),
            Self::Device(error) => error.fmt(formatter),
            Self::Inner(error) => error.fmt(formatter),
        }
    }
}

impl std::error::Error for DeviceProcessError {}

impl From<BrokerError> for DeviceProcessError {
    fn from(error: BrokerError) -> Self {
        Self::Broker(error)
    }
}

impl From<DeviceError> for DeviceProcessError {
    fn from(error: DeviceError) -> Self {
        Self::Device(error)
    }
}

impl From<InnerError> for DeviceProcessError {
    fn from(error: InnerError) -> Self {
        Self::Inner(error)
    }
}

#[derive(Clone, Copy)]
struct PendingEgress {
    sink: Sink,
    artifact: Artifact,
}

struct InputEndpoint {
    path: &'static str,
    file: Option<File>,
    decoder: StreamDecoder,
}

impl InputEndpoint {
    fn new(capability: Capability, path: &'static str) -> Self {
        Self {
            path,
            file: None,
            decoder: StreamDecoder::new(capability),
        }
    }

    fn read_frame_inner(&mut self) -> Result<qk_device_wire::ReceivedFrame, DeviceError> {
        if self.file.is_none() {
            self.file = Some(
                OpenOptions::new()
                    .read(true)
                    .open(self.path)
                    .map_err(|_| DeviceError::PeerLost)?,
            );
        }
        read_frame_from(
            self.file.as_mut().ok_or(DeviceError::PeerLost)?,
            &mut self.decoder,
        )
    }
}

trait DeviceFrameReader {
    fn read_frame(&mut self) -> Result<qk_device_wire::ReceivedFrame, DeviceError>;
}

impl DeviceFrameReader for InputEndpoint {
    fn read_frame(&mut self) -> Result<qk_device_wire::ReceivedFrame, DeviceError> {
        self.read_frame_inner()
    }
}

struct OutputEndpoint {
    capability: Capability,
    path: &'static str,
    file: Option<File>,
    protocol: OneWayProtocol,
}

impl OutputEndpoint {
    const fn new(capability: Capability, path: &'static str) -> Self {
        Self {
            capability,
            path,
            file: None,
            protocol: OneWayProtocol::new(capability),
        }
    }

    fn write_frame_inner(&mut self, kind: MessageKind, body: &[u8]) -> Result<(), DeviceError> {
        if self.file.is_none() {
            self.file = Some(
                OpenOptions::new()
                    .write(true)
                    .open(self.path)
                    .map_err(|_| DeviceError::PeerLost)?,
            );
        }
        write_frame_to(
            self.capability,
            &mut self.protocol,
            self.file.as_mut().ok_or(DeviceError::PeerLost)?,
            kind,
            body,
        )
    }
}

trait DeviceFrameWriter {
    fn write_frame(&mut self, kind: MessageKind, body: &[u8]) -> Result<(), DeviceError>;
}

impl DeviceFrameWriter for OutputEndpoint {
    fn write_frame(&mut self, kind: MessageKind, body: &[u8]) -> Result<(), DeviceError> {
        self.write_frame_inner(kind, body)
    }
}

fn read_frame_from<R: Read>(
    reader: &mut R,
    decoder: &mut StreamDecoder,
) -> Result<qk_device_wire::ReceivedFrame, DeviceError> {
    let mut scratch = [0u8; DEVICE_READ_BYTES];
    loop {
        let received = reader
            .read(&mut scratch)
            .map_err(|_| DeviceError::PeerLost)?;
        if received == 0 {
            return Err(decoder.finish());
        }
        let outcome = match decoder.ingest(&scratch[..received]) {
            Ok(outcome) => outcome,
            Err(error) => {
                crate::wipe::bytes(&mut scratch);
                return Err(error);
            }
        };
        crate::wipe::bytes(&mut scratch);
        if outcome.frame_ready() {
            return decoder.take_frame();
        }
    }
}

fn write_frame_to<W: Write>(
    capability: Capability,
    protocol: &mut OneWayProtocol,
    writer: &mut W,
    kind: MessageKind,
    body: &[u8],
) -> Result<(), DeviceError> {
    let frame_len = HEADER_BYTES
        .checked_add(body.len())
        .ok_or(DeviceError::BodyLengthExceeded)?;
    let mut frame = WipingVec::try_zeroed(frame_len).map_err(|_| DeviceError::AllocationFailed)?;
    let outbound = protocol.next(kind)?;
    if outbound.capability() != capability {
        return Err(DeviceError::CapabilityMismatch);
    }
    let encoded = outbound.encode(body, frame.as_mut_slice())?;
    if encoded != frame_len {
        return Err(DeviceError::UnexpectedFrame);
    }
    writer
        .write_all(frame.as_slice())
        .map_err(|_| DeviceError::PeerLost)?;
    Ok(())
}

pub(crate) struct DeviceProcess {
    camera: InputEndpoint,
    media_input: InputEndpoint,
    print: OutputEndpoint,
    media_output: OutputEndpoint,
    used_sources: u8,
    used_artifacts: u8,
    pending_egress: Option<PendingEgress>,
}

impl DeviceProcess {
    pub(crate) fn new() -> Self {
        Self {
            camera: InputEndpoint::new(Capability::CameraInput, CAMERA_INPUT_PATH),
            media_input: InputEndpoint::new(Capability::MediaInput, MEDIA_INPUT_PATH),
            print: OutputEndpoint::new(Capability::PrintOutput, PRINT_OUTPUT_PATH),
            media_output: OutputEndpoint::new(Capability::MediaOutput, MEDIA_OUTPUT_PATH),
            used_sources: 0,
            used_artifacts: 0,
            pending_egress: None,
        }
    }

    pub(crate) fn accept(
        &mut self,
        broker: &mut BrokerSession,
        frame: &ReceivedFrame,
    ) -> Result<BrokerReply, DeviceProcessError> {
        let parsed = parse_request(frame.payload()).ok();
        if let Some(Request::IngressBegin { source, aux }) = parsed {
            if broker.state() == BrokerState::Idle && aux.is_empty() {
                let mut input = self.read_input(source)?;
                return broker
                    .accept(frame, Some(&mut input), None)
                    .map_err(DeviceProcessError::Broker);
            }
        }

        if matches!(parsed, Some(Request::EgressFinish)) {
            if let Some(pending) = self.pending_egress {
                if pending.sink != Sink::Bbqr {
                    let mut writer = MockOutputWriter::new(pending.sink);
                    let reply = broker.accept(frame, None, Some(&mut writer))?;
                    if reply.status() == ReplyStatus::Success(Operation::EgressFinish) {
                        self.write_output(pending, &writer)?;
                        self.pending_egress = None;
                    }
                    return Ok(reply);
                }
            }
        }

        let reply = broker.accept(frame, None, None)?;
        if reply.status() == ReplyStatus::Success(Operation::EgressBegin) {
            let Some(Request::EgressBegin { sink, artifact, .. }) = parsed else {
                return Err(DeviceError::UnexpectedFrame.into());
            };
            self.pending_egress = Some(PendingEgress { sink, artifact });
        } else if reply.status() == ReplyStatus::Success(Operation::EgressFinish) {
            self.pending_egress = None;
        }
        Ok(reply)
    }

    fn read_input(&mut self, source: Source) -> Result<MockInput, DeviceProcessError> {
        let source_bit = 1u8
            .checked_shl(u32::from(source.wire_value() - 1))
            .ok_or(DeviceError::UnexpectedFrame)?;
        if self.used_sources & source_bit != 0 {
            return Err(DeviceError::UnexpectedFrame.into());
        }
        self.used_sources |= source_bit;
        let expected = device_source(source);
        let (data, filename) = match source {
            Source::MediaPsbt => collect_input(&mut self.media_input, expected)?,
            Source::CameraA1Candidate | Source::CameraKitCandidate | Source::CameraBbqrPsbt => {
                collect_input(&mut self.camera, expected)?
            }
        };
        let raw = if source == Source::MediaPsbt {
            media_record(
                filename.as_ref().ok_or(DeviceError::FilenameRejected)?,
                &data,
            )?
        } else {
            data
        };
        MockInput::try_new(source, raw.as_slice()).map_err(DeviceProcessError::Inner)
    }

    fn write_output(
        &mut self,
        pending: PendingEgress,
        writer: &MockOutputWriter,
    ) -> Result<(), DeviceProcessError> {
        let artifact_bit = 1u8
            .checked_shl(u32::from(pending.artifact.wire_value() - 1))
            .ok_or(DeviceError::UnexpectedFrame)?;
        if self.used_artifacts & artifact_bit != 0 {
            return Err(DeviceError::UnexpectedFrame.into());
        }
        self.used_artifacts |= artifact_bit;
        let bytes = writer.final_bytes().ok_or(DeviceError::UnexpectedFrame)?;
        let filename = writer.final_name().unwrap_or(&[]);
        let artifact = device_artifact(pending.artifact);
        match pending.sink {
            Sink::Sd => emit_output(
                &mut self.media_output,
                MessageKind::MediaWriteBegin,
                MessageKind::MediaWriteChunk,
                MessageKind::MediaWriteFinish,
                artifact,
                filename,
                bytes,
            )?,
            Sink::Print => emit_output(
                &mut self.print,
                MessageKind::PrintWriteBegin,
                MessageKind::PrintWriteChunk,
                MessageKind::PrintWriteFinish,
                artifact,
                filename,
                bytes,
            )?,
            Sink::Bbqr => return Err(DeviceError::UnexpectedFrame.into()),
        }
        Ok(())
    }
}

fn collect_input<R: DeviceFrameReader>(
    endpoint: &mut R,
    expected_source: qk_device_wire::Source,
) -> Result<(WipingVec, Option<WipingVec>), DeviceError> {
    let begin = endpoint.read_frame()?;
    let begin_body = match begin.parsed_body()? {
        BodyRef::CameraInput(InputBody::Begin {
            source,
            total_len,
            filename,
        })
        | BodyRef::MediaInput(InputBody::Begin {
            source,
            total_len,
            filename,
        }) => InputBody::Begin {
            source,
            total_len,
            filename,
        },
        _ => return Err(DeviceError::UnexpectedFrame),
    };
    let InputBody::Begin {
        source,
        total_len,
        filename,
    } = begin_body
    else {
        return Err(DeviceError::UnexpectedFrame);
    };
    if source != expected_source {
        return Err(DeviceError::SourceMismatch);
    }
    let capability = match expected_source {
        qk_device_wire::Source::MediaPsbt => Capability::MediaInput,
        qk_device_wire::Source::CameraA1Candidate
        | qk_device_wire::Source::CameraKitCandidate
        | qk_device_wire::Source::CameraBbqrPsbt => Capability::CameraInput,
    };
    let mut transfer = InputTransfer::begin(capability, begin_body)?;
    let filename = filename
        .map(WipingVec::try_from_slice)
        .transpose()
        .map_err(|_| DeviceError::AllocationFailed)?;
    let mut data =
        WipingVec::try_zeroed(total_len as usize).map_err(|_| DeviceError::AllocationFailed)?;
    loop {
        let frame = endpoint.read_frame()?;
        let body = match frame.parsed_body()? {
            BodyRef::CameraInput(InputBody::Chunk {
                offset,
                final_chunk,
                chunk,
            })
            | BodyRef::MediaInput(InputBody::Chunk {
                offset,
                final_chunk,
                chunk,
            }) => InputBody::Chunk {
                offset,
                final_chunk,
                chunk,
            },
            _ => return Err(DeviceError::UnexpectedFrame),
        };
        let InputBody::Chunk {
            offset,
            final_chunk,
            chunk,
        } = body
        else {
            return Err(DeviceError::UnexpectedFrame);
        };
        transfer.accept(body)?;
        let start = offset as usize;
        let end = transfer.next_offset() as usize;
        data.as_mut_slice()[start..end].copy_from_slice(chunk);
        if final_chunk {
            transfer.finish()?;
            return Ok((data, filename));
        }
    }
}

fn media_record(filename: &WipingVec, data: &WipingVec) -> Result<WipingVec, DeviceError> {
    if filename.len() == 0 || filename.len() > MAX_FILENAME_BYTES {
        return Err(DeviceError::FilenameRejected);
    }
    let length = 1usize
        .checked_add(filename.len())
        .and_then(|value| value.checked_add(4))
        .and_then(|value| value.checked_add(data.len()))
        .filter(|value| *value <= MAX_MOCK_INPUT_BYTES)
        .ok_or(DeviceError::TransferLengthExceeded)?;
    let mut raw = WipingVec::try_zeroed(length).map_err(|_| DeviceError::AllocationFailed)?;
    raw.as_mut_slice()[0] = filename.len() as u8;
    raw.as_mut_slice()[1..1 + filename.len()].copy_from_slice(filename.as_slice());
    let data_len_offset = 1 + filename.len();
    raw.as_mut_slice()[data_len_offset..data_len_offset + 4]
        .copy_from_slice(&(data.len() as u32).to_le_bytes());
    raw.as_mut_slice()[data_len_offset + 4..].copy_from_slice(data.as_slice());
    Ok(raw)
}

fn emit_output<W: DeviceFrameWriter>(
    endpoint: &mut W,
    begin_kind: MessageKind,
    chunk_kind: MessageKind,
    finish_kind: MessageKind,
    artifact: qk_device_wire::Artifact,
    filename: &[u8],
    bytes: &[u8],
) -> Result<(), DeviceError> {
    let total_len = u32::try_from(bytes.len()).map_err(|_| DeviceError::TransferLengthExceeded)?;
    let mut begin =
        WipingVec::try_zeroed(7 + filename.len()).map_err(|_| DeviceError::AllocationFailed)?;
    begin.as_mut_slice()[0] = artifact.wire_value();
    begin.as_mut_slice()[1..5].copy_from_slice(&total_len.to_le_bytes());
    begin.as_mut_slice()[5..7].copy_from_slice(&(filename.len() as u16).to_le_bytes());
    begin.as_mut_slice()[7..].copy_from_slice(filename);
    let mut transfer = OutputTransfer::begin(
        begin_kind.capability(),
        OutputBody::WriteBegin {
            artifact,
            total_len,
            filename,
        },
    )?;
    endpoint.write_frame(begin_kind, begin.as_slice())?;

    let mut offset = 0usize;
    while offset < bytes.len() {
        let end = offset.saturating_add(MAX_CHUNK_BYTES).min(bytes.len());
        let chunk = &bytes[offset..end];
        let mut body =
            WipingVec::try_zeroed(8 + chunk.len()).map_err(|_| DeviceError::AllocationFailed)?;
        body.as_mut_slice()[0..4].copy_from_slice(&(offset as u32).to_le_bytes());
        body.as_mut_slice()[4..8].copy_from_slice(&(chunk.len() as u32).to_le_bytes());
        body.as_mut_slice()[8..].copy_from_slice(chunk);
        transfer.accept(OutputBody::WriteChunk {
            offset: offset as u32,
            chunk,
        })?;
        endpoint.write_frame(chunk_kind, body.as_slice())?;
        offset = end;
    }

    let mut finish = [0u8; 5];
    finish[0] = artifact.wire_value();
    finish[1..5].copy_from_slice(&total_len.to_le_bytes());
    let result = transfer
        .finish(OutputBody::WriteFinish {
            artifact,
            total_len,
        })
        .and_then(|()| endpoint.write_frame(finish_kind, &finish));
    crate::wipe::bytes(&mut finish);
    result
}

const fn device_source(source: Source) -> qk_device_wire::Source {
    match source {
        Source::CameraA1Candidate => qk_device_wire::Source::CameraA1Candidate,
        Source::CameraKitCandidate => qk_device_wire::Source::CameraKitCandidate,
        Source::CameraBbqrPsbt => qk_device_wire::Source::CameraBbqrPsbt,
        Source::MediaPsbt => qk_device_wire::Source::MediaPsbt,
    }
}

const fn device_artifact(artifact: Artifact) -> qk_device_wire::Artifact {
    match artifact {
        Artifact::FinalizedPsbt => qk_device_wire::Artifact::FinalizedPsbt,
        Artifact::RawTransaction => qk_device_wire::Artifact::RawTransaction,
        Artifact::WatchOnlyBsms => qk_device_wire::Artifact::WatchOnlyBsms,
        Artifact::A1PrintArtifact => qk_device_wire::Artifact::A1PrintArtifact,
        Artifact::KitPrintArtifact => qk_device_wire::Artifact::KitPrintArtifact,
    }
}

#[cfg(test)]
#[allow(clippy::panic, clippy::unwrap_used)]
mod tests {
    use super::{
        collect_input, emit_output, media_record, read_frame_from, write_frame_to,
        DeviceFrameReader, DeviceFrameWriter,
    };
    use crate::wipe::{reset_wiped_bytes, wiped_bytes};
    use qk_device_wire::{
        encode_frame, parse_frame, Artifact, BodyRef, Capability, DeviceError, MessageKind,
        OneWayProtocol, OutputBody, Source, StreamDecoder, HEADER_BYTES,
    };
    use std::io::Cursor;

    struct TestReader {
        bytes: Cursor<Vec<u8>>,
        decoder: StreamDecoder,
    }

    impl TestReader {
        fn new(capability: Capability, bytes: Vec<u8>) -> Self {
            Self {
                bytes: Cursor::new(bytes),
                decoder: StreamDecoder::new(capability),
            }
        }
    }

    impl DeviceFrameReader for TestReader {
        fn read_frame(&mut self) -> Result<qk_device_wire::ReceivedFrame, DeviceError> {
            read_frame_from(&mut self.bytes, &mut self.decoder)
        }
    }

    struct TestWriter {
        capability: Capability,
        protocol: OneWayProtocol,
        bytes: Vec<u8>,
    }

    impl TestWriter {
        fn new(capability: Capability) -> Self {
            Self {
                capability,
                protocol: OneWayProtocol::new(capability),
                bytes: Vec::new(),
            }
        }
    }

    impl DeviceFrameWriter for TestWriter {
        fn write_frame(&mut self, kind: MessageKind, body: &[u8]) -> Result<(), DeviceError> {
            write_frame_to(
                self.capability,
                &mut self.protocol,
                &mut self.bytes,
                kind,
                body,
            )
        }
    }

    fn frame(capability: Capability, kind: MessageKind, sequence: u32, body: &[u8]) -> Vec<u8> {
        let mut bytes = vec![0u8; HEADER_BYTES + body.len()];
        let length = encode_frame(capability, kind, sequence, body, &mut bytes).unwrap();
        assert_eq!(length, bytes.len());
        bytes
    }

    fn camera_stream(payload: &[u8]) -> Vec<u8> {
        let mut begin = [0u8; 5];
        begin[0] = Source::CameraA1Candidate.wire_value();
        begin[1..5].copy_from_slice(&(payload.len() as u32).to_le_bytes());
        let first_len = 31usize;
        let mut first = vec![0u8; 9 + first_len];
        first[4..8].copy_from_slice(&(first_len as u32).to_le_bytes());
        first[8] = 0;
        first[9..].copy_from_slice(&payload[..first_len]);
        let mut second = vec![0u8; 9 + payload.len() - first_len];
        second[0..4].copy_from_slice(&(first_len as u32).to_le_bytes());
        second[4..8].copy_from_slice(&((payload.len() - first_len) as u32).to_le_bytes());
        second[8] = 1;
        second[9..].copy_from_slice(&payload[first_len..]);
        [
            frame(Capability::CameraInput, MessageKind::CameraBegin, 1, &begin),
            frame(Capability::CameraInput, MessageKind::CameraChunk, 2, &first),
            frame(
                Capability::CameraInput,
                MessageKind::CameraChunk,
                3,
                &second,
            ),
        ]
        .concat()
    }

    #[test]
    fn fragmented_camera_frames_feed_the_existing_leaf_byte_exactly() {
        let payload = [0x5au8; 67];
        let mut reader = TestReader::new(Capability::CameraInput, camera_stream(&payload));
        let (data, filename) =
            collect_input(&mut reader, Source::CameraA1Candidate).expect("camera input");
        assert_eq!(data.as_slice(), payload);
        assert!(filename.is_none());

        reset_wiped_bytes();
        let capacity = data.capacity();
        drop(data);
        assert_eq!(wiped_bytes(), capacity);
    }

    #[test]
    fn media_record_conversion_is_the_frozen_inner_leaf_shape() {
        let filename = crate::wipe::WipingVec::try_from_slice(b"incoming.psbt").unwrap();
        let payload = crate::wipe::WipingVec::try_from_slice(b"psbt-bytes").unwrap();
        let record = media_record(&filename, &payload).unwrap();
        assert_eq!(record.as_slice()[0], 13);
        assert_eq!(&record.as_slice()[1..14], b"incoming.psbt");
        assert_eq!(&record.as_slice()[14..18], &10u32.to_le_bytes());
        assert_eq!(&record.as_slice()[18..], b"psbt-bytes");
    }

    #[test]
    fn input_transfer_rejects_an_offset_gap_before_copying_it() {
        let payload = [0x33u8; 67];
        let mut bytes = camera_stream(&payload);
        let first_frame_len = HEADER_BYTES + 5;
        let first_chunk_offset = first_frame_len + HEADER_BYTES;
        bytes[first_chunk_offset] = 1;
        let mut reader = TestReader::new(Capability::CameraInput, bytes);
        let result = collect_input(&mut reader, Source::CameraA1Candidate);
        assert!(matches!(result, Err(DeviceError::OffsetMismatch)));
    }

    #[test]
    fn sd_output_is_one_way_begin_chunks_finish_with_contiguous_sequences() {
        let payload = vec![0x6cu8; crate::MAX_CHUNK_BYTES + 3];
        let name = b"qk-11111111111111111111111111111111-final.tx";
        let mut writer = TestWriter::new(Capability::MediaOutput);
        emit_output(
            &mut writer,
            MessageKind::MediaWriteBegin,
            MessageKind::MediaWriteChunk,
            MessageKind::MediaWriteFinish,
            Artifact::RawTransaction,
            name,
            &payload,
        )
        .unwrap();
        let mut cursor = 0usize;
        let mut kinds = Vec::new();
        let mut offsets = Vec::new();
        let mut sequences = Vec::new();
        while cursor < writer.bytes.len() {
            let body_len =
                u32::from_le_bytes(writer.bytes[cursor + 12..cursor + 16].try_into().unwrap())
                    as usize;
            let end = cursor + HEADER_BYTES + body_len;
            let parsed = parse_frame(Capability::MediaOutput, &writer.bytes[cursor..end]).unwrap();
            kinds.push(parsed.header().kind());
            sequences.push(parsed.header().sequence());
            if let BodyRef::MediaOutput(OutputBody::WriteChunk { offset, .. }) =
                parsed.parsed_body().unwrap()
            {
                offsets.push(offset);
            }
            cursor = end;
        }
        assert_eq!(
            kinds,
            [
                MessageKind::MediaWriteBegin,
                MessageKind::MediaWriteChunk,
                MessageKind::MediaWriteChunk,
                MessageKind::MediaWriteFinish,
            ]
        );
        assert_eq!(sequences, [1, 2, 3, 4]);
        assert_eq!(offsets, [0, crate::MAX_CHUNK_BYTES as u32]);
    }

    #[test]
    fn encoded_output_frame_owner_wipes_its_complete_allocation() {
        let mut protocol = OneWayProtocol::new(Capability::MediaOutput);
        let mut bytes = Vec::new();
        let body = [Artifact::RawTransaction.wire_value(), 1, 0, 0, 0];
        reset_wiped_bytes();
        write_frame_to(
            Capability::MediaOutput,
            &mut protocol,
            &mut bytes,
            MessageKind::MediaWriteFinish,
            &body,
        )
        .unwrap();
        assert_eq!(wiped_bytes(), HEADER_BYTES + body.len());
    }
}
