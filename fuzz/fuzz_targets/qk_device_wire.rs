#![no_main]

use libfuzzer_sys::fuzz_target;
use qk_device_wire::{
    encode_frame, parse_frame, reset_wiped_bytes, wiped_bytes, Artifact, Capability, DeviceError,
    ExchangeProtocol, InputBody, InputTransfer, MessageKind, OneWayProtocol, OutputBody,
    OutputTransfer, ReceivedFrame, Source, StreamDecoder, HEADER_BYTES,
};

const CONTROL_BYTES: usize = 16;
const MAX_PRESENTED_BYTES: usize = 262_169;
const MAX_TRANSFER_BYTES: usize = 2_097_152;
const MAX_CHUNK_BYTES: usize = 262_144;
const MAX_CHUNK_BODY_BYTES: usize = 262_153;
const MAX_BODY_BYTES: usize = 2_097_152;
const MAX_FILENAME_BYTES: usize = 64;
const CARD_FACTOR_PREFIX_BYTES: usize = 789;

type ErrorName = &'static str;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum ModelKind {
    DisplayStage,
    DisplayProfile,
    DisplayReview,
    DisplayResult,
    KeypadEvent,
    CardProfile,
    CardNormalFactor,
    CardRejected,
    CardReadProfile,
    CardReadNormalFactor,
    CameraBegin,
    CameraChunk,
    MediaReadBegin,
    MediaReadChunk,
    MediaBeginAccepted,
    MediaChunkAccepted,
    MediaFinished,
    MediaRejected,
    PrintWriteBegin,
    PrintWriteChunk,
    PrintWriteFinish,
    MediaWriteBegin,
    MediaWriteChunk,
    MediaWriteFinish,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct ModelHeader {
    capability: u8,
    kind: ModelKind,
    kind_byte: u8,
    sequence: u32,
    body_len: usize,
}

#[derive(Clone, Debug, Eq, PartialEq)]
enum FrameFact {
    Accepted {
        capability: u8,
        kind: u8,
        sequence: u32,
        body_len: usize,
    },
    Rejected(ErrorName),
}

#[derive(Clone, Debug, Eq, PartialEq)]
enum StreamFact {
    Frame {
        capability: u8,
        kind: u8,
        sequence: u32,
        body_len: usize,
    },
    Finished(ErrorName),
    Rejected(ErrorName),
}

fn error_name(error: DeviceError) -> ErrorName {
    let name = match error {
        DeviceError::DecoderTerminated => "DecoderTerminated",
        DeviceError::HeaderTruncated => "HeaderTruncated",
        DeviceError::MagicMismatch => "MagicMismatch",
        DeviceError::VersionMismatch => "VersionMismatch",
        DeviceError::CapabilityOutOfRange => "CapabilityOutOfRange",
        DeviceError::CapabilityMismatch => "CapabilityMismatch",
        DeviceError::KindOutOfRange => "KindOutOfRange",
        DeviceError::CapabilityKindMismatch => "CapabilityKindMismatch",
        DeviceError::ReservedNonZero => "ReservedNonZero",
        DeviceError::SequenceZero => "SequenceZero",
        DeviceError::SequenceReplay => "SequenceReplay",
        DeviceError::SequenceRegression => "SequenceRegression",
        DeviceError::SequenceSkipped => "SequenceSkipped",
        DeviceError::SequenceExhausted => "SequenceExhausted",
        DeviceError::OutstandingExchange => "OutstandingExchange",
        DeviceError::NoOutstandingExchange => "NoOutstandingExchange",
        DeviceError::ResponseSequenceMismatch => "ResponseSequenceMismatch",
        DeviceError::ResponseKindMismatch => "ResponseKindMismatch",
        DeviceError::BodyLengthExceeded => "BodyLengthExceeded",
        DeviceError::BodyTruncated => "BodyTruncated",
        DeviceError::TrailingByte => "TrailingByte",
        DeviceError::UnexpectedFrame => "UnexpectedFrame",
        DeviceError::ConnectionClosedMidFrame => "ConnectionClosedMidFrame",
        DeviceError::PeerLost => "PeerLost",
        DeviceError::OutputBufferTooSmall => "OutputBufferTooSmall",
        DeviceError::AllocationFailed => "AllocationFailed",
        DeviceError::BodyLengthMismatch => "BodyLengthMismatch",
        DeviceError::ValueOutOfRange => "ValueOutOfRange",
        DeviceError::NestedLengthMismatch => "NestedLengthMismatch",
        DeviceError::CountExceeded => "CountExceeded",
        DeviceError::IndexOrderMismatch => "IndexOrderMismatch",
        DeviceError::OffsetMismatch => "OffsetMismatch",
        DeviceError::ChunkLengthZero => "ChunkLengthZero",
        DeviceError::ChunkLengthExceeded => "ChunkLengthExceeded",
        DeviceError::FinalFlagOutOfRange => "FinalFlagOutOfRange",
        DeviceError::FinalFlagMismatch => "FinalFlagMismatch",
        DeviceError::TransferLengthExceeded => "TransferLengthExceeded",
        DeviceError::TransferIncomplete => "TransferIncomplete",
        DeviceError::SourceMismatch => "SourceMismatch",
        DeviceError::FilenameRejected => "FilenameRejected",
        DeviceError::ArtifactMismatch => "ArtifactMismatch",
        DeviceError::DeviceRejected => "DeviceRejected",
    };
    assert_eq!(error.name(), name);
    assert_eq!(error.to_string(), name);
    name
}

fn selected_capability(selector: u8) -> (u8, Capability) {
    match selector % 8 {
        0 => (0x01, Capability::Display),
        1 => (0x02, Capability::Keypad),
        2 => (0x03, Capability::CardResponse),
        3 => (0x04, Capability::CardRequest),
        4 => (0x05, Capability::CameraInput),
        5 => (0x06, Capability::MediaInput),
        6 => (0x07, Capability::PrintOutput),
        7 => (0x08, Capability::MediaOutput),
        _ => unreachable!("modulo eight is exhaustive"),
    }
}

fn read_u16(bytes: &[u8], offset: usize) -> Option<u16> {
    let raw: [u8; 2] = bytes.get(offset..offset.checked_add(2)?)?.try_into().ok()?;
    Some(u16::from_le_bytes(raw))
}

fn read_u32(bytes: &[u8], offset: usize) -> Option<u32> {
    let raw: [u8; 4] = bytes.get(offset..offset.checked_add(4)?)?.try_into().ok()?;
    Some(u32::from_le_bytes(raw))
}

fn exact(bytes: &[u8], length: usize) -> Result<(), ErrorName> {
    if bytes.len() == length {
        Ok(())
    } else {
        Err("BodyLengthMismatch")
    }
}

fn value_in(value: u8, lower: u8, upper: u8) -> Result<(), ErrorName> {
    if (lower..=upper).contains(&value) {
        Ok(())
    } else {
        Err("ValueOutOfRange")
    }
}

fn model_kind(capability: u8, value: u8) -> Result<ModelKind, ErrorName> {
    if !matches!(value, 0x01 | 0x02 | 0x03 | 0x04 | 0x81 | 0x82 | 0x83 | 0xff) {
        return Err("KindOutOfRange");
    }
    match (capability, value) {
        (0x01, 0x01) => Ok(ModelKind::DisplayStage),
        (0x01, 0x02) => Ok(ModelKind::DisplayProfile),
        (0x01, 0x03) => Ok(ModelKind::DisplayReview),
        (0x01, 0x04) => Ok(ModelKind::DisplayResult),
        (0x02, 0x01) => Ok(ModelKind::KeypadEvent),
        (0x03, 0x81) => Ok(ModelKind::CardProfile),
        (0x03, 0x82) => Ok(ModelKind::CardNormalFactor),
        (0x03, 0xff) => Ok(ModelKind::CardRejected),
        (0x04, 0x01) => Ok(ModelKind::CardReadProfile),
        (0x04, 0x02) => Ok(ModelKind::CardReadNormalFactor),
        (0x05, 0x01) => Ok(ModelKind::CameraBegin),
        (0x05, 0x02) => Ok(ModelKind::CameraChunk),
        (0x06, 0x01) => Ok(ModelKind::MediaReadBegin),
        (0x06, 0x02) => Ok(ModelKind::MediaReadChunk),
        (0x06, 0x81) => Ok(ModelKind::MediaBeginAccepted),
        (0x06, 0x82) => Ok(ModelKind::MediaChunkAccepted),
        (0x06, 0x83) => Ok(ModelKind::MediaFinished),
        (0x06, 0xff) => Ok(ModelKind::MediaRejected),
        (0x07, 0x01) => Ok(ModelKind::PrintWriteBegin),
        (0x07, 0x02) => Ok(ModelKind::PrintWriteChunk),
        (0x07, 0x03) => Ok(ModelKind::PrintWriteFinish),
        (0x08, 0x01) => Ok(ModelKind::MediaWriteBegin),
        (0x08, 0x02) => Ok(ModelKind::MediaWriteChunk),
        (0x08, 0x03) => Ok(ModelKind::MediaWriteFinish),
        _ => Err("CapabilityKindMismatch"),
    }
}

fn model_body_cap(kind: ModelKind) -> usize {
    match kind {
        ModelKind::DisplayStage | ModelKind::DisplayProfile | ModelKind::CardProfile => 1,
        ModelKind::DisplayReview | ModelKind::DisplayResult => 180,
        ModelKind::KeypadEvent => 17,
        ModelKind::CardNormalFactor => 11_790,
        ModelKind::CardRejected | ModelKind::MediaRejected => 3,
        ModelKind::CardReadProfile | ModelKind::CardReadNormalFactor => 0,
        ModelKind::CameraBegin
        | ModelKind::MediaBeginAccepted
        | ModelKind::MediaFinished
        | ModelKind::PrintWriteFinish
        | ModelKind::MediaWriteFinish => 5,
        ModelKind::MediaReadBegin => 71,
        ModelKind::CameraChunk
        | ModelKind::MediaReadChunk
        | ModelKind::PrintWriteChunk
        | ModelKind::MediaWriteChunk => MAX_CHUNK_BODY_BYTES,
        ModelKind::MediaChunkAccepted => 4,
        ModelKind::PrintWriteBegin | ModelKind::MediaWriteBegin => 73,
    }
}

fn model_header(expected: u8, bytes: &[u8]) -> Result<ModelHeader, ErrorName> {
    if bytes.len() < HEADER_BYTES {
        return Err("HeaderTruncated");
    }
    if bytes.get(..4) != Some(b"QKDV") {
        return Err("MagicMismatch");
    }
    if bytes[4] != 1 {
        return Err("VersionMismatch");
    }
    let capability = bytes[5];
    if !(1..=8).contains(&capability) {
        return Err("CapabilityOutOfRange");
    }
    if capability != expected {
        return Err("CapabilityMismatch");
    }
    let kind_byte = bytes[6];
    let kind = model_kind(capability, kind_byte)?;
    if bytes[7] != 0 {
        return Err("ReservedNonZero");
    }
    let sequence = read_u32(bytes, 8).ok_or("HeaderTruncated")?;
    if sequence == 0 {
        return Err("SequenceZero");
    }
    let body_len = read_u32(bytes, 12).ok_or("HeaderTruncated")? as usize;
    if body_len > model_body_cap(kind) || body_len > MAX_BODY_BYTES {
        return Err("BodyLengthExceeded");
    }
    Ok(ModelHeader {
        capability,
        kind,
        kind_byte,
        sequence,
        body_len,
    })
}

fn cursor_take<'a>(
    bytes: &'a [u8],
    offset: &mut usize,
    count: usize,
) -> Result<&'a [u8], ErrorName> {
    let end = offset.checked_add(count).ok_or("NestedLengthMismatch")?;
    let value = bytes.get(*offset..end).ok_or("NestedLengthMismatch")?;
    *offset = end;
    Ok(value)
}

fn model_review(body: &[u8]) -> Result<(), ErrorName> {
    let (&subtype, rest) = body.split_first().ok_or("BodyLengthMismatch")?;
    match subtype {
        0x01 => {
            exact(rest, 46)?;
            value_in(rest[0], 1, 3)?;
            value_in(rest[1], 1, 1)
        }
        0x02 => exact(rest, 24),
        0x03 => model_recipient(rest),
        0x04 => model_change(rest),
        0x05 => model_op_return(rest),
        0x06 => exact(rest, 4),
        0x07 => {
            exact(rest, 9)?;
            value_in(rest[8], 0, 1)
        }
        0x08 => {
            if rest == b"QK-FEE-POLICY-V2" {
                Ok(())
            } else {
                Err("BodyLengthMismatch")
            }
        }
        0x09 => exact(rest, 20),
        0x0a => {
            exact(rest, 1)?;
            value_in(rest[0], 1, 4)
        }
        0x0b => {
            exact(rest, 33)?;
            value_in(rest[0], 1, 3)
        }
        _ => Err("ValueOutOfRange"),
    }
}

fn model_recipient(rest: &[u8]) -> Result<(), ErrorName> {
    if rest.len() < 15 {
        return Err("NestedLengthMismatch");
    }
    let script_len = usize::from(read_u16(rest, 12).ok_or("NestedLengthMismatch")?);
    if script_len > 83 {
        return Err("ValueOutOfRange");
    }
    let ownership = 14usize
        .checked_add(script_len)
        .ok_or("NestedLengthMismatch")?;
    let tag = *rest.get(ownership).ok_or("NestedLengthMismatch")?;
    match tag {
        0x01 => {
            let recipient_type = *rest.get(ownership + 1).ok_or("NestedLengthMismatch")?;
            value_in(recipient_type, 1, 6)?;
            let data_len =
                usize::from(read_u16(rest, ownership + 2).ok_or("NestedLengthMismatch")?);
            let data_start = ownership.checked_add(4).ok_or("NestedLengthMismatch")?;
            let data_end = data_start
                .checked_add(data_len)
                .ok_or("NestedLengthMismatch")?;
            if data_end != rest.len() {
                return Err("NestedLengthMismatch");
            }
            let valid = match recipient_type {
                1 | 4 | 5 => data_len == 20,
                2 | 3 => data_len == 32,
                6 => data_len <= 80,
                _ => false,
            };
            if valid {
                Ok(())
            } else {
                Err("ValueOutOfRange")
            }
        }
        0x02 => {
            read_u32(rest, ownership + 1).ok_or("NestedLengthMismatch")?;
            let program_len =
                usize::from(read_u16(rest, ownership + 5).ok_or("NestedLengthMismatch")?);
            if program_len != 32 {
                return Err("ValueOutOfRange");
            }
            let end = ownership
                .checked_add(7)
                .and_then(|start| start.checked_add(program_len))
                .ok_or("NestedLengthMismatch")?;
            if end == rest.len() {
                Ok(())
            } else {
                Err("NestedLengthMismatch")
            }
        }
        _ => Err("ValueOutOfRange"),
    }
}

fn model_change(rest: &[u8]) -> Result<(), ErrorName> {
    if rest.len() < 18 {
        return Err("NestedLengthMismatch");
    }
    let script_len = usize::from(read_u16(rest, 12).ok_or("NestedLengthMismatch")?);
    if script_len != 34 {
        return Err("ValueOutOfRange");
    }
    if rest.len() == 14 + script_len + 4 {
        Ok(())
    } else {
        Err("NestedLengthMismatch")
    }
}

fn model_op_return(rest: &[u8]) -> Result<(), ErrorName> {
    if rest.len() < 16 {
        return Err("NestedLengthMismatch");
    }
    let script_len = usize::from(read_u16(rest, 12).ok_or("NestedLengthMismatch")?);
    if script_len == 0 || script_len > 83 {
        return Err("ValueOutOfRange");
    }
    let script_end = 14usize
        .checked_add(script_len)
        .ok_or("NestedLengthMismatch")?;
    let payload_len = usize::from(read_u16(rest, script_end).ok_or("NestedLengthMismatch")?);
    if payload_len > 80 {
        return Err("ValueOutOfRange");
    }
    let end = script_end
        .checked_add(2)
        .and_then(|start| start.checked_add(payload_len))
        .ok_or("NestedLengthMismatch")?;
    if end == rest.len() {
        Ok(())
    } else {
        Err("NestedLengthMismatch")
    }
}

fn model_artifact(value: u8) -> Result<u8, ErrorName> {
    value_in(value, 1, 5)?;
    Ok(value)
}

fn model_result(body: &[u8]) -> Result<(), ErrorName> {
    if body.len() < 67 {
        return Err("BodyLengthMismatch");
    }
    value_in(body[0], 1, 3)?;
    value_in(body[1], 1, 2)?;
    let expected_bitmap = match (body[0], body[1]) {
        (1 | 2, 1) => 0x0f,
        (1 | 2, 2) => 0x01,
        (3, 1) => 0x0a,
        (3, 2) => 0x02,
        _ => return Err("ValueOutOfRange"),
    };
    if body[2] != expected_bitmap {
        return Err("ValueOutOfRange");
    }
    let mut offset = 3;
    for (bit, expected, receipt) in [
        (0x01, 1, false),
        (0x02, 2, false),
        (0x04, 1, true),
        (0x08, 2, true),
    ] {
        if body[2] & bit == 0 {
            continue;
        }
        let artifact = model_artifact(
            *cursor_take(body, &mut offset, 1)?
                .first()
                .ok_or("NestedLengthMismatch")?,
        )?;
        if artifact != expected {
            return Err("ArtifactMismatch");
        }
        let length_bytes = cursor_take(body, &mut offset, 4)?;
        let length = read_u32(length_bytes, 0).ok_or("NestedLengthMismatch")?;
        if length == 0 {
            return Err("ValueOutOfRange");
        }
        if !receipt {
            cursor_take(body, &mut offset, 32)?;
        }
    }
    cursor_take(body, &mut offset, 32)?;
    cursor_take(body, &mut offset, 32)?;
    if offset == body.len() {
        Ok(())
    } else {
        Err("NestedLengthMismatch")
    }
}

fn model_keypad(body: &[u8]) -> Result<(), ErrorName> {
    let (&event, data) = body.split_first().ok_or("BodyLengthMismatch")?;
    match event {
        0x01 => {
            exact(data, 1)?;
            value_in(data[0], 1, 19)
        }
        0x02 => {
            exact(data, 1)?;
            value_in(data[0], 1, 4)?;
            if matches!(data[0], 3 | 4) {
                Ok(())
            } else {
                Err("SourceMismatch")
            }
        }
        0x03 | 0x06 | 0x07 => exact(data, 0),
        0x04 => exact(data, 16),
        0x05 => {
            exact(data, 2)?;
            let value = read_u16(data, 0).ok_or("BodyLengthMismatch")?;
            if (5..=2_680).contains(&value) && value.is_multiple_of(5) {
                Ok(())
            } else {
                Err("ValueOutOfRange")
            }
        }
        _ => Err("ValueOutOfRange"),
    }
}

fn model_card_factor(body: &[u8]) -> Result<(), ErrorName> {
    if body.len() < CARD_FACTOR_PREFIX_BYTES {
        return Err("BodyLengthMismatch");
    }
    let count = usize::from(read_u16(body, 787).ok_or("BodyLengthMismatch")?);
    if count > 100 {
        return Err("CountExceeded");
    }
    let mut offset = CARD_FACTOR_PREFIX_BYTES;
    let mut prior = None;
    for _ in 0..count {
        let index_bytes = cursor_take(body, &mut offset, 4)?;
        let index = read_u32(index_bytes, 0).ok_or("NestedLengthMismatch")?;
        if prior.is_some_and(|old| index <= old) {
            return Err("IndexOrderMismatch");
        }
        prior = Some(index);
        cursor_take(body, &mut offset, 33)?;
        let der_len = usize::from(
            *cursor_take(body, &mut offset, 1)?
                .first()
                .ok_or("NestedLengthMismatch")?,
        );
        if !(8..=72).contains(&der_len) {
            return Err("ValueOutOfRange");
        }
        cursor_take(body, &mut offset, der_len)?;
    }
    if offset == body.len() {
        Ok(())
    } else {
        Err("NestedLengthMismatch")
    }
}

fn model_chunk(body: &[u8], has_final: bool) -> Result<(), ErrorName> {
    let prefix = if has_final { 9 } else { 8 };
    if body.len() < prefix {
        return Err("BodyLengthMismatch");
    }
    let chunk_len = read_u32(body, 4).ok_or("BodyLengthMismatch")? as usize;
    if chunk_len == 0 {
        return Err("ChunkLengthZero");
    }
    if chunk_len > MAX_CHUNK_BYTES {
        return Err("ChunkLengthExceeded");
    }
    if has_final && !matches!(body[8], 0 | 1) {
        return Err("FinalFlagOutOfRange");
    }
    let end = prefix
        .checked_add(chunk_len)
        .ok_or("NestedLengthMismatch")?;
    if end == body.len() {
        Ok(())
    } else {
        Err("NestedLengthMismatch")
    }
}

fn valid_input_filename(name: &[u8]) -> bool {
    name.ends_with(b".psbt")
        && name.iter().all(|byte| {
            byte.is_ascii_lowercase() || byte.is_ascii_digit() || matches!(byte, b'.' | b'_' | b'-')
        })
        && !name.contains(&b'/')
        && !name.contains(&b'\\')
}

fn valid_output_filename(artifact: u8, name: &[u8]) -> bool {
    let suffix: &[u8] = match artifact {
        1 => b"-final.psbt",
        2 => b"-final.tx",
        _ => return false,
    };
    name.len() == 3 + 32 + suffix.len()
        && name.get(..3) == Some(b"qk-")
        && name[3..35]
            .iter()
            .all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f'))
        && name.get(35..) == Some(suffix)
}

fn model_camera_begin(body: &[u8]) -> Result<(), ErrorName> {
    exact(body, 5)?;
    let source = body[0];
    value_in(source, 1, 4)?;
    let total = read_u32(body, 1).ok_or("BodyLengthMismatch")? as usize;
    let valid = match source {
        1 => total == 67,
        2 => total == 142,
        3 => (1..=MAX_TRANSFER_BYTES).contains(&total),
        _ => false,
    };
    if valid {
        Ok(())
    } else {
        Err("SourceMismatch")
    }
}

fn model_media_begin(body: &[u8]) -> Result<(), ErrorName> {
    if body.len() < 7 {
        return Err("BodyLengthMismatch");
    }
    value_in(body[0], 1, 4)?;
    if body[0] != 4 {
        return Err("SourceMismatch");
    }
    let total = read_u32(body, 1).ok_or("BodyLengthMismatch")? as usize;
    if total == 0 || total > MAX_TRANSFER_BYTES {
        return Err("ValueOutOfRange");
    }
    let name_len = usize::from(read_u16(body, 5).ok_or("BodyLengthMismatch")?);
    if name_len == 0 || name_len > MAX_FILENAME_BYTES {
        return Err("FilenameRejected");
    }
    let end = 7usize.checked_add(name_len).ok_or("NestedLengthMismatch")?;
    if end != body.len() {
        return Err("NestedLengthMismatch");
    }
    if valid_input_filename(&body[7..end]) {
        Ok(())
    } else {
        Err("FilenameRejected")
    }
}

fn model_artifact_and_total(body: &[u8]) -> Result<(u8, usize), ErrorName> {
    let artifact = model_artifact(body[0])?;
    let total = read_u32(body, 1).ok_or("BodyLengthMismatch")? as usize;
    if total == 0 || total > MAX_TRANSFER_BYTES {
        return Err("ValueOutOfRange");
    }
    Ok((artifact, total))
}

fn model_output_begin(capability: u8, body: &[u8]) -> Result<(), ErrorName> {
    if body.len() < 7 {
        return Err("BodyLengthMismatch");
    }
    let (artifact, total) = model_artifact_and_total(body)?;
    let name_len = usize::from(read_u16(body, 5).ok_or("BodyLengthMismatch")?);
    if name_len > MAX_FILENAME_BYTES {
        return Err("FilenameRejected");
    }
    let end = 7usize.checked_add(name_len).ok_or("NestedLengthMismatch")?;
    if end != body.len() {
        return Err("NestedLengthMismatch");
    }
    let filename = &body[7..end];
    match capability {
        7 => {
            if !matches!((artifact, total), (4, 67) | (5, 829)) {
                return Err("ArtifactMismatch");
            }
            if filename.is_empty() {
                Ok(())
            } else {
                Err("FilenameRejected")
            }
        }
        8 => {
            if !matches!(artifact, 1 | 2) {
                return Err("ArtifactMismatch");
            }
            if !filename.is_empty() && valid_output_filename(artifact, filename) {
                Ok(())
            } else {
                Err("FilenameRejected")
            }
        }
        _ => Err("CapabilityMismatch"),
    }
}

fn model_output_finish(capability: u8, body: &[u8]) -> Result<(), ErrorName> {
    exact(body, 5)?;
    let (artifact, _) = model_artifact_and_total(body)?;
    let valid = match capability {
        7 => matches!(artifact, 4 | 5),
        8 => matches!(artifact, 1 | 2),
        _ => false,
    };
    if valid {
        Ok(())
    } else {
        Err("ArtifactMismatch")
    }
}

fn model_output_reply(kind: ModelKind, body: &[u8]) -> Result<(), ErrorName> {
    match kind {
        ModelKind::MediaBeginAccepted | ModelKind::MediaFinished => {
            exact(body, 5)?;
            let (artifact, _) = model_artifact_and_total(body)?;
            if matches!(artifact, 1 | 2 | 4 | 5) {
                Ok(())
            } else {
                Err("ArtifactMismatch")
            }
        }
        ModelKind::MediaChunkAccepted => {
            exact(body, 4)?;
            let offset = read_u32(body, 0).ok_or("BodyLengthMismatch")? as usize;
            if (1..=MAX_TRANSFER_BYTES).contains(&offset) {
                Ok(())
            } else {
                Err("ValueOutOfRange")
            }
        }
        ModelKind::MediaRejected => {
            exact(body, 3)?;
            value_in(body[0], 1, 3)?;
            let status = read_u16(body, 1).ok_or("BodyLengthMismatch")?;
            if matches!(status, 0x0001..=0x0029 | 0x0101..=0x011e) {
                Ok(())
            } else {
                Err("ValueOutOfRange")
            }
        }
        _ => Err("CapabilityKindMismatch"),
    }
}

fn model_body(header: ModelHeader, body: &[u8]) -> Result<(), ErrorName> {
    match header.kind {
        ModelKind::DisplayStage => {
            exact(body, 1)?;
            value_in(body[0], 1, 18)
        }
        ModelKind::DisplayProfile | ModelKind::CardProfile => {
            exact(body, 1)?;
            value_in(body[0], 1, 3)
        }
        ModelKind::DisplayReview => model_review(body),
        ModelKind::DisplayResult => model_result(body),
        ModelKind::KeypadEvent => model_keypad(body),
        ModelKind::CardNormalFactor => model_card_factor(body),
        ModelKind::CardRejected => {
            exact(body, 3)?;
            value_in(body[0], 1, 2)?;
            let status = read_u16(body, 1).ok_or("BodyLengthMismatch")?;
            if (1..=3).contains(&status) {
                Ok(())
            } else {
                Err("ValueOutOfRange")
            }
        }
        ModelKind::CardReadProfile | ModelKind::CardReadNormalFactor => exact(body, 0),
        ModelKind::CameraBegin => model_camera_begin(body),
        ModelKind::CameraChunk | ModelKind::MediaReadChunk => model_chunk(body, true),
        ModelKind::MediaReadBegin => model_media_begin(body),
        ModelKind::MediaBeginAccepted
        | ModelKind::MediaChunkAccepted
        | ModelKind::MediaFinished
        | ModelKind::MediaRejected => model_output_reply(header.kind, body),
        ModelKind::PrintWriteBegin | ModelKind::MediaWriteBegin => {
            model_output_begin(header.capability, body)
        }
        ModelKind::PrintWriteChunk | ModelKind::MediaWriteChunk => model_chunk(body, false),
        ModelKind::PrintWriteFinish | ModelKind::MediaWriteFinish => {
            model_output_finish(header.capability, body)
        }
    }
}

fn model_parse_frame(expected: u8, bytes: &[u8]) -> Result<ModelHeader, ErrorName> {
    let header = model_header(expected, bytes)?;
    let frame_len = HEADER_BYTES
        .checked_add(header.body_len)
        .ok_or("BodyLengthExceeded")?;
    if bytes.len() < frame_len {
        return Err("BodyTruncated");
    }
    if bytes.len() > frame_len {
        return Err("TrailingByte");
    }
    model_body(header, &bytes[HEADER_BYTES..frame_len])?;
    Ok(header)
}

fn model_frame_fact(expected: u8, bytes: &[u8]) -> FrameFact {
    match model_parse_frame(expected, bytes) {
        Ok(header) => FrameFact::Accepted {
            capability: header.capability,
            kind: header.kind_byte,
            sequence: header.sequence,
            body_len: header.body_len,
        },
        Err(error) => FrameFact::Rejected(error),
    }
}

fn product_frame_fact(expected: Capability, bytes: &[u8]) -> FrameFact {
    match parse_frame(expected, bytes) {
        Ok(frame) => FrameFact::Accepted {
            capability: frame.header().capability().wire_value(),
            kind: frame.header().kind().wire_value(),
            sequence: frame.header().sequence(),
            body_len: frame.body().len(),
        },
        Err(error) => FrameFact::Rejected(error_name(error)),
    }
}

fn model_sequence(last: u32, current: u32) -> Result<(), ErrorName> {
    if last == u32::MAX {
        return Err("SequenceExhausted");
    }
    if last == 0 {
        return if current == 1 {
            Ok(())
        } else {
            Err("SequenceSkipped")
        };
    }
    if current == last {
        return Err("SequenceReplay");
    }
    if current < last {
        return Err("SequenceRegression");
    }
    if current != last + 1 {
        return Err("SequenceSkipped");
    }
    Ok(())
}

fn model_stream_facts(expected: u8, bytes: &[u8]) -> Vec<StreamFact> {
    let mut facts = Vec::new();
    let mut offset = 0usize;
    let mut last_sequence = 0u32;
    while offset < bytes.len() {
        let rest = &bytes[offset..];
        if rest.len() < HEADER_BYTES {
            facts.push(StreamFact::Finished("ConnectionClosedMidFrame"));
            return facts;
        }
        let header = match model_header(expected, rest) {
            Ok(header) => header,
            Err(error) => {
                facts.push(StreamFact::Rejected(error));
                return facts;
            }
        };
        let Some(frame_len) = HEADER_BYTES.checked_add(header.body_len) else {
            facts.push(StreamFact::Rejected("BodyLengthExceeded"));
            return facts;
        };
        if rest.len() < frame_len {
            facts.push(StreamFact::Finished("ConnectionClosedMidFrame"));
            return facts;
        }
        if let Err(error) = model_sequence(last_sequence, header.sequence) {
            facts.push(StreamFact::Rejected(error));
            return facts;
        }
        if let Err(error) = model_body(header, &rest[HEADER_BYTES..frame_len]) {
            facts.push(StreamFact::Rejected(error));
            return facts;
        }
        facts.push(StreamFact::Frame {
            capability: header.capability,
            kind: header.kind_byte,
            sequence: header.sequence,
            body_len: header.body_len,
        });
        last_sequence = header.sequence;
        offset += frame_len;
    }
    facts.push(StreamFact::Finished("PeerLost"));
    facts
}

fn product_stream_facts(expected: Capability, bytes: &[u8], schedule: &[u8]) -> Vec<StreamFact> {
    let mut decoder = StreamDecoder::new(expected);
    let mut facts = Vec::new();
    let mut offset = 0usize;
    let mut step = 0usize;
    while offset < bytes.len() {
        let requested = usize::from(schedule[step % schedule.len()]) + 1;
        let end = offset.saturating_add(requested).min(bytes.len());
        match decoder.ingest(&bytes[offset..end]) {
            Ok(outcome) => {
                assert!(outcome.consumed() <= end - offset);
                assert!(outcome.consumed() != 0 || outcome.frame_ready());
                offset += outcome.consumed();
                if outcome.frame_ready() {
                    match decoder.take_frame() {
                        Ok(frame) => facts.push(StreamFact::Frame {
                            capability: frame.header().capability().wire_value(),
                            kind: frame.header().kind().wire_value(),
                            sequence: frame.header().sequence(),
                            body_len: frame.body().len(),
                        }),
                        Err(error) => {
                            facts.push(StreamFact::Rejected(error_name(error)));
                            return facts;
                        }
                    }
                }
            }
            Err(error) => {
                facts.push(StreamFact::Rejected(error_name(error)));
                return facts;
            }
        }
        step += 1;
    }
    facts.push(StreamFact::Finished(error_name(decoder.finish())));
    facts
}

fn encoded(capability: Capability, kind: MessageKind, sequence: u32, body: &[u8]) -> Vec<u8> {
    let mut frame = vec![0u8; HEADER_BYTES + body.len()];
    let written = encode_frame(capability, kind, sequence, body, &mut frame)
        .expect("generated body is canonical");
    assert_eq!(written, frame.len());
    frame
}

fn received(
    capability: Capability,
    kind: MessageKind,
    sequence: u32,
    body: &[u8],
) -> ReceivedFrame {
    let frame = encoded(capability, kind, sequence, body);
    let mut decoder = StreamDecoder::new(capability);
    if sequence > 1 {
        for prior in 1..sequence {
            let (prior_kind, prior_body): (MessageKind, &[u8]) = match capability {
                Capability::CardResponse => (MessageKind::CardProfile, &[1]),
                Capability::MediaInput => (MessageKind::MediaChunkAccepted, &[1, 0, 0, 0]),
                _ => (kind, body),
            };
            let prior_frame = encoded(capability, prior_kind, prior, prior_body);
            decoder
                .ingest(&prior_frame)
                .expect("prior frame is canonical");
            drop(decoder.take_frame().expect("prior frame is complete"));
        }
    }
    decoder.ingest(&frame).expect("frame is canonical");
    decoder.take_frame().expect("frame is complete")
}

fn exercise_sequences(selected: Capability) {
    let kind = match selected {
        Capability::Display => MessageKind::DisplayStage,
        Capability::Keypad => MessageKind::KeypadEvent,
        Capability::CardResponse => MessageKind::CardProfile,
        Capability::CardRequest => MessageKind::CardReadProfile,
        Capability::CameraInput => MessageKind::CameraBegin,
        Capability::MediaInput => MessageKind::MediaReadBegin,
        Capability::PrintOutput => MessageKind::PrintWriteBegin,
        Capability::MediaOutput => MessageKind::MediaWriteBegin,
    };
    let mut protocol = OneWayProtocol::new(selected);
    assert_eq!(protocol.next(kind).expect("first sequence").sequence(), 1);
    assert_eq!(protocol.next(kind).expect("second sequence").sequence(), 2);
    let wrong = if selected == Capability::Display {
        MessageKind::KeypadEvent
    } else {
        MessageKind::DisplayStage
    };
    assert_eq!(
        error_name(protocol.next(wrong).expect_err("wrong capability rejects")),
        "CapabilityKindMismatch"
    );
    assert_eq!(
        error_name(protocol.next(kind).expect_err("terminal state absorbs")),
        "DecoderTerminated"
    );
    assert_eq!(
        error_name(OneWayProtocol::fuzz_sequence_exhaustion_probe(
            Capability::Display
        )),
        "SequenceExhausted"
    );
    assert_eq!(
        error_name(StreamDecoder::fuzz_sequence_exhaustion_probe(selected)),
        "SequenceExhausted"
    );
}

fn exercise_card_exchange(selector: u8) {
    let mut exchange = ExchangeProtocol::new(Capability::CardRequest, Capability::CardResponse)
        .expect("the card pair is fixed");
    match selector % 6 {
        0 => {
            let frame = received(Capability::CardResponse, MessageKind::CardProfile, 1, &[1]);
            assert_eq!(
                error_name(exchange.accept_response(&frame).expect_err("no request")),
                "NoOutstandingExchange"
            );
        }
        1 => {
            exchange
                .begin(MessageKind::CardReadProfile)
                .expect("first request");
            assert_eq!(
                error_name(
                    exchange
                        .begin(MessageKind::CardReadProfile)
                        .expect_err("outstanding request")
                ),
                "OutstandingExchange"
            );
        }
        2 => {
            exchange
                .begin(MessageKind::CardReadProfile)
                .expect("first request");
            let frame = received(Capability::CardResponse, MessageKind::CardProfile, 1, &[1]);
            exchange.accept_response(&frame).expect("matching reply");
            assert_eq!(
                exchange
                    .begin(MessageKind::CardReadNormalFactor)
                    .expect("next request")
                    .sequence(),
                2
            );
        }
        3 => {
            exchange
                .begin(MessageKind::CardReadProfile)
                .expect("first request");
            let frame = received(
                Capability::CardResponse,
                MessageKind::CardRejected,
                1,
                &[MessageKind::CardReadProfile.wire_value(), 1, 0],
            );
            assert_eq!(
                error_name(exchange.accept_response(&frame).expect_err("device reject")),
                "DeviceRejected"
            );
        }
        4 => {
            exchange
                .begin(MessageKind::CardReadProfile)
                .expect("first request");
            let frame = received(Capability::CardResponse, MessageKind::CardProfile, 2, &[1]);
            assert_eq!(
                error_name(
                    exchange
                        .accept_response(&frame)
                        .expect_err("wrong sequence")
                ),
                "ResponseSequenceMismatch"
            );
        }
        5 => {
            exchange
                .begin(MessageKind::CardReadNormalFactor)
                .expect("first request");
            let frame = received(Capability::CardResponse, MessageKind::CardProfile, 1, &[1]);
            assert_eq!(
                error_name(exchange.accept_response(&frame).expect_err("wrong kind")),
                "ResponseKindMismatch"
            );
        }
        _ => unreachable!("modulo six is exhaustive"),
    }
}

fn exercise_output_exchange_success(exchange: &mut ExchangeProtocol, byte: u8) {
    let reply = received(
        Capability::MediaInput,
        MessageKind::MediaBeginAccepted,
        1,
        &[2, 3, 0, 0, 0],
    );
    exchange
        .accept_response(&reply)
        .expect("matching begin reply");
    let chunk = OutputBody::WriteChunk {
        offset: 0,
        chunk: &[byte, byte, byte],
    };
    assert_eq!(
        exchange
            .begin_output(chunk)
            .expect("canonical chunk")
            .sequence(),
        2
    );
    let reply = received(
        Capability::MediaInput,
        MessageKind::MediaChunkAccepted,
        2,
        &[3, 0, 0, 0],
    );
    exchange
        .accept_response(&reply)
        .expect("matching chunk reply");
    let finish = OutputBody::WriteFinish {
        artifact: Artifact::RawTransaction,
        total_len: 3,
    };
    assert_eq!(
        exchange
            .begin_output(finish)
            .expect("canonical finish")
            .sequence(),
        3
    );
    let reply = received(
        Capability::MediaInput,
        MessageKind::MediaFinished,
        3,
        &[2, 3, 0, 0, 0],
    );
    exchange
        .accept_response(&reply)
        .expect("matching finish reply");
}

fn exercise_output_exchange(selector: u8, payload: &[u8]) {
    let filename = b"qk-0123456789abcdef0123456789abcdef-final.tx";
    let byte = payload.first().copied().unwrap_or(0x51);
    let mut exchange = ExchangeProtocol::new(Capability::MediaOutput, Capability::MediaInput)
        .expect("the media-output pair is fixed");
    let begin = OutputBody::WriteBegin {
        artifact: Artifact::RawTransaction,
        total_len: 3,
        filename,
    };
    let outbound = exchange.begin_output(begin).expect("canonical begin");
    assert_eq!(outbound.sequence(), 1);
    match selector % 5 {
        0 => exercise_output_exchange_success(&mut exchange, byte),
        1 => {
            let reply = received(
                Capability::MediaInput,
                MessageKind::MediaBeginAccepted,
                1,
                &[1, 3, 0, 0, 0],
            );
            assert_eq!(
                error_name(
                    exchange
                        .accept_response(&reply)
                        .expect_err("wrong artifact")
                ),
                "ArtifactMismatch"
            );
        }
        2 => {
            let reply = received(
                Capability::MediaInput,
                MessageKind::MediaBeginAccepted,
                1,
                &[2, 4, 0, 0, 0],
            );
            assert_eq!(
                error_name(exchange.accept_response(&reply).expect_err("wrong total")),
                "ArtifactMismatch"
            );
        }
        3 => {
            let reply = received(
                Capability::MediaInput,
                MessageKind::MediaChunkAccepted,
                1,
                &[3, 0, 0, 0],
            );
            assert_eq!(
                error_name(exchange.accept_response(&reply).expect_err("wrong kind")),
                "ResponseKindMismatch"
            );
        }
        4 => {
            let reply = received(
                Capability::MediaInput,
                MessageKind::MediaRejected,
                1,
                &[MessageKind::MediaWriteBegin.wire_value(), 1, 0],
            );
            assert_eq!(
                error_name(exchange.accept_response(&reply).expect_err("device reject")),
                "DeviceRejected"
            );
        }
        _ => unreachable!("modulo five is exhaustive"),
    }
}

fn exercise_oversized_input_chunk() {
    let mut transfer = InputTransfer::begin(
        Capability::CameraInput,
        InputBody::Begin {
            source: Source::CameraBbqrPsbt,
            total_len: u32::try_from(MAX_CHUNK_BYTES + 1).expect("fixed u32 total"),
            filename: None,
        },
    )
    .expect("bounded BBQr transfer");
    let chunk = vec![0u8; MAX_CHUNK_BYTES + 1];
    assert_eq!(
        error_name(
            transfer
                .accept(InputBody::Chunk {
                    offset: 0,
                    final_chunk: true,
                    chunk: &chunk,
                })
                .expect_err("oversized direct chunk")
        ),
        "ChunkLengthExceeded"
    );
}

fn assert_input_completion_is_one_use(transfer: &mut InputTransfer) {
    transfer.finish().expect("complete transfer");
    assert_eq!(
        error_name(transfer.finish().expect_err("second finish")),
        "UnexpectedFrame"
    );
    assert_eq!(
        error_name(transfer.finish().expect_err("terminal state absorbs")),
        "DecoderTerminated"
    );
}

fn exercise_input_transfer(selector: u8, payload: &[u8]) {
    let source = if selector & 1 == 0 {
        Source::CameraA1Candidate
    } else {
        Source::CameraKitCandidate
    };
    let total = if source == Source::CameraA1Candidate {
        67
    } else {
        142
    };
    let mut transfer = InputTransfer::begin(
        Capability::CameraInput,
        InputBody::Begin {
            source,
            total_len: total,
            filename: None,
        },
    )
    .expect("canonical camera source");
    let first_len = usize::from(selector % 16 + 1).min(total as usize - 1);
    let bytes = vec![payload.first().copied().unwrap_or(0x51); total as usize];
    match (selector / 2) % 6 {
        0 => {
            transfer
                .accept(InputBody::Chunk {
                    offset: 0,
                    final_chunk: false,
                    chunk: &bytes[..first_len],
                })
                .expect("first chunk");
            transfer
                .accept(InputBody::Chunk {
                    offset: u32::try_from(first_len).expect("bounded offset"),
                    final_chunk: true,
                    chunk: &bytes[first_len..],
                })
                .expect("final chunk");
            assert_input_completion_is_one_use(&mut transfer);
        }
        1 => assert_eq!(
            error_name(
                transfer
                    .accept(InputBody::Chunk {
                        offset: 1,
                        final_chunk: false,
                        chunk: &bytes[..first_len]
                    })
                    .expect_err("offset mismatch")
            ),
            "OffsetMismatch"
        ),
        2 => assert_eq!(
            error_name(
                transfer
                    .accept(InputBody::Chunk {
                        offset: 0,
                        final_chunk: true,
                        chunk: &bytes[..first_len]
                    })
                    .expect_err("final mismatch")
            ),
            "FinalFlagMismatch"
        ),
        3 => assert_eq!(
            error_name(transfer.finish().expect_err("incomplete transfer")),
            "TransferIncomplete"
        ),
        4 => assert_eq!(
            error_name(
                transfer
                    .accept(InputBody::Chunk {
                        offset: 0,
                        final_chunk: true,
                        chunk: &[0u8; 143]
                    })
                    .expect_err("excess transfer")
            ),
            "TransferLengthExceeded"
        ),
        5 => assert_eq!(
            error_name(
                transfer
                    .accept(InputBody::Chunk {
                        offset: 0,
                        final_chunk: false,
                        chunk: &[],
                    })
                    .expect_err("empty chunk")
            ),
            "ChunkLengthZero"
        ),
        _ => unreachable!("modulo six is exhaustive"),
    }
    if selector == 0xfe {
        exercise_oversized_input_chunk();
    }
}

fn assert_output_completion_is_one_use(transfer: &mut OutputTransfer, total: u32) {
    let finish = OutputBody::WriteFinish {
        artifact: Artifact::RawTransaction,
        total_len: total,
    };
    transfer.finish(finish).expect("matching finish");
    assert_eq!(
        error_name(transfer.finish(finish).expect_err("second finish")),
        "UnexpectedFrame"
    );
    assert_eq!(
        error_name(transfer.finish(finish).expect_err("terminal state absorbs")),
        "DecoderTerminated"
    );
}

fn exercise_output_transfer(selector: u8, payload: &[u8]) {
    let total = 3u32;
    let filename = b"qk-0123456789abcdef0123456789abcdef-final.tx";
    let mut transfer = OutputTransfer::begin(
        Capability::MediaOutput,
        OutputBody::WriteBegin {
            artifact: Artifact::RawTransaction,
            total_len: total,
            filename,
        },
    )
    .expect("canonical media output");
    let byte = payload.first().copied().unwrap_or(0x51);
    match selector % 5 {
        0 => {
            transfer
                .accept(OutputBody::WriteChunk {
                    offset: 0,
                    chunk: &[byte, byte, byte],
                })
                .expect("complete chunk");
            assert_output_completion_is_one_use(&mut transfer, total);
        }
        1 => assert_eq!(
            error_name(
                transfer
                    .accept(OutputBody::WriteChunk {
                        offset: 1,
                        chunk: &[byte]
                    })
                    .expect_err("offset mismatch")
            ),
            "OffsetMismatch"
        ),
        2 => assert_eq!(
            error_name(
                transfer
                    .accept(OutputBody::WriteChunk {
                        offset: 0,
                        chunk: &[byte, byte, byte, byte]
                    })
                    .expect_err("excess transfer")
            ),
            "TransferLengthExceeded"
        ),
        3 => assert_eq!(
            error_name(
                transfer
                    .finish(OutputBody::WriteFinish {
                        artifact: Artifact::RawTransaction,
                        total_len: total
                    })
                    .expect_err("incomplete transfer")
            ),
            "TransferIncomplete"
        ),
        4 => {
            transfer
                .accept(OutputBody::WriteChunk {
                    offset: 0,
                    chunk: &[byte, byte, byte],
                })
                .expect("complete chunk");
            assert_eq!(
                error_name(
                    transfer
                        .finish(OutputBody::WriteFinish {
                            artifact: Artifact::FinalizedPsbt,
                            total_len: total
                        })
                        .expect_err("artifact mismatch")
                ),
                "ArtifactMismatch"
            );
        }
        _ => unreachable!("modulo five is exhaustive"),
    }
}

fn exercise_short_output() {
    let body = [1u8];
    let mut output = [0xa5u8; HEADER_BYTES];
    let before = output;
    assert_eq!(
        error_name(
            encode_frame(
                Capability::Display,
                MessageKind::DisplayStage,
                1,
                &body,
                &mut output
            )
            .expect_err("one-byte-short output")
        ),
        "OutputBufferTooSmall"
    );
    assert_eq!(output, before);
}

fn exercise_wipe(payload: &[u8]) {
    let length = payload.len().clamp(1, 4_096);
    let mut body = Vec::with_capacity(9 + length);
    body.extend_from_slice(&0u32.to_le_bytes());
    body.extend_from_slice(
        &u32::try_from(length)
            .expect("bounded wipe length")
            .to_le_bytes(),
    );
    body.push(1);
    body.extend(core::iter::repeat_n(
        payload.first().copied().unwrap_or(0x51),
        length,
    ));
    let frame = encoded(Capability::CameraInput, MessageKind::CameraChunk, 1, &body);
    let mut decoder = StreamDecoder::new(Capability::CameraInput);
    decoder.ingest(&frame).expect("canonical wipe frame");
    let received = decoder.take_frame().expect("wipe frame ready");
    let capacity = received.allocation_capacity();
    reset_wiped_bytes();
    drop(received);
    assert_eq!(wiped_bytes(), capacity);

    let mut partial = frame;
    partial.truncate(HEADER_BYTES + 1);
    let mut decoder = StreamDecoder::new(Capability::CameraInput);
    decoder.ingest(&partial).expect("valid partial frame");
    reset_wiped_bytes();
    drop(decoder);
    assert!(wiped_bytes() >= HEADER_BYTES + length + 9);
}

fn exercise_max_chunk() {
    let mut body = vec![0x5a; MAX_CHUNK_BODY_BYTES];
    body[..4].copy_from_slice(&0u32.to_le_bytes());
    body[4..8].copy_from_slice(
        &u32::try_from(MAX_CHUNK_BYTES)
            .expect("fixed u32 length")
            .to_le_bytes(),
    );
    body[8] = 1;
    let frame = encoded(Capability::CameraInput, MessageKind::CameraChunk, 1, &body);
    assert_eq!(frame.len(), MAX_PRESENTED_BYTES);
    assert!(model_parse_frame(0x05, &frame).is_ok());
    assert!(parse_frame(Capability::CameraInput, &frame).is_ok());
    let mut decoder = StreamDecoder::new(Capability::CameraInput);
    let outcome = decoder.ingest(&frame).expect("maximum chunk presentation");
    assert_eq!(outcome.consumed(), MAX_PRESENTED_BYTES);
    assert!(outcome.frame_ready());
    drop(decoder.take_frame().expect("maximum frame ready"));
}

fuzz_target!(|data: &[u8]| {
    let controls = &data[..data.len().min(CONTROL_BYTES)];
    let candidate = data.get(CONTROL_BYTES..).unwrap_or(&[]);
    let (expected_byte, expected) =
        selected_capability(controls.first().copied().unwrap_or_default());
    let schedule = controls
        .get(1..9)
        .filter(|bytes| !bytes.is_empty())
        .unwrap_or(&[0]);

    assert_eq!(
        model_frame_fact(expected_byte, candidate),
        product_frame_fact(expected, candidate)
    );
    assert_eq!(
        model_stream_facts(expected_byte, candidate),
        product_stream_facts(expected, candidate, schedule)
    );
    exercise_sequences(expected);
    exercise_card_exchange(controls.get(9).copied().unwrap_or_default());
    exercise_output_exchange(controls.get(13).copied().unwrap_or_default(), candidate);
    exercise_input_transfer(controls.get(10).copied().unwrap_or_default(), candidate);
    exercise_output_transfer(controls.get(11).copied().unwrap_or_default(), candidate);
    exercise_short_output();
    exercise_wipe(candidate);
    if controls.get(12).copied() == Some(0xa5) {
        exercise_max_chunk();
    }
});
