//! One-active-transfer ingress implementation.

use crate::mock::MockInput;
use crate::wipe::WipingVec;
use crate::{
    InnerError, Source, A1_CANDIDATE_BYTES, KIT_CANDIDATE_BYTES, MAX_CHUNK_BYTES,
    MAX_FILENAME_BYTES, MAX_TRANSFER_BYTES,
};
use qk_bbqr::{BbqrFileType, Reassembler, MAX_FRAME_TEXT_BYTES, MAX_SUBMISSIONS};

pub(crate) struct IngressTransfer {
    source: Source,
    data: WipingVec,
    next_offset: usize,
}

impl IngressTransfer {
    pub(crate) fn begin(
        source: Source,
        aux: &[u8],
        input: &mut MockInput,
    ) -> Result<Self, InnerError> {
        if !aux.is_empty() {
            return Err(InnerError::TrailingByte);
        }
        let raw = input.take(source)?;
        let data = match source {
            Source::CameraA1Candidate => exact_candidate(raw, A1_CANDIDATE_BYTES)?,
            Source::CameraKitCandidate => exact_candidate(raw, KIT_CANDIDATE_BYTES)?,
            Source::CameraBbqrPsbt => reassemble_bbqr(raw)?,
            Source::MediaPsbt => parse_media_record(raw)?,
        };
        Ok(Self {
            source,
            data,
            next_offset: 0,
        })
    }

    pub(crate) const fn source(&self) -> Source {
        self.source
    }

    pub(crate) fn total_len(&self) -> usize {
        self.data.len()
    }

    pub(crate) fn read(&mut self, expected_offset: usize) -> Result<(WipingVec, bool), InnerError> {
        if expected_offset != self.next_offset {
            return Err(InnerError::OffsetMismatch);
        }
        let remaining = self.data.len() - self.next_offset;
        let chunk_len = remaining.min(MAX_CHUNK_BYTES);
        debug_assert!(chunk_len != 0);
        let final_chunk = chunk_len == remaining;
        let mut body =
            WipingVec::try_zeroed(9 + chunk_len).map_err(|_| InnerError::AllocationFailed)?;
        body.as_mut_slice()[..4].copy_from_slice(&(self.next_offset as u32).to_le_bytes());
        body.as_mut_slice()[4..8].copy_from_slice(&(chunk_len as u32).to_le_bytes());
        body.as_mut_slice()[8] = u8::from(final_chunk);
        let end = self.next_offset + chunk_len;
        body.as_mut_slice()[9..].copy_from_slice(&self.data.as_slice()[self.next_offset..end]);
        self.next_offset = end;
        Ok((body, final_chunk))
    }
}

fn exact_candidate(raw: WipingVec, expected: usize) -> Result<WipingVec, InnerError> {
    if raw.len() != expected {
        return Err(InnerError::SourceLengthMismatch);
    }
    Ok(raw)
}

fn parse_media_record(raw: WipingVec) -> Result<WipingVec, InnerError> {
    let bytes = raw.as_slice();
    let Some(&name_len_byte) = bytes.first() else {
        return Err(InnerError::SourceLengthMismatch);
    };
    let name_len = usize::from(name_len_byte);
    if !(1..=MAX_FILENAME_BYTES).contains(&name_len) {
        return Err(InnerError::InvalidFilename);
    }
    let data_len_offset = 1usize
        .checked_add(name_len)
        .ok_or(InnerError::SourceLengthMismatch)?;
    let data_offset = data_len_offset
        .checked_add(4)
        .ok_or(InnerError::SourceLengthMismatch)?;
    if bytes.len() < data_offset {
        return Err(InnerError::SourceLengthMismatch);
    }
    let name = &bytes[1..data_len_offset];
    if !valid_input_filename(name) {
        return Err(InnerError::InvalidFilename);
    }
    let data_len = read_u32(&bytes[data_len_offset..data_offset]) as usize;
    if data_len == 0 {
        return Err(InnerError::DeclaredLengthZero);
    }
    if data_len > MAX_TRANSFER_BYTES {
        return Err(InnerError::DeclaredLengthExceeded);
    }
    let end = data_offset
        .checked_add(data_len)
        .ok_or(InnerError::DeclaredLengthExceeded)?;
    if bytes.len() != end {
        return Err(InnerError::SourceLengthMismatch);
    }
    WipingVec::try_from_slice(&bytes[data_offset..end]).map_err(|_| InnerError::AllocationFailed)
}

fn valid_input_filename(name: &[u8]) -> bool {
    name.ends_with(b".psbt")
        && name.iter().all(|byte| {
            byte.is_ascii_lowercase() || byte.is_ascii_digit() || matches!(byte, b'.' | b'_' | b'-')
        })
        && !name.contains(&b'/')
        && !name.contains(&b'\\')
}

fn reassemble_bbqr(raw: WipingVec) -> Result<WipingVec, InnerError> {
    let bytes = raw.as_slice();
    if bytes.len() < 2 {
        return Err(InnerError::SourceLengthMismatch);
    }
    let submission_count = usize::from(u16::from_le_bytes([bytes[0], bytes[1]]));
    if !(1..=MAX_SUBMISSIONS).contains(&submission_count) {
        return Err(InnerError::SourceLengthMismatch);
    }

    let mut assembled = WipingVec::try_zeroed(qk_bbqr::MAX_TOTAL_DECODED_BYTES)
        .map_err(|_| InnerError::AllocationFailed)?;
    let complete_len = {
        let output: &mut [u8; qk_bbqr::MAX_TOTAL_DECODED_BYTES] = assembled
            .as_mut_slice()
            .try_into()
            .map_err(|_| InnerError::AllocationFailed)?;
        let mut reassembler = Reassembler::new_typed(BbqrFileType::Psbt, output);
        let mut cursor = 2usize;
        for _ in 0..submission_count {
            let length_end = cursor
                .checked_add(2)
                .ok_or(InnerError::SourceLengthMismatch)?;
            if length_end > bytes.len() {
                return Err(InnerError::SourceLengthMismatch);
            }
            let frame_len = usize::from(u16::from_le_bytes([bytes[cursor], bytes[cursor + 1]]));
            if !(8..=MAX_FRAME_TEXT_BYTES).contains(&frame_len) {
                return Err(InnerError::SourceLengthMismatch);
            }
            let frame_end = length_end
                .checked_add(frame_len)
                .ok_or(InnerError::SourceLengthMismatch)?;
            if frame_end > bytes.len() {
                return Err(InnerError::SourceLengthMismatch);
            }
            reassembler
                .submit(&bytes[length_end..frame_end])
                .map_err(InnerError::Bbqr)?;
            cursor = frame_end;
        }
        if cursor != bytes.len() {
            return Err(InnerError::SourceLengthMismatch);
        }
        reassembler.payload().map_err(InnerError::Bbqr)?.len()
    };
    assembled.truncate(complete_len);
    Ok(assembled)
}

fn read_u32(bytes: &[u8]) -> u32 {
    u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]])
}
