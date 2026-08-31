//! One-active-transfer egress implementation.

use crate::mock::MockOutputWriter;
use crate::wipe::{self, WipingVec};
use crate::{Artifact, InnerError, Sink, MAX_CHUNK_BYTES, MAX_FILENAME_BYTES, MAX_TRANSFER_BYTES};
use qk_bbqr::{
    encode_typed_frame, encoded_part_count, BbqrFileType, MAX_FRAME_TEXT_BYTES,
    MAX_PART_DECODED_BYTES, MAX_TOTAL_DECODED_BYTES,
};

pub(crate) struct EgressTransfer {
    sink: Sink,
    artifact: Artifact,
    total_len: usize,
    next_offset: usize,
    filename: [u8; MAX_FILENAME_BYTES],
    filename_len: usize,
    non_final_part_len: usize,
    data: WipingVec,
}

impl EgressTransfer {
    pub(crate) fn begin(
        sink: Sink,
        artifact: Artifact,
        total_len: usize,
        aux: &[u8],
    ) -> Result<Self, InnerError> {
        validate_pair(sink, artifact)?;
        if total_len == 0 {
            return Err(InnerError::DeclaredLengthZero);
        }
        let cap = if sink == Sink::Bbqr {
            MAX_TOTAL_DECODED_BYTES
        } else {
            MAX_TRANSFER_BYTES
        };
        if total_len > cap {
            return Err(InnerError::DeclaredLengthExceeded);
        }

        let mut filename = [0u8; MAX_FILENAME_BYTES];
        let mut filename_len = 0usize;
        let mut non_final_part_len = 0usize;
        match sink {
            Sink::Sd => {
                let Some(&length) = aux.first() else {
                    return Err(InnerError::InvalidFilename);
                };
                filename_len = usize::from(length);
                if filename_len == 0
                    || filename_len > MAX_FILENAME_BYTES
                    || aux.len() != 1 + filename_len
                    || !valid_output_filename(artifact, &aux[1..])
                {
                    return Err(InnerError::InvalidFilename);
                }
                filename[..filename_len].copy_from_slice(&aux[1..]);
            }
            Sink::Bbqr => {
                if aux.len() != 2 {
                    return Err(if aux.len() < 2 {
                        InnerError::BodyTruncated
                    } else {
                        InnerError::TrailingByte
                    });
                }
                non_final_part_len = usize::from(u16::from_le_bytes([aux[0], aux[1]]));
                if !(5..=MAX_PART_DECODED_BYTES).contains(&non_final_part_len)
                    || !non_final_part_len.is_multiple_of(5)
                {
                    return Err(InnerError::InvalidBbqrPartLength);
                }
                encoded_part_count(total_len, non_final_part_len).map_err(InnerError::Bbqr)?;
            }
            Sink::Print => {
                if !aux.is_empty() {
                    return Err(InnerError::TrailingByte);
                }
            }
        }

        let data = WipingVec::try_zeroed(total_len).map_err(|_| InnerError::AllocationFailed)?;
        Ok(Self {
            sink,
            artifact,
            total_len,
            next_offset: 0,
            filename,
            filename_len,
            non_final_part_len,
            data,
        })
    }

    pub(crate) fn write(&mut self, offset: usize, chunk: &[u8]) -> Result<usize, InnerError> {
        if chunk.is_empty() {
            return Err(InnerError::ChunkLengthZero);
        }
        if chunk.len() > MAX_CHUNK_BYTES {
            return Err(InnerError::ChunkLengthExceeded);
        }
        if offset != self.next_offset {
            return Err(InnerError::OffsetMismatch);
        }
        let end = offset
            .checked_add(chunk.len())
            .filter(|end| *end <= self.total_len)
            .ok_or(InnerError::TransferLengthExceeded)?;
        self.data.as_mut_slice()[offset..end].copy_from_slice(chunk);
        self.next_offset = end;
        Ok(end)
    }

    pub(crate) fn finish(
        self,
        writer: Option<&mut MockOutputWriter>,
    ) -> Result<WipingVec, InnerError> {
        if self.next_offset != self.total_len {
            return Err(InnerError::TransferIncomplete);
        }
        match self.sink {
            Sink::Sd => {
                let writer = writer.ok_or(InnerError::BoundaryMissing)?;
                writer.write_sd(&self.filename[..self.filename_len], self.data.as_slice())?;
                receipt(self.sink, self.artifact, self.total_len)
            }
            Sink::Print => {
                let writer = writer.ok_or(InnerError::BoundaryMissing)?;
                writer.write_print(self.data.as_slice())?;
                receipt(self.sink, self.artifact, self.total_len)
            }
            Sink::Bbqr => {
                if writer.is_some() {
                    return Err(InnerError::UnexpectedBoundary);
                }
                encode_bbqr(
                    self.artifact,
                    self.total_len,
                    self.non_final_part_len,
                    self.data.as_slice(),
                )
            }
        }
    }
}

impl Drop for EgressTransfer {
    fn drop(&mut self) {
        wipe::bytes(&mut self.filename);
        self.filename_len = 0;
        self.non_final_part_len = 0;
    }
}

fn validate_pair(sink: Sink, artifact: Artifact) -> Result<(), InnerError> {
    let valid = matches!(
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
    if valid {
        Ok(())
    } else {
        Err(InnerError::SinkArtifactMismatch)
    }
}

fn valid_output_filename(artifact: Artifact, name: &[u8]) -> bool {
    let suffix: &[u8] = match artifact {
        Artifact::FinalizedPsbt => b"-final.psbt",
        Artifact::RawTransaction => b"-final.tx",
        Artifact::WatchOnlyBsms => b"-watch.bsms",
        Artifact::A1PrintArtifact | Artifact::KitPrintArtifact => return false,
    };
    let expected_len = 3 + 32 + suffix.len();
    name.len() == expected_len
        && &name[..3] == b"qk-"
        && name[3..35]
            .iter()
            .all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f'))
        && &name[35..] == suffix
}

fn receipt(sink: Sink, artifact: Artifact, total_len: usize) -> Result<WipingVec, InnerError> {
    let mut body = WipingVec::try_zeroed(6).map_err(|_| InnerError::AllocationFailed)?;
    body.as_mut_slice()[0] = sink.wire_value();
    body.as_mut_slice()[1] = artifact.wire_value();
    body.as_mut_slice()[2..6].copy_from_slice(&(total_len as u32).to_le_bytes());
    Ok(body)
}

fn encode_bbqr(
    artifact: Artifact,
    total_len: usize,
    non_final_part_len: usize,
    data: &[u8],
) -> Result<WipingVec, InnerError> {
    let file_type = match artifact {
        Artifact::FinalizedPsbt => BbqrFileType::Psbt,
        Artifact::RawTransaction => BbqrFileType::Transaction,
        _ => return Err(InnerError::SinkArtifactMismatch),
    };
    let frame_count =
        encoded_part_count(total_len, non_final_part_len).map_err(InnerError::Bbqr)?;
    let maximum = 8usize
        .checked_add(
            usize::from(frame_count)
                .checked_mul(2 + MAX_FRAME_TEXT_BYTES)
                .ok_or(InnerError::DeclaredLengthExceeded)?,
        )
        .filter(|length| *length <= crate::MAX_INNER_BODY_BYTES)
        .ok_or(InnerError::DeclaredLengthExceeded)?;
    let mut body = WipingVec::try_zeroed(maximum).map_err(|_| InnerError::AllocationFailed)?;
    body.as_mut_slice()[0] = Sink::Bbqr.wire_value();
    body.as_mut_slice()[1] = artifact.wire_value();
    body.as_mut_slice()[2..6].copy_from_slice(&(total_len as u32).to_le_bytes());
    body.as_mut_slice()[6..8].copy_from_slice(&frame_count.to_le_bytes());
    let mut cursor = 8usize;
    let mut frame = [0u8; MAX_FRAME_TEXT_BYTES];
    for index in 0..frame_count {
        let result = encode_typed_frame(file_type, data, non_final_part_len, index, &mut frame);
        let frame_len = match result {
            Ok(length) => length,
            Err(error) => {
                wipe::bytes(&mut frame);
                return Err(InnerError::Bbqr(error));
            }
        };
        body.as_mut_slice()[cursor..cursor + 2].copy_from_slice(&(frame_len as u16).to_le_bytes());
        cursor += 2;
        body.as_mut_slice()[cursor..cursor + frame_len].copy_from_slice(&frame[..frame_len]);
        cursor += frame_len;
        wipe::bytes(&mut frame);
    }
    body.truncate(cursor);
    Ok(body)
}
