//! Bounded SOCK_STREAM chunk reassembly without socket access.

use crate::wipe::{self, WipingByteVec};
use crate::wire::{parse_header, validate_payload_shape};
use crate::{FrameHeader, IpcError, HEADER_BYTES};

/// Result of accepting one byte chunk.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct IngestOutcome {
    consumed: usize,
    frame_ready: bool,
}

impl IngestOutcome {
    /// Bytes consumed from the presented chunk.
    pub const fn consumed(&self) -> usize {
        self.consumed
    }

    /// Whether exactly one complete frame is ready to take.
    pub const fn frame_ready(&self) -> bool {
        self.frame_ready
    }
}

/// One complete decoder-owned frame.
///
/// The payload owner is deliberately non-Clone, non-Copy, non-Debug and
/// non-Display. Drop clears the full allocation capacity.
pub struct ReceivedFrame {
    header: FrameHeader,
    payload: WipingByteVec,
}

impl ReceivedFrame {
    /// Immutable parsed header facts.
    pub const fn header(&self) -> &FrameHeader {
        &self.header
    }

    /// Exact opaque payload bytes.
    pub fn payload(&self) -> &[u8] {
        self.payload.as_slice()
    }
}

impl Drop for ReceivedFrame {
    fn drop(&mut self) {
        wipe::bytes(&mut self.header.session_id);
    }
}

/// Pure, bounded decoder for arbitrary stream chunking.
///
/// At most one frame is owned. If a chunk coalesces multiple frames, ingest
/// stops at the first frame and reports the exact consumed prefix.
pub struct StreamDecoder {
    header_bytes: [u8; HEADER_BYTES],
    header_len: usize,
    parsed_header: Option<FrameHeader>,
    payload: WipingByteVec,
    payload_len: usize,
    frame_ready: bool,
    terminated: bool,
}

impl StreamDecoder {
    /// Construct one empty decoder.
    pub fn new() -> Self {
        Self {
            header_bytes: [0; HEADER_BYTES],
            header_len: 0,
            parsed_header: None,
            payload: WipingByteVec::default(),
            payload_len: 0,
            frame_ready: false,
            terminated: false,
        }
    }

    /// Ingest bytes plus the mandatory control-message-presence fact.
    ///
    /// `ancillary_present` always precedes byte consumption. Any true value
    /// clears accumulated state, latches terminal, and returns
    /// [`IpcError::AncillaryData`].
    pub fn ingest(
        &mut self,
        input: &[u8],
        ancillary_present: bool,
    ) -> Result<IngestOutcome, IpcError> {
        if self.terminated {
            return Err(IpcError::DecoderTerminated);
        }
        if ancillary_present {
            return Err(self.terminate(IpcError::AncillaryData));
        }
        if self.frame_ready {
            return Err(self.terminate(IpcError::OutstandingExchange));
        }

        let mut consumed = 0usize;
        if self.parsed_header.is_none() {
            let required = HEADER_BYTES - self.header_len;
            let copied = required.min(input.len());
            let source = input.get(..copied).ok_or(IpcError::InvalidTransition)?;
            let destination = self
                .header_bytes
                .get_mut(self.header_len..self.header_len + copied)
                .ok_or(IpcError::InvalidTransition)?;
            destination.copy_from_slice(source);
            self.header_len += copied;
            consumed += copied;
            if self.header_len < HEADER_BYTES {
                return Ok(IngestOutcome {
                    consumed,
                    frame_ready: false,
                });
            }

            let header = match parse_header(&self.header_bytes) {
                Ok(header) => header,
                Err(error) => return Err(self.terminate(error)),
            };
            let expected_payload = header.payload_len() as usize;
            let payload = match WipingByteVec::try_zeroed(expected_payload) {
                Ok(payload) => payload,
                Err(()) => return Err(self.terminate(IpcError::PayloadAllocationFailed)),
            };
            self.parsed_header = Some(header);
            self.payload = payload;
            self.payload_len = 0;
            wipe::bytes(&mut self.header_bytes);
            self.header_len = 0;
            if expected_payload == 0 {
                if let Err(error) = validate_payload_shape(header.kind(), expected_payload) {
                    return Err(self.terminate(error));
                }
                self.frame_ready = true;
                return Ok(IngestOutcome {
                    consumed,
                    frame_ready: true,
                });
            }
        }

        let expected_payload = self.payload.as_slice().len();
        let remaining = expected_payload
            .checked_sub(self.payload_len)
            .ok_or_else(|| self.terminate(IpcError::InvalidTransition))?;
        let available = input
            .len()
            .checked_sub(consumed)
            .ok_or_else(|| self.terminate(IpcError::InvalidTransition))?;
        let copied = remaining.min(available);
        let source = input
            .get(consumed..consumed + copied)
            .ok_or_else(|| self.terminate(IpcError::InvalidTransition))?;
        let destination = match self
            .payload
            .as_mut_slice()
            .get_mut(self.payload_len..self.payload_len + copied)
        {
            Some(destination) => destination,
            None => return Err(self.terminate(IpcError::InvalidTransition)),
        };
        destination.copy_from_slice(source);
        self.payload_len += copied;
        consumed += copied;
        if self.payload_len == expected_payload {
            let kind = match self.parsed_header.as_ref() {
                Some(header) => header.kind(),
                None => return Err(self.terminate(IpcError::InvalidTransition)),
            };
            if let Err(error) = validate_payload_shape(kind, expected_payload) {
                return Err(self.terminate(error));
            }
            self.frame_ready = true;
        }

        Ok(IngestOutcome {
            consumed,
            frame_ready: self.frame_ready,
        })
    }

    /// Move out the sole complete frame and reset for the next frame.
    pub fn take_frame(&mut self) -> Result<ReceivedFrame, IpcError> {
        if self.terminated {
            return Err(IpcError::DecoderTerminated);
        }
        if !self.frame_ready {
            return Err(self.terminate(IpcError::InvalidTransition));
        }
        let header = match self.parsed_header.take() {
            Some(header) => header,
            None => return Err(self.terminate(IpcError::InvalidTransition)),
        };
        let payload = core::mem::take(&mut self.payload);
        self.payload_len = 0;
        self.frame_ready = false;
        Ok(ReceivedFrame { header, payload })
    }

    /// Record connection EOF, clear state, and latch terminal.
    pub fn finish(&mut self) -> IpcError {
        if self.terminated {
            return IpcError::DecoderTerminated;
        }
        let partial = self.header_len != 0 || (self.parsed_header.is_some() && !self.frame_ready);
        if partial {
            self.terminate(IpcError::ConnectionClosedMidFrame)
        } else {
            self.terminate(IpcError::PeerLost)
        }
    }

    fn terminate(&mut self, error: IpcError) -> IpcError {
        wipe::bytes(&mut self.header_bytes);
        self.header_len = 0;
        if let Some(mut header) = self.parsed_header.take() {
            wipe::bytes(&mut header.session_id);
        }
        self.payload = WipingByteVec::default();
        self.payload_len = 0;
        self.frame_ready = false;
        self.terminated = true;
        error
    }
}

impl Default for StreamDecoder {
    fn default() -> Self {
        Self::new()
    }
}

impl Drop for StreamDecoder {
    fn drop(&mut self) {
        wipe::bytes(&mut self.header_bytes);
        if let Some(header) = self.parsed_header.as_mut() {
            wipe::bytes(&mut header.session_id);
        }
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::panic)]
mod tests {
    use super::StreamDecoder;
    use crate::wipe::{reset_wiped_bytes, wiped_bytes};
    use crate::{encode_frame, Direction, IpcError, MessageKind};
    use std::panic::{catch_unwind, AssertUnwindSafe};

    fn operation(payload_len: usize) -> Vec<u8> {
        let payload = vec![0x5a; payload_len];
        let mut output = vec![0; 32 + payload_len];
        let length = encode_frame(
            Direction::CoreToIo,
            MessageKind::OperationRequest,
            [0x33; 16],
            1,
            &payload,
            &mut output,
        )
        .unwrap();
        output.truncate(length);
        output
    }

    #[test]
    fn successful_owner_drop_clears_header_session_and_payload_capacity() {
        let frame = operation(71);
        let mut decoder = StreamDecoder::new();
        reset_wiped_bytes();
        assert!(decoder.ingest(&frame, false).unwrap().frame_ready());
        let received = decoder.take_frame().unwrap();
        let payload_capacity = received.payload.capacity();
        drop(received);
        drop(decoder);
        assert_eq!(wiped_bytes(), 32 + 16 + payload_capacity + 32);
    }

    #[test]
    fn partial_decoder_drop_clears_header_session_and_payload_capacity() {
        let frame = operation(137);
        let mut decoder = StreamDecoder::new();
        assert_eq!(decoder.ingest(&frame[..40], false).unwrap().consumed(), 40);
        let payload_capacity = decoder.payload.capacity();
        reset_wiped_bytes();
        drop(decoder);
        assert_eq!(wiped_bytes(), 32 + 16 + payload_capacity);
    }

    #[test]
    fn ancillary_termination_clears_partial_state_before_latching() {
        let frame = operation(19);
        let mut decoder = StreamDecoder::new();
        assert_eq!(decoder.ingest(&frame[..11], false).unwrap().consumed(), 11);
        reset_wiped_bytes();
        assert_eq!(
            decoder.ingest(&frame[11..], true),
            Err(IpcError::AncillaryData)
        );
        assert_eq!(wiped_bytes(), 32);
        drop(decoder);
        assert_eq!(wiped_bytes(), 64);
    }

    #[test]
    fn premature_take_clears_partial_state_and_latches_terminal() {
        let frame = operation(19);
        let mut decoder = StreamDecoder::new();
        assert_eq!(decoder.ingest(&frame[..11], false).unwrap().consumed(), 11);
        reset_wiped_bytes();
        assert_eq!(decoder.take_frame().err(), Some(IpcError::InvalidTransition));
        assert_eq!(wiped_bytes(), 32);
        assert_eq!(
            decoder.take_frame().err(),
            Some(IpcError::DecoderTerminated)
        );
    }

    #[test]
    fn received_owner_clears_during_caught_unwind() {
        let frame = operation(83);
        let mut decoder = StreamDecoder::new();
        decoder.ingest(&frame, false).unwrap();
        let received = decoder.take_frame().unwrap();
        let payload_capacity = received.payload.capacity();
        reset_wiped_bytes();
        let result = catch_unwind(AssertUnwindSafe(move || {
            let _kept_alive = received;
            panic!("test-only caught unwind");
        }));
        assert!(result.is_err());
        assert_eq!(wiped_bytes(), 16 + payload_capacity);
    }
}
