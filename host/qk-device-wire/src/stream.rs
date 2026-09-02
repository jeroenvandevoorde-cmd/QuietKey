//! Bounded stream reassembly for one inherited descriptor.

use crate::wipe::{self, WipingByteVec};
use crate::wire::{parse_body, parse_header};
use crate::{BodyRef, Capability, DeviceError, FrameHeader, FrameRef, HEADER_BYTES};

/// Result of accepting one byte chunk.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct IngestOutcome {
    consumed: usize,
    frame_ready: bool,
}

impl IngestOutcome {
    pub const fn consumed(self) -> usize {
        self.consumed
    }

    pub const fn frame_ready(self) -> bool {
        self.frame_ready
    }
}

/// One decoder-owned, body-valid frame.
///
/// This owner is deliberately non-Clone, non-Copy, non-Debug and
/// non-Display. Drop clears the full body allocation capacity.
pub struct ReceivedFrame {
    header: FrameHeader,
    body: WipingByteVec,
}

impl ReceivedFrame {
    pub const fn header(&self) -> &FrameHeader {
        &self.header
    }

    pub fn body(&self) -> &[u8] {
        self.body.as_slice()
    }

    pub fn as_frame_ref(&self) -> FrameRef<'_> {
        FrameRef::from_parts(self.header, self.body.as_slice())
    }

    pub fn parsed_body(&self) -> Result<BodyRef<'_>, DeviceError> {
        parse_body(&self.as_frame_ref())
    }

    #[cfg(feature = "fuzzing")]
    #[doc(hidden)]
    pub fn allocation_capacity(&self) -> usize {
        self.body.capacity()
    }
}

/// Pure decoder for arbitrary stream fragmentation and coalescing.
///
/// It retains at most one complete frame, consumes only the first complete
/// frame from a coalesced input, and enforces the exact sequence of this one
/// descriptor before validating the capability-specific body.
pub struct StreamDecoder {
    expected_capability: Capability,
    header_bytes: [u8; HEADER_BYTES],
    header_len: usize,
    parsed_header: Option<FrameHeader>,
    body: WipingByteVec,
    body_len: usize,
    last_sequence: u32,
    frame_ready: bool,
    terminated: bool,
}

impl StreamDecoder {
    pub fn new(expected_capability: Capability) -> Self {
        Self {
            expected_capability,
            header_bytes: [0; HEADER_BYTES],
            header_len: 0,
            parsed_header: None,
            body: WipingByteVec::default(),
            body_len: 0,
            last_sequence: 0,
            frame_ready: false,
            terminated: false,
        }
    }

    pub const fn expected_capability(&self) -> Capability {
        self.expected_capability
    }

    /// Ingest an arbitrary prefix and stop after one complete frame.
    pub fn ingest(&mut self, input: &[u8]) -> Result<IngestOutcome, DeviceError> {
        if self.terminated {
            return Err(DeviceError::DecoderTerminated);
        }
        if self.frame_ready {
            return Err(self.terminate(DeviceError::OutstandingExchange));
        }

        let mut consumed = 0usize;
        if self.parsed_header.is_none() {
            let needed = HEADER_BYTES - self.header_len;
            let copied = needed.min(input.len());
            let source = input
                .get(..copied)
                .ok_or_else(|| self.terminate(DeviceError::UnexpectedFrame))?;
            let destination = match self
                .header_bytes
                .get_mut(self.header_len..self.header_len + copied)
            {
                Some(destination) => destination,
                None => return Err(self.terminate(DeviceError::UnexpectedFrame)),
            };
            destination.copy_from_slice(source);
            self.header_len += copied;
            consumed += copied;
            if self.header_len < HEADER_BYTES {
                return Ok(IngestOutcome {
                    consumed,
                    frame_ready: false,
                });
            }
            let header = match parse_header(self.expected_capability, &self.header_bytes) {
                Ok(header) => header,
                Err(error) => return Err(self.terminate(error)),
            };
            let expected_body = header.body_len() as usize;
            let body = match WipingByteVec::try_zeroed(expected_body) {
                Ok(body) => body,
                Err(()) => return Err(self.terminate(DeviceError::AllocationFailed)),
            };
            self.parsed_header = Some(header);
            self.body = body;
            self.body_len = 0;
            wipe::bytes(&mut self.header_bytes);
            self.header_len = 0;
            if expected_body == 0 {
                self.complete_frame()?;
                return Ok(IngestOutcome {
                    consumed,
                    frame_ready: true,
                });
            }
        }

        let expected_body = self.body.as_slice().len();
        let remaining = expected_body
            .checked_sub(self.body_len)
            .ok_or_else(|| self.terminate(DeviceError::UnexpectedFrame))?;
        let available = input
            .len()
            .checked_sub(consumed)
            .ok_or_else(|| self.terminate(DeviceError::UnexpectedFrame))?;
        let copied = remaining.min(available);
        let source = input
            .get(consumed..consumed + copied)
            .ok_or_else(|| self.terminate(DeviceError::UnexpectedFrame))?;
        let destination = match self
            .body
            .as_mut_slice()
            .get_mut(self.body_len..self.body_len + copied)
        {
            Some(destination) => destination,
            None => return Err(self.terminate(DeviceError::UnexpectedFrame)),
        };
        destination.copy_from_slice(source);
        self.body_len += copied;
        consumed += copied;
        if self.body_len == expected_body {
            self.complete_frame()?;
        }
        Ok(IngestOutcome {
            consumed,
            frame_ready: self.frame_ready,
        })
    }

    /// Move out the sole complete frame and reset for the next header.
    pub fn take_frame(&mut self) -> Result<ReceivedFrame, DeviceError> {
        if self.terminated {
            return Err(DeviceError::DecoderTerminated);
        }
        if !self.frame_ready {
            return Err(self.terminate(DeviceError::UnexpectedFrame));
        }
        let header = match self.parsed_header.take() {
            Some(header) => header,
            None => return Err(self.terminate(DeviceError::UnexpectedFrame)),
        };
        let body = core::mem::take(&mut self.body);
        self.body_len = 0;
        self.frame_ready = false;
        Ok(ReceivedFrame { header, body })
    }

    /// Record descriptor EOF, wipe retained state, and latch terminal.
    pub fn finish(&mut self) -> DeviceError {
        if self.terminated {
            return DeviceError::DecoderTerminated;
        }
        let partial = self.header_len != 0 || (self.parsed_header.is_some() && !self.frame_ready);
        if partial {
            self.terminate(DeviceError::ConnectionClosedMidFrame)
        } else {
            self.terminate(DeviceError::PeerLost)
        }
    }

    pub const fn is_terminated(&self) -> bool {
        self.terminated
    }

    /// Exercise the otherwise impractical sequence-exhaustion boundary.
    #[cfg(feature = "fuzzing")]
    #[doc(hidden)]
    pub fn fuzz_sequence_exhaustion_probe(capability: Capability) -> DeviceError {
        let mut decoder = Self::new(capability);
        decoder.last_sequence = u32::MAX;
        decoder.sequence_error(u32::MAX).unwrap_err()
    }

    fn complete_frame(&mut self) -> Result<(), DeviceError> {
        let header = match self.parsed_header {
            Some(header) => header,
            None => return Err(self.terminate(DeviceError::UnexpectedFrame)),
        };
        if let Err(error) = self.sequence_error(header.sequence()) {
            return Err(self.terminate(error));
        }
        let frame = FrameRef::from_parts(header, self.body.as_slice());
        if let Err(error) = parse_body(&frame) {
            return Err(self.terminate(error));
        }
        self.last_sequence = header.sequence();
        self.frame_ready = true;
        Ok(())
    }

    fn sequence_error(&self, sequence: u32) -> Result<(), DeviceError> {
        if self.last_sequence == u32::MAX {
            return Err(DeviceError::SequenceExhausted);
        }
        if self.last_sequence == 0 {
            return if sequence == 1 {
                Ok(())
            } else {
                Err(DeviceError::SequenceSkipped)
            };
        }
        if sequence == self.last_sequence {
            return Err(DeviceError::SequenceReplay);
        }
        if sequence < self.last_sequence {
            return Err(DeviceError::SequenceRegression);
        }
        if sequence != self.last_sequence + 1 {
            return Err(DeviceError::SequenceSkipped);
        }
        Ok(())
    }

    fn terminate(&mut self, error: DeviceError) -> DeviceError {
        wipe::bytes(&mut self.header_bytes);
        self.header_len = 0;
        self.parsed_header = None;
        self.body = WipingByteVec::default();
        self.body_len = 0;
        self.frame_ready = false;
        self.terminated = true;
        error
    }
}

impl Drop for StreamDecoder {
    fn drop(&mut self) {
        wipe::bytes(&mut self.header_bytes);
    }
}
