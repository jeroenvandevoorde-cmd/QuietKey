//! Fixed-storage framing. Untrusted length is used only to bound the frame;
//! response fields become visible only after verification of the whole XOR.

use crate::wipe;

pub const MAX_CCID_BYTES: usize = 271;
pub const MAX_WIRE_BYTES: usize = MAX_CCID_BYTES + 3;
const MAX_PAYLOAD: usize = MAX_CCID_BYTES - 10;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Error {
    PrefixRejected,
    LengthExceeded,
    Truncated,
    ChecksumRejected,
    Nack,
    SlotRejected,
    SequenceRejected,
    ResponseTypeRejected,
    StatusReserved,
    CommandFailed,
    TimeExtensionRejected,
    StatusErrorRejected,
    AlreadyActive,
    CardAbsent,
    IccStatusRejected,
    PayloadRejected,
    ChainingRejected,
    AtrRejected,
    EventBitmapRejected,
    HardwareError,
    EventLimitExceeded,
    ReceiveLimitExceeded,
    UnsolicitedResponse,
    TrailingData,
    SequenceViolation,
    PartialWrite,
    DeadlineExceeded,
    PartialFrameDeadline,
    ClockRegression,
}

impl Error {
    pub fn name(self) -> &'static str {
        match self {
            Self::PrefixRejected => "Sec1210PrefixRejected",
            Self::LengthExceeded => "Sec1210LengthExceeded",
            Self::Truncated => "Sec1210Truncated",
            Self::ChecksumRejected => "Sec1210ChecksumRejected",
            Self::Nack => "Sec1210Nack",
            Self::SlotRejected => "Sec1210SlotRejected",
            Self::SequenceRejected => "Sec1210SequenceRejected",
            Self::ResponseTypeRejected => "Sec1210ResponseTypeRejected",
            Self::StatusReserved => "Sec1210StatusReserved",
            Self::CommandFailed => "Sec1210CommandFailed",
            Self::TimeExtensionRejected => "Sec1210TimeExtensionRejected",
            Self::StatusErrorRejected => "Sec1210StatusErrorRejected",
            Self::AlreadyActive => "Sec1210AlreadyActive",
            Self::CardAbsent => "Sec1210CardAbsent",
            Self::IccStatusRejected => "Sec1210IccStatusRejected",
            Self::PayloadRejected => "Sec1210PayloadRejected",
            Self::ChainingRejected => "Sec1210ChainingRejected",
            Self::AtrRejected => "Sec1210AtrRejected",
            Self::EventBitmapRejected => "Sec1210EventBitmapRejected",
            Self::HardwareError => "Sec1210HardwareError",
            Self::EventLimitExceeded => "Sec1210EventLimitExceeded",
            Self::ReceiveLimitExceeded => "Sec1210ReceiveLimitExceeded",
            Self::UnsolicitedResponse => "Sec1210UnsolicitedResponse",
            Self::TrailingData => "Sec1210TrailingData",
            Self::SequenceViolation => "Sec1210SequenceViolation",
            Self::PartialWrite => "Sec1210PartialWrite",
            Self::DeadlineExceeded => "Sec1210DeadlineExceeded",
            Self::PartialFrameDeadline => "Sec1210PartialFrameDeadline",
            Self::ClockRegression => "Sec1210ClockRegression",
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Response {
    pub message_type: u8,
    pub slot: u8,
    pub sequence: u8,
    pub status: u8,
    pub error: u8,
    pub parameter: u8,
    payload: [u8; MAX_PAYLOAD],
    payload_len: usize,
}

impl Response {
    pub fn payload(&self) -> &[u8] {
        &self.payload[..self.payload_len]
    }

    pub(crate) fn zeroed() -> Self {
        Self {
            message_type: 0,
            slot: 0,
            sequence: 0,
            status: 0,
            error: 0,
            parameter: 0,
            payload: [0; MAX_PAYLOAD],
            payload_len: 0,
        }
    }

    pub(crate) fn clear(&mut self) {
        wipe::values(core::slice::from_mut(&mut self.message_type), 0);
        wipe::values(core::slice::from_mut(&mut self.slot), 0);
        wipe::values(core::slice::from_mut(&mut self.sequence), 0);
        wipe::values(core::slice::from_mut(&mut self.status), 0);
        wipe::values(core::slice::from_mut(&mut self.error), 0);
        wipe::values(core::slice::from_mut(&mut self.parameter), 0);
        wipe::bytes(&mut self.payload);
        wipe::values(core::slice::from_mut(&mut self.payload_len), 0);
    }

    fn overwrite_from_frame(&mut self, frame: &[u8], needed: usize) {
        self.clear();
        self.message_type = frame[2];
        self.slot = frame[7];
        self.sequence = frame[8];
        self.status = frame[9];
        self.error = frame[10];
        self.parameter = frame[11];
        self.payload_len = needed - 13;
        self.payload[..self.payload_len].copy_from_slice(&frame[12..12 + self.payload_len]);
    }

    pub(crate) fn copy_from(&mut self, source: &Self) {
        self.clear();
        self.message_type = source.message_type;
        self.slot = source.slot;
        self.sequence = source.sequence;
        self.status = source.status;
        self.error = source.error;
        self.parameter = source.parameter;
        self.payload_len = source.payload_len;
        self.payload[..self.payload_len].copy_from_slice(source.payload());
    }
}

impl Drop for Response {
    fn drop(&mut self) {
        self.clear();
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Message {
    Response(Box<Response>),
    SlotChange { bitmap: u8 },
    HardwareError { slot: u8, sequence: u8, code: u8 },
}

/// Allocation-free sibling used by the hardened contact session. The public
/// boxed message API remains frozen for the established bench engines.
#[derive(Clone, Copy)]
pub(crate) enum FixedMessage {
    Response,
    SlotChange { bitmap: u8 },
    HardwareError { slot: u8, sequence: u8, code: u8 },
}

pub struct Decoder {
    buffer: [u8; MAX_WIRE_BYTES],
    len: usize,
    failure: Option<Error>,
    response: Response,
}

impl Default for Decoder {
    fn default() -> Self {
        Self {
            buffer: [0; MAX_WIRE_BYTES],
            len: 0,
            failure: None,
            response: Response::zeroed(),
        }
    }
}

impl Decoder {
    pub fn pending_bytes(&self) -> usize {
        self.len
    }

    pub fn finish(&mut self) -> Result<(), Error> {
        if let Some(error) = self.failure {
            return Err(error);
        }
        if self.len != 0 {
            return self.reject(Error::Truncated);
        }
        Ok(())
    }

    fn reject<T>(&mut self, error: Error) -> Result<T, Error> {
        self.failure = Some(error);
        self.clear_buffer();
        Err(error)
    }

    pub fn push(&mut self, byte: u8) -> Result<Option<Message>, Error> {
        self.push_fixed(byte).map(|message| {
            message.map(|message| match message {
                FixedMessage::Response => {
                    let mut response = Box::new(Response::zeroed());
                    self.take_fixed_response_into(&mut response);
                    Message::Response(response)
                }
                FixedMessage::SlotChange { bitmap } => Message::SlotChange { bitmap },
                FixedMessage::HardwareError {
                    slot,
                    sequence,
                    code,
                } => Message::HardwareError {
                    slot,
                    sequence,
                    code,
                },
            })
        })
    }

    pub(crate) fn push_fixed(&mut self, byte: u8) -> Result<Option<FixedMessage>, Error> {
        if let Some(error) = self.failure {
            return Err(error);
        }
        if self.len == MAX_WIRE_BYTES {
            return self.reject(Error::LengthExceeded);
        }
        self.buffer[self.len] = byte;
        self.len += 1;
        let needed = match self.buffer[0] {
            0x50 => 2,
            0x51 => 4,
            0x03 if self.len == 1 => return Ok(None),
            0x03 => match self.buffer[1] {
                0x15 => 3,
                0x06 if self.len < 7 => return Ok(None),
                0x06 => {
                    let length = u32::from_le_bytes(self.buffer[3..7].try_into().unwrap());
                    if length > MAX_PAYLOAD as u32 {
                        return self.reject(Error::LengthExceeded);
                    }
                    13 + length as usize
                }
                _ => return self.reject(Error::PrefixRejected),
            },
            _ => return self.reject(Error::PrefixRejected),
        };
        if self.len < needed {
            return Ok(None);
        }
        let message = match self.buffer[0] {
            0x50 => FixedMessage::SlotChange {
                bitmap: self.buffer[1],
            },
            0x51 => FixedMessage::HardwareError {
                slot: self.buffer[1],
                sequence: self.buffer[2],
                code: self.buffer[3],
            },
            _ => {
                if self.buffer[..needed].iter().fold(0, |a, b| a ^ b) != 0 {
                    return self.reject(Error::ChecksumRejected);
                }
                if self.buffer[1] == 0x15 {
                    return self.reject(Error::Nack);
                }
                self.response.overwrite_from_frame(&self.buffer, needed);
                FixedMessage::Response
            }
        };
        self.clear_buffer();
        Ok(Some(message))
    }

    fn clear_buffer(&mut self) {
        wipe::bytes(&mut self.buffer);
        self.len = 0;
    }

    pub(crate) fn take_fixed_response_into(&mut self, output: &mut Response) {
        output.copy_from(&self.response);
        self.response.clear();
    }

    pub(crate) fn discard_fixed_response(&mut self) {
        self.response.clear();
    }
}

impl Drop for Decoder {
    fn drop(&mut self) {
        self.clear_buffer();
    }
}

#[cfg(test)]
mod tests {
    use super::{Decoder, FixedMessage, Response, MAX_WIRE_BYTES};
    use crate::wipe::{reset_wiped_bytes, wiped_bytes};
    use std::panic::{catch_unwind, AssertUnwindSafe};

    const EMPTY_RESPONSE: [u8; 13] = [3, 6, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x85];

    #[test]
    fn complete_frame_resets_the_full_decoder_storage() {
        let mut decoder = Decoder::default();
        reset_wiped_bytes();
        let mut message = None;
        for byte in EMPTY_RESPONSE {
            message = decoder.push_fixed(byte).unwrap().or(message);
        }
        assert!(matches!(message, Some(FixedMessage::Response)));
        assert_eq!(decoder.pending_bytes(), 0);
        assert_eq!(wiped_bytes(), MAX_WIRE_BYTES + 6 + 261 + size_of::<usize>());
    }

    #[test]
    fn response_drop_clears_payload_and_metadata_storage() {
        let mut decoder = Decoder::default();
        let mut message = None;
        for byte in EMPTY_RESPONSE {
            message = decoder.push_fixed(byte).unwrap().or(message);
        }
        let mut response = Response::zeroed();
        assert!(matches!(message, Some(FixedMessage::Response)));
        decoder.take_fixed_response_into(&mut response);
        reset_wiped_bytes();
        drop(response);
        assert_eq!(wiped_bytes(), 6 + 261 + size_of::<usize>());
    }

    #[test]
    fn decoder_storage_clears_on_drop_and_unwind() {
        reset_wiped_bytes();
        drop(Decoder::default());
        assert_eq!(wiped_bytes(), MAX_WIRE_BYTES + 6 + 261 + size_of::<usize>());

        reset_wiped_bytes();
        let result = catch_unwind(AssertUnwindSafe(|| {
            let _decoder = Decoder::default();
            panic!("test-only caught unwind");
        }));
        assert!(result.is_err());
        assert_eq!(wiped_bytes(), MAX_WIRE_BYTES + 6 + 261 + size_of::<usize>());
    }

    #[test]
    fn response_type_remains_fixed_storage() {
        assert!(size_of::<Response>() >= 261);
    }
}
