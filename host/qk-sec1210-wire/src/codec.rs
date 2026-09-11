//! Fixed-storage framing. Untrusted length is used only to bound the frame;
//! response fields become visible only after verification of the whole XOR.

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
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Message {
    Response(Box<Response>),
    SlotChange { bitmap: u8 },
    HardwareError { slot: u8, sequence: u8, code: u8 },
}

pub struct Decoder {
    buffer: [u8; MAX_WIRE_BYTES],
    len: usize,
    failure: Option<Error>,
}

impl Default for Decoder {
    fn default() -> Self {
        Self {
            buffer: [0; MAX_WIRE_BYTES],
            len: 0,
            failure: None,
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
        Err(error)
    }

    pub fn push(&mut self, byte: u8) -> Result<Option<Message>, Error> {
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
            0x50 => Message::SlotChange {
                bitmap: self.buffer[1],
            },
            0x51 => Message::HardwareError {
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
                let payload_len = needed - 13;
                let mut payload = [0; MAX_PAYLOAD];
                payload[..payload_len].copy_from_slice(&self.buffer[12..12 + payload_len]);
                Message::Response(Box::new(Response {
                    message_type: self.buffer[2],
                    slot: self.buffer[7],
                    sequence: self.buffer[8],
                    status: self.buffer[9],
                    error: self.buffer[10],
                    parameter: self.buffer[11],
                    payload,
                    payload_len,
                }))
            }
        };
        self.len = 0;
        Ok(Some(message))
    }
}
