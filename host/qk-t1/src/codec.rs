use crate::{IFSD, MAX_COMMAND_BYTES};

pub const MAX_BLOCK_BYTES: usize = IFSD + 4;
pub(crate) const IFS_MAX_BLOCK_BYTES: usize = 254 + 4;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Error {
    BlockLengthRejected,
    ChecksumRejected,
    NadRejected,
    PcbRejected,
    ControlLengthRejected,
    RetransmissionRejected,
    WtxRejected,
    IfsRejected,
    ResynchRejected,
    AbortRejected,
    UnexpectedRBlock,
    SequenceRejected,
    StateRejected,
    CommandLengthRejected,
    ResponseLengthRejected,
    ResponseMismatch,
    PartialWrite,
    ExchangeLimitExceeded,
    ApduLimitExceeded,
    DeadlineExceeded,
    ClockRegression,
}

impl Error {
    pub const fn name(self) -> &'static str {
        match self {
            Self::BlockLengthRejected => "T1BlockLengthRejected",
            Self::ChecksumRejected => "T1ChecksumRejected",
            Self::NadRejected => "T1NadRejected",
            Self::PcbRejected => "T1PcbRejected",
            Self::ControlLengthRejected => "T1ControlLengthRejected",
            Self::RetransmissionRejected => "T1RetransmissionRejected",
            Self::WtxRejected => "T1WtxRejected",
            Self::IfsRejected => "T1IfsRejected",
            Self::ResynchRejected => "T1ResynchRejected",
            Self::AbortRejected => "T1AbortRejected",
            Self::UnexpectedRBlock => "T1UnexpectedRBlock",
            Self::SequenceRejected => "T1SequenceRejected",
            Self::StateRejected => "T1StateRejected",
            Self::CommandLengthRejected => "T1CommandLengthRejected",
            Self::ResponseLengthRejected => "T1ResponseLengthRejected",
            Self::ResponseMismatch => "T1ResponseMismatch",
            Self::PartialWrite => "T1PartialWrite",
            Self::ExchangeLimitExceeded => "T1ExchangeLimitExceeded",
            Self::ApduLimitExceeded => "T1ApduLimitExceeded",
            Self::DeadlineExceeded => "T1DeadlineExceeded",
            Self::ClockRegression => "T1ClockRegression",
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Block {
    bytes: [u8; MAX_COMMAND_BYTES + 4],
    len: usize,
}

impl Block {
    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes[..self.len]
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Received<'a> {
    I {
        sequence: u8,
        more: bool,
        inf: &'a [u8],
    },
    R {
        sequence: u8,
    },
}

pub fn encode_command(command: &[u8], sequence: u8) -> Result<Block, Error> {
    if command.is_empty() || command.len() > MAX_COMMAND_BYTES {
        return Err(Error::CommandLengthRejected);
    }
    if sequence > 1 {
        return Err(Error::SequenceRejected);
    }
    let mut block = Block {
        bytes: [0; MAX_COMMAND_BYTES + 4],
        len: command.len() + 4,
    };
    block.bytes[1] = sequence << 6;
    block.bytes[2] = command.len() as u8;
    block.bytes[3..3 + command.len()].copy_from_slice(command);
    block.bytes[block.len - 1] = block.bytes[..block.len - 1].iter().fold(0, |a, b| a ^ b);
    Ok(block)
}

pub fn encode_ack(sequence: u8) -> Result<Block, Error> {
    if sequence > 1 {
        return Err(Error::SequenceRejected);
    }
    let mut block = Block {
        bytes: [0; MAX_COMMAND_BYTES + 4],
        len: 4,
    };
    block.bytes[1] = 0x80 | sequence << 4;
    block.bytes[3] = block.bytes[1];
    Ok(block)
}

pub(crate) fn encode_ifs_request() -> Block {
    let mut block = Block {
        bytes: [0; MAX_COMMAND_BYTES + 4],
        len: 5,
    };
    block.bytes[..5].copy_from_slice(&[0x00, 0xc1, 0x01, 0xfe, 0x3e]);
    block
}

/// Only the session awaiting its single fixed request may accept this echo.
/// Ordinary decoding supplies the unchanged field-validation ordering first.
pub(crate) fn validate_ifs_response(bytes: &[u8]) -> Result<(), Error> {
    match decode(bytes) {
        Err(Error::IfsRejected) if bytes == [0x00, 0xe1, 0x01, 0xfe, 0x1e] => Ok(()),
        Err(error) => Err(error),
        Ok(Received::R { .. }) => Err(Error::UnexpectedRBlock),
        Ok(Received::I { .. }) => Err(Error::IfsRejected),
    }
}

/// A complete reader TPDU, not a stream fragment. Bounds and exact LEN precede
/// LRC; NAD, PCB and control semantics are inspected only after LRC succeeds.
pub fn decode(bytes: &[u8]) -> Result<Received<'_>, Error> {
    decode_bounded(bytes, MAX_BLOCK_BYTES)
}

/// This bound is selected only from the session's private negotiation state.
pub(crate) fn decode_bounded(bytes: &[u8], receive_bound: usize) -> Result<Received<'_>, Error> {
    if !(4..=receive_bound).contains(&bytes.len()) || usize::from(bytes[2]) + 4 != bytes.len() {
        return Err(Error::BlockLengthRejected);
    }
    if bytes.iter().fold(0, |a, b| a ^ b) != 0 {
        return Err(Error::ChecksumRejected);
    }
    if bytes[0] != 0 {
        return Err(Error::NadRejected);
    }
    let pcb = bytes[1];
    let inf = &bytes[3..bytes.len() - 1];
    match pcb & 0xc0 {
        0x00 | 0x40 => {
            if pcb & 0x1f != 0 {
                return Err(Error::PcbRejected);
            }
            Ok(Received::I {
                sequence: (pcb >> 6) & 1,
                more: pcb & 0x20 != 0,
                inf,
            })
        }
        0x80 => {
            if pcb & 0x2c != 0 || pcb & 3 == 3 {
                return Err(Error::PcbRejected);
            }
            if !inf.is_empty() {
                return Err(Error::ControlLengthRejected);
            }
            if pcb & 3 != 0 {
                return Err(Error::RetransmissionRejected);
            }
            Ok(Received::R {
                sequence: (pcb >> 4) & 1,
            })
        }
        _ => {
            if pcb & 0x1c != 0 {
                return Err(Error::PcbRejected);
            }
            let function = pcb & 3;
            let required = usize::from(function == 1 || function == 3);
            if inf.len() != required {
                return Err(Error::ControlLengthRejected);
            }
            Err(match function {
                0 => Error::ResynchRejected,
                1 => Error::IfsRejected,
                2 => Error::AbortRejected,
                _ => Error::WtxRejected,
            })
        }
    }
}
