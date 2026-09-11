//! Fixed two-command R2a engine. No caller-supplied command or device path.
use std::io::Write;
use std::panic::{catch_unwind, AssertUnwindSafe};
use std::path::{Component, Path, PathBuf};

use crate::sec1210_transcript::Sec1210Transcript;
use qk_sec1210_wire::{Exchange, Phase, MAX_RECEIVED_BYTES, MAX_WIRE_BYTES};

pub const SEC1210_TOOL_VERSION: &str = "0.0.9";
pub const SEC1210_TTY: &str = "/dev/ttyAMA0";
pub const SEC1210_STTY_ARGS: [&str; 20] = [
    "-F",
    SEC1210_TTY,
    "115200",
    "raw",
    "-echo",
    "-echonl",
    "cs8",
    "-parenb",
    "cstopb",
    "cread",
    "clocal",
    "-hupcl",
    "-crtscts",
    "-parmrk",
    "-ignpar",
    "-inpck",
    "min",
    "0",
    "time",
    "5",
];

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Sec1210Error {
    Wire(qk_sec1210_wire::Error),
    MetadataRejected,
    OutputRejected,
    OutputCreateFailed,
    UnsupportedPlatform,
    SttyUnavailable,
    SttyFailed,
    OpenFailed,
    WriteFailed,
    ReadFailed,
    ReadLengthRejected,
    CloseFailed,
    BoundaryPanicked,
    TranscriptIo,
    TranscriptLimit,
}
impl Sec1210Error {
    pub fn name(self) -> &'static str {
        match self {
            Self::Wire(error) => error.name(),
            Self::MetadataRejected => "Sec1210MetadataRejected",
            Self::OutputRejected => "Sec1210OutputRejected",
            Self::OutputCreateFailed => "Sec1210OutputCreateFailed",
            Self::UnsupportedPlatform => "Sec1210UnsupportedPlatform",
            Self::SttyUnavailable => "Sec1210SttyUnavailable",
            Self::SttyFailed => "Sec1210SttyFailed",
            Self::OpenFailed => "Sec1210OpenFailed",
            Self::WriteFailed => "Sec1210WriteFailed",
            Self::ReadFailed => "Sec1210ReadFailed",
            Self::ReadLengthRejected => "Sec1210ReadLengthRejected",
            Self::CloseFailed => "Sec1210CloseFailed",
            Self::BoundaryPanicked => "Sec1210BoundaryPanicked",
            Self::TranscriptIo => "Sec1210TranscriptIo",
            Self::TranscriptLimit => "Sec1210TranscriptLimit",
        }
    }
}
impl From<qk_sec1210_wire::Error> for Sec1210Error {
    fn from(error: qk_sec1210_wire::Error) -> Self {
        Self::Wire(error)
    }
}

#[derive(Clone, Debug)]
pub struct Sec1210Metadata {
    source: String,
    utc: String,
    output: PathBuf,
}
impl Sec1210Metadata {
    pub fn new(
        source: String,
        utc: String,
        host: &str,
        specimen: &str,
        output: PathBuf,
    ) -> Result<Self, Sec1210Error> {
        if source.len() != 40
            || !source
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
            || host != "RIG-HOST-PI3B-01"
            || specimen != "J3R180-03"
            || !valid_utc(&utc)
        {
            return Err(Sec1210Error::MetadataRejected);
        }
        if !output.is_absolute()
            || output.as_os_str().len() > 4096
            || output
                .components()
                .any(|c| matches!(c, Component::ParentDir | Component::CurDir))
            || output.file_name().and_then(|n| n.to_str())
                != Some(sec1210_output_basename(&utc).as_str())
        {
            return Err(Sec1210Error::OutputRejected);
        }
        Ok(Self {
            source,
            utc,
            output,
        })
    }
    pub fn source(&self) -> &str {
        &self.source
    }
    pub fn utc(&self) -> &str {
        &self.utc
    }
    pub fn output(&self) -> &Path {
        &self.output
    }
}
pub fn sec1210_output_basename(utc: &str) -> String {
    format!("qk-card-sitting-v1__sec1210-probe__J3R180-03__{utc}.txt")
}
fn valid_utc(value: &str) -> bool {
    let b = value.as_bytes();
    if b.len() != 20
        || b[4] != b'-'
        || b[7] != b'-'
        || b[10] != b'T'
        || b[13] != b':'
        || b[16] != b':'
        || b[19] != b'Z'
        || b.iter()
            .enumerate()
            .any(|(i, b)| !matches!(i, 4 | 7 | 10 | 13 | 16 | 19) && !b.is_ascii_digit())
    {
        return false;
    }
    let num = |a: usize, z: usize| {
        b[a..z]
            .iter()
            .fold(0u32, |n, b| n * 10 + u32::from(b - b'0'))
    };
    let year = num(0, 4);
    let month = num(5, 7);
    let day = num(8, 10);
    let days = match month {
        1 | 3 | 5 | 7 | 8 | 10 | 12 => 31,
        4 | 6 | 9 | 11 => 30,
        2 if year.is_multiple_of(400) || (year.is_multiple_of(4) && !year.is_multiple_of(100)) => {
            29
        }
        2 => 28,
        _ => 0,
    };
    year != 0 && day >= 1 && day <= days && num(11, 13) < 24 && num(14, 16) < 60 && num(17, 19) < 60
}

/// Mock implementations supply the same raw read fragments and elapsed-time
/// observations as the private UART implementation; no response is invented.
pub trait Sec1210Transport {
    fn configure(&mut self) -> Result<i32, Sec1210Error>;
    fn open(&mut self) -> Result<(), Sec1210Error>;
    fn write_once(&mut self, request: &[u8]) -> Result<usize, Sec1210Error>;
    fn pause_after_write(&mut self) -> Result<(), Sec1210Error>;
    fn read(&mut self, buffer: &mut [u8]) -> Result<(usize, u64), Sec1210Error>;
    /// Releases local ownership only; not a checked kernel close or card power-off.
    fn release(&mut self) -> Result<bool, Sec1210Error>;
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Sec1210Summary {
    pub request_count: usize,
    pub response_count: usize,
    pub event_count: usize,
    pub received_bytes: usize,
    pub local_handle_released: bool,
    pub failure: Option<Sec1210Error>,
}

pub fn run_sec1210<T: Sec1210Transport, W: Write>(
    metadata: &Sec1210Metadata,
    transport: &mut T,
    transcript: &mut Sec1210Transcript<W>,
) -> Sec1210Summary {
    let mut exchange = Exchange::default();
    let mut captured = 0usize;
    let mut summary = Sec1210Summary {
        request_count: 0,
        response_count: 0,
        event_count: 0,
        received_bytes: 0,
        local_handle_released: false,
        failure: None,
    };
    let result = catch_unwind(AssertUnwindSafe(|| -> Result<(), Sec1210Error> {
        transcript.header(metadata)?;
        let configuration = transport.configure();
        transcript.field(
            "stty.exit",
            &match configuration {
                Ok(code) => code.to_string(),
                Err(e) => e.name().to_string(),
            },
        )?;
        if configuration? != 0 {
            return Err(Sec1210Error::SttyFailed);
        }
        transport.open()?;
        transcript.field("stream.open", "PASS")?;
        let mut read_index = 0;
        let mut observation_index = 0;
        while exchange.phase() != Phase::Complete {
            let command = exchange.begin()?;
            let request = command.encode();
            let index = usize::from(command.sequence());
            transcript.hex(&format!("command.{index}.request_hex"), &request)?;
            let write = transport.write_once(&request);
            transcript.field(
                &format!("command.{index}.write_bytes"),
                &match write {
                    Ok(n) => n.to_string(),
                    Err(e) => e.name().to_string(),
                },
            )?;
            exchange.written(write?)?;
            transcript.field(&format!("command.{index}.post_send_pause_ms"), "10")?;
            transport.pause_after_write()?;
            while matches!(exchange.phase(), Phase::Receiving(_)) {
                let mut buffer = [0u8; MAX_WIRE_BYTES];
                let (length, elapsed) = transport.read(&mut buffer)?;
                if length > buffer.len() {
                    return Err(Sec1210Error::ReadLengthRejected);
                }
                let retained = length.min(MAX_RECEIVED_BYTES - captured);
                transcript.field(
                    &format!("read.{read_index}.elapsed_ms"),
                    &elapsed.to_string(),
                )?;
                transcript.hex(&format!("read.{read_index}.rx_hex"), &buffer[..retained])?;
                captured += retained;
                if retained != length {
                    transcript.field("capture_overflow", "TRUE")?;
                    transcript.field("capture_omitted_bytes", &(length - retained).to_string())?;
                    return Err(qk_sec1210_wire::Error::ReceiveLimitExceeded.into());
                }
                read_index += 1;
                // Record bytes even when the read returned after the deadline.
                let result = exchange.receive(&buffer[..length], elapsed);
                for observation in &exchange.observations()[observation_index..] {
                    transcript.observation(observation_index, observation)?;
                }
                observation_index = exchange.observations().len();
                transcript.field(
                    &format!("read.{}.comparison", read_index - 1),
                    result.as_ref().map(|_| "PASS").unwrap_or_else(|e| e.name()),
                )?;
                result?;
            }
        }
        Ok(())
    }))
    .unwrap_or(Err(Sec1210Error::BoundaryPanicked));
    summary.failure = result.err();
    let release = catch_unwind(AssertUnwindSafe(|| transport.release()))
        .unwrap_or(Err(Sec1210Error::BoundaryPanicked));
    match release {
        Ok(released) => {
            summary.local_handle_released = released;
            if !released && summary.failure.is_none() {
                summary.failure = Some(Sec1210Error::CloseFailed);
            }
        }
        Err(error) => {
            summary.failure.get_or_insert(error);
        }
    }
    summary.request_count = exchange.requests();
    summary.response_count = exchange.responses();
    summary.event_count = exchange.events();
    summary.received_bytes = captured;
    let final_result = catch_unwind(AssertUnwindSafe(|| transcript.finish(&summary)))
        .unwrap_or(Err(Sec1210Error::BoundaryPanicked));
    if let Err(error) = final_result {
        summary.failure.get_or_insert(error);
    }
    summary
}
