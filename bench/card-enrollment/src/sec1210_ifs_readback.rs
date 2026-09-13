//! Explicit IFSD-254 negotiation followed by the frozen public-GOLDEN readback.
use std::io::Write;
use std::panic::{catch_unwind, AssertUnwindSafe};
use std::path::{Path, PathBuf};

use crate::{
    fixed_sitting_plan, sec1210_output_basename, Sec1210Error, Sec1210IfsReadbackTranscript,
    Sec1210Metadata, Sec1210ReadbackTransport, SittingMode,
};
use qk_sec1210_wire::{
    ReadbackError, ReadbackPhase, ReadbackRequest, ReadbackSession, MAX_WIRE_BYTES,
    READBACK_MAX_RECEIVED_BYTES,
};

pub const SEC1210_IFS_READBACK_TOOL_VERSION: &str = "0.0.11";
pub const IFS_READBACK_LIMITS: [(&str, u64); 7] = [
    ("QK-LIM-T1-IFS-READBACK-EXCHANGES-V1", 16),
    ("QK-LIM-T1-IFS-READBACK-COMMANDS-V1", 128),
    ("QK-LIM-T1-IFS-READBACK-RESPONSE-MS-V1", 5000),
    ("QK-LIM-T1-IFS-READBACK-APDU-MS-V1", 30000),
    ("QK-LIM-T1-IFS-READBACK-EVENTS-V1", 64),
    ("QK-LIM-T1-IFS-READBACK-RX-V1", 8192),
    ("QK-LIM-BENCH-T1-IFS-READBACK-TRANSCRIPT-V1", 262144),
];

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Sec1210IfsReadbackError {
    Native(Sec1210Error),
    Wire(ReadbackError),
    T1(qk_t1::Error),
    PlanRejected,
    ResponseMissing,
    TranscriptLimit,
    TranscriptIo,
}
impl Sec1210IfsReadbackError {
    pub fn name(self) -> &'static str {
        match self {
            Self::Native(e) => e.name(),
            Self::Wire(e) => e.name(),
            Self::T1(e) => e.name(),
            Self::PlanRejected => "Sec1210IfsReadbackPlanRejected",
            Self::ResponseMissing => "Sec1210IfsReadbackResponseMissing",
            Self::TranscriptLimit => "Sec1210IfsReadbackTranscriptLimit",
            Self::TranscriptIo => "Sec1210IfsReadbackTranscriptIo",
        }
    }
}
impl From<Sec1210Error> for Sec1210IfsReadbackError {
    fn from(e: Sec1210Error) -> Self {
        Self::Native(e)
    }
}
impl From<ReadbackError> for Sec1210IfsReadbackError {
    fn from(e: ReadbackError) -> Self {
        Self::Wire(e)
    }
}
impl From<qk_t1::Error> for Sec1210IfsReadbackError {
    fn from(e: qk_t1::Error) -> Self {
        Self::T1(e)
    }
}

#[derive(Clone, Debug)]
pub struct Sec1210IfsReadbackMetadata {
    binding: Sec1210Metadata,
    output: PathBuf,
}
impl Sec1210IfsReadbackMetadata {
    pub fn new(
        source: String,
        utc: String,
        host: &str,
        specimen: &str,
        output: PathBuf,
    ) -> Result<Self, Sec1210IfsReadbackError> {
        if output.as_os_str().len() > 4096
            || output.file_name().and_then(|n| n.to_str())
                != Some(sec1210_ifs_readback_output_basename(&utc).as_str())
        {
            return Err(Sec1210Error::OutputRejected.into());
        }
        let parent = output.parent().ok_or(Sec1210Error::OutputRejected)?;
        // Reuse the existing calendar/source/apparatus/path validation without
        // altering the probe's basename grammar or ever opening this sibling.
        let binding = Sec1210Metadata::new(
            source,
            utc.clone(),
            host,
            specimen,
            parent.join(sec1210_output_basename(&utc)),
        )?;
        Ok(Self { binding, output })
    }
    pub fn source(&self) -> &str {
        self.binding.source()
    }
    pub fn utc(&self) -> &str {
        self.binding.utc()
    }
    pub fn output(&self) -> &Path {
        &self.output
    }
}
pub fn sec1210_ifs_readback_output_basename(utc: &str) -> String {
    format!("qk-card-sitting-v1__sec1210-ifs-readback__J3R180-03__{utc}.txt")
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Sec1210IfsReadbackSummary {
    pub request_count: usize,
    pub response_count: usize,
    pub event_count: usize,
    pub captured_rx_bytes: usize,
    pub apdu_transmit_count: usize,
    pub apdu_response_count: usize,
    pub ifs_accepted: bool,
    pub continuation_count: usize,
    pub local_handle_released: bool,
    pub failure: Option<Sec1210IfsReadbackError>,
}

struct Engine<'a, T, W: Write> {
    transport: &'a mut T,
    transcript: &'a mut Sec1210IfsReadbackTranscript<W>,
    wire: ReadbackSession,
    t1: qk_t1::Session,
    read_index: usize,
    observation_index: usize,
    captured: usize,
    apdu_transmits: usize,
    continuations: usize,
    t1_active: bool,
    first_failure: Option<Sec1210IfsReadbackError>,
}
impl<T: Sec1210ReadbackTransport, W: Write> Engine<'_, T, W> {
    fn clocks(&mut self) -> Result<u64, Sec1210IfsReadbackError> {
        let now = self.transport.now_ms();
        self.wire.tick(now)?;
        if self.t1_active {
            self.t1.tick(now)?;
        }
        Ok(now)
    }
    fn exchange(
        &mut self,
        request: ReadbackRequest,
        first_block: bool,
        continuation: bool,
    ) -> Result<(), Sec1210IfsReadbackError> {
        let index = request.sequence();
        self.transcript
            .hex(&format!("command.{index}.request_hex"), request.as_bytes())?;
        self.clocks()?; // Trace work cannot move a write past its deadline.
        if first_block {
            self.apdu_transmits += 1;
        }
        if continuation {
            self.continuations += 1;
        }
        let write = self.transport.write_once(request.as_bytes());
        let written_at = self.transport.now_ms();
        let accepted = write
            .map_err(Sec1210IfsReadbackError::from)
            .and_then(|n| self.wire.written(n, written_at).map_err(Into::into));
        if let Err(error) = accepted {
            self.first_failure.get_or_insert(error);
        }
        self.transcript.field(
            &format!("command.{index}.write_bytes"),
            &match write {
                Ok(n) => n.to_string(),
                Err(e) => e.name().to_string(),
            },
        )?;
        accepted?;
        self.clocks()?;
        self.transcript
            .field(&format!("command.{index}.post_send_pause_ms"), "10")?;
        self.transport.pause_after_write()?;
        while matches!(self.wire.phase(), ReadbackPhase::Receiving(_)) {
            self.clocks()?;
            let mut buffer = [0u8; MAX_WIRE_BYTES];
            let (length, elapsed) = self.transport.read(&mut buffer)?;
            let now = self.transport.now_ms();
            if length > buffer.len() {
                return Err(Sec1210Error::ReadLengthRejected.into());
            }
            let retained = length.min(READBACK_MAX_RECEIVED_BYTES - self.captured);
            if retained != length {
                self.first_failure.get_or_insert(
                    ReadbackError::Wire(qk_sec1210_wire::Error::ReceiveLimitExceeded).into(),
                );
            }
            self.transcript.field(
                &format!("read.{}.elapsed_ms", self.read_index),
                &elapsed.to_string(),
            )?;
            self.transcript.field(
                &format!("read.{}.monotonic_ms", self.read_index),
                &now.to_string(),
            )?;
            self.transcript.hex(
                &format!("read.{}.rx_hex", self.read_index),
                &buffer[..retained],
            )?;
            self.captured += retained;
            if retained != length {
                self.transcript.field("capture_overflow", "TRUE")?;
                self.transcript
                    .field("capture_omitted_bytes", &(length - retained).to_string())?;
                return Err(
                    ReadbackError::Wire(qk_sec1210_wire::Error::ReceiveLimitExceeded).into(),
                );
            }
            // Retain late raw bytes before either absolute deadline rejects.
            // Evidence writes are part of the absolute budget too. The raw
            // record keeps arrival time; acceptance uses a fresh clock value.
            let validation_ms = self.transport.now_ms();
            let result = self.wire.receive(&buffer[..length], validation_ms);
            if let Err(error) = result {
                self.first_failure.get_or_insert(error.into());
            }
            self.transcript.field(
                &format!("read.{}.validation_ms", self.read_index),
                &validation_ms.to_string(),
            )?;
            for (offset, observation) in self.wire.observations()[self.observation_index..]
                .iter()
                .enumerate()
            {
                self.transcript
                    .observation(self.observation_index + offset, observation)?;
            }
            self.observation_index = self.wire.observations().len();
            self.transcript.field(
                &format!("read.{}.comparison", self.read_index),
                result.as_ref().map(|_| "PASS").unwrap_or_else(|e| e.name()),
            )?;
            self.read_index += 1;
            result?;
            self.clocks()?;
        }
        Ok(())
    }
    fn run(
        &mut self,
        metadata: &Sec1210IfsReadbackMetadata,
    ) -> Result<(), Sec1210IfsReadbackError> {
        let plan = fixed_sitting_plan(SittingMode::CommittedReadback)
            .map_err(|_| Sec1210IfsReadbackError::PlanRejected)?;
        if plan.exchanges().len() != 8
            || plan.exchanges().iter().any(|e| {
                e.request().len() > qk_t1::MAX_COMMAND_BYTES
                    || e.expected_response().len() > qk_t1::MAX_RESPONSE_BYTES
            })
        {
            return Err(Sec1210IfsReadbackError::PlanRejected);
        }
        self.transcript.header(metadata)?;
        let configured = self.transport.configure();
        if let Some(error) = match configured {
            Err(e) => Some(e.into()),
            Ok(n) if n != 0 => Some(Sec1210Error::SttyFailed.into()),
            _ => None,
        } {
            self.first_failure.get_or_insert(error);
        }
        self.transcript.field(
            "stty.exit",
            &match configured {
                Ok(n) => n.to_string(),
                Err(e) => e.name().to_string(),
            },
        )?;
        if configured? != 0 {
            return Err(Sec1210Error::SttyFailed.into());
        }
        self.transport.open()?;
        self.transcript.field("stream.open", "PASS")?;
        while self.wire.phase() != ReadbackPhase::ReadyTransfer {
            let now = self.transport.now_ms();
            let request = self.wire.begin_initial(now)?;
            self.exchange(request, false, false)?;
        }
        // IFS is exactly one explicit transaction before any application block.
        self.t1.begin_ifs(self.transport.now_ms())?;
        self.t1_active = true;
        self.transcript.field(
            "ifs.receive_bound_before",
            &self.t1.receive_bound().to_string(),
        )?;
        self.transcript.field(
            "ifs.send_sequence_before",
            &self.t1.send_sequence().to_string(),
        )?;
        self.transcript.field(
            "ifs.receive_sequence_before",
            &self.t1.receive_sequence().to_string(),
        )?;
        let now = self.clocks()?;
        let block = self.t1.next_block(now)?;
        self.transcript.hex("ifs.request_hex", block.as_bytes())?;
        let request = self
            .wire
            .begin_transfer(block.as_bytes(), self.transport.now_ms())?;
        self.exchange(request, false, false)?;
        self.t1
            .written(block.as_bytes().len(), self.transport.now_ms())?;
        let response = self
            .wire
            .response()
            .ok_or(Sec1210IfsReadbackError::ResponseMissing)?;
        self.transcript
            .hex("ifs.response_hex", response.payload())?;
        let checked = self.t1.receive(response.payload(), self.transport.now_ms());
        if let Err(error) = checked {
            self.first_failure.get_or_insert(error.into());
        }
        self.transcript.field(
            "ifs.comparison",
            checked
                .as_ref()
                .map(|_| "PASS")
                .unwrap_or_else(|e| e.name()),
        )?;
        self.transcript.field(
            "ifs.receive_bound_after",
            &self.t1.receive_bound().to_string(),
        )?;
        self.transcript.field(
            "ifs.send_sequence_after",
            &self.t1.send_sequence().to_string(),
        )?;
        self.transcript.field(
            "ifs.receive_sequence_after",
            &self.t1.receive_sequence().to_string(),
        )?;
        checked?;
        self.t1_active = false;
        for apdu in plan.exchanges() {
            self.t1_active = true;
            self.t1.begin(
                apdu.request(),
                apdu.expected_response(),
                self.transport.now_ms(),
            )?;
            self.transcript
                .hex(&format!("apdu.{}.tx_hex", apdu.index()), apdu.request())?;
            let mut first_block = true;
            while self.t1.phase() != qk_t1::Phase::Complete {
                let now = self.clocks()?;
                let block = self.t1.next_block(now)?;
                self.transcript.hex(
                    &format!("t1.{}.tx_hex", self.wire.sequence() + 1),
                    block.as_bytes(),
                )?;
                self.transcript.field(
                    &format!("t1.{}.send_sequence", self.wire.sequence() + 1),
                    &self.t1.send_sequence().to_string(),
                )?;
                self.transcript.field(
                    &format!("t1.{}.receive_sequence", self.wire.sequence() + 1),
                    &self.t1.receive_sequence().to_string(),
                )?;
                let request = self
                    .wire
                    .begin_transfer(block.as_bytes(), self.transport.now_ms())?;
                self.exchange(request, first_block, !first_block)?;
                // A single full CCID write carried this block; no resending.
                self.t1
                    .written(block.as_bytes().len(), self.transport.now_ms())?;
                first_block = false;
                let response = self
                    .wire
                    .response()
                    .ok_or(Sec1210IfsReadbackError::ResponseMissing)?;
                self.transcript.hex(
                    &format!("t1.{}.rx_hex", self.wire.sequence()),
                    response.payload(),
                )?;
                let checked = self.t1.receive(response.payload(), self.transport.now_ms());
                if let Err(error) = checked {
                    self.first_failure.get_or_insert(error.into());
                }
                self.transcript.field(
                    &format!("t1.{}.comparison", self.wire.sequence()),
                    checked
                        .as_ref()
                        .map(|_| "PASS")
                        .unwrap_or_else(|e| e.name()),
                )?;
                checked?;
            }
            self.t1_active = false;
            self.transcript.hex(
                &format!("apdu.{}.rx_hex", apdu.index()),
                self.t1.response_prefix(),
            )?;
            self.transcript
                .field(&format!("apdu.{}.comparison", apdu.index()), "PASS")?;
        }
        Ok(())
    }
}

pub fn run_sec1210_ifs_readback<T: Sec1210ReadbackTransport, W: Write>(
    metadata: &Sec1210IfsReadbackMetadata,
    transport: &mut T,
    transcript: &mut Sec1210IfsReadbackTranscript<W>,
) -> Sec1210IfsReadbackSummary {
    let mut engine = Engine {
        transport,
        transcript,
        wire: ReadbackSession::default(),
        t1: qk_t1::Session::with_ifs(),
        read_index: 0,
        observation_index: 0,
        captured: 0,
        apdu_transmits: 0,
        continuations: 0,
        t1_active: false,
        first_failure: None,
    };
    let result = catch_unwind(AssertUnwindSafe(|| engine.run(metadata)))
        .unwrap_or(Err(Sec1210Error::BoundaryPanicked.into()));
    let mut summary = Sec1210IfsReadbackSummary {
        request_count: engine.wire.requests(),
        response_count: engine.wire.responses(),
        event_count: engine.wire.events(),
        captured_rx_bytes: engine.captured,
        apdu_transmit_count: engine.apdu_transmits,
        apdu_response_count: engine.t1.completed_apdus(),
        ifs_accepted: engine.t1.ifs_accepted(),
        continuation_count: engine.continuations,
        local_handle_released: false,
        failure: engine.first_failure.or_else(|| result.err()),
    };
    let release = catch_unwind(AssertUnwindSafe(|| engine.transport.release()))
        .unwrap_or(Err(Sec1210Error::BoundaryPanicked));
    match release {
        Ok(released) => {
            summary.local_handle_released = released;
            if !released {
                summary
                    .failure
                    .get_or_insert(Sec1210Error::CloseFailed.into());
            }
        }
        Err(e) => {
            summary.failure.get_or_insert(e.into());
        }
    }
    if let Err(e) = catch_unwind(AssertUnwindSafe(|| engine.transcript.finish(&summary)))
        .unwrap_or(Err(Sec1210Error::BoundaryPanicked.into()))
    {
        summary.failure.get_or_insert(e);
    }
    summary
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Sec1210Transport;

    #[test]
    fn capture_overflow_is_bounded_and_latched_before_diagnostics() {
        struct Overflow;
        impl Sec1210Transport for Overflow {
            fn configure(&mut self) -> Result<i32, Sec1210Error> {
                Ok(0)
            }
            fn open(&mut self) -> Result<(), Sec1210Error> {
                Ok(())
            }
            fn write_once(&mut self, bytes: &[u8]) -> Result<usize, Sec1210Error> {
                Ok(bytes.len())
            }
            fn pause_after_write(&mut self) -> Result<(), Sec1210Error> {
                Ok(())
            }
            fn read(&mut self, bytes: &mut [u8]) -> Result<(usize, u64), Sec1210Error> {
                bytes[..3].copy_from_slice(&[3, 6, 0x80]);
                Ok((3, 0))
            }
            fn release(&mut self) -> Result<bool, Sec1210Error> {
                Ok(true)
            }
        }
        impl Sec1210ReadbackTransport for Overflow {
            fn now_ms(&mut self) -> u64 {
                0
            }
        }
        let mut transcript = Sec1210IfsReadbackTranscript::new(Vec::new());
        let mut transport = Overflow;
        let mut engine = Engine {
            transport: &mut transport,
            transcript: &mut transcript,
            wire: ReadbackSession::default(),
            t1: qk_t1::Session::with_ifs(),
            read_index: 0,
            observation_index: 0,
            captured: READBACK_MAX_RECEIVED_BYTES - 2,
            apdu_transmits: 0,
            continuations: 0,
            t1_active: false,
            first_failure: None,
        };
        let request = engine.wire.begin_initial(0).unwrap();
        let expected: Sec1210IfsReadbackError =
            ReadbackError::Wire(qk_sec1210_wire::Error::ReceiveLimitExceeded).into();
        assert_eq!(engine.exchange(request, false, false), Err(expected));
        assert_eq!(engine.first_failure, Some(expected));
        assert_eq!(engine.captured, READBACK_MAX_RECEIVED_BYTES);
        let text = String::from_utf8(transcript.into_inner()).unwrap();
        assert!(text.contains("read.0.rx_hex=0306\n"));
        assert!(text.contains("capture_overflow=TRUE\ncapture_omitted_bytes=1\n"));
    }

    struct LaterStep {
        configured: Result<i32, Sec1210Error>,
    }
    impl Sec1210Transport for LaterStep {
        fn configure(&mut self) -> Result<i32, Sec1210Error> {
            self.configured
        }
        fn open(&mut self) -> Result<(), Sec1210Error> {
            Err(Sec1210Error::OpenFailed)
        }
        fn write_once(&mut self, _: &[u8]) -> Result<usize, Sec1210Error> {
            panic!("no write authorized by this mock")
        }
        fn pause_after_write(&mut self) -> Result<(), Sec1210Error> {
            panic!("no write authorized by this mock")
        }
        fn read(&mut self, _: &mut [u8]) -> Result<(usize, u64), Sec1210Error> {
            panic!("no read authorized by this mock")
        }
        fn release(&mut self) -> Result<bool, Sec1210Error> {
            panic!("no handle acquired by this mock")
        }
    }
    impl Sec1210ReadbackTransport for LaterStep {
        fn now_ms(&mut self) -> u64 {
            0
        }
    }

    #[test]
    fn first_failure_name_survives_later_success_and_failure_steps() {
        let utc = "2026-09-13T00:00:00Z";
        let metadata = Sec1210IfsReadbackMetadata::new(
            "a".repeat(40),
            utc.into(),
            "RIG-HOST-PI3B-01",
            "J3R180-03",
            std::env::temp_dir().join(sec1210_ifs_readback_output_basename(utc)),
        )
        .unwrap();
        for (configured, later_error) in [
            (Ok(0), Sec1210Error::OpenFailed),
            (Ok(1), Sec1210Error::SttyFailed),
            (
                Err(Sec1210Error::SttyUnavailable),
                Sec1210Error::SttyUnavailable,
            ),
        ] {
            let mut transport = LaterStep { configured };
            let mut transcript = Sec1210IfsReadbackTranscript::new(Vec::new());
            // Seed the private invariant to exercise later bookkeeping; the
            // public runner still returns immediately on failure, without retry.
            let mut engine = Engine {
                transport: &mut transport,
                transcript: &mut transcript,
                wire: ReadbackSession::default(),
                t1: qk_t1::Session::with_ifs(),
                read_index: 0,
                observation_index: 0,
                captured: 0,
                apdu_transmits: 0,
                continuations: 0,
                t1_active: false,
                first_failure: Some(Sec1210Error::ReadFailed.into()),
            };
            assert_eq!(engine.run(&metadata), Err(later_error.into()));
            assert_eq!(
                engine.first_failure.map(Sec1210IfsReadbackError::name),
                Some("Sec1210ReadFailed"),
                "later configuration result: {configured:?}"
            );
        }
    }
}
