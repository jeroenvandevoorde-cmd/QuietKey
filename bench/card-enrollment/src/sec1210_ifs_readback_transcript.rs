//! QK-CARD-SITTING-V1 extension for the explicit IFSD-254 readback lane.
use crate::{
    Sec1210IfsReadbackError as E, Sec1210IfsReadbackMetadata, Sec1210IfsReadbackSummary,
    CANONICAL_CAP_BYTES, CANONICAL_CAP_SHA256, IFS_READBACK_LIMITS, READBACK_PLAN_SHA256,
    SEC1210_IFS_READBACK_TOOL_VERSION, SEC1210_STTY_ARGS, SEC1210_TTY,
    SITTING_APPLET_SOURCE_COMMIT,
};
use qk_sec1210_wire::ReadbackObservation;
use std::io::Write;

pub const MAX_SEC1210_IFS_READBACK_TRANSCRIPT_BYTES: usize = 262_144;
pub struct Sec1210IfsReadbackTranscript<W: Write> {
    writer: W,
    bytes: usize,
    broken: bool,
    capped: bool,
}
impl<W: Write> Sec1210IfsReadbackTranscript<W> {
    pub fn new(writer: W) -> Self {
        Self {
            writer,
            bytes: 0,
            broken: false,
            capped: false,
        }
    }
    pub fn bytes_written(&self) -> usize {
        self.bytes
    }
    pub fn into_inner(self) -> W {
        self.writer
    }
    fn line(&mut self, line: &str, terminal: bool) -> Result<(), E> {
        if self.broken {
            return Err(E::TranscriptIo);
        }
        if self.capped && !terminal {
            return Err(E::TranscriptLimit);
        }
        if !line.is_ascii() || line.contains(['\r', '\n', '\0']) {
            return Err(crate::Sec1210Error::MetadataRejected.into());
        }
        let limit = MAX_SEC1210_IFS_READBACK_TRANSCRIPT_BYTES - if terminal { 0 } else { 2048 };
        if line.len() >= limit.saturating_sub(self.bytes) {
            self.capped = true;
            return Err(E::TranscriptLimit);
        }
        if self
            .writer
            .write_all(line.as_bytes())
            .and_then(|_| self.writer.write_all(b"\n"))
            .and_then(|_| self.writer.flush())
            .is_err()
        {
            self.broken = true;
            return Err(E::TranscriptIo);
        }
        self.bytes += line.len() + 1;
        Ok(())
    }
    pub fn field(&mut self, name: &str, value: &str) -> Result<(), E> {
        if name.len() > 96 || value.len() > 8192 {
            return Err(E::TranscriptLimit);
        }
        self.line(&format!("{name}={value}"), false)
    }
    pub fn hex(&mut self, name: &str, bytes: &[u8]) -> Result<(), E> {
        if bytes.len() > 4096 {
            return Err(E::TranscriptLimit);
        }
        let mut hex = String::with_capacity(bytes.len() * 2);
        for b in bytes {
            use std::fmt::Write;
            write!(&mut hex, "{b:02x}").expect("String writer");
        }
        self.field(name, &hex)
    }
    pub fn header(&mut self, m: &Sec1210IfsReadbackMetadata) -> Result<(), E> {
        self.line("QK-CARD-SITTING-V1", false)?;
        for (name, value) in [
            ("visibility", "PRIVATE_CUSTODY_ONLY"),
            ("allowlist", "QK-DEC-167-SUP-007"),
            ("tool_version", SEC1210_IFS_READBACK_TOOL_VERSION),
            ("source_commit", m.source()),
            ("timestamp_utc", m.utc()),
            ("host_alias", "RIG-HOST-PI3B-01"),
            ("specimen_alias", "J3R180-03"),
            ("mode", "sec1210-ifs-readback"),
            ("transport", "sec1210-uart"),
            ("tty", SEC1210_TTY),
            ("slot", "0"),
            ("power_select", "02"),
            ("campaign_source_commit", SITTING_APPLET_SOURCE_COMMIT),
            ("applet_source_commit", SITTING_APPLET_SOURCE_COMMIT),
            ("canonical_cap_sha256", CANONICAL_CAP_SHA256),
            ("plan_sha256", READBACK_PLAN_SHA256),
            ("plan_bytes", "2943"),
            ("plan_lf", "13"),
            ("t1.nad", "00"),
            ("t1.edc", "LRC"),
            ("t1.ifsc", "254"),
            ("t1.initial_ifsd", "32"),
            ("t1.requested_ifsd", "254"),
            ("outer_watchdog_required_seconds", "300"),
            ("stty.program", "stty"),
        ] {
            self.field(name, value)?;
        }
        self.field("canonical_cap_bytes", &CANONICAL_CAP_BYTES.to_string())?;
        self.field(
            "output_basename",
            m.output()
                .file_name()
                .and_then(|n| n.to_str())
                .ok_or(crate::Sec1210Error::OutputRejected)?,
        )?;
        self.field("stty.argv", &SEC1210_STTY_ARGS.join(" "))?;
        for (id, value) in IFS_READBACK_LIMITS {
            self.field(id, &value.to_string())?;
        }
        Ok(())
    }
    pub fn observation(&mut self, index: usize, o: &ReadbackObservation) -> Result<(), E> {
        let text = match o {
            ReadbackObservation::SlotChange { bitmap, slot1_bits } => {
                format!("SlotChange bitmap={bitmap:02x} slot1_bits={slot1_bits}")
            }
            ReadbackObservation::HardwareError {
                slot,
                sequence,
                code,
            } => format!("HardwareError slot={slot} sequence={sequence} code={code:02x}"),
            ReadbackObservation::SlotStatus {
                status,
                error,
                clock,
            } => format!("SlotStatus status={status:02x} error={error:02x} clock={clock:02x}"),
            ReadbackObservation::Atr(atr) => {
                self.hex("atr_hex", atr)?;
                "AtrExactMatch".to_string()
            }
            ReadbackObservation::Parameters { protocol, bytes } => {
                self.hex("parameters_hex", bytes)?;
                format!(
                    "Parameters protocol={protocol:02x} ifsc={:02x} edc_bit={}",
                    bytes[5],
                    bytes[1] & 1
                )
            }
            ReadbackObservation::Transfer {
                sequence,
                payload_bytes,
            } => format!("Transfer sequence={sequence} payload_bytes={payload_bytes}"),
        };
        self.field(&format!("observation.{index}"), &text)
    }
    pub fn finish(&mut self, s: &Sec1210IfsReadbackSummary) -> Result<(), E> {
        for (name, value) in [
            ("request_count", s.request_count),
            ("response_count", s.response_count),
            ("event_count", s.event_count),
            ("captured_rx_bytes", s.captured_rx_bytes),
            ("apdu_transmit_count", s.apdu_transmit_count),
            ("apdu_response_count", s.apdu_response_count),
            ("continuation_count", s.continuation_count),
        ] {
            self.line(&format!("{name}={value}"), true)?;
        }
        self.line(
            &format!(
                "ifs_accepted={}",
                if s.ifs_accepted { "PASS" } else { "FALSE" }
            ),
            true,
        )?;
        self.line(
            &format!(
                "local_handle_released={}",
                if s.local_handle_released {
                    "PASS"
                } else {
                    "NO_LOCAL_HANDLE"
                }
            ),
            true,
        )?;
        self.line("kernel_close_result=UNOBSERVED", true)?;
        self.line(
            &format!(
                "transcript_overflow={}",
                if self.capped { "TRUE" } else { "FALSE" }
            ),
            true,
        )?;
        self.line(
            &format!(
                "first_failure={}",
                s.failure.map(|e| e.name()).unwrap_or("NONE")
            ),
            true,
        )?;
        self.line(
            &format!("result={}", s.failure.map(|e| e.name()).unwrap_or("PASS")),
            true,
        )
    }
}
