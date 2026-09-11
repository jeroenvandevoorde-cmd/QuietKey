//! New UART lane only; existing PC/SC encoders are unchanged.
use crate::{
    Sec1210Error, Sec1210Metadata, Sec1210Summary, CANONICAL_CAP_BYTES, CANONICAL_CAP_SHA256,
    MAX_SITTING_TRANSCRIPT_BYTES, SEC1210_STTY_ARGS, SEC1210_TOOL_VERSION, SEC1210_TTY,
    SITTING_APPLET_SOURCE_COMMIT,
};
use qk_sec1210_wire::Observation;
use std::io::Write;

pub struct Sec1210Transcript<W: Write> {
    writer: W,
    bytes: usize,
    broken: bool,
    capped: bool,
}
impl<W: Write> Sec1210Transcript<W> {
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
    fn line(&mut self, line: &str, terminal: bool) -> Result<(), Sec1210Error> {
        if self.broken {
            return Err(Sec1210Error::TranscriptIo);
        }
        if self.capped && !terminal {
            return Err(Sec1210Error::TranscriptLimit);
        }
        if !line.is_ascii() || line.contains(['\r', '\n', '\0']) {
            return Err(Sec1210Error::MetadataRejected);
        }
        let limit = if terminal {
            MAX_SITTING_TRANSCRIPT_BYTES
        } else {
            MAX_SITTING_TRANSCRIPT_BYTES - 1024
        };
        if line.len() >= limit.saturating_sub(self.bytes) {
            self.capped = true;
            return Err(Sec1210Error::TranscriptLimit);
        }
        let result = self
            .writer
            .write_all(line.as_bytes())
            .and_then(|_| self.writer.write_all(b"\n"))
            .and_then(|_| self.writer.flush());
        if result.is_err() {
            self.broken = true;
            return Err(Sec1210Error::TranscriptIo);
        }
        self.bytes += line.len() + 1;
        Ok(())
    }
    pub fn field(&mut self, name: &str, value: &str) -> Result<(), Sec1210Error> {
        if name.len() > 96 || value.len() > 8192 {
            return Err(Sec1210Error::TranscriptLimit);
        }
        self.line(&format!("{name}={value}"), false)
    }
    pub fn hex(&mut self, name: &str, value: &[u8]) -> Result<(), Sec1210Error> {
        if value.len() > 4096 {
            return Err(Sec1210Error::TranscriptLimit);
        }
        let mut hex = String::with_capacity(value.len() * 2);
        for byte in value {
            use std::fmt::Write;
            write!(&mut hex, "{byte:02x}").expect("String writer");
        }
        self.field(name, &hex)
    }
    pub fn header(&mut self, m: &Sec1210Metadata) -> Result<(), Sec1210Error> {
        self.line("QK-CARD-SITTING-V1", false)?;
        self.field("visibility", "PRIVATE_CUSTODY_ONLY")?;
        self.field("allowlist", "QK-DEC-167")?;
        self.field("tool_version", SEC1210_TOOL_VERSION)?;
        self.field("source_commit", m.source())?;
        self.field("timestamp_utc", m.utc())?;
        self.field("host_alias", "RIG-HOST-PI3B-01")?;
        self.field("specimen_alias", "J3R180-03")?;
        self.field("mode", "sec1210-probe")?;
        self.field("transport", "sec1210-uart")?;
        self.field("tty", SEC1210_TTY)?;
        self.field("slot", "0")?;
        self.field("power_select", "02")?;
        self.field("applet_source_commit", SITTING_APPLET_SOURCE_COMMIT)?;
        self.field("canonical_cap_bytes", &CANONICAL_CAP_BYTES.to_string())?;
        self.field("canonical_cap_sha256", CANONICAL_CAP_SHA256)?;
        self.field(
            "output_basename",
            m.output()
                .file_name()
                .and_then(|s| s.to_str())
                .ok_or(Sec1210Error::OutputRejected)?,
        )?;
        self.field("stty.program", "stty")?;
        self.field("stty.argv", &SEC1210_STTY_ARGS.join(" "))?;
        self.field("receive_budget_ms", "5000")?;
        self.field("outer_watchdog_required_seconds", "300")
    }
    pub fn observation(&mut self, index: usize, value: &Observation) -> Result<(), Sec1210Error> {
        let value = match value {
            Observation::SlotChange { bitmap, slot1_bits } => {
                format!("SlotChange bitmap={bitmap:02x} slot1_bits={slot1_bits}")
            }
            Observation::HardwareError {
                slot,
                sequence,
                code,
            } => format!("HardwareError slot={slot} sequence={sequence} code={code:02x}"),
            Observation::SlotStatus {
                status,
                error,
                clock,
            } => format!("SlotStatus status={status:02x} error={error:02x} clock={clock:02x}"),
            Observation::Atr(atr) => {
                self.hex("atr_hex", atr)?;
                "AtrExactMatch".to_string()
            }
        };
        self.field(&format!("observation.{index}"), &value)
    }
    pub fn finish(&mut self, s: &Sec1210Summary) -> Result<(), Sec1210Error> {
        for (name, value) in [
            ("request_count", s.request_count.to_string()),
            ("response_count", s.response_count.to_string()),
            ("event_count", s.event_count.to_string()),
            ("captured_rx_bytes", s.received_bytes.to_string()),
            ("apdu_transmit_count", "0".to_string()),
            (
                "local_handle_released",
                if s.local_handle_released {
                    "PASS"
                } else {
                    "NO_LOCAL_HANDLE"
                }
                .to_string(),
            ),
            ("kernel_close_result", "UNOBSERVED".to_string()),
            (
                "transcript_overflow",
                if self.capped { "TRUE" } else { "FALSE" }.to_string(),
            ),
            (
                "first_failure",
                s.failure.map(|e| e.name()).unwrap_or("NONE").to_string(),
            ),
            (
                "result",
                s.failure.map(|e| e.name()).unwrap_or("PASS").to_string(),
            ),
        ] {
            self.line(&format!("{name}={value}"), true)?;
        }
        Ok(())
    }
}
