//! Bounded private transcript for SUP-013's one public-GOLDEN SIGN session.
use crate::{
    Sec1210FidiSignError as E, Sec1210FidiSignMetadata, Sec1210FidiSignSummary, B6_DIGEST,
    B6_EXPANDED_REQUEST_BYTES, B6_PLAN_SHA256, B6_PUBLIC_KEY, B6_REVIEW_HASH, B6_SESSION_IDS,
    B6_TOTAL_EXCHANGES, B6_WALLET_ID, CANONICAL_CAP_BYTES, CANONICAL_CAP_SHA256, FIDI_SIGN_LIMITS,
    FIDI_SIGN_PLAN_BYTES, FIDI_SIGN_PLAN_SHA256, SEC1210_FIDI_SIGN_TOOL_VERSION, SEC1210_STTY_ARGS,
    SEC1210_TTY, SITTING_APPLET_SOURCE_COMMIT,
};
use qk_sec1210_wire::RawObservation;
use std::io::Write;

pub const MAX_SEC1210_FIDI_SIGN_TRANSCRIPT_BYTES: usize = 1_048_576;
const TERMINAL_RESERVE: usize = 8_192;

pub struct Sec1210FidiSignTranscript<W: Write> {
    writer: W,
    bytes: usize,
    broken: bool,
    capped: bool,
}

impl<W: Write> Sec1210FidiSignTranscript<W> {
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
            return Err(E::Native(crate::Sec1210Error::MetadataRejected));
        }
        let limit =
            MAX_SEC1210_FIDI_SIGN_TRANSCRIPT_BYTES - if terminal { 0 } else { TERMINAL_RESERVE };
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
        if self.broken {
            return Err(E::TranscriptIo);
        }
        if self.capped || name.len() > 96 || value.len() > 8_192 {
            self.capped = true;
            return Err(E::TranscriptLimit);
        }
        if name.is_empty() || name.contains('=') {
            return Err(E::Native(crate::Sec1210Error::MetadataRejected));
        }
        self.line(&format!("{name}={value}"), false)
    }

    pub fn hex(&mut self, name: &str, bytes: &[u8]) -> Result<(), E> {
        if self.broken {
            return Err(E::TranscriptIo);
        }
        if self.capped || bytes.len() > 4_096 {
            self.capped = true;
            return Err(E::TranscriptLimit);
        }
        let mut hex = String::with_capacity(bytes.len() * 2);
        for byte in bytes {
            use std::fmt::Write;
            write!(&mut hex, "{byte:02x}").expect("String writer");
        }
        self.field(name, &hex)
    }

    pub fn header(&mut self, metadata: &Sec1210FidiSignMetadata) -> Result<(), E> {
        self.line("QK-CARD-SITTING-V1", false)?;
        for (name, value) in [
            ("visibility", "PRIVATE_CUSTODY_ONLY"),
            ("allowlist", "QK-DEC-167-SUP-013"),
            ("tool_version", SEC1210_FIDI_SIGN_TOOL_VERSION),
            ("source_commit", metadata.source()),
            ("timestamp_utc", metadata.utc()),
            ("host_alias", "RIG-HOST-PI3B-01"),
            ("specimen_alias", "J3R180-03"),
            ("mode", "sec1210-fidi-sign"),
            ("transport", "sec1210-uart"),
            ("tty", SEC1210_TTY),
            ("slot", "0"),
            ("power_select", "02"),
            ("campaign_source_commit", SITTING_APPLET_SOURCE_COMMIT),
            ("applet_source_commit", SITTING_APPLET_SOURCE_COMMIT),
            ("canonical_cap_sha256", CANONICAL_CAP_SHA256),
            ("parent_b6_plan_sha256", B6_PLAN_SHA256),
            ("plan_sha256", FIDI_SIGN_PLAN_SHA256),
            ("plan_requests", "102"),
            ("b6.session_index", "0"),
            ("b6.signature_count", "100"),
            ("set_parameters.requested_bmFindexDindex", "18"),
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
            "parent_b6_plan_bytes",
            &B6_EXPANDED_REQUEST_BYTES.to_string(),
        )?;
        self.field("parent_b6_plan_requests", &B6_TOTAL_EXCHANGES.to_string())?;
        self.field("plan_bytes", &FIDI_SIGN_PLAN_BYTES.to_string())?;
        self.hex("b6.session_id_hex", &B6_SESSION_IDS[0])?;
        self.hex("b6.wallet_id_hex", &B6_WALLET_ID)?;
        self.hex("b6.review_hash_hex", &B6_REVIEW_HASH)?;
        self.hex("b6.digest_hex", &B6_DIGEST)?;
        self.hex("b6.public_key_hex", &B6_PUBLIC_KEY)?;
        self.field(
            "output_basename",
            metadata
                .output()
                .file_name()
                .and_then(|name| name.to_str())
                .ok_or(E::Native(crate::Sec1210Error::OutputRejected))?,
        )?;
        self.field("stty.argv", &SEC1210_STTY_ARGS.join(" "))?;
        for (id, value) in FIDI_SIGN_LIMITS {
            self.field(id, value)?;
        }
        Ok(())
    }

    pub fn set_parameters_reply(&mut self, reply: &qk_sec1210_wire::Response) -> Result<(), E> {
        self.field("set_parameters.bStatus", &format!("{:02x}", reply.status))?;
        self.field("set_parameters.bError", &format!("{:02x}", reply.error))?;
        self.field(
            "set_parameters.bProtocolNum",
            &format!("{:02x}", reply.parameter),
        )?;
        // Preserve the actual decoded candidate, including a rejected length.
        self.hex("set_parameters.response_hex", reply.payload())
    }

    pub fn observation(
        &mut self,
        index: usize,
        observation: &RawObservation,
        set_parameters: bool,
    ) -> Result<(), E> {
        let text = match observation {
            RawObservation::SlotChange { bitmap, slot1_bits } => {
                format!("SlotChange bitmap={bitmap:02x} slot1_bits={slot1_bits}")
            }
            RawObservation::HardwareError { slot, sequence, code } => {
                format!("HardwareError slot={slot} sequence={sequence} code={code:02x}")
            }
            RawObservation::SlotStatus { status, error, clock } => {
                format!("SlotStatus status={status:02x} error={error:02x} clock={clock:02x}")
            }
            RawObservation::Atr(atr) => {
                self.hex("atr_hex", atr)?;
                "AtrExactMatch".to_string()
            }
            RawObservation::Parameters { protocol, bytes } => {
                let kind = if set_parameters {
                    "SetParameters"
                } else {
                    self.hex("parameters_hex", bytes)?;
                    "Parameters"
                };
                format!(
                    "{kind} protocol={protocol:02x} ifsc={:02x} edc_bit={}",
                    bytes[5],
                    bytes[1] & 1
                )
            }
            RawObservation::Transfer { ordinal, sequence, payload_bytes } => {
                format!("Transfer ordinal={ordinal} sequence={sequence} payload_bytes={payload_bytes}")
            }
            RawObservation::TimeExtension {
                ordinal,
                sequence,
                multiplier,
                apdu_count,
                invocation_count,
                command_deadline_ms,
                apdu_deadline_ms,
                span,
            } => format!(
                "TimeExtension ordinal={ordinal} sequence={sequence} multiplier={multiplier} apdu_count={apdu_count} invocation_count={invocation_count} command_deadline_ms={command_deadline_ms} apdu_deadline_ms={apdu_deadline_ms} start_rx_offset={} end_rx_offset={}",
                span.start_rx_offset, span.end_rx_offset
            ),
        };
        self.field(&format!("observation.{index}"), &text)
    }

    pub fn finish(&mut self, summary: &Sec1210FidiSignSummary) -> Result<(), E> {
        let complete = summary.set_parameters_accepted
            && summary.ifs_accepted
            && 107usize.checked_add(summary.wtx_count) == Some(summary.request_count)
            && summary.request_count == summary.response_count
            && summary.request_count <= 512
            && summary.event_count <= 64
            && summary.captured_rx_bytes <= 32_768
            && summary.wtx_count <= 8 * 102
            && summary.time_extension_count <= 8 * 102
            && summary.apdu_transmit_count == 102
            && summary.apdu_response_count == 102
            && summary.apdu_accepted_count == 102
            && summary.signature_fact_count == 100
            && summary.signature_accepted_count == 100
            && summary.normalization_changed_count <= 100
            && summary.completed_sessions == 1
            && summary.session_start_utc.is_some()
            && summary.session_end_utc.is_some()
            && summary.local_handle_released;
        let failure = summary.failure.or(if self.capped {
            Some(E::TranscriptLimit)
        } else if !complete {
            Some(E::PlanRejected)
        } else {
            None
        });
        for (name, value) in [
            ("request_count", summary.request_count),
            ("response_count", summary.response_count),
            ("event_count", summary.event_count),
            ("captured_rx_bytes", summary.captured_rx_bytes),
            ("read_fragment_count", summary.read_fragment_count),
            ("apdu_transmit_count", summary.apdu_transmit_count),
            ("apdu_response_count", summary.apdu_response_count),
            ("apdu_accepted_count", summary.apdu_accepted_count),
            ("signature_fact_count", summary.signature_fact_count),
            ("signature_accepted_count", summary.signature_accepted_count),
            (
                "normalization_changed_count",
                summary.normalization_changed_count,
            ),
            ("completed_sessions", summary.completed_sessions),
            ("wtx_count", summary.wtx_count),
            ("time_extension_count", summary.time_extension_count),
        ] {
            self.line(&format!("{name}={value}"), true)?;
        }
        // The engine emits start_utc at the session boundary, before SELECT.
        self.line(
            &format!(
                "session.0.end_utc={}",
                summary.session_end_utc.as_deref().unwrap_or("UNOBSERVED")
            ),
            true,
        )?;
        for (name, value) in [
            ("set_parameters_accepted", summary.set_parameters_accepted),
            ("ifs_accepted", summary.ifs_accepted),
        ] {
            self.line(
                &format!("{name}={}", if value { "PASS" } else { "FALSE" }),
                true,
            )?;
        }
        self.line(
            &format!(
                "local_handle_released={}",
                if summary.local_handle_released {
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
                failure.map(|error| error.name()).unwrap_or("NONE")
            ),
            true,
        )?;
        self.line(
            &format!(
                "result={}",
                failure.map(|error| error.name()).unwrap_or("PASS")
            ),
            true,
        )
    }
}
