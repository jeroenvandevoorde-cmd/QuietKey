//! Incrementally flushed QK-DEC-165 sitting transcript writer.

use std::io::Write;
use std::panic::{catch_unwind, AssertUnwindSafe};

use crate::{
    sitting::{SittingMetadata, SittingOutcome},
    NegotiatedProtocol, SittingError, SittingExchange, CANONICAL_CAP_BYTES, CANONICAL_CAP_SHA256,
    GOLDEN_FIXTURE_BLOB, GOLDEN_FIXTURE_BYTES, GOLDEN_FIXTURE_LF, GOLDEN_FIXTURE_PATH,
    GOLDEN_FIXTURE_SHA256, MAX_SITTING_TRANSCRIPT_BYTES, SITTING_APPLET_SOURCE_COMMIT,
    SITTING_CAMPAIGN_SOURCE_COMMIT, SITTING_PLAN_VERSION, SITTING_TOOL_VERSION,
};

pub const SITTING_TRANSCRIPT_VERSION: &str = "QK-CARD-SITTING-V1";

pub struct SittingTranscript<W: Write> {
    writer: W,
    bytes_written: usize,
    event_count: usize,
}

impl<W: Write> SittingTranscript<W> {
    pub const fn new(writer: W) -> Self {
        Self {
            writer,
            bytes_written: 0,
            event_count: 0,
        }
    }

    pub const fn bytes_written(&self) -> usize {
        self.bytes_written
    }

    pub fn into_inner(self) -> W {
        self.writer
    }

    pub fn write_header(&mut self, metadata: &SittingMetadata) -> Result<(), SittingError> {
        let enrollment = metadata.enrollment().inner();
        let output_basename = metadata
            .output_path()
            .file_name()
            .and_then(|name| name.to_str())
            .ok_or(SittingError::SittingOutputPathRejected)?;
        self.write_line(SITTING_TRANSCRIPT_VERSION)?;
        self.write_field("plan_version", SITTING_PLAN_VERSION)?;
        self.write_field("tool_version", SITTING_TOOL_VERSION)?;
        self.write_field("source_commit", &enrollment.source_commit)?;
        self.write_field("campaign_source_commit", SITTING_CAMPAIGN_SOURCE_COMMIT)?;
        self.write_field("applet_source_commit", SITTING_APPLET_SOURCE_COMMIT)?;
        self.write_field("canonical_cap_bytes", &CANONICAL_CAP_BYTES.to_string())?;
        self.write_field("canonical_cap_sha256", CANONICAL_CAP_SHA256)?;
        self.write_field("golden_fixture_path", GOLDEN_FIXTURE_PATH)?;
        self.write_field("golden_fixture_bytes", &GOLDEN_FIXTURE_BYTES.to_string())?;
        self.write_field("golden_fixture_lf", &GOLDEN_FIXTURE_LF.to_string())?;
        self.write_field("golden_fixture_sha256", GOLDEN_FIXTURE_SHA256)?;
        self.write_field("golden_fixture_blob", GOLDEN_FIXTURE_BLOB)?;
        self.write_field("timestamp_utc", &enrollment.timestamp_utc)?;
        self.write_field("host_alias", &enrollment.host_alias)?;
        self.write_field("reader_alias", &enrollment.reader_alias)?;
        self.write_field(
            "specimen_alias",
            enrollment.specimen_alias.as_deref().unwrap_or("NONE"),
        )?;
        self.write_field("mode", metadata.mode().as_str())?;
        self.write_field(
            "selected_reader_name_hex",
            &hex(enrollment
                .selected_reader_name
                .as_deref()
                .unwrap_or_default()),
        )?;
        self.write_field("output_basename", output_basename)
    }

    pub fn record_readers(&mut self, readers: &[Vec<u8>]) -> Result<(), SittingError> {
        self.write_field("reader_count", &readers.len().to_string())?;
        for (index, reader) in readers.iter().enumerate() {
            self.write_field(&format!("reader.{index}.name_hex"), &hex(reader))?;
        }
        Ok(())
    }

    pub fn record_observation(
        &mut self,
        atr: &[u8],
        protocol: Option<NegotiatedProtocol>,
    ) -> Result<(), SittingError> {
        self.write_field("atr_hex", &hex(atr))?;
        self.write_field(
            "protocol",
            protocol.map(NegotiatedProtocol::as_str).unwrap_or("NONE"),
        )
    }

    pub fn record_event(
        &mut self,
        operation: &str,
        outcome: SittingOutcome,
    ) -> Result<(), SittingError> {
        if !valid_label(operation) {
            return Err(SittingError::SittingSequenceViolation);
        }
        let line = format!(
            "event.{}={}:{}",
            self.event_count,
            operation,
            outcome.as_str()
        );
        self.write_line(&line)?;
        self.event_count += 1;
        Ok(())
    }

    pub fn record_request(&mut self, exchange: &SittingExchange) -> Result<(), SittingError> {
        self.write_field(
            &format!("apdu.{}.phase", exchange.index()),
            exchange.phase(),
        )?;
        self.write_field(&format!("apdu.{}.name", exchange.index()), exchange.name())?;
        self.write_field(
            &format!("apdu.{}.tx_hex", exchange.index()),
            &hex(exchange.request()),
        )
    }

    pub fn record_response(
        &mut self,
        exchange: &SittingExchange,
        response: &[u8],
    ) -> Result<(), SittingError> {
        self.write_field(&format!("apdu.{}.rx_hex", exchange.index()), &hex(response))
    }

    pub fn record_comparison(
        &mut self,
        exchange: &SittingExchange,
        outcome: SittingOutcome,
    ) -> Result<(), SittingError> {
        self.write_field(
            &format!("apdu.{}.comparison", exchange.index()),
            outcome.as_str(),
        )?;
        self.record_event(
            &format!("Exchange/{}/{}", exchange.phase(), exchange.name()),
            outcome,
        )
    }

    pub fn record_counts(
        &mut self,
        transmit_calls: usize,
        received_responses: usize,
    ) -> Result<(), SittingError> {
        self.write_field("transmit_call_count", &transmit_calls.to_string())?;
        self.write_field("received_response_count", &received_responses.to_string())
    }

    pub fn record_disconnect(&mut self, outcome: SittingOutcome) -> Result<(), SittingError> {
        self.record_event("Disconnect", outcome)?;
        self.write_field("disconnect", outcome.as_str())
    }

    pub fn record_disconnect_none(&mut self) -> Result<(), SittingError> {
        self.write_field("disconnect", "NONE")
    }

    pub fn record_result(&mut self, outcome: SittingOutcome) -> Result<(), SittingError> {
        self.write_field("event_count", &self.event_count.to_string())?;
        self.write_field("result", outcome.as_str())
    }

    fn write_field(&mut self, name: &str, value: &str) -> Result<(), SittingError> {
        if !valid_label(name) || !value.is_ascii() || value.contains(['\r', '\n']) {
            return Err(SittingError::SittingSequenceViolation);
        }
        self.write_line(&format!("{name}={value}"))
    }

    fn write_line(&mut self, line: &str) -> Result<(), SittingError> {
        if !line.is_ascii() || line.contains(['\r', '\n']) {
            return Err(SittingError::SittingSequenceViolation);
        }
        let added = line
            .len()
            .checked_add(1)
            .ok_or(SittingError::SittingTranscriptTooLarge)?;
        let next = self
            .bytes_written
            .checked_add(added)
            .ok_or(SittingError::SittingTranscriptTooLarge)?;
        if next > MAX_SITTING_TRANSCRIPT_BYTES {
            return Err(SittingError::SittingTranscriptTooLarge);
        }
        match catch_unwind(AssertUnwindSafe(|| {
            self.writer
                .write_all(line.as_bytes())
                .and_then(|()| self.writer.write_all(b"\n"))
        })) {
            Ok(Ok(())) => {}
            Ok(Err(_)) => return Err(SittingError::SittingOutputWriteFailed),
            Err(_) => return Err(SittingError::SittingBoundaryPanicked),
        }
        self.bytes_written = next;
        match catch_unwind(AssertUnwindSafe(|| self.writer.flush())) {
            Ok(Ok(())) => Ok(()),
            Ok(Err(_)) => Err(SittingError::SittingOutputFlushFailed),
            Err(_) => Err(SittingError::SittingBoundaryPanicked),
        }
    }
}

fn valid_label(value: &str) -> bool {
    !value.is_empty()
        && value.bytes().all(|byte| {
            byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-' | b'/' | b':')
        })
}

fn hex(input: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut output = String::with_capacity(input.len() * 2);
    for byte in input {
        output.push(char::from(HEX[usize::from(byte >> 4)]));
        output.push(char::from(HEX[usize::from(byte & 0x0f)]));
    }
    output
}
