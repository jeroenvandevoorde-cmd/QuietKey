//! Streaming private transcript for the fixed management-observation sitting.

use std::io::Write;
use std::panic::{catch_unwind, AssertUnwindSafe};

use crate::{
    InitializationFields, ManagementObservationMetadata, NegotiatedProtocol, ObservationError,
    ObservationFailure, ObservationOutcome, ObservationPhase, SittingError,
    MANAGEMENT_OBSERVATION_ALLOWLIST_ID, MANAGEMENT_OBSERVATION_TOOL_VERSION,
    MAX_SITTING_TRANSCRIPT_BYTES, SITTING_CAMPAIGN_SOURCE_COMMIT,
};

pub const MANAGEMENT_OBSERVATION_TRANSCRIPT_VERSION: &str = "QK-CARD-MANAGEMENT-OBSERVATION-V1";

pub struct ManagementObservationTranscript<W: Write> {
    writer: W,
    bytes_written: usize,
    event_count: usize,
    terminal_error: Option<SittingError>,
}

impl<W: Write> ManagementObservationTranscript<W> {
    pub const fn new(writer: W) -> Self {
        Self {
            writer,
            bytes_written: 0,
            event_count: 0,
            terminal_error: None,
        }
    }

    pub const fn bytes_written(&self) -> usize {
        self.bytes_written
    }

    pub fn into_inner(self) -> W {
        self.writer
    }

    pub fn write_header(
        &mut self,
        metadata: &ManagementObservationMetadata,
    ) -> Result<(), ObservationError> {
        let enrollment = metadata.enrollment().inner();
        let output_basename = metadata
            .output_path()
            .file_name()
            .and_then(|name| name.to_str())
            .ok_or(ObservationError::Sitting(
                SittingError::SittingOutputPathRejected,
            ))?;
        self.write_line(MANAGEMENT_OBSERVATION_TRANSCRIPT_VERSION)?;
        self.write_field("allowlist", MANAGEMENT_OBSERVATION_ALLOWLIST_ID)?;
        self.write_field("tool_version", MANAGEMENT_OBSERVATION_TOOL_VERSION)?;
        self.write_field("source_commit", &enrollment.source_commit)?;
        self.write_field("campaign_source_commit", SITTING_CAMPAIGN_SOURCE_COMMIT)?;
        self.write_field("visibility", "PRIVATE_CUSTODY_ONLY")?;
        self.write_field("timestamp_utc", &enrollment.timestamp_utc)?;
        self.write_field("host_alias", &enrollment.host_alias)?;
        self.write_field("reader_alias", &enrollment.reader_alias)?;
        self.write_field(
            "specimen_alias",
            enrollment.specimen_alias.as_deref().unwrap_or("NONE"),
        )?;
        self.write_field("mode", "management-observe")?;
        self.write_field(
            "selected_reader_name_hex",
            &hex(enrollment
                .selected_reader_name
                .as_deref()
                .unwrap_or_default()),
        )?;
        self.write_field("output_basename", output_basename)
    }

    pub fn record_readers(&mut self, readers: &[Vec<u8>]) -> Result<(), ObservationError> {
        self.write_field("reader_count", &readers.len().to_string())?;
        for (index, reader) in readers.iter().enumerate() {
            self.write_field(&format!("reader.{index}.name_hex"), &hex(reader))?;
        }
        Ok(())
    }

    pub fn record_status(
        &mut self,
        atr: &[u8],
        protocol: Option<NegotiatedProtocol>,
    ) -> Result<(), ObservationError> {
        self.write_field("atr_hex", &hex(atr))?;
        self.write_field(
            "protocol",
            protocol.map(NegotiatedProtocol::as_str).unwrap_or("NONE"),
        )
    }

    pub fn record_event(
        &mut self,
        phase: ObservationPhase,
        outcome: ObservationOutcome,
    ) -> Result<(), ObservationError> {
        let line = format!(
            "event.{}={}:{}",
            self.event_count,
            phase.name(),
            outcome.as_str()
        );
        self.write_line(&line)?;
        self.event_count += 1;
        Ok(())
    }

    pub fn record_request(
        &mut self,
        index: usize,
        phase: ObservationPhase,
        request: &[u8],
    ) -> Result<(), ObservationError> {
        self.write_field(&format!("exchange.{index}.phase"), phase.name())?;
        self.write_field(&format!("exchange.{index}.tx_hex"), &hex(request))
    }

    pub fn record_response(
        &mut self,
        index: usize,
        _phase: ObservationPhase,
        response: &[u8],
    ) -> Result<(), ObservationError> {
        self.write_field(&format!("exchange.{index}.rx_hex"), &hex(response))
    }

    pub fn record_initialization_fields(
        &mut self,
        fields: &InitializationFields,
    ) -> Result<(), ObservationError> {
        self.write_field("initialize.body_bytes", &fields.body_len.to_string())?;
        self.write_field("initialize.key_version_hex", &hex_byte(fields.key_version))?;
        self.write_field("initialize.scp_version_hex", &hex_byte(fields.scp_version))?;
        match fields.scp_i {
            Some(value) => self.write_field("initialize.scp_i_hex", &hex_byte(value)),
            None => self.write_field("initialize.scp_i_hex", "NONE"),
        }
    }

    pub fn record_counts(
        &mut self,
        transmit_calls: usize,
        received_responses: usize,
    ) -> Result<(), ObservationError> {
        self.write_field("transmit_call_count", &transmit_calls.to_string())?;
        self.write_field("received_response_count", &received_responses.to_string())
    }

    pub fn record_first_failure(
        &mut self,
        failure: Option<&ObservationFailure>,
    ) -> Result<(), ObservationError> {
        match failure {
            Some(failure) => self.write_field(
                "first_failure",
                &format!("{}:{}", failure.phase.name(), failure.error.name()),
            ),
            None => self.write_field("first_failure", "NONE"),
        }
    }

    pub fn record_disconnect(
        &mut self,
        outcome: ObservationOutcome,
    ) -> Result<(), ObservationError> {
        self.record_event(ObservationPhase::Disconnect, outcome)?;
        self.write_field("disconnect", outcome.as_str())
    }

    pub fn record_disconnect_none(&mut self) -> Result<(), ObservationError> {
        self.write_field("disconnect", "NONE")
    }

    pub fn record_result(&mut self, outcome: ObservationOutcome) -> Result<(), ObservationError> {
        self.write_field("event_count", &self.event_count.to_string())?;
        self.write_field("result", outcome.as_str())
    }

    fn write_field(&mut self, name: &str, value: &str) -> Result<(), ObservationError> {
        if !valid_label(name) || !value.is_ascii() || value.contains(['\r', '\n']) {
            return Err(self.fail(SittingError::SittingSequenceViolation));
        }
        self.write_line(&format!("{name}={value}"))
    }

    fn write_line(&mut self, line: &str) -> Result<(), ObservationError> {
        if let Some(error) = self.terminal_error {
            return Err(ObservationError::Sitting(error));
        }
        if !line.is_ascii() || line.contains(['\r', '\n']) {
            return Err(self.fail(SittingError::SittingSequenceViolation));
        }
        let added = line
            .len()
            .checked_add(1)
            .ok_or_else(|| self.fail(SittingError::SittingTranscriptTooLarge))?;
        let next = self
            .bytes_written
            .checked_add(added)
            .ok_or_else(|| self.fail(SittingError::SittingTranscriptTooLarge))?;
        if next > MAX_SITTING_TRANSCRIPT_BYTES {
            return Err(self.fail(SittingError::SittingTranscriptTooLarge));
        }
        match catch_unwind(AssertUnwindSafe(|| {
            self.writer
                .write_all(line.as_bytes())
                .and_then(|()| self.writer.write_all(b"\n"))
        })) {
            Ok(Ok(())) => {}
            Ok(Err(_)) => return Err(self.fail(SittingError::SittingOutputWriteFailed)),
            Err(_) => return Err(self.fail(SittingError::SittingBoundaryPanicked)),
        }
        self.bytes_written = next;
        match catch_unwind(AssertUnwindSafe(|| self.writer.flush())) {
            Ok(Ok(())) => Ok(()),
            Ok(Err(_)) => Err(self.fail(SittingError::SittingOutputFlushFailed)),
            Err(_) => Err(self.fail(SittingError::SittingBoundaryPanicked)),
        }
    }

    fn fail(&mut self, error: SittingError) -> ObservationError {
        let first = *self.terminal_error.get_or_insert(error);
        ObservationError::Sitting(first)
    }
}

fn valid_label(value: &str) -> bool {
    !value.is_empty()
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-'))
}

fn hex(input: &[u8]) -> String {
    let mut output = String::with_capacity(input.len() * 2);
    for byte in input {
        output.push(char::from(HEX[usize::from(byte >> 4)]));
        output.push(char::from(HEX[usize::from(byte & 0x0f)]));
    }
    output
}

fn hex_byte(byte: u8) -> String {
    let mut output = String::with_capacity(2);
    output.push(char::from(HEX[usize::from(byte >> 4)]));
    output.push(char::from(HEX[usize::from(byte & 0x0f)]));
    output
}

const HEX: &[u8; 16] = b"0123456789abcdef";
