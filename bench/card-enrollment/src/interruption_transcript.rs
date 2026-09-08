//! Bounded, flushed private records for the fixed interruption observations.

use std::io::Write;
use std::panic::{catch_unwind, AssertUnwindSafe};

use crate::interruption::ClearOnDrop;
use crate::{
    InterruptionError, InterruptionMetadata, InterruptionPlanRow, InterruptionSummary,
    NegotiatedProtocol, ObservationStatus, SittingError, CANONICAL_CAP_BYTES, CANONICAL_CAP_SHA256,
    GOLDEN_FIXTURE_SHA256, INTERRUPTION_PLAN_BYTES, INTERRUPTION_PLAN_LF, INTERRUPTION_PLAN_SHA256,
    INTERRUPTION_TOOL_VERSION, MAX_SITTING_TRANSCRIPT_BYTES, SITTING_APPLET_SOURCE_COMMIT,
    SITTING_CAMPAIGN_SOURCE_COMMIT, SITTING_TRANSCRIPT_VERSION,
};

pub struct InterruptionTranscript<W: Write> {
    writer: W,
    bytes_written: usize,
    events: usize,
}

impl<W: Write> InterruptionTranscript<W> {
    pub const fn new(writer: W) -> Self {
        Self {
            writer,
            bytes_written: 0,
            events: 0,
        }
    }
    pub const fn bytes_written(&self) -> usize {
        self.bytes_written
    }
    pub fn into_inner(self) -> W {
        self.writer
    }

    pub(crate) fn header(&mut self, m: &InterruptionMetadata) -> Result<(), InterruptionError> {
        let e = m.enrollment.inner();
        self.line(SITTING_TRANSCRIPT_VERSION.as_bytes())?;
        self.field("custody", "PRIVATE_CUSTODY_ONLY")?;
        self.field("tool_version", INTERRUPTION_TOOL_VERSION)?;
        self.field("source_commit", &e.source_commit)?;
        self.field("campaign_source_commit", SITTING_CAMPAIGN_SOURCE_COMMIT)?;
        self.field("applet_source_commit", SITTING_APPLET_SOURCE_COMMIT)?;
        self.field("canonical_cap_bytes", &CANONICAL_CAP_BYTES.to_string())?;
        self.field("canonical_cap_sha256", CANONICAL_CAP_SHA256)?;
        self.field("golden_fixture_sha256", GOLDEN_FIXTURE_SHA256)?;
        self.field("plan_path", "tests/fixtures/sitting_interruption_v1.tsv")?;
        self.field("plan_bytes", &INTERRUPTION_PLAN_BYTES.to_string())?;
        self.field("plan_lf", &INTERRUPTION_PLAN_LF.to_string())?;
        self.field("plan_sha256", INTERRUPTION_PLAN_SHA256)?;
        self.field("timestamp_utc", &e.timestamp_utc)?;
        self.field("host_alias", &e.host_alias)?;
        self.field("reader_alias", &e.reader_alias)?;
        self.field(
            "specimen_alias",
            e.specimen_alias.as_deref().unwrap_or("NONE"),
        )?;
        self.field("mode", m.mode.as_str())?;
        self.field("trial_id", m.trial.as_str())?;
        self.field("checkpoint", m.trial.checkpoint())?;
        self.field(
            "removal_wait_ms",
            &m.removal_wait
                .map(|v| v.get().to_string())
                .unwrap_or_else(|| "NOT_APPLICABLE".into()),
        )?;
        self.hex(
            "selected_reader_name_hex",
            e.selected_reader_name.as_deref().unwrap_or_default(),
        )?;
        self.field(
            "output_basename",
            m.output_path()
                .file_name()
                .and_then(|s| s.to_str())
                .ok_or(SittingError::SittingOutputPathRejected)?,
        )
    }

    pub(crate) fn field(&mut self, name: &str, value: &str) -> Result<(), InterruptionError> {
        if name.is_empty()
            || !name
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b"._-/".contains(&b))
            || !value.is_ascii()
            || value.contains(['\r', '\n'])
        {
            return Err(SittingError::SittingSequenceViolation.into());
        }
        let mut scratch = [0u8; 8192];
        let scratch = ClearOnDrop(&mut scratch);
        let size = name
            .len()
            .checked_add(value.len())
            .and_then(|v| v.checked_add(1))
            .ok_or(SittingError::SittingTranscriptTooLarge)?;
        if size > scratch.0.len() {
            return Err(SittingError::SittingTranscriptTooLarge.into());
        }
        scratch.0[..name.len()].copy_from_slice(name.as_bytes());
        scratch.0[name.len()] = b'=';
        scratch.0[name.len() + 1..size].copy_from_slice(value.as_bytes());
        self.line(&scratch.0[..size])
    }

    fn hex(&mut self, name: &str, bytes: &[u8]) -> Result<(), InterruptionError> {
        let mut scratch = [0u8; 8192];
        let scratch = ClearOnDrop(&mut scratch);
        if bytes.len() > scratch.0.len() / 2 {
            return Err(SittingError::SittingTranscriptTooLarge.into());
        }
        const HEX: &[u8; 16] = b"0123456789abcdef";
        for (i, byte) in bytes.iter().enumerate() {
            scratch.0[2 * i] = HEX[(byte >> 4) as usize];
            scratch.0[2 * i + 1] = HEX[(byte & 15) as usize];
        }
        let value = std::str::from_utf8(&scratch.0[..bytes.len() * 2])
            .map_err(|_| SittingError::SittingSequenceViolation)?;
        self.field(name, value)
    }

    fn line(&mut self, bytes: &[u8]) -> Result<(), InterruptionError> {
        let next = self
            .bytes_written
            .checked_add(bytes.len())
            .and_then(|v| v.checked_add(1))
            .ok_or(SittingError::SittingTranscriptTooLarge)?;
        if next > MAX_SITTING_TRANSCRIPT_BYTES {
            return Err(SittingError::SittingTranscriptTooLarge.into());
        }
        match catch_unwind(AssertUnwindSafe(|| {
            self.writer
                .write_all(bytes)
                .and_then(|()| self.writer.write_all(b"\n"))
        })) {
            Ok(Ok(())) => {}
            Ok(Err(_)) => return Err(SittingError::SittingOutputWriteFailed.into()),
            Err(_) => return Err(SittingError::SittingBoundaryPanicked.into()),
        }
        self.bytes_written = next;
        match catch_unwind(AssertUnwindSafe(|| self.writer.flush())) {
            Ok(Ok(())) => Ok(()),
            Ok(Err(_)) => Err(SittingError::SittingOutputFlushFailed.into()),
            Err(_) => Err(SittingError::SittingBoundaryPanicked.into()),
        }
    }

    pub(crate) fn boundary(
        &mut self,
        name: &str,
        result: Result<(), InterruptionError>,
    ) -> Result<(), InterruptionError> {
        self.field(
            name,
            result
                .map(|()| "PASS")
                .unwrap_or_else(InterruptionError::name),
        )?;
        if let Err(InterruptionError::Native(error)) = result {
            self.field(&format!("{name}.native"), &format!("{error:?}: {error}"))?;
        }
        self.events += 1;
        Ok(())
    }
    pub(crate) fn readers(&mut self, readers: &[Vec<u8>]) -> Result<(), InterruptionError> {
        self.field("reader_count", &readers.len().to_string())?;
        for (i, r) in readers.iter().enumerate() {
            self.hex(&format!("reader.{i}.name_hex"), r)?;
        }
        Ok(())
    }
    pub(crate) fn observation(
        &mut self,
        status: &ObservationStatus,
    ) -> Result<(), InterruptionError> {
        self.hex("atr_hex", &status.atr)?;
        self.field(
            "protocol",
            status
                .protocol
                .map(NegotiatedProtocol::as_str)
                .unwrap_or("NONE"),
        )
    }
    pub(crate) fn request(
        &mut self,
        row: &InterruptionPlanRow,
        bytes: &[u8],
    ) -> Result<(), InterruptionError> {
        self.field(&format!("apdu.{}.phase", row.index), row.branch)?;
        self.field(&format!("apdu.{}.name", row.index), row.name)?;
        self.hex(&format!("apdu.{}.tx_hex", row.index), bytes)
    }
    pub(crate) fn response(
        &mut self,
        row: &InterruptionPlanRow,
        bytes: &[u8],
    ) -> Result<(), InterruptionError> {
        self.hex(&format!("apdu.{}.rx_hex", row.index), bytes)
    }
    pub(crate) fn comparison(
        &mut self,
        row: &InterruptionPlanRow,
        result: &str,
    ) -> Result<(), InterruptionError> {
        self.field(&format!("apdu.{}.comparison", row.index), result)?;
        self.events += 1;
        Ok(())
    }
    pub(crate) fn transport(
        &mut self,
        row: &InterruptionPlanRow,
        error: InterruptionError,
    ) -> Result<(), InterruptionError> {
        self.boundary(&format!("apdu.{}.transport", row.index), Err(error))
    }
    pub(crate) fn finish(&mut self, s: &InterruptionSummary) -> Result<(), InterruptionError> {
        self.field("transmit_call_count", &s.transmit_calls.to_string())?;
        self.field("received_response_count", &s.received_responses.to_string())?;
        self.field("event_count", &self.events.to_string())?;
        self.field("result", s.outcome.as_str())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn ceiling_and_line_grammar_fail_before_extra_output() {
        let mut t = InterruptionTranscript::new(Vec::new());
        for _ in 0..4 {
            t.line(&[b'x'; 8191]).unwrap();
        }
        assert_eq!(t.bytes_written(), 32768);
        assert_eq!(
            t.line(b""),
            Err(SittingError::SittingTranscriptTooLarge.into())
        );
        assert_eq!(t.into_inner().len(), 32768);
        let mut t = InterruptionTranscript::new(Vec::new());
        for (name, value) in [
            ("x", "\n"),
            ("x", "\r"),
            ("x", "\u{00e9}"),
            ("", "x"),
            ("bad=name", "x"),
        ] {
            assert_eq!(
                t.field(name, value),
                Err(SittingError::SittingSequenceViolation.into())
            );
        }
        assert!(t.into_inner().is_empty());
    }
}
