//! Bounded, incrementally flushed private B6 observation transcript.

use std::io::Write;
use std::panic::{catch_unwind, AssertUnwindSafe};

use crate::{
    b6::{
        B6Error, B6Exchange, B6Metadata, B6Observer, B6Outcome, B6SignatureFacts, B6_MODE,
        B6_PLAN_SHA256, B6_PLAN_VERSION, B6_SESSION_COUNT, B6_TOOL_VERSION, B6_TRANSCRIPT_LIMIT_ID,
        B6_TRANSCRIPT_VERSION, MAX_B6_TRANSCRIPT_BYTES,
    },
    NegotiatedProtocol, CANONICAL_CAP_BYTES, CANONICAL_CAP_SHA256, GOLDEN_FIXTURE_BLOB,
    GOLDEN_FIXTURE_BYTES, GOLDEN_FIXTURE_LF, GOLDEN_FIXTURE_PATH, GOLDEN_FIXTURE_SHA256,
    MAX_ATR_BYTES, MAX_READERS, MAX_READER_LIST_BYTES, MAX_READER_NAME_BYTES,
    MAX_SITTING_CAPTURE_BYTES, SITTING_APPLET_SOURCE_COMMIT, SITTING_CAMPAIGN_SOURCE_COMMIT,
};

pub struct B6Transcript<W: Write> {
    writer: W,
    bytes_written: usize,
    event_count: usize,
    signature_count: usize,
    normalization_changed_count: usize,
    signature_exchange: Option<usize>,
    terminal_error: Option<B6Error>,
}

impl<W: Write> B6Transcript<W> {
    pub const fn new(writer: W) -> Self {
        Self {
            writer,
            bytes_written: 0,
            event_count: 0,
            signature_count: 0,
            normalization_changed_count: 0,
            signature_exchange: None,
            terminal_error: None,
        }
    }

    pub const fn bytes_written(&self) -> usize {
        self.bytes_written
    }

    pub fn into_inner(self) -> W {
        self.writer
    }

    pub fn write_header(&mut self, metadata: &B6Metadata) -> Result<(), B6Error> {
        let enrollment = metadata.enrollment().inner();
        let output_basename = metadata
            .output_path()
            .file_name()
            .and_then(|name| name.to_str())
            .ok_or(B6Error::B6OutputPathRejected)?;
        self.write_line(B6_TRANSCRIPT_VERSION)?;
        self.write_field("plan_version", B6_PLAN_VERSION)?;
        self.write_field("plan_sha256", B6_PLAN_SHA256)?;
        self.write_field("tool_version", B6_TOOL_VERSION)?;
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
        self.write_field("transcript_limit_id", B6_TRANSCRIPT_LIMIT_ID)?;
        self.write_field(
            "transcript_limit_bytes",
            &MAX_B6_TRANSCRIPT_BYTES.to_string(),
        )?;
        self.write_field("visibility", "PRIVATE_CUSTODY_ONLY")?;
        self.write_field("timestamp_utc", &enrollment.timestamp_utc)?;
        self.write_field("host_alias", &enrollment.host_alias)?;
        self.write_field("reader_alias", &enrollment.reader_alias)?;
        self.write_field(
            "specimen_alias",
            enrollment.specimen_alias.as_deref().unwrap_or("NONE"),
        )?;
        self.write_field("mode", B6_MODE)?;
        self.write_field(
            "selected_reader_name_hex",
            &hex(enrollment
                .selected_reader_name
                .as_deref()
                .unwrap_or_default()),
        )?;
        self.write_field("output_basename", output_basename)
    }

    pub fn record_readers(&mut self, readers: &[Vec<u8>]) -> Result<(), B6Error> {
        if readers.len() > MAX_READERS {
            return Err(self.fail(B6Error::B6ReaderCountExceeded));
        }
        let mut list_bytes = 1usize;
        for reader in readers {
            if reader.is_empty() || reader.len() > MAX_READER_NAME_BYTES || reader.contains(&0) {
                return Err(self.fail(B6Error::B6ReaderNameRejected));
            }
            list_bytes = list_bytes
                .checked_add(reader.len())
                .and_then(|size| size.checked_add(1))
                .ok_or_else(|| self.fail(B6Error::B6ReaderListTooLarge))?;
            if list_bytes > MAX_READER_LIST_BYTES {
                return Err(self.fail(B6Error::B6ReaderListTooLarge));
            }
        }
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
    ) -> Result<(), B6Error> {
        if atr.len() > MAX_ATR_BYTES {
            return Err(self.fail(B6Error::B6AtrRejected));
        }
        self.write_field("atr_hex", &hex(atr))?;
        self.write_field(
            "protocol",
            protocol.map(NegotiatedProtocol::as_str).unwrap_or("NONE"),
        )
    }

    pub fn record_event(&mut self, operation: &str, outcome: B6Outcome) -> Result<(), B6Error> {
        if !valid_label(operation) {
            return Err(self.fail(B6Error::B6SequenceViolation));
        }
        let index = self.event_count.to_string();
        let line_len = "event."
            .len()
            .checked_add(index.len())
            .and_then(|size| size.checked_add(1))
            .and_then(|size| size.checked_add(operation.len()))
            .and_then(|size| size.checked_add(1))
            .and_then(|size| size.checked_add(outcome.as_str().len()))
            .ok_or_else(|| self.fail(B6Error::B6TranscriptTooLarge))?;
        self.check_line_size(line_len)?;
        let next_count = self
            .event_count
            .checked_add(1)
            .ok_or_else(|| self.fail(B6Error::B6TranscriptTooLarge))?;
        self.write_line(&format!(
            "event.{}={}:{}",
            self.event_count,
            operation,
            outcome.as_str()
        ))?;
        self.event_count = next_count;
        Ok(())
    }

    pub fn record_counts(
        &mut self,
        transmit_calls: usize,
        received_responses: usize,
    ) -> Result<(), B6Error> {
        self.write_field("transmit_call_count", &transmit_calls.to_string())?;
        self.write_field("received_response_count", &received_responses.to_string())
    }

    pub fn record_disconnect(&mut self, outcome: B6Outcome) -> Result<(), B6Error> {
        self.record_event("Disconnect", outcome)?;
        self.write_field("disconnect", outcome.as_str())
    }

    pub fn record_disconnect_none(&mut self) -> Result<(), B6Error> {
        self.write_field("disconnect", "NONE")
    }

    pub fn record_result(&mut self, outcome: B6Outcome) -> Result<(), B6Error> {
        self.write_field("signature_fact_count", &self.signature_count.to_string())?;
        self.write_field(
            "normalization_changed_count",
            &self.normalization_changed_count.to_string(),
        )?;
        self.write_field("event_count", &self.event_count.to_string())?;
        self.write_field("result", outcome.as_str())
    }

    fn write_field(&mut self, name: &str, value: &str) -> Result<(), B6Error> {
        if !valid_label(name) || !valid_text(value) {
            return Err(self.fail(B6Error::B6SequenceViolation));
        }
        let len = name
            .len()
            .checked_add(1)
            .and_then(|size| size.checked_add(value.len()))
            .ok_or_else(|| self.fail(B6Error::B6TranscriptTooLarge))?;
        self.check_line_size(len)?;
        self.write_line(&format!("{name}={value}"))
    }

    fn check_line_size(&mut self, len: usize) -> Result<usize, B6Error> {
        if let Some(error) = self.terminal_error {
            return Err(error);
        }
        let next = len
            .checked_add(1)
            .and_then(|size| self.bytes_written.checked_add(size))
            .ok_or_else(|| self.fail(B6Error::B6TranscriptTooLarge))?;
        if next > MAX_B6_TRANSCRIPT_BYTES {
            return Err(self.fail(B6Error::B6TranscriptTooLarge));
        }
        Ok(next)
    }

    fn write_line(&mut self, line: &str) -> Result<(), B6Error> {
        if !valid_text(line) {
            return Err(self.fail(B6Error::B6SequenceViolation));
        }
        let next = self.check_line_size(line.len())?;
        match catch_unwind(AssertUnwindSafe(|| {
            self.writer
                .write_all(line.as_bytes())
                .and_then(|()| self.writer.write_all(b"\n"))
        })) {
            Ok(Ok(())) => {}
            Ok(Err(_)) => return Err(self.fail(B6Error::B6OutputWriteFailed)),
            Err(_) => return Err(self.fail(B6Error::B6BoundaryPanicked)),
        }
        self.bytes_written = next;
        match catch_unwind(AssertUnwindSafe(|| self.writer.flush())) {
            Ok(Ok(())) => Ok(()),
            Ok(Err(_)) => Err(self.fail(B6Error::B6OutputFlushFailed)),
            Err(_) => Err(self.fail(B6Error::B6BoundaryPanicked)),
        }
    }

    fn fail(&mut self, error: B6Error) -> B6Error {
        *self.terminal_error.get_or_insert(error)
    }
}

impl<W: Write> B6Observer for B6Transcript<W> {
    fn session_start(&mut self, session: usize, utc: &str) -> Result<(), B6Error> {
        if session >= B6_SESSION_COUNT || !valid_utc(utc) {
            return Err(self.fail(B6Error::B6SequenceViolation));
        }
        self.write_field(&format!("session.{session}.start_utc"), utc)
    }

    fn session_end(
        &mut self,
        session: usize,
        utc: &str,
        outcome: B6Outcome,
    ) -> Result<(), B6Error> {
        if session >= B6_SESSION_COUNT || !valid_utc(utc) {
            return Err(self.fail(B6Error::B6SequenceViolation));
        }
        self.write_field(&format!("session.{session}.end_utc"), utc)?;
        self.write_field(&format!("session.{session}.result"), outcome.as_str())
    }

    fn record_request(&mut self, exchange: &B6Exchange) -> Result<(), B6Error> {
        self.signature_exchange = None;
        self.write_field(
            &format!("apdu.{}.session", exchange.index()),
            &exchange.session_index().to_string(),
        )?;
        self.write_field(
            &format!("apdu.{}.position", exchange.index()),
            &exchange.position().to_string(),
        )?;
        self.write_field(&format!("apdu.{}.name", exchange.index()), exchange.name())?;
        self.write_field(
            &format!("apdu.{}.tx_hex", exchange.index()),
            &hex(exchange.request()),
        )
    }

    fn record_response(&mut self, exchange: &B6Exchange, response: &[u8]) -> Result<(), B6Error> {
        if response.len() > MAX_SITTING_CAPTURE_BYTES {
            return Err(self.fail(B6Error::B6ResponseCaptureExceeded));
        }
        self.write_field(&format!("apdu.{}.rx_hex", exchange.index()), &hex(response))
    }

    fn record_comparison(
        &mut self,
        exchange: &B6Exchange,
        outcome: B6Outcome,
    ) -> Result<(), B6Error> {
        if exchange.input_index().is_some() && self.signature_exchange != Some(exchange.index()) {
            self.write_field(
                &format!("apdu.{}.normalized", exchange.index()),
                "NOT_EVALUATED",
            )?;
            self.write_field(&format!("apdu.{}.r_hex", exchange.index()), "NONE")?;
            self.write_field(
                &format!("apdu.{}.verify", exchange.index()),
                "NOT_EVALUATED",
            )?;
        }
        self.write_field(
            &format!("apdu.{}.comparison", exchange.index()),
            outcome.as_str(),
        )?;
        self.record_event(&format!("Exchange/{}", exchange.name()), outcome)
    }

    fn record_signature(
        &mut self,
        exchange: &B6Exchange,
        facts: B6SignatureFacts,
    ) -> Result<(), B6Error> {
        if exchange.input_index().is_none() {
            return Err(self.fail(B6Error::B6SequenceViolation));
        }
        let next_signature_count = self
            .signature_count
            .checked_add(1)
            .ok_or_else(|| self.fail(B6Error::B6TranscriptTooLarge))?;
        let next_changed_count = self
            .normalization_changed_count
            .checked_add(usize::from(facts.normalized))
            .ok_or_else(|| self.fail(B6Error::B6TranscriptTooLarge))?;
        self.write_field(
            &format!("apdu.{}.normalized", exchange.index()),
            if facts.normalized { "true" } else { "false" },
        )?;
        self.write_field(&format!("apdu.{}.r_hex", exchange.index()), &hex(&facts.r))?;
        self.write_field(
            &format!("apdu.{}.verify", exchange.index()),
            if facts.verified { "PASS" } else { "FAIL" },
        )?;
        self.signature_count = next_signature_count;
        self.normalization_changed_count = next_changed_count;
        self.signature_exchange = Some(exchange.index());
        Ok(())
    }
}

fn valid_label(value: &str) -> bool {
    !value.is_empty()
        && value.bytes().all(|byte| {
            byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-' | b'/' | b':')
        })
}

fn valid_text(value: &str) -> bool {
    value.is_ascii() && !value.bytes().any(|byte| byte.is_ascii_control())
}

fn valid_utc(value: &str) -> bool {
    value.len() == 20
        && value.bytes().enumerate().all(|(index, byte)| match index {
            4 | 7 => byte == b'-',
            10 => byte == b'T',
            13 | 16 => byte == b':',
            19 => byte == b'Z',
            _ => byte.is_ascii_digit(),
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn exact_ceiling_accepts_last_byte_then_fails_without_any_extra_output() {
        let mut transcript = B6Transcript::new(Vec::new());
        let line = "x".repeat(MAX_B6_TRANSCRIPT_BYTES - 1);
        transcript.write_line(&line).expect("exact ceiling");
        assert_eq!(transcript.bytes_written(), MAX_B6_TRANSCRIPT_BYTES);
        assert_eq!(
            transcript.write_line(""),
            Err(B6Error::B6TranscriptTooLarge)
        );
        assert_eq!(
            transcript.record_result(B6Outcome::Pass),
            Err(B6Error::B6TranscriptTooLarge)
        );
        assert_eq!(transcript.into_inner().len(), MAX_B6_TRANSCRIPT_BYTES);
    }

    #[test]
    fn exceeding_by_one_is_rejected_before_any_write() {
        let mut transcript = B6Transcript::new(Vec::new());
        assert_eq!(
            transcript.write_line(&"x".repeat(MAX_B6_TRANSCRIPT_BYTES)),
            Err(B6Error::B6TranscriptTooLarge)
        );
        assert!(transcript.into_inner().is_empty());
    }
}
