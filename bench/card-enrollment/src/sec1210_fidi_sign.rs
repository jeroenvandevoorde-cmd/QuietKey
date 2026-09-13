//! Fixed public B6 session 0 over reusable bounded raw-response transports.
use std::io::Write;
use std::panic::{catch_unwind, AssertUnwindSafe};
use std::path::{Path, PathBuf};

use crate::{
    b6_exchange, sec1210_output_basename, B6Error, B6Exchange, Sec1210Error,
    Sec1210FidiSignTranscript, Sec1210Metadata, Sec1210Transport, B6_DIGEST,
    B6_EXCHANGES_PER_SESSION, B6_PUBLIC_KEY, B6_SIGNATURES_PER_SESSION,
};
use qk_sec1210_wire::{RawCommand, RawFrameSpan, RawObservation, RawPhase, RawRequest};

pub const SEC1210_FIDI_SIGN_TOOL_VERSION: &str = "0.0.13";
pub const FIDI_SIGN_PLAN_BYTES: usize = 13_236;
pub const FIDI_SIGN_PLAN_SHA256: &str =
    "ad0ffd7e79ebb8500a4f94a5f06aa527ec59537a59923956170f45cfdbdf3659";
pub const FIDI_SIGN_LIMITS: [(&str, &str); 15] = [
    ("QK-LIM-T1-FIDI-SIGN-COMMAND-INF-V1", "254"),
    ("QK-LIM-T1-FIDI-SIGN-RESPONSE-INF-V1", "254"),
    ("QK-LIM-T1-FIDI-SIGN-BLOCK-V1", "258"),
    ("QK-LIM-T1-FIDI-SIGN-APDUS-V1", "128"),
    ("QK-LIM-T1-FIDI-SIGN-EXCHANGES-V1", "16"),
    ("QK-LIM-T1-FIDI-SIGN-COMMANDS-V1", "512"),
    ("QK-LIM-T1-FIDI-SIGN-RESPONSE-MS-V1", "5000"),
    ("QK-LIM-T1-FIDI-SIGN-BWT-MS-V1", "1190"),
    ("QK-LIM-T1-FIDI-SIGN-APDU-MS-V1", "30000"),
    ("QK-LIM-T1-FIDI-SIGN-WTX-MULTIPLIER-V1", "1..24"),
    ("QK-LIM-T1-FIDI-SIGN-WTX-COUNT-V1", "8"),
    ("QK-LIM-T1-FIDI-SIGN-TIME-EXTENSIONS-V1", "8"),
    ("QK-LIM-T1-FIDI-SIGN-EVENTS-V1", "64"),
    ("QK-LIM-T1-FIDI-SIGN-RX-V1", "32768"),
    ("QK-LIM-BENCH-T1-FIDI-SIGN-TRANSCRIPT-V1", "1048576"),
];

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Sec1210FidiSignError {
    Native(Sec1210Error),
    Wire(qk_sec1210_wire::RawError),
    T1(qk_t1::RawError),
    B6(B6Error),
    PlanRejected,
    ResponseMissing,
    TranscriptLimit,
    TranscriptIo,
    TimingEvidenceRejected,
}
impl Sec1210FidiSignError {
    pub fn name(self) -> &'static str {
        match self {
            Self::Native(e) => e.name(),
            Self::Wire(e) => e.name(),
            Self::T1(e) => e.name(),
            Self::B6(e) => e.name(),
            Self::PlanRejected => "Sec1210FidiSignPlanRejected",
            Self::ResponseMissing => "Sec1210FidiSignResponseMissing",
            Self::TranscriptLimit => "Sec1210FidiSignTranscriptLimit",
            Self::TranscriptIo => "Sec1210FidiSignTranscriptIo",
            Self::TimingEvidenceRejected => "Sec1210FidiSignTimingEvidenceRejected",
        }
    }
}
impl From<Sec1210Error> for Sec1210FidiSignError {
    fn from(e: Sec1210Error) -> Self {
        Self::Native(e)
    }
}
impl From<qk_sec1210_wire::RawError> for Sec1210FidiSignError {
    fn from(e: qk_sec1210_wire::RawError) -> Self {
        Self::Wire(e)
    }
}
impl From<qk_t1::RawError> for Sec1210FidiSignError {
    fn from(e: qk_t1::RawError) -> Self {
        Self::T1(e)
    }
}
impl From<B6Error> for Sec1210FidiSignError {
    fn from(e: B6Error) -> Self {
        Self::B6(e)
    }
}

/// Mock evidence and the private adapter use the same explicit clock/read API.
/// The old transport read method is not used by this mode.
pub trait Sec1210FidiSignTransport: Sec1210Transport {
    fn now_ms(&mut self) -> u64;
    fn utc_now(&mut self) -> Result<String, Sec1210FidiSignError>;
    fn read_until(
        &mut self,
        buffer: &mut [u8],
        deadline_ms: u64,
    ) -> Result<(usize, u64), Sec1210Error>;
}

#[derive(Clone, Debug)]
pub struct Sec1210FidiSignMetadata {
    binding: Sec1210Metadata,
    output: PathBuf,
}
impl Sec1210FidiSignMetadata {
    pub fn new(
        source: String,
        utc: String,
        host: &str,
        specimen: &str,
        output: PathBuf,
    ) -> Result<Self, Sec1210FidiSignError> {
        if output.as_os_str().len() > 4096
            || output.file_name().and_then(|n| n.to_str())
                != Some(sec1210_fidi_sign_output_basename(&utc).as_str())
        {
            return Err(Sec1210Error::OutputRejected.into());
        }
        let parent = output.parent().ok_or(Sec1210Error::OutputRejected)?;
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
pub fn sec1210_fidi_sign_output_basename(utc: &str) -> String {
    format!("qk-card-sitting-v1__sec1210-fidi-sign__J3R180-03__{utc}.txt")
}

fn checked_session_utc(
    metadata: &Sec1210FidiSignMetadata,
    utc: String,
) -> Result<String, Sec1210FidiSignError> {
    // Reuse the registered calendar grammar without widening its visibility.
    Sec1210Metadata::new(
        metadata.source().into(),
        utc.clone(),
        "RIG-HOST-PI3B-01",
        "J3R180-03",
        metadata
            .output()
            .parent()
            .expect("validated output")
            .join(sec1210_output_basename(&utc)),
    )
    .map_err(|_| B6Error::B6ClockFailed)?;
    Ok(utc)
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Sec1210FidiSignSummary {
    pub request_count: usize,
    pub response_count: usize,
    pub event_count: usize,
    pub captured_rx_bytes: usize,
    pub read_fragment_count: usize,
    pub apdu_transmit_count: usize,
    pub apdu_response_count: usize,
    pub apdu_accepted_count: usize,
    pub signature_fact_count: usize,
    pub signature_accepted_count: usize,
    pub normalization_changed_count: usize,
    pub completed_sessions: usize,
    pub wtx_count: usize,
    pub time_extension_count: usize,
    pub set_parameters_accepted: bool,
    pub ifs_accepted: bool,
    pub local_handle_released: bool,
    pub session_start_utc: Option<String>,
    pub session_end_utc: Option<String>,
    pub failure: Option<Sec1210FidiSignError>,
}

#[derive(Clone, Copy)]
struct FragmentClock {
    start: usize,
    end: usize,
    elapsed: u64,
    monotonic: u64,
}
#[derive(Clone, Copy)]
struct FrameClock {
    first_bytes_ms: u64,
    complete_ms: u64,
    first_monotonic_ms: u64,
    complete_monotonic_ms: u64,
}

struct Engine<'a, T, W: Write, V> {
    transport: &'a mut T,
    transcript: &'a mut Sec1210FidiSignTranscript<W>,
    verify: V,
    wire: qk_sec1210_wire::RawSession,
    t1: qk_t1::RawSession,
    read_index: usize,
    observation_index: usize,
    captured: usize,
    fragment_clocks: Vec<FragmentClock>,
    command_deadline: Option<u64>,
    apdu_first_write: Option<u64>,
    apdu_transmits: usize,
    apdu_accepted: usize,
    signature_facts: usize,
    signatures: usize,
    normalized: usize,
    seen: [[u8; 32]; B6_SIGNATURES_PER_SESSION],
    session_start: Option<String>,
    session_end: Option<String>,
    completed_sessions: usize,
    first_failure: Option<Sec1210FidiSignError>,
}
impl<T: Sec1210FidiSignTransport, W: Write, V> Engine<'_, T, W, V>
where
    V: FnMut(&qk_secp::Signature, &[u8; 32], &qk_secp::PublicKey) -> Result<(), B6Error>,
{
    fn latch<R>(
        &mut self,
        result: Result<R, Sec1210FidiSignError>,
    ) -> Result<R, Sec1210FidiSignError> {
        result.map_err(|error| *self.first_failure.get_or_insert(error))
    }
    fn clocks(&mut self) -> Result<u64, Sec1210FidiSignError> {
        if let Some(error) = self.first_failure {
            return Err(error);
        }
        let now = self.transport.now_ms();
        // Wire tick gives the original APDU deadline precedence over command
        // and partial-frame deadlines, even after a complete response arrives.
        let checked = self.wire.tick(now).map_err(Into::into);
        self.latch(checked)?;
        // Keep the command cap through its evidence work after pure acceptance.
        if self
            .command_deadline
            .is_some_and(|deadline| now >= deadline)
        {
            return self.latch(Err(qk_sec1210_wire::RawError::Wire(
                qk_sec1210_wire::Error::DeadlineExceeded,
            )
            .into()));
        }
        let checked = self.t1.tick(now).map_err(Into::into);
        self.latch(checked)?;
        Ok(now)
    }
    fn frame_clock(&self, span: RawFrameSpan) -> Result<FrameClock, Sec1210FidiSignError> {
        if span.start_rx_offset >= span.end_rx_offset {
            return Err(Sec1210FidiSignError::TimingEvidenceRejected);
        }
        let find = |offset| {
            self.fragment_clocks
                .iter()
                .find(|r| r.start <= offset && offset < r.end)
        };
        let first =
            find(span.start_rx_offset).ok_or(Sec1210FidiSignError::TimingEvidenceRejected)?;
        let last =
            find(span.end_rx_offset - 1).ok_or(Sec1210FidiSignError::TimingEvidenceRejected)?;
        Ok(FrameClock {
            first_bytes_ms: first.elapsed,
            complete_ms: last.elapsed,
            first_monotonic_ms: first.monotonic,
            complete_monotonic_ms: last.monotonic,
        })
    }
    fn record_frame(
        &mut self,
        prefix: &str,
        span: RawFrameSpan,
    ) -> Result<FrameClock, Sec1210FidiSignError> {
        let clock = self.frame_clock(span)?;
        for (name, value) in [
            ("start_rx_offset", span.start_rx_offset as u64),
            ("end_rx_offset", span.end_rx_offset as u64),
            ("first_response_bytes_ms", clock.first_bytes_ms),
            ("frame_complete_ms", clock.complete_ms),
            ("first_response_monotonic_ms", clock.first_monotonic_ms),
            ("frame_complete_monotonic_ms", clock.complete_monotonic_ms),
        ] {
            self.transcript
                .field(&format!("{prefix}.{name}"), &value.to_string())?;
        }
        Ok(clock)
    }
    fn exchange(
        &mut self,
        request: RawRequest,
        t1_length: Option<usize>,
        first_apdu_block: bool,
    ) -> Result<FrameClock, Sec1210FidiSignError> {
        self.fragment_clocks.clear();
        self.command_deadline = Some(request.deadline_ms());
        let ordinal = request.ordinal();
        let prefix = format!("command.{ordinal}");
        for (name, value) in [
            ("sequence", u64::from(request.sequence())),
            ("bBWI", u64::from(request.bwi())),
            ("host_allowance_ms", request.host_allowance_ms()),
            ("deadline_ms", request.deadline_ms()),
        ] {
            self.transcript
                .field(&format!("{prefix}.{name}"), &value.to_string())?;
        }
        self.transcript.field(
            &format!("{prefix}.apdu_deadline_ms"),
            &request
                .apdu_deadline_ms()
                .map(|n| n.to_string())
                .unwrap_or_else(|| "NONE".into()),
        )?;
        self.transcript
            .hex(&format!("{prefix}.request_hex"), request.as_bytes())?;
        self.clocks()?;
        if first_apdu_block {
            self.apdu_transmits += 1;
        }
        let write = self.transport.write_once(request.as_bytes());
        let written_at = self.transport.now_ms();
        if first_apdu_block {
            self.apdu_first_write = Some(written_at);
        }
        let accepted = write
            .map_err(Sec1210FidiSignError::from)
            .and_then(|n| self.wire.written(n, written_at).map_err(Into::into))
            .and_then(|_| match t1_length {
                Some(n) => self.t1.written(n, written_at).map_err(Into::into),
                None => Ok(()),
            });
        if let Err(error) = accepted {
            self.first_failure.get_or_insert(error);
        }
        self.transcript.field(
            &format!("{prefix}.write_bytes"),
            &match write {
                Ok(n) => n.to_string(),
                Err(e) => e.name().into(),
            },
        )?;
        self.transcript.field(
            &format!("{prefix}.write_monotonic_ms"),
            &written_at.to_string(),
        )?;
        accepted?;
        self.clocks()?;
        self.transcript
            .field(&format!("{prefix}.post_send_pause_ms"), "10")?;
        self.transport.pause_after_write()?;
        let set_parameters = request.command() == RawCommand::SetParameters;
        let mut first_response_recorded = false;
        while matches!(self.wire.phase(), RawPhase::Receiving(_)) {
            self.clocks()?;
            let mut buffer = [0u8; qk_sec1210_wire::MAX_WIRE_BYTES];
            let (length, elapsed) = self
                .transport
                .read_until(&mut buffer, request.deadline_ms())?;
            let now = self.transport.now_ms();
            if length > buffer.len() {
                return Err(Sec1210Error::ReadLengthRejected.into());
            }
            let retained = length.min(qk_sec1210_wire::RAW_MAX_RECEIVED_BYTES - self.captured);
            if retained != length {
                self.first_failure.get_or_insert(
                    qk_sec1210_wire::RawError::Wire(qk_sec1210_wire::Error::ReceiveLimitExceeded)
                        .into(),
                );
            }
            let start = self.captured;
            self.transcript.field(
                &format!("read.{}.command_ordinal", self.read_index),
                &ordinal.to_string(),
            )?;
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
            if retained > 0 {
                // At most RX-cap entries: each retained interval consumes at
                // least one byte. Zero-length records never grow this vector.
                self.fragment_clocks.push(FragmentClock {
                    start,
                    end: self.captured,
                    elapsed,
                    monotonic: now,
                });
            }
            if retained != length {
                self.transcript.field("capture_overflow", "TRUE")?;
                self.transcript
                    .field("capture_omitted_bytes", &(length - retained).to_string())?;
                return Err(*self
                    .first_failure
                    .as_ref()
                    .expect("capture failure latched"));
            }
            let validation_ms = self.transport.now_ms();
            let result = self.wire.receive(&buffer[..length], validation_ms);
            if let Err(error) = result {
                self.first_failure.get_or_insert(error.into());
            }
            self.transcript.field(
                &format!("read.{}.validation_ms", self.read_index),
                &validation_ms.to_string(),
            )?;
            if set_parameters {
                if let Some(reply) = self.wire.set_parameters_reply_evidence() {
                    self.transcript.set_parameters_reply(reply)?;
                }
            }
            while self.observation_index < self.wire.observations().len() {
                let observation = self.wire.observations()[self.observation_index].clone();
                self.transcript.observation(
                    self.observation_index,
                    &observation,
                    set_parameters,
                )?;
                if let RawObservation::TimeExtension {
                    apdu_count, span, ..
                } = observation
                {
                    self.record_frame(&format!("{prefix}.time_extension.{apdu_count}"), span)?;
                    if !first_response_recorded {
                        self.record_frame(&format!("{prefix}.first_reply"), span)?;
                        first_response_recorded = true;
                    }
                }
                self.observation_index += 1;
            }
            self.transcript.field(
                &format!("read.{}.comparison", self.read_index),
                result.as_ref().map(|_| "PASS").unwrap_or_else(|e| e.name()),
            )?;
            self.read_index += 1;
            result?;
            self.clocks()?;
        }
        let span = self
            .wire
            .last_reply_span()
            .ok_or(Sec1210FidiSignError::ResponseMissing)?;
        if !first_response_recorded {
            self.record_frame(&format!("{prefix}.first_reply"), span)?;
        }
        self.record_frame(&format!("{prefix}.final_reply"), span)
    }
    fn finish_command(&mut self) -> Result<(), Sec1210FidiSignError> {
        self.clocks()?;
        self.command_deadline = None;
        Ok(())
    }
    fn initialize(&mut self) -> Result<(), Sec1210FidiSignError> {
        while self.wire.phase() != RawPhase::ReadyIfs {
            let now = self.clocks()?;
            let request = self.wire.begin_initial(now)?;
            let setting = request.command() == RawCommand::SetParameters;
            if setting {
                self.transcript.hex(
                    "set_parameters.request_hex",
                    &qk_sec1210_wire::FIDI_PARAMETERS,
                )?;
            }
            let result = self.exchange(request, None, false);
            if let Err(error) = result {
                self.first_failure.get_or_insert(error);
            }
            if setting {
                self.transcript.field(
                    "set_parameters.comparison",
                    result.as_ref().map(|_| "PASS").unwrap_or_else(|e| e.name()),
                )?;
            }
            result?;
            self.finish_command()?;
        }
        let now = self.clocks()?;
        self.t1.begin_ifs(now)?;
        for (name, value) in [
            ("receive_bound_before", self.t1.receive_bound()),
            ("send_sequence_before", usize::from(self.t1.send_sequence())),
            (
                "receive_sequence_before",
                usize::from(self.t1.receive_sequence()),
            ),
        ] {
            self.transcript
                .field(&format!("ifs.{name}"), &value.to_string())?;
        }
        let now = self.clocks()?;
        let block = self.t1.next_block(now)?;
        self.transcript.hex("ifs.request_hex", block.as_bytes())?;
        let now = self.clocks()?;
        let request = self.wire.begin_ifs_transfer(block.as_bytes(), now)?;
        self.exchange(request, Some(block.as_bytes().len()), false)?;
        let payload = self
            .wire
            .response()
            .ok_or(Sec1210FidiSignError::ResponseMissing)?
            .payload()
            .to_vec();
        self.transcript.hex("ifs.response_hex", &payload)?;
        let checked = self.t1.receive(&payload, self.transport.now_ms());
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
        for (name, value) in [
            ("receive_bound_after", self.t1.receive_bound()),
            ("send_sequence_after", usize::from(self.t1.send_sequence())),
            (
                "receive_sequence_after",
                usize::from(self.t1.receive_sequence()),
            ),
        ] {
            self.transcript
                .field(&format!("ifs.{name}"), &value.to_string())?;
        }
        checked?;
        let now = self.clocks()?;
        self.wire.accept_ifs(now)?;
        self.finish_command()
    }
    fn validate_application(
        &mut self,
        exchange: &B6Exchange,
        response: &[u8],
    ) -> Result<(), Sec1210FidiSignError> {
        let Some(der) = crate::b6::validate_response(exchange, response)? else {
            return Ok(());
        };
        let mut normalized = [0u8; 72];
        let length = qk_secp::normalize_card_signature_der(der, &mut normalized)
            .map_err(|_| B6Error::B6DerRejected)?;
        let normalized = &normalized[..length];
        let r = crate::b6::strict_der_r(normalized)?;
        let parsed =
            qk_secp::signature_parse_der(normalized).map_err(|_| B6Error::B6DerRejected)?;
        let key = qk_secp::pubkey_parse_compressed(&B6_PUBLIC_KEY)
            .map_err(|_| B6Error::B6SignatureVerificationFailed)?;
        let verified = (self.verify)(&parsed, &B6_DIGEST, &key);
        if let Err(error) = verified {
            self.first_failure.get_or_insert(error.into());
        }
        let prefix = format!("apdu.{}", exchange.position());
        let changed = der != normalized;
        self.transcript.field(
            &format!("{prefix}.normalization_changed"),
            if changed { "TRUE" } else { "FALSE" },
        )?;
        self.transcript.hex(&format!("{prefix}.r_hex"), &r)?;
        self.transcript.field(
            &format!("{prefix}.verify"),
            if verified.is_ok() {
                "PASS"
            } else {
                "B6SignatureVerificationFailed"
            },
        )?;
        self.signature_facts += 1;
        self.normalized += usize::from(changed);
        verified?;
        if self.seen[..self.signatures].contains(&r) {
            return Err(B6Error::B6RepeatedR.into());
        }
        self.seen[self.signatures] = r;
        self.signatures += 1;
        Ok(())
    }
    fn application(&mut self, exchange: &B6Exchange) -> Result<(), Sec1210FidiSignError> {
        let position = exchange.position();
        let prefix = format!("apdu.{position}");
        let now = self.clocks()?;
        self.t1.begin(exchange.request(), now)?;
        self.wire.begin_apdu(now)?;
        self.apdu_first_write = None;
        self.transcript
            .hex(&format!("{prefix}.tx_hex"), exchange.request())?;
        self.transcript
            .field(&format!("{prefix}.name"), exchange.name())?;
        self.transcript.field(
            &format!("{prefix}.input_index"),
            &exchange
                .input_index()
                .map(|v| v.to_string())
                .unwrap_or_else(|| "NONE".into()),
        )?;
        self.transcript.field(
            &format!("{prefix}.deadline_ms"),
            &self.t1.apdu_deadline_ms().expect("APDU active").to_string(),
        )?;
        let mut first = true;
        let final_clock = loop {
            let now = self.clocks()?;
            let block = self.t1.next_block(now)?;
            let ordinal = self.wire.ordinal() + 1;
            self.transcript
                .hex(&format!("t1.{ordinal}.tx_hex"), block.as_bytes())?;
            self.transcript.field(
                &format!("t1.{ordinal}.send_sequence"),
                &self.t1.send_sequence().to_string(),
            )?;
            self.transcript.field(
                &format!("t1.{ordinal}.receive_sequence"),
                &self.t1.receive_sequence().to_string(),
            )?;
            let now = self.clocks()?;
            let request = self
                .wire
                .begin_transfer(block.as_bytes(), block.bwi(), now)?;
            if block.bwi() != 0 {
                let wtx = self.t1.wtx_count();
                let w = format!("{prefix}.wtx.{wtx}");
                self.transcript
                    .hex(&format!("{w}.response_hex"), block.as_bytes())?;
                self.transcript
                    .field(&format!("{w}.bBWI"), &block.bwi().to_string())?;
                self.transcript.field(
                    &format!("{w}.host_allowance_ms"),
                    &request.host_allowance_ms().to_string(),
                )?;
                self.transcript.field(
                    &format!("{w}.effective_deadline_ms"),
                    &request.deadline_ms().to_string(),
                )?;
                self.transcript.field(
                    &format!("{w}.apdu_deadline_ms"),
                    &request.apdu_deadline_ms().expect("APDU active").to_string(),
                )?;
            }
            let clock = self.exchange(request, Some(block.as_bytes().len()), first)?;
            first = false;
            let payload = self
                .wire
                .response()
                .ok_or(Sec1210FidiSignError::ResponseMissing)?
                .payload()
                .to_vec();
            self.transcript
                .hex(&format!("t1.{ordinal}.rx_hex"), &payload)?;
            let checked = self.t1.receive(&payload, self.transport.now_ms());
            if let Err(error) = checked {
                self.first_failure.get_or_insert(error.into());
            }
            self.transcript.field(
                &format!("t1.{ordinal}.comparison"),
                checked
                    .as_ref()
                    .map(|_| "PASS")
                    .unwrap_or_else(|e| e.name()),
            )?;
            checked?;
            if self.t1.phase() == qk_t1::Phase::Complete {
                break clock;
            }
            let wtx = self.t1.wtx_count();
            let multiplier = *self
                .t1
                .wtx_multipliers()
                .last()
                .ok_or(Sec1210FidiSignError::ResponseMissing)?;
            self.transcript
                .hex(&format!("{prefix}.wtx.{wtx}.request_hex"), &payload)?;
            self.transcript.field(
                &format!("{prefix}.wtx.{wtx}.multiplier"),
                &multiplier.to_string(),
            )?;
            self.finish_command()?;
        };
        let response = self.t1.response().to_vec();
        self.transcript
            .hex(&format!("{prefix}.rx_hex"), &response)?;
        for (name, value) in [
            ("final_response_first_bytes_ms", final_clock.first_bytes_ms),
            ("final_response_frame_complete_ms", final_clock.complete_ms),
            (
                "final_response_first_monotonic_ms",
                final_clock.first_monotonic_ms,
            ),
            (
                "final_response_complete_monotonic_ms",
                final_clock.complete_monotonic_ms,
            ),
            ("wtx_count", self.t1.wtx_count() as u64),
            (
                "time_extension_count",
                self.wire.apdu_time_extension_count() as u64,
            ),
        ] {
            self.transcript
                .field(&format!("{prefix}.{name}"), &value.to_string())?;
        }
        let validated = self.validate_application(exchange, &response);
        if let Err(error) = validated {
            self.first_failure.get_or_insert(error);
        }
        self.transcript.field(
            &format!("{prefix}.comparison"),
            validated
                .as_ref()
                .map(|_| "PASS")
                .unwrap_or_else(|e| e.name()),
        )?;
        validated?;
        let now = self.clocks()?;
        let start = self
            .apdu_first_write
            .ok_or(Sec1210FidiSignError::TimingEvidenceRejected)?;
        self.transcript.field(
            &format!("{prefix}.first_write_monotonic_ms"),
            &start.to_string(),
        )?;
        self.transcript.field(
            &format!("{prefix}.elapsed_ms"),
            &now.saturating_sub(start).to_string(),
        )?;
        self.finish_command()?;
        // Do not clear the absolute APDU clock until verification and all
        // corresponding evidence have completed within the original budget.
        let now = self.clocks()?;
        self.wire.end_apdu(now)?;
        self.apdu_accepted += 1;
        Ok(())
    }
    fn run(&mut self, metadata: &Sec1210FidiSignMetadata) -> Result<(), Sec1210FidiSignError> {
        let mut plan_bytes = 0;
        for position in 0..B6_EXCHANGES_PER_SESSION {
            let exchange = b6_exchange(0, position)?;
            if exchange.request().len() > qk_t1::RAW_MAX_COMMAND_BYTES {
                return Err(Sec1210FidiSignError::PlanRejected);
            }
            plan_bytes += exchange.request().len();
        }
        if plan_bytes != FIDI_SIGN_PLAN_BYTES {
            return Err(Sec1210FidiSignError::PlanRejected);
        }
        self.transcript.header(metadata)?;
        let configured = self.transport.configure();
        let checked = match configured {
            Ok(0) => Ok(()),
            Ok(_) => Err(Sec1210Error::SttyFailed.into()),
            Err(e) => Err(e.into()),
        };
        if let Err(error) = checked {
            self.first_failure.get_or_insert(error);
        }
        self.transcript.field(
            "stty.exit",
            &match configured {
                Ok(n) => n.to_string(),
                Err(e) => e.name().into(),
            },
        )?;
        checked?;
        self.transport.open()?;
        self.transcript.field("stream.open", "PASS")?;
        self.initialize()?;
        let utc = checked_session_utc(metadata, self.transport.utc_now()?)?;
        self.session_start = Some(utc.clone());
        self.transcript.field("session.0.start_utc", &utc)?;
        for position in 0..B6_EXCHANGES_PER_SESSION {
            self.application(&b6_exchange(0, position)?)?;
        }
        if self.apdu_accepted != 102
            || self.signatures != 100
            || !self.t1.ifs_accepted()
            || !self.wire.set_parameters_accepted()
        {
            return Err(Sec1210FidiSignError::PlanRejected);
        }
        Ok(())
    }
}

/// Production always performs the real curve verification in the fixed order.
pub fn run_sec1210_fidi_sign<T: Sec1210FidiSignTransport, W: Write>(
    metadata: &Sec1210FidiSignMetadata,
    transport: &mut T,
    transcript: &mut Sec1210FidiSignTranscript<W>,
) -> Sec1210FidiSignSummary {
    run_inner(metadata, transport, transcript, |signature, digest, key| {
        qk_secp::ecdsa_verify(signature, digest, key)
            .map_err(|_| B6Error::B6SignatureVerificationFailed)
    })
}
fn run_inner<T: Sec1210FidiSignTransport, W: Write, V>(
    metadata: &Sec1210FidiSignMetadata,
    transport: &mut T,
    transcript: &mut Sec1210FidiSignTranscript<W>,
    verify: V,
) -> Sec1210FidiSignSummary
where
    V: FnMut(&qk_secp::Signature, &[u8; 32], &qk_secp::PublicKey) -> Result<(), B6Error>,
{
    let mut engine = Engine {
        transport,
        transcript,
        verify,
        wire: qk_sec1210_wire::RawSession::new(),
        t1: qk_t1::RawSession::default(),
        read_index: 0,
        observation_index: 0,
        captured: 0,
        fragment_clocks: Vec::new(),
        command_deadline: None,
        apdu_first_write: None,
        apdu_transmits: 0,
        apdu_accepted: 0,
        signature_facts: 0,
        signatures: 0,
        normalized: 0,
        seen: [[0; 32]; B6_SIGNATURES_PER_SESSION],
        session_start: None,
        session_end: None,
        completed_sessions: 0,
        first_failure: None,
    };
    let result = catch_unwind(AssertUnwindSafe(|| engine.run(metadata)))
        .unwrap_or(Err(Sec1210Error::BoundaryPanicked.into()));
    if let Err(error) = result {
        engine.first_failure.get_or_insert(error);
    }
    if engine.session_start.is_some() {
        let ending = catch_unwind(AssertUnwindSafe(|| {
            engine
                .transport
                .utc_now()
                .and_then(|utc| checked_session_utc(metadata, utc))
        }))
        .unwrap_or(Err(B6Error::B6ClockFailed.into()));
        match ending {
            Ok(utc) => {
                engine.session_end = Some(utc);
                if engine.first_failure.is_none() {
                    engine.completed_sessions = 1;
                }
            }
            Err(error) => {
                engine.first_failure.get_or_insert(error);
            }
        }
    }
    let mut summary = Sec1210FidiSignSummary {
        request_count: engine.wire.requests(),
        response_count: engine.wire.responses(),
        event_count: engine.wire.events(),
        captured_rx_bytes: engine.captured,
        read_fragment_count: engine.read_index,
        apdu_transmit_count: engine.apdu_transmits,
        apdu_response_count: engine.t1.completed_apdus(),
        apdu_accepted_count: engine.apdu_accepted,
        signature_fact_count: engine.signature_facts,
        signature_accepted_count: engine.signatures,
        normalization_changed_count: engine.normalized,
        completed_sessions: engine.completed_sessions,
        wtx_count: engine.t1.total_wtx_count(),
        time_extension_count: engine.wire.time_extension_count(),
        set_parameters_accepted: engine.wire.set_parameters_accepted(),
        ifs_accepted: engine.t1.ifs_accepted() && engine.wire.ifs_accepted(),
        local_handle_released: false,
        session_start_utc: engine.session_start,
        session_end_utc: engine.session_end,
        failure: engine.first_failure,
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
        Err(error) => {
            summary.failure.get_or_insert(error.into());
        }
    }
    if let Err(error) = catch_unwind(AssertUnwindSafe(|| engine.transcript.finish(&summary)))
        .unwrap_or(Err(Sec1210Error::BoundaryPanicked.into()))
    {
        summary.failure.get_or_insert(error);
    }
    summary
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::Cell;
    use std::collections::VecDeque;
    use std::rc::Rc;
    const UTC: &str = "2026-09-14T00:00:00Z";

    fn hex(bytes: &[u8]) -> String {
        use std::fmt::Write;
        let mut s = String::new();
        for byte in bytes {
            write!(&mut s, "{byte:02x}").unwrap();
        }
        s
    }
    fn decode(s: &str) -> Vec<u8> {
        s.as_bytes()
            .as_chunks::<2>()
            .0
            .iter()
            .map(|p| u8::from_str_radix(std::str::from_utf8(p).unwrap(), 16).unwrap())
            .collect()
    }
    fn block(pcb: u8, inf: &[u8]) -> Vec<u8> {
        let mut b = vec![0, pcb, inf.len() as u8];
        b.extend_from_slice(inf);
        b.push(b.iter().fold(0, |x, b| x ^ b));
        b
    }
    fn ccid(kind: u8, seq: u8, status: u8, error: u8, parameter: u8, payload: &[u8]) -> Vec<u8> {
        let mut b = vec![3, 6, kind];
        b.extend_from_slice(&(payload.len() as u32).to_le_bytes());
        b.extend_from_slice(&[0, seq, status, error, parameter]);
        b.extend_from_slice(payload);
        b.push(b.iter().fold(0, |x, b| x ^ b));
        b
    }
    fn synthetic(position: usize, repeated: bool) -> Vec<u8> {
        if position == 0 {
            return vec![0x90, 0];
        }
        let mut b = vec![1];
        b.extend_from_slice(&crate::B6_SESSION_IDS[0]);
        b.extend_from_slice(&((position - 1) as u32).to_be_bytes());
        if position > 1 {
            b.extend_from_slice(&crate::B6_REVIEW_HASH);
            b.extend_from_slice(&((position - 2) as u32).to_be_bytes());
            b.extend_from_slice(&B6_PUBLIC_KEY);
            // Distinct canonical r integers; only curve verification is mocked.
            let r = if repeated { 1 } else { (position - 1) as u8 };
            b.extend_from_slice(&[8, 0x30, 6, 2, 1, r, 2, 1, 1]);
        }
        b.extend_from_slice(&[0x90, 0]);
        b
    }
    #[derive(Clone, Default)]
    enum Scenario {
        #[default]
        Plain,
        Repeat(usize),
        Wtx(u8, usize, u64),
        Extension(usize, bool),
        ChangedExtension,
        BadClock,
        Partial,
        Extra,
        WriteFail,
    }
    struct Reader {
        scenario: Scenario,
        writes: Vec<Vec<u8>>,
        queue: VecDeque<(Vec<u8>, u64)>,
        now: Rc<Cell<u64>>,
        sent: u64,
        position: usize,
        pending: Option<(u8, Vec<u8>)>,
        wtx_left: usize,
        width: usize,
        opened: bool,
    }
    impl Reader {
        fn new(scenario: Scenario) -> Self {
            Self {
                scenario,
                writes: Vec::new(),
                queue: VecDeque::new(),
                now: Rc::new(Cell::new(0)),
                sent: 0,
                position: 0,
                pending: None,
                wtx_left: 0,
                width: 8,
                opened: false,
            }
        }
        fn queue(&mut self, bytes: Vec<u8>, delay: u64) {
            for (i, piece) in bytes.chunks(self.width).enumerate() {
                self.queue
                    .push_back((piece.to_vec(), if i == 0 { delay } else { 1 }));
            }
        }
        fn response(&mut self, request: &[u8]) {
            let seq = request[8];
            let ordinal = self.writes.len() + 1;
            assert_eq!(request.iter().fold(0, |x, b| x ^ b), 0);
            assert_eq!(seq, ordinal as u8);
            let reply = match ordinal {
                1 => ccid(0x81, seq, 1, 0, 1, &[]),
                2 => ccid(0x80, seq, 0, 0, 0, &qk_sec1210_wire::REGISTERED_ATR),
                3 => ccid(0x82, seq, 0, 0, 1, &decode("1110ff4d00fe00")),
                4 => ccid(0x82, seq, 0, 0, 1, &decode("1810ff4d00fe00")),
                5 => ccid(0x80, seq, 0, 0, 0, &block(0xe1, &[254])),
                _ => {
                    assert_eq!(request[2], 0x6f);
                    let tpdu = &request[12..request.len() - 1];
                    assert_eq!(tpdu.iter().fold(0, |x, b| x ^ b), 0);
                    if let Some((pcb, response)) = self.pending.clone() {
                        let Scenario::Wtx(multiplier, _, delay) = self.scenario else {
                            panic!("pending without WTX")
                        };
                        assert_eq!(tpdu, block(0xe3, &[multiplier]));
                        assert_eq!(request[9], multiplier);
                        if self.wtx_left > 0 {
                            self.wtx_left -= 1;
                            self.queue(
                                ccid(0x80, seq, 0, 0, 0, &block(0xc3, &[multiplier])),
                                delay,
                            );
                        } else {
                            self.pending = None;
                            self.queue(ccid(0x80, seq, 0, 0, 0, &block(pcb, &response)), delay);
                        }
                        return;
                    }
                    let position = self.position;
                    let expected = b6_exchange(0, position).unwrap();
                    assert_eq!(&tpdu[3..tpdu.len() - 1], expected.request());
                    assert_eq!(tpdu[1], ((position % 2) as u8) << 6);
                    assert_eq!(request[9], 0);
                    self.position += 1;
                    let repeated = matches!(self.scenario,Scenario::Repeat(p) if p==position);
                    let response = synthetic(position, repeated);
                    if position == 2 {
                        if let Scenario::Wtx(multiplier, count, _) = self.scenario {
                            self.pending = Some((tpdu[1], response));
                            self.wtx_left = count.saturating_sub(1);
                            self.queue(ccid(0x80, seq, 0, 0, 0, &block(0xc3, &[multiplier])), 1);
                            return;
                        }
                    }
                    ccid(0x80, seq, 0, 0, 0, &block(tpdu[1], &response))
                }
            };
            if self.position == 3 && ordinal > 5 {
                if let Scenario::Extension(count, coalesced) = self.scenario {
                    let te = ccid(0x80, seq, 0x80, 0xa5, 0, &[]);
                    if coalesced {
                        let mut joined = Vec::new();
                        for _ in 0..count {
                            joined.extend_from_slice(&te);
                        }
                        joined.extend_from_slice(&reply);
                        self.queue.push_back((joined, 40));
                    } else {
                        for _ in 0..count {
                            self.queue(te.clone(), 1);
                        }
                        self.queue(reply, 40);
                    }
                    return;
                }
                if matches!(self.scenario, Scenario::ChangedExtension) {
                    let changed = ccid(0x80, seq.wrapping_add(1), 0x80, 1, 0, &[]);
                    self.queue(changed, 1);
                    return;
                }
                if matches!(self.scenario, Scenario::Partial) {
                    self.queue(reply[..4].to_vec(), 1);
                    self.queue.push_back((Vec::new(), 5000));
                    return;
                }
                if matches!(self.scenario, Scenario::Extra) {
                    let mut extra = reply;
                    extra.push(0);
                    self.queue.push_back((extra, 1));
                    return;
                }
            }
            self.queue(reply, 1);
        }
    }
    impl Sec1210Transport for Reader {
        fn configure(&mut self) -> Result<i32, Sec1210Error> {
            Ok(0)
        }
        fn open(&mut self) -> Result<(), Sec1210Error> {
            self.opened = true;
            Ok(())
        }
        fn write_once(&mut self, b: &[u8]) -> Result<usize, Sec1210Error> {
            assert!(self.queue.is_empty());
            if self.position == 2 && matches!(self.scenario, Scenario::WriteFail) {
                self.writes.push(b.to_vec());
                return Err(Sec1210Error::WriteFailed);
            }
            self.response(b);
            self.writes.push(b.to_vec());
            self.sent = self.now.get();
            Ok(b.len())
        }
        fn pause_after_write(&mut self) -> Result<(), Sec1210Error> {
            self.now.set(self.now.get() + 10);
            Ok(())
        }
        fn read(&mut self, _: &mut [u8]) -> Result<(usize, u64), Sec1210Error> {
            panic!("old read path")
        }
        fn release(&mut self) -> Result<bool, Sec1210Error> {
            let b = self.opened;
            self.opened = false;
            Ok(b)
        }
    }
    impl Sec1210FidiSignTransport for Reader {
        fn now_ms(&mut self) -> u64 {
            self.now.get()
        }
        fn utc_now(&mut self) -> Result<String, Sec1210FidiSignError> {
            Ok(if matches!(self.scenario, Scenario::BadClock) {
                "2026-02-30T00:00:00Z"
            } else {
                UTC
            }
            .into())
        }
        fn read_until(&mut self, b: &mut [u8], _: u64) -> Result<(usize, u64), Sec1210Error> {
            let (bytes, delta) = self.queue.pop_front().unwrap_or((Vec::new(), 5000));
            self.now.set(self.now.get() + delta);
            b[..bytes.len()].copy_from_slice(&bytes);
            Ok((bytes.len(), self.now.get() - self.sent))
        }
    }
    fn metadata() -> Sec1210FidiSignMetadata {
        Sec1210FidiSignMetadata::new(
            "a".repeat(40),
            UTC.into(),
            "RIG-HOST-PI3B-01",
            "J3R180-03",
            std::env::temp_dir().join(sec1210_fidi_sign_output_basename(UTC)),
        )
        .unwrap()
    }
    struct Replay {
        commands: VecDeque<(Vec<u8>, u64)>,
        reads: VecDeque<(Vec<u8>, u64, u64)>,
        clocks: VecDeque<String>,
        now: u64,
    }
    impl Replay {
        fn from_transcript(text: &str) -> Self {
            let fields: std::collections::BTreeMap<_, _> =
                text.lines().filter_map(|l| l.split_once('=')).collect();
            let requests: usize = fields["request_count"].parse().unwrap();
            let read_count: usize = fields["read_fragment_count"].parse().unwrap();
            let commands = (1..=requests)
                .map(|i| {
                    (
                        decode(fields[format!("command.{i}.request_hex").as_str()]),
                        fields[format!("command.{i}.write_monotonic_ms").as_str()]
                            .parse()
                            .unwrap(),
                    )
                })
                .collect();
            let reads = (0..read_count)
                .map(|i| {
                    (
                        decode(fields[format!("read.{i}.rx_hex").as_str()]),
                        fields[format!("read.{i}.elapsed_ms").as_str()]
                            .parse()
                            .unwrap(),
                        fields[format!("read.{i}.monotonic_ms").as_str()]
                            .parse()
                            .unwrap(),
                    )
                })
                .collect();
            Self {
                commands,
                reads,
                clocks: [
                    fields["session.0.start_utc"].to_string(),
                    fields["session.0.end_utc"].to_string(),
                ]
                .into(),
                now: 0,
            }
        }
    }
    impl Sec1210Transport for Replay {
        fn configure(&mut self) -> Result<i32, Sec1210Error> {
            Ok(0)
        }
        fn open(&mut self) -> Result<(), Sec1210Error> {
            Ok(())
        }
        fn write_once(&mut self, bytes: &[u8]) -> Result<usize, Sec1210Error> {
            let (expected, clock) = self.commands.pop_front().unwrap();
            assert_eq!(bytes, expected);
            assert_eq!(self.now, clock);
            Ok(bytes.len())
        }
        fn pause_after_write(&mut self) -> Result<(), Sec1210Error> {
            self.now += 10;
            Ok(())
        }
        fn read(&mut self, _: &mut [u8]) -> Result<(usize, u64), Sec1210Error> {
            panic!("old read path")
        }
        fn release(&mut self) -> Result<bool, Sec1210Error> {
            Ok(true)
        }
    }
    impl Sec1210FidiSignTransport for Replay {
        fn now_ms(&mut self) -> u64 {
            self.now
        }
        fn utc_now(&mut self) -> Result<String, Sec1210FidiSignError> {
            Ok(self.clocks.pop_front().unwrap())
        }
        fn read_until(&mut self, buffer: &mut [u8], _: u64) -> Result<(usize, u64), Sec1210Error> {
            let (bytes, elapsed, clock) = self.reads.pop_front().unwrap();
            self.now = clock;
            buffer[..bytes.len()].copy_from_slice(&bytes);
            Ok((bytes.len(), elapsed))
        }
    }
    fn run(reader: &mut Reader) -> (Sec1210FidiSignSummary, String) {
        let mut writer = Sec1210FidiSignTranscript::new(Vec::new());
        let summary = run_inner(&metadata(), reader, &mut writer, |_, _, _| Ok(()));
        (summary, String::from_utf8(writer.into_inner()).unwrap())
    }
    #[test]
    fn full_100_traversal_mocks_only_curve_and_reproduces_byte_for_byte() {
        let mut a = Reader::new(Scenario::Plain);
        let (summary, text) = run(&mut a);
        assert_eq!(summary.failure, None);
        assert_eq!((summary.request_count, summary.response_count), (107, 107));
        assert_eq!(
            (
                summary.apdu_accepted_count,
                summary.signature_fact_count,
                summary.signature_accepted_count
            ),
            (102, 100, 100)
        );
        assert_eq!(summary.completed_sessions, 1);
        assert_eq!(text.lines().filter(|l| l.contains(".r_hex=")).count(), 100);
        assert_eq!(
            text.lines()
                .filter(|l| l.starts_with("session.0.start_utc="))
                .count(),
            1
        );
        let mut replay = Replay::from_transcript(&text);
        let mut copy = Sec1210FidiSignTranscript::new(Vec::new());
        let reproduced = run_inner(&metadata(), &mut replay, &mut copy, |_, _, _| Ok(()));
        assert_eq!(summary, reproduced);
        assert_eq!(text, String::from_utf8(copy.into_inner()).unwrap());
        assert!(replay.commands.is_empty() && replay.reads.is_empty() && replay.clocks.is_empty());
        assert!(text.contains("result=PASS\n"));
    }
    #[test]
    fn repeated_numeric_r_in_a_later_signature_stops_without_next_write() {
        let mut reader = Reader::new(Scenario::Repeat(99));
        let (s, text) = run(&mut reader);
        assert_eq!(s.failure.unwrap().name(), "B6RepeatedR");
        assert_eq!(s.signature_accepted_count, 97);
        assert_eq!(reader.writes.len(), 105);
        assert!(text.contains("apdu.99.verify=PASS"));
        assert!(!text.contains("apdu.100.tx_hex="));
    }
    #[test]
    fn final_i_block_timing_does_not_use_an_earlier_time_extension() {
        let (s, text) = run(&mut Reader::new(Scenario::Extension(1, false)));
        assert_eq!(s.failure, None);
        assert_eq!(s.time_extension_count, 1);
        assert!(text.contains("command.8.first_reply.first_response_bytes_ms=11\n"));
        assert!(text.contains("apdu.2.final_response_first_bytes_ms=52\n"));
        assert!(text.contains("command.8.time_extension.1."));
        let (s, coalesced) = run(&mut Reader::new(Scenario::Extension(1, true)));
        assert_eq!(s.failure, None);
        assert!(coalesced.contains("apdu.2.final_response_first_bytes_ms=50\n"));
    }
    #[test]
    fn reader_extensions_never_emit_writes_and_ninth_is_terminal() {
        let (s, _) = run(&mut Reader::new(Scenario::Extension(8, false)));
        assert_eq!(s.failure, None);
        assert_eq!(s.request_count, 107);
        assert_eq!(s.time_extension_count, 8);
        let (s, text) = run(&mut Reader::new(Scenario::Extension(9, false)));
        assert_eq!(
            s.failure.unwrap().name(),
            "Sec1210TimeExtensionLimitExceeded"
        );
        assert_eq!(s.request_count, 8);
        assert_eq!(s.signature_fact_count, 0);
        assert!(!text.contains("apdu.3.tx_hex="));
    }
    #[test]
    fn changed_extension_sequence_is_terminal() {
        let (s, _) = run(&mut Reader::new(Scenario::ChangedExtension));
        assert_eq!(s.failure.unwrap().name(), "Sec1210SequenceRejected");
        assert_eq!(s.request_count, 8);
    }
    #[test]
    fn wtx_allows_more_than_five_seconds_only_with_the_fixed_multiplier() {
        let (s, text) = run(&mut Reader::new(Scenario::Wtx(6, 1, 6000)));
        assert_eq!(s.failure, None);
        assert_eq!(s.wtx_count, 1);
        assert_eq!(s.request_count, 108);
        assert!(text.contains("apdu.2.wtx.1.multiplier=6\n"));
        assert!(text.contains("apdu.2.wtx.1.bBWI=6\n"));
        assert!(text.contains("apdu.2.wtx.1.host_allowance_ms=7140\n"));
        let (s, _) = run(&mut Reader::new(Scenario::Wtx(1, 1, 6000)));
        assert_eq!(s.failure.unwrap().name(), "Sec1210DeadlineExceeded");
        let (s, _) = run(&mut Reader::new(Scenario::Wtx(25, 1, 1)));
        assert_eq!(s.failure.unwrap().name(), "T1WtxMultiplierRejected");
    }
    #[test]
    fn ninth_wtx_and_absolute_apdu_deadline_stop_the_loop() {
        let (s, _) = run(&mut Reader::new(Scenario::Wtx(1, 9, 1)));
        assert_eq!(s.failure.unwrap().name(), "T1WtxLimitExceeded");
        let (s, text) = run(&mut Reader::new(Scenario::Wtx(24, 2, 16000)));
        assert_eq!(s.failure.unwrap().name(), "T1DeadlineExceeded");
        assert!(!text.contains("apdu.3.tx_hex="));
    }
    #[test]
    fn budgets_cover_curve_verification_and_latch_before_later_cleanup() {
        for (cost, name) in [
            (5000, "Sec1210DeadlineExceeded"),
            (30000, "T1DeadlineExceeded"),
        ] {
            let mut r = Reader::new(Scenario::Plain);
            let clock = r.now.clone();
            let mut writer = Sec1210FidiSignTranscript::new(Vec::new());
            let s = run_inner(&metadata(), &mut r, &mut writer, move |_, _, _| {
                clock.set(clock.get() + cost);
                Ok(())
            });
            assert_eq!(s.failure.unwrap().name(), name);
            assert_eq!(s.signature_fact_count, 1);
            assert_eq!(s.apdu_accepted_count, 2);
        }
    }
    #[test]
    fn partial_extra_write_failure_and_bad_utc_are_named_and_stop() {
        for (scenario, name, requests) in [
            (Scenario::Partial, "Sec1210PartialFrameDeadline", 8),
            (Scenario::Extra, "Sec1210TrailingData", 8),
            (Scenario::WriteFail, "Sec1210WriteFailed", 7),
            (Scenario::BadClock, "B6ClockFailed", 5),
        ] {
            let mut reader = Reader::new(scenario);
            let (s, text) = run(&mut reader);
            assert_eq!(s.failure.unwrap().name(), name);
            assert_eq!(s.request_count, requests);
            // An errored write is attempted and recorded but never accepted
            // by RawSession::written as one completely transmitted command.
            assert_eq!(
                reader.writes.len(),
                requests + usize::from(name == "Sec1210WriteFailed")
            );
            assert!(!text.contains("result=PASS\n"));
        }
    }
    #[test]
    fn initial_requests_match_the_independent_literal_constructor() {
        let mut r = Reader::new(Scenario::BadClock);
        let (s, _) = run(&mut r);
        assert_eq!(s.request_count, 5);
        let expected = [
            "03066500000000000100000061",
            "03066200000000000202000067",
            "03066c0000000000030000006a",
            "0306610700000000040100001810ff4d00fe0022",
            "03066f05000000000500000000c101fe3e6a",
        ];
        assert_eq!(
            r.writes.iter().map(|b| hex(b)).collect::<Vec<_>>(),
            expected
        );
    }
}
