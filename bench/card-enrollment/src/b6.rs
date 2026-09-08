//! Fixed public GOLDEN B6 request expansion and online fail-first verification.

use core::fmt;
use std::panic::{catch_unwind, AssertUnwindSafe};
use std::path::{Path, PathBuf};

use qk_card_protocol::{
    encode_open_session, encode_select, encode_sign_digest, parse_response, EnvelopeRef,
    Instruction, Mode, ResponseRef, SignRequest,
};

use crate::{
    validate_sitting_binding, SittingTransportFailure, ValidatedMetadata,
    MAX_SITTING_CAPTURE_BYTES, MAX_SITTING_REQUEST_BYTES, MAX_SITTING_RESPONSE_BYTES,
    SITTING_CAMPAIGN_SOURCE_COMMIT,
};

pub const B6_MODE: &str = "sign-golden";
pub const B6_PLAN_VERSION: &str = "1";
pub const B6_TOOL_VERSION: &str = "0.0.7";
pub const B6_TRANSCRIPT_VERSION: &str = "QK-CARD-B6-V1";
pub const B6_TRANSCRIPT_LIMIT_ID: &str = "QK-LIM-BENCH-B6-TRANSCRIPT-V1";
pub const MAX_B6_TRANSCRIPT_BYTES: usize = 2_097_152;
pub const B6_CAMPAIGN_SOURCE_COMMIT: &str = SITTING_CAMPAIGN_SOURCE_COMMIT;
pub const B6_SESSION_COUNT: usize = 10;
pub const B6_SIGNATURES_PER_SESSION: usize = 100;
pub const B6_TOTAL_SIGNATURES: usize = 1_000;
pub const B6_EXCHANGES_PER_SESSION: usize = 102;
pub const B6_TOTAL_EXCHANGES: usize = 1_020;
pub const B6_EXPANDED_REQUEST_BYTES: usize = 132_360;
/// SHA-256 of all 1,020 complete requests concatenated in traversal order.
pub const B6_PLAN_SHA256: &str = "44ca636942407f6523d5641cf1bf4396bb07b980ec534395514dee0abd31b348";
pub const B6_SESSION_IDS: [[u8; 16]; 10] = [
    [0xc0; 16], [0xc1; 16], [0xc2; 16], [0xc3; 16], [0xc4; 16], [0xc5; 16], [0xc6; 16], [0xc7; 16],
    [0xc8; 16], [0xc9; 16],
];
pub const B6_WALLET_ID: [u8; 32] =
    hex32("d5b7e52f569ae51e7c66af14240d8e4459c6246785ce5c441773995614f60e9e");
pub const B6_REVIEW_HASH: [u8; 32] =
    hex32("9c5de46f2ac5f29f6c9335b4016b65fe96aa0cd04e3a6b5b7224389db5fae3a3");
pub const B6_DIGEST: [u8; 32] =
    hex32("0d3d0763b43943f0f5342003355f8359fff4ba942dae2286becc635dc88d8386");
pub const B6_PUBLIC_KEY: [u8; 33] = [
    0x03, 0x9a, 0xd8, 0xf8, 0x74, 0xde, 0x32, 0xed, 0x2b, 0x16, 0x81, 0x24, 0xda, 0x66, 0x8f, 0x7a,
    0xc6, 0xdb, 0xb5, 0xf8, 0xd9, 0x33, 0x0d, 0xa2, 0x45, 0xec, 0xf7, 0x09, 0x85, 0x38, 0xbe, 0xf7,
    0x9f,
];

const fn hex32(value: &str) -> [u8; 32] {
    let bytes = value.as_bytes();
    let mut result = [0; 32];
    let mut index = 0;
    while index < 32 {
        result[index] = (hex_digit(bytes[index * 2]) << 4) | hex_digit(bytes[index * 2 + 1]);
        index += 1;
    }
    result
}
const fn hex_digit(value: u8) -> u8 {
    match value {
        b'0'..=b'9' => value - b'0',
        b'a'..=b'f' => value - b'a' + 10,
        _ => 0,
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum B6Error {
    B6BindingMismatch,
    B6OutputPathRejected,
    B6OutputNameMismatch,
    B6OutputCreateFailed,
    B6OutputWriteFailed,
    B6OutputFlushFailed,
    B6ContextUnavailable,
    B6ReaderEnumerationFailed,
    B6ReaderListTooLarge,
    B6ReaderCountExceeded,
    B6ReaderNameRejected,
    B6SelectedReaderMissing,
    B6SelectedReaderDuplicate,
    B6ConnectFailed,
    B6ResetFailed,
    B6StatusFailed,
    B6AtrRejected,
    B6ProtocolMismatch,
    B6TransmitFailed,
    B6ResponseCaptureExceeded,
    B6ResponseLimitExceeded,
    B6ResponseLengthMismatch,
    B6StatusRejected,
    B6ResponseVersionMismatch,
    B6ResponseSessionMismatch,
    B6ResponseCounterMismatch,
    B6ResponseReviewHashMismatch,
    B6ResponseInputIndexMismatch,
    B6ResponseKeyMismatch,
    B6ResponseDerLengthMismatch,
    B6DerRejected,
    B6SignatureVerificationFailed,
    B6RepeatedR,
    B6DisconnectFailed,
    B6BoundaryPanicked,
    B6SequenceViolation,
    B6TranscriptTooLarge,
    B6ClockFailed,
    B6RequestEncodingFailed,
}
impl B6Error {
    pub const fn name(self) -> &'static str {
        match self {
            Self::B6BindingMismatch => "B6BindingMismatch",
            Self::B6OutputPathRejected => "B6OutputPathRejected",
            Self::B6OutputNameMismatch => "B6OutputNameMismatch",
            Self::B6OutputCreateFailed => "B6OutputCreateFailed",
            Self::B6OutputWriteFailed => "B6OutputWriteFailed",
            Self::B6OutputFlushFailed => "B6OutputFlushFailed",
            Self::B6ContextUnavailable => "B6ContextUnavailable",
            Self::B6ReaderEnumerationFailed => "B6ReaderEnumerationFailed",
            Self::B6ReaderListTooLarge => "B6ReaderListTooLarge",
            Self::B6ReaderCountExceeded => "B6ReaderCountExceeded",
            Self::B6ReaderNameRejected => "B6ReaderNameRejected",
            Self::B6SelectedReaderMissing => "B6SelectedReaderMissing",
            Self::B6SelectedReaderDuplicate => "B6SelectedReaderDuplicate",
            Self::B6ConnectFailed => "B6ConnectFailed",
            Self::B6ResetFailed => "B6ResetFailed",
            Self::B6StatusFailed => "B6StatusFailed",
            Self::B6AtrRejected => "B6AtrRejected",
            Self::B6ProtocolMismatch => "B6ProtocolMismatch",
            Self::B6TransmitFailed => "B6TransmitFailed",
            Self::B6ResponseCaptureExceeded => "B6ResponseCaptureExceeded",
            Self::B6ResponseLimitExceeded => "B6ResponseLimitExceeded",
            Self::B6ResponseLengthMismatch => "B6ResponseLengthMismatch",
            Self::B6StatusRejected => "B6StatusRejected",
            Self::B6ResponseVersionMismatch => "B6ResponseVersionMismatch",
            Self::B6ResponseSessionMismatch => "B6ResponseSessionMismatch",
            Self::B6ResponseCounterMismatch => "B6ResponseCounterMismatch",
            Self::B6ResponseReviewHashMismatch => "B6ResponseReviewHashMismatch",
            Self::B6ResponseInputIndexMismatch => "B6ResponseInputIndexMismatch",
            Self::B6ResponseKeyMismatch => "B6ResponseKeyMismatch",
            Self::B6ResponseDerLengthMismatch => "B6ResponseDerLengthMismatch",
            Self::B6DerRejected => "B6DerRejected",
            Self::B6SignatureVerificationFailed => "B6SignatureVerificationFailed",
            Self::B6RepeatedR => "B6RepeatedR",
            Self::B6DisconnectFailed => "B6DisconnectFailed",
            Self::B6BoundaryPanicked => "B6BoundaryPanicked",
            Self::B6SequenceViolation => "B6SequenceViolation",
            Self::B6TranscriptTooLarge => "B6TranscriptTooLarge",
            Self::B6ClockFailed => "B6ClockFailed",
            Self::B6RequestEncodingFailed => "B6RequestEncodingFailed",
        }
    }
}
impl fmt::Display for B6Error {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.name())
    }
}
impl std::error::Error for B6Error {}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum B6Outcome {
    Pass,
    Reject(B6Error),
}
impl B6Outcome {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Pass => "PASS",
            Self::Reject(error) => error.name(),
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct B6Metadata {
    enrollment: ValidatedMetadata,
    output_path: PathBuf,
}
impl B6Metadata {
    pub fn new(enrollment: ValidatedMetadata, output_path: PathBuf) -> Result<Self, B6Error> {
        validate_sitting_binding(&enrollment).map_err(|_| B6Error::B6BindingMismatch)?;
        if !output_path.is_absolute() || output_path.parent().is_none() {
            return Err(B6Error::B6OutputPathRejected);
        }
        let expected = b6_output_basename(&enrollment.inner().timestamp_utc);
        if output_path.file_name().and_then(|value| value.to_str()) != Some(expected.as_str()) {
            return Err(B6Error::B6OutputNameMismatch);
        }
        Ok(Self {
            enrollment,
            output_path,
        })
    }
    pub fn output_path(&self) -> &Path {
        &self.output_path
    }
    pub(crate) fn enrollment(&self) -> &ValidatedMetadata {
        &self.enrollment
    }
}
pub fn b6_output_basename(timestamp_utc: &str) -> String {
    format!("qk-card-b6-v1__{B6_MODE}__J3R180-02__{timestamp_utc}.txt")
}

/// Bounded, fixed-plan request. Callers cannot substitute any request field.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct B6Exchange {
    session: usize,
    position: usize,
    bytes: [u8; MAX_SITTING_REQUEST_BYTES],
    length: usize,
}
impl B6Exchange {
    pub const fn index(&self) -> usize {
        self.session * B6_EXCHANGES_PER_SESSION + self.position
    }
    pub const fn session_index(&self) -> usize {
        self.session
    }
    pub const fn position(&self) -> usize {
        self.position
    }
    pub const fn name(&self) -> &'static str {
        match self.position {
            0 => "select",
            1 => "normal-open",
            _ => "sign",
        }
    }
    pub fn request(&self) -> &[u8] {
        &self.bytes[..self.length]
    }
    pub fn input_index(&self) -> Option<u32> {
        self.position.checked_sub(2).map(|index| index as u32)
    }
}

/// Expand one of the immutable ten-by-102 positions, without loading a plan file.
pub fn b6_exchange(session: usize, position: usize) -> Result<B6Exchange, B6Error> {
    if session >= B6_SESSION_COUNT || position >= B6_EXCHANGES_PER_SESSION {
        return Err(B6Error::B6SequenceViolation);
    }
    let mut exchange = B6Exchange {
        session,
        position,
        bytes: [0; MAX_SITTING_REQUEST_BYTES],
        length: 0,
    };
    exchange.length = match position {
        0 => encode_select(&mut exchange.bytes),
        1 => encode_open_session(Mode::Normal, &B6_SESSION_IDS[session], &mut exchange.bytes),
        _ => encode_sign_digest(
            EnvelopeRef::new(&B6_SESSION_IDS[session], (position - 1) as u32),
            SignRequest {
                wallet_id: &B6_WALLET_ID,
                review_hash: &B6_REVIEW_HASH,
                input_index: (position - 2) as u32,
                branch: 0,
                child_index: 0,
                digest: &B6_DIGEST,
            },
            &mut exchange.bytes,
        ),
    }
    .map_err(|_| B6Error::B6RequestEncodingFailed)?;
    Ok(exchange)
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct B6SignatureFacts {
    pub normalized: bool,
    pub r: [u8; 32],
    pub verified: bool,
}

/// Observer failures terminate before any later transport call.
pub trait B6Observer {
    fn session_start(&mut self, session: usize, utc: &str) -> Result<(), B6Error>;
    fn session_end(&mut self, session: usize, utc: &str, outcome: B6Outcome)
        -> Result<(), B6Error>;
    fn record_request(&mut self, exchange: &B6Exchange) -> Result<(), B6Error>;
    fn record_response(&mut self, exchange: &B6Exchange, bytes: &[u8]) -> Result<(), B6Error>;
    fn record_comparison(
        &mut self,
        exchange: &B6Exchange,
        outcome: B6Outcome,
    ) -> Result<(), B6Error>;
    fn record_signature(
        &mut self,
        exchange: &B6Exchange,
        facts: B6SignatureFacts,
    ) -> Result<(), B6Error>;
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct B6RunSummary {
    pub transmit_calls: usize,
    pub received_responses: usize,
    pub verified_signatures: usize,
    pub normalized_signatures: usize,
    pub completed_sessions: usize,
    pub outcome: B6Outcome,
}
impl B6RunSummary {
    const fn empty() -> Self {
        Self {
            transmit_calls: 0,
            received_responses: 0,
            verified_signatures: 0,
            normalized_signatures: 0,
            completed_sessions: 0,
            outcome: B6Outcome::Pass,
        }
    }
}

fn boundary<T>(call: impl FnOnce() -> Result<T, B6Error>) -> Result<T, B6Error> {
    catch_unwind(AssertUnwindSafe(call)).unwrap_or(Err(B6Error::B6BoundaryPanicked))
}

/// Run precisely the registered plan. This entry always uses real curve verification.
pub fn run_b6<O, F, C>(observer: &mut O, exchange_call: F, utc_clock: C) -> B6RunSummary
where
    O: B6Observer,
    F: FnMut(&[u8], &mut [u8; MAX_SITTING_CAPTURE_BYTES]) -> Result<usize, SittingTransportFailure>,
    C: FnMut() -> Result<String, B6Error>,
{
    run_b6_inner(
        observer,
        exchange_call,
        utc_clock,
        |signature, digest, key| {
            qk_secp::ecdsa_verify(signature, digest, key)
                .map_err(|_| B6Error::B6SignatureVerificationFailed)
        },
    )
}

fn run_b6_inner<O, F, C, V>(
    observer: &mut O,
    mut exchange_call: F,
    mut utc_clock: C,
    mut verify: V,
) -> B6RunSummary
where
    O: B6Observer,
    F: FnMut(&[u8], &mut [u8; MAX_SITTING_CAPTURE_BYTES]) -> Result<usize, SittingTransportFailure>,
    C: FnMut() -> Result<String, B6Error>,
    V: FnMut(&qk_secp::Signature, &[u8; 32], &qk_secp::PublicKey) -> Result<(), B6Error>,
{
    let mut summary = B6RunSummary::empty();
    let mut seen = [[0u8; 32]; B6_TOTAL_SIGNATURES];
    for session in 0..B6_SESSION_COUNT {
        let start = boundary(&mut utc_clock)
            .and_then(|utc| boundary(|| observer.session_start(session, &utc)));
        if let Err(error) = start {
            summary.outcome = B6Outcome::Reject(error);
            return summary;
        }
        for position in 0..B6_EXCHANGES_PER_SESSION {
            let exchange = match b6_exchange(session, position) {
                Ok(exchange) => exchange,
                Err(error) => {
                    summary.outcome = B6Outcome::Reject(error);
                    break;
                }
            };
            let result = boundary(|| {
                observer.record_request(&exchange)?;
                let mut response = [0u8; MAX_SITTING_CAPTURE_BYTES];
                summary.transmit_calls += 1;
                let response_length = match exchange_call(exchange.request(), &mut response) {
                    Ok(length) if length <= response.len() => length,
                    Ok(_) | Err(SittingTransportFailure::CaptureExceeded) => {
                        return Err(B6Error::B6ResponseCaptureExceeded)
                    }
                    Err(SittingTransportFailure::Failed) => return Err(B6Error::B6TransmitFailed),
                    Err(SittingTransportFailure::BoundaryPanicked) => {
                        return Err(B6Error::B6BoundaryPanicked)
                    }
                };
                summary.received_responses += 1;
                observer.record_response(&exchange, &response[..response_length])?;
                let der = validate_response(&exchange, &response[..response_length])?;
                if let Some(der) = der {
                    let mut normalized = [0u8; 72];
                    let length = qk_secp::normalize_card_signature_der(der, &mut normalized)
                        .map_err(|_| B6Error::B6DerRejected)?;
                    let normalized = &normalized[..length];
                    let r = strict_der_r(normalized)?;
                    let parsed = qk_secp::signature_parse_der(normalized)
                        .map_err(|_| B6Error::B6DerRejected)?;
                    let key = qk_secp::pubkey_parse_compressed(&B6_PUBLIC_KEY)
                        .map_err(|_| B6Error::B6SignatureVerificationFailed)?;
                    let verified = verify(&parsed, &B6_DIGEST, &key);
                    let facts = B6SignatureFacts {
                        normalized: der != normalized,
                        r,
                        verified: verified.is_ok(),
                    };
                    observer.record_signature(&exchange, facts)?;
                    summary.normalized_signatures += usize::from(facts.normalized);
                    verified?;
                    if seen[..summary.verified_signatures].contains(&r) {
                        return Err(B6Error::B6RepeatedR);
                    }
                    seen[summary.verified_signatures] = r;
                    summary.verified_signatures += 1;
                }
                Ok(())
            });
            let outcome = match result {
                Ok(()) => B6Outcome::Pass,
                Err(error) => B6Outcome::Reject(error),
            };
            let recording = boundary(|| observer.record_comparison(&exchange, outcome));
            summary.outcome = match (outcome, recording) {
                (B6Outcome::Reject(error), _) | (_, Err(error)) => B6Outcome::Reject(error),
                _ => B6Outcome::Pass,
            };
            if summary.outcome != B6Outcome::Pass {
                break;
            }
        }
        let ending = boundary(&mut utc_clock)
            .and_then(|utc| boundary(|| observer.session_end(session, &utc, summary.outcome)));
        if summary.outcome == B6Outcome::Pass {
            if let Err(error) = ending {
                summary.outcome = B6Outcome::Reject(error);
            }
        }
        if summary.outcome != B6Outcome::Pass {
            return summary;
        }
        summary.completed_sessions += 1;
    }
    summary
}

fn validate_response<'a>(
    exchange: &B6Exchange,
    response: &'a [u8],
) -> Result<Option<&'a [u8]>, B6Error> {
    if response.len() > MAX_SITTING_RESPONSE_BYTES {
        return Err(B6Error::B6ResponseLimitExceeded);
    }
    if response.len() < 2 {
        return Err(B6Error::B6ResponseLengthMismatch);
    }
    if response[response.len() - 2..] != [0x90, 0x00] {
        return Err(B6Error::B6StatusRejected);
    }
    let body = &response[..response.len() - 2];
    if exchange.position == 0 {
        return match parse_response(Instruction::Select, response) {
            Ok(ResponseRef::Select) => Ok(None),
            _ => Err(B6Error::B6ResponseLengthMismatch),
        };
    }
    if body.len() < 21 {
        return Err(B6Error::B6ResponseLengthMismatch);
    }
    if body[0] != 1 {
        return Err(B6Error::B6ResponseVersionMismatch);
    }
    if body[1..17] != B6_SESSION_IDS[exchange.session] {
        return Err(B6Error::B6ResponseSessionMismatch);
    }
    let expected_sequence = (exchange.position - 1) as u32;
    if body[17..21] != expected_sequence.to_be_bytes() {
        return Err(B6Error::B6ResponseCounterMismatch);
    }
    if exchange.position == 1 {
        return match parse_response(Instruction::OpenSession, response) {
            Ok(ResponseRef::OpenSession { .. }) => Ok(None),
            _ => Err(B6Error::B6ResponseLengthMismatch),
        };
    }
    if body.len() < 91 {
        return Err(B6Error::B6ResponseLengthMismatch);
    }
    if body[21..53] != B6_REVIEW_HASH {
        return Err(B6Error::B6ResponseReviewHashMismatch);
    }
    if body[53..57] != ((exchange.position - 2) as u32).to_be_bytes() {
        return Err(B6Error::B6ResponseInputIndexMismatch);
    }
    if body[57..90] != B6_PUBLIC_KEY {
        return Err(B6Error::B6ResponseKeyMismatch);
    }
    let length = usize::from(body[90]);
    if !(8..=72).contains(&length) || body.len() != 91 + length {
        return Err(B6Error::B6ResponseDerLengthMismatch);
    }
    match parse_response(Instruction::SignDigest, response) {
        Ok(ResponseRef::SignDigest { signature_der, .. }) => Ok(Some(signature_der)),
        _ => Err(B6Error::B6ResponseDerLengthMismatch),
    }
}

/// Parse canonical positive DER integers and return r as one fixed-width value.
fn strict_der_r(der: &[u8]) -> Result<[u8; 32], B6Error> {
    if !(8..=72).contains(&der.len()) || der[0] != 0x30 || usize::from(der[1]) != der.len() - 2 {
        return Err(B6Error::B6DerRejected);
    }
    let (r, after_r) = der_integer(der, 2)?;
    let (_, end) = der_integer(der, after_r)?;
    if end != der.len() {
        return Err(B6Error::B6DerRejected);
    }
    Ok(r)
}
fn der_integer(der: &[u8], offset: usize) -> Result<([u8; 32], usize), B6Error> {
    if der.get(offset) != Some(&0x02) {
        return Err(B6Error::B6DerRejected);
    }
    let length = usize::from(*der.get(offset + 1).ok_or(B6Error::B6DerRejected)?);
    let start = offset + 2;
    let end = start.checked_add(length).ok_or(B6Error::B6DerRejected)?;
    let integer = der.get(start..end).ok_or(B6Error::B6DerRejected)?;
    if integer.is_empty()
        || integer[0] & 0x80 != 0
        || (integer.len() > 1 && integer[0] == 0 && integer[1] & 0x80 == 0)
    {
        return Err(B6Error::B6DerRejected);
    }
    let magnitude = if integer[0] == 0 {
        &integer[1..]
    } else {
        integer
    };
    if magnitude.is_empty() || magnitude.len() > 32 {
        return Err(B6Error::B6DerRejected);
    }
    let mut padded = [0; 32];
    padded[32 - magnitude.len()..].copy_from_slice(magnitude);
    if padded == [0; 32] || padded >= CURVE_ORDER {
        return Err(B6Error::B6DerRejected);
    }
    Ok((padded, end))
}
const CURVE_ORDER: [u8; 32] =
    hex32("fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141");

#[cfg(test)]
mod tests {
    use super::*;

    #[derive(Default)]
    struct Observer {
        requests: usize,
        responses: usize,
        facts: Vec<B6SignatureFacts>,
        ends: usize,
    }
    impl B6Observer for Observer {
        fn session_start(&mut self, _: usize, _: &str) -> Result<(), B6Error> {
            Ok(())
        }
        fn session_end(&mut self, _: usize, _: &str, _: B6Outcome) -> Result<(), B6Error> {
            self.ends += 1;
            Ok(())
        }
        fn record_request(&mut self, _: &B6Exchange) -> Result<(), B6Error> {
            self.requests += 1;
            Ok(())
        }
        fn record_response(&mut self, _: &B6Exchange, _: &[u8]) -> Result<(), B6Error> {
            self.responses += 1;
            Ok(())
        }
        fn record_comparison(&mut self, _: &B6Exchange, _: B6Outcome) -> Result<(), B6Error> {
            Ok(())
        }
        fn record_signature(
            &mut self,
            _: &B6Exchange,
            facts: B6SignatureFacts,
        ) -> Result<(), B6Error> {
            self.facts.push(facts);
            Ok(())
        }
    }

    fn synthetic_response(request: &[u8], serial: usize) -> Vec<u8> {
        if request[1] == 0xa4 {
            return vec![0x90, 0];
        }
        if request[1] == 0x10 {
            let mut response = vec![1];
            response.extend_from_slice(&request[7..23]);
            response.extend_from_slice(&[0, 0, 0, 0, 0x90, 0]);
            return response;
        }
        let mut response = request[5..26].to_vec();
        response.extend_from_slice(&B6_REVIEW_HASH);
        response.extend_from_slice(&request[90..94]);
        response.extend_from_slice(&B6_PUBLIC_KEY);
        let serial = serial as u32;
        let full = serial.to_be_bytes();
        let first = full.iter().position(|&byte| byte != 0).unwrap();
        let mut integer = full[first..].to_vec();
        if integer[0] & 0x80 != 0 {
            integer.insert(0, 0);
        }
        let mut der = vec![0x30, (integer.len() + 5) as u8, 2, integer.len() as u8];
        der.extend_from_slice(&integer);
        der.extend_from_slice(&[2, 1, 1]);
        response.push(der.len() as u8);
        response.extend_from_slice(&der);
        response.extend_from_slice(&[0x90, 0]);
        response
    }

    fn traversal(repeat_at: Option<usize>) -> (B6RunSummary, Observer, usize) {
        let mut observer = Observer::default();
        let mut signed = 0;
        let mut curve_checks = 0;
        let result = run_b6_inner(
            &mut observer,
            |request, output| {
                let serial = if request[1] == 0x15 {
                    signed += 1;
                    if repeat_at == Some(signed) {
                        1
                    } else {
                        signed
                    }
                } else {
                    1
                };
                let response = synthetic_response(request, serial);
                output[..response.len()].copy_from_slice(&response);
                Ok(response.len())
            },
            || Ok("2026-09-07T12:00:00Z".into()),
            |_, digest, key| {
                // Only the curve equation is mocked. Parsing and normalization
                // already ran, and the pinned key and digest are still checked.
                assert_eq!(digest, &B6_DIGEST);
                assert_eq!(
                    qk_secp::pubkey_serialize_compressed(key).unwrap(),
                    B6_PUBLIC_KEY
                );
                curve_checks += 1;
                Ok(())
            },
        );
        (result, observer, curve_checks)
    }

    #[test]
    fn thousand_signatures_traverse_real_der_normalization_extraction_and_comparison() {
        let (result, observer, curve_checks) = traversal(None);
        assert_eq!(result.outcome, B6Outcome::Pass);
        assert_eq!(result.transmit_calls, 1_020);
        assert_eq!(result.received_responses, 1_020);
        assert_eq!(result.verified_signatures, 1_000);
        assert_eq!(result.normalized_signatures, 0);
        assert_eq!(result.completed_sessions, 10);
        assert_eq!(curve_checks, 1_000);
        assert_eq!(observer.requests, 1_020);
        assert_eq!(observer.responses, 1_020);
        assert_eq!(observer.ends, 10);
        assert_eq!(observer.facts.len(), 1_000);
        for (index, fact) in observer.facts.iter().enumerate() {
            let mut expected = [0; 32];
            expected[28..].copy_from_slice(&((index + 1) as u32).to_be_bytes());
            assert_eq!(fact.r, expected);
            assert!(fact.verified);
        }
    }

    #[test]
    fn repeated_numeric_r_in_a_later_session_terminates_without_a_next_request() {
        let (result, observer, checks) = traversal(Some(701));
        assert_eq!(result.outcome, B6Outcome::Reject(B6Error::B6RepeatedR));
        assert_eq!(result.verified_signatures, 700);
        assert_eq!(result.completed_sessions, 7);
        assert_eq!(result.transmit_calls, 717);
        assert_eq!(checks, 701);
        assert_eq!(observer.ends, 8);
        assert_eq!(observer.facts[0].r, observer.facts[700].r);
        assert!(observer.facts[700].verified);
    }

    #[test]
    fn strict_parser_rejects_nonminimal_negative_zero_overlong_and_trailing_integers() {
        for der in [
            vec![0x30, 6, 2, 1, 0, 2, 1, 1],
            vec![0x30, 6, 2, 1, 0x80, 2, 1, 1],
            vec![0x30, 7, 2, 2, 0, 1, 2, 1, 1],
            vec![0x30, 6, 2, 1, 1, 2, 1, 1, 0],
            vec![0x30, 6, 2, 1, 1, 2, 2, 1],
        ] {
            assert_eq!(strict_der_r(&der), Err(B6Error::B6DerRejected));
        }
        let mut too_wide = vec![0x30, 38, 2, 33, 1];
        too_wide.extend_from_slice(&[0; 32]);
        too_wide.extend_from_slice(&[2, 1, 1]);
        assert_eq!(strict_der_r(&too_wide), Err(B6Error::B6DerRejected));
        assert_eq!(
            strict_der_r(&[0x30, 7, 2, 2, 0, 0x80, 2, 1, 1]).unwrap()[31],
            0x80
        );
    }

    #[test]
    fn caught_transport_unwind_stops_and_closes_the_started_session() {
        let mut observer = Observer::default();
        let result = run_b6(
            &mut observer,
            |_, _| panic!("test transport"),
            || Ok("2026-09-07T12:00:00Z".into()),
        );
        assert_eq!(
            result.outcome,
            B6Outcome::Reject(B6Error::B6BoundaryPanicked)
        );
        assert_eq!(result.transmit_calls, 1);
        assert_eq!(result.received_responses, 0);
        assert_eq!(observer.ends, 1);
    }
}
