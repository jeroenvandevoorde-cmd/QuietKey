use crate::allowlist::live_mode_registered;
use crate::hex::{decode, decode_sha256, HexError};

const MAGIC: &str = "QK-CARD-TRACE-V1";
const EMPTY_ALLOWLIST: &str = "QK-F8-G0-EMPTY-V1";

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TraceMode {
    Mock,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct TraceLimits {
    max_trace_bytes: usize,
    max_records: usize,
    max_record_bytes: usize,
    max_identifier_bytes: usize,
    max_atr_bytes: usize,
}

impl TraceLimits {
    /// Creates explicit HOST harness controls.
    ///
    /// There is deliberately no `Default`: these values do not select or
    /// imply any QK-LIM-APDU or product limit.
    pub fn new(
        max_trace_bytes: usize,
        max_records: usize,
        max_record_bytes: usize,
        max_identifier_bytes: usize,
        max_atr_bytes: usize,
    ) -> Result<Self, TraceError> {
        if max_trace_bytes == 0
            || max_records == 0
            || max_record_bytes == 0
            || max_identifier_bytes == 0
            || max_atr_bytes == 0
        {
            return Err(TraceError::InvalidHarnessLimit);
        }
        Ok(Self {
            max_trace_bytes,
            max_records,
            max_record_bytes,
            max_identifier_bytes,
            max_atr_bytes,
        })
    }

    pub fn max_trace_bytes(self) -> usize {
        self.max_trace_bytes
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TraceSummary {
    pub mode: TraceMode,
    pub records: usize,
    pub atr_records: usize,
    pub protocol_records: usize,
    pub apdu_commands: usize,
    pub apdu_responses: usize,
    pub expected_filename: String,
    pub raw_artifact_sha256: [u8; 32],
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TraceError {
    InvalidHarnessLimit,
    InputTooLarge,
    EmptyInput,
    NonAscii,
    CarriageReturn,
    MissingFinalLf,
    InvalidMagic,
    InvalidHeader,
    InvalidIdentifier,
    InvalidTimestamp,
    InvalidMode,
    LiveModeNotAuthorized,
    UnsupportedAllowlist,
    InvalidDigest,
    InvalidRecordCount,
    TooManyRecords,
    InvalidRecord,
    InvalidSequence,
    NonMonotonicTime,
    InvalidHex,
    RecordTooLarge,
    AtrMustBeFirst,
    DuplicateAtr,
    InvalidAtrLength,
    ProtocolBeforeAtr,
    ProtocolMissing,
    ApduRecordNotAuthorized,
    RecordCountMismatch,
    MockIdentityMismatch,
    FilenameMismatch,
}

fn parse_prefixed<'a>(line: &'a str, prefix: &str) -> Result<&'a str, TraceError> {
    line.strip_prefix(prefix).ok_or(TraceError::InvalidHeader)
}

fn valid_identifier(value: &str, max_bytes: usize) -> bool {
    !value.is_empty()
        && value.len() <= max_bytes
        && value
            .bytes()
            .all(|byte| byte.is_ascii_uppercase() || byte.is_ascii_digit() || byte == b'-')
}

fn valid_timestamp(value: &str) -> bool {
    if value.len() != 16 || value.as_bytes()[8] != b'T' || value.as_bytes()[15] != b'Z' {
        return false;
    }
    if value
        .bytes()
        .enumerate()
        .any(|(index, byte)| index != 8 && index != 15 && !byte.is_ascii_digit())
    {
        return false;
    }
    let number =
        |range: core::ops::Range<usize>| -> Option<u32> { value.get(range)?.parse::<u32>().ok() };
    matches!(number(4..6), Some(1..=12))
        && matches!(number(6..8), Some(1..=31))
        && matches!(number(9..11), Some(0..=23))
        && matches!(number(11..13), Some(0..=59))
        && matches!(number(13..15), Some(0..=59))
}

fn canonical_usize(value: &str) -> Option<usize> {
    if value.is_empty() || (value.len() > 1 && value.starts_with('0')) {
        return None;
    }
    value.parse().ok()
}

fn canonical_u64(value: &str) -> Option<u64> {
    if value.is_empty() || (value.len() > 1 && value.starts_with('0')) {
        return None;
    }
    value.parse().ok()
}

fn map_hex_error(error: HexError) -> TraceError {
    match error {
        HexError::WrongLength => TraceError::RecordTooLarge,
        HexError::Empty | HexError::OddLength | HexError::InvalidDigit => TraceError::InvalidHex,
    }
}

fn expected_filename(run_id: &str, specimen_id: &str, captured_utc: &str) -> String {
    format!("qk-card-trace-v1__{run_id}__{specimen_id}__{captured_utc}.txt")
}

/// Checks one complete canonical trace against explicit HOST-only limits.
pub fn inspect_trace(
    input: &[u8],
    presented_filename: &str,
    limits: TraceLimits,
) -> Result<TraceSummary, TraceError> {
    if input.len() > limits.max_trace_bytes {
        return Err(TraceError::InputTooLarge);
    }
    if input.is_empty() {
        return Err(TraceError::EmptyInput);
    }
    if !input.is_ascii() {
        return Err(TraceError::NonAscii);
    }
    if input.contains(&b'\r') {
        return Err(TraceError::CarriageReturn);
    }
    if !input.ends_with(b"\n") {
        return Err(TraceError::MissingFinalLf);
    }
    let text = core::str::from_utf8(input).map_err(|_| TraceError::NonAscii)?;
    let lines: Vec<&str> = text[..text.len() - 1].split('\n').collect();
    if lines.first().copied() != Some(MAGIC) {
        return Err(TraceError::InvalidMagic);
    }
    if lines.len() < 10 {
        return Err(TraceError::InvalidHeader);
    }

    let run_id = parse_prefixed(lines[1], "run_id=")?;
    let specimen_id = parse_prefixed(lines[2], "specimen_id=")?;
    let reader_id = parse_prefixed(lines[3], "reader_id=")?;
    let captured_utc = parse_prefixed(lines[4], "captured_utc=")?;
    let mode = match parse_prefixed(lines[5], "mode=")? {
        "MOCK" => TraceMode::Mock,
        "LIVE" if !live_mode_registered() => return Err(TraceError::LiveModeNotAuthorized),
        _ => return Err(TraceError::InvalidMode),
    };
    if parse_prefixed(lines[6], "allowlist=")? != EMPTY_ALLOWLIST {
        return Err(TraceError::UnsupportedAllowlist);
    }
    let raw_artifact_sha256 = decode_sha256(parse_prefixed(lines[7], "raw_sha256=")?)
        .map_err(|_| TraceError::InvalidDigest)?;
    let declared_records = canonical_usize(parse_prefixed(lines[8], "record_count=")?)
        .ok_or(TraceError::InvalidRecordCount)?;
    if declared_records == 0 {
        return Err(TraceError::InvalidRecordCount);
    }
    if declared_records > limits.max_records {
        return Err(TraceError::TooManyRecords);
    }
    if !lines[9].is_empty() {
        return Err(TraceError::InvalidHeader);
    }
    for identifier in [run_id, specimen_id, reader_id] {
        if !valid_identifier(identifier, limits.max_identifier_bytes) {
            return Err(TraceError::InvalidIdentifier);
        }
    }
    if !valid_timestamp(captured_utc) {
        return Err(TraceError::InvalidTimestamp);
    }
    if !run_id.starts_with("MOCK-")
        || !specimen_id.starts_with("MOCK-")
        || !reader_id.starts_with("MOCK-")
    {
        return Err(TraceError::MockIdentityMismatch);
    }
    let expected_filename = expected_filename(run_id, specimen_id, captured_utc);
    if presented_filename != expected_filename {
        return Err(TraceError::FilenameMismatch);
    }

    let records = &lines[10..];
    if records.len() != declared_records {
        return Err(TraceError::RecordCountMismatch);
    }
    let mut last_elapsed = None;
    let mut atr_records = 0usize;
    let mut protocol_records = 0usize;

    for (index, line) in records.iter().copied().enumerate() {
        let mut fields = line.split(' ');
        let sequence = fields.next().ok_or(TraceError::InvalidRecord)?;
        let elapsed = fields.next().ok_or(TraceError::InvalidRecord)?;
        let kind = fields.next().ok_or(TraceError::InvalidRecord)?;
        let encoded = fields.next().ok_or(TraceError::InvalidRecord)?;
        if fields.next().is_some() {
            return Err(TraceError::InvalidRecord);
        }
        if sequence.len() != 6
            || !sequence.bytes().all(|byte| byte.is_ascii_digit())
            || sequence.parse::<usize>().ok() != Some(index)
        {
            return Err(TraceError::InvalidSequence);
        }
        let elapsed = canonical_u64(elapsed).ok_or(TraceError::InvalidRecord)?;
        if last_elapsed.is_some_and(|previous| elapsed < previous) {
            return Err(TraceError::NonMonotonicTime);
        }
        last_elapsed = Some(elapsed);
        let bytes = decode(encoded, limits.max_record_bytes).map_err(map_hex_error)?;

        match kind {
            "ATR" => {
                if index != 0 {
                    return Err(if atr_records == 0 {
                        TraceError::AtrMustBeFirst
                    } else {
                        TraceError::DuplicateAtr
                    });
                }
                // `decode` already requires nonempty mock record bytes. This
                // upper ingestion control belongs only to this invocation;
                // it is not a card, APDU, session, or product limit.
                if bytes.len() > limits.max_atr_bytes {
                    return Err(TraceError::InvalidAtrLength);
                }
                atr_records += 1;
            }
            "PROTOCOL" => {
                if atr_records == 0 {
                    return Err(TraceError::ProtocolBeforeAtr);
                }
                protocol_records += 1;
            }
            "APDU_TX" | "APDU_RX" => return Err(TraceError::ApduRecordNotAuthorized),
            _ => return Err(TraceError::InvalidRecord),
        }
    }
    if atr_records != 1 {
        return Err(TraceError::AtrMustBeFirst);
    }
    if protocol_records == 0 {
        return Err(TraceError::ProtocolMissing);
    }
    Ok(TraceSummary {
        mode,
        records: records.len(),
        atr_records,
        protocol_records,
        apdu_commands: 0,
        apdu_responses: 0,
        expected_filename,
        raw_artifact_sha256,
    })
}
