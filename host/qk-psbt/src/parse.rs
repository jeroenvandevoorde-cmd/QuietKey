//! Bounded structural parse of one immutable PSBT v0 buffer.

use crate::error::{ParseError, RejectCategory};
use crate::limits;
use crate::raw::{decode_compact_size, decode_record, Item, RawRecord, Records, Span};

/// Where the assembled input bytes came from; selects the byte cap.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InputSource {
    /// microSD artifact: capped at [`limits::MAX_SD_INPUT_BYTES`].
    MicroSd,
    /// Assembled QR payload: capped at [`limits::MAX_QR_INPUT_BYTES`].
    Qr,
}

impl InputSource {
    /// Byte cap for this source.
    #[must_use]
    pub const fn max_bytes(self) -> usize {
        match self {
            Self::MicroSd => limits::MAX_SD_INPUT_BYTES,
            Self::Qr => limits::MAX_QR_INPUT_BYTES,
        }
    }
}

/// Structural facts about the unsigned transaction: its byte range and
/// the input/output counts that fix the expected map counts.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct UnsignedTxSummary {
    /// Value byte range of the unsigned transaction record.
    pub span: Span,
    /// Declared transaction input count (<= `limits::MAX_INPUTS`).
    pub input_count: usize,
    /// Declared transaction output count (<= `limits::MAX_OUTPUTS`).
    pub output_count: usize,
}

/// Parsed structural view over one borrowed immutable buffer.
/// Persistent metadata is bounded to the global/input/output map ranges
/// plus [`UnsignedTxSummary`]; records are re-walked on demand as views.
#[derive(Debug)]
pub struct PsbtView<'a> {
    buf: &'a [u8],
    unsigned_tx: UnsignedTxSummary,
    global_map: Span,
    input_maps: Vec<Span>,
    output_maps: Vec<Span>,
}

impl<'a> PsbtView<'a> {
    /// The borrowed input buffer.
    #[must_use]
    pub const fn buffer(&self) -> &'a [u8] {
        self.buf
    }

    /// Structural unsigned-transaction facts.
    #[must_use]
    pub const fn unsigned_tx(&self) -> UnsignedTxSummary {
        self.unsigned_tx
    }

    /// Unsigned transaction bytes (empty only if the span is invalid,
    /// which validation excludes).
    #[must_use]
    pub fn unsigned_tx_bytes(&self) -> &'a [u8] {
        self.unsigned_tx.span.slice(self.buf).unwrap_or(&[])
    }

    /// Byte range of the global map (records plus separator).
    #[must_use]
    pub const fn global_map_span(&self) -> Span {
        self.global_map
    }

    /// Number of input maps (equals the transaction input count).
    #[must_use]
    pub fn input_map_count(&self) -> usize {
        self.input_maps.len()
    }

    /// Number of output maps (equals the transaction output count).
    #[must_use]
    pub fn output_map_count(&self) -> usize {
        self.output_maps.len()
    }

    /// Byte range of input map `i`.
    #[must_use]
    pub fn input_map_span(&self, i: usize) -> Option<Span> {
        self.input_maps.get(i).copied()
    }

    /// Byte range of output map `i`.
    #[must_use]
    pub fn output_map_span(&self, i: usize) -> Option<Span> {
        self.output_maps.get(i).copied()
    }

    /// Iterate the global map records verbatim.
    #[must_use]
    pub fn global_records(&self) -> Records<'a> {
        Records::new(self.buf, self.global_map)
    }

    /// Iterate the records of input map `i` verbatim.
    #[must_use]
    pub fn input_records(&self, i: usize) -> Option<Records<'a>> {
        Some(Records::new(self.buf, self.input_map_span(i)?))
    }

    /// Iterate the records of output map `i` verbatim.
    #[must_use]
    pub fn output_records(&self, i: usize) -> Option<Records<'a>> {
        Some(Records::new(self.buf, self.output_map_span(i)?))
    }
}

/// Ephemeral fallible duplicate set of borrowed complete-key slices.
/// Keys are appended as the map is walked (O(1) amortized, fallible),
/// then checked once at map completion by sorting and comparing
/// adjacent entries — O(n log n) total, never quadratic. Cleared per
/// map; allocation failure is a clean rejection.
struct DupSet<'a> {
    entries: Vec<(&'a [u8], usize)>,
}

impl<'a> DupSet<'a> {
    const fn new() -> Self {
        Self {
            entries: Vec::new(),
        }
    }

    fn clear(&mut self) {
        self.entries.clear();
    }

    /// Append one complete raw key with its offset; no search here.
    fn record(&mut self, key: &'a [u8], offset: usize) -> Result<(), ParseError> {
        self.entries
            .try_reserve(1)
            .map_err(|_| ParseError::new(RejectCategory::AllocationFailed, offset))?;
        self.entries.push((key, offset));
        Ok(())
    }

    /// Check at map completion: sort by (key, offset), then any
    /// adjacent pair with equal key bytes is a duplicate; report the
    /// later occurrence's offset.
    fn check(&mut self) -> Result<(), ParseError> {
        self.entries.sort_unstable();
        for (a, b) in self.entries.iter().zip(self.entries.iter().skip(1)) {
            if a.0 == b.0 {
                return Err(ParseError::new(RejectCategory::DuplicateKey, b.1));
            }
        }
        Ok(())
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Scope {
    Global,
    Input,
    Output,
}

/// Cursor bounded to one value range; overruns are structural errors
/// with the supplied category.
struct Cursor<'a> {
    buf: &'a [u8],
    pos: usize,
    end: usize,
    overrun: RejectCategory,
}

impl<'a> Cursor<'a> {
    const fn new(buf: &'a [u8], span: Span, overrun: RejectCategory) -> Self {
        Self {
            buf,
            pos: span.start,
            end: span.end,
            overrun,
        }
    }

    fn take(&mut self, n: usize) -> Result<Span, ParseError> {
        let err = ParseError::new(self.overrun, self.pos);
        let next = self.pos.checked_add(n).ok_or(err)?;
        if next > self.end {
            return Err(err);
        }
        let span = Span {
            start: self.pos,
            end: next,
        };
        self.pos = next;
        Ok(span)
    }

    fn compact_size(&mut self) -> Result<u64, ParseError> {
        let window = self
            .buf
            .get(self.pos..self.end)
            .ok_or(ParseError::new(self.overrun, self.pos))?;
        let (v, sz) = decode_compact_size(window, 0).map_err(|e| match e.category {
            RejectCategory::Truncated => ParseError::new(self.overrun, self.pos),
            c => ParseError::new(c, self.pos.saturating_add(e.offset)),
        })?;
        self.pos = self.pos.saturating_add(sz);
        Ok(v)
    }

    fn peek(&self) -> Option<u8> {
        if self.pos < self.end {
            self.buf.get(self.pos).copied()
        } else {
            None
        }
    }

    fn at_end(&self) -> bool {
        self.pos == self.end
    }
}

/// Parse the unsigned transaction value only as far as necessary to
/// validate its structure and derive the input/output map counts.
fn parse_unsigned_tx(buf: &[u8], value: Span) -> Result<UnsignedTxSummary, ParseError> {
    let malformed = RejectCategory::MalformedUnsignedTx;
    let mut c = Cursor::new(buf, value, malformed);
    c.take(4)?; // version
    let count_pos = c.pos;
    let input_count = c.compact_size()?;
    if input_count == 0 {
        if c.peek() == Some(0x01) {
            return Err(ParseError::new(
                RejectCategory::UnsignedTxWitnessFormat,
                count_pos,
            ));
        }
        return Err(ParseError::new(
            RejectCategory::UnsignedTxZeroInputs,
            count_pos,
        ));
    }
    if input_count > limits::MAX_INPUTS as u64 {
        return Err(ParseError::new(RejectCategory::TooManyInputs, count_pos));
    }
    let input_count = usize::try_from(input_count)
        .map_err(|_| ParseError::new(RejectCategory::TooManyInputs, count_pos))?;
    for _ in 0..input_count {
        c.take(32)?; // previous txid
        c.take(4)?; // previous vout
        let script_pos = c.pos;
        let script_len = c.compact_size()?;
        if script_len != 0 {
            return Err(ParseError::new(
                RejectCategory::UnsignedTxScriptSigNotEmpty,
                script_pos,
            ));
        }
        c.take(4)?; // sequence
    }
    let out_pos = c.pos;
    let output_count = c.compact_size()?;
    if output_count == 0 {
        return Err(ParseError::new(
            RejectCategory::UnsignedTxZeroOutputs,
            out_pos,
        ));
    }
    if output_count > limits::MAX_OUTPUTS as u64 {
        return Err(ParseError::new(RejectCategory::TooManyOutputs, out_pos));
    }
    let output_count = usize::try_from(output_count)
        .map_err(|_| ParseError::new(RejectCategory::TooManyOutputs, out_pos))?;
    for _ in 0..output_count {
        c.take(8)?; // amount
        let script_pos = c.pos;
        let script_len = c.compact_size()?;
        // Candidate per-output scriptPubKey cap, checked after the
        // minimal length decode and before conversion or slicing.
        if script_len > limits::MAX_TX_OUTPUT_SCRIPT_BYTES as u64 {
            return Err(ParseError::new(
                RejectCategory::TxOutputScriptTooLong,
                script_pos,
            ));
        }
        let script_len =
            usize::try_from(script_len).map_err(|_| ParseError::new(malformed, c.pos))?;
        c.take(script_len)?;
    }
    c.take(4)?; // locktime
    if !c.at_end() {
        return Err(ParseError::new(malformed, c.pos));
    }
    Ok(UnsignedTxSummary {
        span: value,
        input_count,
        output_count,
    })
}

/// Structural check of a witness UTXO value: 8-byte amount, minimal
/// CompactSize script length, script bytes, nothing else.
fn check_witness_utxo(buf: &[u8], value: Span) -> Result<(), ParseError> {
    let bad = RejectCategory::InvalidValueStructure;
    let mut c = Cursor::new(buf, value, bad);
    c.take(8)?;
    let script_len = c.compact_size()?;
    let script_len = usize::try_from(script_len).map_err(|_| ParseError::new(bad, c.pos))?;
    c.take(script_len)?;
    if !c.at_end() {
        return Err(ParseError::new(bad, c.pos));
    }
    Ok(())
}

/// Structural check of a BIP32 derivation value: 4-byte fingerprint
/// plus whole 4-byte path elements, depth capped.
fn check_bip32_value(r: &RawRecord) -> Result<(), ParseError> {
    let len = r.value.len();
    let rest = len.checked_sub(4).ok_or(ParseError::new(
        RejectCategory::InvalidValueStructure,
        r.value.start,
    ))?;
    if rest % 4 != 0 {
        return Err(ParseError::new(
            RejectCategory::InvalidValueStructure,
            r.value.start,
        ));
    }
    if rest / 4 > limits::MAX_PATH_DEPTH {
        return Err(ParseError::new(RejectCategory::PathTooDeep, r.value.start));
    }
    Ok(())
}

fn require_empty_key_data(r: &RawRecord) -> Result<(), ParseError> {
    if r.key_data.is_empty() {
        Ok(())
    } else {
        Err(ParseError::new(
            RejectCategory::InvalidKeyStructure,
            r.key_data.start,
        ))
    }
}

fn require_pubkey_key_data(r: &RawRecord) -> Result<(), ParseError> {
    let n = r.key_data.len();
    if n == 33 || n == 65 {
        Ok(())
    } else {
        Err(ParseError::new(
            RejectCategory::InvalidKeyStructure,
            r.key_data.start,
        ))
    }
}

fn bump_signer_count(count: &mut usize, offset: usize) -> Result<(), ParseError> {
    *count = count.saturating_add(1);
    if *count > limits::MAX_SIGNERS {
        return Err(ParseError::new(RejectCategory::TooManySigners, offset));
    }
    Ok(())
}

struct MapResult {
    span: Span,
    next: usize,
    unsigned_tx: Option<UnsignedTxSummary>,
}

/// Walk one map: enforce duplicate-key rejection over complete raw
/// keys, scope policy, and structural rules. Preserved unknown and
/// proprietary records pass through untouched.
fn walk_map<'a>(
    buf: &'a [u8],
    start: usize,
    scope: Scope,
    dup: &mut DupSet<'a>,
) -> Result<MapResult, ParseError> {
    dup.clear();
    let mut pos = start;
    let mut unsigned_tx: Option<UnsignedTxSummary> = None;
    // One shared cap for all signer-bearing records in this map:
    // global xpubs, input partial signatures, and input/output BIP32
    // derivations all count against the same per-map limit.
    let mut signers: usize = 0;
    // Candidate per-map record cap: every non-separator record counts
    // — known, unknown, proprietary, and the required global
    // unsigned-transaction record — and the count resets per map. It
    // is checked before duplicate-set insertion and scope/type
    // validation, is not an aggregate cap, and does not replace the
    // separate shared signer cap.
    let mut records: usize = 0;
    loop {
        match decode_record(buf, pos)? {
            Item::Separator { end } => {
                dup.check()?;
                if scope == Scope::Global && unsigned_tx.is_none() {
                    return Err(ParseError::new(RejectCategory::MissingUnsignedTx, start));
                }
                return Ok(MapResult {
                    span: Span { start, end },
                    next: end,
                    unsigned_tx,
                });
            }
            Item::Record(r) => {
                records = records.saturating_add(1);
                if records > limits::MAX_RECORDS_PER_MAP {
                    return Err(ParseError::new(
                        RejectCategory::TooManyRecords,
                        r.full_key.start,
                    ));
                }
                let key = r
                    .full_key
                    .slice(buf)
                    .ok_or(ParseError::new(RejectCategory::Truncated, r.full_key.start))?;
                dup.record(key, r.full_key.start)?;
                match scope {
                    Scope::Global => match r.key_type {
                        0x00 => {
                            require_empty_key_data(&r)?;
                            // Parse structurally even when this is a
                            // duplicate; the duplicate complete raw
                            // key is rejected by the map-completion
                            // check, so structural categories keep
                            // precedence over `DuplicateKey`.
                            let summary = parse_unsigned_tx(buf, r.value)?;
                            if unsigned_tx.is_none() {
                                unsigned_tx = Some(summary);
                            }
                        }
                        0x01 => {
                            // Global xpub: 78-byte xpub key data,
                            // fingerprint-plus-path value.
                            if r.key_data.len() != 78 {
                                return Err(ParseError::new(
                                    RejectCategory::InvalidKeyStructure,
                                    r.key_data.start,
                                ));
                            }
                            check_bip32_value(&r)?;
                            bump_signer_count(&mut signers, r.full_key.start)?;
                        }
                        0x02..=0x06 => {
                            return Err(ParseError::new(
                                RejectCategory::V2GlobalField,
                                r.full_key.start,
                            ));
                        }
                        0xfb => {
                            // Explicit v0 version field: empty key
                            // data, exactly four little-endian value
                            // bytes, value zero. Omission stays legal.
                            require_empty_key_data(&r)?;
                            if r.value.len() != 4 {
                                return Err(ParseError::new(
                                    RejectCategory::InvalidValueStructure,
                                    r.value.start,
                                ));
                            }
                            if r.value.slice(buf) != Some(&[0, 0, 0, 0]) {
                                return Err(ParseError::new(
                                    RejectCategory::UnsupportedPsbtVersion,
                                    r.value.start,
                                ));
                            }
                        }
                        // 0xfc (proprietary) and all other types:
                        // preserved verbatim as views.
                        _ => {}
                    },
                    Scope::Input => match r.key_type {
                        0x00 => require_empty_key_data(&r)?, // non-witness utxo (opaque)
                        0x01 => {
                            require_empty_key_data(&r)?;
                            check_witness_utxo(buf, r.value)?;
                        }
                        0x02 => {
                            require_pubkey_key_data(&r)?;
                            if r.value.is_empty() {
                                return Err(ParseError::new(
                                    RejectCategory::InvalidValueStructure,
                                    r.value.start,
                                ));
                            }
                            bump_signer_count(&mut signers, r.full_key.start)?;
                        }
                        0x03 => {
                            require_empty_key_data(&r)?;
                            if r.value.len() != 4 {
                                return Err(ParseError::new(
                                    RejectCategory::InvalidValueStructure,
                                    r.value.start,
                                ));
                            }
                        }
                        0x04 | 0x05 | 0x07 | 0x08 => require_empty_key_data(&r)?,
                        0x06 => {
                            require_pubkey_key_data(&r)?;
                            check_bip32_value(&r)?;
                            bump_signer_count(&mut signers, r.full_key.start)?;
                        }
                        0x13..=0x18 => {
                            return Err(ParseError::new(
                                RejectCategory::TaprootField,
                                r.full_key.start,
                            ));
                        }
                        // 0x09-0x0d (hash preimages, POR), 0x0e-0x12
                        // (BIP-370 input-only numbers, opaque preserved
                        // unknowns per QK-DEC-030), 0xfc proprietary,
                        // and unknown types: preserved verbatim.
                        _ => {}
                    },
                    Scope::Output => match r.key_type {
                        0x00 | 0x01 => require_empty_key_data(&r)?,
                        0x02 => {
                            require_pubkey_key_data(&r)?;
                            check_bip32_value(&r)?;
                            bump_signer_count(&mut signers, r.full_key.start)?;
                        }
                        0x05..=0x07 => {
                            return Err(ParseError::new(
                                RejectCategory::TaprootField,
                                r.full_key.start,
                            ));
                        }
                        // 0x03/0x04 (BIP-370 output-only numbers, opaque
                        // preserved unknowns per QK-DEC-030), 0xfc
                        // proprietary, and unknown types: preserved.
                        _ => {}
                    },
                }
                pos = r.end;
            }
        }
    }
}

/// Parse one immutable buffer as a PSBT v0 container under the declared
/// input source cap. Read-only, bounded, panic-free; returns either a
/// borrowed structural view or one stable rejection category.
pub fn parse(buf: &[u8], source: InputSource) -> Result<PsbtView<'_>, ParseError> {
    if buf.len() > source.max_bytes() {
        return Err(ParseError::new(
            RejectCategory::InputTooLarge,
            source.max_bytes(),
        ));
    }
    const MAGIC: [u8; 5] = [0x70, 0x73, 0x62, 0x74, 0xff];
    match buf.get(0..5) {
        None => return Err(ParseError::new(RejectCategory::Truncated, buf.len())),
        Some(head) if head != MAGIC => {
            return Err(ParseError::new(RejectCategory::InvalidMagic, 0));
        }
        Some(_) => {}
    }
    let mut dup = DupSet::new();
    let global = walk_map(buf, 5, Scope::Global, &mut dup)?;
    let unsigned_tx = global
        .unsigned_tx
        .ok_or(ParseError::new(RejectCategory::MissingUnsignedTx, 5))?;
    let mut input_maps: Vec<Span> = Vec::new();
    input_maps
        .try_reserve_exact(unsigned_tx.input_count)
        .map_err(|_| ParseError::new(RejectCategory::AllocationFailed, global.next))?;
    let mut output_maps: Vec<Span> = Vec::new();
    output_maps
        .try_reserve_exact(unsigned_tx.output_count)
        .map_err(|_| ParseError::new(RejectCategory::AllocationFailed, global.next))?;
    let mut pos = global.next;
    for _ in 0..unsigned_tx.input_count {
        if pos >= buf.len() {
            return Err(ParseError::new(RejectCategory::InvalidMapCount, pos));
        }
        let m = walk_map(buf, pos, Scope::Input, &mut dup)?;
        input_maps.push(m.span);
        pos = m.next;
    }
    for _ in 0..unsigned_tx.output_count {
        if pos >= buf.len() {
            return Err(ParseError::new(RejectCategory::InvalidMapCount, pos));
        }
        let m = walk_map(buf, pos, Scope::Output, &mut dup)?;
        output_maps.push(m.span);
        pos = m.next;
    }
    if pos != buf.len() {
        return Err(ParseError::new(RejectCategory::TrailingBytes, pos));
    }
    Ok(PsbtView {
        buf,
        unsigned_tx,
        global_map: global.span,
        input_maps,
        output_maps,
    })
}
