//! M6 bounded HOST-only semantic-subset analyzer (QK-DEC-037,
//! QK-DEC-038, QK-DEC-039; recorded under the QK-DEC-034 process).
//!
//! This module extracts a STRUCTURAL CANDIDATE view of one already
//! structurally parsed PSBT v0. It performs no cryptographic
//! signature verification, no signing, no curve arithmetic, and no
//! policy evaluation. Nothing here decides validity, signability,
//! completeness, or exportability; every "candidate" fact is a
//! deferred claim that requires future cryptographic verification.
//! Analysis is read-only over the borrowed buffer, bounded by the
//! QK-DEC-039 candidate caps, deterministic, and fail-closed: the
//! first violation in the frozen precedence order below is the
//! result.
//!
//! Frozen deterministic precedence: existing PSBT structural parse
//! (before this module runs); full unsigned-transaction facts plus
//! duplicate-outpoint rejection; inputs in ascending order (missing
//! prevtx / prevtx parse and caps -> txid match -> vout range ->
//! selected amount and running input total -> witness-utxo equality);
//! unsigned outputs, totals, and fee; per-input signature and sighash
//! checks plus witness-script form; script token iteration.
//!
//! M8 (QK-DEC-044..046) adds one separate read-only entrypoint,
//! [`analyze_and_verify_signatures`], which upgrades the M6
//! structural signature candidates to cryptographically verified
//! facts through the qk-secp verification boundary and the bounded
//! [`crate::bip143`] digest engine. The M6 entrypoint, output, and
//! legacy precedence are preserved unchanged; the shared private
//! phases below were extracted verbatim. Frozen M8 precedence: the
//! M6 structural stages, then per input ascending the M8
//! pre-verification screen (missing witnessScript -> unsupported
//! final-script fields -> malformed witnessScript push -> actual
//! OP_CODESEPARATOR opcode by parsed opcode semantics, which in M8
//! precedes any sighash classification -> canonical multisig form ->
//! exact native P2WSH commitment -> redeem-script route), then the
//! unchanged M6 signature/sighash and script-token stages, then per
//! input ascending the cryptographic stage (digest once per input;
//! per signature in map order: witnessScript membership -> pubkey
//! curve validity -> trailing sighash byte -> DER-only signature
//! parse -> digest verification). Any invalid signature rejects the
//! whole verified result. Verified statuses and the
//! VERIFY_AND_EXPORT_ONLY disposition are returned facts only: no
//! export is performed or authorized, and no later S4/S7,
//! ownership, or change check is bypassed.

use crate::bip143::{
    sighash_all_digest, Bip143Error, Bip143InputFacts, Bip143PrecomputeBuilder, SIGHASH_ALL,
};
use crate::limits;
use crate::parse::PsbtView;
use crate::raw::{decode_compact_size, Span};
use crate::sha256::{sha256, sha256d};
use core::fmt;

/// MoneyRange upper bound in satoshis (Bitcoin Core `MAX_MONEY`),
/// applied to every used amount and running total: `0..=MAX_MONEY`.
const MAX_MONEY_SATS: u64 = 2_100_000_000_000_000;

/// Low-S inclusive upper bound (BIP146 `LOW_S_MAX`), big-endian.
const LOW_S_MAX: [u8; 32] = [
    0x7f, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0x5d, 0x57, 0x6e, 0x73, 0x57, 0xa4, 0x50, 0x1d, 0xdf, 0xe9, 0x2f, 0x46, 0x68, 0x1b, 0x20, 0xa0,
];

/// Stable semantic rejection category. Fail-closed; no category ever
/// carries attacker-controlled bytes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum SemanticCategory {
    /// Prevtx declares more inputs than `limits::MAX_PREVTX_INPUTS`.
    PrevTxTooManyInputs,
    /// Prevtx declares more outputs than `limits::MAX_PREVTX_OUTPUTS`.
    PrevTxTooManyOutputs,
    /// A prevtx scriptSig or scriptPubKey exceeds
    /// `limits::MAX_PREVTX_SCRIPT_BYTES`.
    PrevTxScriptTooLong,
    /// A prevtx input declares more witness items than
    /// `limits::MAX_PREVTX_WITNESS_ITEMS`.
    PrevTxTooManyWitnessItems,
    /// A prevtx witness item exceeds
    /// `limits::MAX_PREVTX_WITNESS_ITEM_BYTES`.
    PrevTxWitnessItemTooLong,
    /// The prevtx witness section is structurally malformed.
    PrevTxWitnessMalformed,
    /// The prevtx carries a witness marker with a flag other than 0x01.
    PrevTxWitnessUnsupportedFlag,
    /// The prevtx uses witness serialization although every input
    /// witness stack is empty.
    PrevTxWitnessSuperfluous,
    /// The prevtx is otherwise structurally malformed (truncation,
    /// non-minimal CompactSize, zero inputs or outputs, trailing
    /// bytes).
    PrevTxMalformed,
    /// A script push declares more bytes than remain in the script.
    MalformedScriptPush,
    /// An input has no non_witness_utxo previous transaction.
    MissingPrevTx,
    /// The prevtx double-SHA256 does not equal the 32 wire outpoint
    /// txid bytes of the unsigned transaction input.
    PrevTxIdMismatch,
    /// The outpoint vout does not index an output of the prevtx.
    VoutOutOfRange,
    /// A witness_utxo record is not byte-equal (amount and
    /// scriptPubKey) to the selected prevtx output (QK-DEC-032).
    WitnessUtxoMismatch,
    /// Two unsigned-transaction inputs spend the same outpoint.
    DuplicateOutpoint,
    /// An amount or running total exceeds MoneyRange
    /// (`0..=2_100_000_000_000_000` sats).
    MoneyRangeExceeded,
    /// Checked arithmetic on amounts overflowed.
    ValueOverflow,
    /// Total output amount exceeds total input amount.
    NegativeFee,
    /// A sighash record or signature trailing byte is anything other
    /// than SIGHASH_ALL (1).
    UnsupportedSighash,
    /// A partial-signature pubkey is not exactly 33 bytes beginning
    /// 0x02 or 0x03.
    CompressedPubkeySyntax,
    /// A partial signature is not strict BIP66 DER with a trailing
    /// sighash byte.
    StrictDer,
    /// A partial-signature S value exceeds the BIP146 low-S bound.
    HighS,
    /// A witnessScript is not exact canonical small-integer m-of-n
    /// compressed-pubkey CHECKMULTISIG under `limits::MAX_SIGNERS`.
    WitnessScriptForm,
    /// A bounded result allocation failed.
    AllocationFailed,
    /// Hash length accounting failed.
    HashFailure,
    /// An internal invariant guaranteed by the structural parser did
    /// not hold.
    InternalInvariant,
    /// M8: an input has no witnessScript record, so no signature
    /// verification is possible.
    MissingWitnessScript,
    /// M8: final-script fields (final_scriptSig, final_scriptwitness)
    /// are unsupported by signature verification.
    UnsupportedFinalScriptFields,
    /// M8: a redeem-script record (wrapped route) is unsupported by
    /// signature verification.
    UnsupportedRedeemScriptRoute,
    /// M8: the witnessScript contains an actual OP_CODESEPARATOR
    /// opcode (parsed opcode semantics; a pushed 0xAB data byte never
    /// matches).
    UnsupportedCodeSeparator,
    /// M8: the selected prevout scriptPubKey is not the exact native
    /// P2WSH commitment `00 20 SHA256(witnessScript)`.
    PrevoutNotNativeWitnessScriptHash,
    /// M8: a partial-signature map pubkey is not a member of the
    /// input's witnessScript key set. Never ignored.
    PartialSignaturePubkeyNotInWitnessScript,
    /// M8: a partial-signature map pubkey is not a cryptographically
    /// valid compressed curve point.
    InvalidCryptographicPubkey,
    /// M8: a partial signature failed cryptographic parsing or
    /// verification against the computed BIP143 SIGHASH_ALL digest.
    SignatureVerificationFailed,
    /// M8: the cryptographic backend or digest engine reported an
    /// unexpected condition; fails closed.
    CryptographicBackendInvariant,
}

impl fmt::Display for SemanticCategory {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let s = match self {
            Self::PrevTxTooManyInputs => "prevtx exceeds input cap",
            Self::PrevTxTooManyOutputs => "prevtx exceeds output cap",
            Self::PrevTxScriptTooLong => "prevtx script exceeds byte cap",
            Self::PrevTxTooManyWitnessItems => "prevtx exceeds witness item cap",
            Self::PrevTxWitnessItemTooLong => "prevtx witness item exceeds byte cap",
            Self::PrevTxWitnessMalformed => "prevtx witness section malformed",
            Self::PrevTxWitnessUnsupportedFlag => "prevtx witness flag unsupported",
            Self::PrevTxWitnessSuperfluous => "prevtx witness serialization superfluous",
            Self::PrevTxMalformed => "prevtx malformed",
            Self::MalformedScriptPush => "script push malformed",
            Self::MissingPrevTx => "missing non_witness_utxo prevtx",
            Self::PrevTxIdMismatch => "prevtx txid mismatch",
            Self::VoutOutOfRange => "outpoint vout out of range",
            Self::WitnessUtxoMismatch => "witness utxo not equal to prevtx output",
            Self::DuplicateOutpoint => "duplicate outpoint",
            Self::MoneyRangeExceeded => "amount outside money range",
            Self::ValueOverflow => "amount arithmetic overflow",
            Self::NegativeFee => "outputs exceed inputs",
            Self::UnsupportedSighash => "unsupported sighash type",
            Self::CompressedPubkeySyntax => "invalid compressed pubkey syntax",
            Self::StrictDer => "signature not strict der",
            Self::HighS => "signature s value outside permitted low-s range",
            Self::WitnessScriptForm => "witness script not canonical multisig form",
            Self::AllocationFailed => "result allocation failed",
            Self::HashFailure => "hash length accounting failed",
            Self::InternalInvariant => "internal invariant violated",
            Self::MissingWitnessScript => "missing witness script for signature verification",
            Self::UnsupportedFinalScriptFields => {
                "final script fields unsupported for signature verification"
            }
            Self::UnsupportedRedeemScriptRoute => {
                "redeem script route unsupported for signature verification"
            }
            Self::UnsupportedCodeSeparator => "witness script contains code separator",
            Self::PrevoutNotNativeWitnessScriptHash => {
                "prevout not native witness script hash commitment"
            }
            Self::PartialSignaturePubkeyNotInWitnessScript => {
                "partial signature pubkey not in witness script"
            }
            Self::InvalidCryptographicPubkey => "pubkey not a valid curve point",
            Self::SignatureVerificationFailed => {
                "partial signature failed cryptographic verification"
            }
            Self::CryptographicBackendInvariant => "cryptographic backend invariant failed",
        };
        f.write_str(s)
    }
}

/// One semantic rejection: a stable category, the input index it was
/// detected in (`None` for global facts), and the byte offset in the
/// PSBT buffer. Display never includes attacker-controlled bytes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SemanticError {
    /// Stable semantic rejection category.
    pub category: SemanticCategory,
    /// Unsigned-transaction input index, when input-scoped.
    pub input_index: Option<usize>,
    /// Byte offset in the PSBT input buffer where detection occurred.
    pub offset: usize,
}

impl SemanticError {
    const fn global(category: SemanticCategory, offset: usize) -> Self {
        Self {
            category,
            input_index: None,
            offset,
        }
    }

    const fn at_input(category: SemanticCategory, input_index: usize, offset: usize) -> Self {
        Self {
            category,
            input_index: Some(input_index),
            offset,
        }
    }
}

impl fmt::Display for SemanticError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.input_index {
            Some(i) => write!(f, "{} (input {}) at byte {}", self.category, i, self.offset),
            None => write!(f, "{} at byte {}", self.category, self.offset),
        }
    }
}

impl std::error::Error for SemanticError {}

/// One script token: a data push (payload bytes) or a single opcode
/// byte. No policy meaning is attached to either.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ScriptToken<'a> {
    /// A direct push (0x01-0x4b) or OP_PUSHDATA1/2/4 payload.
    Push(&'a [u8]),
    /// Any other single opcode byte, verbatim.
    Opcode(u8),
}

/// A push whose declared length exceeds the remaining script bytes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MalformedPush {
    /// Offset of the push opcode within the script slice.
    pub offset: usize,
}

/// Zero-allocation full-consumption script token iterator. Handles
/// direct pushes and OP_PUSHDATA1/2/4 with checked lengths; imposes no
/// minimal-push or policy rule. After yielding an error it terminates.
#[derive(Debug, Clone)]
pub struct ScriptTokens<'a> {
    script: &'a [u8],
    pos: usize,
    failed: bool,
}

impl<'a> ScriptTokens<'a> {
    /// Start tokenizing one borrowed script.
    #[must_use]
    pub const fn new(script: &'a [u8]) -> Self {
        Self {
            script,
            pos: 0,
            failed: false,
        }
    }

    fn push(&mut self, opcode_at: usize, data_start: usize, len: usize) -> Option<ScriptToken<'a>> {
        let end = match data_start.checked_add(len) {
            Some(e) => e,
            None => {
                self.failed = true;
                self.pos = opcode_at;
                return None;
            }
        };
        match self.script.get(data_start..end) {
            Some(data) => {
                self.pos = end;
                Some(ScriptToken::Push(data))
            }
            None => {
                self.failed = true;
                self.pos = opcode_at;
                None
            }
        }
    }
}

impl<'a> Iterator for ScriptTokens<'a> {
    type Item = Result<ScriptToken<'a>, MalformedPush>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.failed || self.pos >= self.script.len() {
            return None;
        }
        let at = self.pos;
        let op = *self.script.get(at)?;
        let after = at.checked_add(1)?;
        let took = match op {
            0x01..=0x4b => self.push(at, after, usize::from(op)),
            0x4c => match self.script.get(after).copied() {
                Some(l) => self.push(at, after.checked_add(1)?, usize::from(l)),
                None => {
                    self.failed = true;
                    None
                }
            },
            0x4d => match self.script.get(after..after.checked_add(2)?) {
                Some([a, b]) => {
                    let l = usize::from(u16::from_le_bytes([*a, *b]));
                    self.push(at, after.checked_add(2)?, l)
                }
                _ => {
                    self.failed = true;
                    None
                }
            },
            0x4e => match self.script.get(after..after.checked_add(4)?) {
                Some([a, b, c, d]) => {
                    let declared = u32::from_le_bytes([*a, *b, *c, *d]);
                    match usize::try_from(declared) {
                        Ok(l) => self.push(at, after.checked_add(4)?, l),
                        Err(_) => {
                            self.failed = true;
                            None
                        }
                    }
                }
                _ => {
                    self.failed = true;
                    None
                }
            },
            _ => {
                self.pos = after;
                Some(ScriptToken::Opcode(op))
            }
        };
        match took {
            Some(t) => Some(Ok(t)),
            None => Some(Err(MalformedPush { offset: at })),
        }
    }
}

/// Exact canonical small-integer m-of-n compressed-pubkey
/// CHECKMULTISIG facts extracted from one witnessScript. STRUCTURAL
/// CANDIDATE ONLY: no key validity, no cryptographic meaning.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MultisigForm {
    /// Declared threshold m (1..=n).
    pub required_m: usize,
    /// Declared key count n (m..=`limits::MAX_SIGNERS`).
    pub total_n: usize,
}

/// Per-input structural signature candidate status. These are
/// deferred structural claims only; no status here means an input is
/// verified, signable, or complete.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InputSignatureStatus {
    /// No witnessScript record: no structural threshold analysis is
    /// possible and no candidate is claimed.
    WitnessScriptUnavailableNoStructuralCandidate,
    /// Fewer structurally valid partial-signature candidates than the
    /// witnessScript threshold m.
    BelowThresholdStructuralCandidate,
    /// At least m structurally valid partial-signature candidates
    /// exist. This is NOT validity, signability, or completeness;
    /// cryptographic verification remains mandatory and outside M6.
    ThresholdStructuralCandidateRequiresCryptographicVerification,
}

/// Borrowed per-input semantic candidate facts.
#[derive(Debug, Clone, Copy)]
pub struct InputSemanticFacts<'a> {
    /// 32 outpoint txid bytes exactly as on the wire (not reversed).
    pub outpoint_txid_wire: &'a [u8],
    /// Outpoint output index.
    pub outpoint_vout: u32,
    /// Input sequence number.
    pub sequence: u32,
    /// Amount of the selected prevtx output, in satoshis.
    pub prevout_amount: u64,
    /// scriptPubKey bytes of the selected prevtx output.
    pub prevout_script_pubkey: &'a [u8],
    /// Whether a witness_utxo record is present (and therefore checked
    /// byte-equal to the selected prevtx output per QK-DEC-032).
    pub witness_utxo_present: bool,
    /// Canonical m-of-n witnessScript form, when a witnessScript
    /// record is present.
    pub multisig_form: Option<MultisigForm>,
    /// Count of structurally valid partial signatures whose pubkey
    /// appears in the witnessScript. Structural candidates only.
    pub structural_signature_candidates: usize,
    /// Whether final-script fields (final_scriptSig or
    /// final_scriptwitness) are present. Their presence is surfaced
    /// as requiring future cryptographic verification and is never
    /// treated as completion.
    pub final_fields_require_cryptographic_verification: bool,
    /// Structural signature candidate status for this input.
    pub signature_status: InputSignatureStatus,
}

/// Borrowed per-output semantic candidate facts.
#[derive(Debug, Clone, Copy)]
pub struct OutputSemanticFacts<'a> {
    /// Output amount in satoshis (MoneyRange-checked).
    pub amount: u64,
    /// Output scriptPubKey bytes (token-iterated, full consumption).
    pub script_pubkey: &'a [u8],
}

/// The semantic-subset candidate result: borrowed checked
/// unsigned-transaction facts, selected prevouts, checked totals and
/// fee, script facts, and per-input structural signature candidate
/// status. Nothing here asserts validity, signability, completeness,
/// or exportability; cryptographic verification is deferred and
/// outside M6.
#[derive(Debug, Clone)]
pub struct SemanticCandidate<'a> {
    /// Unsigned-transaction version, little-endian decoded.
    pub version: u32,
    /// Unsigned-transaction locktime, little-endian decoded.
    pub locktime: u32,
    /// Per-input candidate facts, in unsigned-transaction order.
    pub inputs: Vec<InputSemanticFacts<'a>>,
    /// Per-output candidate facts, in unsigned-transaction order.
    pub outputs: Vec<OutputSemanticFacts<'a>>,
    /// Checked sum of selected prevout amounts (MoneyRange-checked).
    pub total_input_amount: u64,
    /// Checked sum of unsigned output amounts (MoneyRange-checked).
    pub total_output_amount: u64,
    /// `total_input_amount - total_output_amount` (checked).
    pub fee: u64,
}

/// Cursor over one absolute span of the PSBT buffer. All failures are
/// reported by the caller with an explicit category at `pos`.
struct TxCursor<'a> {
    buf: &'a [u8],
    pos: usize,
    end: usize,
}

impl<'a> TxCursor<'a> {
    const fn new(buf: &'a [u8], span: Span) -> Self {
        Self {
            buf,
            pos: span.start,
            end: span.end,
        }
    }

    fn take(&mut self, n: usize) -> Option<Span> {
        let next = self.pos.checked_add(n)?;
        if next > self.end {
            return None;
        }
        let span = Span {
            start: self.pos,
            end: next,
        };
        self.pos = next;
        Some(span)
    }

    fn bytes(&mut self, n: usize) -> Option<&'a [u8]> {
        let span = self.take(n)?;
        span.slice(self.buf)
    }

    fn u32_le(&mut self) -> Option<u32> {
        let b: [u8; 4] = self.bytes(4)?.try_into().ok()?;
        Some(u32::from_le_bytes(b))
    }

    fn u64_le(&mut self) -> Option<u64> {
        let b: [u8; 8] = self.bytes(8)?.try_into().ok()?;
        Some(u64::from_le_bytes(b))
    }

    /// Minimal CompactSize wholly inside the span; `None` on
    /// truncation, overrun, or non-minimal encoding.
    fn compact(&mut self) -> Option<u64> {
        let window = self.buf.get(self.pos..self.end)?;
        let (v, sz) = decode_compact_size(window, 0).ok()?;
        self.pos = self.pos.checked_add(sz)?;
        Some(v)
    }

    fn peek(&self) -> Option<u8> {
        if self.pos < self.end {
            self.buf.get(self.pos).copied()
        } else {
            None
        }
    }

    const fn at_end(&self) -> bool {
        self.pos == self.end
    }
}

struct UnsignedInputFacts {
    txid: Span,
    vout: u32,
    sequence: u32,
    outpoint_offset: usize,
}

struct UnsignedOutputFacts {
    amount: u64,
    amount_offset: usize,
    script: Span,
}

struct UnsignedFacts {
    version: u32,
    locktime: u32,
    inputs: Vec<UnsignedInputFacts>,
    outputs: Vec<UnsignedOutputFacts>,
}

fn reserve_exact<T>(v: &mut Vec<T>, n: usize, offset: usize) -> Result<(), SemanticError> {
    v.try_reserve_exact(n)
        .map_err(|_| SemanticError::global(SemanticCategory::AllocationFailed, offset))
}

/// Re-walk the already structurally validated unsigned transaction,
/// extracting facts. Any structural failure here is an internal
/// invariant violation, not a new rejection surface.
fn unsigned_facts(view: &PsbtView<'_>) -> Result<UnsignedFacts, SemanticError> {
    let span = view.unsigned_tx().span;
    let inv = SemanticError::global(SemanticCategory::InternalInvariant, span.start);
    let mut c = TxCursor::new(view.buffer(), span);
    let version = c.u32_le().ok_or(inv)?;
    let input_count = usize::try_from(c.compact().ok_or(inv)?).map_err(|_| inv)?;
    let mut inputs: Vec<UnsignedInputFacts> = Vec::new();
    reserve_exact(&mut inputs, input_count, span.start)?;
    for _ in 0..input_count {
        let outpoint_offset = c.pos;
        let txid = c.take(32).ok_or(inv)?;
        let vout = c.u32_le().ok_or(inv)?;
        let script_len = c.compact().ok_or(inv)?;
        if script_len != 0 {
            return Err(inv);
        }
        let sequence = c.u32_le().ok_or(inv)?;
        inputs.push(UnsignedInputFacts {
            txid,
            vout,
            sequence,
            outpoint_offset,
        });
    }
    let output_count = usize::try_from(c.compact().ok_or(inv)?).map_err(|_| inv)?;
    let mut outputs: Vec<UnsignedOutputFacts> = Vec::new();
    reserve_exact(&mut outputs, output_count, span.start)?;
    for _ in 0..output_count {
        let amount_offset = c.pos;
        let amount = c.u64_le().ok_or(inv)?;
        let script_len = usize::try_from(c.compact().ok_or(inv)?).map_err(|_| inv)?;
        let script = c.take(script_len).ok_or(inv)?;
        outputs.push(UnsignedOutputFacts {
            amount,
            amount_offset,
            script,
        });
    }
    let locktime = c.u32_le().ok_or(inv)?;
    if !c.at_end() {
        return Err(inv);
    }
    Ok(UnsignedFacts {
        version,
        locktime,
        inputs,
        outputs,
    })
}

/// Reject duplicate unsigned outpoints before any prevtx parsing.
/// Bounded O(n^2) over at most `limits::MAX_INPUTS` inputs; no
/// allocation.
fn check_duplicate_outpoints(
    buf: &[u8],
    inputs: &[UnsignedInputFacts],
) -> Result<(), SemanticError> {
    for (j, b) in inputs.iter().enumerate() {
        for a in inputs.get(..j).unwrap_or(&[]) {
            if a.vout == b.vout && a.txid.slice(buf) == b.txid.slice(buf) {
                return Err(SemanticError::at_input(
                    SemanticCategory::DuplicateOutpoint,
                    j,
                    b.outpoint_offset,
                ));
            }
        }
    }
    Ok(())
}

struct SelectedPrevout {
    amount: u64,
    amount_offset: usize,
    script: Span,
}

/// Streaming bounded parse of one previous transaction carried in a
/// non_witness_utxo value. Retains only the selected output; never
/// allocates. Computes the txid digest over the witness-stripped
/// serialization directly from spans.
fn parse_prevtx(
    buf: &[u8],
    value: Span,
    selected_vout: u32,
    input_index: usize,
) -> Result<([u8; 32], Option<SelectedPrevout>, u64), SemanticError> {
    let cat = |category: SemanticCategory, offset: usize| {
        SemanticError::at_input(category, input_index, offset)
    };
    let malformed = |c: &TxCursor<'_>| cat(SemanticCategory::PrevTxMalformed, c.pos.min(value.end));
    let mut c = TxCursor::new(buf, value);
    let version = c
        .take(4)
        .ok_or(cat(SemanticCategory::PrevTxMalformed, c.pos))?;
    // Witness marker/flag: accept exactly 00 01; a 0x00 first byte is
    // unambiguous because a legacy transaction cannot declare zero
    // inputs.
    let is_witness = if c.peek() == Some(0x00) {
        let marker_offset = c.pos;
        let pair = c
            .bytes(2)
            .ok_or(cat(SemanticCategory::PrevTxWitnessMalformed, marker_offset))?;
        if pair != [0x00, 0x01] {
            return Err(cat(
                SemanticCategory::PrevTxWitnessUnsupportedFlag,
                marker_offset,
            ));
        }
        true
    } else {
        false
    };
    let body_start = c.pos;
    let count_offset = c.pos;
    let input_count = c.compact().ok_or(malformed(&c))?;
    if input_count == 0 {
        return Err(cat(SemanticCategory::PrevTxMalformed, count_offset));
    }
    if input_count > limits::MAX_PREVTX_INPUTS as u64 {
        return Err(cat(SemanticCategory::PrevTxTooManyInputs, count_offset));
    }
    for _ in 0..input_count {
        c.take(36).ok_or(malformed(&c))?; // outpoint txid + vout
        let len_offset = c.pos;
        let script_len = c.compact().ok_or(malformed(&c))?;
        if script_len > limits::MAX_PREVTX_SCRIPT_BYTES as u64 {
            return Err(cat(SemanticCategory::PrevTxScriptTooLong, len_offset));
        }
        let script_len = usize::try_from(script_len).map_err(|_| malformed(&c))?;
        c.take(script_len).ok_or(malformed(&c))?;
        c.take(4).ok_or(malformed(&c))?; // sequence
    }
    let out_count_offset = c.pos;
    let output_count = c.compact().ok_or(malformed(&c))?;
    if output_count == 0 {
        return Err(cat(SemanticCategory::PrevTxMalformed, out_count_offset));
    }
    if output_count > limits::MAX_PREVTX_OUTPUTS as u64 {
        return Err(cat(
            SemanticCategory::PrevTxTooManyOutputs,
            out_count_offset,
        ));
    }
    let mut selected: Option<SelectedPrevout> = None;
    let mut j: u64 = 0;
    while j < output_count {
        let amount_offset = c.pos;
        let amount = c.u64_le().ok_or(malformed(&c))?;
        let len_offset = c.pos;
        let script_len = c.compact().ok_or(malformed(&c))?;
        if script_len > limits::MAX_PREVTX_SCRIPT_BYTES as u64 {
            return Err(cat(SemanticCategory::PrevTxScriptTooLong, len_offset));
        }
        let script_len = usize::try_from(script_len).map_err(|_| malformed(&c))?;
        let script = c.take(script_len).ok_or(malformed(&c))?;
        if j == u64::from(selected_vout) {
            selected = Some(SelectedPrevout {
                amount,
                amount_offset,
                script,
            });
        }
        j = j.saturating_add(1);
    }
    let body_end = c.pos;
    if is_witness {
        let witness_offset = c.pos;
        let wmal = |c: &TxCursor<'_>| {
            cat(
                SemanticCategory::PrevTxWitnessMalformed,
                c.pos.min(value.end),
            )
        };
        let mut any_nonempty = false;
        for _ in 0..input_count {
            let items_offset = c.pos;
            let item_count = c.compact().ok_or(wmal(&c))?;
            if item_count > limits::MAX_PREVTX_WITNESS_ITEMS as u64 {
                return Err(cat(
                    SemanticCategory::PrevTxTooManyWitnessItems,
                    items_offset,
                ));
            }
            if item_count > 0 {
                any_nonempty = true;
            }
            let mut k: u64 = 0;
            while k < item_count {
                let len_offset = c.pos;
                let item_len = c.compact().ok_or(wmal(&c))?;
                if item_len > limits::MAX_PREVTX_WITNESS_ITEM_BYTES as u64 {
                    return Err(cat(SemanticCategory::PrevTxWitnessItemTooLong, len_offset));
                }
                let item_len = usize::try_from(item_len).map_err(|_| wmal(&c))?;
                c.take(item_len).ok_or(wmal(&c))?;
                k = k.saturating_add(1);
            }
        }
        if !any_nonempty {
            return Err(cat(
                SemanticCategory::PrevTxWitnessSuperfluous,
                witness_offset,
            ));
        }
    }
    let locktime = c.take(4).ok_or(malformed(&c))?;
    if !c.at_end() {
        return Err(cat(SemanticCategory::PrevTxMalformed, c.pos));
    }
    let inv = cat(SemanticCategory::InternalInvariant, value.start);
    let version_bytes = version.slice(buf).ok_or(inv)?;
    let body_bytes = buf.get(body_start..body_end).ok_or(inv)?;
    let locktime_bytes = locktime.slice(buf).ok_or(inv)?;
    let txid = sha256d(&[version_bytes, body_bytes, locktime_bytes])
        .map_err(|_| cat(SemanticCategory::HashFailure, value.start))?;
    Ok((txid, selected, output_count))
}

/// Strict BIP66 DER check over a signature that includes its trailing
/// sighash byte. Returns the (start, len) of the S value within `sig`
/// on success; `None` means not strict DER.
fn strict_der_s_range(sig: &[u8]) -> Option<(usize, usize)> {
    let n = sig.len();
    if !(9..=73).contains(&n) {
        return None;
    }
    let b = |i: usize| sig.get(i).copied();
    if b(0)? != 0x30 {
        return None;
    }
    if usize::from(b(1)?) != n.checked_sub(3)? {
        return None;
    }
    if b(2)? != 0x02 {
        return None;
    }
    let len_r = usize::from(b(3)?);
    if len_r == 0 {
        return None;
    }
    if 5usize.checked_add(len_r)? >= n {
        return None;
    }
    if b(4)? & 0x80 != 0 {
        return None;
    }
    if len_r > 1 && b(4)? == 0x00 && b(5)? & 0x80 == 0 {
        return None;
    }
    let s_marker = 4usize.checked_add(len_r)?;
    if b(s_marker)? != 0x02 {
        return None;
    }
    let len_s = usize::from(b(s_marker.checked_add(1)?)?);
    if len_s == 0 {
        return None;
    }
    if len_r.checked_add(len_s)?.checked_add(7)? != n {
        return None;
    }
    let s_start = s_marker.checked_add(2)?;
    if b(s_start)? & 0x80 != 0 {
        return None;
    }
    if len_s > 1 && b(s_start)? == 0x00 && b(s_start.checked_add(1)?)? & 0x80 == 0 {
        return None;
    }
    Some((s_start, len_s))
}

/// QK-DEC-037 / BIP146 low-S: the big-endian S magnitude must lie in
/// `1..=LOW_S_MAX`. Zero magnitude fails closed before the size/bound
/// comparison; it never counts toward candidate status.
fn s_is_low(s: &[u8]) -> bool {
    let mut lead = 0usize;
    for byte in s {
        if *byte == 0 {
            lead = lead.saturating_add(1);
        } else {
            break;
        }
    }
    let rest = s.get(lead..).unwrap_or(&[]);
    if rest.is_empty() {
        return false;
    }
    if rest.len() > 32 {
        return false;
    }
    if rest.len() < 32 {
        return true;
    }
    rest <= LOW_S_MAX.as_slice()
}

/// Exact canonical form: OP_m, then n pushes of 33-byte compressed
/// keys (0x21 prefix, 0x02/0x03 first byte), then OP_n, then
/// OP_CHECKMULTISIG, full consumption, 1 <= m <= n <=
/// `limits::MAX_SIGNERS`.
fn parse_multisig_form(script: &[u8]) -> Option<MultisigForm> {
    let first = script.first().copied()?;
    if !(0x51..=0x60).contains(&first) {
        return None;
    }
    let m = usize::from(first.checked_sub(0x50)?);
    let mut pos = 1usize;
    let mut n_keys = 0usize;
    while script.get(pos).copied() == Some(0x21) {
        let key_start = pos.checked_add(1)?;
        let key_end = key_start.checked_add(33)?;
        let key = script.get(key_start..key_end)?;
        match key.first().copied() {
            Some(0x02 | 0x03) => {}
            _ => return None,
        }
        n_keys = n_keys.checked_add(1)?;
        if n_keys > limits::MAX_SIGNERS {
            return None;
        }
        pos = key_end;
    }
    let n_op = script.get(pos).copied()?;
    if !(0x51..=0x60).contains(&n_op) {
        return None;
    }
    let n = usize::from(n_op.checked_sub(0x50)?);
    if n != n_keys || m > n || n > limits::MAX_SIGNERS {
        return None;
    }
    pos = pos.checked_add(1)?;
    if script.get(pos).copied()? != 0xae {
        return None;
    }
    if pos.checked_add(1)? != script.len() {
        return None;
    }
    Some(MultisigForm {
        required_m: m,
        total_n: n,
    })
}

/// Whether `pubkey` appears among the 33-byte keys of an
/// already-form-checked canonical multisig witnessScript.
fn multisig_contains_key(script: &[u8], pubkey: &[u8]) -> bool {
    let mut pos = 1usize;
    while script.get(pos).copied() == Some(0x21) {
        let key_start = match pos.checked_add(1) {
            Some(v) => v,
            None => return false,
        };
        let key_end = match key_start.checked_add(33) {
            Some(v) => v,
            None => return false,
        };
        match script.get(key_start..key_end) {
            Some(key) if key == pubkey => return true,
            Some(_) => pos = key_end,
            None => return false,
        }
    }
    false
}

/// Full-consumption token walk of one script; the first malformed
/// push is the result.
fn check_script_tokens(
    script: &[u8],
    script_offset: usize,
    input_index: Option<usize>,
) -> Result<(), SemanticError> {
    for t in ScriptTokens::new(script) {
        if let Err(m) = t {
            return Err(SemanticError {
                category: SemanticCategory::MalformedScriptPush,
                input_index,
                offset: script_offset.saturating_add(m.offset),
            });
        }
    }
    Ok(())
}

fn money_checked(
    amount: u64,
    offset: usize,
    input_index: Option<usize>,
) -> Result<u64, SemanticError> {
    if amount > MAX_MONEY_SATS {
        return Err(SemanticError {
            category: SemanticCategory::MoneyRangeExceeded,
            input_index,
            offset,
        });
    }
    Ok(amount)
}

fn add_checked(
    total: u64,
    amount: u64,
    offset: usize,
    input_index: Option<usize>,
) -> Result<u64, SemanticError> {
    let next = total.checked_add(amount).ok_or(SemanticError {
        category: SemanticCategory::ValueOverflow,
        input_index,
        offset,
    })?;
    money_checked(next, offset, input_index)
}

struct InputWork<'a> {
    prevout_amount: u64,
    prevout_script: &'a [u8],
    prevout_script_offset: usize,
    witness_utxo_present: bool,
    multisig_form: Option<MultisigForm>,
    candidates: usize,
    final_fields: bool,
}

/// Shared M6 stage-1 state: checked unsigned-transaction facts,
/// per-input prevout work, and totals. Extracted verbatim from the
/// M6 analyzer so the M6 and M8 entrypoints share one implementation;
/// no M6 behavior changed.
struct AnalysisState<'a> {
    facts: UnsignedFacts,
    work: Vec<InputWork<'a>>,
    total_input: u64,
    total_output: u64,
    fee: u64,
}

/// Frozen M6 structural stages: unsigned-transaction facts, duplicate
/// outpoints, inputs ascending, unsigned outputs, totals, and fee.
fn structural_phase<'a>(view: &PsbtView<'a>) -> Result<AnalysisState<'a>, SemanticError> {
    let buf = view.buffer();
    let facts = unsigned_facts(view)?;
    check_duplicate_outpoints(buf, &facts.inputs)?;

    // Inputs ascending: missing/parse/caps -> txid -> vout -> amount
    // -> witness-utxo equality.
    let mut work: Vec<InputWork<'a>> = Vec::new();
    reserve_exact(&mut work, facts.inputs.len(), view.unsigned_tx().span.start)?;
    let mut total_input: u64 = 0;
    for (i, uin) in facts.inputs.iter().enumerate() {
        let map_start = view
            .input_map_span(i)
            .map(|s| s.start)
            .unwrap_or(uin.outpoint_offset);
        let records = view.input_records(i).ok_or(SemanticError::at_input(
            SemanticCategory::InternalInvariant,
            i,
            map_start,
        ))?;
        let mut non_witness_utxo = None;
        let mut witness_utxo = None;
        for r in records.clone() {
            match r.key_type {
                0x00 => non_witness_utxo = Some(r),
                0x01 => witness_utxo = Some(r),
                _ => {}
            }
        }
        let prev = non_witness_utxo.ok_or(SemanticError::at_input(
            SemanticCategory::MissingPrevTx,
            i,
            map_start,
        ))?;
        let (txid, selected, output_count) = parse_prevtx(buf, prev.value_span, uin.vout, i)?;
        let outpoint_txid = uin.txid.slice(buf).ok_or(SemanticError::at_input(
            SemanticCategory::InternalInvariant,
            i,
            uin.outpoint_offset,
        ))?;
        // Wire-order digest comparison: the 32 outpoint bytes are the
        // double-SHA256 exactly as serialized, never reversed.
        if txid.as_slice() != outpoint_txid {
            return Err(SemanticError::at_input(
                SemanticCategory::PrevTxIdMismatch,
                i,
                uin.outpoint_offset,
            ));
        }
        if u64::from(uin.vout) >= output_count {
            return Err(SemanticError::at_input(
                SemanticCategory::VoutOutOfRange,
                i,
                uin.outpoint_offset.saturating_add(32),
            ));
        }
        let sel = selected.ok_or(SemanticError::at_input(
            SemanticCategory::InternalInvariant,
            i,
            prev.value_span.start,
        ))?;
        money_checked(sel.amount, sel.amount_offset, Some(i))?;
        total_input = add_checked(total_input, sel.amount, sel.amount_offset, Some(i))?;
        let sel_script = sel.script.slice(buf).ok_or(SemanticError::at_input(
            SemanticCategory::InternalInvariant,
            i,
            sel.script.start,
        ))?;
        if let Some(w) = witness_utxo {
            // QK-DEC-032 byte equality: amount and scriptPubKey of the
            // witness_utxo must equal the selected prevtx output. The
            // witness_utxo value is one fully consumed TxOut; its
            // structure was already enforced by the parser.
            let wmis = SemanticError::at_input(
                SemanticCategory::WitnessUtxoMismatch,
                i,
                w.value_span.start,
            );
            let winv =
                SemanticError::at_input(SemanticCategory::InternalInvariant, i, w.value_span.start);
            let mut wc = TxCursor::new(buf, w.value_span);
            let w_amount = wc.u64_le().ok_or(winv)?;
            let w_script_len = usize::try_from(wc.compact().ok_or(winv)?).map_err(|_| winv)?;
            let w_script = wc.bytes(w_script_len).ok_or(winv)?;
            if !wc.at_end() {
                return Err(winv);
            }
            if w_amount != sel.amount || w_script != sel_script {
                return Err(wmis);
            }
        }
        work.push(InputWork {
            prevout_amount: sel.amount,
            prevout_script: sel_script,
            prevout_script_offset: sel.script.start,
            witness_utxo_present: witness_utxo.is_some(),
            multisig_form: None,
            candidates: 0,
            final_fields: false,
        });
    }

    // Unsigned outputs, totals, fee.
    let mut total_output: u64 = 0;
    for out in &facts.outputs {
        money_checked(out.amount, out.amount_offset, None)?;
        total_output = add_checked(total_output, out.amount, out.amount_offset, None)?;
    }
    let fee = total_input
        .checked_sub(total_output)
        .ok_or(SemanticError::global(
            SemanticCategory::NegativeFee,
            view.unsigned_tx().span.start,
        ))?;
    Ok(AnalysisState {
        facts,
        work,
        total_input,
        total_output,
        fee,
    })
}

/// Frozen M6 signature stage: sighash record, then partial signatures
/// in map order, then witnessScript form and candidate counting,
/// inputs ascending.
fn signature_phase(view: &PsbtView<'_>, work: &mut [InputWork<'_>]) -> Result<(), SemanticError> {
    // Signature and sighash checks, inputs ascending: sighash record,
    // then partial signatures in map order, then witnessScript form
    // and candidate counting.
    for (i, w) in work.iter_mut().enumerate() {
        let map_start = view.input_map_span(i).map(|s| s.start).unwrap_or(0);
        let records = view.input_records(i).ok_or(SemanticError::at_input(
            SemanticCategory::InternalInvariant,
            i,
            map_start,
        ))?;
        let mut witness_script = None;
        for r in records.clone() {
            match r.key_type {
                0x03 => {
                    // PSBT_IN_SIGHASH_TYPE: absent means SIGHASH_ALL;
                    // present must be the 4-byte little-endian value 1.
                    let b: [u8; 4] = r.value.try_into().map_err(|_| {
                        SemanticError::at_input(
                            SemanticCategory::InternalInvariant,
                            i,
                            r.value_span.start,
                        )
                    })?;
                    if u32::from_le_bytes(b) != u32::from(SIGHASH_ALL) {
                        return Err(SemanticError::at_input(
                            SemanticCategory::UnsupportedSighash,
                            i,
                            r.value_span.start,
                        ));
                    }
                }
                0x05 => witness_script = Some(r),
                0x07 | 0x08 => w.final_fields = true,
                _ => {}
            }
        }
        for r in records.clone() {
            if r.key_type != 0x02 {
                continue;
            }
            let key_ok =
                r.key_data.len() == 33 && matches!(r.key_data.first().copied(), Some(0x02 | 0x03));
            if !key_ok {
                return Err(SemanticError::at_input(
                    SemanticCategory::CompressedPubkeySyntax,
                    i,
                    r.key_data_span.start,
                ));
            }
            let (s_start, s_len) = strict_der_s_range(r.value).ok_or(SemanticError::at_input(
                SemanticCategory::StrictDer,
                i,
                r.value_span.start,
            ))?;
            let s_end = s_start.checked_add(s_len).ok_or(SemanticError::at_input(
                SemanticCategory::InternalInvariant,
                i,
                r.value_span.start,
            ))?;
            let s = r.value.get(s_start..s_end).ok_or(SemanticError::at_input(
                SemanticCategory::InternalInvariant,
                i,
                r.value_span.start,
            ))?;
            if !s_is_low(s) {
                return Err(SemanticError::at_input(
                    SemanticCategory::HighS,
                    i,
                    r.value_span.start,
                ));
            }
            let trailing_offset = r.value_span.end.saturating_sub(1);
            if r.value.last().copied() != Some(SIGHASH_ALL) {
                return Err(SemanticError::at_input(
                    SemanticCategory::UnsupportedSighash,
                    i,
                    trailing_offset,
                ));
            }
        }
        match witness_script {
            Some(ws) => {
                let form = parse_multisig_form(ws.value).ok_or(SemanticError::at_input(
                    SemanticCategory::WitnessScriptForm,
                    i,
                    ws.value_span.start,
                ))?;
                let mut candidates = 0usize;
                for r in records.clone() {
                    if r.key_type == 0x02 && multisig_contains_key(ws.value, r.key_data) {
                        candidates = candidates.saturating_add(1);
                    }
                }
                w.multisig_form = Some(form);
                w.candidates = candidates;
            }
            None => {
                w.multisig_form = None;
                w.candidates = 0;
            }
        }
    }
    Ok(())
}

/// Frozen M6 script-token stage, full consumption: unsigned output
/// scriptPubKeys, then selected prevout scriptPubKeys.
fn token_phase(view: &PsbtView<'_>, state: &AnalysisState<'_>) -> Result<(), SemanticError> {
    let buf = view.buffer();
    for out in &state.facts.outputs {
        let script = out.script.slice(buf).ok_or(SemanticError::global(
            SemanticCategory::InternalInvariant,
            out.script.start,
        ))?;
        check_script_tokens(script, out.script.start, None)?;
    }
    for (i, w) in state.work.iter().enumerate() {
        check_script_tokens(w.prevout_script, w.prevout_script_offset, Some(i))?;
    }
    Ok(())
}

/// Frozen M6 assembly of the candidate result.
fn assemble<'a>(
    view: &PsbtView<'a>,
    state: AnalysisState<'a>,
) -> Result<SemanticCandidate<'a>, SemanticError> {
    let buf = view.buffer();
    let mut inputs: Vec<InputSemanticFacts<'a>> = Vec::new();
    reserve_exact(&mut inputs, state.work.len(), view.unsigned_tx().span.start)?;
    for (uin, w) in state.facts.inputs.iter().zip(state.work.iter()) {
        let outpoint_txid_wire = uin.txid.slice(buf).ok_or(SemanticError::global(
            SemanticCategory::InternalInvariant,
            uin.outpoint_offset,
        ))?;
        let signature_status = match w.multisig_form {
            None => InputSignatureStatus::WitnessScriptUnavailableNoStructuralCandidate,
            Some(form) if w.candidates >= form.required_m => {
                InputSignatureStatus::ThresholdStructuralCandidateRequiresCryptographicVerification
            }
            Some(_) => InputSignatureStatus::BelowThresholdStructuralCandidate,
        };
        inputs.push(InputSemanticFacts {
            outpoint_txid_wire,
            outpoint_vout: uin.vout,
            sequence: uin.sequence,
            prevout_amount: w.prevout_amount,
            prevout_script_pubkey: w.prevout_script,
            witness_utxo_present: w.witness_utxo_present,
            multisig_form: w.multisig_form,
            structural_signature_candidates: w.candidates,
            final_fields_require_cryptographic_verification: w.final_fields,
            signature_status,
        });
    }
    let mut outputs: Vec<OutputSemanticFacts<'a>> = Vec::new();
    reserve_exact(
        &mut outputs,
        state.facts.outputs.len(),
        view.unsigned_tx().span.start,
    )?;
    for out in &state.facts.outputs {
        let script_pubkey = out.script.slice(buf).ok_or(SemanticError::global(
            SemanticCategory::InternalInvariant,
            out.script.start,
        ))?;
        outputs.push(OutputSemanticFacts {
            amount: out.amount,
            script_pubkey,
        });
    }
    Ok(SemanticCandidate {
        version: state.facts.version,
        locktime: state.facts.locktime,
        inputs,
        outputs,
        total_input_amount: state.total_input,
        total_output_amount: state.total_output,
        fee: state.fee,
    })
}

/// Analyze the M6 semantic subset of one structurally parsed PSBT v0.
///
/// STRUCTURAL CANDIDATE ANALYSIS ONLY. This function performs no
/// cryptographic signature verification, no signing, and no policy
/// evaluation; it never decides that a PSBT is valid, signable,
/// complete, or exportable, and it never changes parsing, rejection,
/// serialization, or any existing behavior. Every returned fact is a
/// deferred structural claim that requires future cryptographic
/// verification outside M6. Present final-script fields are surfaced
/// as requiring that future verification, never as completion.
///
/// Analysis is read-only over the borrowed buffer, bounded by the
/// QK-DEC-039 candidate caps, deterministic, and fail-closed with the
/// frozen precedence documented at module level.
///
/// # Errors
///
/// Returns the first [`SemanticError`] in the frozen precedence
/// order.
pub fn analyze_semantic_subset<'a>(
    view: &PsbtView<'a>,
) -> Result<SemanticCandidate<'a>, SemanticError> {
    let mut state = structural_phase(view)?;
    signature_phase(view, &mut state.work)?;
    token_phase(view, &state)?;
    assemble(view, state)
}

// ====================================================================
// M8 read-only cryptographic verification of existing signatures
// (QK-DEC-044, QK-DEC-045, QK-DEC-046; QK-DEC-033 enacted as a
// returned disposition only).
// ====================================================================

/// Defensive upper bound on qk-secp verification calls per analysis.
/// Derivation: at most `limits::MAX_INPUTS` (100) inputs, and per
/// input at most `limits::MAX_SIGNERS` (15) distinct witnessScript
/// member keys can carry counted partial signatures (non-member
/// records reject immediately), so 1500 calls is structurally
/// unreachable and exceeding it is an internal invariant violation.
const MAX_VERIFICATION_CALLS: usize = 1_500;

/// Per-input cryptographic verification status (M8). A status is a
/// verified fact about existing partial signatures only; it is not an
/// authorization and bypasses no later S4/S7, ownership, or change
/// check.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VerifiedInputStatus {
    /// Fewer cryptographically verified member signatures than the
    /// input's witnessScript threshold m.
    BelowThreshold,
    /// At least m existing partial signatures verified
    /// cryptographically against this input's computed BIP143
    /// SIGHASH_ALL digest.
    CryptographicallyVerifiedThreshold,
}

/// Aggregate cryptographic completeness across all inputs (M8).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VerifiedAggregateStatus {
    /// Every input is below its threshold.
    AllInputsBelowThreshold,
    /// Some inputs reached their threshold and others did not.
    MixedInputCompleteness,
    /// Every input reached its cryptographically verified threshold
    /// (the QK-DEC-033 disposition). This is a returned fact and a
    /// no-additional-signature direction only: no export is performed
    /// or authorized here, and no later S4/S7 authorization,
    /// ownership, or change check is bypassed or weakened.
    VerifyAndExportOnly,
}

/// Per-input verified facts (M8).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct VerifiedInputFacts {
    /// Count of existing partial signatures that verified
    /// cryptographically against this input's computed digest. Only
    /// witnessScript member records are counted; any malformed,
    /// off-curve, non-member, or failing record rejects the whole
    /// result instead of being skipped.
    pub verified_signature_count: usize,
    /// Verified threshold status for this input.
    pub status: VerifiedInputStatus,
}

/// The M8 verified result: the unchanged, still non-authoritative M6
/// structural candidate plus cryptographically verified per-input
/// facts and one aggregate status. Everything is derived read-only
/// from the same parsed view; nothing here signs, inserts, finalizes,
/// exports, or authorizes anything.
#[derive(Debug, Clone)]
pub struct VerifiedSemanticCandidate<'a> {
    /// The embedded M6 structural candidate, unchanged and still
    /// explicitly non-authoritative (its structural signature counts
    /// remain unverified claims).
    pub candidate: SemanticCandidate<'a>,
    /// Per-input verified facts in unsigned-transaction input order.
    pub verified_inputs: Vec<VerifiedInputFacts>,
    /// Aggregate verified status across all inputs.
    pub aggregate_status: VerifiedAggregateStatus,
}

/// Map a digest-engine error into the semantic error space. `Hash`
/// maps to the existing hash-failure category; every other engine
/// condition (including an unsigned-transaction output scriptPubKey
/// exceeding the engine's output-script cap) fails closed as a
/// cryptographic backend invariant.
fn map_bip143(e: Bip143Error, input_index: Option<usize>, offset: usize) -> SemanticError {
    let category = match e {
        Bip143Error::Hash => SemanticCategory::HashFailure,
        Bip143Error::ScriptCodeTooLong
        | Bip143Error::OutputScriptTooLong
        | Bip143Error::Invariant => SemanticCategory::CryptographicBackendInvariant,
    };
    SemanticError {
        category,
        input_index,
        offset,
    }
}

/// M8 pre-verification screen, inputs ascending, before any
/// cryptographic call: require a witnessScript record; reject
/// final-script fields; reject a malformed witnessScript push; reject
/// an actual OP_CODESEPARATOR opcode by parsed opcode semantics
/// (never a raw byte scan; pushed 0xAB data never matches); require
/// the canonical bounded m-of-n form; require the selected prevout
/// scriptPubKey to be the exact native P2WSH commitment
/// `00 20 SHA256(witnessScript)` (a coherence check, not an ownership
/// claim); reject a redeem-script (wrapped) route.
fn verification_screen(
    view: &PsbtView<'_>,
    state: &AnalysisState<'_>,
) -> Result<(), SemanticError> {
    for (i, w) in state.work.iter().enumerate() {
        let map_start = view.input_map_span(i).map_or(0, |s| s.start);
        let invariant = SemanticError::at_input(SemanticCategory::InternalInvariant, i, map_start);
        let records = view.input_records(i).ok_or(invariant)?;
        let mut witness_script = None;
        let mut final_field = None;
        let mut redeem_script = None;
        for r in records.clone() {
            match r.key_type {
                0x04 => {
                    if redeem_script.is_none() {
                        redeem_script = Some(r);
                    }
                }
                0x05 => witness_script = Some(r),
                0x07 | 0x08 => {
                    if final_field.is_none() {
                        final_field = Some(r);
                    }
                }
                _ => {}
            }
        }
        let ws = witness_script.ok_or(SemanticError::at_input(
            SemanticCategory::MissingWitnessScript,
            i,
            map_start,
        ))?;
        if let Some(r) = final_field {
            return Err(SemanticError::at_input(
                SemanticCategory::UnsupportedFinalScriptFields,
                i,
                r.value_span.start,
            ));
        }
        for token in ScriptTokens::new(ws.value) {
            match token {
                Err(m) => {
                    return Err(SemanticError::at_input(
                        SemanticCategory::MalformedScriptPush,
                        i,
                        ws.value_span.start.saturating_add(m.offset),
                    ));
                }
                Ok(ScriptToken::Opcode(0xab)) => {
                    return Err(SemanticError::at_input(
                        SemanticCategory::UnsupportedCodeSeparator,
                        i,
                        ws.value_span.start,
                    ));
                }
                Ok(_) => {}
            }
        }
        if parse_multisig_form(ws.value).is_none() {
            return Err(SemanticError::at_input(
                SemanticCategory::WitnessScriptForm,
                i,
                ws.value_span.start,
            ));
        }
        let commitment = sha256(&[ws.value]).map_err(|_| {
            SemanticError::at_input(SemanticCategory::HashFailure, i, ws.value_span.start)
        })?;
        let native = w.prevout_script.len() == 34
            && w.prevout_script.first() == Some(&0x00)
            && w.prevout_script.get(1) == Some(&0x20)
            && w.prevout_script.get(2..) == Some(commitment.as_slice());
        if !native {
            return Err(SemanticError::at_input(
                SemanticCategory::PrevoutNotNativeWitnessScriptHash,
                i,
                w.prevout_script_offset,
            ));
        }
        if let Some(r) = redeem_script {
            return Err(SemanticError::at_input(
                SemanticCategory::UnsupportedRedeemScriptRoute,
                i,
                r.value_span.start,
            ));
        }
    }
    Ok(())
}

/// M8 cryptographic stage. Precomputes hashPrevouts, hashSequence,
/// and hashOutputs exactly once, derives exactly one BIP143
/// SIGHASH_ALL digest per input (no per-signature rehashing and no
/// transaction-sized buffer), then verifies every existing partial
/// signature in map order through qk-secp: witnessScript membership
/// first, then compressed-pubkey curve validity, then the trailing
/// sighash byte bound to [`SIGHASH_ALL`], then a DER-only signature
/// parse (the trailing byte is never passed on), then digest
/// verification. Any failing record rejects the whole result.
fn verification_phase(
    view: &PsbtView<'_>,
    candidate: &SemanticCandidate<'_>,
) -> Result<(Vec<VerifiedInputFacts>, VerifiedAggregateStatus), SemanticError> {
    let global_offset = view.unsigned_tx().span.start;
    let mut builder = Bip143PrecomputeBuilder::new();
    for (i, input) in candidate.inputs.iter().enumerate() {
        let txid: &[u8; 32] = input.outpoint_txid_wire.try_into().map_err(|_| {
            SemanticError::at_input(SemanticCategory::InternalInvariant, i, global_offset)
        })?;
        builder
            .add_input(txid, input.outpoint_vout, input.sequence)
            .map_err(|e| map_bip143(e, Some(i), global_offset))?;
    }
    for output in &candidate.outputs {
        builder
            .add_output(output.amount, output.script_pubkey)
            .map_err(|e| map_bip143(e, None, global_offset))?;
    }
    let precomputed = builder
        .finish()
        .map_err(|e| map_bip143(e, None, global_offset))?;

    let mut verified_inputs: Vec<VerifiedInputFacts> = Vec::new();
    reserve_exact(&mut verified_inputs, candidate.inputs.len(), global_offset)?;
    let mut verification_calls = 0usize;
    for (i, input) in candidate.inputs.iter().enumerate() {
        let map_start = view.input_map_span(i).map_or(0, |s| s.start);
        let invariant = SemanticError::at_input(SemanticCategory::InternalInvariant, i, map_start);
        let records = view.input_records(i).ok_or(invariant)?;
        let mut witness_script = None;
        for r in records.clone() {
            if r.key_type == 0x05 {
                witness_script = Some(r);
            }
        }
        let ws = witness_script.ok_or(invariant)?;
        let form = input.multisig_form.ok_or(invariant)?;
        let txid: &[u8; 32] = input.outpoint_txid_wire.try_into().map_err(|_| invariant)?;
        let facts = Bip143InputFacts {
            outpoint_txid_wire: txid,
            outpoint_vout: input.outpoint_vout,
            script_code: ws.value,
            amount_sats: input.prevout_amount,
            sequence: input.sequence,
        };
        let digest =
            sighash_all_digest(candidate.version, candidate.locktime, &precomputed, &facts)
                .map_err(|e| map_bip143(e, Some(i), ws.value_span.start))?;
        let mut verified = 0usize;
        for r in records.clone() {
            if r.key_type != 0x02 {
                continue;
            }
            if !multisig_contains_key(ws.value, r.key_data) {
                return Err(SemanticError::at_input(
                    SemanticCategory::PartialSignaturePubkeyNotInWitnessScript,
                    i,
                    r.key_data_span.start,
                ));
            }
            let key: &[u8; 33] = r.key_data.try_into().map_err(|_| invariant)?;
            // A normal parse failure is an attacker-input rejection;
            // an unknown backend return code is never attributed to
            // input and fails closed as a backend invariant.
            let pubkey = qk_secp::pubkey_parse_compressed(key).map_err(|e| {
                SemanticError::at_input(
                    match e {
                        qk_secp::SecpError::UnknownReturnCode => {
                            SemanticCategory::CryptographicBackendInvariant
                        }
                        _ => SemanticCategory::InvalidCryptographicPubkey,
                    },
                    i,
                    r.key_data_span.start,
                )
            })?;
            let (trailing, der) = r.value.split_last().ok_or(invariant)?;
            if *trailing != SIGHASH_ALL {
                return Err(SemanticError::at_input(
                    SemanticCategory::UnsupportedSighash,
                    i,
                    r.value_span.end.saturating_sub(1),
                ));
            }
            // Same fail-closed split for signature parsing: unknown
            // backend return codes are a backend invariant, never an
            // ordinary attacker-input rejection.
            let signature = qk_secp::signature_parse_der(der).map_err(|e| {
                SemanticError::at_input(
                    match e {
                        qk_secp::SecpError::UnknownReturnCode => {
                            SemanticCategory::CryptographicBackendInvariant
                        }
                        _ => SemanticCategory::SignatureVerificationFailed,
                    },
                    i,
                    r.value_span.start,
                )
            })?;
            verification_calls = verification_calls.saturating_add(1);
            if verification_calls > MAX_VERIFICATION_CALLS {
                return Err(invariant);
            }
            match qk_secp::ecdsa_verify(&signature, &digest, &pubkey) {
                Ok(()) => {}
                Err(qk_secp::SecpError::VerificationFailed) => {
                    return Err(SemanticError::at_input(
                        SemanticCategory::SignatureVerificationFailed,
                        i,
                        r.value_span.start,
                    ));
                }
                Err(_) => {
                    return Err(SemanticError::at_input(
                        SemanticCategory::CryptographicBackendInvariant,
                        i,
                        r.value_span.start,
                    ));
                }
            }
            verified = verified.saturating_add(1);
        }
        let status = if verified >= form.required_m {
            VerifiedInputStatus::CryptographicallyVerifiedThreshold
        } else {
            VerifiedInputStatus::BelowThreshold
        };
        verified_inputs.push(VerifiedInputFacts {
            verified_signature_count: verified,
            status,
        });
    }
    let all_verified = !verified_inputs.is_empty()
        && verified_inputs
            .iter()
            .all(|v| v.status == VerifiedInputStatus::CryptographicallyVerifiedThreshold);
    let none_verified = verified_inputs
        .iter()
        .all(|v| v.status == VerifiedInputStatus::BelowThreshold);
    let aggregate_status = if all_verified {
        VerifiedAggregateStatus::VerifyAndExportOnly
    } else if none_verified {
        VerifiedAggregateStatus::AllInputsBelowThreshold
    } else {
        VerifiedAggregateStatus::MixedInputCompleteness
    };
    Ok((verified_inputs, aggregate_status))
}

/// Analyze one structurally parsed PSBT v0 and cryptographically
/// verify its existing partial signatures (M8, QK-DEC-044..046).
///
/// READ-ONLY VERIFICATION OF EXISTING SIGNATURES ONLY. Everything is
/// derived from the same borrowed view; no separately supplied
/// candidate is accepted. This entrypoint performs no signing, no
/// signature insertion, no finalization, no export, and no policy
/// authorization; the M6 structural candidate it embeds is preserved
/// unchanged and remains non-authoritative. The
/// [`VerifiedAggregateStatus::VerifyAndExportOnly`] disposition is a
/// returned fact only and bypasses no later S4/S7 authorization,
/// ownership, or change check.
///
/// Frozen M8 precedence is documented at module level. Analysis is
/// deterministic, fail-closed, bounded by the existing structural
/// caps plus [`MAX_VERIFICATION_CALLS`], computes the three BIP143
/// precomputed hashes once and one digest per input, and allocates
/// only exact fallible reservations.
///
/// # Errors
///
/// Returns the first [`SemanticError`] in the frozen M8 precedence
/// order. Any malformed, off-curve, non-member, or cryptographically
/// failing partial signature rejects the whole result even when m
/// other signatures verify.
pub fn analyze_and_verify_signatures<'a>(
    view: &PsbtView<'a>,
) -> Result<VerifiedSemanticCandidate<'a>, SemanticError> {
    let mut state = structural_phase(view)?;
    verification_screen(view, &state)?;
    signature_phase(view, &mut state.work)?;
    token_phase(view, &state)?;
    let candidate = assemble(view, state)?;
    let (verified_inputs, aggregate_status) = verification_phase(view, &candidate)?;
    Ok(VerifiedSemanticCandidate {
        candidate,
        verified_inputs,
        aggregate_status,
    })
}
