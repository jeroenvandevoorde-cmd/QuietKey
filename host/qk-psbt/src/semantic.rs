//! M6 bounded HOST-only semantic-subset analyzer (QK-DEC-037,
//! QK-DEC-038, QK-DEC-039; recorded under the QK-DEC-034 process).
//!
//! The M6 route extracts a STRUCTURAL CANDIDATE view of one already
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
//!
//! M13 (QK-DEC-065..068) adds one further HOST-only entrypoint,
//! [`analyze_recipient_script_facts`]. It first completes the unchanged
//! M12 ownership and M8 verification path, then classifies only
//! [`OutputOwnership::NotProvenOwned`] outputs against six exact
//! destination templates. Descriptor-proven change and self-transfer
//! outputs remain unchanged and receive no recipient fact.
//!
//! M23 (QK-DEC-110) adds a separate no-signature-verification route,
//! [`analyze_review_v2_semantics`], for schema-v2 facts. It retains the
//! M6 syntax and M12 descriptor proofs, classifies every non-change
//! output (including self-transfer), and evaluates the fixed
//! QK-FEE-POLICY-V1 arithmetic. It returns no verified-signature or
//! completion state. The M6, M8, M12, and M13 entrypoints and behavior
//! remain unchanged.

use crate::bip143::{
    sighash_all_digest, Bip143Error, Bip143InputFacts, Bip143PrecomputeBuilder, SIGHASH_ALL,
};
use crate::limits;
use crate::parse::PsbtView;
use crate::raw::{decode_compact_size, Record, Span};
use crate::review_v2::{apply_fee_policy, FeePolicyFacts, ReviewV2Error};
use crate::sha256::{sha256, sha256d};
use core::fmt;
use qk_descriptor::{
    match_change_derivation_claims, match_receive_derivation_claims, DerivedScript, DescriptorPair,
};

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
    /// M12: descriptor origin fingerprints do not uniquely map A/B/C.
    AmbiguousDescriptorFingerprints,
    /// M12: an input does not carry exactly three BIP32 derivation
    /// records.
    DescriptorDerivationRecordCount,
    /// M12: a relevant derivation record key is not one exact
    /// compressed public key.
    DescriptorDerivationPublicKey,
    /// M12: a relevant derivation record does not carry the exact
    /// BIP48 prefix and path depth.
    DescriptorDerivationPath,
    /// M12: an input derivation fingerprint does not map to D.
    ForeignInputDescriptorRole,
    /// M12: two relevant derivation records map to the same D role.
    DuplicateDescriptorRole,
    /// M12: relevant derivation records disagree on branch or index.
    MixedDescriptorCoordinates,
    /// M12: a relevant derivation branch is not receive 0 or change 1.
    DescriptorBranchOutOfRange,
    /// M12: a relevant descriptor child index exceeds
    /// `limits::MAX_CHILD_INDEX`.
    DescriptorChildIndexOutOfRange,
    /// M12: role-preserving public derivation does not equal the
    /// supplied A/B/C keys.
    DescriptorDerivationKeyMismatch,
    /// M12: a present witnessScript is not byte-equal to the script
    /// reconstructed from D.
    DescriptorWitnessScriptMismatch,
    /// M12: the selected QK-DEC-032 prevout scriptPubKey is not the
    /// exact native P2WSH commitment reconstructed from D.
    DescriptorPrevoutScriptMismatch,
    /// M12: a complete output A/B/C set does not match the exact
    /// unsigned-output scriptPubKey.
    DescriptorOutputScriptMismatch,
    /// M12: bounded public descriptor derivation failed.
    DescriptorDerivationFailed,
    /// M12: descriptor CKDpub calls would exceed the candidate
    /// `limits::MAX_CHILD_DERIVATIONS`.
    DescriptorChildDerivationLimitExceeded,
    /// M13: an output is an exact bare-pubkey script.
    BarePubkeyRecipientScript,
    /// M13: an output is an exact canonical bare-multisig script.
    BareMultisigRecipientScript,
    /// M13: a canonical witness program uses version 2 through 16.
    FutureWitnessVersion,
    /// M13: a version 0 or 1 witness program has a nonselected length,
    /// or a version 0 through 16 witness-looking script is malformed.
    MalformedWitnessProgram,
    /// M13: an output script matches none of the selected templates or
    /// separately named rejection forms.
    UnsupportedRecipientScript,
    /// M13: an OP_RETURN output has nonzero value.
    OpReturnNonZeroValue,
    /// M13: more than one NotProvenOwned output begins with OP_RETURN.
    MultipleOpReturnOutputs,
    /// M13: canonical OP_RETURN is followed by more than one push.
    OpReturnMultiplePushes,
    /// M13: an OP_RETURN push is not the selected minimal encoding.
    OpReturnNonMinimalPush,
    /// M13: an OP_RETURN payload exceeds
    /// `limits::MAX_OP_RETURN_PAYLOAD_BYTES`.
    OpReturnPayloadTooLong,
    /// M23: the exact transaction fee is strictly greater than the
    /// QK-FEE-POLICY-V1 emergency ceiling.
    EmergencyFeeCeilingExceeded,
    /// M23: checked weight, virtual-size, fee-rate, or fee-share
    /// arithmetic could not be represented.
    FeePolicyArithmeticOverflow,
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
            Self::AmbiguousDescriptorFingerprints => {
                "descriptor origin fingerprints do not uniquely map roles"
            }
            Self::DescriptorDerivationRecordCount => {
                "input does not have exactly three descriptor derivation records"
            }
            Self::DescriptorDerivationPublicKey => {
                "descriptor derivation key is not exact compressed form"
            }
            Self::DescriptorDerivationPath => "descriptor derivation path is not exact BIP48 form",
            Self::ForeignInputDescriptorRole => {
                "input derivation fingerprint does not map to descriptor"
            }
            Self::DuplicateDescriptorRole => "duplicate descriptor role",
            Self::MixedDescriptorCoordinates => "mixed descriptor branch or child index",
            Self::DescriptorBranchOutOfRange => "descriptor branch is not receive or change",
            Self::DescriptorChildIndexOutOfRange => "descriptor child index exceeds cap",
            Self::DescriptorDerivationKeyMismatch => {
                "descriptor-derived role key does not match claim"
            }
            Self::DescriptorWitnessScriptMismatch => {
                "witness script does not equal descriptor reconstruction"
            }
            Self::DescriptorPrevoutScriptMismatch => {
                "prevout script does not equal descriptor reconstruction"
            }
            Self::DescriptorOutputScriptMismatch => {
                "output script does not equal descriptor reconstruction"
            }
            Self::DescriptorDerivationFailed => "bounded descriptor derivation failed",
            Self::DescriptorChildDerivationLimitExceeded => {
                "descriptor child derivation cap exceeded"
            }
            Self::BarePubkeyRecipientScript => "bare pubkey recipient script rejected",
            Self::BareMultisigRecipientScript => "bare multisig recipient script rejected",
            Self::FutureWitnessVersion => "future witness version rejected",
            Self::MalformedWitnessProgram => "witness program malformed",
            Self::UnsupportedRecipientScript => "recipient script unsupported",
            Self::OpReturnNonZeroValue => "OP_RETURN value must be zero",
            Self::MultipleOpReturnOutputs => "multiple OP_RETURN outputs",
            Self::OpReturnMultiplePushes => "OP_RETURN has multiple pushes",
            Self::OpReturnNonMinimalPush => "OP_RETURN push encoding nonminimal",
            Self::OpReturnPayloadTooLong => "OP_RETURN payload exceeds byte cap",
            Self::EmergencyFeeCeilingExceeded => "emergency fee ceiling exceeded",
            Self::FeePolicyArithmeticOverflow => "fee policy arithmetic overflow",
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
    serialized: Span,
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
                serialized: Span {
                    start: amount_offset,
                    end: c.pos,
                },
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
            // QK-DEC-032/QK-DEC-110 exact serialized TxOut equality.
            // Both values were already structurally checked with minimal
            // CompactSize framing, so compare the complete amount, length,
            // and script bytes directly without field normalization.
            let wmis = SemanticError::at_input(
                SemanticCategory::WitnessUtxoMismatch,
                i,
                w.value_span.start,
            );
            let selected_serialized = sel.serialized.slice(buf).ok_or_else(|| {
                SemanticError::at_input(SemanticCategory::InternalInvariant, i, sel.amount_offset)
            })?;
            if w.value != selected_serialized {
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

/// Shared M8/M12 pre-verification screen, inputs ascending, before any
/// cryptographic call. Public M8 requires a witnessScript and checks
/// its selected-prevout commitment. M12 permits an absent record and
/// defers both exact script equalities until after reconstruction from
/// D. All other existing screen rules run before M12 wallet analysis.
fn verification_screen(
    view: &PsbtView<'_>,
    state: &AnalysisState<'_>,
    witness_required: bool,
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
        if witness_required && witness_script.is_none() {
            return Err(SemanticError::at_input(
                SemanticCategory::MissingWitnessScript,
                i,
                map_start,
            ));
        }
        if let Some(r) = final_field {
            return Err(SemanticError::at_input(
                SemanticCategory::UnsupportedFinalScriptFields,
                i,
                r.value_span.start,
            ));
        }
        if let Some(ws) = witness_script {
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
            if witness_required {
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
            }
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
enum VerificationScriptSource<'a> {
    Recorded,
    Descriptor(&'a [DerivedScript]),
}

fn verification_phase(
    view: &PsbtView<'_>,
    candidate: &SemanticCandidate<'_>,
    script_source: VerificationScriptSource<'_>,
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
        let (script_code, form, script_offset) = match script_source {
            VerificationScriptSource::Recorded => {
                let mut witness_script = None;
                for r in records.clone() {
                    if r.key_type == 0x05 {
                        witness_script = Some(r);
                    }
                }
                let ws = witness_script.ok_or(invariant)?;
                let form = input.multisig_form.ok_or(invariant)?;
                (ws.value, form, ws.value_span.start)
            }
            VerificationScriptSource::Descriptor(scripts) => {
                let derived = scripts.get(i).ok_or(invariant)?;
                (
                    derived.witness_script.as_slice(),
                    MultisigForm {
                        required_m: 2,
                        total_n: 3,
                    },
                    map_start,
                )
            }
        };
        let txid: &[u8; 32] = input.outpoint_txid_wire.try_into().map_err(|_| invariant)?;
        let facts = Bip143InputFacts {
            outpoint_txid_wire: txid,
            outpoint_vout: input.outpoint_vout,
            script_code,
            amount_sats: input.prevout_amount,
            sequence: input.sequence,
        };
        let digest =
            sighash_all_digest(candidate.version, candidate.locktime, &precomputed, &facts)
                .map_err(|e| map_bip143(e, Some(i), script_offset))?;
        let mut verified = 0usize;
        for r in records.clone() {
            if r.key_type != 0x02 {
                continue;
            }
            if !multisig_contains_key(script_code, r.key_data) {
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
    verification_screen(view, &state, true)?;
    signature_phase(view, &mut state.work)?;
    token_phase(view, &state)?;
    let candidate = assemble(view, state)?;
    let (verified_inputs, aggregate_status) =
        verification_phase(view, &candidate, VerificationScriptSource::Recorded)?;
    Ok(VerifiedSemanticCandidate {
        candidate,
        verified_inputs,
        aggregate_status,
    })
}

// ====================================================================
// M12 HOST-only descriptor-backed ownership facts (QK-DEC-060..064).
// ====================================================================

const CHILD_DERIVATIONS_PER_ROUTE: usize = 6;
const DESCRIPTOR_PATH_VALUE_BYTES: usize = 28;
const BIP48_PURPOSE: u32 = 0x8000_0030;
const BIP48_COIN_TYPE: u32 = 0x8000_0000;
const BIP48_ACCOUNT: u32 = 0x8000_0000;
const BIP48_SCRIPT_TYPE: u32 = 0x8000_0002;

/// One input whose exact A/B/C derivation claims, reconstructed script,
/// optional witnessScript, and selected prevout all cohered with D.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ProvenWalletInput {
    /// Descriptor branch: receive 0 or change 1.
    pub branch: u32,
    /// Nonhardened descriptor child index.
    pub index: u32,
}

/// Descriptor-backed fact about one unsigned transaction output.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OutputOwnership {
    /// No complete coherent A/B/C proof was present. This is neither
    /// recipient authorization nor a renderability decision.
    NotProvenOwned,
    /// Exact branch-1 descriptor script at this child index.
    ProvenChange(u32),
    /// Exact branch-0 descriptor script at this child index.
    ProvenSelfTransfer(u32),
}

/// M12 wallet facts, separate from structural and cryptographic facts.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DescriptorWalletFacts {
    /// Every input, in unsigned-transaction order.
    pub inputs: Vec<ProvenWalletInput>,
    /// One descriptor-backed classification per unsigned output.
    pub outputs: Vec<OutputOwnership>,
}

/// M12 result: a record-truthful semantic candidate, existing
/// cryptographic facts over D-reconstructed effective scripts, and
/// separate wallet facts. No field authenticates D or authorizes a
/// recipient, signing, finalization, or export.
#[derive(Debug, Clone)]
pub struct DescriptorOwnershipAnalysis<'a> {
    /// Record-truthful M6 candidate; a missing witnessScript remains
    /// visibly absent here.
    pub candidate: SemanticCandidate<'a>,
    /// Existing-signature cryptographic facts, in input order.
    pub verified_inputs: Vec<VerifiedInputFacts>,
    /// Existing aggregate cryptographic status.
    pub aggregate_status: VerifiedAggregateStatus,
    /// Descriptor-backed input and output facts.
    pub wallet: DescriptorWalletFacts,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct DescriptorCoordinates {
    branch: u32,
    index: u32,
}

struct DescriptorClaims {
    keys: [Option<[u8; 33]>; 3],
    coordinates: Option<DescriptorCoordinates>,
    relevant_count: usize,
}

impl DescriptorClaims {
    const fn new() -> Self {
        Self {
            keys: [None; 3],
            coordinates: None,
            relevant_count: 0,
        }
    }

    fn add(
        &mut self,
        role: usize,
        key: [u8; 33],
        coordinates: DescriptorCoordinates,
        input_index: Option<usize>,
        offset: usize,
    ) -> Result<(), SemanticError> {
        let slot = self.keys.get(role).ok_or(SemanticError {
            category: SemanticCategory::InternalInvariant,
            input_index,
            offset,
        })?;
        if slot.is_some() {
            return Err(SemanticError {
                category: SemanticCategory::DuplicateDescriptorRole,
                input_index,
                offset,
            });
        }
        if self
            .coordinates
            .is_some_and(|existing| existing != coordinates)
        {
            return Err(SemanticError {
                category: SemanticCategory::MixedDescriptorCoordinates,
                input_index,
                offset,
            });
        }
        if self.coordinates.is_none() {
            self.coordinates = Some(coordinates);
        }
        let slot = self.keys.get_mut(role).ok_or(SemanticError {
            category: SemanticCategory::InternalInvariant,
            input_index,
            offset,
        })?;
        *slot = Some(key);
        self.relevant_count = self.relevant_count.saturating_add(1);
        Ok(())
    }
}

fn little_endian_u32_at(value: &[u8], offset: usize) -> Option<u32> {
    let end = offset.checked_add(4)?;
    let bytes: [u8; 4] = value.get(offset..end)?.try_into().ok()?;
    Some(u32::from_le_bytes(bytes))
}

fn descriptor_role(fingerprints: &[[u8; 4]; 3], candidate: &[u8]) -> Option<usize> {
    fingerprints
        .iter()
        .position(|fingerprint| fingerprint.as_slice() == candidate)
}

fn parse_descriptor_claim(
    record: Record<'_>,
    input_index: Option<usize>,
) -> Result<([u8; 33], DescriptorCoordinates), SemanticError> {
    let error = |category, offset| SemanticError {
        category,
        input_index,
        offset,
    };
    let key: [u8; 33] = record.key_data.try_into().map_err(|_| {
        error(
            SemanticCategory::DescriptorDerivationPublicKey,
            record.key_data_span.start,
        )
    })?;
    if !matches!(key.first(), Some(0x02 | 0x03)) {
        return Err(error(
            SemanticCategory::DescriptorDerivationPublicKey,
            record.key_data_span.start,
        ));
    }
    if record.value.len() != DESCRIPTOR_PATH_VALUE_BYTES {
        return Err(error(
            SemanticCategory::DescriptorDerivationPath,
            record.value_span.start,
        ));
    }
    for (offset, expected) in [
        (4, BIP48_PURPOSE),
        (8, BIP48_COIN_TYPE),
        (12, BIP48_ACCOUNT),
        (16, BIP48_SCRIPT_TYPE),
    ] {
        if little_endian_u32_at(record.value, offset) != Some(expected) {
            return Err(error(
                SemanticCategory::DescriptorDerivationPath,
                record.value_span.start.saturating_add(offset),
            ));
        }
    }
    let branch = little_endian_u32_at(record.value, 20).ok_or_else(|| {
        error(
            SemanticCategory::DescriptorDerivationPath,
            record.value_span.start,
        )
    })?;
    if branch > 1 {
        return Err(error(
            SemanticCategory::DescriptorBranchOutOfRange,
            record.value_span.start.saturating_add(20),
        ));
    }
    let index = little_endian_u32_at(record.value, 24).ok_or_else(|| {
        error(
            SemanticCategory::DescriptorDerivationPath,
            record.value_span.start,
        )
    })?;
    if index > limits::MAX_CHILD_INDEX {
        return Err(error(
            SemanticCategory::DescriptorChildIndexOutOfRange,
            record.value_span.start.saturating_add(24),
        ));
    }
    Ok((key, DescriptorCoordinates { branch, index }))
}

fn unique_descriptor_fingerprints(
    descriptor: &DescriptorPair,
    offset: usize,
) -> Result<[[u8; 4]; 3], SemanticError> {
    let fingerprints = descriptor.origin_fingerprints();
    let [a, b, c] = fingerprints;
    if a == b || a == c || b == c {
        return Err(SemanticError::global(
            SemanticCategory::AmbiguousDescriptorFingerprints,
            offset,
        ));
    }
    Ok(fingerprints)
}

fn consume_descriptor_route(
    calls: &mut usize,
    input_index: Option<usize>,
    offset: usize,
) -> Result<(), SemanticError> {
    let next = calls
        .checked_add(CHILD_DERIVATIONS_PER_ROUTE)
        .ok_or(SemanticError {
            category: SemanticCategory::DescriptorChildDerivationLimitExceeded,
            input_index,
            offset,
        })?;
    if next > limits::MAX_CHILD_DERIVATIONS {
        return Err(SemanticError {
            category: SemanticCategory::DescriptorChildDerivationLimitExceeded,
            input_index,
            offset,
        });
    }
    *calls = next;
    Ok(())
}

fn match_descriptor_claims(
    descriptor: &DescriptorPair,
    claims: &DescriptorClaims,
    calls: &mut usize,
    input_index: Option<usize>,
    offset: usize,
) -> Result<DerivedScript, SemanticError> {
    let coordinates = claims.coordinates.ok_or(SemanticError {
        category: SemanticCategory::InternalInvariant,
        input_index,
        offset,
    })?;
    consume_descriptor_route(calls, input_index, offset)?;
    let matched = match coordinates.branch {
        0 => match_receive_derivation_claims(descriptor, coordinates.index, &claims.keys),
        1 => match_change_derivation_claims(descriptor, coordinates.index, &claims.keys),
        _ => {
            return Err(SemanticError {
                category: SemanticCategory::InternalInvariant,
                input_index,
                offset,
            })
        }
    }
    .map_err(|_| SemanticError {
        category: SemanticCategory::DescriptorDerivationFailed,
        input_index,
        offset,
    })?;
    matched.ok_or(SemanticError {
        category: SemanticCategory::DescriptorDerivationKeyMismatch,
        input_index,
        offset,
    })
}

fn prove_descriptor_input(
    view: &PsbtView<'_>,
    descriptor: &DescriptorPair,
    fingerprints: &[[u8; 4]; 3],
    input_index: usize,
    work: &InputWork<'_>,
    calls: &mut usize,
) -> Result<(ProvenWalletInput, DerivedScript), SemanticError> {
    let map_start = view
        .input_map_span(input_index)
        .map_or(0, |span| span.start);
    let invariant =
        SemanticError::at_input(SemanticCategory::InternalInvariant, input_index, map_start);
    let records = view.input_records(input_index).ok_or(invariant)?;
    let derivation_count = records
        .clone()
        .filter(|record| record.key_type == 0x06)
        .count();
    if derivation_count != 3 {
        return Err(SemanticError::at_input(
            SemanticCategory::DescriptorDerivationRecordCount,
            input_index,
            map_start,
        ));
    }

    let mut claims = DescriptorClaims::new();
    let mut witness_script = None;
    for record in records {
        if record.key_type == 0x05 {
            witness_script = Some(record);
            continue;
        }
        if record.key_type != 0x06 {
            continue;
        }
        let fingerprint = record.value.get(..4).ok_or(invariant)?;
        let role = descriptor_role(fingerprints, fingerprint).ok_or_else(|| {
            SemanticError::at_input(
                SemanticCategory::ForeignInputDescriptorRole,
                input_index,
                record.value_span.start,
            )
        })?;
        let (key, coordinates) = parse_descriptor_claim(record, Some(input_index))?;
        claims.add(
            role,
            key,
            coordinates,
            Some(input_index),
            record.value_span.start,
        )?;
    }

    let derived =
        match_descriptor_claims(descriptor, &claims, calls, Some(input_index), map_start)?;
    if let Some(record) = witness_script {
        if record.value != derived.witness_script {
            return Err(SemanticError::at_input(
                SemanticCategory::DescriptorWitnessScriptMismatch,
                input_index,
                record.value_span.start,
            ));
        }
    }
    if work.prevout_script != derived.script_pubkey {
        return Err(SemanticError::at_input(
            SemanticCategory::DescriptorPrevoutScriptMismatch,
            input_index,
            work.prevout_script_offset,
        ));
    }
    let coordinates = claims.coordinates.ok_or(invariant)?;
    Ok((
        ProvenWalletInput {
            branch: coordinates.branch,
            index: coordinates.index,
        },
        derived,
    ))
}

fn classify_descriptor_output(
    view: &PsbtView<'_>,
    descriptor: &DescriptorPair,
    fingerprints: &[[u8; 4]; 3],
    output_index: usize,
    output: &OutputSemanticFacts<'_>,
    calls: &mut usize,
) -> Result<OutputOwnership, SemanticError> {
    let map_start = view
        .output_map_span(output_index)
        .map_or(0, |span| span.start);
    let records = view
        .output_records(output_index)
        .ok_or(SemanticError::global(
            SemanticCategory::InternalInvariant,
            map_start,
        ))?;
    let mut claims = DescriptorClaims::new();
    for record in records {
        if record.key_type != 0x02 {
            continue;
        }
        let fingerprint = record.value.get(..4).ok_or(SemanticError::global(
            SemanticCategory::InternalInvariant,
            record.value_span.start,
        ))?;
        let Some(role) = descriptor_role(fingerprints, fingerprint) else {
            continue;
        };
        let (key, coordinates) = parse_descriptor_claim(record, None)?;
        claims.add(role, key, coordinates, None, record.value_span.start)?;
    }
    if claims.relevant_count == 0 {
        return Ok(OutputOwnership::NotProvenOwned);
    }

    let derived = match_descriptor_claims(descriptor, &claims, calls, None, map_start)?;
    if claims.relevant_count < 3 {
        return Ok(OutputOwnership::NotProvenOwned);
    }
    if output.script_pubkey != derived.script_pubkey {
        return Err(SemanticError::global(
            SemanticCategory::DescriptorOutputScriptMismatch,
            map_start,
        ));
    }
    let coordinates = claims.coordinates.ok_or(SemanticError::global(
        SemanticCategory::InternalInvariant,
        map_start,
    ))?;
    match coordinates.branch {
        0 => Ok(OutputOwnership::ProvenSelfTransfer(coordinates.index)),
        1 => Ok(OutputOwnership::ProvenChange(coordinates.index)),
        _ => Err(SemanticError::global(
            SemanticCategory::InternalInvariant,
            map_start,
        )),
    }
}

/// Analyze one structurally parsed PSBT v0 against one caller-supplied,
/// already-authenticated descriptor pair (M12, QK-DEC-060..064).
///
/// HOST-ONLY READ-ONLY FACTS. This route authenticates neither D nor
/// recipients and performs no signing, insertion, finalization,
/// serialization, persistence, export, or policy authorization.
/// Structural/QK-DEC-032 and the existing M8 screen and signature
/// syntax phases run before descriptor wallet analysis. Every input
/// must then prove exact A/B/C ownership by D reconstruction and both
/// script equalities. Missing witnessScript is allowed only here; the
/// reconstructed, selected-prevout-bound script is used for existing
/// signature cryptography while the returned semantic candidate stays
/// truthful to records.
///
/// # Errors
///
/// Returns the first [`SemanticError`] in deterministic phase, input,
/// record, then output order.
pub fn analyze_descriptor_ownership<'a>(
    view: &PsbtView<'a>,
    descriptor: &DescriptorPair,
) -> Result<DescriptorOwnershipAnalysis<'a>, SemanticError> {
    let mut state = structural_phase(view)?;
    verification_screen(view, &state, false)?;
    signature_phase(view, &mut state.work)?;
    token_phase(view, &state)?;

    let global_offset = view.unsigned_tx().span.start;
    let fingerprints = unique_descriptor_fingerprints(descriptor, global_offset)?;
    let mut derivation_calls = 0usize;

    let mut wallet_inputs: Vec<ProvenWalletInput> = Vec::new();
    reserve_exact(&mut wallet_inputs, state.work.len(), global_offset)?;
    let mut effective_scripts: Vec<DerivedScript> = Vec::new();
    reserve_exact(&mut effective_scripts, state.work.len(), global_offset)?;
    for (input_index, work) in state.work.iter().enumerate() {
        let (wallet_input, script) = prove_descriptor_input(
            view,
            descriptor,
            &fingerprints,
            input_index,
            work,
            &mut derivation_calls,
        )?;
        wallet_inputs.push(wallet_input);
        effective_scripts.push(script);
    }

    let candidate = assemble(view, state)?;
    let (verified_inputs, aggregate_status) = verification_phase(
        view,
        &candidate,
        VerificationScriptSource::Descriptor(&effective_scripts),
    )?;

    let mut wallet_outputs: Vec<OutputOwnership> = Vec::new();
    reserve_exact(&mut wallet_outputs, candidate.outputs.len(), global_offset)?;
    for (output_index, output) in candidate.outputs.iter().enumerate() {
        wallet_outputs.push(classify_descriptor_output(
            view,
            descriptor,
            &fingerprints,
            output_index,
            output,
            &mut derivation_calls,
        )?);
    }

    Ok(DescriptorOwnershipAnalysis {
        candidate,
        verified_inputs,
        aggregate_status,
        wallet: DescriptorWalletFacts {
            inputs: wallet_inputs,
            outputs: wallet_outputs,
        },
    })
}

// ====================================================================
// M13 HOST-only recipient-script facts (QK-DEC-065..068).
// ====================================================================

/// Exact accepted recipient destination template.
///
/// This is a raw script classification only. It is not an address,
/// recipient authorization, amount warning, or approval disposition.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RecipientType {
    /// Native version-0 20-byte witness program.
    P2wpkh,
    /// Native version-0 32-byte witness program.
    P2wsh,
    /// Destination-only version-1 32-byte witness program.
    P2tr,
    /// Exact legacy pay-to-public-key-hash template.
    P2pkh,
    /// Exact legacy pay-to-script-hash template.
    P2sh,
    /// Canonical zero-value OP_RETURN under QK-DEC-067.
    OpReturn,
}

/// Borrowed raw program, hash, or OP_RETURN data for one accepted
/// NotProvenOwned output.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RecipientScriptFacts<'a> {
    /// Exact accepted destination template.
    pub recipient_type: RecipientType,
    /// Exact borrowed witness program, hash, or OP_RETURN payload bytes.
    pub data: &'a [u8],
    /// Absolute half-open span of `data` in the immutable PSBT buffer.
    pub data_span: Span,
}

/// M13 result: the complete unchanged M12 analysis plus one optional
/// recipient fact per output.
///
/// `None` means the parallel ownership fact is ProvenChange or
/// ProvenSelfTransfer. Every NotProvenOwned output has `Some` on
/// success; unsupported or malformed recipient scripts reject.
#[derive(Debug, Clone)]
pub struct RecipientScriptAnalysis<'a> {
    /// Complete unchanged M12 descriptor-ownership analysis.
    pub ownership: DescriptorOwnershipAnalysis<'a>,
    /// Parallel to unsigned outputs in exact order.
    pub recipient_outputs: Vec<Option<RecipientScriptFacts<'a>>>,
}

fn recipient_fact<'a>(
    recipient_type: RecipientType,
    script: &'a [u8],
    script_span: Span,
    data_start: usize,
    data_len: usize,
) -> Result<RecipientScriptFacts<'a>, SemanticError> {
    let data_end = data_start.checked_add(data_len).ok_or_else(|| {
        SemanticError::global(SemanticCategory::InternalInvariant, script_span.start)
    })?;
    let data = script.get(data_start..data_end).ok_or_else(|| {
        SemanticError::global(SemanticCategory::InternalInvariant, script_span.start)
    })?;
    let absolute_start = script_span.start.checked_add(data_start).ok_or_else(|| {
        SemanticError::global(SemanticCategory::InternalInvariant, script_span.start)
    })?;
    let absolute_end = absolute_start.checked_add(data_len).ok_or_else(|| {
        SemanticError::global(SemanticCategory::InternalInvariant, script_span.start)
    })?;
    if absolute_end > script_span.end {
        return Err(SemanticError::global(
            SemanticCategory::InternalInvariant,
            script_span.start,
        ));
    }
    Ok(RecipientScriptFacts {
        recipient_type,
        data,
        data_span: Span {
            start: absolute_start,
            end: absolute_end,
        },
    })
}

fn is_bare_pubkey(script: &[u8]) -> bool {
    match script {
        [0x21, key @ .., 0xac] => key.len() == 33 && matches!(key.first(), Some(0x02 | 0x03)),
        [0x41, key @ .., 0xac] => key.len() == 65 && key.first() == Some(&0x04),
        _ => false,
    }
}

const fn is_push_opcode(opcode: u8) -> bool {
    matches!(opcode, 0x00..=0x4f | 0x51..=0x60)
}

fn complete_op_return_push(
    script: &[u8],
    script_span: Span,
    data_start: usize,
    data_len: usize,
) -> Result<(), SemanticError> {
    let data_end = data_start.checked_add(data_len).ok_or_else(|| {
        SemanticError::global(SemanticCategory::InternalInvariant, script_span.start)
    })?;
    if script.len() < data_end {
        return Err(SemanticError::global(
            SemanticCategory::MalformedScriptPush,
            script_span.start.saturating_add(1),
        ));
    }
    if let Some(trailing) = script.get(data_end).copied() {
        let category = if is_push_opcode(trailing) {
            SemanticCategory::OpReturnMultiplePushes
        } else {
            SemanticCategory::UnsupportedRecipientScript
        };
        return Err(SemanticError::global(
            category,
            script_span.start.saturating_add(data_end),
        ));
    }
    Ok(())
}

fn classify_op_return<'a>(
    output: &OutputSemanticFacts<'a>,
    script_span: Span,
) -> Result<RecipientScriptFacts<'a>, SemanticError> {
    let script = output.script_pubkey;
    if output.amount != 0 {
        return Err(SemanticError::global(
            SemanticCategory::OpReturnNonZeroValue,
            script_span.start,
        ));
    }
    let rest = script.get(1..).ok_or_else(|| {
        SemanticError::global(SemanticCategory::InternalInvariant, script_span.start)
    })?;
    let Some(opcode) = rest.first().copied() else {
        return recipient_fact(RecipientType::OpReturn, script, script_span, 1, 0);
    };
    if opcode == 0x00 {
        complete_op_return_push(script, script_span, 2, 0)?;
        return recipient_fact(RecipientType::OpReturn, script, script_span, 2, 0);
    }
    if (0x01..=0x4b).contains(&opcode) {
        let data_len = usize::from(opcode);
        let data_start = 2usize;
        complete_op_return_push(script, script_span, data_start, data_len)?;
        return recipient_fact(
            RecipientType::OpReturn,
            script,
            script_span,
            data_start,
            data_len,
        );
    }
    if opcode == 0x4c {
        let Some(declared) = rest.get(1).copied() else {
            return Err(SemanticError::global(
                SemanticCategory::MalformedScriptPush,
                script_span.start.saturating_add(1),
            ));
        };
        let data_len = usize::from(declared);
        let data_start = 3usize;
        complete_op_return_push(script, script_span, data_start, data_len)?;
        if data_len <= 75 {
            return Err(SemanticError::global(
                SemanticCategory::OpReturnNonMinimalPush,
                script_span.start.saturating_add(1),
            ));
        }
        if data_len > limits::MAX_OP_RETURN_PAYLOAD_BYTES {
            return Err(SemanticError::global(
                SemanticCategory::OpReturnPayloadTooLong,
                script_span.start.saturating_add(data_start),
            ));
        }
        return recipient_fact(
            RecipientType::OpReturn,
            script,
            script_span,
            data_start,
            data_len,
        );
    }
    if opcode == 0x4d {
        let declared: [u8; 2] = rest
            .get(1..3)
            .and_then(|bytes| bytes.try_into().ok())
            .ok_or_else(|| {
                SemanticError::global(
                    SemanticCategory::MalformedScriptPush,
                    script_span.start.saturating_add(1),
                )
            })?;
        let data_len = usize::from(u16::from_le_bytes(declared));
        let data_start = 4usize;
        complete_op_return_push(script, script_span, data_start, data_len)?;
        let category = if data_len <= usize::from(u8::MAX) {
            SemanticCategory::OpReturnNonMinimalPush
        } else {
            SemanticCategory::OpReturnPayloadTooLong
        };
        return Err(SemanticError::global(
            category,
            script_span
                .start
                .saturating_add(if data_len <= usize::from(u8::MAX) {
                    1
                } else {
                    data_start
                }),
        ));
    }
    if opcode == 0x4e {
        let declared: [u8; 4] = rest
            .get(1..5)
            .and_then(|bytes| bytes.try_into().ok())
            .ok_or_else(|| {
                SemanticError::global(
                    SemanticCategory::MalformedScriptPush,
                    script_span.start.saturating_add(1),
                )
            })?;
        let data_len = usize::try_from(u32::from_le_bytes(declared)).map_err(|_| {
            SemanticError::global(
                SemanticCategory::MalformedScriptPush,
                script_span.start.saturating_add(1),
            )
        })?;
        let data_start = 6usize;
        complete_op_return_push(script, script_span, data_start, data_len)?;
        let category = if data_len <= usize::from(u16::MAX) {
            SemanticCategory::OpReturnNonMinimalPush
        } else {
            SemanticCategory::OpReturnPayloadTooLong
        };
        return Err(SemanticError::global(
            category,
            script_span
                .start
                .saturating_add(if data_len <= usize::from(u16::MAX) {
                    1
                } else {
                    data_start
                }),
        ));
    }
    if matches!(opcode, 0x4f | 0x51..=0x60) {
        complete_op_return_push(script, script_span, 2, 0)?;
        return Err(SemanticError::global(
            SemanticCategory::OpReturnNonMinimalPush,
            script_span.start.saturating_add(1),
        ));
    }
    Err(SemanticError::global(
        SemanticCategory::UnsupportedRecipientScript,
        script_span.start.saturating_add(1),
    ))
}

fn classify_recipient_output<'a>(
    output: &OutputSemanticFacts<'a>,
    script_span: Span,
    op_return_seen: &mut bool,
) -> Result<RecipientScriptFacts<'a>, SemanticError> {
    let script = output.script_pubkey;
    match script {
        [0x00, 0x14, program @ ..] if program.len() == 20 => {
            return recipient_fact(RecipientType::P2wpkh, script, script_span, 2, 20);
        }
        [0x00, 0x20, program @ ..] if program.len() == 32 => {
            return recipient_fact(RecipientType::P2wsh, script, script_span, 2, 32);
        }
        [0x51, 0x20, program @ ..] if program.len() == 32 => {
            return recipient_fact(RecipientType::P2tr, script, script_span, 2, 32);
        }
        [0x76, 0xa9, 0x14, hash @ .., 0x88, 0xac] if hash.len() == 20 => {
            return recipient_fact(RecipientType::P2pkh, script, script_span, 3, 20);
        }
        [0xa9, 0x14, hash @ .., 0x87] if hash.len() == 20 => {
            return recipient_fact(RecipientType::P2sh, script, script_span, 2, 20);
        }
        _ => {}
    }

    if is_bare_pubkey(script) {
        return Err(SemanticError::global(
            SemanticCategory::BarePubkeyRecipientScript,
            script_span.start,
        ));
    }
    if parse_multisig_form(script).is_some() {
        return Err(SemanticError::global(
            SemanticCategory::BareMultisigRecipientScript,
            script_span.start,
        ));
    }

    let first = script.first().copied();
    if matches!(first, Some(0x00 | 0x51..=0x60)) {
        let canonical_length = script
            .get(1)
            .copied()
            .filter(|length| (2..=40).contains(length))
            .map(usize::from)
            .and_then(|length| length.checked_add(2))
            == Some(script.len());
        if canonical_length && matches!(first, Some(0x52..=0x60)) {
            return Err(SemanticError::global(
                SemanticCategory::FutureWitnessVersion,
                script_span.start,
            ));
        }
        return Err(SemanticError::global(
            SemanticCategory::MalformedWitnessProgram,
            script_span.start,
        ));
    }

    if first == Some(0x6a) {
        if *op_return_seen {
            return Err(SemanticError::global(
                SemanticCategory::MultipleOpReturnOutputs,
                script_span.start,
            ));
        }
        *op_return_seen = true;
        return classify_op_return(output, script_span);
    }
    Err(SemanticError::global(
        SemanticCategory::UnsupportedRecipientScript,
        script_span.start,
    ))
}

/// Analyze selected recipient-script policy facts after complete M12
/// descriptor ownership and existing M8 signature verification.
///
/// HOST-ONLY READ-ONLY FACTS. Only NotProvenOwned outputs are
/// classified. ProvenChange and ProvenSelfTransfer remain unchanged
/// inside `ownership` and have `None` in `recipient_outputs`.
/// Successful recipient facts expose only an exact raw destination type,
/// borrowed program/hash/data bytes, and their immutable source span.
/// This performs no address encoding, display, amount warning, approval,
/// signing, insertion, finalization, serialization, or export.
///
/// # Errors
///
/// Returns any existing M6/M8/M12 error before M13. Recipient failures
/// then occur in unsigned-output order, with a second OP_RETURN before
/// that output's value or push-shape checks.
pub fn analyze_recipient_script_facts<'a>(
    view: &PsbtView<'a>,
    descriptor: &DescriptorPair,
) -> Result<RecipientScriptAnalysis<'a>, SemanticError> {
    let ownership = analyze_descriptor_ownership(view, descriptor)?;
    let tx_span = view.unsigned_tx().span;
    let inv = SemanticError::global(SemanticCategory::InternalInvariant, tx_span.start);
    let mut cursor = TxCursor::new(view.buffer(), tx_span);
    let version = cursor.u32_le().ok_or(inv)?;
    let input_count = usize::try_from(cursor.compact().ok_or(inv)?).map_err(|_| inv)?;
    if version != ownership.candidate.version || input_count != ownership.candidate.inputs.len() {
        return Err(inv);
    }
    for _ in 0..input_count {
        cursor.take(32).ok_or(inv)?;
        cursor.u32_le().ok_or(inv)?;
        if cursor.compact().ok_or(inv)? != 0 {
            return Err(inv);
        }
        cursor.u32_le().ok_or(inv)?;
    }
    let output_count = usize::try_from(cursor.compact().ok_or(inv)?).map_err(|_| inv)?;
    if ownership.wallet.outputs.len() != ownership.candidate.outputs.len()
        || output_count != ownership.candidate.outputs.len()
    {
        return Err(SemanticError::global(
            SemanticCategory::InternalInvariant,
            tx_span.start,
        ));
    }

    let mut recipient_outputs: Vec<Option<RecipientScriptFacts<'a>>> = Vec::new();
    reserve_exact(&mut recipient_outputs, output_count, tx_span.start)?;
    let mut op_return_seen = false;
    for (owner, output) in ownership
        .wallet
        .outputs
        .iter()
        .zip(&ownership.candidate.outputs)
    {
        let amount = cursor.u64_le().ok_or(inv)?;
        let script_len = usize::try_from(cursor.compact().ok_or(inv)?).map_err(|_| inv)?;
        let script_span = cursor.take(script_len).ok_or(inv)?;
        if amount != output.amount || script_span.slice(view.buffer()) != Some(output.script_pubkey)
        {
            return Err(inv);
        }
        let recipient = match owner {
            OutputOwnership::NotProvenOwned => Some(classify_recipient_output(
                output,
                script_span,
                &mut op_return_seen,
            )?),
            OutputOwnership::ProvenChange(_) | OutputOwnership::ProvenSelfTransfer(_) => None,
        };
        recipient_outputs.push(recipient);
    }
    let locktime = cursor.u32_le().ok_or(inv)?;
    if locktime != ownership.candidate.locktime || !cursor.at_end() {
        return Err(inv);
    }

    Ok(RecipientScriptAnalysis {
        ownership,
        recipient_outputs,
    })
}

// ====================================================================
// M23 HOST-only review-v2 semantic and fee-policy facts (QK-DEC-110).
// ====================================================================

/// One M23 input fact. Existing signatures have passed syntax, strict-DER,
/// low-S, and SIGHASH_ALL checks only; no cryptographic status is carried.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct ReviewV2SemanticInput<'a> {
    /// 32 outpoint txid bytes exactly as serialized in the unsigned tx.
    pub outpoint_txid_wire: &'a [u8],
    /// Selected previous-output index.
    pub outpoint_vout: u32,
    /// MoneyRange-proven previous-output amount.
    pub prevout_amount: u64,
    /// MoneyRange-proven previous-output scriptPubKey.
    pub prevout_script_pubkey: &'a [u8],
    /// Raw unsigned-transaction sequence.
    pub sequence: u32,
    /// Effective sighash type; always SIGHASH_ALL after the M6 syntax phase.
    pub effective_sighash: u32,
    /// Descriptor-proven receive/change branch.
    pub branch: u32,
    /// Descriptor-proven nonhardened child index.
    pub index: u32,
    /// Exact descriptor-reconstructed witness script used by the fixed
    /// BIP141 witness-size estimate. This is public descriptor material.
    pub witness_script: [u8; 105],
}

/// M23 ownership plus destination facts for one unsigned output.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ReviewV2SemanticOutputOwnership<'a> {
    /// No descriptor ownership proof; exact selected recipient type and data.
    NotOwned(RecipientScriptFacts<'a>),
    /// Exact branch-1 descriptor change output.
    ProvenChange(u32),
    /// Exact branch-0 descriptor output, additionally classified as the
    /// required P2WSH destination and carrying its exact 32-byte program.
    ProvenSelfTransfer {
        /// Descriptor child index.
        index: u32,
        /// Exact P2WSH destination fact borrowed from the unsigned tx.
        recipient: RecipientScriptFacts<'a>,
    },
}

/// One M23 output in unsigned-transaction order.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct ReviewV2SemanticOutput<'a> {
    /// MoneyRange-checked output amount.
    pub amount: u64,
    /// Exact borrowed output scriptPubKey bytes.
    pub script_pubkey: &'a [u8],
    /// Descriptor ownership and, for every non-change output, destination.
    pub ownership: ReviewV2SemanticOutputOwnership<'a>,
}

/// Complete no-signature-verification M23 facts consumed by review schema v2.
/// This type intentionally carries no signature count, threshold state,
/// aggregate completion state, authorization, or export disposition.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ReviewV2SemanticAnalysis<'a> {
    /// Raw transaction version.
    pub version: u32,
    /// Raw transaction locktime.
    pub locktime: u32,
    /// Proven input facts in unsigned-transaction order.
    pub inputs: Vec<ReviewV2SemanticInput<'a>>,
    /// Classified output facts in unsigned-transaction order.
    pub outputs: Vec<ReviewV2SemanticOutput<'a>>,
    /// MoneyRange-checked selected-input total.
    pub total_input_amount: u64,
    /// MoneyRange-checked unsigned-output total.
    pub total_output_amount: u64,
    /// Exact checked fee.
    pub fee: u64,
    /// Fixed-witness BIP141 estimate, fee rate, and ordered nonfatal warnings.
    pub fee_policy: FeePolicyFacts,
}

fn map_fee_policy_error(error: ReviewV2Error, offset: usize) -> SemanticError {
    let category = match error {
        ReviewV2Error::EmergencyFeeCeilingExceeded => SemanticCategory::EmergencyFeeCeilingExceeded,
        ReviewV2Error::FeePolicyArithmeticOverflow => SemanticCategory::FeePolicyArithmeticOverflow,
        _ => SemanticCategory::InternalInvariant,
    };
    SemanticError::global(category, offset)
}

/// Build the M23 semantic and QK-FEE-POLICY-V1 facts without verifying any
/// existing partial signature cryptographically.
///
/// This follows the existing structural, SIGHASH_ALL/signature-syntax, token,
/// and M12 descriptor proof phases. Every branch-1 descriptor output remains
/// change; every other output, including branch-0 self-transfer, is passed
/// through the unchanged six-template M13 classifier. The returned surface
/// contains no cryptographic completeness or authorization state.
///
/// # Errors
///
/// Returns the first existing structural/M6/M12/M13 rejection, followed by
/// checked fee-policy arithmetic, the strict emergency ceiling, and warning
/// construction in QK-DEC-110 order.
pub(crate) fn analyze_review_v2_semantics<'a>(
    view: &PsbtView<'a>,
    descriptor: &DescriptorPair,
) -> Result<ReviewV2SemanticAnalysis<'a>, SemanticError> {
    let mut state = structural_phase(view)?;
    verification_screen(view, &state, false)?;
    signature_phase(view, &mut state.work)?;
    token_phase(view, &state)?;

    let tx_span = view.unsigned_tx().span;
    let global_offset = tx_span.start;
    let fingerprints = unique_descriptor_fingerprints(descriptor, global_offset)?;
    let mut derivation_calls = 0usize;

    let mut wallet_inputs: Vec<ProvenWalletInput> = Vec::new();
    reserve_exact(&mut wallet_inputs, state.work.len(), global_offset)?;
    let mut effective_scripts: Vec<DerivedScript> = Vec::new();
    reserve_exact(&mut effective_scripts, state.work.len(), global_offset)?;
    for (input_index, work) in state.work.iter().enumerate() {
        let (wallet_input, script) = prove_descriptor_input(
            view,
            descriptor,
            &fingerprints,
            input_index,
            work,
            &mut derivation_calls,
        )?;
        wallet_inputs.push(wallet_input);
        effective_scripts.push(script);
    }

    let candidate = assemble(view, state)?;
    if candidate.inputs.len() != wallet_inputs.len()
        || candidate.inputs.len() != effective_scripts.len()
    {
        return Err(SemanticError::global(
            SemanticCategory::InternalInvariant,
            global_offset,
        ));
    }

    let mut inputs: Vec<ReviewV2SemanticInput<'a>> = Vec::new();
    reserve_exact(&mut inputs, candidate.inputs.len(), global_offset)?;
    for ((input, wallet), script) in candidate
        .inputs
        .iter()
        .zip(&wallet_inputs)
        .zip(&effective_scripts)
    {
        inputs.push(ReviewV2SemanticInput {
            outpoint_txid_wire: input.outpoint_txid_wire,
            outpoint_vout: input.outpoint_vout,
            prevout_amount: input.prevout_amount,
            prevout_script_pubkey: input.prevout_script_pubkey,
            sequence: input.sequence,
            effective_sighash: u32::from(SIGHASH_ALL),
            branch: wallet.branch,
            index: wallet.index,
            witness_script: script.witness_script,
        });
    }

    let mut wallet_outputs: Vec<OutputOwnership> = Vec::new();
    reserve_exact(&mut wallet_outputs, candidate.outputs.len(), global_offset)?;
    for (output_index, output) in candidate.outputs.iter().enumerate() {
        wallet_outputs.push(classify_descriptor_output(
            view,
            descriptor,
            &fingerprints,
            output_index,
            output,
            &mut derivation_calls,
        )?);
    }

    let inv = SemanticError::global(SemanticCategory::InternalInvariant, global_offset);
    let mut cursor = TxCursor::new(view.buffer(), tx_span);
    let version = cursor.u32_le().ok_or(inv)?;
    let input_count = usize::try_from(cursor.compact().ok_or(inv)?).map_err(|_| inv)?;
    if version != candidate.version || input_count != candidate.inputs.len() {
        return Err(inv);
    }
    for _ in 0..input_count {
        cursor.take(32).ok_or(inv)?;
        cursor.u32_le().ok_or(inv)?;
        if cursor.compact().ok_or(inv)? != 0 {
            return Err(inv);
        }
        cursor.u32_le().ok_or(inv)?;
    }
    let output_count = usize::try_from(cursor.compact().ok_or(inv)?).map_err(|_| inv)?;
    if output_count != candidate.outputs.len() || output_count != wallet_outputs.len() {
        return Err(inv);
    }

    let mut outputs: Vec<ReviewV2SemanticOutput<'a>> = Vec::new();
    reserve_exact(&mut outputs, output_count, global_offset)?;
    let mut op_return_seen = false;
    for (owner, output) in wallet_outputs.iter().zip(&candidate.outputs) {
        let amount = cursor.u64_le().ok_or(inv)?;
        let script_len = usize::try_from(cursor.compact().ok_or(inv)?).map_err(|_| inv)?;
        let script_span = cursor.take(script_len).ok_or(inv)?;
        if amount != output.amount || script_span.slice(view.buffer()) != Some(output.script_pubkey)
        {
            return Err(inv);
        }

        let ownership = match owner {
            OutputOwnership::NotProvenOwned => ReviewV2SemanticOutputOwnership::NotOwned(
                classify_recipient_output(output, script_span, &mut op_return_seen)?,
            ),
            OutputOwnership::ProvenChange(index) => {
                ReviewV2SemanticOutputOwnership::ProvenChange(*index)
            }
            OutputOwnership::ProvenSelfTransfer(index) => {
                let recipient =
                    classify_recipient_output(output, script_span, &mut op_return_seen)?;
                if recipient.recipient_type != RecipientType::P2wsh {
                    return Err(inv);
                }
                ReviewV2SemanticOutputOwnership::ProvenSelfTransfer {
                    index: *index,
                    recipient,
                }
            }
        };
        outputs.push(ReviewV2SemanticOutput {
            amount: output.amount,
            script_pubkey: output.script_pubkey,
            ownership,
        });
    }
    let locktime = cursor.u32_le().ok_or(inv)?;
    if locktime != candidate.locktime || !cursor.at_end() {
        return Err(inv);
    }

    let fee_policy = apply_fee_policy(
        view.unsigned_tx_bytes().len(),
        effective_scripts.len(),
        candidate.fee,
        candidate.total_input_amount,
    )
    .map_err(|error| map_fee_policy_error(error, global_offset))?;

    Ok(ReviewV2SemanticAnalysis {
        version: candidate.version,
        locktime: candidate.locktime,
        inputs,
        outputs,
        total_input_amount: candidate.total_input_amount,
        total_output_amount: candidate.total_output_amount,
        fee: candidate.fee,
        fee_policy,
    })
}
