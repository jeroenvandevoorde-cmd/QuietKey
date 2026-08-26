//! Owned, session-free D-09 v2 review binding and QK-FEE-POLICY-V1.

use crate::limits;
use crate::parse::{InputSource, PsbtView};
use crate::review::{ReviewContext, ReviewNetwork};
use crate::semantic::{
    analyze_review_v2_semantics, RecipientType, ReviewV2SemanticOutputOwnership, SemanticError,
};
use crate::sha256::sha256;
use core::fmt;
use qk_descriptor::DescriptorPair;

/// D-09 v2 schema byte.
pub const REVIEW_V2_SCHEMA_VERSION: u8 = 2;
/// Policy identifier bound in both the hash domain and canonical bytes.
pub const FEE_POLICY_IDENTIFIER: &[u8] = b"QK-FEE-POLICY-V1";
/// Exact D-09 v2 hash domain.
pub const REVIEW_V2_HASH_DOMAIN: &[u8] = b"QuietKey/D-09/review/v2/QK-FEE-POLICY-V1";
/// Exact HOST-candidate maximum canonical D-09 v2 byte length.
pub const MAX_CANONICAL_REVIEW_V2_BYTES: usize = limits::MAX_CANONICAL_REVIEW_V2_BYTES;
/// Exact HOST-candidate maximum streamed hash transcript length.
pub const MAX_REVIEW_V2_HASH_TRANSCRIPT_BYTES: usize = limits::MAX_REVIEW_V2_HASH_TRANSCRIPT_BYTES;
/// Exact HOST-candidate maximum estimated virtual size.
pub const MAX_ESTIMATED_VSIZE: u32 = limits::MAX_ESTIMATED_VSIZE;
/// Maximum number of simultaneously applicable fee warnings.
pub const MAX_FEE_WARNINGS: usize = 3;

const SIGHASH_ALL: u32 = 1;
const MAX_UNSIGNED_TX_BYTES: usize = 5_535;
const ESTIMATED_WITNESS_BYTES_PER_INPUT: usize = 254;
const EMERGENCY_FEE_CEILING_SATS: u64 = 5_000_000;
const LOW_FEE_RATE_MSAT_PER_VBYTE: u64 = 1_000;
const HIGH_FEE_RATE_MSAT_PER_VBYTE: u64 = 200_000;
const HIGH_ABSOLUTE_FEE_SATS: u64 = 1_000_000;

const _: [(); 16] = [(); FEE_POLICY_IDENTIFIER.len()];
const _: [(); 40] = [(); REVIEW_V2_HASH_DOMAIN.len()];
const _: [(); 254] = [(); 1 + 1 + (2 * (1 + 72)) + 1 + 105];
const _: [(); 11_886] = [(); ((4usize * 5_535) + 2 + (100 * 254)).div_ceil(4)];
const _: [(); MAX_CANONICAL_REVIEW_V2_BYTES] = [(); 162 + 5_535 + (100 * 102) + 185 + (31 * 92)];
const _: [(); MAX_REVIEW_V2_HASH_TRANSCRIPT_BYTES] = [(); MAX_CANONICAL_REVIEW_V2_BYTES + 40 + 1];

/// D-09 v2 review hash.
pub type ReviewV2Hash = [u8; 32];

/// A deterministic direct-RBF signal derived from an input sequence.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DirectRbf {
    /// The sequence is at least `0xfffffffe`.
    NotSignaled,
    /// The sequence is below `0xfffffffe`.
    Signaled,
}

impl DirectRbf {
    const fn from_sequence(sequence: u32) -> Self {
        if sequence < 0xffff_fffe {
            Self::Signaled
        } else {
            Self::NotSignaled
        }
    }
}

/// One QK-FEE-POLICY-V1 warning in canonical order.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FeeWarning {
    /// Fee rate below 1,000 milli-satoshi per virtual byte.
    RateLow,
    /// Fee rate at least 200,000 milli-satoshi per virtual byte.
    RateHigh,
    /// Fee is at least five percent of checked input value.
    ShareHigh,
    /// Absolute fee is at least 1,000,000 satoshis.
    AbsoluteHigh,
}

impl FeeWarning {
    /// Stable canonical warning tag.
    #[must_use]
    pub const fn tag(self) -> u8 {
        match self {
            Self::RateLow => 1,
            Self::RateHigh => 2,
            Self::ShareHigh => 3,
            Self::AbsoluteHigh => 4,
        }
    }

    /// Stable human-readable warning code.
    #[must_use]
    pub const fn code(self) -> &'static str {
        match self {
            Self::RateLow => "W-FEERATE-LOW",
            Self::RateHigh => "W-FEERATE-HIGH",
            Self::ShareHigh => "W-FEESHARE-HIGH",
            Self::AbsoluteHigh => "W-FEEABS-HIGH",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct FeeWarningSet {
    fee_rate_low: bool,
    fee_rate_high: bool,
    fee_share_high: bool,
    fee_absolute_high: bool,
}

impl FeeWarningSet {
    fn iter(self) -> impl Iterator<Item = FeeWarning> {
        [
            self.fee_rate_low.then_some(FeeWarning::RateLow),
            self.fee_rate_high.then_some(FeeWarning::RateHigh),
            self.fee_share_high.then_some(FeeWarning::ShareHigh),
            self.fee_absolute_high.then_some(FeeWarning::AbsoluteHigh),
        ]
        .into_iter()
        .flatten()
    }

    fn count(self) -> usize {
        self.iter().count()
    }
}

/// Derived QK-FEE-POLICY-V1 facts.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FeePolicyFacts {
    estimated_vsize: u32,
    fee_rate_msat_per_vbyte: u64,
    warnings: FeeWarningSet,
}

impl FeePolicyFacts {
    /// Estimated virtual size under the fixed v1 witness model.
    #[must_use]
    pub const fn estimated_vsize(&self) -> u32 {
        self.estimated_vsize
    }

    /// Truncated internal fee rate in milli-satoshi per virtual byte.
    #[must_use]
    pub const fn fee_rate_msat_per_vbyte(&self) -> u64 {
        self.fee_rate_msat_per_vbyte
    }

    /// Number of applicable warnings.
    #[must_use]
    pub fn warning_count(&self) -> usize {
        self.warnings.count()
    }

    /// Applicable warnings in their fixed canonical order.
    pub fn warnings(&self) -> impl Iterator<Item = FeeWarning> {
        self.warnings.iter()
    }
}

/// Borrowed facts for one proven input at the semantic-to-review seam.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct ReviewV2InputFacts<'a> {
    /// Explicit unsigned-transaction input index.
    pub index: u32,
    /// Wire-order outpoint transaction ID.
    pub outpoint_txid_wire: [u8; 32],
    /// Outpoint output index.
    pub outpoint_vout: u32,
    /// Proven selected previous-output amount.
    pub prevout_amount: u64,
    /// Proven selected previous-output scriptPubKey.
    pub prevout_script_pubkey: &'a [u8],
    /// Raw unsigned-transaction sequence.
    pub sequence: u32,
    /// Effective sighash, required to be SIGHASH_ALL.
    pub effective_sighash: u32,
    /// Proven descriptor branch.
    pub branch: u32,
    /// Proven descriptor child index.
    pub child_index: u32,
}

/// Output ownership, parameterized over borrowed or owned exact data.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReviewV2OutputOwnership<B> {
    /// Not descriptor-owned, with an exact accepted recipient classification.
    NotOwned {
        /// Accepted destination template.
        recipient_type: RecipientType,
        /// Exact program, hash, or OP_RETURN payload.
        data: B,
    },
    /// Descriptor-proven change child.
    ProvenChange {
        /// Descriptor child index.
        child_index: u32,
    },
    /// Descriptor-proven branch-zero self-transfer.
    ProvenSelfTransfer {
        /// Descriptor child index.
        child_index: u32,
        /// Exact 32-byte P2WSH witness program.
        witness_program: B,
    },
}

/// Borrowed facts for one output at the semantic-to-review seam.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct ReviewV2OutputFacts<'a> {
    /// Explicit unsigned-transaction output index.
    pub index: u32,
    /// Output amount.
    pub amount: u64,
    /// Exact raw output scriptPubKey.
    pub script_pubkey: &'a [u8],
    /// Proven ownership or recipient classification.
    pub ownership: ReviewV2OutputOwnership<&'a [u8]>,
}

/// Borrowed, already-proven inputs to D-09 v2 construction.
///
/// The semantic adapter owns the hostile-input work and produces this
/// closed seam. [`build_review_v2_from_facts`] validates its bounded
/// shape, applies the fee policy, and returns a fully owned review.
#[derive(Debug, Clone, Copy)]
pub(crate) struct ReviewV2Facts<'a> {
    /// Network and exact retained-input provenance.
    pub context: ReviewContext,
    /// SHA-256 of exact immutable S0 bytes.
    pub s0_sha256: [u8; 32],
    /// Authenticated descriptor wallet ID.
    pub wallet_id: [u8; 32],
    /// Authenticated descriptor A/B/C fingerprints.
    pub origin_fingerprints: [[u8; 4]; 3],
    /// Exact unsigned-transaction value bytes.
    pub unsigned_tx: &'a [u8],
    /// Raw unsigned-transaction version.
    pub version: u32,
    /// Raw unsigned-transaction locktime.
    pub locktime: u32,
    /// Proven input facts in transaction order.
    pub inputs: &'a [ReviewV2InputFacts<'a>],
    /// Classified output facts in transaction order.
    pub outputs: &'a [ReviewV2OutputFacts<'a>],
    /// Checked total selected-input amount.
    pub total_input_amount: u64,
    /// Checked total unsigned-output amount.
    pub total_output_amount: u64,
    /// Exact checked fee.
    pub fee: u64,
    /// Policy facts computed by the semantic route from the same exact facts.
    pub fee_policy: FeePolicyFacts,
}

/// Fully owned facts for one review input.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReviewV2Input {
    index: u32,
    outpoint_txid_wire: [u8; 32],
    outpoint_vout: u32,
    prevout_amount: u64,
    prevout_script_pubkey: Vec<u8>,
    sequence: u32,
    effective_sighash: u32,
    branch: u32,
    child_index: u32,
}

impl ReviewV2Input {
    /// Explicit input index.
    #[must_use]
    pub const fn index(&self) -> u32 {
        self.index
    }

    /// Wire-order outpoint transaction ID.
    #[must_use]
    pub const fn outpoint_txid_wire(&self) -> [u8; 32] {
        self.outpoint_txid_wire
    }

    /// Outpoint output index.
    #[must_use]
    pub const fn outpoint_vout(&self) -> u32 {
        self.outpoint_vout
    }

    /// Proven selected previous-output amount.
    #[must_use]
    pub const fn prevout_amount(&self) -> u64 {
        self.prevout_amount
    }

    /// Proven selected previous-output scriptPubKey.
    #[must_use]
    pub fn prevout_script_pubkey(&self) -> &[u8] {
        &self.prevout_script_pubkey
    }

    /// Raw sequence.
    #[must_use]
    pub const fn sequence(&self) -> u32 {
        self.sequence
    }

    /// Effective sighash.
    #[must_use]
    pub const fn effective_sighash(&self) -> u32 {
        self.effective_sighash
    }

    /// Proven descriptor branch.
    #[must_use]
    pub const fn branch(&self) -> u32 {
        self.branch
    }

    /// Proven descriptor child index.
    #[must_use]
    pub const fn child_index(&self) -> u32 {
        self.child_index
    }

    /// Direct-RBF signal derived from the raw sequence.
    #[must_use]
    pub const fn direct_rbf(&self) -> DirectRbf {
        DirectRbf::from_sequence(self.sequence)
    }
}

/// Fully owned facts for one review output.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReviewV2Output {
    index: u32,
    amount: u64,
    script_pubkey: Vec<u8>,
    ownership: ReviewV2OutputOwnership<Vec<u8>>,
}

impl ReviewV2Output {
    /// Explicit output index.
    #[must_use]
    pub const fn index(&self) -> u32 {
        self.index
    }

    /// Output amount.
    #[must_use]
    pub const fn amount(&self) -> u64 {
        self.amount
    }

    /// Exact raw output scriptPubKey.
    #[must_use]
    pub fn script_pubkey(&self) -> &[u8] {
        &self.script_pubkey
    }

    /// Proven ownership or recipient classification.
    #[must_use]
    pub const fn ownership(&self) -> &ReviewV2OutputOwnership<Vec<u8>> {
        &self.ownership
    }
}

/// Complete, fully owned, session-free D-09 v2 review.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReviewV2 {
    context: ReviewContext,
    s0_sha256: [u8; 32],
    wallet_id: [u8; 32],
    origin_fingerprints: [[u8; 4]; 3],
    unsigned_tx: Vec<u8>,
    version: u32,
    locktime: u32,
    inputs: Vec<ReviewV2Input>,
    outputs: Vec<ReviewV2Output>,
    total_input_amount: u64,
    total_output_amount: u64,
    fee: u64,
    fee_policy: FeePolicyFacts,
    canonical: Vec<u8>,
}

impl ReviewV2 {
    /// Canonical schema version.
    #[must_use]
    pub const fn schema_version(&self) -> u8 {
        REVIEW_V2_SCHEMA_VERSION
    }

    /// Construction context.
    #[must_use]
    pub const fn context(&self) -> ReviewContext {
        self.context
    }

    /// SHA-256 of exact immutable S0 bytes.
    #[must_use]
    pub const fn s0_sha256(&self) -> [u8; 32] {
        self.s0_sha256
    }

    /// Authenticated descriptor wallet ID.
    #[must_use]
    pub const fn wallet_id(&self) -> [u8; 32] {
        self.wallet_id
    }

    /// Authenticated descriptor A/B/C fingerprints.
    #[must_use]
    pub const fn origin_fingerprints(&self) -> [[u8; 4]; 3] {
        self.origin_fingerprints
    }

    /// Repeated policy identifier bound by the schema and hash domain.
    #[must_use]
    pub const fn fee_policy_identifier(&self) -> &'static [u8] {
        FEE_POLICY_IDENTIFIER
    }

    /// Exact unsigned-transaction value bytes.
    #[must_use]
    pub fn unsigned_tx_bytes(&self) -> &[u8] {
        &self.unsigned_tx
    }

    /// Raw transaction version.
    #[must_use]
    pub const fn version(&self) -> u32 {
        self.version
    }

    /// Raw transaction locktime.
    #[must_use]
    pub const fn locktime(&self) -> u32 {
        self.locktime
    }

    /// Fully owned input facts in transaction order.
    #[must_use]
    pub fn inputs(&self) -> &[ReviewV2Input] {
        &self.inputs
    }

    /// Fully owned output facts in transaction order.
    #[must_use]
    pub fn outputs(&self) -> &[ReviewV2Output] {
        &self.outputs
    }

    /// Checked total selected-input amount.
    #[must_use]
    pub const fn total_input_amount(&self) -> u64 {
        self.total_input_amount
    }

    /// Checked total unsigned-output amount.
    #[must_use]
    pub const fn total_output_amount(&self) -> u64 {
        self.total_output_amount
    }

    /// Exact checked fee.
    #[must_use]
    pub const fn fee(&self) -> u64 {
        self.fee
    }

    /// Derived fee-policy facts.
    #[must_use]
    pub const fn fee_policy(&self) -> FeePolicyFacts {
        self.fee_policy
    }

    /// Estimated virtual size under the fixed v1 witness model.
    #[must_use]
    pub const fn estimated_vsize(&self) -> u32 {
        self.fee_policy.estimated_vsize()
    }

    /// Truncated internal fee rate in milli-satoshi per virtual byte.
    #[must_use]
    pub const fn fee_rate_msat_per_vbyte(&self) -> u64 {
        self.fee_policy.fee_rate_msat_per_vbyte()
    }

    /// Applicable fee warnings in their fixed canonical order.
    pub fn fee_warnings(&self) -> impl Iterator<Item = FeeWarning> {
        self.fee_policy.warnings()
    }

    /// Aggregate direct-RBF signal derived from all raw sequences.
    #[must_use]
    pub fn direct_rbf(&self) -> DirectRbf {
        if self
            .inputs
            .iter()
            .any(|input| input.direct_rbf() == DirectRbf::Signaled)
        {
            DirectRbf::Signaled
        } else {
            DirectRbf::NotSignaled
        }
    }

    /// Exact canonical D-09 v2 bytes.
    #[must_use]
    pub fn canonical_bytes(&self) -> &[u8] {
        &self.canonical
    }

    /// SHA-256 of the exact domain, separator, and canonical bytes.
    ///
    /// # Errors
    ///
    /// Returns [`ReviewV2Error::HashFailure`] if checked SHA-256 length
    /// accounting fails.
    pub fn review_hash(&self) -> Result<ReviewV2Hash, ReviewV2Error> {
        hash_canonical(&self.canonical)
    }
}

/// Explicit v2 binding or fee-policy failure.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReviewV2Error {
    /// The requested context source differs from the immutable parsed source.
    SourceMismatch,
    /// Hostile-input semantic analysis rejected under its stable category.
    Semantic(SemanticError),
    /// Effective input sighash is not SIGHASH_ALL.
    UnsupportedSighash,
    /// Checked QK-FEE-POLICY-V1 arithmetic overflowed or produced zero vsize.
    FeePolicyArithmeticOverflow,
    /// Exact fee exceeds 5,000,000 satoshis.
    EmergencyFeeCeilingExceeded,
    /// The semantic seam supplied more than 100 inputs.
    InputCountTooLarge,
    /// The semantic seam supplied more than 32 outputs.
    OutputCountTooLarge,
    /// Exact unsigned transaction exceeds the 5,535-byte profile maximum.
    UnsignedTransactionTooLong,
    /// Explicit input index differs from its transaction position.
    InputIndexMismatch,
    /// Explicit output index differs from its transaction position.
    OutputIndexMismatch,
    /// Checked canonical length arithmetic overflowed.
    LengthOverflow,
    /// A count or variable field cannot be represented by u32.
    FieldLengthOverflow,
    /// Canonical bytes exceed the exact D-09 v2 cap.
    CanonicalTooLong,
    /// A bounded allocation failed.
    AllocationFailed,
    /// SHA-256 length accounting or an internal hash invariant failed.
    HashFailure,
    /// Already-proven facts violated the closed seam's shape or totals.
    InternalInvariant,
}

impl fmt::Display for ReviewV2Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::SourceMismatch => {
                f.write_str("review context input source differs from parsed PSBT source")
            }
            Self::Semantic(error) => write!(f, "review-v2 semantic analysis failed: {error}"),
            Self::UnsupportedSighash => f.write_str("unsupported effective sighash"),
            Self::FeePolicyArithmeticOverflow => {
                f.write_str("QK-FEE-POLICY-V1 arithmetic overflow")
            }
            Self::EmergencyFeeCeilingExceeded => {
                f.write_str("fee exceeds QK-FEE-POLICY-V1 emergency ceiling")
            }
            Self::InputCountTooLarge => f.write_str("review input count exceeds cap"),
            Self::OutputCountTooLarge => f.write_str("review output count exceeds cap"),
            Self::UnsignedTransactionTooLong => {
                f.write_str("exact unsigned transaction exceeds profile cap")
            }
            Self::InputIndexMismatch => f.write_str("review input index mismatch"),
            Self::OutputIndexMismatch => f.write_str("review output index mismatch"),
            Self::LengthOverflow => f.write_str("review length arithmetic overflow"),
            Self::FieldLengthOverflow => f.write_str("review field length exceeds u32"),
            Self::CanonicalTooLong => f.write_str("canonical review exceeds byte cap"),
            Self::AllocationFailed => f.write_str("review allocation failed"),
            Self::HashFailure => f.write_str("review hash failed"),
            Self::InternalInvariant => f.write_str("review fact invariant failed"),
        }
    }
}

impl std::error::Error for ReviewV2Error {}

impl From<SemanticError> for ReviewV2Error {
    fn from(value: SemanticError) -> Self {
        Self::Semantic(value)
    }
}

fn hash_canonical(canonical: &[u8]) -> Result<ReviewV2Hash, ReviewV2Error> {
    sha256(&[REVIEW_V2_HASH_DOMAIN, &[0], canonical]).map_err(|_| ReviewV2Error::HashFailure)
}

/// Estimate virtual size from the exact unsigned transaction length and
/// the fixed 254-byte v1 witness serialization for each input.
///
/// # Errors
///
/// Returns [`ReviewV2Error::FeePolicyArithmeticOverflow`] for checked
/// arithmetic failure or an unrepresentable/zero virtual size.
pub(crate) fn estimate_vsize(
    unsigned_tx_len: usize,
    input_count: usize,
) -> Result<u32, ReviewV2Error> {
    let base_weight = unsigned_tx_len
        .checked_mul(4)
        .and_then(|weight| weight.checked_add(2))
        .ok_or(ReviewV2Error::FeePolicyArithmeticOverflow)?;
    let witness_weight = input_count
        .checked_mul(ESTIMATED_WITNESS_BYTES_PER_INPUT)
        .ok_or(ReviewV2Error::FeePolicyArithmeticOverflow)?;
    let weight = base_weight
        .checked_add(witness_weight)
        .ok_or(ReviewV2Error::FeePolicyArithmeticOverflow)?;
    let rounded_weight = weight
        .checked_add(3)
        .ok_or(ReviewV2Error::FeePolicyArithmeticOverflow)?;
    let vsize = rounded_weight / 4;
    if vsize == 0 {
        return Err(ReviewV2Error::FeePolicyArithmeticOverflow);
    }
    u32::try_from(vsize).map_err(|_| ReviewV2Error::FeePolicyArithmeticOverflow)
}

fn classify_fee_warnings(
    fee_rate_msat_per_vbyte: u64,
    fee: u64,
    total_input_amount: u64,
) -> Result<FeeWarningSet, ReviewV2Error> {
    let scaled_fee = fee
        .checked_mul(20)
        .ok_or(ReviewV2Error::FeePolicyArithmeticOverflow)?;
    Ok(FeeWarningSet {
        fee_rate_low: fee_rate_msat_per_vbyte < LOW_FEE_RATE_MSAT_PER_VBYTE,
        fee_rate_high: fee_rate_msat_per_vbyte >= HIGH_FEE_RATE_MSAT_PER_VBYTE,
        fee_share_high: scaled_fee >= total_input_amount,
        fee_absolute_high: fee >= HIGH_ABSOLUTE_FEE_SATS,
    })
}

/// Apply QK-FEE-POLICY-V1 to already-checked fee and input totals.
///
/// # Errors
///
/// Returns the named emergency-ceiling or checked-arithmetic failure.
pub(crate) fn apply_fee_policy(
    unsigned_tx_len: usize,
    input_count: usize,
    fee: u64,
    total_input_amount: u64,
) -> Result<FeePolicyFacts, ReviewV2Error> {
    let estimated_vsize = estimate_vsize(unsigned_tx_len, input_count)?;
    let scaled_fee = fee
        .checked_mul(1_000)
        .ok_or(ReviewV2Error::FeePolicyArithmeticOverflow)?;
    let fee_rate_msat_per_vbyte = scaled_fee
        .checked_div(u64::from(estimated_vsize))
        .ok_or(ReviewV2Error::FeePolicyArithmeticOverflow)?;
    if fee > EMERGENCY_FEE_CEILING_SATS {
        return Err(ReviewV2Error::EmergencyFeeCeilingExceeded);
    }
    let warnings = classify_fee_warnings(fee_rate_msat_per_vbyte, fee, total_input_amount)?;
    if warnings.count() > MAX_FEE_WARNINGS {
        return Err(ReviewV2Error::InternalInvariant);
    }
    Ok(FeePolicyFacts {
        estimated_vsize,
        fee_rate_msat_per_vbyte,
        warnings,
    })
}

fn checked_add(total: &mut usize, value: usize) -> Result<(), ReviewV2Error> {
    *total = total
        .checked_add(value)
        .ok_or(ReviewV2Error::LengthOverflow)?;
    Ok(())
}

fn variable_len(total: &mut usize, bytes: &[u8]) -> Result<(), ReviewV2Error> {
    u32::try_from(bytes.len()).map_err(|_| ReviewV2Error::FieldLengthOverflow)?;
    checked_add(total, 4)?;
    checked_add(total, bytes.len())
}

fn network_code(network: ReviewNetwork) -> u8 {
    match network {
        ReviewNetwork::BitcoinMainnet => 1,
    }
}

fn source_code(source: InputSource) -> u8 {
    match source {
        InputSource::MicroSd => 1,
        InputSource::Qr => 2,
    }
}

fn recipient_code(recipient: RecipientType) -> u8 {
    match recipient {
        RecipientType::P2wpkh => 1,
        RecipientType::P2wsh => 2,
        RecipientType::P2tr => 3,
        RecipientType::P2pkh => 4,
        RecipientType::P2sh => 5,
        RecipientType::OpReturn => 6,
    }
}

fn put_u32(bytes: &mut Vec<u8>, value: u32) {
    bytes.extend_from_slice(&value.to_le_bytes());
}

fn put_u64(bytes: &mut Vec<u8>, value: u64) {
    bytes.extend_from_slice(&value.to_le_bytes());
}

fn put_variable(bytes: &mut Vec<u8>, value: &[u8]) -> Result<(), ReviewV2Error> {
    let length = u32::try_from(value.len()).map_err(|_| ReviewV2Error::FieldLengthOverflow)?;
    put_u32(bytes, length);
    bytes.extend_from_slice(value);
    Ok(())
}

fn p2wsh_shape(script: &[u8]) -> bool {
    matches!(script, [0x00, 0x20, program @ ..] if program.len() == 32)
}

fn op_return_shape(script: &[u8], data: &[u8]) -> bool {
    match script {
        [0x6a] => data.is_empty(),
        [0x6a, 0x00] => data.is_empty(),
        [0x6a, length @ 0x01..=0x4b, payload @ ..] => {
            usize::from(*length) == data.len() && payload == data
        }
        [0x6a, 0x4c, length @ 76..=80, payload @ ..] => {
            usize::from(*length) == data.len() && payload == data
        }
        _ => false,
    }
}

fn recipient_shape(recipient_type: RecipientType, script: &[u8], data: &[u8], amount: u64) -> bool {
    match recipient_type {
        RecipientType::P2wpkh => {
            matches!(script, [0x00, 0x14, program @ ..] if program.len() == 20 && program == data)
        }
        RecipientType::P2wsh => {
            matches!(script, [0x00, 0x20, program @ ..] if program.len() == 32 && program == data)
        }
        RecipientType::P2tr => {
            matches!(script, [0x51, 0x20, program @ ..] if program.len() == 32 && program == data)
        }
        RecipientType::P2pkh => {
            matches!(script, [0x76, 0xa9, 0x14, hash @ .., 0x88, 0xac] if hash.len() == 20 && hash == data)
        }
        RecipientType::P2sh => {
            matches!(script, [0xa9, 0x14, hash @ .., 0x87] if hash.len() == 20 && hash == data)
        }
        RecipientType::OpReturn => {
            amount == 0
                && data.len() <= limits::MAX_OP_RETURN_PAYLOAD_BYTES
                && op_return_shape(script, data)
        }
    }
}

fn validate_facts(facts: &ReviewV2Facts<'_>) -> Result<(), ReviewV2Error> {
    if facts.inputs.len() > limits::MAX_INPUTS {
        return Err(ReviewV2Error::InputCountTooLarge);
    }
    if facts.outputs.len() > limits::MAX_OUTPUTS {
        return Err(ReviewV2Error::OutputCountTooLarge);
    }
    if facts.unsigned_tx.len() > MAX_UNSIGNED_TX_BYTES {
        return Err(ReviewV2Error::UnsignedTransactionTooLong);
    }
    u32::try_from(facts.inputs.len()).map_err(|_| ReviewV2Error::FieldLengthOverflow)?;
    u32::try_from(facts.outputs.len()).map_err(|_| ReviewV2Error::FieldLengthOverflow)?;
    u32::try_from(facts.unsigned_tx.len()).map_err(|_| ReviewV2Error::FieldLengthOverflow)?;

    let mut input_total = 0u64;
    for (position, input) in facts.inputs.iter().enumerate() {
        let expected = u32::try_from(position).map_err(|_| ReviewV2Error::FieldLengthOverflow)?;
        if input.index != expected {
            return Err(ReviewV2Error::InputIndexMismatch);
        }
        if input.effective_sighash != SIGHASH_ALL {
            return Err(ReviewV2Error::UnsupportedSighash);
        }
        if input.branch > 1
            || input.child_index > limits::MAX_CHILD_INDEX
            || !p2wsh_shape(input.prevout_script_pubkey)
        {
            return Err(ReviewV2Error::InternalInvariant);
        }
        input_total = input_total
            .checked_add(input.prevout_amount)
            .ok_or(ReviewV2Error::InternalInvariant)?;
    }
    if input_total != facts.total_input_amount {
        return Err(ReviewV2Error::InternalInvariant);
    }

    let mut output_total = 0u64;
    let mut saw_op_return = false;
    for (position, output) in facts.outputs.iter().enumerate() {
        let expected = u32::try_from(position).map_err(|_| ReviewV2Error::FieldLengthOverflow)?;
        if output.index != expected {
            return Err(ReviewV2Error::OutputIndexMismatch);
        }
        output_total = output_total
            .checked_add(output.amount)
            .ok_or(ReviewV2Error::InternalInvariant)?;
        match output.ownership {
            ReviewV2OutputOwnership::NotOwned {
                recipient_type,
                data,
            } => {
                if recipient_type == RecipientType::OpReturn {
                    if saw_op_return {
                        return Err(ReviewV2Error::InternalInvariant);
                    }
                    saw_op_return = true;
                }
                if !recipient_shape(recipient_type, output.script_pubkey, data, output.amount) {
                    return Err(ReviewV2Error::InternalInvariant);
                }
            }
            ReviewV2OutputOwnership::ProvenChange { child_index } => {
                if child_index > limits::MAX_CHILD_INDEX || !p2wsh_shape(output.script_pubkey) {
                    return Err(ReviewV2Error::InternalInvariant);
                }
            }
            ReviewV2OutputOwnership::ProvenSelfTransfer {
                child_index,
                witness_program,
            } => {
                if child_index > limits::MAX_CHILD_INDEX
                    || !matches!(output.script_pubkey, [0x00, 0x20, program @ ..] if program.len() == 32 && program == witness_program)
                {
                    return Err(ReviewV2Error::InternalInvariant);
                }
            }
        }
    }
    if output_total != facts.total_output_amount {
        return Err(ReviewV2Error::InternalInvariant);
    }
    let recomputed_fee = facts
        .total_input_amount
        .checked_sub(facts.total_output_amount)
        .ok_or(ReviewV2Error::InternalInvariant)?;
    if recomputed_fee != facts.fee {
        return Err(ReviewV2Error::InternalInvariant);
    }
    Ok(())
}

fn canonical_length(
    facts: &ReviewV2Facts<'_>,
    fee_policy: FeePolicyFacts,
) -> Result<usize, ReviewV2Error> {
    let mut length = 159usize;
    checked_add(&mut length, facts.unsigned_tx.len())?;
    checked_add(&mut length, fee_policy.warning_count())?;
    for input in facts.inputs {
        checked_add(&mut length, 64)?;
        variable_len(&mut length, input.prevout_script_pubkey)?;
    }
    for output in facts.outputs {
        checked_add(&mut length, 12)?;
        variable_len(&mut length, output.script_pubkey)?;
        checked_add(&mut length, 1)?;
        match output.ownership {
            ReviewV2OutputOwnership::NotOwned { data, .. } => {
                checked_add(&mut length, 1)?;
                variable_len(&mut length, data)?;
            }
            ReviewV2OutputOwnership::ProvenChange { .. } => {
                checked_add(&mut length, 4)?;
            }
            ReviewV2OutputOwnership::ProvenSelfTransfer {
                witness_program, ..
            } => {
                checked_add(&mut length, 5)?;
                variable_len(&mut length, witness_program)?;
            }
        }
    }
    if length > MAX_CANONICAL_REVIEW_V2_BYTES {
        return Err(ReviewV2Error::CanonicalTooLong);
    }
    Ok(length)
}

fn canonical_bytes(
    facts: &ReviewV2Facts<'_>,
    fee_policy: FeePolicyFacts,
) -> Result<Vec<u8>, ReviewV2Error> {
    let length = canonical_length(facts, fee_policy)?;
    let input_count =
        u32::try_from(facts.inputs.len()).map_err(|_| ReviewV2Error::FieldLengthOverflow)?;
    let output_count =
        u32::try_from(facts.outputs.len()).map_err(|_| ReviewV2Error::FieldLengthOverflow)?;
    let warning_count = u32::try_from(fee_policy.warning_count())
        .map_err(|_| ReviewV2Error::FieldLengthOverflow)?;

    let mut bytes = Vec::new();
    bytes
        .try_reserve_exact(length)
        .map_err(|_| ReviewV2Error::AllocationFailed)?;
    bytes.push(REVIEW_V2_SCHEMA_VERSION);
    bytes.push(network_code(facts.context.network));
    bytes.push(source_code(facts.context.input_source));
    bytes.extend_from_slice(&facts.s0_sha256);
    bytes.extend_from_slice(&facts.wallet_id);
    for fingerprint in facts.origin_fingerprints {
        bytes.extend_from_slice(&fingerprint);
    }
    put_variable(&mut bytes, FEE_POLICY_IDENTIFIER)?;
    put_variable(&mut bytes, facts.unsigned_tx)?;
    put_u32(&mut bytes, facts.version);
    put_u32(&mut bytes, facts.locktime);
    put_u32(&mut bytes, input_count);
    for input in facts.inputs {
        put_u32(&mut bytes, input.index);
        bytes.extend_from_slice(&input.outpoint_txid_wire);
        put_u32(&mut bytes, input.outpoint_vout);
        put_u64(&mut bytes, input.prevout_amount);
        put_variable(&mut bytes, input.prevout_script_pubkey)?;
        put_u32(&mut bytes, input.sequence);
        put_u32(&mut bytes, input.effective_sighash);
        put_u32(&mut bytes, input.branch);
        put_u32(&mut bytes, input.child_index);
    }
    put_u32(&mut bytes, output_count);
    for output in facts.outputs {
        put_u32(&mut bytes, output.index);
        put_u64(&mut bytes, output.amount);
        put_variable(&mut bytes, output.script_pubkey)?;
        match output.ownership {
            ReviewV2OutputOwnership::NotOwned {
                recipient_type,
                data,
            } => {
                bytes.push(1);
                bytes.push(recipient_code(recipient_type));
                put_variable(&mut bytes, data)?;
            }
            ReviewV2OutputOwnership::ProvenChange { child_index } => {
                bytes.push(2);
                put_u32(&mut bytes, child_index);
            }
            ReviewV2OutputOwnership::ProvenSelfTransfer {
                child_index,
                witness_program,
            } => {
                bytes.push(3);
                put_u32(&mut bytes, child_index);
                bytes.push(recipient_code(RecipientType::P2wsh));
                put_variable(&mut bytes, witness_program)?;
            }
        }
    }
    put_u64(&mut bytes, facts.total_input_amount);
    put_u64(&mut bytes, facts.total_output_amount);
    put_u64(&mut bytes, facts.fee);
    put_u32(&mut bytes, fee_policy.estimated_vsize());
    put_u64(&mut bytes, fee_policy.fee_rate_msat_per_vbyte());
    put_u32(&mut bytes, warning_count);
    for warning in fee_policy.warnings() {
        bytes.push(warning.tag());
    }
    if bytes.len() != length {
        return Err(ReviewV2Error::InternalInvariant);
    }
    Ok(bytes)
}

fn own_bytes(bytes: &[u8]) -> Result<Vec<u8>, ReviewV2Error> {
    let mut owned = Vec::new();
    owned
        .try_reserve_exact(bytes.len())
        .map_err(|_| ReviewV2Error::AllocationFailed)?;
    owned.extend_from_slice(bytes);
    Ok(owned)
}

fn own_inputs(inputs: &[ReviewV2InputFacts<'_>]) -> Result<Vec<ReviewV2Input>, ReviewV2Error> {
    let mut owned = Vec::new();
    owned
        .try_reserve_exact(inputs.len())
        .map_err(|_| ReviewV2Error::AllocationFailed)?;
    for input in inputs {
        owned.push(ReviewV2Input {
            index: input.index,
            outpoint_txid_wire: input.outpoint_txid_wire,
            outpoint_vout: input.outpoint_vout,
            prevout_amount: input.prevout_amount,
            prevout_script_pubkey: own_bytes(input.prevout_script_pubkey)?,
            sequence: input.sequence,
            effective_sighash: input.effective_sighash,
            branch: input.branch,
            child_index: input.child_index,
        });
    }
    Ok(owned)
}

fn own_outputs(outputs: &[ReviewV2OutputFacts<'_>]) -> Result<Vec<ReviewV2Output>, ReviewV2Error> {
    let mut owned = Vec::new();
    owned
        .try_reserve_exact(outputs.len())
        .map_err(|_| ReviewV2Error::AllocationFailed)?;
    for output in outputs {
        let ownership = match output.ownership {
            ReviewV2OutputOwnership::NotOwned {
                recipient_type,
                data,
            } => ReviewV2OutputOwnership::NotOwned {
                recipient_type,
                data: own_bytes(data)?,
            },
            ReviewV2OutputOwnership::ProvenChange { child_index } => {
                ReviewV2OutputOwnership::ProvenChange { child_index }
            }
            ReviewV2OutputOwnership::ProvenSelfTransfer {
                child_index,
                witness_program,
            } => ReviewV2OutputOwnership::ProvenSelfTransfer {
                child_index,
                witness_program: own_bytes(witness_program)?,
            },
        };
        owned.push(ReviewV2Output {
            index: output.index,
            amount: output.amount,
            script_pubkey: own_bytes(output.script_pubkey)?,
            ownership,
        });
    }
    Ok(owned)
}

/// Build the complete, fully owned D-09 v2 review from one parsed immutable
/// S0 view and one caller-authenticated descriptor pair.
///
/// This is the only public review-v2 construction path. It performs the M23
/// no-crypto semantic route itself, so callers cannot inject ownership,
/// destination, fee, warning, or RBF facts around that route.
///
/// # Errors
///
/// Returns the stable source, semantic, policy, arithmetic, cap, allocation,
/// hash, or internal-invariant rejection that stopped construction.
pub fn build_review_v2(
    view: &PsbtView<'_>,
    descriptor: &DescriptorPair,
    context: ReviewContext,
) -> Result<ReviewV2, ReviewV2Error> {
    if context.input_source != view.source() {
        return Err(ReviewV2Error::SourceMismatch);
    }
    let analysis = analyze_review_v2_semantics(view, descriptor)?;

    let mut inputs = Vec::new();
    inputs
        .try_reserve_exact(analysis.inputs.len())
        .map_err(|_| ReviewV2Error::AllocationFailed)?;
    for (position, input) in analysis.inputs.iter().enumerate() {
        let index = u32::try_from(position).map_err(|_| ReviewV2Error::FieldLengthOverflow)?;
        let outpoint_txid_wire = input
            .outpoint_txid_wire
            .try_into()
            .map_err(|_| ReviewV2Error::InternalInvariant)?;
        inputs.push(ReviewV2InputFacts {
            index,
            outpoint_txid_wire,
            outpoint_vout: input.outpoint_vout,
            prevout_amount: input.prevout_amount,
            prevout_script_pubkey: input.prevout_script_pubkey,
            sequence: input.sequence,
            effective_sighash: input.effective_sighash,
            branch: input.branch,
            child_index: input.index,
        });
    }

    let mut outputs = Vec::new();
    outputs
        .try_reserve_exact(analysis.outputs.len())
        .map_err(|_| ReviewV2Error::AllocationFailed)?;
    for (position, output) in analysis.outputs.iter().enumerate() {
        let index = u32::try_from(position).map_err(|_| ReviewV2Error::FieldLengthOverflow)?;
        let ownership = match output.ownership {
            ReviewV2SemanticOutputOwnership::NotOwned(recipient) => {
                ReviewV2OutputOwnership::NotOwned {
                    recipient_type: recipient.recipient_type,
                    data: recipient.data,
                }
            }
            ReviewV2SemanticOutputOwnership::ProvenChange(child_index) => {
                ReviewV2OutputOwnership::ProvenChange { child_index }
            }
            ReviewV2SemanticOutputOwnership::ProvenSelfTransfer { index, recipient } => {
                ReviewV2OutputOwnership::ProvenSelfTransfer {
                    child_index: index,
                    witness_program: recipient.data,
                }
            }
        };
        outputs.push(ReviewV2OutputFacts {
            index,
            amount: output.amount,
            script_pubkey: output.script_pubkey,
            ownership,
        });
    }

    let s0_sha256 = sha256(&[view.buffer()]).map_err(|_| ReviewV2Error::HashFailure)?;
    let facts = ReviewV2Facts {
        context,
        s0_sha256,
        wallet_id: descriptor.wallet_id(),
        origin_fingerprints: descriptor.origin_fingerprints(),
        unsigned_tx: view.unsigned_tx_bytes(),
        version: analysis.version,
        locktime: analysis.locktime,
        inputs: &inputs,
        outputs: &outputs,
        total_input_amount: analysis.total_input_amount,
        total_output_amount: analysis.total_output_amount,
        fee: analysis.fee,
        fee_policy: analysis.fee_policy,
    };
    build_review_v2_from_facts(facts)
}

/// Build a complete, fully owned D-09 v2 review from proven borrowed facts.
///
/// A later semantic entrypoint can perform hostile-input analysis and
/// descriptor reconstruction, then convert its successful result into
/// [`ReviewV2Facts`] without coupling this binder to parser internals.
///
/// # Errors
///
/// Returns an explicit shape, fee-policy, arithmetic, cap, allocation,
/// or internal-invariant error.
pub(crate) fn build_review_v2_from_facts(
    facts: ReviewV2Facts<'_>,
) -> Result<ReviewV2, ReviewV2Error> {
    validate_facts(&facts)?;
    let recomputed_fee_policy = apply_fee_policy(
        facts.unsigned_tx.len(),
        facts.inputs.len(),
        facts.fee,
        facts.total_input_amount,
    )?;
    if recomputed_fee_policy != facts.fee_policy {
        return Err(ReviewV2Error::InternalInvariant);
    }
    let fee_policy = facts.fee_policy;
    if fee_policy.estimated_vsize() > MAX_ESTIMATED_VSIZE {
        return Err(ReviewV2Error::InternalInvariant);
    }
    let canonical = canonical_bytes(&facts, fee_policy)?;
    let unsigned_tx = own_bytes(facts.unsigned_tx)?;
    let inputs = own_inputs(facts.inputs)?;
    let outputs = own_outputs(facts.outputs)?;
    Ok(ReviewV2 {
        context: facts.context,
        s0_sha256: facts.s0_sha256,
        wallet_id: facts.wallet_id,
        origin_fingerprints: facts.origin_fingerprints,
        unsigned_tx,
        version: facts.version,
        locktime: facts.locktime,
        inputs,
        outputs,
        total_input_amount: facts.total_input_amount,
        total_output_amount: facts.total_output_amount,
        fee: facts.fee,
        fee_policy,
        canonical,
    })
}

#[cfg(test)]
#[allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects
)]
mod tests {
    use super::{
        apply_fee_policy, build_review_v2_from_facts, classify_fee_warnings, estimate_vsize,
        DirectRbf, FeeWarning, ReviewV2, ReviewV2Error, ReviewV2Facts, ReviewV2InputFacts,
        ReviewV2OutputFacts, ReviewV2OutputOwnership, MAX_CANONICAL_REVIEW_V2_BYTES,
        MAX_ESTIMATED_VSIZE, MAX_REVIEW_V2_HASH_TRANSCRIPT_BYTES, REVIEW_V2_HASH_DOMAIN,
    };
    use crate::review::{ReviewContext, ReviewNetwork};
    use crate::semantic::RecipientType;
    use crate::sha256::sha256;
    use crate::InputSource;

    fn warning_vec(
        fee_rate: u64,
        fee: u64,
        total_input: u64,
    ) -> Result<Vec<FeeWarning>, ReviewV2Error> {
        Ok(classify_fee_warnings(fee_rate, fee, total_input)?
            .iter()
            .collect())
    }

    #[test]
    fn fixed_witness_vsize_arithmetic_and_cap_are_exact() {
        assert_eq!(estimate_vsize(5_535, 100).unwrap(), MAX_ESTIMATED_VSIZE);
        assert_eq!(estimate_vsize(1, 0).unwrap(), 2);
        assert_eq!(estimate_vsize(2, 0).unwrap(), 3);
        assert!(matches!(
            estimate_vsize(usize::MAX, 1),
            Err(ReviewV2Error::FeePolicyArithmeticOverflow)
        ));
        assert_eq!(
            MAX_REVIEW_V2_HASH_TRANSCRIPT_BYTES,
            MAX_CANONICAL_REVIEW_V2_BYTES + REVIEW_V2_HASH_DOMAIN.len() + 1
        );
    }

    #[test]
    fn fee_warning_edges_are_in_fixed_order_and_do_not_suppress() {
        assert_eq!(warning_vec(999, 1, 21).unwrap(), [FeeWarning::RateLow]);
        assert_eq!(warning_vec(1_000, 1, 21).unwrap(), []);
        assert_eq!(warning_vec(199_999, 1, 21).unwrap(), []);
        assert_eq!(warning_vec(200_000, 1, 21).unwrap(), [FeeWarning::RateHigh]);
        assert_eq!(
            warning_vec(200_000, 1_000_000, 20_000_000).unwrap(),
            [
                FeeWarning::RateHigh,
                FeeWarning::ShareHigh,
                FeeWarning::AbsoluteHigh,
            ]
        );
        assert_eq!(FeeWarning::RateLow.tag(), 1);
        assert_eq!(FeeWarning::RateHigh.tag(), 2);
        assert_eq!(FeeWarning::ShareHigh.tag(), 3);
        assert_eq!(FeeWarning::AbsoluteHigh.tag(), 4);

        assert_eq!(warning_vec(1_000, 99_999, 2_000_000).unwrap(), []);
        assert_eq!(
            warning_vec(1_000, 100_000, 2_000_000).unwrap(),
            [FeeWarning::ShareHigh]
        );
        assert_eq!(warning_vec(1_000, 999_999, 20_000_001).unwrap(), []);
        assert_eq!(
            warning_vec(1_000, 1_000_000, 20_000_001).unwrap(),
            [FeeWarning::AbsoluteHigh]
        );
    }

    #[test]
    fn emergency_ceiling_is_strict_and_arithmetic_precedes_it() {
        assert!(apply_fee_policy(1, 0, 4_999_999, 5_000_000).is_ok());
        let at_ceiling = apply_fee_policy(1, 0, 5_000_000, 5_000_000).unwrap();
        assert_eq!(at_ceiling.warning_count(), 3);
        assert!(matches!(
            apply_fee_policy(1, 0, 5_000_001, 5_000_001),
            Err(ReviewV2Error::EmergencyFeeCeilingExceeded)
        ));
        assert!(matches!(
            apply_fee_policy(1, 0, u64::MAX, u64::MAX),
            Err(ReviewV2Error::FeePolicyArithmeticOverflow)
        ));
        assert!(matches!(
            classify_fee_warnings(0, u64::MAX, 0),
            Err(ReviewV2Error::FeePolicyArithmeticOverflow)
        ));
    }

    fn build_maximum_review() -> ReviewV2 {
        let unsigned_tx = vec![0u8; 5_535];
        let prevout_script = [
            0x00, 0x20, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0,
        ];
        let mut inputs = Vec::new();
        for position in 0..100u32 {
            inputs.push(ReviewV2InputFacts {
                index: position,
                outpoint_txid_wire: [position as u8; 32],
                outpoint_vout: position,
                prevout_amount: 50_000,
                prevout_script_pubkey: &prevout_script,
                sequence: if position == 0 {
                    0xffff_fffd
                } else {
                    0xffff_ffff
                },
                effective_sighash: 1,
                branch: 0,
                child_index: position,
            });
        }

        let op_return_data = [0x5a; 80];
        let mut op_return_script = vec![0x6a, 0x4c, 80];
        op_return_script.extend_from_slice(&op_return_data);
        let witness_program = [0x6b; 32];
        let mut p2wsh_script = vec![0x00, 0x20];
        p2wsh_script.extend_from_slice(&witness_program);
        let mut outputs = Vec::new();
        outputs.push(ReviewV2OutputFacts {
            index: 0,
            amount: 0,
            script_pubkey: &op_return_script,
            ownership: ReviewV2OutputOwnership::NotOwned {
                recipient_type: RecipientType::OpReturn,
                data: &op_return_data,
            },
        });
        for position in 1..32u32 {
            outputs.push(ReviewV2OutputFacts {
                index: position,
                amount: 0,
                script_pubkey: &p2wsh_script,
                ownership: ReviewV2OutputOwnership::ProvenSelfTransfer {
                    child_index: position,
                    witness_program: &witness_program,
                },
            });
        }
        let fee_policy =
            apply_fee_policy(unsigned_tx.len(), inputs.len(), 5_000_000, 5_000_000).unwrap();

        build_review_v2_from_facts(ReviewV2Facts {
            context: ReviewContext {
                network: ReviewNetwork::BitcoinMainnet,
                input_source: InputSource::MicroSd,
            },
            s0_sha256: [1; 32],
            wallet_id: [2; 32],
            origin_fingerprints: [[3; 4], [4; 4], [5; 4]],
            unsigned_tx: &unsigned_tx,
            version: 2,
            locktime: 500_000,
            inputs: &inputs,
            outputs: &outputs,
            total_input_amount: 5_000_000,
            total_output_amount: 0,
            fee: 5_000_000,
            fee_policy,
        })
        .unwrap()
    }

    #[test]
    fn maximum_canonical_arithmetic_is_exact_and_review_is_owned() {
        let review = build_maximum_review();
        assert_eq!(
            review.canonical_bytes().len(),
            MAX_CANONICAL_REVIEW_V2_BYTES
        );
        assert_eq!(review.fee_policy().estimated_vsize(), MAX_ESTIMATED_VSIZE);
        assert_eq!(review.fee_policy().warning_count(), 3);
        assert_eq!(review.inputs().len(), 100);
        assert_eq!(review.outputs().len(), 32);
        assert_eq!(review.direct_rbf(), DirectRbf::Signaled);
        assert_eq!(
            review.inputs().first().unwrap().direct_rbf(),
            DirectRbf::Signaled
        );
        assert_eq!(
            review.inputs().last().unwrap().direct_rbf(),
            DirectRbf::NotSignaled
        );
        assert_eq!(review.review_hash().unwrap(), review.review_hash().unwrap());
    }

    #[test]
    fn hash_uses_exact_v2_policy_domain_and_separator() {
        let review = build_maximum_review();
        let expected = sha256(&[REVIEW_V2_HASH_DOMAIN, &[0], review.canonical_bytes()]).unwrap();
        assert_eq!(review.review_hash().unwrap(), expected);
        let missing_separator = sha256(&[REVIEW_V2_HASH_DOMAIN, review.canonical_bytes()]).unwrap();
        assert_ne!(review.review_hash().unwrap(), missing_separator);
    }
}
