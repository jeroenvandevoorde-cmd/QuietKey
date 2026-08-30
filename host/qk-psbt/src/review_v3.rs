//! Owned, session-free D-09 review schema v3 and QK-FEE-POLICY-V2.

use crate::limits;
use crate::parse::{InputSource, PsbtView};
use crate::review::{ReviewContext, ReviewNetwork};
use crate::review_v2::{DirectRbf, FeeWarning};
use crate::semantic::{
    analyze_review_v3_semantics, RecipientType, ReviewV3SemanticOutputOwnership, SemanticError,
};
use crate::sha256::sha256;
use crate::wipe;
use core::fmt;
use qk_descriptor::DescriptorPairV2;

/// D-09 review schema-v3 byte.
pub const REVIEW_V3_SCHEMA_VERSION: u8 = 3;
/// Exact policy identifier repeated inside canonical schema-v3 bytes.
pub const FEE_POLICY_V2_IDENTIFIER: &[u8] = b"QK-FEE-POLICY-V2";
/// Exact D-09 review-v3 hash domain, excluding its raw zero separator.
pub const REVIEW_V3_HASH_DOMAIN: &[u8] = b"QuietKey/D-09/review/v3";
/// Exact HOST-candidate maximum canonical D-09 review-v3 byte length.
pub const MAX_CANONICAL_REVIEW_V3_BYTES: usize = limits::MAX_CANONICAL_REVIEW_V3_BYTES;
/// Exact HOST-candidate maximum review-v3 hash transcript length.
pub const MAX_REVIEW_V3_HASH_TRANSCRIPT_BYTES: usize = limits::MAX_REVIEW_V3_HASH_TRANSCRIPT_BYTES;
/// Exact HOST-candidate maximum estimated virtual size under QK-FEE-POLICY-V2.
pub const MAX_ESTIMATED_VSIZE_V2: u32 = limits::MAX_ESTIMATED_VSIZE_V2;
/// Maximum number of simultaneously applicable QK-FEE-POLICY-V2 warnings.
pub const MAX_FEE_WARNINGS_V2: usize = 3;

const SIGHASH_ALL: u32 = 1;
const MAX_UNSIGNED_TX_BYTES: usize = 5_535;
const ESTIMATED_WITNESS_WEIGHT_PER_INPUT: usize = 220;
const EMERGENCY_FEE_CEILING_SATS: u64 = 5_000_000;
const LOW_FEE_RATE_MSAT_PER_VBYTE: u64 = 1_000;
const HIGH_FEE_RATE_MSAT_PER_VBYTE: u64 = 200_000;
const HIGH_ABSOLUTE_FEE_SATS: u64 = 1_000_000;

const _: [(); 16] = [(); FEE_POLICY_V2_IDENTIFIER.len()];
const _: [(); 23] = [(); REVIEW_V3_HASH_DOMAIN.len()];
const _: [(); 220] = [(); 1 + 1 + (2 * (1 + 72)) + (1 + 71)];
const _: [(); 11_036] =
    [(); ((4usize * 5_535) + 2 + (100 * ESTIMATED_WITNESS_WEIGHT_PER_INPUT)).div_ceil(4)];
const _: [(); MAX_CANONICAL_REVIEW_V3_BYTES] = [(); 158 + 5_535 + (100 * 102) + 185 + (31 * 92)];
const _: [(); MAX_REVIEW_V3_HASH_TRANSCRIPT_BYTES] = [(); MAX_CANONICAL_REVIEW_V3_BYTES + 23 + 1];

/// D-09 review-v3 hash.
pub type ReviewV3Hash = [u8; 32];

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct FeeWarningSetV2 {
    fee_rate_low: bool,
    fee_rate_high: bool,
    fee_share_high: bool,
    fee_absolute_high: bool,
}

impl FeeWarningSetV2 {
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

/// Derived QK-FEE-POLICY-V2 facts.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FeePolicyV2Facts {
    estimated_vsize: u32,
    fee_rate_msat_per_vbyte: u64,
    warnings: FeeWarningSetV2,
}

impl FeePolicyV2Facts {
    /// Estimated virtual size under the fixed 220-WU-per-input v2 model.
    #[must_use]
    pub const fn estimated_vsize(&self) -> u32 {
        self.estimated_vsize
    }

    /// Truncated internal fee rate in milli-satoshi per virtual byte.
    #[must_use]
    pub const fn fee_rate_msat_per_vbyte(&self) -> u64 {
        self.fee_rate_msat_per_vbyte
    }

    /// Number of independently applicable warnings.
    #[must_use]
    pub fn warning_count(&self) -> usize {
        self.warnings.count()
    }

    /// Applicable warnings in their fixed canonical order.
    pub fn warnings(&self) -> impl Iterator<Item = FeeWarning> {
        self.warnings.iter()
    }
}

/// Borrowed facts for one descriptor-proven schema-v3 input.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct ReviewV3InputFacts<'a> {
    pub index: u32,
    pub outpoint_txid_wire: [u8; 32],
    pub outpoint_vout: u32,
    pub prevout_amount: u64,
    pub prevout_script_pubkey: &'a [u8],
    pub sequence: u32,
    pub effective_sighash: u32,
    pub branch: u32,
    pub child_index: u32,
}

/// Schema-v3 output ownership, parameterized over borrowed or owned exact data.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReviewV3OutputOwnership<B> {
    /// Not descriptor-owned, with an exact accepted recipient classification.
    NotOwned {
        /// Accepted destination template.
        recipient_type: RecipientType,
        /// Exact program, hash, or OP_RETURN payload.
        data: B,
    },
    /// Descriptor-proven branch-one change child.
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

/// Borrowed facts for one schema-v3 output.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct ReviewV3OutputFacts<'a> {
    pub index: u32,
    pub amount: u64,
    pub script_pubkey: &'a [u8],
    pub ownership: ReviewV3OutputOwnership<&'a [u8]>,
}

/// Borrowed, already-proven inputs to D-09 review-v3 construction.
#[derive(Debug, Clone, Copy)]
pub(crate) struct ReviewV3Facts<'a> {
    pub context: ReviewContext,
    pub s0_sha256: [u8; 32],
    pub wallet_id: [u8; 32],
    pub origin_fingerprints: [[u8; 4]; 2],
    pub unsigned_tx: &'a [u8],
    pub version: u32,
    pub locktime: u32,
    pub inputs: &'a [ReviewV3InputFacts<'a>],
    pub outputs: &'a [ReviewV3OutputFacts<'a>],
    pub total_input_amount: u64,
    pub total_output_amount: u64,
    pub fee: u64,
    pub fee_policy: FeePolicyV2Facts,
}

/// Fully owned facts for one schema-v3 input.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReviewV3Input {
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

impl ReviewV3Input {
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

    /// Selected previous-output index.
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

    /// Effective sighash, always SIGHASH_ALL after construction.
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
        if self.sequence < 0xffff_fffe {
            DirectRbf::Signaled
        } else {
            DirectRbf::NotSignaled
        }
    }
}

impl Drop for ReviewV3Input {
    fn drop(&mut self) {
        wipe::bytes(&mut self.outpoint_txid_wire);
        wipe::byte_vec(&mut self.prevout_script_pubkey);
    }
}

/// Fully owned facts for one schema-v3 output.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReviewV3Output {
    index: u32,
    amount: u64,
    script_pubkey: Vec<u8>,
    ownership: ReviewV3OutputOwnership<Vec<u8>>,
}

impl ReviewV3Output {
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
    pub const fn ownership(&self) -> &ReviewV3OutputOwnership<Vec<u8>> {
        &self.ownership
    }
}

impl Drop for ReviewV3Output {
    fn drop(&mut self) {
        wipe::byte_vec(&mut self.script_pubkey);
        match &mut self.ownership {
            ReviewV3OutputOwnership::NotOwned { data, .. } => wipe::byte_vec(data),
            ReviewV3OutputOwnership::ProvenChange { .. } => {}
            ReviewV3OutputOwnership::ProvenSelfTransfer {
                witness_program, ..
            } => wipe::byte_vec(witness_program),
        }
    }
}

/// Complete, fully owned, session-free D-09 review schema-v3 object.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReviewV3 {
    context: ReviewContext,
    s0_sha256: [u8; 32],
    wallet_id: [u8; 32],
    origin_fingerprints: [[u8; 4]; 2],
    unsigned_tx: Vec<u8>,
    version: u32,
    locktime: u32,
    inputs: Vec<ReviewV3Input>,
    outputs: Vec<ReviewV3Output>,
    total_input_amount: u64,
    total_output_amount: u64,
    fee: u64,
    fee_policy: FeePolicyV2Facts,
    canonical: Vec<u8>,
}

impl Drop for ReviewV3 {
    fn drop(&mut self) {
        wipe::bytes(&mut self.s0_sha256);
        wipe::bytes(&mut self.wallet_id);
        for fingerprint in &mut self.origin_fingerprints {
            wipe::bytes(fingerprint);
        }
        wipe::byte_vec(&mut self.unsigned_tx);
        wipe::byte_vec(&mut self.canonical);

        while let Some(input) = self.inputs.pop() {
            drop(input);
        }
        wipe::empty_vec_allocation(&mut self.inputs);

        while let Some(output) = self.outputs.pop() {
            drop(output);
        }
        wipe::empty_vec_allocation(&mut self.outputs);
    }
}

impl ReviewV3 {
    /// Canonical schema version.
    #[must_use]
    pub const fn schema_version(&self) -> u8 {
        REVIEW_V3_SCHEMA_VERSION
    }

    /// Construction context.
    #[must_use]
    pub const fn context(&self) -> ReviewContext {
        self.context
    }

    /// SHA-256 of the exact immutable S0 bytes.
    #[must_use]
    pub const fn s0_sha256(&self) -> [u8; 32] {
        self.s0_sha256
    }

    /// Authenticated descriptor wallet ID.
    #[must_use]
    pub const fn wallet_id(&self) -> [u8; 32] {
        self.wallet_id
    }

    /// Authenticated descriptor A/B fingerprints in role order.
    #[must_use]
    pub const fn origin_fingerprints(&self) -> [[u8; 4]; 2] {
        self.origin_fingerprints
    }

    /// Policy identifier repeated inside the canonical object.
    #[must_use]
    pub const fn fee_policy_identifier(&self) -> &'static [u8] {
        FEE_POLICY_V2_IDENTIFIER
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

    /// Fully owned input facts in unsigned-transaction order.
    #[must_use]
    pub fn inputs(&self) -> &[ReviewV3Input] {
        &self.inputs
    }

    /// Canonically bound input count.
    #[must_use]
    pub fn input_count(&self) -> usize {
        self.inputs.len()
    }

    /// Fully owned output facts in unsigned-transaction order.
    #[must_use]
    pub fn outputs(&self) -> &[ReviewV3Output] {
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

    /// Derived QK-FEE-POLICY-V2 facts.
    #[must_use]
    pub const fn fee_policy(&self) -> FeePolicyV2Facts {
        self.fee_policy
    }

    /// Estimated virtual size under the fixed 220-WU-per-input model.
    #[must_use]
    pub const fn estimated_vsize(&self) -> u32 {
        self.fee_policy.estimated_vsize()
    }

    /// Truncated internal fee rate in milli-satoshi per virtual byte.
    #[must_use]
    pub const fn fee_rate_msat_per_vbyte(&self) -> u64 {
        self.fee_policy.fee_rate_msat_per_vbyte()
    }

    /// Applicable warnings in canonical policy order.
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

    /// Exact canonical D-09 review-v3 bytes.
    #[must_use]
    pub fn canonical_bytes(&self) -> &[u8] {
        &self.canonical
    }

    /// Require byte identity with this exact canonical review-v3 object.
    ///
    /// A missing or non-v3 first byte rejects as an unsupported schema
    /// before the remaining bytes are compared. No translation exists.
    ///
    /// # Errors
    ///
    /// Returns the stable schema or canonical-identity rejection.
    pub fn verify_exact_identity(&self, presented: &[u8]) -> Result<(), ReviewV3Error> {
        if presented.first().copied() != Some(REVIEW_V3_SCHEMA_VERSION) {
            return Err(ReviewV3Error::UnsupportedReviewSchemaVersion);
        }
        if presented != self.canonical {
            return Err(ReviewV3Error::CanonicalReviewMismatch);
        }
        Ok(())
    }

    /// SHA-256 of the exact domain, separator, and canonical bytes.
    ///
    /// # Errors
    ///
    /// Returns [`ReviewV3Error::HashFailure`] if checked SHA-256 length
    /// accounting fails.
    pub fn review_hash(&self) -> Result<ReviewV3Hash, ReviewV3Error> {
        hash_canonical(&self.canonical)
    }
}

/// Explicit schema-v3 binding or QK-FEE-POLICY-V2 failure.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReviewV3Error {
    /// The requested context source differs from the immutable parsed source.
    SourceMismatch,
    /// Hostile-input semantic analysis rejected under its stable category.
    Semantic(SemanticError),
    /// Checked QK-FEE-POLICY-V2 arithmetic overflowed or produced zero vsize.
    FeePolicyArithmeticOverflow,
    /// Exact fee exceeds 5,000,000 satoshis.
    EmergencyFeeCeilingExceeded,
    /// The semantic seam supplied more than 100 inputs.
    InputCountTooLarge,
    /// The semantic seam supplied more than 32 outputs.
    OutputCountTooLarge,
    /// Exact unsigned transaction exceeds 5,535 bytes.
    UnsignedTransactionTooLong,
    /// Explicit input index differs from its transaction position.
    InputIndexMismatch,
    /// Explicit output index differs from its transaction position.
    OutputIndexMismatch,
    /// Checked canonical length arithmetic overflowed.
    LengthOverflow,
    /// A count or variable field cannot be represented by u32.
    FieldLengthOverflow,
    /// Canonical bytes exceed the exact D-09 review-v3 cap.
    CanonicalTooLong,
    /// A bounded allocation failed.
    AllocationFailed,
    /// SHA-256 length accounting or an internal hash invariant failed.
    HashFailure,
    /// Presented canonical bytes do not begin with schema byte 03.
    UnsupportedReviewSchemaVersion,
    /// Presented schema-v3 bytes differ from the bound canonical object.
    CanonicalReviewMismatch,
    /// Already-proven facts violated the closed seam's shape or totals.
    InternalInvariant,
}

impl fmt::Display for ReviewV3Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::SourceMismatch => {
                f.write_str("review context input source differs from parsed PSBT source")
            }
            Self::Semantic(error) => write!(f, "review-v3 semantic analysis failed: {error}"),
            Self::FeePolicyArithmeticOverflow => {
                f.write_str("QK-FEE-POLICY-V2 arithmetic overflow")
            }
            Self::EmergencyFeeCeilingExceeded => {
                f.write_str("fee exceeds QK-FEE-POLICY-V2 emergency ceiling")
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
            Self::UnsupportedReviewSchemaVersion => {
                f.write_str("unsupported review schema version")
            }
            Self::CanonicalReviewMismatch => f.write_str("canonical review mismatch"),
            Self::InternalInvariant => f.write_str("review fact invariant failed"),
        }
    }
}

impl std::error::Error for ReviewV3Error {}

impl From<SemanticError> for ReviewV3Error {
    fn from(value: SemanticError) -> Self {
        match value.category {
            crate::semantic::SemanticCategory::FeePolicyArithmeticOverflow => {
                Self::FeePolicyArithmeticOverflow
            }
            crate::semantic::SemanticCategory::EmergencyFeeCeilingExceeded => {
                Self::EmergencyFeeCeilingExceeded
            }
            _ => Self::Semantic(value),
        }
    }
}

fn hash_canonical(canonical: &[u8]) -> Result<ReviewV3Hash, ReviewV3Error> {
    sha256(&[REVIEW_V3_HASH_DOMAIN, &[0], canonical]).map_err(|_| ReviewV3Error::HashFailure)
}

/// Estimate vsize from exact unsigned-transaction length and 220 WU per input.
pub(crate) fn estimate_vsize_v2(
    unsigned_tx_len: usize,
    input_count: usize,
) -> Result<u32, ReviewV3Error> {
    let base_weight = unsigned_tx_len
        .checked_mul(4)
        .and_then(|weight| weight.checked_add(2))
        .ok_or(ReviewV3Error::FeePolicyArithmeticOverflow)?;
    let witness_weight = input_count
        .checked_mul(ESTIMATED_WITNESS_WEIGHT_PER_INPUT)
        .ok_or(ReviewV3Error::FeePolicyArithmeticOverflow)?;
    let weight = base_weight
        .checked_add(witness_weight)
        .ok_or(ReviewV3Error::FeePolicyArithmeticOverflow)?;
    let rounded_weight = weight
        .checked_add(3)
        .ok_or(ReviewV3Error::FeePolicyArithmeticOverflow)?;
    let vsize = rounded_weight / 4;
    if vsize == 0 {
        return Err(ReviewV3Error::FeePolicyArithmeticOverflow);
    }
    u32::try_from(vsize).map_err(|_| ReviewV3Error::FeePolicyArithmeticOverflow)
}

fn classify_fee_warnings_v2(
    fee_rate_msat_per_vbyte: u64,
    fee: u64,
    total_input_amount: u64,
) -> Result<FeeWarningSetV2, ReviewV3Error> {
    let scaled_fee = fee
        .checked_mul(20)
        .ok_or(ReviewV3Error::FeePolicyArithmeticOverflow)?;
    Ok(FeeWarningSetV2 {
        fee_rate_low: fee_rate_msat_per_vbyte < LOW_FEE_RATE_MSAT_PER_VBYTE,
        fee_rate_high: fee_rate_msat_per_vbyte >= HIGH_FEE_RATE_MSAT_PER_VBYTE,
        fee_share_high: scaled_fee >= total_input_amount,
        fee_absolute_high: fee >= HIGH_ABSOLUTE_FEE_SATS,
    })
}

/// Apply QK-FEE-POLICY-V2 to already-checked fee and input totals.
pub(crate) fn apply_fee_policy_v2(
    unsigned_tx_len: usize,
    input_count: usize,
    fee: u64,
    total_input_amount: u64,
) -> Result<FeePolicyV2Facts, ReviewV3Error> {
    let estimated_vsize = estimate_vsize_v2(unsigned_tx_len, input_count)?;
    let scaled_fee = fee
        .checked_mul(1_000)
        .ok_or(ReviewV3Error::FeePolicyArithmeticOverflow)?;
    let fee_rate_msat_per_vbyte = scaled_fee
        .checked_div(u64::from(estimated_vsize))
        .ok_or(ReviewV3Error::FeePolicyArithmeticOverflow)?;
    if fee > EMERGENCY_FEE_CEILING_SATS {
        return Err(ReviewV3Error::EmergencyFeeCeilingExceeded);
    }
    let warnings = classify_fee_warnings_v2(fee_rate_msat_per_vbyte, fee, total_input_amount)?;
    if warnings.count() > MAX_FEE_WARNINGS_V2 {
        return Err(ReviewV3Error::InternalInvariant);
    }
    Ok(FeePolicyV2Facts {
        estimated_vsize,
        fee_rate_msat_per_vbyte,
        warnings,
    })
}

fn checked_add(total: &mut usize, value: usize) -> Result<(), ReviewV3Error> {
    *total = total
        .checked_add(value)
        .ok_or(ReviewV3Error::LengthOverflow)?;
    Ok(())
}

fn variable_len(total: &mut usize, bytes: &[u8]) -> Result<(), ReviewV3Error> {
    u32::try_from(bytes.len()).map_err(|_| ReviewV3Error::FieldLengthOverflow)?;
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

fn put_variable(bytes: &mut Vec<u8>, value: &[u8]) -> Result<(), ReviewV3Error> {
    let length = u32::try_from(value.len()).map_err(|_| ReviewV3Error::FieldLengthOverflow)?;
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

fn validate_facts(facts: &ReviewV3Facts<'_>) -> Result<(), ReviewV3Error> {
    if facts.inputs.len() > limits::MAX_INPUTS {
        return Err(ReviewV3Error::InputCountTooLarge);
    }
    if facts.outputs.len() > limits::MAX_OUTPUTS {
        return Err(ReviewV3Error::OutputCountTooLarge);
    }
    if facts.unsigned_tx.len() > MAX_UNSIGNED_TX_BYTES {
        return Err(ReviewV3Error::UnsignedTransactionTooLong);
    }
    u32::try_from(facts.inputs.len()).map_err(|_| ReviewV3Error::FieldLengthOverflow)?;
    u32::try_from(facts.outputs.len()).map_err(|_| ReviewV3Error::FieldLengthOverflow)?;
    u32::try_from(facts.unsigned_tx.len()).map_err(|_| ReviewV3Error::FieldLengthOverflow)?;

    let [fingerprint_a, fingerprint_b] = facts.origin_fingerprints;
    if fingerprint_a == fingerprint_b {
        return Err(ReviewV3Error::InternalInvariant);
    }

    let mut input_total = 0u64;
    for (position, input) in facts.inputs.iter().enumerate() {
        let expected = u32::try_from(position).map_err(|_| ReviewV3Error::FieldLengthOverflow)?;
        if input.index != expected {
            return Err(ReviewV3Error::InputIndexMismatch);
        }
        if input.effective_sighash != SIGHASH_ALL
            || input.branch > 1
            || input.child_index > limits::MAX_CHILD_INDEX
            || !p2wsh_shape(input.prevout_script_pubkey)
        {
            return Err(ReviewV3Error::InternalInvariant);
        }
        input_total = input_total
            .checked_add(input.prevout_amount)
            .ok_or(ReviewV3Error::InternalInvariant)?;
    }
    if input_total != facts.total_input_amount {
        return Err(ReviewV3Error::InternalInvariant);
    }

    let mut output_total = 0u64;
    let mut saw_op_return = false;
    for (position, output) in facts.outputs.iter().enumerate() {
        let expected = u32::try_from(position).map_err(|_| ReviewV3Error::FieldLengthOverflow)?;
        if output.index != expected {
            return Err(ReviewV3Error::OutputIndexMismatch);
        }
        output_total = output_total
            .checked_add(output.amount)
            .ok_or(ReviewV3Error::InternalInvariant)?;
        match output.ownership {
            ReviewV3OutputOwnership::NotOwned {
                recipient_type,
                data,
            } => {
                if recipient_type == RecipientType::OpReturn {
                    if saw_op_return {
                        return Err(ReviewV3Error::InternalInvariant);
                    }
                    saw_op_return = true;
                }
                if !recipient_shape(recipient_type, output.script_pubkey, data, output.amount) {
                    return Err(ReviewV3Error::InternalInvariant);
                }
            }
            ReviewV3OutputOwnership::ProvenChange { child_index } => {
                if child_index > limits::MAX_CHILD_INDEX || !p2wsh_shape(output.script_pubkey) {
                    return Err(ReviewV3Error::InternalInvariant);
                }
            }
            ReviewV3OutputOwnership::ProvenSelfTransfer {
                child_index,
                witness_program,
            } => {
                if child_index > limits::MAX_CHILD_INDEX
                    || !matches!(output.script_pubkey, [0x00, 0x20, program @ ..] if program.len() == 32 && program == witness_program)
                {
                    return Err(ReviewV3Error::InternalInvariant);
                }
            }
        }
    }
    if output_total != facts.total_output_amount {
        return Err(ReviewV3Error::InternalInvariant);
    }
    let recomputed_fee = facts
        .total_input_amount
        .checked_sub(facts.total_output_amount)
        .ok_or(ReviewV3Error::InternalInvariant)?;
    if recomputed_fee != facts.fee {
        return Err(ReviewV3Error::InternalInvariant);
    }
    Ok(())
}

fn canonical_length(
    facts: &ReviewV3Facts<'_>,
    fee_policy: FeePolicyV2Facts,
) -> Result<usize, ReviewV3Error> {
    let mut length = 155usize;
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
            ReviewV3OutputOwnership::NotOwned { data, .. } => {
                checked_add(&mut length, 1)?;
                variable_len(&mut length, data)?;
            }
            ReviewV3OutputOwnership::ProvenChange { .. } => checked_add(&mut length, 4)?,
            ReviewV3OutputOwnership::ProvenSelfTransfer {
                witness_program, ..
            } => {
                checked_add(&mut length, 5)?;
                variable_len(&mut length, witness_program)?;
            }
        }
    }
    if length > MAX_CANONICAL_REVIEW_V3_BYTES {
        return Err(ReviewV3Error::CanonicalTooLong);
    }
    Ok(length)
}

fn canonical_bytes(
    facts: &ReviewV3Facts<'_>,
    fee_policy: FeePolicyV2Facts,
) -> Result<wipe::WipingByteVec, ReviewV3Error> {
    let length = canonical_length(facts, fee_policy)?;
    let input_count =
        u32::try_from(facts.inputs.len()).map_err(|_| ReviewV3Error::FieldLengthOverflow)?;
    let output_count =
        u32::try_from(facts.outputs.len()).map_err(|_| ReviewV3Error::FieldLengthOverflow)?;
    let warning_count = u32::try_from(fee_policy.warning_count())
        .map_err(|_| ReviewV3Error::FieldLengthOverflow)?;

    let mut bytes = wipe::WipingByteVec::new();
    bytes
        .try_reserve_exact(length)
        .map_err(|_| ReviewV3Error::AllocationFailed)?;
    bytes.push(REVIEW_V3_SCHEMA_VERSION);
    bytes.push(network_code(facts.context.network));
    bytes.push(source_code(facts.context.input_source));
    bytes.extend_from_slice(&facts.s0_sha256);
    bytes.extend_from_slice(&facts.wallet_id);
    for fingerprint in facts.origin_fingerprints {
        bytes.extend_from_slice(&fingerprint);
    }
    put_variable(&mut bytes, FEE_POLICY_V2_IDENTIFIER)?;
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
            ReviewV3OutputOwnership::NotOwned {
                recipient_type,
                data,
            } => {
                bytes.push(1);
                bytes.push(recipient_code(recipient_type));
                put_variable(&mut bytes, data)?;
            }
            ReviewV3OutputOwnership::ProvenChange { child_index } => {
                bytes.push(2);
                put_u32(&mut bytes, child_index);
            }
            ReviewV3OutputOwnership::ProvenSelfTransfer {
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
        return Err(ReviewV3Error::InternalInvariant);
    }
    Ok(bytes)
}

fn own_bytes(bytes: &[u8]) -> Result<wipe::WipingByteVec, ReviewV3Error> {
    let mut owned = wipe::WipingByteVec::new();
    owned
        .try_reserve_exact(bytes.len())
        .map_err(|_| ReviewV3Error::AllocationFailed)?;
    owned.extend_from_slice(bytes);
    Ok(owned)
}

fn own_inputs(
    inputs: &[ReviewV3InputFacts<'_>],
) -> Result<wipe::WipingValueVec<ReviewV3Input>, ReviewV3Error> {
    let mut owned = wipe::WipingValueVec::new();
    owned
        .try_reserve_exact(inputs.len())
        .map_err(|_| ReviewV3Error::AllocationFailed)?;
    for input in inputs {
        let prevout_script_pubkey = own_bytes(input.prevout_script_pubkey)?;
        owned.push(ReviewV3Input {
            index: input.index,
            outpoint_txid_wire: input.outpoint_txid_wire,
            outpoint_vout: input.outpoint_vout,
            prevout_amount: input.prevout_amount,
            prevout_script_pubkey: prevout_script_pubkey.into_vec(),
            sequence: input.sequence,
            effective_sighash: input.effective_sighash,
            branch: input.branch,
            child_index: input.child_index,
        });
    }
    Ok(owned)
}

fn own_outputs(
    outputs: &[ReviewV3OutputFacts<'_>],
) -> Result<wipe::WipingValueVec<ReviewV3Output>, ReviewV3Error> {
    let mut owned = wipe::WipingValueVec::new();
    owned
        .try_reserve_exact(outputs.len())
        .map_err(|_| ReviewV3Error::AllocationFailed)?;
    for output in outputs {
        let script_pubkey = own_bytes(output.script_pubkey)?;
        let owned_output = match output.ownership {
            ReviewV3OutputOwnership::NotOwned {
                recipient_type,
                data,
            } => {
                let data = own_bytes(data)?;
                ReviewV3Output {
                    index: output.index,
                    amount: output.amount,
                    script_pubkey: script_pubkey.into_vec(),
                    ownership: ReviewV3OutputOwnership::NotOwned {
                        recipient_type,
                        data: data.into_vec(),
                    },
                }
            },
            ReviewV3OutputOwnership::ProvenChange { child_index } => ReviewV3Output {
                index: output.index,
                amount: output.amount,
                script_pubkey: script_pubkey.into_vec(),
                ownership: ReviewV3OutputOwnership::ProvenChange { child_index },
            },
            ReviewV3OutputOwnership::ProvenSelfTransfer {
                child_index,
                witness_program,
            } => {
                let witness_program = own_bytes(witness_program)?;
                ReviewV3Output {
                    index: output.index,
                    amount: output.amount,
                    script_pubkey: script_pubkey.into_vec(),
                    ownership: ReviewV3OutputOwnership::ProvenSelfTransfer {
                        child_index,
                        witness_program: witness_program.into_vec(),
                    },
                }
            }
        };
        owned.push(owned_output);
    }
    Ok(owned)
}

/// Build the complete owned D-09 review-v3 object from one immutable PSBT view.
///
/// This is the sole public schema-v3 construction path. The supplied
/// descriptor pair is assumed authenticated by the caller; this function
/// proves transaction ownership and change but not descriptor authenticity.
///
/// # Errors
///
/// Returns the first stable source, semantic, policy, arithmetic, cap,
/// allocation, hash, or invariant rejection.
pub fn build_review_v3(
    view: &PsbtView<'_>,
    descriptor: &DescriptorPairV2,
    context: ReviewContext,
) -> Result<ReviewV3, ReviewV3Error> {
    if context.input_source != view.source() {
        return Err(ReviewV3Error::SourceMismatch);
    }
    let analysis = analyze_review_v3_semantics(view, descriptor)?;

    let mut inputs = wipe::WipingValueVec::new();
    inputs
        .try_reserve_exact(analysis.inputs.len())
        .map_err(|_| ReviewV3Error::AllocationFailed)?;
    for (position, input) in analysis.inputs.iter().enumerate() {
        let index = u32::try_from(position).map_err(|_| ReviewV3Error::FieldLengthOverflow)?;
        let outpoint_txid_wire = input
            .outpoint_txid_wire
            .try_into()
            .map_err(|_| ReviewV3Error::InternalInvariant)?;
        inputs.push(ReviewV3InputFacts {
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

    let mut outputs = wipe::WipingValueVec::new();
    outputs
        .try_reserve_exact(analysis.outputs.len())
        .map_err(|_| ReviewV3Error::AllocationFailed)?;
    for (position, output) in analysis.outputs.iter().enumerate() {
        let index = u32::try_from(position).map_err(|_| ReviewV3Error::FieldLengthOverflow)?;
        let ownership = match output.ownership {
            ReviewV3SemanticOutputOwnership::NotOwned(recipient) => {
                ReviewV3OutputOwnership::NotOwned {
                    recipient_type: recipient.recipient_type,
                    data: recipient.data,
                }
            }
            ReviewV3SemanticOutputOwnership::ProvenChange(child_index) => {
                ReviewV3OutputOwnership::ProvenChange { child_index }
            }
            ReviewV3SemanticOutputOwnership::ProvenSelfTransfer { index, recipient } => {
                ReviewV3OutputOwnership::ProvenSelfTransfer {
                    child_index: index,
                    witness_program: recipient.data,
                }
            }
        };
        outputs.push(ReviewV3OutputFacts {
            index,
            amount: output.amount,
            script_pubkey: output.script_pubkey,
            ownership,
        });
    }

    let s0_sha256 = sha256(&[view.buffer()]).map_err(|_| ReviewV3Error::HashFailure)?;
    build_review_v3_from_facts(ReviewV3Facts {
        context,
        s0_sha256,
        wallet_id: descriptor.wallet_id(),
        origin_fingerprints: descriptor.origin_fingerprints(),
        unsigned_tx: view.unsigned_tx_bytes(),
        version: analysis.version,
        locktime: analysis.locktime,
        inputs: inputs.as_slice(),
        outputs: outputs.as_slice(),
        total_input_amount: analysis.total_input_amount,
        total_output_amount: analysis.total_output_amount,
        fee: analysis.fee,
        fee_policy: analysis.fee_policy,
    })
}

pub(crate) fn build_review_v3_from_facts(
    facts: ReviewV3Facts<'_>,
) -> Result<ReviewV3, ReviewV3Error> {
    validate_facts(&facts)?;
    let recomputed_fee_policy = apply_fee_policy_v2(
        facts.unsigned_tx.len(),
        facts.inputs.len(),
        facts.fee,
        facts.total_input_amount,
    )?;
    if recomputed_fee_policy != facts.fee_policy {
        return Err(ReviewV3Error::InternalInvariant);
    }
    let fee_policy = facts.fee_policy;
    if fee_policy.estimated_vsize() > MAX_ESTIMATED_VSIZE_V2 {
        return Err(ReviewV3Error::InternalInvariant);
    }
    let canonical = canonical_bytes(&facts, fee_policy)?;
    let unsigned_tx = own_bytes(facts.unsigned_tx)?;
    let inputs = own_inputs(facts.inputs)?;
    let outputs = own_outputs(facts.outputs)?;
    Ok(ReviewV3 {
        context: facts.context,
        s0_sha256: facts.s0_sha256,
        wallet_id: facts.wallet_id,
        origin_fingerprints: facts.origin_fingerprints,
        unsigned_tx: unsigned_tx.into_vec(),
        version: facts.version,
        locktime: facts.locktime,
        inputs: inputs.into_vec(),
        outputs: outputs.into_vec(),
        total_input_amount: facts.total_input_amount,
        total_output_amount: facts.total_output_amount,
        fee: facts.fee,
        fee_policy,
        canonical: canonical.into_vec(),
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
        apply_fee_policy_v2, build_review_v3_from_facts, classify_fee_warnings_v2,
        estimate_vsize_v2, FeeWarning, ReviewV3, ReviewV3Error, ReviewV3Facts, ReviewV3InputFacts,
        ReviewV3OutputFacts, ReviewV3OutputOwnership, MAX_CANONICAL_REVIEW_V3_BYTES,
        MAX_ESTIMATED_VSIZE_V2, MAX_REVIEW_V3_HASH_TRANSCRIPT_BYTES, REVIEW_V3_HASH_DOMAIN,
    };
    use crate::review::{ReviewContext, ReviewNetwork};
    use crate::semantic::RecipientType;
    use crate::sha256::sha256;
    use crate::wipe::{reset_wiped_bytes, wiped_bytes};
    use crate::InputSource;

    fn warning_vec(
        fee_rate: u64,
        fee: u64,
        total_input: u64,
    ) -> Result<Vec<FeeWarning>, ReviewV3Error> {
        Ok(classify_fee_warnings_v2(fee_rate, fee, total_input)?
            .iter()
            .collect())
    }

    #[test]
    fn exact_220_wu_vsize_geometry_and_caps_are_const_tied() {
        assert_eq!(estimate_vsize_v2(182, 1).unwrap(), 238);
        assert_eq!(estimate_vsize_v2(5_535, 100).unwrap(), 11_036);
        assert_eq!(
            estimate_vsize_v2(5_535, 100).unwrap(),
            MAX_ESTIMATED_VSIZE_V2
        );
        assert_eq!(estimate_vsize_v2(1, 0).unwrap(), 2);
        assert_eq!(estimate_vsize_v2(2, 0).unwrap(), 3);
        assert!(matches!(
            estimate_vsize_v2(usize::MAX, 1),
            Err(ReviewV3Error::FeePolicyArithmeticOverflow)
        ));
        assert_eq!(
            MAX_REVIEW_V3_HASH_TRANSCRIPT_BYTES,
            MAX_CANONICAL_REVIEW_V3_BYTES + REVIEW_V3_HASH_DOMAIN.len() + 1
        );
    }

    #[test]
    fn fee_warning_edges_are_in_fixed_order_and_never_suppress() {
        assert_eq!(warning_vec(999, 1, 21).unwrap(), [FeeWarning::RateLow]);
        assert_eq!(warning_vec(1_000, 1, 21).unwrap(), []);
        assert_eq!(warning_vec(199_999, 1, 21).unwrap(), []);
        assert_eq!(warning_vec(200_000, 1, 21).unwrap(), [FeeWarning::RateHigh]);
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
        assert_eq!(
            warning_vec(200_000, 1_000_000, 20_000_000).unwrap(),
            [
                FeeWarning::RateHigh,
                FeeWarning::ShareHigh,
                FeeWarning::AbsoluteHigh,
            ]
        );
        assert!(matches!(
            classify_fee_warnings_v2(0, u64::MAX, 0),
            Err(ReviewV3Error::FeePolicyArithmeticOverflow)
        ));
    }

    #[test]
    fn policy_arithmetic_precedes_strict_emergency_ceiling() {
        assert!(apply_fee_policy_v2(1, 0, 4_999_999, 5_000_000).is_ok());
        let at_ceiling = apply_fee_policy_v2(1, 0, 5_000_000, 5_000_000).unwrap();
        assert_eq!(at_ceiling.warning_count(), 3);
        assert!(matches!(
            apply_fee_policy_v2(1, 0, 5_000_001, 5_000_001),
            Err(ReviewV3Error::EmergencyFeeCeilingExceeded)
        ));
        assert!(matches!(
            apply_fee_policy_v2(1, 0, u64::MAX, u64::MAX),
            Err(ReviewV3Error::FeePolicyArithmeticOverflow)
        ));
    }

    fn build_maximum_review() -> ReviewV3 {
        let unsigned_tx = vec![0u8; 5_535];
        let prevout_script = [
            0x00, 0x20, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0,
        ];
        let mut inputs = Vec::new();
        for position in 0..100u32 {
            inputs.push(ReviewV3InputFacts {
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
        outputs.push(ReviewV3OutputFacts {
            index: 0,
            amount: 0,
            script_pubkey: &op_return_script,
            ownership: ReviewV3OutputOwnership::NotOwned {
                recipient_type: RecipientType::OpReturn,
                data: &op_return_data,
            },
        });
        for position in 1..32u32 {
            outputs.push(ReviewV3OutputFacts {
                index: position,
                amount: 0,
                script_pubkey: &p2wsh_script,
                ownership: ReviewV3OutputOwnership::ProvenSelfTransfer {
                    child_index: position,
                    witness_program: &witness_program,
                },
            });
        }
        let fee_policy =
            apply_fee_policy_v2(unsigned_tx.len(), inputs.len(), 5_000_000, 5_000_000).unwrap();
        build_review_v3_from_facts(ReviewV3Facts {
            context: ReviewContext {
                network: ReviewNetwork::BitcoinMainnet,
                input_source: InputSource::MicroSd,
            },
            s0_sha256: [1; 32],
            wallet_id: [2; 32],
            origin_fingerprints: [[3; 4], [4; 4]],
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
    fn maximum_review_and_hash_domain_are_exact() {
        let review = build_maximum_review();
        assert_eq!(
            review.canonical_bytes().len(),
            MAX_CANONICAL_REVIEW_V3_BYTES
        );
        assert_eq!(review.estimated_vsize(), MAX_ESTIMATED_VSIZE_V2);
        let expected = sha256(&[REVIEW_V3_HASH_DOMAIN, &[0], review.canonical_bytes()]).unwrap();
        assert_eq!(review.review_hash().unwrap(), expected);
        let missing_separator = sha256(&[REVIEW_V3_HASH_DOMAIN, review.canonical_bytes()]).unwrap();
        assert_ne!(review.review_hash().unwrap(), missing_separator);
    }

    #[test]
    fn every_owned_review_byte_buffer_is_wiped_on_drop() {
        let review = build_maximum_review();
        let fixed_bytes = 32 + 32 + (2 * 4);
        let input_bytes = review
            .inputs
            .iter()
            .map(|input| 32 + input.prevout_script_pubkey.capacity())
            .sum::<usize>();
        let output_bytes = review
            .outputs
            .iter()
            .map(|output| {
                let ownership_bytes = match &output.ownership {
                    ReviewV3OutputOwnership::NotOwned { data, .. } => data.capacity(),
                    ReviewV3OutputOwnership::ProvenChange { .. } => 0,
                    ReviewV3OutputOwnership::ProvenSelfTransfer {
                        witness_program, ..
                    } => witness_program.capacity(),
                };
                output.script_pubkey.capacity() + ownership_bytes
            })
            .sum::<usize>();
        let expected = fixed_bytes
            + review.unsigned_tx.capacity()
            + review.canonical.capacity()
            + input_bytes
            + output_bytes
            + review.inputs.capacity() * core::mem::size_of::<super::ReviewV3Input>()
            + review.outputs.capacity() * core::mem::size_of::<super::ReviewV3Output>();
        reset_wiped_bytes();
        drop(review);
        assert_eq!(wiped_bytes(), expected);
    }

    #[test]
    fn schema_rejection_precedes_canonical_mismatch_without_translation() {
        let review = build_maximum_review();
        assert_eq!(
            review.verify_exact_identity(review.canonical_bytes()),
            Ok(())
        );

        for legacy in [1u8, 2] {
            let mut presented = review.canonical_bytes().to_vec();
            presented[0] = legacy;
            presented[1] ^= 1;
            assert_eq!(
                review.verify_exact_identity(&presented),
                Err(ReviewV3Error::UnsupportedReviewSchemaVersion)
            );
        }

        let mut wrong_v3 = review.canonical_bytes().to_vec();
        wrong_v3[1] ^= 1;
        assert_eq!(
            review.verify_exact_identity(&wrong_v3),
            Err(ReviewV3Error::CanonicalReviewMismatch)
        );
        assert_eq!(
            review.verify_exact_identity(&[]),
            Err(ReviewV3Error::UnsupportedReviewSchemaVersion)
        );
    }
}
