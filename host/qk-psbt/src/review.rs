//! Private implementation of the session-free D-09 v1 review binding.

use crate::limits;
use crate::parse::{InputSource, PsbtView};
use crate::semantic::{
    analyze_recipient_script_facts, OutputOwnership, RecipientType, SemanticError,
    VerifiedAggregateStatus, VerifiedInputStatus,
};
use crate::sha256::sha256;
use core::fmt;
use qk_descriptor::DescriptorPair;

const SCHEMA_VERSION: u8 = 1;
const SIGHASH_ALL: u32 = 1;
const HASH_DOMAIN: &[u8] = b"QuietKey/D-09/review/v1";

fn hash_canonical(canonical: &[u8]) -> Result<ReviewHash, ReviewError> {
    sha256(&[HASH_DOMAIN, &[0], canonical]).map_err(|_| ReviewError::HashFailure)
}

/// Review network. D-09 v1 supports mainnet only.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReviewNetwork {
    /// Bitcoin mainnet.
    BitcoinMainnet,
}

/// Session-free provenance needed to construct a review.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ReviewContext {
    /// The transaction network.
    pub network: ReviewNetwork,
    /// Retained S0 intake provenance.
    pub input_source: InputSource,
}

/// D-09 review hash.
pub type ReviewHash = [u8; 32];

/// Stable review facts for one input.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ReviewInput<'a> {
    /// Explicit unsigned-transaction input index.
    pub index: u32,
    /// Wire-order outpoint transaction ID.
    pub outpoint_txid_wire: &'a [u8],
    /// Outpoint output index.
    pub outpoint_vout: u32,
    /// Selected previous-output amount.
    pub prevout_amount: u64,
    /// Selected previous-output scriptPubKey.
    pub prevout_script_pubkey: &'a [u8],
    /// Unsigned-transaction sequence.
    pub sequence: u32,
    /// Effective sighash (always SIGHASH_ALL in v1).
    pub effective_sighash: u32,
    /// Proven descriptor branch.
    pub branch: u32,
    /// Proven descriptor child index.
    pub child_index: u32,
    /// Count of cryptographically verified signatures.
    pub verified_signature_count: u32,
    /// Cryptographic threshold status.
    pub verified_status: VerifiedInputStatus,
}

/// Stable recipient facts for a not-owned output.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ReviewRecipient<'a> {
    /// Exact accepted recipient template.
    pub recipient_type: RecipientType,
    /// Exact raw program, hash, or OP_RETURN payload.
    pub data: &'a [u8],
}

/// Stable output ownership facts.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReviewOutputOwnership<'a> {
    /// Not descriptor-proven owned, with exact recipient facts.
    NotOwned(ReviewRecipient<'a>),
    /// Descriptor-proven change child.
    Change(u32),
    /// Descriptor-proven self-transfer child.
    SelfTransfer(u32),
}

/// Stable review facts for one output.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ReviewOutput<'a> {
    /// Explicit unsigned-transaction output index.
    pub index: u32,
    /// Output amount.
    pub amount: u64,
    /// Exact raw unsigned-output scriptPubKey.
    pub script_pubkey: &'a [u8],
    /// Descriptor ownership or recipient facts.
    pub ownership: ReviewOutputOwnership<'a>,
}

/// A complete, session-free D-09 v1 review.
#[derive(Debug, Clone)]
pub struct Review<'a> {
    context: ReviewContext,
    s0_sha256: [u8; 32],
    wallet_id: [u8; 32],
    origin_fingerprints: [[u8; 4]; 3],
    unsigned_tx: &'a [u8],
    version: u32,
    locktime: u32,
    inputs: Vec<ReviewInput<'a>>,
    outputs: Vec<ReviewOutput<'a>>,
    total_input_amount: u64,
    total_output_amount: u64,
    fee: u64,
    aggregate_status: VerifiedAggregateStatus,
    canonical: Vec<u8>,
}

impl<'a> Review<'a> {
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

    /// Authenticated descriptor A/B/C fingerprints.
    #[must_use]
    pub const fn origin_fingerprints(&self) -> [[u8; 4]; 3] {
        self.origin_fingerprints
    }

    /// Exact unsigned-transaction value bytes.
    #[must_use]
    pub const fn unsigned_tx_bytes(&self) -> &'a [u8] {
        self.unsigned_tx
    }

    /// Decoded transaction version.
    #[must_use]
    pub const fn version(&self) -> u32 {
        self.version
    }

    /// Decoded transaction locktime.
    #[must_use]
    pub const fn locktime(&self) -> u32 {
        self.locktime
    }

    /// Stable input facts in unsigned-transaction order.
    #[must_use]
    pub fn inputs(&self) -> &[ReviewInput<'a>] {
        &self.inputs
    }

    /// Stable output facts in unsigned-transaction order.
    #[must_use]
    pub fn outputs(&self) -> &[ReviewOutput<'a>] {
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

    /// M8 aggregate status.
    #[must_use]
    pub const fn aggregate_status(&self) -> VerifiedAggregateStatus {
        self.aggregate_status
    }

    /// Exact canonical D-09 v1 bytes.
    #[must_use]
    pub fn canonical_bytes(&self) -> &[u8] {
        &self.canonical
    }

    /// SHA-256 of the domain-separated canonical transcript.
    ///
    /// # Errors
    ///
    /// Returns [`ReviewError::HashFailure`] if checked SHA-256 length
    /// accounting fails.
    pub fn review_hash(&self) -> Result<ReviewHash, ReviewError> {
        hash_canonical(&self.canonical)
    }
}

/// Explicit review-construction failure.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReviewError {
    /// The supplied review context does not match the source retained by parse.
    SourceMismatch,
    /// M6-M13 analysis rejected.
    Semantic(SemanticError),
    /// Checked canonical length arithmetic overflowed.
    LengthOverflow,
    /// A count or variable field cannot be represented by u32.
    FieldLengthOverflow,
    /// Canonical bytes exceed the exact D-09 v1 cap.
    CanonicalTooLong,
    /// A bounded allocation failed.
    AllocationFailed,
    /// SHA-256 length accounting or an internal hash invariant failed.
    HashFailure,
    /// Successful M13 facts did not satisfy an internal parallel-shape invariant.
    InternalInvariant,
}

impl fmt::Display for ReviewError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::SourceMismatch => {
                f.write_str("review context input source differs from parsed PSBT source")
            }
            Self::Semantic(error) => write!(f, "review semantic analysis failed: {error}"),
            Self::LengthOverflow => f.write_str("review length arithmetic overflow"),
            Self::FieldLengthOverflow => f.write_str("review field length exceeds u32"),
            Self::CanonicalTooLong => f.write_str("canonical review exceeds byte cap"),
            Self::AllocationFailed => f.write_str("review allocation failed"),
            Self::HashFailure => f.write_str("review hash failed"),
            Self::InternalInvariant => f.write_str("review internal invariant failed"),
        }
    }
}

impl std::error::Error for ReviewError {}

impl From<SemanticError> for ReviewError {
    fn from(value: SemanticError) -> Self {
        Self::Semantic(value)
    }
}

fn checked_add(total: &mut usize, value: usize) -> Result<(), ReviewError> {
    *total = total
        .checked_add(value)
        .ok_or(ReviewError::LengthOverflow)?;
    Ok(())
}

fn variable_len(total: &mut usize, bytes: &[u8]) -> Result<(), ReviewError> {
    u32::try_from(bytes.len()).map_err(|_| ReviewError::FieldLengthOverflow)?;
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

fn verified_status_code(status: VerifiedInputStatus) -> u8 {
    match status {
        VerifiedInputStatus::BelowThreshold => 1,
        VerifiedInputStatus::CryptographicallyVerifiedThreshold => 2,
    }
}

fn aggregate_code(status: VerifiedAggregateStatus) -> u8 {
    match status {
        VerifiedAggregateStatus::AllInputsBelowThreshold => 1,
        VerifiedAggregateStatus::MixedInputCompleteness => 2,
        VerifiedAggregateStatus::VerifyAndExportOnly => 3,
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

fn put_variable(bytes: &mut Vec<u8>, value: &[u8]) -> Result<(), ReviewError> {
    let length = u32::try_from(value.len()).map_err(|_| ReviewError::FieldLengthOverflow)?;
    put_u32(bytes, length);
    bytes.extend_from_slice(value);
    Ok(())
}

fn canonical_bytes(review: &Review<'_>) -> Result<Vec<u8>, ReviewError> {
    let input_count =
        u32::try_from(review.inputs.len()).map_err(|_| ReviewError::FieldLengthOverflow)?;
    let output_count =
        u32::try_from(review.outputs.len()).map_err(|_| ReviewError::FieldLengthOverflow)?;
    let mut length = 124usize;
    checked_add(&mut length, review.unsigned_tx.len())?;
    for input in &review.inputs {
        checked_add(&mut length, 69)?;
        variable_len(&mut length, input.prevout_script_pubkey)?;
        if input.outpoint_txid_wire.len() != 32 {
            return Err(ReviewError::InternalInvariant);
        }
    }
    for output in &review.outputs {
        checked_add(&mut length, 12)?;
        variable_len(&mut length, output.script_pubkey)?;
        checked_add(&mut length, 1)?;
        match output.ownership {
            ReviewOutputOwnership::NotOwned(recipient) => {
                checked_add(&mut length, 1)?;
                variable_len(&mut length, recipient.data)?;
            }
            ReviewOutputOwnership::Change(_) | ReviewOutputOwnership::SelfTransfer(_) => {
                checked_add(&mut length, 4)?;
            }
        }
    }
    u32::try_from(review.unsigned_tx.len()).map_err(|_| ReviewError::FieldLengthOverflow)?;
    if length > limits::MAX_CANONICAL_REVIEW_BYTES {
        return Err(ReviewError::CanonicalTooLong);
    }

    let mut bytes = Vec::new();
    bytes
        .try_reserve_exact(length)
        .map_err(|_| ReviewError::AllocationFailed)?;
    bytes.push(SCHEMA_VERSION);
    bytes.push(network_code(review.context.network));
    bytes.push(source_code(review.context.input_source));
    bytes.extend_from_slice(&review.s0_sha256);
    bytes.extend_from_slice(&review.wallet_id);
    for fingerprint in review.origin_fingerprints {
        bytes.extend_from_slice(&fingerprint);
    }
    put_variable(&mut bytes, review.unsigned_tx)?;
    put_u32(&mut bytes, review.version);
    put_u32(&mut bytes, review.locktime);
    put_u32(&mut bytes, input_count);
    for input in &review.inputs {
        put_u32(&mut bytes, input.index);
        bytes.extend_from_slice(input.outpoint_txid_wire);
        put_u32(&mut bytes, input.outpoint_vout);
        put_u64(&mut bytes, input.prevout_amount);
        put_variable(&mut bytes, input.prevout_script_pubkey)?;
        put_u32(&mut bytes, input.sequence);
        put_u32(&mut bytes, input.effective_sighash);
        put_u32(&mut bytes, input.branch);
        put_u32(&mut bytes, input.child_index);
        put_u32(&mut bytes, input.verified_signature_count);
        bytes.push(verified_status_code(input.verified_status));
    }
    put_u32(&mut bytes, output_count);
    for output in &review.outputs {
        put_u32(&mut bytes, output.index);
        put_u64(&mut bytes, output.amount);
        put_variable(&mut bytes, output.script_pubkey)?;
        match output.ownership {
            ReviewOutputOwnership::NotOwned(recipient) => {
                bytes.push(1);
                bytes.push(recipient_code(recipient.recipient_type));
                put_variable(&mut bytes, recipient.data)?;
            }
            ReviewOutputOwnership::Change(index) => {
                bytes.push(2);
                put_u32(&mut bytes, index);
            }
            ReviewOutputOwnership::SelfTransfer(index) => {
                bytes.push(3);
                put_u32(&mut bytes, index);
            }
        }
    }
    put_u64(&mut bytes, review.total_input_amount);
    put_u64(&mut bytes, review.total_output_amount);
    put_u64(&mut bytes, review.fee);
    bytes.push(aggregate_code(review.aggregate_status));
    if bytes.len() != length {
        return Err(ReviewError::InternalInvariant);
    }
    Ok(bytes)
}

/// Build a complete session-free D-09 v1 review from authenticated inputs.
///
/// # Errors
///
/// Returns an explicit semantic, arithmetic, size, allocation, hash, or
/// internal-invariant error. No caller-supplied opaque bytes are accepted.
pub fn build_review<'a>(
    view: &PsbtView<'a>,
    descriptor: &DescriptorPair,
    context: ReviewContext,
) -> Result<Review<'a>, ReviewError> {
    if context.input_source != view.source() {
        return Err(ReviewError::SourceMismatch);
    }
    let analysis = analyze_recipient_script_facts(view, descriptor)?;
    let ownership = &analysis.ownership;
    if ownership.candidate.inputs.len() != ownership.wallet.inputs.len()
        || ownership.candidate.inputs.len() != ownership.verified_inputs.len()
        || ownership.candidate.outputs.len() != ownership.wallet.outputs.len()
        || ownership.candidate.outputs.len() != analysis.recipient_outputs.len()
    {
        return Err(ReviewError::InternalInvariant);
    }

    let mut inputs = Vec::new();
    inputs
        .try_reserve_exact(ownership.candidate.inputs.len())
        .map_err(|_| ReviewError::AllocationFailed)?;
    for (position, ((input, route), verified)) in ownership
        .candidate
        .inputs
        .iter()
        .zip(&ownership.wallet.inputs)
        .zip(&ownership.verified_inputs)
        .enumerate()
    {
        inputs.push(ReviewInput {
            index: u32::try_from(position).map_err(|_| ReviewError::FieldLengthOverflow)?,
            outpoint_txid_wire: input.outpoint_txid_wire,
            outpoint_vout: input.outpoint_vout,
            prevout_amount: input.prevout_amount,
            prevout_script_pubkey: input.prevout_script_pubkey,
            sequence: input.sequence,
            effective_sighash: SIGHASH_ALL,
            branch: route.branch,
            child_index: route.index,
            verified_signature_count: u32::try_from(verified.verified_signature_count)
                .map_err(|_| ReviewError::FieldLengthOverflow)?,
            verified_status: verified.status,
        });
    }

    let mut outputs = Vec::new();
    outputs
        .try_reserve_exact(ownership.candidate.outputs.len())
        .map_err(|_| ReviewError::AllocationFailed)?;
    for (position, ((output, owner), recipient)) in ownership
        .candidate
        .outputs
        .iter()
        .zip(&ownership.wallet.outputs)
        .zip(&analysis.recipient_outputs)
        .enumerate()
    {
        let output_ownership = match (owner, recipient) {
            (OutputOwnership::NotProvenOwned, Some(facts)) => {
                ReviewOutputOwnership::NotOwned(ReviewRecipient {
                    recipient_type: facts.recipient_type,
                    data: facts.data,
                })
            }
            (OutputOwnership::ProvenChange(index), None) => ReviewOutputOwnership::Change(*index),
            (OutputOwnership::ProvenSelfTransfer(index), None) => {
                ReviewOutputOwnership::SelfTransfer(*index)
            }
            _ => return Err(ReviewError::InternalInvariant),
        };
        outputs.push(ReviewOutput {
            index: u32::try_from(position).map_err(|_| ReviewError::FieldLengthOverflow)?,
            amount: output.amount,
            script_pubkey: output.script_pubkey,
            ownership: output_ownership,
        });
    }

    let s0_sha256 = sha256(&[view.buffer()]).map_err(|_| ReviewError::HashFailure)?;
    let mut review = Review {
        context,
        s0_sha256,
        wallet_id: descriptor.wallet_id(),
        origin_fingerprints: descriptor.origin_fingerprints(),
        unsigned_tx: view.unsigned_tx_bytes(),
        version: ownership.candidate.version,
        locktime: ownership.candidate.locktime,
        inputs,
        outputs,
        total_input_amount: ownership.candidate.total_input_amount,
        total_output_amount: ownership.candidate.total_output_amount,
        fee: ownership.candidate.fee,
        aggregate_status: ownership.aggregate_status,
        canonical: Vec::new(),
    };
    review.canonical = canonical_bytes(&review)?;
    Ok(review)
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
        canonical_bytes, hash_canonical, Review, ReviewContext, ReviewError, ReviewNetwork,
        VerifiedAggregateStatus,
    };
    use crate::sha256::sha256;
    use crate::{limits, InputSource};

    fn synthetic_review(unsigned_tx: &[u8]) -> Review<'_> {
        Review {
            context: ReviewContext {
                network: ReviewNetwork::BitcoinMainnet,
                input_source: InputSource::MicroSd,
            },
            s0_sha256: [0; 32],
            wallet_id: [0; 32],
            origin_fingerprints: [[0; 4]; 3],
            unsigned_tx,
            version: 0,
            locktime: 0,
            inputs: Vec::new(),
            outputs: Vec::new(),
            total_input_amount: 0,
            total_output_amount: 0,
            fee: 0,
            aggregate_status: VerifiedAggregateStatus::AllInputsBelowThreshold,
            canonical: Vec::new(),
        }
    }

    #[test]
    fn canonical_cap_boundary_and_over_limit_rejection() {
        let boundary = vec![0; limits::MAX_CANONICAL_REVIEW_BYTES - 124];
        let boundary_review = synthetic_review(&boundary);
        let encoded = canonical_bytes(&boundary_review).unwrap();
        assert_eq!(encoded.len(), limits::MAX_CANONICAL_REVIEW_BYTES);

        let over = vec![0; limits::MAX_CANONICAL_REVIEW_BYTES - 123];
        let over_review = synthetic_review(&over);
        assert!(matches!(
            canonical_bytes(&over_review),
            Err(ReviewError::CanonicalTooLong)
        ));
    }

    #[test]
    fn exact_domain_separator_and_every_canonical_byte_are_hash_bound() {
        let canonical: Vec<u8> = (0..=255).collect();
        let baseline = hash_canonical(&canonical).unwrap();

        for position in 0..canonical.len() {
            let mut changed = canonical.clone();
            changed[position] ^= 1;
            assert_ne!(hash_canonical(&changed).unwrap(), baseline);
        }

        let wrong_domain = sha256(&[b"QuietKey/D-09/review/v2", &[0], &canonical]).unwrap();
        let missing_separator = sha256(&[b"QuietKey/D-09/review/v1", &canonical]).unwrap();
        assert_ne!(wrong_domain, baseline);
        assert_ne!(missing_separator, baseline);
    }

    #[test]
    fn published_review_binding_fixture_contract_is_frozen() {
        const FIXTURE: &[u8] = include_bytes!("../tests/fixtures/review_binding.txt");
        const REQUIRED_FIELDS: [&str; 14] = [
            "case",
            "class",
            "expected",
            "s0_len",
            "s0_sha256",
            "s0_hex",
            "unsigned_tx_hex",
            "wallet_id",
            "canonical_review_len",
            "canonical_review_hex",
            "domain_ascii",
            "domain_hex",
            "review_hash",
            "separator_hex",
        ];
        const CASES: [(&str, &str, &str, &str, &str); 2] = [
            (
                "M14-FULL",
                "returned-fact-never-fund",
                "complete-schema-v1",
                "922",
                "617",
            ),
            (
                "M14-RAW-MUTATION",
                "returned-fact-never-fund",
                "same-semantics-different-raw-s0",
                "927",
                "617",
            ),
        ];
        const EXPECTED_SHA256: [u8; 32] = [
            0xcc, 0x12, 0x18, 0x46, 0xa9, 0x42, 0xbf, 0x21, 0xa0, 0x22, 0x85, 0x25, 0xfc, 0x06,
            0xbe, 0xd3, 0xae, 0x85, 0xa5, 0xbf, 0xc6, 0x88, 0xe1, 0x2e, 0xa7, 0x9d, 0x15, 0x5e,
            0xec, 0x37, 0x00, 0x04,
        ];

        assert_eq!(FIXTURE.len(), 10_205);
        assert_eq!(FIXTURE.iter().filter(|&&byte| byte == b'\n').count(), 43);
        assert_eq!(FIXTURE.iter().filter(|&&byte| byte == b'\r').count(), 0);
        assert_eq!(FIXTURE.last(), Some(&b'\n'));
        assert_eq!(sha256(&[FIXTURE]).unwrap(), EXPECTED_SHA256);

        let text = core::str::from_utf8(FIXTURE).unwrap();
        let blocks: Vec<&str> = text
            .split("\n\n")
            .filter(|block| block.starts_with("case: "))
            .collect();
        assert_eq!(blocks.len(), CASES.len());
        assert_eq!(
            blocks
                .iter()
                .map(|block| block
                    .strip_prefix("case: ")
                    .unwrap()
                    .lines()
                    .next()
                    .unwrap())
                .collect::<Vec<_>>(),
            CASES.iter().map(|case| case.0).collect::<Vec<_>>()
        );

        for (block, (name, class, expected, s0_len, canonical_len)) in blocks.iter().zip(CASES) {
            let lines: Vec<&str> = block.lines().collect();
            assert_eq!(lines.len(), REQUIRED_FIELDS.len(), "{name}");
            for field in REQUIRED_FIELDS {
                let prefix = format!("{field}: ");
                assert_eq!(
                    lines
                        .iter()
                        .filter(|line| line.starts_with(&prefix))
                        .count(),
                    1,
                    "{name}: {field}"
                );
            }
            let value = |field| {
                lines
                    .iter()
                    .find_map(|line| line.strip_prefix(&format!("{field}: ")))
                    .unwrap()
            };
            assert_eq!(value("case"), name);
            assert_eq!(value("class"), class);
            assert_eq!(value("expected"), expected);
            assert_eq!(value("s0_len"), s0_len);
            assert_eq!(value("canonical_review_len"), canonical_len);
            assert_eq!(value("domain_ascii"), "QuietKey/D-09/review/v1");
            assert_eq!(
                value("domain_hex"),
                "51756965744b65792f442d30392f7265766965772f7631"
            );
            assert_eq!(value("separator_hex"), "00");
        }
    }
}
