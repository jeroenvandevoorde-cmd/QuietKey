//! Purpose-bound schema-v3 proof, signature insertion, and finalization.
//!
//! This feature-gated leaf owns the exact normal-wallet transaction bytes and
//! exposes only descriptor-derived signing plans plus one consuming
//! finalization operation. It contains no key derivation or signing operation.

use crate::bip143::{
    sighash_all_digest, Bip143InputFacts, Bip143PrecomputeBuilder, Bip143Precomputed, SIGHASH_ALL,
};
use crate::wipe;
use crate::{
    analyze_descriptor_ownership_v2, build_review_v3, canonical_serialize, parse, InputSource,
    OwnedS0, ParseError, PsbtView, Record, ReviewContext, ReviewNetwork, ReviewV3, ReviewV3Error,
    ReviewV3Hash, SemanticError, SerializeError, Span, VerifiedAggregateStatus, VerifiedInputFacts,
};
use core::fmt;
use qk_descriptor::{
    derive_change_script_v2, derive_receive_script_v2, DerivedScriptV2, DescriptorPairV2,
};

const ROLE_COUNT: usize = 2;
const THRESHOLD: usize = 2;
const DER_CAPACITY: usize = 72;
const MAX_INSERTIONS: usize = 200;
const PSBT_MAGIC_BYTES: usize = 5;
const WITNESS_SCRIPT_BYTES: usize = 71;
const DER_PLUS_SIGHASH_MAX_BYTES: usize = 72;
const DERIVATION_RECORD_BYTES: usize = 64;
const PARTIAL_SIGNATURE_RECORD_MAX_BYTES: usize = 108;
const MAX_UNSIGNED_TRANSACTION_BYTES: usize = 5_535;
const MAX_WITNESS_BYTES_PER_INPUT: usize = 220;
const MAX_FINAL_WITNESS_RECORD_BYTES: usize = 223;
const MAX_RAW_TRANSACTION_BYTES: usize = 27_537;
const MIN_FINALIZED_PSBT_SHRINK_PER_INPUT: usize = 121;

const _: [(); MAX_WITNESS_BYTES_PER_INPUT] =
    [(); 1 + 1 + 2 * (1 + DER_PLUS_SIGHASH_MAX_BYTES) + (1 + WITNESS_SCRIPT_BYTES)];
const _: [(); MAX_FINAL_WITNESS_RECORD_BYTES] = [(); 1 + 1 + 1 + MAX_WITNESS_BYTES_PER_INPUT];
const _: [(); MAX_RAW_TRANSACTION_BYTES] =
    [(); MAX_UNSIGNED_TRANSACTION_BYTES + 2 + 100 * MAX_WITNESS_BYTES_PER_INPUT];
const _: [(); MIN_FINALIZED_PSBT_SHRINK_PER_INPUT] = [(); 2 * PARTIAL_SIGNATURE_RECORD_MAX_BYTES
    + 2 * DERIVATION_RECORD_BYTES
    - MAX_FINAL_WITNESS_RECORD_BYTES];

/// One immutable descriptor-derived input signing plan.
pub struct NormalInputSigningPlanV3 {
    input_index: u32,
    branch: u32,
    child_index: u32,
    digest: [u8; 32],
    role_public_keys: [[u8; 33]; ROLE_COUNT],
    existing_role_signatures: [bool; ROLE_COUNT],
}

impl NormalInputSigningPlanV3 {
    #[must_use]
    pub const fn input_index(&self) -> u32 {
        self.input_index
    }

    #[must_use]
    pub const fn branch(&self) -> u32 {
        self.branch
    }

    #[must_use]
    pub const fn child_index(&self) -> u32 {
        self.child_index
    }

    #[must_use]
    pub const fn digest(&self) -> &[u8; 32] {
        &self.digest
    }

    #[must_use]
    pub const fn role_public_keys(&self) -> &[[u8; 33]; ROLE_COUNT] {
        &self.role_public_keys
    }

    #[must_use]
    pub const fn existing_role_signatures(&self) -> [bool; ROLE_COUNT] {
        self.existing_role_signatures
    }
}

impl Drop for NormalInputSigningPlanV3 {
    fn drop(&mut self) {
        wipe::bytes(&mut self.digest);
        for key in &mut self.role_public_keys {
            wipe::bytes(key);
        }
        wipe::bools(&mut self.existing_role_signatures);
    }
}

/// Opaque proof that exact retained S0 produced one schema-v3 normal review.
pub struct ValidatedNormalV3 {
    s0: OwnedS0,
    descriptor: DescriptorPairV2,
    review: ReviewV3,
    review_hash: wipe::ByteArray<32>,
    plans: wipe::WipingValueVec<NormalInputSigningPlanV3>,
}

impl ValidatedNormalV3 {
    #[must_use]
    pub const fn wallet_id(&self) -> [u8; 32] {
        self.review.wallet_id()
    }

    #[must_use]
    pub const fn review(&self) -> &ReviewV3 {
        &self.review
    }

    #[must_use]
    pub const fn review_hash(&self) -> ReviewV3Hash {
        self.review_hash.value()
    }

    #[must_use]
    pub const fn s0_sha256(&self) -> [u8; 32] {
        self.s0.sha256()
    }

    #[must_use]
    pub const fn input_source(&self) -> InputSource {
        self.s0.source()
    }

    #[must_use]
    pub fn input_signing_plans(&self) -> &[NormalInputSigningPlanV3] {
        self.plans.as_slice()
    }

    /// Reparse only retained immutable S0 and reproduce its exact review.
    pub fn revalidate(&self) -> Result<(), NormalV3Error> {
        revalidate_exact(&self.s0, &self.descriptor, &self.review, self.review_hash())
    }

    #[must_use]
    pub fn into_parts(self) -> ValidatedNormalV3Parts {
        let Self {
            s0,
            descriptor,
            review,
            review_hash,
            plans,
        } = self;
        ValidatedNormalV3Parts {
            s0,
            descriptor,
            review,
            review_hash,
            plans,
        }
    }
}

/// Move-only proof ownership retained across the purpose-bound signer.
pub struct ValidatedNormalV3Parts {
    s0: OwnedS0,
    descriptor: DescriptorPairV2,
    review: ReviewV3,
    review_hash: wipe::ByteArray<32>,
    plans: wipe::WipingValueVec<NormalInputSigningPlanV3>,
}

impl ValidatedNormalV3Parts {
    #[must_use]
    pub const fn wallet_id(&self) -> [u8; 32] {
        self.review.wallet_id()
    }

    #[must_use]
    pub const fn review_hash(&self) -> ReviewV3Hash {
        self.review_hash.value()
    }

    #[must_use]
    pub fn input_signing_plans(&self) -> &[NormalInputSigningPlanV3] {
        self.plans.as_slice()
    }

    #[must_use]
    pub fn input_count(&self) -> usize {
        self.plans.len()
    }
}

/// DER-only signature response bound by the finalizer to role and input.
#[derive(Clone, Copy)]
pub struct NormalSubmittedSignatureV3<'a> {
    input_index: u32,
    der_signature: &'a [u8],
}

impl<'a> NormalSubmittedSignatureV3<'a> {
    #[must_use]
    pub const fn new(input_index: u32, der_signature: &'a [u8]) -> Self {
        Self {
            input_index,
            der_signature,
        }
    }

    #[must_use]
    pub const fn input_index(self) -> u32 {
        self.input_index
    }

    #[must_use]
    pub const fn der_signature(self) -> &'a [u8] {
        self.der_signature
    }
}

/// Stable proof-construction and same-S0 revalidation errors.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NormalV3Error {
    Parse(ParseError),
    Review(ReviewV3Error),
    ExistingSignatureVerification(SemanticError),
    DigestFailed,
    AllocationFailed,
    ReviewFactsMismatch,
    ReviewHashMismatch,
    RetainedS0Mismatch,
    InternalInvariant,
}

impl NormalV3Error {
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::Parse(_) => "TransactionParseFailed",
            Self::Review(_) => "TransactionReviewRejected",
            Self::ExistingSignatureVerification(_) => "ExistingSignatureVerificationFailed",
            Self::DigestFailed => "DigestFailed",
            Self::AllocationFailed => "AllocationFailed",
            Self::ReviewFactsMismatch => "ReviewFactsMismatch",
            Self::ReviewHashMismatch => "ReviewHashMismatch",
            Self::RetainedS0Mismatch => "RetainedS0Mismatch",
            Self::InternalInvariant => "InternalInvariant",
        }
    }
}

impl fmt::Display for NormalV3Error {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.name())
    }
}

impl std::error::Error for NormalV3Error {}

/// Consume one exact S0 into a normal schema-v3 signing proof.
pub fn build_validated_normal_v3(
    s0: OwnedS0,
    descriptor: DescriptorPairV2,
) -> Result<ValidatedNormalV3, NormalV3Error> {
    let view = s0.parse().map_err(NormalV3Error::Parse)?;
    let review = build_review_v3(
        &view,
        &descriptor,
        ReviewContext {
            network: ReviewNetwork::BitcoinMainnet,
            input_source: s0.source(),
        },
    )
    .map_err(NormalV3Error::Review)?;
    let verified = analyze_descriptor_ownership_v2(&view, &descriptor)
        .map_err(NormalV3Error::ExistingSignatureVerification)?;
    let plans = build_signing_plans(&view, &review, &descriptor, &verified.verified_inputs)?;
    let mut review_hash =
        wipe::ByteArray::new(review.review_hash().map_err(NormalV3Error::Review)?);
    if review.s0_sha256() != s0.sha256()
        || review.wallet_id() != descriptor.wallet_id()
        || plans.len() != review.input_count()
    {
        return Err(NormalV3Error::InternalInvariant);
    }
    drop(view);
    Ok(ValidatedNormalV3 {
        s0,
        descriptor,
        review,
        review_hash: wipe::ByteArray::new(review_hash.take()),
        plans,
    })
}

fn revalidate_exact(
    s0: &OwnedS0,
    descriptor: &DescriptorPairV2,
    bound_review: &ReviewV3,
    bound_hash: ReviewV3Hash,
) -> Result<(), NormalV3Error> {
    let view = s0.parse().map_err(NormalV3Error::Parse)?;
    if view.buffer().as_ptr() != s0.bytes().as_ptr()
        || view.buffer().len() != s0.bytes().len()
        || view.source() != s0.source()
    {
        return Err(NormalV3Error::RetainedS0Mismatch);
    }
    let rebuilt = build_review_v3(
        &view,
        descriptor,
        ReviewContext {
            network: ReviewNetwork::BitcoinMainnet,
            input_source: s0.source(),
        },
    )
    .map_err(NormalV3Error::Review)?;
    if &rebuilt != bound_review {
        return Err(NormalV3Error::ReviewFactsMismatch);
    }
    if rebuilt.review_hash().map_err(NormalV3Error::Review)? != bound_hash {
        return Err(NormalV3Error::ReviewHashMismatch);
    }
    analyze_descriptor_ownership_v2(&view, descriptor)
        .map_err(NormalV3Error::ExistingSignatureVerification)?;
    Ok(())
}

fn build_signing_plans(
    view: &PsbtView<'_>,
    review: &ReviewV3,
    descriptor: &DescriptorPairV2,
    verified_inputs: &[VerifiedInputFacts],
) -> Result<wipe::WipingValueVec<NormalInputSigningPlanV3>, NormalV3Error> {
    let mut digests = compute_digests(review, descriptor).map_err(map_final_to_proof)?;
    if verified_inputs.len() != review.input_count() || digests.len() != review.input_count() {
        return Err(NormalV3Error::InternalInvariant);
    }
    let fingerprints = descriptor.origin_fingerprints();
    let mut plans = wipe::WipingValueVec::new();
    plans
        .try_reserve_exact(review.input_count())
        .map_err(|_| NormalV3Error::AllocationFailed)?;
    for ((input, verified), mut digest) in review
        .inputs()
        .iter()
        .zip(verified_inputs)
        .zip(digests.drain(..))
    {
        let input_index =
            usize::try_from(input.index()).map_err(|_| NormalV3Error::InternalInvariant)?;
        let (role_keys, occupied) = collect_role_public_keys(view, input_index, &fingerprints)
            .map_err(map_final_to_proof)?;
        if occupied.iter().filter(|present| **present).count() != verified.verified_signature_count
        {
            return Err(NormalV3Error::InternalInvariant);
        }
        let [mut role_a, mut role_b] = role_keys;
        plans.push(NormalInputSigningPlanV3 {
            input_index: input.index(),
            branch: input.branch(),
            child_index: input.child_index(),
            digest: digest.take(),
            role_public_keys: [role_a.take(), role_b.take()],
            existing_role_signatures: occupied,
        });
    }
    Ok(plans)
}

fn map_final_to_proof(error: NormalFinalizationErrorV3) -> NormalV3Error {
    match error {
        NormalFinalizationErrorV3::DigestFailed => NormalV3Error::DigestFailed,
        NormalFinalizationErrorV3::AllocationFailed => NormalV3Error::AllocationFailed,
        _ => NormalV3Error::InternalInvariant,
    }
}

/// Fully checked canonical PSBT and extracted witness transaction.
///
/// No public constructor or byte-extraction operation exists. Both backing
/// allocations and both identifiers are cleared on drop.
pub struct FinalizedNormalV3 {
    finalized_psbt: crate::TransactionMaterialVec<u8>,
    raw_transaction: crate::TransactionMaterialVec<u8>,
    finalized_psbt_sha256: wipe::ByteArray<32>,
    raw_transaction_sha256: wipe::ByteArray<32>,
    txid: wipe::ByteArray<32>,
    wtxid: wipe::ByteArray<32>,
    review_hash: wipe::ByteArray<32>,
    wallet_id: wipe::ByteArray<32>,
}

impl FinalizedNormalV3 {
    #[must_use]
    pub fn finalized_psbt(&self) -> &[u8] {
        self.finalized_psbt.as_slice()
    }

    #[must_use]
    pub fn raw_transaction(&self) -> &[u8] {
        self.raw_transaction.as_slice()
    }

    #[must_use]
    pub const fn finalized_psbt_sha256(&self) -> [u8; 32] {
        self.finalized_psbt_sha256.value()
    }

    #[must_use]
    pub const fn raw_transaction_sha256(&self) -> [u8; 32] {
        self.raw_transaction_sha256.value()
    }

    #[must_use]
    pub const fn txid(&self) -> [u8; 32] {
        self.txid.value()
    }

    #[must_use]
    pub const fn wtxid(&self) -> [u8; 32] {
        self.wtxid.value()
    }

    #[must_use]
    pub const fn review_hash(&self) -> [u8; 32] {
        self.review_hash.value()
    }

    #[must_use]
    pub const fn wallet_id(&self) -> [u8; 32] {
        self.wallet_id.value()
    }
}

/// Stable signature-insertion and finalization rejection surface.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NormalFinalizationErrorV3 {
    Revalidation(NormalV3Error),
    ParseFailed,
    ReviewFactsMismatch,
    ReviewHashMismatch,
    ExistingSignatureVerification(SemanticError),
    DigestFailed,
    SerializeFailed(SerializeError),
    InputOutOfRange,
    DuplicateRole,
    SignatureConflict,
    ThresholdAlreadyMet,
    ThresholdIncomplete,
    TooManyInsertions,
    InvalidRoleASignature,
    InvalidMockSignature,
    DuplicateSignature,
    ForbiddenDelta,
    NonCanonicalOutput,
    ArtifactTooLarge,
    CapabilityParse,
    WitnessShapeMismatch,
    WitnessOrderMismatch,
    LengthOverflow,
    AllocationFailed,
    FinalizedPsbtReparse,
    FinalizedPsbtNonCanonical,
    RawTransactionReparse,
    BaseTransactionMismatch,
    WitnessMismatch,
    FinalSignatureVerificationFailed,
    HashFailed,
    InternalInvariant,
}

impl NormalFinalizationErrorV3 {
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::Revalidation(_) => "RevalidationMismatch",
            Self::ParseFailed => "ParseFailed",
            Self::ReviewFactsMismatch => "ReviewFactsMismatch",
            Self::ReviewHashMismatch => "ReviewHashMismatch",
            Self::ExistingSignatureVerification(_) => "ExistingSignatureVerificationFailed",
            Self::DigestFailed => "DigestFailed",
            Self::SerializeFailed(_) => "SerializeFailed",
            Self::InputOutOfRange => "InputOutOfRange",
            Self::DuplicateRole => "DuplicateRole",
            Self::SignatureConflict => "SignatureConflict",
            Self::ThresholdAlreadyMet => "ThresholdAlreadyMet",
            Self::ThresholdIncomplete => "ThresholdIncomplete",
            Self::TooManyInsertions => "TooManyInsertions",
            Self::InvalidRoleASignature => "InvalidRoleASignature",
            Self::InvalidMockSignature => "InvalidMockSignature",
            Self::DuplicateSignature => "DuplicateSignature",
            Self::ForbiddenDelta => "ForbiddenDelta",
            Self::NonCanonicalOutput => "NonCanonicalOutput",
            Self::ArtifactTooLarge => "ArtifactTooLarge",
            Self::CapabilityParse => "CapabilityParse",
            Self::WitnessShapeMismatch => "WitnessShapeMismatch",
            Self::WitnessOrderMismatch => "WitnessOrderMismatch",
            Self::LengthOverflow => "LengthOverflow",
            Self::AllocationFailed => "AllocationFailed",
            Self::FinalizedPsbtReparse => "FinalizedPsbtReparse",
            Self::FinalizedPsbtNonCanonical => "FinalizedPsbtNonCanonical",
            Self::RawTransactionReparse => "RawTransactionReparse",
            Self::BaseTransactionMismatch => "BaseTransactionMismatch",
            Self::WitnessMismatch => "WitnessMismatch",
            Self::FinalSignatureVerificationFailed => "FinalSignatureVerificationFailed",
            Self::HashFailed => "HashFailed",
            Self::InternalInvariant => "InternalInvariant",
        }
    }
}

impl fmt::Display for NormalFinalizationErrorV3 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.name())
    }
}

impl std::error::Error for NormalFinalizationErrorV3 {}

struct WipingDigest(wipe::ByteArray<32>);

impl WipingDigest {
    fn new(value: [u8; 32]) -> Self {
        Self(wipe::ByteArray::new(value))
    }

    const fn as_array(&self) -> &[u8; 32] {
        self.0.as_array()
    }

    fn take(&mut self) -> [u8; 32] {
        self.0.take()
    }
}

struct WipingPrecomputed(Bip143Precomputed);

impl Drop for WipingPrecomputed {
    fn drop(&mut self) {
        wipe::bytes(&mut self.0.hash_prevouts);
        wipe::bytes(&mut self.0.hash_sequence);
        wipe::bytes(&mut self.0.hash_outputs);
    }
}

struct WipingDerivedScript(DerivedScriptV2);

impl Drop for WipingDerivedScript {
    fn drop(&mut self) {
        wipe::bytes(&mut self.0.witness_script);
        wipe::bytes(&mut self.0.script_pubkey);
    }
}

fn derive_script(
    descriptor: &DescriptorPairV2,
    branch: u32,
    index: u32,
) -> Result<DerivedScriptV2, NormalFinalizationErrorV3> {
    match branch {
        0 => derive_receive_script_v2(descriptor, index),
        1 => derive_change_script_v2(descriptor, index),
        _ => return Err(NormalFinalizationErrorV3::InternalInvariant),
    }
    .map_err(|_| NormalFinalizationErrorV3::InternalInvariant)
}

fn compute_digests(
    review: &ReviewV3,
    descriptor: &DescriptorPairV2,
) -> Result<wipe::WipingValueVec<WipingDigest>, NormalFinalizationErrorV3> {
    let mut builder = Bip143PrecomputeBuilder::new();
    for input in review.inputs() {
        let txid = input.outpoint_txid_wire();
        builder
            .add_input(&txid, input.outpoint_vout(), input.sequence())
            .map_err(|_| NormalFinalizationErrorV3::DigestFailed)?;
    }
    for output in review.outputs() {
        builder
            .add_output(output.amount(), output.script_pubkey())
            .map_err(|_| NormalFinalizationErrorV3::DigestFailed)?;
    }
    let precomputed = WipingPrecomputed(
        builder
            .finish()
            .map_err(|_| NormalFinalizationErrorV3::DigestFailed)?,
    );
    let mut digests = wipe::WipingValueVec::new();
    digests
        .try_reserve_exact(review.input_count())
        .map_err(|_| NormalFinalizationErrorV3::AllocationFailed)?;
    for input in review.inputs() {
        if input.effective_sighash() != u32::from(SIGHASH_ALL) {
            return Err(NormalFinalizationErrorV3::InternalInvariant);
        }
        let script = WipingDerivedScript(derive_script(
            descriptor,
            input.branch(),
            input.child_index(),
        )?);
        let txid = WipingDigest::new(input.outpoint_txid_wire());
        let facts = Bip143InputFacts {
            outpoint_txid_wire: txid.as_array(),
            outpoint_vout: input.outpoint_vout(),
            script_code: &script.0.witness_script,
            amount_sats: input.prevout_amount(),
            sequence: input.sequence(),
        };
        digests.push(WipingDigest::new(
            sighash_all_digest(review.version(), review.locktime(), &precomputed.0, &facts)
                .map_err(|_| NormalFinalizationErrorV3::DigestFailed)?,
        ));
    }
    Ok(digests)
}

fn collect_role_public_keys(
    view: &PsbtView<'_>,
    input_index: usize,
    fingerprints: &[[u8; 4]; ROLE_COUNT],
) -> Result<([wipe::ByteArray<33>; ROLE_COUNT], [bool; ROLE_COUNT]), NormalFinalizationErrorV3> {
    let records = view
        .input_records(input_index)
        .ok_or(NormalFinalizationErrorV3::InternalInvariant)?;
    let mut keys: [Option<wipe::ByteArray<33>>; ROLE_COUNT] = [None, None];
    for record in records {
        if record.key_type != 0x06 {
            continue;
        }
        let fingerprint = record
            .value
            .get(..4)
            .ok_or(NormalFinalizationErrorV3::InternalInvariant)?;
        let role = fingerprints
            .iter()
            .position(|candidate| candidate.as_slice() == fingerprint)
            .ok_or(NormalFinalizationErrorV3::InternalInvariant)?;
        let key: [u8; 33] = record
            .key_data
            .try_into()
            .map_err(|_| NormalFinalizationErrorV3::InternalInvariant)?;
        if keys
            .get_mut(role)
            .ok_or(NormalFinalizationErrorV3::InternalInvariant)?
            .replace(wipe::ByteArray::new(key))
            .is_some()
        {
            return Err(NormalFinalizationErrorV3::InternalInvariant);
        }
    }
    let [key_a, key_b] = keys;
    let key_a = key_a.ok_or(NormalFinalizationErrorV3::InternalInvariant)?;
    let key_b = key_b.ok_or(NormalFinalizationErrorV3::InternalInvariant)?;
    let mut occupied = [false; ROLE_COUNT];
    for record in view
        .input_records(input_index)
        .ok_or(NormalFinalizationErrorV3::InternalInvariant)?
    {
        if record.key_type != 0x02 {
            continue;
        }
        let role = if record.key_data == key_a.as_array() {
            0
        } else if record.key_data == key_b.as_array() {
            1
        } else {
            return Err(NormalFinalizationErrorV3::InternalInvariant);
        };
        let target = occupied
            .get_mut(role)
            .ok_or(NormalFinalizationErrorV3::InternalInvariant)?;
        if *target {
            return Err(NormalFinalizationErrorV3::InternalInvariant);
        }
        *target = true;
    }
    Ok(([key_a, key_b], occupied))
}

struct PlannedSignature {
    input_index: usize,
    public_key: [u8; 33],
    der_signature: Vec<u8>,
}

struct OwnedBytes(Vec<u8>);

impl OwnedBytes {
    fn take(value: Vec<u8>) -> Self {
        Self(value)
    }

    fn new() -> Self {
        Self(Vec::new())
    }

    fn as_slice(&self) -> &[u8] {
        &self.0
    }

    fn as_mut_vec(&mut self) -> &mut Vec<u8> {
        &mut self.0
    }

    fn into_vec(mut self) -> Vec<u8> {
        core::mem::take(&mut self.0)
    }
}

impl Drop for OwnedBytes {
    fn drop(&mut self) {
        wipe::byte_vec(&mut self.0);
    }
}

impl Drop for PlannedSignature {
    fn drop(&mut self) {
        wipe::bytes(&mut self.public_key);
        wipe::byte_vec(&mut self.der_signature);
    }
}

/// Insert exact role-A and role-B responses, then finalize and freshly verify.
///
/// Every supplied DER value is verified against the descriptor-derived role
/// key and exact BIP143 digest before it is copied into an intermediate PSBT.
pub fn finalize_validated_normal_v3(
    proof: ValidatedNormalV3Parts,
    role_a_signatures: &[NormalSubmittedSignatureV3<'_>],
    role_b_signatures: &[NormalSubmittedSignatureV3<'_>],
) -> Result<FinalizedNormalV3, NormalFinalizationErrorV3> {
    revalidate_exact(
        &proof.s0,
        &proof.descriptor,
        &proof.review,
        proof.review_hash(),
    )
    .map_err(NormalFinalizationErrorV3::Revalidation)?;
    if role_a_signatures
        .len()
        .saturating_add(role_b_signatures.len())
        > MAX_INSERTIONS
    {
        return Err(NormalFinalizationErrorV3::TooManyInsertions);
    }
    let view = proof
        .s0
        .parse()
        .map_err(|_| NormalFinalizationErrorV3::ParseFailed)?;
    let mut planned = plan_submitted_signatures(
        &view,
        proof.input_signing_plans(),
        role_a_signatures,
        role_b_signatures,
    )?;
    planned.sort_unstable_by(|left, right| {
        left.input_index
            .cmp(&right.input_index)
            .then_with(|| left.public_key.cmp(&right.public_key))
    });
    let source = proof.s0.source();
    let mut current = OwnedBytes::take(
        canonical_serialize(&view).map_err(NormalFinalizationErrorV3::SerializeFailed)?,
    );
    drop(view);
    let mut verified_counts = OwnedBytes::new();
    verified_counts
        .as_mut_vec()
        .try_reserve_exact(proof.input_count())
        .map_err(|_| NormalFinalizationErrorV3::AllocationFailed)?;
    for plan in proof.input_signing_plans() {
        verified_counts.as_mut_vec().push(
            u8::try_from(
                plan.existing_role_signatures()
                    .iter()
                    .filter(|present| **present)
                    .count(),
            )
            .map_err(|_| NormalFinalizationErrorV3::InternalInvariant)?,
        );
    }

    for signature in planned.iter() {
        let previous = core::mem::replace(&mut current, OwnedBytes::new());
        let previous_view = parse(previous.as_slice(), source)
            .map_err(|_| NormalFinalizationErrorV3::ParseFailed)?;
        let (next, offset, inserted) = insert_partial_signature(
            &previous_view,
            previous.as_slice(),
            source,
            signature.input_index,
            &signature.public_key,
            &signature.der_signature,
        )?;
        let next_owner = OwnedBytes::take(next);
        if !exact_insert_delta(previous.as_slice(), next_owner.as_slice(), offset, inserted) {
            return Err(NormalFinalizationErrorV3::ForbiddenDelta);
        }
        let next_view = parse(next_owner.as_slice(), source)
            .map_err(|_| NormalFinalizationErrorV3::ParseFailed)?;
        let canonical = OwnedBytes::take(
            canonical_serialize(&next_view).map_err(NormalFinalizationErrorV3::SerializeFailed)?,
        );
        if canonical.as_slice() != next_owner.as_slice() {
            return Err(NormalFinalizationErrorV3::NonCanonicalOutput);
        }
        let next_review = build_review_v3(
            &next_view,
            &proof.descriptor,
            ReviewContext {
                network: ReviewNetwork::BitcoinMainnet,
                input_source: source,
            },
        )
        .map_err(|_| NormalFinalizationErrorV3::ReviewFactsMismatch)?;
        if !transition_review_facts_equal(&proof.review, &next_review) {
            return Err(NormalFinalizationErrorV3::ForbiddenDelta);
        }
        let verified = analyze_descriptor_ownership_v2(&next_view, &proof.descriptor)
            .map_err(NormalFinalizationErrorV3::ExistingSignatureVerification)?;
        advance_verified_counts(
            verified_counts.as_mut_vec().as_mut_slice(),
            &verified.verified_inputs,
            signature.input_index,
        )?;
        current = next_owner;
    }
    drop(planned);

    let complete_view =
        parse(current.as_slice(), source).map_err(|_| NormalFinalizationErrorV3::ParseFailed)?;
    let complete = analyze_descriptor_ownership_v2(&complete_view, &proof.descriptor)
        .map_err(NormalFinalizationErrorV3::ExistingSignatureVerification)?;
    if complete.aggregate_status != VerifiedAggregateStatus::VerifyAndExportOnly
        || complete
            .verified_inputs
            .iter()
            .any(|input| input.verified_signature_count != THRESHOLD)
    {
        return Err(NormalFinalizationErrorV3::ThresholdIncomplete);
    }
    drop(complete_view);
    finalize_complete(
        current,
        source,
        &proof.descriptor,
        &proof.review,
        proof.review_hash(),
    )
}

fn plan_submitted_signatures(
    view: &PsbtView<'_>,
    plans: &[NormalInputSigningPlanV3],
    role_a: &[NormalSubmittedSignatureV3<'_>],
    role_b: &[NormalSubmittedSignatureV3<'_>],
) -> Result<wipe::WipingValueVec<PlannedSignature>, NormalFinalizationErrorV3> {
    let mut by_input: Vec<[Option<&[u8]>; ROLE_COUNT]> = Vec::new();
    by_input
        .try_reserve_exact(plans.len())
        .map_err(|_| NormalFinalizationErrorV3::AllocationFailed)?;
    for _ in plans {
        by_input.push([None, None]);
    }
    for (role, supplied) in [role_a, role_b].into_iter().enumerate() {
        for signature in supplied {
            let input_index = usize::try_from(signature.input_index)
                .map_err(|_| NormalFinalizationErrorV3::InputOutOfRange)?;
            let slot = by_input
                .get_mut(input_index)
                .and_then(|roles| roles.get_mut(role))
                .ok_or(NormalFinalizationErrorV3::InputOutOfRange)?;
            if slot.replace(signature.der_signature).is_some() {
                return Err(NormalFinalizationErrorV3::DuplicateRole);
            }
        }
    }
    let mut planned = wipe::WipingValueVec::new();
    planned
        .try_reserve_exact(role_a.len().saturating_add(role_b.len()))
        .map_err(|_| NormalFinalizationErrorV3::AllocationFailed)?;
    for (position, (plan, supplied)) in plans.iter().zip(&by_input).enumerate() {
        if usize::try_from(plan.input_index()) != Ok(position) {
            return Err(NormalFinalizationErrorV3::InternalInvariant);
        }
        let occupied = plan.existing_role_signatures();
        let keys = plan.role_public_keys();
        let digest = plan.digest();
        if occupied.iter().all(|present| *present) && supplied.iter().any(Option::is_some) {
            return Err(NormalFinalizationErrorV3::ThresholdAlreadyMet);
        }
        for (role, ((is_occupied, signature), key)) in occupied
            .into_iter()
            .zip(supplied.iter().copied())
            .zip(keys.iter())
            .enumerate()
        {
            match (is_occupied, signature) {
                (true, None) => {}
                (true, Some(_)) => return Err(NormalFinalizationErrorV3::SignatureConflict),
                (false, None) => return Err(NormalFinalizationErrorV3::ThresholdIncomplete),
                (false, Some(der)) => {
                    verify_der_signature(der, digest, key).map_err(|_| {
                        if role == 0 {
                            NormalFinalizationErrorV3::InvalidRoleASignature
                        } else {
                            NormalFinalizationErrorV3::InvalidMockSignature
                        }
                    })?;
                    if signature_matches_existing_or_planned(view, planned.as_slice(), der)? {
                        return Err(NormalFinalizationErrorV3::DuplicateSignature);
                    }
                    let mut copied = Vec::new();
                    copied
                        .try_reserve_exact(der.len())
                        .map_err(|_| NormalFinalizationErrorV3::AllocationFailed)?;
                    copied.extend_from_slice(der);
                    planned.push(PlannedSignature {
                        input_index: position,
                        public_key: *key,
                        der_signature: copied,
                    });
                }
            }
        }
    }
    Ok(planned)
}

fn verify_der_signature(der: &[u8], digest: &[u8; 32], key: &[u8; 33]) -> Result<(), ()> {
    let public_key = qk_secp::pubkey_parse_compressed(key).map_err(|_| ())?;
    let signature = qk_secp::signature_parse_der(der).map_err(|_| ())?;
    let mut canonical = wipe::ByteArray::<DER_CAPACITY>::new([0; DER_CAPACITY]);
    let len =
        qk_secp::signature_serialize_der(&signature, canonical.as_mut_array()).map_err(|_| ())?;
    if canonical.as_slice().get(..len) != Some(der) {
        return Err(());
    }
    qk_secp::ecdsa_verify(&signature, digest, &public_key).map_err(|_| ())
}

fn signature_matches_existing_or_planned(
    view: &PsbtView<'_>,
    planned: &[PlannedSignature],
    candidate: &[u8],
) -> Result<bool, NormalFinalizationErrorV3> {
    for input_index in 0..view.input_map_count() {
        for record in view
            .input_records(input_index)
            .ok_or(NormalFinalizationErrorV3::InternalInvariant)?
        {
            if record.key_type == 0x02
                && record.value.last() == Some(&SIGHASH_ALL)
                && record.value.get(..record.value.len().saturating_sub(1)) == Some(candidate)
            {
                return Ok(true);
            }
        }
    }
    Ok(planned.iter().any(|prior| prior.der_signature == candidate))
}

fn insert_partial_signature(
    view: &PsbtView<'_>,
    bytes: &[u8],
    source: InputSource,
    input_index: usize,
    public_key: &[u8; 33],
    der_signature: &[u8],
) -> Result<(Vec<u8>, usize, usize), NormalFinalizationErrorV3> {
    let span = view
        .input_map_span(input_index)
        .ok_or(NormalFinalizationErrorV3::InputOutOfRange)?;
    let records = view
        .input_records(input_index)
        .ok_or(NormalFinalizationErrorV3::InternalInvariant)?;
    let mut insertion_offset = span.start;
    for record in records {
        let ordered_after = record.key_type > 0x02
            || (record.key_type == 0x02 && record.key_data > public_key.as_slice());
        if ordered_after {
            break;
        }
        insertion_offset = record.value_span.end;
    }
    if insertion_offset >= span.end || bytes.get(insertion_offset).is_none() {
        return Err(NormalFinalizationErrorV3::InternalInvariant);
    }
    let value_len = der_signature
        .len()
        .checked_add(1)
        .ok_or(NormalFinalizationErrorV3::LengthOverflow)?;
    let record_len = 1usize
        .checked_add(34)
        .and_then(|value| value.checked_add(1))
        .and_then(|value| value.checked_add(value_len))
        .ok_or(NormalFinalizationErrorV3::LengthOverflow)?;
    let next_len = bytes
        .len()
        .checked_add(record_len)
        .ok_or(NormalFinalizationErrorV3::ArtifactTooLarge)?;
    if next_len > source.max_bytes() {
        return Err(NormalFinalizationErrorV3::ArtifactTooLarge);
    }
    let mut next = Vec::new();
    next.try_reserve_exact(next_len)
        .map_err(|_| NormalFinalizationErrorV3::AllocationFailed)?;
    append_slice(
        &mut next,
        bytes
            .get(..insertion_offset)
            .ok_or(NormalFinalizationErrorV3::InternalInvariant)?,
    );
    next.push(34);
    next.push(0x02);
    next.extend_from_slice(public_key);
    next.push(u8::try_from(value_len).map_err(|_| NormalFinalizationErrorV3::InternalInvariant)?);
    next.extend_from_slice(der_signature);
    next.push(SIGHASH_ALL);
    append_slice(
        &mut next,
        bytes
            .get(insertion_offset..)
            .ok_or(NormalFinalizationErrorV3::InternalInvariant)?,
    );
    if next.len() != next_len {
        wipe::byte_vec(&mut next);
        return Err(NormalFinalizationErrorV3::InternalInvariant);
    }
    Ok((next, insertion_offset, record_len))
}

fn exact_insert_delta(previous: &[u8], next: &[u8], offset: usize, inserted: usize) -> bool {
    let Some(suffix) = offset.checked_add(inserted) else {
        return false;
    };
    next.get(..offset) == previous.get(..offset)
        && next.get(suffix..) == previous.get(offset..)
        && next.len() == previous.len().saturating_add(inserted)
}

fn advance_verified_counts(
    previous: &mut [u8],
    next: &[VerifiedInputFacts],
    changed_input: usize,
) -> Result<(), NormalFinalizationErrorV3> {
    if previous.len() != next.len() {
        return Err(NormalFinalizationErrorV3::ForbiddenDelta);
    }
    for (index, (before, after)) in previous.iter_mut().zip(next).enumerate() {
        let expected = if index == changed_input {
            before
                .checked_add(1)
                .ok_or(NormalFinalizationErrorV3::InternalInvariant)?
        } else {
            *before
        };
        let actual = u8::try_from(after.verified_signature_count)
            .map_err(|_| NormalFinalizationErrorV3::InternalInvariant)?;
        if actual != expected {
            return Err(NormalFinalizationErrorV3::ForbiddenDelta);
        }
        *before = actual;
    }
    Ok(())
}

fn transition_review_facts_equal(left: &ReviewV3, right: &ReviewV3) -> bool {
    left.context() == right.context()
        && left.wallet_id() == right.wallet_id()
        && left.origin_fingerprints() == right.origin_fingerprints()
        && left.fee_policy_identifier() == right.fee_policy_identifier()
        && left.unsigned_tx_bytes() == right.unsigned_tx_bytes()
        && left.version() == right.version()
        && left.locktime() == right.locktime()
        && left.inputs() == right.inputs()
        && left.outputs() == right.outputs()
        && left.total_input_amount() == right.total_input_amount()
        && left.total_output_amount() == right.total_output_amount()
        && left.fee() == right.fee()
        && left.fee_policy() == right.fee_policy()
}

struct InputShape {
    witness_script: [u8; WITNESS_SCRIPT_BYTES],
}

impl Drop for InputShape {
    fn drop(&mut self) {
        wipe::bytes(&mut self.witness_script);
    }
}

struct WitnessParts<'a> {
    first_signature: &'a [u8],
    second_signature: &'a [u8],
    witness_script: [u8; WITNESS_SCRIPT_BYTES],
    encoded_len: usize,
}

impl Drop for WitnessParts<'_> {
    fn drop(&mut self) {
        wipe::bytes(&mut self.witness_script);
    }
}

fn finalize_complete(
    capability: OwnedBytes,
    source: InputSource,
    descriptor: &DescriptorPairV2,
    bound_review: &ReviewV3,
    bound_hash: [u8; 32],
) -> Result<FinalizedNormalV3, NormalFinalizationErrorV3> {
    let view = parse(capability.as_slice(), source)
        .map_err(|_| NormalFinalizationErrorV3::CapabilityParse)?;
    let canonical = OwnedBytes::take(
        canonical_serialize(&view).map_err(NormalFinalizationErrorV3::SerializeFailed)?,
    );
    if canonical.as_slice() != capability.as_slice() {
        return Err(NormalFinalizationErrorV3::NonCanonicalOutput);
    }
    let candidate_review = build_review_v3(
        &view,
        descriptor,
        ReviewContext {
            network: ReviewNetwork::BitcoinMainnet,
            input_source: source,
        },
    )
    .map_err(|_| NormalFinalizationErrorV3::ReviewFactsMismatch)?;
    if !transition_review_facts_equal(bound_review, &candidate_review) {
        return Err(NormalFinalizationErrorV3::ReviewFactsMismatch);
    }
    // The approved hash is the immutable pre-insertion commitment. A
    // post-insertion ReviewV3 has a mechanically different S0 identity and is
    // compared only through the exact permitted transition facts above.
    let verified = analyze_descriptor_ownership_v2(&view, descriptor)
        .map_err(NormalFinalizationErrorV3::ExistingSignatureVerification)?;
    if verified.aggregate_status != VerifiedAggregateStatus::VerifyAndExportOnly
        || verified
            .verified_inputs
            .iter()
            .any(|input| input.verified_signature_count != THRESHOLD)
    {
        return Err(NormalFinalizationErrorV3::ThresholdIncomplete);
    }

    let shapes = collect_input_shapes(&view, descriptor, bound_review)?;
    let witnesses = select_witnesses(&view, &shapes)?;
    let finalized_psbt = transform_psbt(&view, capability.as_slice(), &witnesses, source)?;
    let finalized_view = parse(finalized_psbt.as_slice(), source)
        .map_err(|_| NormalFinalizationErrorV3::FinalizedPsbtReparse)?;
    let final_canonical = OwnedBytes::take(
        canonical_serialize(&finalized_view).map_err(NormalFinalizationErrorV3::SerializeFailed)?,
    );
    if final_canonical.as_slice() != finalized_psbt.as_slice() {
        return Err(NormalFinalizationErrorV3::FinalizedPsbtNonCanonical);
    }
    if finalized_view.unsigned_tx_bytes() != view.unsigned_tx_bytes()
        || !allowed_finalized_delta(&view, &finalized_view, &witnesses)?
    {
        return Err(NormalFinalizationErrorV3::ForbiddenDelta);
    }
    let raw_transaction = extract_raw_transaction(view.unsigned_tx_bytes(), &witnesses)?;
    let parsed_witnesses = parse_and_rebind_raw(
        raw_transaction.as_slice(),
        view.unsigned_tx_bytes(),
        &finalized_view,
    )?;
    verify_parsed_witnesses(&parsed_witnesses, &witnesses, bound_review, descriptor)?;
    rebind_final_witness_records(&parsed_witnesses, &finalized_view)?;

    let finalized_psbt_sha256 = crate::sha256::sha256(&[finalized_psbt.as_slice()])
        .map_err(|_| NormalFinalizationErrorV3::HashFailed)?;
    let raw_transaction_sha256 = crate::sha256::sha256(&[raw_transaction.as_slice()])
        .map_err(|_| NormalFinalizationErrorV3::HashFailed)?;
    let mut txid = wipe::ByteArray::new(sha256d(&[view.unsigned_tx_bytes()])?);
    let mut wtxid = wipe::ByteArray::new(sha256d(&[raw_transaction.as_slice()])?);
    Ok(FinalizedNormalV3 {
        finalized_psbt: crate::TransactionMaterialVec::from_vec(finalized_psbt.into_vec()),
        raw_transaction: crate::TransactionMaterialVec::from_vec(raw_transaction.into_vec()),
        finalized_psbt_sha256: wipe::ByteArray::new(finalized_psbt_sha256),
        raw_transaction_sha256: wipe::ByteArray::new(raw_transaction_sha256),
        txid: wipe::ByteArray::new(txid.take()),
        wtxid: wipe::ByteArray::new(wtxid.take()),
        review_hash: wipe::ByteArray::new(bound_hash),
        wallet_id: wipe::ByteArray::new(bound_review.wallet_id()),
    })
}

fn collect_input_shapes(
    view: &PsbtView<'_>,
    descriptor: &DescriptorPairV2,
    review: &ReviewV3,
) -> Result<wipe::WipingValueVec<InputShape>, NormalFinalizationErrorV3> {
    if view.input_map_count() != review.input_count() {
        return Err(NormalFinalizationErrorV3::InternalInvariant);
    }
    let mut shapes = wipe::WipingValueVec::new();
    shapes
        .try_reserve_exact(view.input_map_count())
        .map_err(|_| NormalFinalizationErrorV3::AllocationFailed)?;
    for input_index in 0..view.input_map_count() {
        let review_input = review
            .inputs()
            .get(input_index)
            .ok_or(NormalFinalizationErrorV3::InternalInvariant)?;
        let derived = WipingDerivedScript(derive_script(
            descriptor,
            review_input.branch(),
            review_input.child_index(),
        )?);
        let mut derivations = 0usize;
        let mut partials = 0usize;
        let mut witness_script = None;
        for record in view
            .input_records(input_index)
            .ok_or(NormalFinalizationErrorV3::InternalInvariant)?
        {
            match record.key_type {
                0x02 => {
                    partials = partials
                        .checked_add(1)
                        .ok_or(NormalFinalizationErrorV3::LengthOverflow)?;
                }
                0x05 => {
                    if !record.key_data.is_empty() || witness_script.replace(record.value).is_some()
                    {
                        return Err(NormalFinalizationErrorV3::WitnessShapeMismatch);
                    }
                }
                0x06 => {
                    derivations = derivations
                        .checked_add(1)
                        .ok_or(NormalFinalizationErrorV3::LengthOverflow)?;
                }
                0x07 | 0x08 => return Err(NormalFinalizationErrorV3::WitnessShapeMismatch),
                _ => {}
            }
        }
        if derivations != ROLE_COUNT || partials != THRESHOLD {
            return Err(NormalFinalizationErrorV3::WitnessShapeMismatch);
        }
        if witness_script.is_some_and(|value| value != derived.0.witness_script.as_slice()) {
            return Err(NormalFinalizationErrorV3::WitnessShapeMismatch);
        }
        shapes.push(InputShape {
            witness_script: derived.0.witness_script,
        });
    }
    Ok(shapes)
}

fn select_witnesses<'a>(
    view: &PsbtView<'a>,
    shapes: &[InputShape],
) -> Result<wipe::WipingValueVec<WitnessParts<'a>>, NormalFinalizationErrorV3> {
    if shapes.len() != view.input_map_count() {
        return Err(NormalFinalizationErrorV3::InternalInvariant);
    }
    let mut witnesses = wipe::WipingValueVec::new();
    witnesses
        .try_reserve_exact(view.input_map_count())
        .map_err(|_| NormalFinalizationErrorV3::AllocationFailed)?;
    for input_index in 0..view.input_map_count() {
        let shape = shapes
            .get(input_index)
            .ok_or(NormalFinalizationErrorV3::InternalInvariant)?;
        let keys = script_keys(&shape.witness_script)?;
        let mut partials: [Option<Record<'a>>; ROLE_COUNT] = [None, None];
        let mut partial_count = 0usize;
        for record in view
            .input_records(input_index)
            .ok_or(NormalFinalizationErrorV3::InternalInvariant)?
        {
            if record.key_type == 0x02 {
                let slot = partials
                    .get_mut(partial_count)
                    .ok_or(NormalFinalizationErrorV3::WitnessShapeMismatch)?;
                *slot = Some(record);
                partial_count = partial_count
                    .checked_add(1)
                    .ok_or(NormalFinalizationErrorV3::LengthOverflow)?;
            }
        }
        let [first, second] = partials;
        let first = first.ok_or(NormalFinalizationErrorV3::WitnessShapeMismatch)?;
        let second = second.ok_or(NormalFinalizationErrorV3::WitnessShapeMismatch)?;
        let [first_key, second_key] = keys;
        if first.key_data != first_key.as_slice() || second.key_data != second_key.as_slice() {
            if first.key_data == second_key.as_slice() && second.key_data == first_key.as_slice() {
                return Err(NormalFinalizationErrorV3::WitnessOrderMismatch);
            }
            return Err(NormalFinalizationErrorV3::WitnessShapeMismatch);
        }
        let encoded_len = witness_encoded_len(first.value, second.value, &shape.witness_script)?;
        if encoded_len > MAX_WITNESS_BYTES_PER_INPUT {
            return Err(NormalFinalizationErrorV3::ArtifactTooLarge);
        }
        witnesses.push(WitnessParts {
            first_signature: first.value,
            second_signature: second.value,
            witness_script: shape.witness_script,
            encoded_len,
        });
    }
    Ok(witnesses)
}

fn script_keys(
    script: &[u8; WITNESS_SCRIPT_BYTES],
) -> Result<[[u8; 33]; ROLE_COUNT], NormalFinalizationErrorV3> {
    if script.first() != Some(&0x52)
        || script.get(1) != Some(&0x21)
        || script.get(35) != Some(&0x21)
        || script.get(69) != Some(&0x52)
        || script.get(70) != Some(&0xae)
    {
        return Err(NormalFinalizationErrorV3::WitnessShapeMismatch);
    }
    let first: [u8; 33] = script
        .get(2..35)
        .ok_or(NormalFinalizationErrorV3::WitnessShapeMismatch)?
        .try_into()
        .map_err(|_| NormalFinalizationErrorV3::WitnessShapeMismatch)?;
    let second: [u8; 33] = script
        .get(36..69)
        .ok_or(NormalFinalizationErrorV3::WitnessShapeMismatch)?
        .try_into()
        .map_err(|_| NormalFinalizationErrorV3::WitnessShapeMismatch)?;
    if !matches!(first.first().copied(), Some(0x02 | 0x03))
        || !matches!(second.first().copied(), Some(0x02 | 0x03))
        || first >= second
    {
        return Err(NormalFinalizationErrorV3::WitnessShapeMismatch);
    }
    Ok([first, second])
}

fn witness_encoded_len(
    first: &[u8],
    second: &[u8],
    script: &[u8],
) -> Result<usize, NormalFinalizationErrorV3> {
    1usize
        .checked_add(1)
        .and_then(|value| value.checked_add(compact_size_len(first.len())))
        .and_then(|value| value.checked_add(first.len()))
        .and_then(|value| value.checked_add(compact_size_len(second.len())))
        .and_then(|value| value.checked_add(second.len()))
        .and_then(|value| value.checked_add(compact_size_len(script.len())))
        .and_then(|value| value.checked_add(script.len()))
        .ok_or(NormalFinalizationErrorV3::LengthOverflow)
}

fn transform_psbt(
    view: &PsbtView<'_>,
    bytes: &[u8],
    witnesses: &[WitnessParts<'_>],
    source: InputSource,
) -> Result<OwnedBytes, NormalFinalizationErrorV3> {
    if witnesses.len() != view.input_map_count() {
        return Err(NormalFinalizationErrorV3::InternalInvariant);
    }
    let mut final_len = PSBT_MAGIC_BYTES
        .checked_add(view.global_map_span().len())
        .ok_or(NormalFinalizationErrorV3::LengthOverflow)?;
    for (input_index, witness) in witnesses.iter().enumerate() {
        let span = view
            .input_map_span(input_index)
            .ok_or(NormalFinalizationErrorV3::InternalInvariant)?;
        let mut removed = 0usize;
        let mut record_start = span.start;
        for record in view
            .input_records(input_index)
            .ok_or(NormalFinalizationErrorV3::InternalInvariant)?
        {
            let encoded_len = record
                .value_span
                .end
                .checked_sub(record_start)
                .ok_or(NormalFinalizationErrorV3::InternalInvariant)?;
            if (0x02..=0x06).contains(&record.key_type) {
                removed = removed
                    .checked_add(encoded_len)
                    .ok_or(NormalFinalizationErrorV3::LengthOverflow)?;
            }
            record_start = record.value_span.end;
        }
        if record_start.checked_add(1) != Some(span.end) {
            return Err(NormalFinalizationErrorV3::InternalInvariant);
        }
        let map_len = span
            .len()
            .checked_sub(removed)
            .and_then(|value| {
                value.checked_add(final_witness_record_len(witness.encoded_len).ok()?)
            })
            .ok_or(NormalFinalizationErrorV3::LengthOverflow)?;
        final_len = final_len
            .checked_add(map_len)
            .ok_or(NormalFinalizationErrorV3::LengthOverflow)?;
    }
    for output_index in 0..view.output_map_count() {
        final_len = final_len
            .checked_add(
                view.output_map_span(output_index)
                    .ok_or(NormalFinalizationErrorV3::InternalInvariant)?
                    .len(),
            )
            .ok_or(NormalFinalizationErrorV3::LengthOverflow)?;
    }
    let minimum_shrink = view
        .input_map_count()
        .checked_mul(MIN_FINALIZED_PSBT_SHRINK_PER_INPUT)
        .ok_or(NormalFinalizationErrorV3::LengthOverflow)?;
    let largest_allowed = bytes
        .len()
        .checked_sub(minimum_shrink)
        .ok_or(NormalFinalizationErrorV3::ForbiddenDelta)?;
    if final_len > largest_allowed {
        return Err(NormalFinalizationErrorV3::ForbiddenDelta);
    }
    if final_len > source.max_bytes() {
        return Err(NormalFinalizationErrorV3::ArtifactTooLarge);
    }
    let mut finalized = OwnedBytes::new();
    finalized
        .as_mut_vec()
        .try_reserve_exact(final_len)
        .map_err(|_| NormalFinalizationErrorV3::AllocationFailed)?;
    append_slice(
        finalized.as_mut_vec(),
        bytes
            .get(..PSBT_MAGIC_BYTES)
            .ok_or(NormalFinalizationErrorV3::InternalInvariant)?,
    );
    append_span(finalized.as_mut_vec(), bytes, view.global_map_span())?;
    for (input_index, witness) in witnesses.iter().enumerate() {
        emit_finalized_input(finalized.as_mut_vec(), view, bytes, input_index, witness)?;
    }
    for output_index in 0..view.output_map_count() {
        append_span(
            finalized.as_mut_vec(),
            bytes,
            view.output_map_span(output_index)
                .ok_or(NormalFinalizationErrorV3::InternalInvariant)?,
        )?;
    }
    if finalized.as_slice().len() != final_len {
        return Err(NormalFinalizationErrorV3::InternalInvariant);
    }
    Ok(finalized)
}

fn emit_finalized_input(
    output: &mut Vec<u8>,
    view: &PsbtView<'_>,
    bytes: &[u8],
    input_index: usize,
    witness: &WitnessParts<'_>,
) -> Result<(), NormalFinalizationErrorV3> {
    let span = view
        .input_map_span(input_index)
        .ok_or(NormalFinalizationErrorV3::InternalInvariant)?;
    let mut record_start = span.start;
    let mut emitted_final = false;
    for record in view
        .input_records(input_index)
        .ok_or(NormalFinalizationErrorV3::InternalInvariant)?
    {
        if !emitted_final && record.key_type > 0x08 {
            emit_final_witness_record(output, witness)?;
            emitted_final = true;
        }
        if !(0x02..=0x06).contains(&record.key_type) {
            append_slice(
                output,
                bytes
                    .get(record_start..record.value_span.end)
                    .ok_or(NormalFinalizationErrorV3::InternalInvariant)?,
            );
        }
        record_start = record.value_span.end;
    }
    if !emitted_final {
        emit_final_witness_record(output, witness)?;
    }
    if record_start.checked_add(1) != Some(span.end) || bytes.get(record_start) != Some(&0x00) {
        return Err(NormalFinalizationErrorV3::InternalInvariant);
    }
    output.push(0x00);
    Ok(())
}

fn final_witness_record_len(witness_len: usize) -> Result<usize, NormalFinalizationErrorV3> {
    2usize
        .checked_add(compact_size_len(witness_len))
        .and_then(|value| value.checked_add(witness_len))
        .ok_or(NormalFinalizationErrorV3::LengthOverflow)
}

fn emit_final_witness_record(
    output: &mut Vec<u8>,
    witness: &WitnessParts<'_>,
) -> Result<(), NormalFinalizationErrorV3> {
    output.extend_from_slice(&[0x01, 0x08]);
    write_compact_size(output, witness.encoded_len)?;
    emit_witness(output, witness)
}

fn emit_witness(
    output: &mut Vec<u8>,
    witness: &WitnessParts<'_>,
) -> Result<(), NormalFinalizationErrorV3> {
    let before = output.len();
    output.extend_from_slice(&[0x04, 0x00]);
    write_compact_size(output, witness.first_signature.len())?;
    append_slice(output, witness.first_signature);
    write_compact_size(output, witness.second_signature.len())?;
    append_slice(output, witness.second_signature);
    write_compact_size(output, witness.witness_script.len())?;
    append_slice(output, &witness.witness_script);
    if output.len().checked_sub(before) != Some(witness.encoded_len) {
        return Err(NormalFinalizationErrorV3::InternalInvariant);
    }
    Ok(())
}

fn allowed_finalized_delta(
    before: &PsbtView<'_>,
    after: &PsbtView<'_>,
    witnesses: &[WitnessParts<'_>],
) -> Result<bool, NormalFinalizationErrorV3> {
    if before.input_map_count() != after.input_map_count()
        || before.output_map_count() != after.output_map_count()
        || witnesses.len() != before.input_map_count()
        || before.global_map_span().slice(before.buffer())
            != after.global_map_span().slice(after.buffer())
    {
        return Ok(false);
    }
    for output_index in 0..before.output_map_count() {
        if before
            .output_map_span(output_index)
            .and_then(|span| span.slice(before.buffer()))
            != after
                .output_map_span(output_index)
                .and_then(|span| span.slice(after.buffer()))
        {
            return Ok(false);
        }
    }
    for (input_index, witness) in witnesses.iter().enumerate() {
        let mut preserved = match before.input_records(input_index) {
            Some(records) => records.filter(|record| {
                !(0x02..=0x06).contains(&record.key_type)
                    && record.key_type != 0x07
                    && record.key_type != 0x08
            }),
            None => return Ok(false),
        };
        let Some(after_records) = after.input_records(input_index) else {
            return Ok(false);
        };
        let mut final_seen = false;
        for record in after_records {
            if record.key_type == 0x08 {
                if final_seen || !record.key_data.is_empty() {
                    return Ok(false);
                }
                let mut expected = OwnedBytes::new();
                expected
                    .as_mut_vec()
                    .try_reserve_exact(witness.encoded_len)
                    .map_err(|_| NormalFinalizationErrorV3::AllocationFailed)?;
                emit_witness(expected.as_mut_vec(), witness)?;
                if record.value != expected.as_slice() {
                    return Ok(false);
                }
                final_seen = true;
            } else {
                if (0x02..=0x07).contains(&record.key_type) {
                    return Ok(false);
                }
                let Some(expected) = preserved.next() else {
                    return Ok(false);
                };
                if record.full_key != expected.full_key || record.value != expected.value {
                    return Ok(false);
                }
            }
        }
        if !final_seen || preserved.next().is_some() {
            return Ok(false);
        }
    }
    Ok(true)
}

fn extract_raw_transaction(
    base: &[u8],
    witnesses: &[WitnessParts<'_>],
) -> Result<OwnedBytes, NormalFinalizationErrorV3> {
    if base.len() > MAX_UNSIGNED_TRANSACTION_BYTES || base.len() < 8 {
        return Err(NormalFinalizationErrorV3::ArtifactTooLarge);
    }
    let witness_total = witnesses.iter().try_fold(0usize, |total, witness| {
        total
            .checked_add(witness.encoded_len)
            .ok_or(NormalFinalizationErrorV3::LengthOverflow)
    })?;
    let raw_len = base
        .len()
        .checked_add(2)
        .and_then(|value| value.checked_add(witness_total))
        .ok_or(NormalFinalizationErrorV3::LengthOverflow)?;
    if raw_len > MAX_RAW_TRANSACTION_BYTES {
        return Err(NormalFinalizationErrorV3::ArtifactTooLarge);
    }
    let locktime_start = base
        .len()
        .checked_sub(4)
        .ok_or(NormalFinalizationErrorV3::InternalInvariant)?;
    let mut raw = OwnedBytes::new();
    raw.as_mut_vec()
        .try_reserve_exact(raw_len)
        .map_err(|_| NormalFinalizationErrorV3::AllocationFailed)?;
    append_slice(
        raw.as_mut_vec(),
        base.get(..4)
            .ok_or(NormalFinalizationErrorV3::InternalInvariant)?,
    );
    raw.as_mut_vec().extend_from_slice(&[0x00, 0x01]);
    append_slice(
        raw.as_mut_vec(),
        base.get(4..locktime_start)
            .ok_or(NormalFinalizationErrorV3::InternalInvariant)?,
    );
    for witness in witnesses {
        emit_witness(raw.as_mut_vec(), witness)?;
    }
    append_slice(
        raw.as_mut_vec(),
        base.get(locktime_start..)
            .ok_or(NormalFinalizationErrorV3::InternalInvariant)?,
    );
    if raw.as_slice().len() != raw_len {
        return Err(NormalFinalizationErrorV3::InternalInvariant);
    }
    Ok(raw)
}

#[derive(Clone, Copy)]
struct ParsedRawWitness<'a> {
    encoded: &'a [u8],
    item_count: u64,
    items: [Option<&'a [u8]>; 4],
}

fn parse_and_rebind_raw<'a>(
    raw: &'a [u8],
    base: &[u8],
    finalized_view: &PsbtView<'_>,
) -> Result<Vec<ParsedRawWitness<'a>>, NormalFinalizationErrorV3> {
    let mut cursor = RawCursor::new(raw);
    let mut stripped = OwnedBytes::new();
    stripped
        .as_mut_vec()
        .try_reserve_exact(base.len())
        .map_err(|_| NormalFinalizationErrorV3::AllocationFailed)?;
    append_slice(stripped.as_mut_vec(), cursor.take(4)?);
    if cursor.take(2)? != [0x00, 0x01].as_slice() {
        return Err(NormalFinalizationErrorV3::RawTransactionReparse);
    }
    let (input_count, input_count_bytes) = cursor.compact_size()?;
    let input_count = usize::try_from(input_count)
        .map_err(|_| NormalFinalizationErrorV3::RawTransactionReparse)?;
    if input_count == 0 || input_count != finalized_view.input_map_count() {
        return Err(NormalFinalizationErrorV3::RawTransactionReparse);
    }
    append_slice(stripped.as_mut_vec(), input_count_bytes);
    for _ in 0..input_count {
        append_slice(stripped.as_mut_vec(), cursor.take(36)?);
        let (script_len, script_len_bytes) = cursor.compact_size()?;
        if script_len != 0 {
            return Err(NormalFinalizationErrorV3::RawTransactionReparse);
        }
        append_slice(stripped.as_mut_vec(), script_len_bytes);
        append_slice(stripped.as_mut_vec(), cursor.take(4)?);
    }
    let (output_count, output_count_bytes) = cursor.compact_size()?;
    let output_count = usize::try_from(output_count)
        .map_err(|_| NormalFinalizationErrorV3::RawTransactionReparse)?;
    if output_count == 0 || output_count != finalized_view.output_map_count() {
        return Err(NormalFinalizationErrorV3::RawTransactionReparse);
    }
    append_slice(stripped.as_mut_vec(), output_count_bytes);
    for _ in 0..output_count {
        append_slice(stripped.as_mut_vec(), cursor.take(8)?);
        let (script_len, script_len_bytes) = cursor.compact_size()?;
        let script_len = usize::try_from(script_len)
            .map_err(|_| NormalFinalizationErrorV3::RawTransactionReparse)?;
        append_slice(stripped.as_mut_vec(), script_len_bytes);
        append_slice(stripped.as_mut_vec(), cursor.take(script_len)?);
    }

    let mut parsed = Vec::new();
    parsed
        .try_reserve_exact(input_count)
        .map_err(|_| NormalFinalizationErrorV3::AllocationFailed)?;
    for _ in 0..input_count {
        let witness_start = cursor.position();
        let (item_count, _) = cursor.compact_size()?;
        let mut items: [Option<&[u8]>; 4] = [None, None, None, None];
        let mut item_index = 0u64;
        while item_index < item_count {
            let (item_len, _) = cursor.compact_size()?;
            let item_len = usize::try_from(item_len)
                .map_err(|_| NormalFinalizationErrorV3::RawTransactionReparse)?;
            let item = cursor.take(item_len)?;
            if item_index < 4 {
                let index = usize::try_from(item_index)
                    .map_err(|_| NormalFinalizationErrorV3::RawTransactionReparse)?;
                *items
                    .get_mut(index)
                    .ok_or(NormalFinalizationErrorV3::InternalInvariant)? = Some(item);
            }
            item_index = item_index
                .checked_add(1)
                .ok_or(NormalFinalizationErrorV3::RawTransactionReparse)?;
        }
        let encoded = raw
            .get(witness_start..cursor.position())
            .ok_or(NormalFinalizationErrorV3::RawTransactionReparse)?;
        parsed.push(ParsedRawWitness {
            encoded,
            item_count,
            items,
        });
    }
    append_slice(stripped.as_mut_vec(), cursor.take(4)?);
    if !cursor.at_end() || stripped.as_slice() != base {
        return Err(if cursor.at_end() {
            NormalFinalizationErrorV3::BaseTransactionMismatch
        } else {
            NormalFinalizationErrorV3::RawTransactionReparse
        });
    }
    Ok(parsed)
}

fn rebind_final_witness_records(
    parsed: &[ParsedRawWitness<'_>],
    finalized_view: &PsbtView<'_>,
) -> Result<(), NormalFinalizationErrorV3> {
    if parsed.len() != finalized_view.input_map_count() {
        return Err(NormalFinalizationErrorV3::InternalInvariant);
    }
    for (input_index, witness) in parsed.iter().enumerate() {
        let final_witness = finalized_view
            .input_records(input_index)
            .ok_or(NormalFinalizationErrorV3::InternalInvariant)?
            .find(|record| record.key_type == 0x08)
            .ok_or(NormalFinalizationErrorV3::WitnessMismatch)?;
        if witness.encoded != final_witness.value {
            return Err(NormalFinalizationErrorV3::WitnessMismatch);
        }
    }
    Ok(())
}

fn verify_parsed_witnesses(
    parsed: &[ParsedRawWitness<'_>],
    expected: &[WitnessParts<'_>],
    review: &ReviewV3,
    descriptor: &DescriptorPairV2,
) -> Result<(), NormalFinalizationErrorV3> {
    if parsed.len() != expected.len() || parsed.len() != review.input_count() {
        return Err(NormalFinalizationErrorV3::InternalInvariant);
    }
    let digests = compute_digests(review, descriptor)?;
    for (input_index, (actual, expected_witness)) in parsed.iter().zip(expected).enumerate() {
        let [dummy, first, second, script] = actual.items;
        if actual.item_count != 4 || !matches!(dummy, Some(value) if value.is_empty()) {
            return Err(NormalFinalizationErrorV3::WitnessMismatch);
        }
        let first = first.ok_or(NormalFinalizationErrorV3::WitnessMismatch)?;
        let second = second.ok_or(NormalFinalizationErrorV3::WitnessMismatch)?;
        let script = script.ok_or(NormalFinalizationErrorV3::WitnessMismatch)?;
        if first == expected_witness.second_signature && second == expected_witness.first_signature
        {
            return Err(NormalFinalizationErrorV3::WitnessOrderMismatch);
        }
        if first != expected_witness.first_signature
            || second != expected_witness.second_signature
            || script != expected_witness.witness_script.as_slice()
        {
            return Err(NormalFinalizationErrorV3::WitnessMismatch);
        }
        let [first_key, second_key] = script_keys(&expected_witness.witness_script)?;
        let digest = digests
            .get(input_index)
            .ok_or(NormalFinalizationErrorV3::InternalInvariant)?;
        verify_complete_signature(first, digest.as_array(), &first_key)?;
        verify_complete_signature(second, digest.as_array(), &second_key)?;
    }
    Ok(())
}

fn verify_complete_signature(
    complete: &[u8],
    digest: &[u8; 32],
    key: &[u8; 33],
) -> Result<(), NormalFinalizationErrorV3> {
    let (sighash, der) = complete
        .split_last()
        .ok_or(NormalFinalizationErrorV3::FinalSignatureVerificationFailed)?;
    if *sighash != SIGHASH_ALL {
        return Err(NormalFinalizationErrorV3::FinalSignatureVerificationFailed);
    }
    verify_der_signature(der, digest, key)
        .map_err(|_| NormalFinalizationErrorV3::FinalSignatureVerificationFailed)
}

fn sha256d(chunks: &[&[u8]]) -> Result<[u8; 32], NormalFinalizationErrorV3> {
    let mut first = wipe::ByteArray::new(
        crate::sha256::sha256(chunks).map_err(|_| NormalFinalizationErrorV3::HashFailed)?,
    );
    let result = crate::sha256::sha256(&[first.as_slice()])
        .map_err(|_| NormalFinalizationErrorV3::HashFailed)?;
    wipe::bytes(first.as_mut_array());
    Ok(result)
}

struct RawCursor<'a> {
    bytes: &'a [u8],
    position: usize,
}

impl<'a> RawCursor<'a> {
    const fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, position: 0 }
    }

    const fn position(&self) -> usize {
        self.position
    }

    fn take(&mut self, count: usize) -> Result<&'a [u8], NormalFinalizationErrorV3> {
        let end = self
            .position
            .checked_add(count)
            .ok_or(NormalFinalizationErrorV3::RawTransactionReparse)?;
        let value = self
            .bytes
            .get(self.position..end)
            .ok_or(NormalFinalizationErrorV3::RawTransactionReparse)?;
        self.position = end;
        Ok(value)
    }

    fn compact_size(&mut self) -> Result<(u64, &'a [u8]), NormalFinalizationErrorV3> {
        let start = self.position;
        let first = *self
            .take(1)?
            .first()
            .ok_or(NormalFinalizationErrorV3::RawTransactionReparse)?;
        let value = match first {
            0xfd => {
                let value = u64::from(u16::from_le_bytes(
                    self.take(2)?
                        .try_into()
                        .map_err(|_| NormalFinalizationErrorV3::RawTransactionReparse)?,
                ));
                if value < 0xfd {
                    return Err(NormalFinalizationErrorV3::RawTransactionReparse);
                }
                value
            }
            0xfe => {
                let value = u64::from(u32::from_le_bytes(
                    self.take(4)?
                        .try_into()
                        .map_err(|_| NormalFinalizationErrorV3::RawTransactionReparse)?,
                ));
                if value <= 0xffff {
                    return Err(NormalFinalizationErrorV3::RawTransactionReparse);
                }
                value
            }
            0xff => {
                let value = u64::from_le_bytes(
                    self.take(8)?
                        .try_into()
                        .map_err(|_| NormalFinalizationErrorV3::RawTransactionReparse)?,
                );
                if value <= 0xffff_ffff {
                    return Err(NormalFinalizationErrorV3::RawTransactionReparse);
                }
                value
            }
            value => u64::from(value),
        };
        let encoded = self
            .bytes
            .get(start..self.position)
            .ok_or(NormalFinalizationErrorV3::RawTransactionReparse)?;
        Ok((value, encoded))
    }

    fn at_end(&self) -> bool {
        self.position == self.bytes.len()
    }
}

fn compact_size_len(value: usize) -> usize {
    if value < 0xfd {
        1
    } else if value <= 0xffff {
        3
    } else if value <= 0xffff_ffff {
        5
    } else {
        9
    }
}

fn write_compact_size(output: &mut Vec<u8>, value: usize) -> Result<(), NormalFinalizationErrorV3> {
    let value = u64::try_from(value).map_err(|_| NormalFinalizationErrorV3::LengthOverflow)?;
    if value < 0xfd {
        output.push(u8::try_from(value).map_err(|_| NormalFinalizationErrorV3::InternalInvariant)?);
    } else if value <= 0xffff {
        output.push(0xfd);
        output.extend_from_slice(
            &u16::try_from(value)
                .map_err(|_| NormalFinalizationErrorV3::InternalInvariant)?
                .to_le_bytes(),
        );
    } else if value <= 0xffff_ffff {
        output.push(0xfe);
        output.extend_from_slice(
            &u32::try_from(value)
                .map_err(|_| NormalFinalizationErrorV3::InternalInvariant)?
                .to_le_bytes(),
        );
    } else {
        output.push(0xff);
        output.extend_from_slice(&value.to_le_bytes());
    }
    Ok(())
}

fn append_span(
    output: &mut Vec<u8>,
    source: &[u8],
    span: Span,
) -> Result<(), NormalFinalizationErrorV3> {
    append_slice(
        output,
        span.slice(source)
            .ok_or(NormalFinalizationErrorV3::InternalInvariant)?,
    );
    Ok(())
}

fn append_slice(output: &mut Vec<u8>, value: &[u8]) {
    output.extend_from_slice(value);
}

#[cfg(test)]
#[allow(clippy::arithmetic_side_effects)]
mod tests {
    use super::{FinalizedNormalV3, NormalInputSigningPlanV3, OwnedBytes};
    use crate::wipe::{reset_wiped_bytes, wiped_bytes, ByteArray};
    use crate::TransactionMaterialVec;

    #[test]
    fn plan_and_owned_scratch_clear_exact_complete_storage() {
        let plan = NormalInputSigningPlanV3 {
            input_index: 0,
            branch: 0,
            child_index: 0,
            digest: [0x11; 32],
            role_public_keys: [[0x22; 33], [0x33; 33]],
            existing_role_signatures: [false, true],
        };
        reset_wiped_bytes();
        drop(plan);
        assert_eq!(wiped_bytes(), 32 + (2 * 33) + 2);

        let mut bytes = Vec::with_capacity(97);
        bytes.extend_from_slice(&[0x44; 13]);
        reset_wiped_bytes();
        drop(OwnedBytes::take(bytes));
        assert_eq!(wiped_bytes(), 97);
    }

    #[test]
    fn finalized_owner_clears_artifacts_hashes_and_identifiers() {
        let finalized = FinalizedNormalV3 {
            finalized_psbt: TransactionMaterialVec::from_vec(vec![0x11; 19]),
            raw_transaction: TransactionMaterialVec::from_vec(vec![0x22; 23]),
            finalized_psbt_sha256: ByteArray::new([0x33; 32]),
            raw_transaction_sha256: ByteArray::new([0x44; 32]),
            txid: ByteArray::new([0x55; 32]),
            wtxid: ByteArray::new([0x66; 32]),
            review_hash: ByteArray::new([0x77; 32]),
            wallet_id: ByteArray::new([0x88; 32]),
        };
        reset_wiped_bytes();
        drop(finalized);
        assert_eq!(wiped_bytes(), 19 + 23 + (6 * 32));
    }
}
