//! Typed schema-v3 proof that one retained PSBT is an exact Kit sweep.

use crate::bip143::{sighash_all_digest, Bip143InputFacts, Bip143PrecomputeBuilder, SIGHASH_ALL};
use crate::limits;
use crate::review::{ReviewContext, ReviewNetwork};
use crate::wipe;
use crate::{
    analyze_descriptor_ownership_v2, build_review_v3, InputSource, OwnedS0, ParseError,
    RejectCategory, ReviewV3, ReviewV3Error, ReviewV3Hash, ReviewV3OutputOwnership, SemanticError,
    VerifiedInputFacts,
};
use core::fmt;
use qk_descriptor::{
    derive_change_script_v2, derive_receive_script_v2, DerivedScriptV2, DescriptorPairV2,
};

/// One immutable signing plan proven from exact schema-v3 transaction facts.
///
/// Public keys remain in authenticated descriptor role A/B order. The digest
/// is the exact BIP143 SIGHASH_ALL value for this input.
pub struct KitSweepInputSigningPlanV3 {
    input_index: u32,
    branch: u32,
    child_index: u32,
    digest: [u8; 32],
    role_public_keys: [[u8; 33]; 2],
    existing_role_signatures: [bool; 2],
}

impl KitSweepInputSigningPlanV3 {
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
    pub const fn digest(&self) -> [u8; 32] {
        self.digest
    }

    #[must_use]
    pub const fn role_public_keys(&self) -> [[u8; 33]; 2] {
        self.role_public_keys
    }

    /// Roles whose exact existing partial signatures were cryptographically
    /// verified before this plan was constructed.
    #[must_use]
    pub const fn existing_role_signatures(&self) -> [bool; 2] {
        self.existing_role_signatures
    }
}

impl Drop for KitSweepInputSigningPlanV3 {
    fn drop(&mut self) {
        wipe::bytes(&mut self.digest);
        for key in &mut self.role_public_keys {
            wipe::bytes(key);
        }
        wipe::bools(&mut self.existing_role_signatures);
    }
}

/// Move-only owner for the exact schema-v3 review hash.
pub struct KitSweepReviewHashV3 {
    bytes: ReviewV3Hash,
}

impl KitSweepReviewHashV3 {
    #[must_use]
    pub const fn value(&self) -> ReviewV3Hash {
        self.bytes
    }

    #[must_use]
    pub const fn as_bytes(&self) -> &ReviewV3Hash {
        &self.bytes
    }
}

impl Drop for KitSweepReviewHashV3 {
    fn drop(&mut self) {
        wipe::bytes(&mut self.bytes);
    }
}

/// One non-clonable proof of an exact old-wallet-to-replacement-wallet sweep.
///
/// No public constructor exists. Signing implementations may only borrow the
/// already-proven input plans; finalization consumes this owner through
/// [`ValidatedKitSweepV3::into_parts`].
pub struct ValidatedKitSweepV3 {
    s0: OwnedS0,
    old_descriptor: DescriptorPairV2,
    review: ReviewV3,
    review_hash: KitSweepReviewHashV3,
    replacement_wallet_id: wipe::ByteArray<32>,
    destination_index: u32,
    input_signing_plans: Vec<KitSweepInputSigningPlanV3>,
}

impl ValidatedKitSweepV3 {
    #[must_use]
    pub const fn wallet_id(&self) -> [u8; 32] {
        self.review.wallet_id()
    }

    #[must_use]
    pub const fn replacement_wallet_id(&self) -> [u8; 32] {
        self.replacement_wallet_id.value()
    }

    #[must_use]
    pub const fn destination_index(&self) -> u32 {
        self.destination_index
    }

    #[must_use]
    pub fn input_count(&self) -> usize {
        self.input_signing_plans.len()
    }

    #[must_use]
    pub fn input_signing_plans(&self) -> &[KitSweepInputSigningPlanV3] {
        &self.input_signing_plans
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

    /// Consume the proof into still-opaque execution ownership.
    #[must_use]
    pub fn into_parts(self) -> ValidatedKitSweepV3Parts {
        let Self {
            s0,
            old_descriptor,
            review,
            review_hash,
            replacement_wallet_id,
            destination_index,
            input_signing_plans,
        } = self;
        ValidatedKitSweepV3Parts {
            s0,
            old_descriptor,
            review,
            review_hash,
            replacement_wallet_id,
            destination_index,
            input_signing_plans,
        }
    }
}

/// Consumed sweep-proof fields retained as one move-only owner until the
/// insertion/finalization boundary takes them together.
pub struct ValidatedKitSweepV3Parts {
    s0: OwnedS0,
    old_descriptor: DescriptorPairV2,
    review: ReviewV3,
    review_hash: KitSweepReviewHashV3,
    replacement_wallet_id: wipe::ByteArray<32>,
    destination_index: u32,
    input_signing_plans: Vec<KitSweepInputSigningPlanV3>,
}

impl ValidatedKitSweepV3Parts {
    #[must_use]
    pub const fn wallet_id(&self) -> [u8; 32] {
        self.review.wallet_id()
    }

    #[must_use]
    pub const fn replacement_wallet_id(&self) -> [u8; 32] {
        self.replacement_wallet_id.value()
    }

    #[must_use]
    pub const fn destination_index(&self) -> u32 {
        self.destination_index
    }

    #[must_use]
    pub fn input_count(&self) -> usize {
        self.input_signing_plans.len()
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
    pub fn input_signing_plans(&self) -> &[KitSweepInputSigningPlanV3] {
        &self.input_signing_plans
    }

    #[must_use]
    pub const fn review(&self) -> &ReviewV3 {
        &self.review
    }

    #[must_use]
    pub const fn review_hash(&self) -> &KitSweepReviewHashV3 {
        &self.review_hash
    }

    /// Release all proof components together to the existing insertion and
    /// finalization implementation. None has an independent constructor.
    #[must_use]
    pub fn into_execution_parts(
        self,
    ) -> (
        OwnedS0,
        DescriptorPairV2,
        ReviewV3,
        KitSweepReviewHashV3,
        Vec<KitSweepInputSigningPlanV3>,
    ) {
        let Self {
            s0,
            old_descriptor,
            review,
            review_hash,
            replacement_wallet_id: _,
            destination_index: _,
            input_signing_plans,
        } = self;
        (s0, old_descriptor, review, review_hash, input_signing_plans)
    }
}

/// Stable rejection boundary for exact Kit-sweep validation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KitSweepV3Error {
    DestinationIndexOutOfRange,
    ReplacementWalletUnchanged,
    Parse(ParseError),
    Review(ReviewV3Error),
    ExistingSignatureVerification(SemanticError),
    OutputCountNotOne,
    OldWalletDestination,
    ChangeOutputProhibited,
    DestinationTypeMismatch,
    DestinationDerivationFailed,
    DestinationMismatch,
    DigestFailed,
    AllocationFailed,
    InternalInvariant,
}

impl KitSweepV3Error {
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::DestinationIndexOutOfRange => "DestinationIndexOutOfRange",
            Self::ReplacementWalletUnchanged => "ReplacementWalletUnchanged",
            Self::Parse(_) => "TransactionParseFailed",
            Self::Review(_) => "TransactionReviewRejected",
            Self::ExistingSignatureVerification(_) => "ExistingSignatureVerificationFailed",
            Self::OutputCountNotOne => "OutputCountNotOne",
            Self::OldWalletDestination => "OldWalletDestination",
            Self::ChangeOutputProhibited => "ChangeOutputProhibited",
            Self::DestinationTypeMismatch => "DestinationTypeMismatch",
            Self::DestinationDerivationFailed => "DestinationDerivationFailed",
            Self::DestinationMismatch => "DestinationMismatch",
            Self::DigestFailed => "DigestFailed",
            Self::AllocationFailed => "AllocationFailed",
            Self::InternalInvariant => "InternalInvariant",
        }
    }
}

impl fmt::Display for KitSweepV3Error {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.name())
    }
}

impl std::error::Error for KitSweepV3Error {}

/// Consume one exact S0 into a proof that it is the sole permitted Kit sweep.
pub fn build_validated_kit_sweep_v3(
    s0: OwnedS0,
    old_descriptor: DescriptorPairV2,
    replacement_descriptor: DescriptorPairV2,
    destination_index: u32,
) -> Result<ValidatedKitSweepV3, KitSweepV3Error> {
    if destination_index > limits::MAX_CHILD_INDEX {
        return Err(KitSweepV3Error::DestinationIndexOutOfRange);
    }
    let old_wallet_id = old_descriptor.wallet_id();
    let replacement_wallet_id = replacement_descriptor.wallet_id();
    if replacement_wallet_id == old_wallet_id {
        return Err(KitSweepV3Error::ReplacementWalletUnchanged);
    }

    let view = match s0.parse() {
        Ok(view) => view,
        Err(error) if error.category == RejectCategory::UnsignedTxZeroOutputs => {
            return Err(KitSweepV3Error::OutputCountNotOne)
        }
        Err(error) => return Err(KitSweepV3Error::Parse(error)),
    };
    if view.unsigned_tx().output_count != 1 {
        return Err(KitSweepV3Error::OutputCountNotOne);
    }
    let context = ReviewContext {
        network: ReviewNetwork::BitcoinMainnet,
        input_source: s0.source(),
    };
    let review =
        build_review_v3(&view, &old_descriptor, context).map_err(KitSweepV3Error::Review)?;
    let verification = analyze_descriptor_ownership_v2(&view, &old_descriptor)
        .map_err(KitSweepV3Error::ExistingSignatureVerification)?;
    validate_destination(
        &review,
        &old_descriptor,
        &replacement_descriptor,
        destination_index,
    )?;
    let input_signing_plans = build_signing_plans(
        &view,
        &review,
        &old_descriptor,
        &verification.verified_inputs,
    )?;
    let mut review_hash =
        wipe::ByteArray::new(review.review_hash().map_err(KitSweepV3Error::Review)?);
    if review.s0_sha256() != s0.sha256()
        || review.wallet_id() != old_wallet_id
        || input_signing_plans.len() != review.input_count()
    {
        return Err(KitSweepV3Error::InternalInvariant);
    }
    drop(view);

    Ok(ValidatedKitSweepV3 {
        s0,
        old_descriptor,
        review,
        review_hash: KitSweepReviewHashV3 {
            bytes: review_hash.take(),
        },
        replacement_wallet_id: wipe::ByteArray::new(replacement_wallet_id),
        destination_index,
        input_signing_plans,
    })
}

fn validate_destination(
    review: &ReviewV3,
    old_descriptor: &DescriptorPairV2,
    replacement_descriptor: &DescriptorPairV2,
    destination_index: u32,
) -> Result<(), KitSweepV3Error> {
    let [output] = review.outputs() else {
        return Err(KitSweepV3Error::OutputCountNotOne);
    };
    match output.ownership() {
        ReviewV3OutputOwnership::ProvenSelfTransfer { .. } => {
            return Err(KitSweepV3Error::OldWalletDestination)
        }
        ReviewV3OutputOwnership::ProvenChange { .. } => {
            return Err(KitSweepV3Error::ChangeOutputProhibited)
        }
        ReviewV3OutputOwnership::NotOwned { recipient_type, .. }
            if *recipient_type != crate::RecipientType::P2wsh =>
        {
            return Err(KitSweepV3Error::DestinationTypeMismatch)
        }
        ReviewV3OutputOwnership::NotOwned { .. } => {}
    }
    let expected = WipingDerivedScript(
        derive_receive_script_v2(replacement_descriptor, destination_index)
            .map_err(|_| KitSweepV3Error::DestinationDerivationFailed)?,
    );
    let old_receive = WipingDerivedScript(
        derive_receive_script_v2(old_descriptor, destination_index)
            .map_err(|_| KitSweepV3Error::InternalInvariant)?,
    );
    let old_change = WipingDerivedScript(
        derive_change_script_v2(old_descriptor, destination_index)
            .map_err(|_| KitSweepV3Error::InternalInvariant)?,
    );
    if output.script_pubkey() == old_receive.0.script_pubkey {
        return Err(KitSweepV3Error::OldWalletDestination);
    }
    if output.script_pubkey() == old_change.0.script_pubkey {
        return Err(KitSweepV3Error::ChangeOutputProhibited);
    }
    if output.script_pubkey() != expected.0.script_pubkey {
        return Err(KitSweepV3Error::DestinationMismatch);
    }
    Ok(())
}

fn build_signing_plans(
    view: &crate::PsbtView<'_>,
    review: &ReviewV3,
    descriptor: &DescriptorPairV2,
    verified_inputs: &[VerifiedInputFacts],
) -> Result<Vec<KitSweepInputSigningPlanV3>, KitSweepV3Error> {
    let mut builder = Bip143PrecomputeBuilder::new();
    for input in review.inputs() {
        let txid = input.outpoint_txid_wire();
        builder
            .add_input(&txid, input.outpoint_vout(), input.sequence())
            .map_err(|_| KitSweepV3Error::DigestFailed)?;
    }
    for output in review.outputs() {
        builder
            .add_output(output.amount(), output.script_pubkey())
            .map_err(|_| KitSweepV3Error::DigestFailed)?;
    }
    let precomputed = WipingPrecomputed(
        builder
            .finish()
            .map_err(|_| KitSweepV3Error::DigestFailed)?,
    );
    let fingerprints = descriptor.origin_fingerprints();
    let mut plans = Vec::new();
    plans
        .try_reserve_exact(review.input_count())
        .map_err(|_| KitSweepV3Error::AllocationFailed)?;
    if verified_inputs.len() != review.input_count() {
        return Err(KitSweepV3Error::InternalInvariant);
    }
    for (input, verified) in review.inputs().iter().zip(verified_inputs) {
        if input.effective_sighash() != u32::from(SIGHASH_ALL) {
            return Err(KitSweepV3Error::InternalInvariant);
        }
        let input_index =
            usize::try_from(input.index()).map_err(|_| KitSweepV3Error::InternalInvariant)?;
        let script = WipingDerivedScript(derive_old_script(
            descriptor,
            input.branch(),
            input.child_index(),
        )?);
        let txid = wipe::ByteArray::new(input.outpoint_txid_wire());
        let facts = Bip143InputFacts {
            outpoint_txid_wire: txid.as_array(),
            outpoint_vout: input.outpoint_vout(),
            script_code: &script.0.witness_script,
            amount_sats: input.prevout_amount(),
            sequence: input.sequence(),
        };
        let mut digest = wipe::ByteArray::new(
            sighash_all_digest(review.version(), review.locktime(), &precomputed.0, &facts)
                .map_err(|_| KitSweepV3Error::DigestFailed)?,
        );
        let (role_public_keys, existing_role_signatures) =
            collect_role_public_keys(view, input_index, &fingerprints)?;
        let existing_count = existing_role_signatures
            .iter()
            .filter(|present| **present)
            .count();
        if existing_count != verified.verified_signature_count {
            return Err(KitSweepV3Error::InternalInvariant);
        }
        let [mut role_a, mut role_b] = role_public_keys;
        plans.push(KitSweepInputSigningPlanV3 {
            input_index: input.index(),
            branch: input.branch(),
            child_index: input.child_index(),
            digest: digest.take(),
            role_public_keys: [role_a.take(), role_b.take()],
            existing_role_signatures,
        });
    }
    Ok(plans)
}

struct WipingPrecomputed(crate::bip143::Bip143Precomputed);

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

fn derive_old_script(
    descriptor: &DescriptorPairV2,
    branch: u32,
    index: u32,
) -> Result<DerivedScriptV2, KitSweepV3Error> {
    match branch {
        0 => derive_receive_script_v2(descriptor, index),
        1 => derive_change_script_v2(descriptor, index),
        _ => return Err(KitSweepV3Error::InternalInvariant),
    }
    .map_err(|_| KitSweepV3Error::InternalInvariant)
}

fn collect_role_public_keys(
    view: &crate::PsbtView<'_>,
    input_index: usize,
    fingerprints: &[[u8; 4]; 2],
) -> Result<([wipe::ByteArray<33>; 2], [bool; 2]), KitSweepV3Error> {
    let records = view
        .input_records(input_index)
        .ok_or(KitSweepV3Error::InternalInvariant)?;
    let mut keys: [Option<wipe::ByteArray<33>>; 2] = [None, None];
    for record in records {
        if record.key_type != 0x06 {
            continue;
        }
        let fingerprint = record
            .value
            .get(..4)
            .ok_or(KitSweepV3Error::InternalInvariant)?;
        let role = fingerprints
            .iter()
            .position(|candidate| candidate.as_slice() == fingerprint)
            .ok_or(KitSweepV3Error::InternalInvariant)?;
        let key: [u8; 33] = record
            .key_data
            .try_into()
            .map_err(|_| KitSweepV3Error::InternalInvariant)?;
        let target = keys
            .get_mut(role)
            .ok_or(KitSweepV3Error::InternalInvariant)?;
        if target.replace(wipe::ByteArray::new(key)).is_some() {
            return Err(KitSweepV3Error::InternalInvariant);
        }
    }
    let [key_a, key_b] = keys;
    let key_a = key_a.ok_or(KitSweepV3Error::InternalInvariant)?;
    let key_b = key_b.ok_or(KitSweepV3Error::InternalInvariant)?;
    let mut existing = [false; 2];
    for record in view
        .input_records(input_index)
        .ok_or(KitSweepV3Error::InternalInvariant)?
    {
        if record.key_type != 0x02 {
            continue;
        }
        let role = if record.key_data == key_a.as_array() {
            0
        } else if record.key_data == key_b.as_array() {
            1
        } else {
            return Err(KitSweepV3Error::InternalInvariant);
        };
        let slot = existing
            .get_mut(role)
            .ok_or(KitSweepV3Error::InternalInvariant)?;
        if *slot {
            return Err(KitSweepV3Error::InternalInvariant);
        }
        *slot = true;
    }
    Ok(([key_a, key_b], existing))
}

#[cfg(test)]
#[allow(clippy::arithmetic_side_effects)]
mod tests {
    use super::{
        KitSweepInputSigningPlanV3, KitSweepReviewHashV3, WipingDerivedScript, WipingPrecomputed,
    };
    use crate::bip143::Bip143Precomputed;
    use crate::wipe::{reset_wiped_bytes, wiped_bytes};
    use qk_descriptor::DerivedScriptV2;

    #[test]
    fn plan_hash_precompute_and_script_owners_wipe_complete_values() {
        let plan = KitSweepInputSigningPlanV3 {
            input_index: 0,
            branch: 0,
            child_index: 0,
            digest: [0xa1; 32],
            role_public_keys: [[0xb2; 33], [0xc3; 33]],
            existing_role_signatures: [true, false],
        };
        reset_wiped_bytes();
        drop(plan);
        assert_eq!(wiped_bytes(), 32 + (2 * 33) + 2);

        let hash = KitSweepReviewHashV3 { bytes: [0xd4; 32] };
        reset_wiped_bytes();
        drop(hash);
        assert_eq!(wiped_bytes(), 32);

        let precomputed = WipingPrecomputed(Bip143Precomputed {
            hash_prevouts: [0xe5; 32],
            hash_sequence: [0xf6; 32],
            hash_outputs: [0x17; 32],
        });
        reset_wiped_bytes();
        drop(precomputed);
        assert_eq!(wiped_bytes(), 96);

        let script = WipingDerivedScript(DerivedScriptV2 {
            witness_script: [0x28; 71],
            script_pubkey: [0x39; 34],
        });
        reset_wiped_bytes();
        drop(script);
        assert_eq!(wiped_bytes(), 105);
    }
}
