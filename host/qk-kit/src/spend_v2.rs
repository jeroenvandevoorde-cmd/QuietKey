//! Opaque, consuming HOST-only Kit-Spend signing boundary.
//!
//! A recovered payload first proves exact agreement with caller-authenticated
//! old-wallet D. It can then be consumed only with qk-psbt's opaque validated
//! one-output sweep capability. The result carries public transaction
//! signatures and the validated capability, never payload or key material.

use crate::RecoveredKitPayload;
use core::fmt;
use qk_psbt::ValidatedKitSweepV3;
use qk_wallet_v2::{
    rebind_wallet_v2, sign_validated_kit_sweep_v3, KitSweepSigningErrorV3,
    WalletKitSweepSignaturesV3, WalletPublicV2,
};

const PAYLOAD_BYTES: usize = 96;
const SEED_A_OFFSET: usize = 0;
const SIGNER_B_OFFSET: usize = 32;

/// Closed rejection surface for the consuming Kit-Spend math boundary.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum KitSpendMathErrorV3 {
    RecoveredWalletMismatch,
    ValidatedWalletMismatch,
    InvalidSigningPlan,
    ChildDerivationFailed,
    ExpectedPublicKeyMismatch,
    CryptographicSigningFailed,
}

impl KitSpendMathErrorV3 {
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::RecoveredWalletMismatch => "RecoveredWalletMismatch",
            Self::ValidatedWalletMismatch => "ValidatedWalletMismatch",
            Self::InvalidSigningPlan => "InvalidSigningPlan",
            Self::ChildDerivationFailed => "ChildDerivationFailed",
            Self::ExpectedPublicKeyMismatch => "ExpectedPublicKeyMismatch",
            Self::CryptographicSigningFailed => "CryptographicSigningFailed",
        }
    }
}

impl fmt::Display for KitSpendMathErrorV3 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.name())
    }
}

impl std::error::Error for KitSpendMathErrorV3 {}

/// Exact rebound recovered wallet owner for one future validated sweep.
///
/// No payload, entropy, scalar, signer, formatter, serializer, or reusable
/// operation is exposed. Its only signing operation consumes this owner and
/// requires qk-psbt's exact-sweep capability.
pub struct BoundKitSpendV2 {
    payload: RecoveredKitPayload,
    wallet: WalletPublicV2,
}

impl RecoveredKitPayload {
    /// Rebind recovered A/B authority to exact authenticated old-wallet D.
    pub fn bind_spend_v2(
        self,
        expected_descriptors: &[[u8; 306]; 2],
        expected_wallet_id: &[u8; 32],
    ) -> Result<BoundKitSpendV2, KitSpendMathErrorV3> {
        let seed_a = payload_part(self._bytes.as_bytes(), SEED_A_OFFSET);
        let signer_b = payload_part(self._bytes.as_bytes(), SIGNER_B_OFFSET);
        let wallet = rebind_wallet_v2(seed_a, signer_b, expected_descriptors, expected_wallet_id)
            .map_err(|_| KitSpendMathErrorV3::RecoveredWalletMismatch)?;
        Ok(BoundKitSpendV2 {
            payload: self,
            wallet,
        })
    }
}

impl BoundKitSpendV2 {
    #[must_use]
    pub fn wallet_id(&self) -> [u8; 32] {
        self.wallet.wallet_id()
    }

    /// Consume the rebound payload into signatures for exactly one validated
    /// schema-v3 Kit sweep.
    pub fn sign_validated_sweep_v3(
        self,
        proof: ValidatedKitSweepV3,
    ) -> Result<SignedKitSweepV3, KitSpendMathErrorV3> {
        if proof.wallet_id() != self.wallet.wallet_id() {
            return Err(KitSpendMathErrorV3::ValidatedWalletMismatch);
        }
        let seed_a = payload_part(self.payload._bytes.as_bytes(), SEED_A_OFFSET);
        let signer_b = payload_part(self.payload._bytes.as_bytes(), SIGNER_B_OFFSET);
        let signatures = sign_validated_kit_sweep_v3(
            seed_a,
            signer_b,
            &self.wallet.descriptors(),
            &self.wallet.wallet_id(),
            &proof,
        )
        .map_err(map_signing_error)?;
        Ok(SignedKitSweepV3 { proof, signatures })
    }
}

/// One non-clonable, proof-carrying signed Kit sweep.
///
/// The only decomposition consumes this capability and releases the already
/// validated public transaction proof plus its wiping signature owners. It
/// contains no recovered secret and cannot sign a second transaction.
pub struct SignedKitSweepV3 {
    proof: ValidatedKitSweepV3,
    signatures: WalletKitSweepSignaturesV3,
}

impl SignedKitSweepV3 {
    #[must_use]
    pub fn wallet_id(&self) -> [u8; 32] {
        self.proof.wallet_id()
    }

    #[must_use]
    pub fn input_count(&self) -> usize {
        self.proof.input_count()
    }

    pub fn into_execution_parts(self) -> (ValidatedKitSweepV3, WalletKitSweepSignaturesV3) {
        (self.proof, self.signatures)
    }
}

fn payload_part(payload: &[u8; PAYLOAD_BYTES], offset: usize) -> &[u8; 32] {
    payload[offset..offset + 32]
        .try_into()
        .expect("const-checked payload partition")
}

fn map_signing_error(error: KitSweepSigningErrorV3) -> KitSpendMathErrorV3 {
    match error {
        KitSweepSigningErrorV3::RecoveredWalletMismatch => {
            KitSpendMathErrorV3::RecoveredWalletMismatch
        }
        KitSweepSigningErrorV3::InvalidSigningPlan => KitSpendMathErrorV3::InvalidSigningPlan,
        KitSweepSigningErrorV3::ChildDerivationFailed => KitSpendMathErrorV3::ChildDerivationFailed,
        KitSweepSigningErrorV3::ExpectedPublicKeyMismatch => {
            KitSpendMathErrorV3::ExpectedPublicKeyMismatch
        }
        KitSweepSigningErrorV3::CryptographicSigningFailed => {
            KitSpendMathErrorV3::CryptographicSigningFailed
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::secret::{reset_wiped_bytes, wiped_bytes};
    use crate::{combine_frames, RecoveredKitPayload};

    const PROVISIONING: &[u8] =
        include_bytes!("../../qk-provisioning/tests/fixtures/provisioning_v2.txt");
    const KIT_SHARES: &[u8] = include_bytes!("../tests/fixtures/kit_share_v2.txt");

    fn field<'a>(fixture: &'a [u8], name: &str) -> &'a str {
        core::str::from_utf8(fixture)
            .expect("registered ASCII fixture")
            .lines()
            .find_map(|line| line.strip_prefix(name)?.strip_prefix(": "))
            .expect("registered field")
    }

    fn hex_array<const N: usize>(value: &str) -> [u8; N] {
        assert_eq!(value.len(), N * 2);
        let mut output = [0u8; N];
        for (slot, position) in output.iter_mut().zip((0..value.len()).step_by(2)) {
            *slot = u8::from_str_radix(&value[position..position + 2], 16)
                .expect("registered lowercase hex");
        }
        output
    }

    fn recovered() -> RecoveredKitPayload {
        combine_frames(
            &hex_array::<142>(field(KIT_SHARES, "frame_1_hex")),
            &hex_array::<142>(field(KIT_SHARES, "frame_2_hex")),
        )
        .expect("registered pair")
    }

    fn descriptors() -> [[u8; 306]; 2] {
        [
            field(PROVISIONING, "receive_descriptor")
                .as_bytes()
                .try_into()
                .expect("receive descriptor width"),
            field(PROVISIONING, "change_descriptor")
                .as_bytes()
                .try_into()
                .expect("change descriptor width"),
        ]
    }

    fn wallet_id() -> [u8; 32] {
        hex_array(field(PROVISIONING, "wallet_id"))
    }

    #[test]
    fn every_partial_spend_owner_routes_the_payload_through_wipe() {
        let bound = recovered()
            .bind_spend_v2(&descriptors(), &wallet_id())
            .expect("registered recovered wallet");
        reset_wiped_bytes();
        drop(bound);
        assert_eq!(wiped_bytes(), 96);

        let mut wrong_wallet = wallet_id();
        wrong_wallet[31] ^= 1;
        let payload = recovered();
        reset_wiped_bytes();
        assert!(payload
            .bind_spend_v2(&descriptors(), &wrong_wallet)
            .is_err());
        assert_eq!(wiped_bytes(), 96);
    }
}
