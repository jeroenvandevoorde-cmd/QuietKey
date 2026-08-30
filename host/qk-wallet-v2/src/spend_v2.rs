//! Purpose-bound HOST signing for one validated Kit-Spend sweep.
//!
//! The only signing input is qk-psbt's opaque exact-sweep capability. No
//! caller-selected digest, reusable signer, scalar, xprv, or secret accessor
//! exists. Role A and B route keys are derived from the recovered entropy,
//! matched to the capability's descriptor-derived keys, used once, and
//! cleared with every other secret scratch owner.

use crate::bip32_private::{derive_account_private, derive_route_scalar, PrivateNode};
use crate::bip39::entropy_to_seed;
use crate::secret::Secret;
use crate::{rebind_wallet_v2, WalletV2Error};
use core::fmt;
use qk_psbt::ValidatedKitSweepV3;

const MAX_INPUTS: usize = 100;
const DER_CAPACITY: usize = 72;

/// Closed failure surface for purpose-bound Kit-Spend signing.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum KitSweepSigningErrorV3 {
    RecoveredWalletMismatch,
    InvalidSigningPlan,
    ChildDerivationFailed,
    ExpectedPublicKeyMismatch,
    CryptographicSigningFailed,
}

impl KitSweepSigningErrorV3 {
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::RecoveredWalletMismatch => "RecoveredWalletMismatch",
            Self::InvalidSigningPlan => "InvalidSigningPlan",
            Self::ChildDerivationFailed => "ChildDerivationFailed",
            Self::ExpectedPublicKeyMismatch => "ExpectedPublicKeyMismatch",
            Self::CryptographicSigningFailed => "CryptographicSigningFailed",
        }
    }
}

impl fmt::Display for KitSweepSigningErrorV3 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.name())
    }
}

impl std::error::Error for KitSweepSigningErrorV3 {}

/// One fixed-capacity low-S DER signature cleared on drop.
pub struct KitSweepDerSignatureV3 {
    bytes: Secret<DER_CAPACITY>,
    len: usize,
}

impl KitSweepDerSignatureV3 {
    #[must_use]
    pub fn der(&self) -> &[u8] {
        &self.bytes.as_bytes()[..self.len]
    }
}

/// Exact role-A and role-B signatures for one validated input.
pub struct KitSweepInputSignaturesV3 {
    input_index: u32,
    role_a: Option<KitSweepDerSignatureV3>,
    role_b: Option<KitSweepDerSignatureV3>,
}

impl KitSweepInputSignaturesV3 {
    #[must_use]
    pub const fn input_index(&self) -> u32 {
        self.input_index
    }

    #[must_use]
    pub const fn role_a(&self) -> Option<&KitSweepDerSignatureV3> {
        self.role_a.as_ref()
    }

    #[must_use]
    pub const fn role_b(&self) -> Option<&KitSweepDerSignatureV3> {
        self.role_b.as_ref()
    }
}

/// Ordered signatures for exactly one validated Kit sweep.
pub struct WalletKitSweepSignaturesV3 {
    inputs: [KitSweepInputSignaturesV3; MAX_INPUTS],
    len: usize,
}

impl WalletKitSweepSignaturesV3 {
    #[must_use]
    pub fn inputs(&self) -> &[KitSweepInputSignaturesV3] {
        &self.inputs[..self.len]
    }
}

/// Sign every A/B input plan from one qk-psbt exact-sweep capability.
///
/// Both entropy values are borrowed only for this call. The expected D pair
/// and wallet ID are rebound before any route key is derived. Each produced
/// signature is RFC6979 deterministic, low-S, immediately self-verified by
/// qk-secp, and retained only in a wiping fixed-capacity owner.
pub fn sign_validated_kit_sweep_v3(
    seed_a: &[u8; 32],
    signer_b: &[u8; 32],
    expected_descriptors: &[[u8; 306]; 2],
    expected_wallet_id: &[u8; 32],
    proof: &ValidatedKitSweepV3,
) -> Result<WalletKitSweepSignaturesV3, KitSweepSigningErrorV3> {
    let rebound = rebind_wallet_v2(seed_a, signer_b, expected_descriptors, expected_wallet_id)
        .map_err(|_| KitSweepSigningErrorV3::RecoveredWalletMismatch)?;
    if rebound.wallet_id() != proof.wallet_id() || proof.wallet_id() != *expected_wallet_id {
        return Err(KitSweepSigningErrorV3::RecoveredWalletMismatch);
    }

    let plans = proof.input_signing_plans();
    if plans.is_empty() || plans.len() != proof.input_count() || plans.len() > MAX_INPUTS {
        return Err(KitSweepSigningErrorV3::InvalidSigningPlan);
    }

    let need_role_a = plans.iter().any(|plan| !plan.existing_role_signatures()[0]);
    let need_role_b = plans.iter().any(|plan| !plan.existing_role_signatures()[1]);
    let account_a = need_role_a
        .then(|| derive_signing_account(seed_a))
        .transpose()?;
    let account_b = need_role_b
        .then(|| derive_signing_account(signer_b))
        .transpose()?;

    let mut inputs = core::array::from_fn(|_| KitSweepInputSignaturesV3 {
        input_index: 0,
        role_a: None,
        role_b: None,
    });
    for (position, plan) in plans.iter().enumerate() {
        let input_index =
            u32::try_from(position).map_err(|_| KitSweepSigningErrorV3::InvalidSigningPlan)?;
        if plan.input_index() != input_index {
            return Err(KitSweepSigningErrorV3::InvalidSigningPlan);
        }
        let mut public_keys = plan.role_public_keys();
        let role_a_public_key = Secret::take(&mut public_keys[0]);
        let role_b_public_key = Secret::take(&mut public_keys[1]);
        let mut digest = plan.digest();
        let digest = Secret::take(&mut digest);
        let occupied = plan.existing_role_signatures();
        let role_a = if occupied[0] {
            None
        } else {
            Some(sign_role(
                account_a
                    .as_ref()
                    .ok_or(KitSweepSigningErrorV3::InvalidSigningPlan)?,
                plan.branch(),
                plan.child_index(),
                digest.as_bytes(),
                role_a_public_key.as_bytes(),
            )?)
        };
        let role_b = if occupied[1] {
            None
        } else {
            Some(sign_role(
                account_b
                    .as_ref()
                    .ok_or(KitSweepSigningErrorV3::InvalidSigningPlan)?,
                plan.branch(),
                plan.child_index(),
                digest.as_bytes(),
                role_b_public_key.as_bytes(),
            )?)
        };
        inputs[position] = KitSweepInputSignaturesV3 {
            input_index,
            role_a,
            role_b,
        };
    }
    Ok(WalletKitSweepSignaturesV3 {
        inputs,
        len: plans.len(),
    })
}

fn derive_signing_account(entropy: &[u8; 32]) -> Result<PrivateNode, KitSweepSigningErrorV3> {
    let bip39_seed = entropy_to_seed(entropy).map_err(map_child_error)?;
    let account = derive_account_private(bip39_seed.as_bytes()).map_err(map_child_error)?;
    drop(bip39_seed);
    Ok(account)
}

fn sign_role(
    account: &PrivateNode,
    branch: u32,
    child_index: u32,
    digest: &[u8; 32],
    expected_public_key: &[u8; 33],
) -> Result<KitSweepDerSignatureV3, KitSweepSigningErrorV3> {
    let (route_scalar, mut derived_public_key) =
        derive_route_scalar(account, branch, child_index).map_err(map_child_error)?;
    let derived_public_key = Secret::take(&mut derived_public_key);
    if derived_public_key.as_bytes() != expected_public_key {
        return Err(KitSweepSigningErrorV3::ExpectedPublicKeyMismatch);
    }
    let public_key = qk_secp::pubkey_parse_compressed(expected_public_key)
        .map_err(|_| KitSweepSigningErrorV3::CryptographicSigningFailed)?;
    let mut scalar = *route_scalar.as_bytes();
    let secret_key = qk_secp::secret_key_import(&mut scalar)
        .map_err(|_| KitSweepSigningErrorV3::CryptographicSigningFailed)?;
    let signature = qk_secp::ecdsa_sign_rfc6979(&secret_key, digest, &public_key)
        .map_err(|_| KitSweepSigningErrorV3::CryptographicSigningFailed)?;
    let mut der = [0u8; DER_CAPACITY];
    let len = qk_secp::signature_serialize_der(&signature, &mut der)
        .map_err(|_| KitSweepSigningErrorV3::CryptographicSigningFailed)?;
    Ok(KitSweepDerSignatureV3 {
        bytes: Secret::take(&mut der),
        len,
    })
}

fn map_child_error(_error: WalletV2Error) -> KitSweepSigningErrorV3 {
    KitSweepSigningErrorV3::ChildDerivationFailed
}

#[cfg(test)]
mod tests {
    use super::{
        sign_role, sign_validated_kit_sweep_v3, KitSweepDerSignatureV3, KitSweepSigningErrorV3,
    };
    use crate::bip32_private::derive_account_private;
    use crate::bip39::entropy_to_seed;
    use crate::secret::{reset_wiped_bytes, wiped_bytes, Secret};
    use qk_descriptor::parse_descriptor_pair_v2;
    use qk_psbt::{build_validated_kit_sweep_v3, InputSource, OwnedS0};

    const FIXTURE: &str = include_str!("../../qk-psbt/tests/fixtures/signing_finalization_v2.txt");
    const KIT_FIXTURE: &str = include_str!("../../qk-host-sim/tests/fixtures/kit_spend_v2.txt");

    fn field(name: &str) -> &str {
        FIXTURE
            .lines()
            .find_map(|line| line.strip_prefix(name)?.strip_prefix(": "))
            .expect("registered signing field")
    }

    fn hex_array<const N: usize>(text: &str) -> [u8; N] {
        assert_eq!(text.len(), N * 2);
        let mut output = [0u8; N];
        for (slot, position) in output.iter_mut().zip((0..text.len()).step_by(2)) {
            *slot = u8::from_str_radix(&text[position..position + 2], 16)
                .expect("registered lowercase hex");
        }
        output
    }

    fn kit_field(name: &str) -> &str {
        KIT_FIXTURE
            .lines()
            .find_map(|line| line.strip_prefix(name)?.strip_prefix(": "))
            .expect("registered Kit-Spend field")
    }

    fn account(entropy_field: &str) -> crate::bip32_private::PrivateNode {
        let entropy = hex_array(field(entropy_field));
        let seed = entropy_to_seed(&entropy).expect("registered entropy");
        derive_account_private(seed.as_bytes()).expect("registered account")
    }

    #[test]
    fn exact_route_der_signatures_match_registered_public_lineage() {
        let digest = hex_array(field("bip143_digest_hex"));
        let role_a = sign_role(
            &account("role_a_transcript_sha256"),
            0,
            0,
            &digest,
            &hex_array(field("role_a_route_public_key_hex")),
        )
        .expect("registered role A");
        let role_b = sign_role(
            &account("role_b_transcript_sha256"),
            0,
            0,
            &digest,
            &hex_array(field("role_b_route_public_key_hex")),
        )
        .expect("registered role B");
        assert_eq!(role_a.der(), hex_array::<71>(field("role_a_der_hex")));
        assert_eq!(role_b.der(), hex_array::<71>(field("role_b_der_hex")));
    }

    #[test]
    fn route_and_expected_key_fail_closed_before_signature_release() {
        let digest = hex_array(field("bip143_digest_hex"));
        let account = account("role_a_transcript_sha256");
        let expected = hex_array(field("role_a_route_public_key_hex"));
        assert!(matches!(
            sign_role(&account, 2, 0, &digest, &expected),
            Err(KitSweepSigningErrorV3::ChildDerivationFailed)
        ));
        assert!(matches!(
            sign_role(&account, 0, 65_536, &digest, &expected),
            Err(KitSweepSigningErrorV3::ChildDerivationFailed)
        ));
        let mut wrong = expected;
        wrong[1] ^= 1;
        assert!(matches!(
            sign_role(&account, 0, 0, &digest, &wrong),
            Err(KitSweepSigningErrorV3::ExpectedPublicKeyMismatch)
        ));
    }

    #[test]
    fn der_owner_routes_its_complete_capacity_through_wipe() {
        let mut bytes = [0xa5; 72];
        let signature = KitSweepDerSignatureV3 {
            bytes: Secret::take(&mut bytes),
            len: 71,
        };
        reset_wiped_bytes();
        drop(signature);
        assert_eq!(wiped_bytes(), 72);
    }

    #[test]
    fn complete_signature_owner_wipes_both_fixed_capacities() {
        let old_receive = kit_field("old_receive_descriptor");
        let old_change = kit_field("old_change_descriptor");
        let replacement_receive = kit_field("replacement_receive_descriptor");
        let replacement_change = kit_field("replacement_change_descriptor");
        let s0 = hex_array::<383>(kit_field("s0_hex"));
        let proof = build_validated_kit_sweep_v3(
            OwnedS0::new(&s0, InputSource::MicroSd).expect("bounded S0"),
            parse_descriptor_pair_v2(old_receive.as_bytes(), old_change.as_bytes())
                .expect("registered old descriptor"),
            parse_descriptor_pair_v2(
                replacement_receive.as_bytes(),
                replacement_change.as_bytes(),
            )
            .expect("registered replacement descriptor"),
            0,
        )
        .expect("registered exact sweep");
        let descriptors = [
            old_receive
                .as_bytes()
                .try_into()
                .expect("old receive descriptor width"),
            old_change
                .as_bytes()
                .try_into()
                .expect("old change descriptor width"),
        ];
        let signatures = sign_validated_kit_sweep_v3(
            &hex_array(field("role_a_transcript_sha256")),
            &hex_array(field("role_b_transcript_sha256")),
            &descriptors,
            &hex_array(kit_field("old_wallet_id_hex")),
            &proof,
        )
        .expect("registered recovered authority");
        assert!(signatures.inputs()[0].role_a().is_some());
        assert!(signatures.inputs()[0].role_b().is_some());

        reset_wiped_bytes();
        drop(signatures);
        assert_eq!(wiped_bytes(), 2 * 72);
    }
}
