//! Purpose-bound role-A signing for one validated normal schema-v3 flow.

use crate::bip32_private::{
    account_public, derive_account_private, derive_route_scalar, AccountPublic, PrivateNode,
};
use crate::bip39::entropy_to_seed;
use crate::secret::Secret;
use crate::WalletV2Error;
use core::fmt;
use qk_psbt::{ValidatedNormalV3, ValidatedNormalV3Parts};

const MAX_INPUTS: usize = 100;
const DER_CAPACITY: usize = 72;
const ROLE_A_ORIGIN_START: usize = 19;
const ROLE_A_ORIGIN_END: usize = 27;
const ROLE_A_XPUB_START: usize = 41;
const ROLE_A_XPUB_END: usize = 152;

/// Closed non-signing role-A binding failure surface.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum WalletNormalV3Error {
    RecoveredWalletMismatch,
    RevalidationFailed,
    InvalidSigningPlan,
    ChildDerivationFailed,
    ExpectedPublicKeyMismatch,
}

impl WalletNormalV3Error {
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::RecoveredWalletMismatch => "RecoveredWalletMismatch",
            Self::RevalidationFailed => "RevalidationFailed",
            Self::InvalidSigningPlan => "InvalidSigningPlan",
            Self::ChildDerivationFailed => "ChildDerivationFailed",
            Self::ExpectedPublicKeyMismatch => "ExpectedPublicKeyMismatch",
        }
    }
}

impl fmt::Display for WalletNormalV3Error {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.name())
    }
}

impl std::error::Error for WalletNormalV3Error {}

/// Closed purpose-bound normal role-A signing failure surface.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum NormalRoleASigningErrorV3 {
    RecoveredWalletMismatch,
    RevalidationFailed,
    InvalidSigningPlan,
    ChildDerivationFailed,
    ExpectedPublicKeyMismatch,
    CryptographicSigningFailed,
    DuplicateSignature,
}

impl NormalRoleASigningErrorV3 {
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::RecoveredWalletMismatch => "RecoveredWalletMismatch",
            Self::RevalidationFailed => "RevalidationFailed",
            Self::InvalidSigningPlan => "InvalidSigningPlan",
            Self::ChildDerivationFailed => "ChildDerivationFailed",
            Self::ExpectedPublicKeyMismatch => "ExpectedPublicKeyMismatch",
            Self::CryptographicSigningFailed => "CryptographicSigningFailed",
            Self::DuplicateSignature => "DuplicateSignature",
        }
    }
}

impl fmt::Display for NormalRoleASigningErrorV3 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.name())
    }
}

impl std::error::Error for NormalRoleASigningErrorV3 {}

/// One fixed-capacity low-S DER role-A signature cleared on drop.
pub struct NormalRoleADerSignatureV3 {
    bytes: Secret<DER_CAPACITY>,
    len: usize,
}

impl NormalRoleADerSignatureV3 {
    #[must_use]
    pub fn der(&self) -> &[u8] {
        self.bytes.as_bytes().get(..self.len).unwrap_or_default()
    }
}

/// The optional role-A signature for one exact transaction input.
pub struct NormalRoleAInputSignatureV3 {
    input_index: u32,
    role_a: Option<NormalRoleADerSignatureV3>,
}

impl NormalRoleAInputSignatureV3 {
    #[must_use]
    pub const fn input_index(&self) -> u32 {
        self.input_index
    }

    #[must_use]
    pub const fn role_a(&self) -> Option<&NormalRoleADerSignatureV3> {
        self.role_a.as_ref()
    }
}

/// Ordered role-A results for every input in one consumed proof.
pub struct WalletNormalRoleASignaturesV3 {
    inputs: [NormalRoleAInputSignatureV3; MAX_INPUTS],
    len: usize,
}

impl WalletNormalRoleASignaturesV3 {
    #[must_use]
    pub fn inputs(&self) -> &[NormalRoleAInputSignatureV3] {
        self.inputs.get(..self.len).unwrap_or_default()
    }
}

/// Move-only normal proof paired with its purpose-bound role-A results.
pub struct WalletSignedNormalRoleAV3 {
    proof: ValidatedNormalV3Parts,
    signatures: WalletNormalRoleASignaturesV3,
}

impl WalletSignedNormalRoleAV3 {
    #[must_use]
    pub const fn wallet_id(&self) -> [u8; 32] {
        self.proof.wallet_id()
    }

    #[must_use]
    pub fn input_count(&self) -> usize {
        self.proof.input_count()
    }

    #[must_use]
    pub fn into_finalization_parts(
        self,
    ) -> (ValidatedNormalV3Parts, WalletNormalRoleASignaturesV3) {
        (self.proof, self.signatures)
    }
}

/// Sign every missing descriptor role-A slot from one exact normal proof.
///
/// The caller cannot select a digest or public key. The route is fixed by the
/// proof, and every derived public key must equal the proof's role-A key before
/// RFC6979 signing can release one DER owner.
pub fn sign_validated_normal_role_a_v3(
    seed_a: &[u8; 32],
    expected_descriptors: &[[u8; 306]; 2],
    expected_wallet_id: &[u8; 32],
    proof: ValidatedNormalV3,
) -> Result<WalletSignedNormalRoleAV3, NormalRoleASigningErrorV3> {
    validate_normal_role_a_binding_v3(seed_a, expected_descriptors, expected_wallet_id, &proof)
        .map_err(map_binding_error)?;
    let proof = proof.into_parts();
    let plans = proof.input_signing_plans();
    if plans.is_empty() || plans.len() > MAX_INPUTS || plans.len() != proof.input_count() {
        return Err(NormalRoleASigningErrorV3::InvalidSigningPlan);
    }
    let needs_signing = plans.iter().any(|plan| !plan.existing_role_signatures()[0]);
    let account = needs_signing
        .then(|| derive_signing_account(seed_a))
        .transpose()?;
    let mut inputs = core::array::from_fn(|_| NormalRoleAInputSignatureV3 {
        input_index: 0,
        role_a: None,
    });
    for (position, plan) in plans.iter().enumerate() {
        let input_index =
            u32::try_from(position).map_err(|_| NormalRoleASigningErrorV3::InvalidSigningPlan)?;
        if plan.input_index() != input_index {
            return Err(NormalRoleASigningErrorV3::InvalidSigningPlan);
        }
        let occupied = plan.existing_role_signatures();
        let role_a = if occupied[0] {
            None
        } else {
            let keys = plan.role_public_keys();
            Some(sign_role_a(
                account
                    .as_ref()
                    .ok_or(NormalRoleASigningErrorV3::InvalidSigningPlan)?,
                plan.branch(),
                plan.child_index(),
                plan.digest(),
                keys.first()
                    .ok_or(NormalRoleASigningErrorV3::InvalidSigningPlan)?,
            )?)
        };
        if role_a.as_ref().is_some_and(|candidate| {
            inputs
                .get(..position)
                .unwrap_or_default()
                .iter()
                .filter_map(NormalRoleAInputSignatureV3::role_a)
                .any(|prior| prior.der() == candidate.der())
        }) {
            return Err(NormalRoleASigningErrorV3::DuplicateSignature);
        }
        *inputs
            .get_mut(position)
            .ok_or(NormalRoleASigningErrorV3::InvalidSigningPlan)? = NormalRoleAInputSignatureV3 {
            input_index,
            role_a,
        };
    }
    let len = plans.len();
    Ok(WalletSignedNormalRoleAV3 {
        proof,
        signatures: WalletNormalRoleASignaturesV3 { inputs, len },
    })
}

/// Prove that Seed-A derives every role-A route fixed by one normal proof.
///
/// This operation signs nothing and releases no key, scalar, digest, or
/// signature. All route scalar and public-key scratch is cleared before it
/// returns. The signing operation repeats this complete check after the
/// post-hold same-S0 revalidation.
pub fn validate_normal_role_a_binding_v3(
    seed_a: &[u8; 32],
    expected_descriptors: &[[u8; 306]; 2],
    expected_wallet_id: &[u8; 32],
    proof: &ValidatedNormalV3,
) -> Result<(), WalletNormalV3Error> {
    let expected = qk_descriptor::parse_descriptor_pair_v2(
        expected_descriptors
            .first()
            .ok_or(WalletNormalV3Error::RecoveredWalletMismatch)?,
        expected_descriptors
            .get(1)
            .ok_or(WalletNormalV3Error::RecoveredWalletMismatch)?,
    )
    .map_err(|_| WalletNormalV3Error::RecoveredWalletMismatch)?;
    if expected.wallet_id() != *expected_wallet_id || proof.wallet_id() != *expected_wallet_id {
        return Err(WalletNormalV3Error::RecoveredWalletMismatch);
    }
    proof
        .revalidate()
        .map_err(|_| WalletNormalV3Error::RevalidationFailed)?;
    let plans = proof.input_signing_plans();
    if plans.is_empty() || plans.len() > MAX_INPUTS {
        return Err(WalletNormalV3Error::InvalidSigningPlan);
    }
    let account = derive_binding_account(seed_a)?;
    if !account_matches_role_a(&account, expected_descriptors)? {
        return Err(WalletNormalV3Error::RecoveredWalletMismatch);
    }
    for (position, plan) in plans.iter().enumerate() {
        let input_index =
            u32::try_from(position).map_err(|_| WalletNormalV3Error::InvalidSigningPlan)?;
        if plan.input_index() != input_index {
            return Err(WalletNormalV3Error::InvalidSigningPlan);
        }
        let (_route_scalar, mut derived_public_key) =
            derive_route_scalar(&account, plan.branch(), plan.child_index())
                .map_err(|_| WalletNormalV3Error::ChildDerivationFailed)?;
        let derived_public_key = Secret::take(&mut derived_public_key);
        let keys = plan.role_public_keys();
        if Some(derived_public_key.as_bytes()) != keys.first() {
            return Err(WalletNormalV3Error::ExpectedPublicKeyMismatch);
        }
    }
    Ok(())
}

fn derive_binding_account(entropy: &[u8; 32]) -> Result<PrivateNode, WalletNormalV3Error> {
    let seed = entropy_to_seed(entropy).map_err(|_| WalletNormalV3Error::ChildDerivationFailed)?;
    let account = derive_account_private(seed.as_bytes())
        .map_err(|_| WalletNormalV3Error::ChildDerivationFailed)?;
    drop(seed);
    Ok(account)
}

fn account_matches_role_a(
    account: &PrivateNode,
    expected_descriptors: &[[u8; 306]; 2],
) -> Result<bool, WalletNormalV3Error> {
    let account =
        account_public(account).map_err(|_| WalletNormalV3Error::ChildDerivationFailed)?;
    Ok(account_public_matches_role_a(account, expected_descriptors))
}

fn account_public_matches_role_a(
    account: AccountPublic,
    expected_descriptors: &[[u8; 306]; 2],
) -> bool {
    let AccountPublic {
        mut xpub,
        mut origin_fingerprint,
    } = account;
    let xpub = Secret::take(&mut xpub);
    let origin_fingerprint = Secret::take(&mut origin_fingerprint);
    let mut origin_hex = hex_fingerprint(origin_fingerprint.as_bytes());
    let origin_hex = Secret::take(&mut origin_hex);
    expected_descriptors.iter().all(|descriptor| {
        descriptor.get(ROLE_A_ORIGIN_START..ROLE_A_ORIGIN_END)
            == Some(origin_hex.as_bytes().as_slice())
            && descriptor.get(ROLE_A_XPUB_START..ROLE_A_XPUB_END)
                == Some(xpub.as_bytes().as_slice())
    })
}

fn hex_fingerprint(value: &[u8; 4]) -> [u8; 8] {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut output = [0u8; 8];
    for (index, byte) in value.iter().copied().enumerate() {
        output[index * 2] = HEX[usize::from(byte >> 4)];
        output[index * 2 + 1] = HEX[usize::from(byte & 15)];
    }
    output
}

fn map_binding_error(error: WalletNormalV3Error) -> NormalRoleASigningErrorV3 {
    match error {
        WalletNormalV3Error::RecoveredWalletMismatch => {
            NormalRoleASigningErrorV3::RecoveredWalletMismatch
        }
        WalletNormalV3Error::RevalidationFailed => NormalRoleASigningErrorV3::RevalidationFailed,
        WalletNormalV3Error::InvalidSigningPlan => NormalRoleASigningErrorV3::InvalidSigningPlan,
        WalletNormalV3Error::ChildDerivationFailed => {
            NormalRoleASigningErrorV3::ChildDerivationFailed
        }
        WalletNormalV3Error::ExpectedPublicKeyMismatch => {
            NormalRoleASigningErrorV3::ExpectedPublicKeyMismatch
        }
    }
}

fn derive_signing_account(entropy: &[u8; 32]) -> Result<PrivateNode, NormalRoleASigningErrorV3> {
    let seed = entropy_to_seed(entropy).map_err(map_child_error)?;
    let account = derive_account_private(seed.as_bytes()).map_err(map_child_error)?;
    drop(seed);
    Ok(account)
}

fn sign_role_a(
    account: &PrivateNode,
    branch: u32,
    child_index: u32,
    digest: &[u8; 32],
    expected_public_key: &[u8; 33],
) -> Result<NormalRoleADerSignatureV3, NormalRoleASigningErrorV3> {
    let (route_scalar, mut derived_public_key) =
        derive_route_scalar(account, branch, child_index).map_err(map_child_error)?;
    let derived_public_key = Secret::take(&mut derived_public_key);
    if derived_public_key.as_bytes() != expected_public_key {
        return Err(NormalRoleASigningErrorV3::ExpectedPublicKeyMismatch);
    }
    let public_key = qk_secp::pubkey_parse_compressed(expected_public_key)
        .map_err(|_| NormalRoleASigningErrorV3::CryptographicSigningFailed)?;
    let mut scalar = *route_scalar.as_bytes();
    let secret_key = qk_secp::secret_key_import(&mut scalar)
        .map_err(|_| NormalRoleASigningErrorV3::CryptographicSigningFailed)?;
    let signature = qk_secp::ecdsa_sign_rfc6979(&secret_key, digest, &public_key)
        .map_err(|_| NormalRoleASigningErrorV3::CryptographicSigningFailed)?;
    let mut der = Secret::<DER_CAPACITY>::zeroed();
    let len = qk_secp::signature_serialize_der(&signature, der.as_mut_bytes())
        .map_err(|_| NormalRoleASigningErrorV3::CryptographicSigningFailed)?;
    Ok(NormalRoleADerSignatureV3 { bytes: der, len })
}

fn map_child_error(_error: WalletV2Error) -> NormalRoleASigningErrorV3 {
    NormalRoleASigningErrorV3::ChildDerivationFailed
}

#[cfg(test)]
mod tests {
    use super::{account_public_matches_role_a, NormalRoleADerSignatureV3, DER_CAPACITY};
    use crate::bip32_private::AccountPublic;
    use crate::secret::{reset_wiped_bytes, wiped_bytes, Secret};

    #[test]
    fn normal_der_owner_clears_its_complete_fixed_capacity() {
        let mut bytes = [0x5a; DER_CAPACITY];
        let signature = NormalRoleADerSignatureV3 {
            bytes: Secret::take(&mut bytes),
            len: 71,
        };
        reset_wiped_bytes();
        drop(signature);
        assert_eq!(wiped_bytes(), DER_CAPACITY);
    }

    #[test]
    fn account_public_binding_clears_every_derived_public_scratch_byte() {
        let account = AccountPublic {
            xpub: [b'x'; 111],
            origin_fingerprint: [0x12, 0x34, 0xab, 0xcd],
        };
        let mut descriptors = [[0u8; 306]; 2];
        for descriptor in &mut descriptors {
            descriptor[19..27].copy_from_slice(b"1234abcd");
            descriptor[41..152].copy_from_slice(&[b'x'; 111]);
        }
        reset_wiped_bytes();
        assert!(account_public_matches_role_a(account, &descriptors));
        assert_eq!(wiped_bytes(), 2 * (111 + 4 + 8));
    }
}
