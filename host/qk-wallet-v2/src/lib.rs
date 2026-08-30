//! Fixed-memory HOST reference for QuietKey v2 entropy-to-public-wallet facts.
//!
//! HOST REFERENCE ONLY — NOT PRODUCTION CRYPTOGRAPHY — NOT A WALLET —
//! NO ENTROPY, GENERAL SIGNING, CARD, TARGET, PERFORMANCE, OR GATE CLAIM.
//!
//! The two caller-supplied entropy values are transformed through the frozen
//! v2 BIP39/BIP32/descriptor chain. Only role-ordered public account facts,
//! exact descriptors, wallet identity, and first-route public facts leave the
//! crate. No mnemonic, seed, scalar, chain code, xprv, arbitrary digest, or
//! reusable signer is public. The sole signing operation consumes qk-psbt's
//! opaque validated Kit-sweep capability and returns it inseparably paired
//! with ordered wiping low-S DER owners.

#![deny(unsafe_code)]

mod bech32;
mod bip32_private;
mod bip39;
mod descriptor;
mod hmac_sha512;
mod ripemd160;
mod secret;
mod sha256;
mod sha512;
mod spend_v2;

use bip32_private::derive_account;
use core::fmt;
use descriptor::build_wallet_v2;

pub use spend_v2::{
    sign_validated_kit_sweep_v3, KitSweepDerSignatureV3, KitSweepInputSignaturesV3,
    KitSweepSigningErrorV3, WalletKitSweepSignaturesV3, WalletSignedKitSweepV3,
};

/// Closed failure surface for v2 entropy-to-public-wallet derivation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum WalletV2Error {
    InvalidMasterScalar,
    InvalidChildTweak,
    ZeroChild,
    CryptographicBackend,
    CryptographicInvariant,
    GeneratedDescriptorInvalid,
    RecoveredWalletMismatch,
}

impl fmt::Display for WalletV2Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let text = match self {
            Self::InvalidMasterScalar => "invalid BIP32 master scalar",
            Self::InvalidChildTweak => "invalid BIP32 child tweak",
            Self::ZeroChild => "BIP32 child scalar is zero",
            Self::CryptographicBackend => "cryptographic backend failure",
            Self::CryptographicInvariant => "cryptographic invariant failure",
            Self::GeneratedDescriptorInvalid => "generated descriptor failed strict reparse",
            Self::RecoveredWalletMismatch => "recovered wallet does not match expected wallet",
        };
        f.write_str(text)
    }
}

impl std::error::Error for WalletV2Error {}

/// Exact public facts derived from Seed-A and Signer-B entropy.
///
/// Every field is public wallet metadata. The private fields and by-value
/// getters prevent references from becoming an accidental lifetime bridge to
/// either caller-supplied entropy value.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct WalletPublicV2 {
    account_xpubs: [[u8; 111]; 2],
    origin_fingerprints: [[u8; 4]; 2],
    descriptors: [[u8; 306]; 2],
    wallet_id: [u8; 32],
    first_scripts: [[u8; 34]; 2],
    first_addresses: [[u8; 62]; 2],
}

impl WalletPublicV2 {
    #[must_use]
    pub const fn account_xpubs(&self) -> [[u8; 111]; 2] {
        self.account_xpubs
    }

    #[must_use]
    pub const fn origin_fingerprints(&self) -> [[u8; 4]; 2] {
        self.origin_fingerprints
    }

    #[must_use]
    pub const fn descriptors(&self) -> [[u8; 306]; 2] {
        self.descriptors
    }

    #[must_use]
    pub const fn wallet_id(&self) -> [u8; 32] {
        self.wallet_id
    }

    #[must_use]
    pub const fn first_scripts(&self) -> [[u8; 34]; 2] {
        self.first_scripts
    }

    #[must_use]
    pub const fn first_addresses(&self) -> [[u8; 62]; 2] {
        self.first_addresses
    }
}

/// Derive the exact v2 public wallet from two 32-byte entropy values.
///
/// The inputs are Seed-A and Signer-B entropy in that role order. Both are
/// borrowed only for this call. BIP39 mnemonic and seed material, BIP32 private
/// nodes, chain codes, tweaks, and scalar scratch remain private fixed-size
/// owners and are cleared by their established drop boundaries.
pub fn derive_wallet_v2(
    seed_a: &[u8; 32],
    signer_b: &[u8; 32],
) -> Result<WalletPublicV2, WalletV2Error> {
    let seed_a_bip39 = bip39::entropy_to_seed(seed_a)?;
    let account_a = derive_account(seed_a_bip39.as_bytes())?;
    drop(seed_a_bip39);

    let signer_b_bip39 = bip39::entropy_to_seed(signer_b)?;
    let account_b = derive_account(signer_b_bip39.as_bytes())?;
    drop(signer_b_bip39);

    let account_xpubs = [account_a.xpub, account_b.xpub];
    let origin_fingerprints = [account_a.origin_fingerprint, account_b.origin_fingerprint];
    let derived = build_wallet_v2([account_a, account_b])?;
    Ok(WalletPublicV2 {
        account_xpubs,
        origin_fingerprints,
        descriptors: derived.descriptors,
        wallet_id: derived.wallet_id,
        first_scripts: derived.scripts,
        first_addresses: derived.addresses,
    })
}

/// Derive and require exact agreement with one caller-authenticated v2 D pair.
///
/// Any malformed expected descriptor, descriptor-byte difference, role-order
/// difference, origin-fingerprint difference, account-xpub difference, or
/// wallet-id difference is the single named recovery-boundary rejection.
pub fn rebind_wallet_v2(
    seed_a: &[u8; 32],
    signer_b: &[u8; 32],
    expected_descriptors: &[[u8; 306]; 2],
    expected_wallet_id: &[u8; 32],
) -> Result<WalletPublicV2, WalletV2Error> {
    let expected_pair =
        qk_descriptor::parse_descriptor_pair_v2(&expected_descriptors[0], &expected_descriptors[1])
            .map_err(|_| WalletV2Error::RecoveredWalletMismatch)?;
    let derived = derive_wallet_v2(seed_a, signer_b)?;
    if derived.descriptors != *expected_descriptors
        || derived.wallet_id != *expected_wallet_id
        || expected_pair.wallet_id() != *expected_wallet_id
        || expected_pair.origin_fingerprints() != derived.origin_fingerprints
    {
        return Err(WalletV2Error::RecoveredWalletMismatch);
    }
    Ok(derived)
}

#[cfg(test)]
mod tests {
    use super::{derive_wallet_v2, rebind_wallet_v2, WalletV2Error};

    const GOLDEN: &str = include_str!("../../qk-provisioning/tests/fixtures/provisioning_v2.txt");

    fn field(name: &str) -> &str {
        GOLDEN
            .lines()
            .filter(|line| !line.starts_with('#'))
            .find_map(|line| {
                let (key, value) = line.split_once(": ")?;
                (key == name).then_some(value)
            })
            .expect("registered GOLDEN field")
    }

    fn hex_array<const N: usize>(text: &str) -> [u8; N] {
        assert_eq!(text.len(), N * 2);
        let mut output = [0u8; N];
        for (slot, position) in output.iter_mut().zip((0..text.len()).step_by(2)) {
            *slot = u8::from_str_radix(&text[position..position + 2], 16).expect("fixture hex");
        }
        output
    }

    fn golden_entropy(name: &str) -> [u8; 32] {
        hex_array(field(name))
    }

    #[test]
    fn golden_public_wallet_and_role_order_are_exact() {
        let wallet = derive_wallet_v2(
            &golden_entropy("seed_a_transcript_sha256"),
            &golden_entropy("signer_b_transcript_sha256"),
        )
        .expect("registered v2 GOLDEN wallet");
        let xpubs = wallet.account_xpubs();
        assert_eq!(xpubs[0].as_slice(), field("role_a_account_xpub").as_bytes());
        assert_eq!(xpubs[1].as_slice(), field("role_b_account_xpub").as_bytes());
        let fingerprints = wallet.origin_fingerprints();
        assert_eq!(
            fingerprints[0],
            hex_array(field("role_a_origin_fingerprint"))
        );
        assert_eq!(
            fingerprints[1],
            hex_array(field("role_b_origin_fingerprint"))
        );
        let descriptors = wallet.descriptors();
        assert_eq!(
            descriptors[0].as_slice(),
            field("receive_descriptor").as_bytes()
        );
        assert_eq!(
            descriptors[1].as_slice(),
            field("change_descriptor").as_bytes()
        );
        assert_eq!(wallet.wallet_id(), hex_array(field("wallet_id")));
        assert_eq!(
            wallet.first_scripts()[0],
            hex_array(field("receive_0_script_pubkey"))
        );
        assert_eq!(
            wallet.first_scripts()[1],
            hex_array(field("change_0_script_pubkey"))
        );
        assert_eq!(
            wallet.first_addresses()[0].as_slice(),
            field("receive_0_address").as_bytes()
        );
        assert_eq!(
            wallet.first_addresses()[1].as_slice(),
            field("change_0_address").as_bytes()
        );
    }

    #[test]
    fn rebind_requires_exact_descriptor_and_wallet_identity() {
        let seed_a = golden_entropy("seed_a_transcript_sha256");
        let signer_b = golden_entropy("signer_b_transcript_sha256");
        let wallet = derive_wallet_v2(&seed_a, &signer_b).expect("GOLDEN wallet");
        let descriptors = wallet.descriptors();
        let wallet_id = wallet.wallet_id();
        assert_eq!(
            rebind_wallet_v2(&seed_a, &signer_b, &descriptors, &wallet_id),
            Ok(wallet)
        );

        let mut wrong_wallet_id = wallet_id;
        wrong_wallet_id[0] ^= 1;
        assert_eq!(
            rebind_wallet_v2(&seed_a, &signer_b, &descriptors, &wrong_wallet_id),
            Err(WalletV2Error::RecoveredWalletMismatch)
        );

        let mut wrong_descriptor = descriptors;
        wrong_descriptor[0][0] ^= 1;
        assert_eq!(
            rebind_wallet_v2(&seed_a, &signer_b, &wrong_descriptor, &wallet_id),
            Err(WalletV2Error::RecoveredWalletMismatch)
        );

        let other_b = [0x42; 32];
        assert_eq!(
            rebind_wallet_v2(&seed_a, &other_b, &descriptors, &wallet_id),
            Err(WalletV2Error::RecoveredWalletMismatch)
        );
    }

    #[test]
    fn derivation_clears_private_fixed_size_owners() {
        crate::secret::reset_wiped_bytes();
        let wallet = derive_wallet_v2(
            &golden_entropy("seed_a_transcript_sha256"),
            &golden_entropy("signer_b_transcript_sha256"),
        )
        .expect("registered v2 GOLDEN wallet");
        assert_ne!(wallet.wallet_id(), [0u8; 32]);
        assert!(
            crate::secret::wiped_bytes() >= 128,
            "mnemonic, seed, scalar, chain-code, and derivation scratch owners clear"
        );
    }
}
